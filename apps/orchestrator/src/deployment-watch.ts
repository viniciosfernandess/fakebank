import type { Bank } from "../../world/src/bank.ts";
import type { CustomerSimulator } from "../../world/src/simulator.ts";
import type { Gateway } from "../../world/src/gateway.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import { RollbackWatch, watchDurationMs, type RollbackReason, type WatchSample } from "./rollback-watch.ts";

interface WatchRow {
  run_id: string; round_id: string; incident_id: string; task_id: string;
  rule_id: string; started_at: string; baseline_5xx: number; baseline_p95: number;
  baseline_drift: number; last_metric_id: number; last_sim_minute: string; last_event_seq: number;
  last_probe_at: string; samples_json: string; state: string; reason: string | null;
}
interface Metric { id: number; status: number; duration_ms: number; }

export class DeploymentWatch {
  private readonly bank: Bank;
  private readonly gateway: Gateway;
  private readonly simulator: CustomerSimulator;
  private readonly events: EventStore;
  private readonly now: () => Date;
  private readonly durationMs: number;
  constructor(bank: Bank, gateway: Gateway, simulator: CustomerSimulator,
    events: EventStore, now: () => Date = () => new Date()) {
    this.bank = bank; this.gateway = gateway; this.simulator = simulator;
    this.events = events; this.now = now;
    this.durationMs = watchDurationMs();
    events.db.exec(`CREATE TABLE IF NOT EXISTS deployment_watches (
      run_id TEXT PRIMARY KEY, round_id TEXT NOT NULL, incident_id TEXT NOT NULL,
      task_id TEXT NOT NULL, rule_id TEXT NOT NULL, started_at TEXT NOT NULL,
      baseline_5xx REAL NOT NULL, baseline_p95 REAL NOT NULL,
      baseline_drift INTEGER NOT NULL,
      last_metric_id INTEGER NOT NULL, last_sim_minute TEXT NOT NULL,
      last_event_seq INTEGER NOT NULL, last_probe_at TEXT NOT NULL,
      samples_json TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('watching','passed','failed','rolled_back')),
      reason TEXT
    );`);
  }
  private row(runId: string): WatchRow | undefined {
    return this.events.db.prepare("SELECT * FROM deployment_watches WHERE run_id=?")
      .get(runId) as WatchRow | undefined;
  }
  private ledgerDriftCents(): number {
    const accounts = this.bank.db.prepare(`SELECT COALESCE(SUM(ABS(a.balance_cached-
      COALESCE(l.total,0))),0) amount FROM accounts a LEFT JOIN
      (SELECT account_id,SUM(amount) total FROM ledger_entries GROUP BY account_id) l
      ON l.account_id=a.id`).get() as { amount: number };
    const transactions = this.bank.db.prepare(`SELECT COALESCE(SUM(ABS(total)),0) amount FROM
      (SELECT SUM(amount) total FROM ledger_entries GROUP BY tx_id HAVING total<>0)`)
      .get() as { amount: number };
    const rounding = this.bank.db.prepare("SELECT balance_cached FROM accounts WHERE kind='system' AND system_role='rounding'")
      .get() as { balance_cached: number } | undefined;
    return accounts.amount + transactions.amount + Math.abs(rounding?.balance_cached ?? 0);
  }
  state(runId: string): { state: "watching" | "passed" | "failed" | "rolled_back";
    reason?: RollbackReason } | undefined {
    const row = this.row(runId);
    return row ? { state: row.state as "watching" | "passed" | "failed" | "rolled_back",
      ...(row.reason ? { reason: row.reason as RollbackReason } : {}) } : undefined;
  }
  startedAt(runId: string): Date {
    const row = this.row(runId);
    if (!row) throw new Error("DEPLOYMENT_WATCH_NOT_FOUND");
    return new Date(row.started_at);
  }
  markRolledBack(runId: string): void {
    this.events.db.prepare("UPDATE deployment_watches SET state='rolled_back' WHERE run_id=? AND state='failed'")
      .run(runId);
  }
  begin(input: { runId: string; roundId: string; incidentId: string; taskId: string;
    ruleId: string }): void {
    if (this.row(input.runId)) return;
    const started = this.now();
    const metrics = this.bank.db.prepare(`SELECT id,status,duration_ms FROM gateway_metrics
      WHERE at>=? AND at<? ORDER BY id`).all(
        new Date(started.getTime() - 120_000).toISOString(), started.toISOString()) as unknown as Metric[];
    const errors = metrics.filter((item) => item.status >= 500).length;
    const durations = metrics.map((item) => item.duration_ms).sort((a, b) => a - b);
    const baselineP95 = durations[Math.max(0, Math.ceil(durations.length * 0.95) - 1)] ?? 100;
    const lastMetric = this.bank.db.prepare("SELECT COALESCE(MAX(id),0) id FROM gateway_metrics")
      .get() as { id: number };
    this.events.db.prepare(`INSERT INTO deployment_watches VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'[]','watching',NULL)`)
      .run(input.runId, input.roundId, input.incidentId, input.taskId, input.ruleId,
        started.toISOString(), metrics.length ? errors / metrics.length : 0,
        Math.max(1, baselineP95), this.ledgerDriftCents(), lastMetric.id, started.toISOString(),
        this.events.latestSeq(), started.toISOString());
  }
  async observe(): Promise<{ runId: string; reason: RollbackReason }[]> {
    const failed = (this.events.db.prepare("SELECT run_id,reason FROM deployment_watches WHERE state='failed'")
      .all() as { run_id: string; reason: RollbackReason }[])
      .map((row) => ({ runId: row.run_id, reason: row.reason }));
    const rows = this.events.db.prepare("SELECT * FROM deployment_watches WHERE state='watching'")
      .all() as unknown as WatchRow[];
    for (const row of rows) {
      const now = this.now();
      const startedMs = Date.parse(row.started_at);
      const at = new Date(Math.min(now.getTime(), startedMs + this.durationMs));
      const metrics = this.bank.db.prepare(`SELECT id,status,duration_ms FROM gateway_metrics
        WHERE id>? ORDER BY id`).all(row.last_metric_id) as unknown as Metric[];
      const ticks = this.bank.db.prepare(`SELECT minute,ops,honest_blocked FROM sim_ticks
        WHERE minute>? ORDER BY minute`).all(row.last_sim_minute) as
        { minute: string; ops: number; honest_blocked: number }[];
      const alerts: ReturnType<EventStore["list"]> = [];
      let cursor = row.last_event_seq;
      for (;;) {
        const page = this.events.list({ after: cursor, types: ["sentinel.alert"], limit: 500 });
        alerts.push(...page);
        if (page.length < 500) break;
        cursor = page.at(-1)!.seq;
      }
      let healthOk = false;
      try {
        healthOk = (await this.gateway.call({ method: "GET", path: "/api/v1/health",
          peerIp: "127.0.0.1" })).status === 200;
      } catch { healthOk = false; }
      let probes = 0; let probeFailures = 0;
      if (now.getTime() - Date.parse(row.last_probe_at) >= 30_000) {
        probes = 1;
        try { probeFailures = (await this.simulator.honestProbe()) ? 0 : 1; }
        catch { probeFailures = 1; }
      }
      const durations = metrics.map((item) => item.duration_ms).sort((a, b) => a - b);
      const prior = JSON.parse(row.samples_json) as WatchSample[];
      const driftDue = [...new Set([1, Math.min(5, this.durationMs / 60_000),
        this.durationMs / 60_000])].some((minute) => {
        const threshold = startedMs + minute * 60_000;
        return at.getTime() >= threshold && prior.every((sample) =>
          Date.parse(String(sample.at)) < threshold);
      });
      const sample: WatchSample = { at, requests: metrics.length,
        errors5xx: metrics.filter((item) => item.status >= 500).length,
        honestRequests: ticks.reduce((sum, item) => sum + item.ops, 0),
        wronglyBlocked: ticks.reduce((sum, item) => sum + item.honest_blocked, 0),
        p95Ms: durations[Math.max(0, Math.ceil(durations.length * 0.95) - 1)] ?? row.baseline_p95,
        healthOk, probes, probeFailures,
        ledgerDriftCents: driftDue ? Math.abs(this.ledgerDriftCents() - row.baseline_drift) : 0,
        attackerDriftCents: 0,
        unrelatedCritical: alerts.some((event) => event.public.severity === "critical" &&
          event.public.rule_id !== row.rule_id) };
      const watch = new RollbackWatch({ startedAt: new Date(row.started_at),
        baseline5xxRate: row.baseline_5xx, baselineP95Ms: row.baseline_p95,
        durationMs: this.durationMs });
      for (const previous of prior) watch.observe({ ...previous, at: new Date(previous.at) });
      const reason = watch.observe(sample);
      const state = reason ? "failed" : now.getTime() >= startedMs + this.durationMs ? "passed" : "watching";
      this.events.db.prepare(`UPDATE deployment_watches SET last_metric_id=?,last_sim_minute=?,
        last_event_seq=?,last_probe_at=?,samples_json=?,state=?,reason=? WHERE run_id=?`)
        .run(metrics.at(-1)?.id ?? row.last_metric_id,
          ticks.at(-1)?.minute ?? row.last_sim_minute,
          this.events.latestSeq(), probes ? now.toISOString() : row.last_probe_at,
          JSON.stringify([...prior, sample]), state, reason, row.run_id);
      if (reason) failed.push({ runId: row.run_id, reason });
    }
    return failed;
  }
}
