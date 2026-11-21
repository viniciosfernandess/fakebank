import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";
import { Bank } from "../apps/world/src/bank.ts";
import { EcosystemClient } from "../apps/ecosystem/src/client.ts";
import { SeparatedPixCoordinator } from "../apps/world/src/separated-pix-coordinator.ts";
import { PIX_OUTCOME, PixOutcomeController, percentile } from "../apps/world/src/pix-outcome-controller.ts";
import { verifySplitSnapshots } from "./verify-split-snapshot.mjs";

export function buildPixArrivals(phases, baseRate) {
  let offset = 0;
  const arrivals = [];
  for (const [index, phase] of phases.entries()) {
    const rate = baseRate * phase.multiplier;
    for (let sample = 0; sample * 1_000 < phase.ms * rate; sample++)
      arrivals.push({ index: arrivals.length, phase: index, at: offset + sample * 1_000 / rate });
    offset += phase.ms;
  }
  return arrivals;
}

function stats(samples) {
  return { count: samples.length, p50: percentile(samples, 0.5),
    p95: percentile(samples, 0.95), p99: percentile(samples, 0.99) };
}

export async function runPixOutcomeTrial({ source, dir, scenario, baseRate, policy, feedback }) {
  mkdirSync(dir);
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  copyFileSync(join(source, "bank.sqlite"), bankPath);
  copyFileSync(join(source, "ecosystem.sqlite"), ecosystemPath);
  const arrivals = buildPixArrivals(scenario.phases, baseRate);
  const realNow = () => new Date();
  const simStart = Date.parse("2026-11-20T15:00:00Z");
  let start = performance.now();
  const bank = new Bank(bankPath, () => new Date(simStart + Math.max(0, performance.now() - start) * 60),
    realNow, { ecosystemMode: "separated" });
  let ecosystem;
  let riskTrace;
  try {
    ecosystem = await EcosystemClient.start(ecosystemPath);
    const senders = bank.db.prepare(`SELECT a.id,a.customer_id FROM accounts a
      JOIN customer_risk_profiles p ON p.customer_id=a.customer_id
      WHERE a.status='active' AND a.balance_cached>=500 AND p.risk_tier='low'
      ORDER BY a.id LIMIT ?`).all(arrivals.length);
    assert.equal(senders.length, arrivals.length, "Fixture must provide independent funded senders");
    const recipients = await ecosystem.syntheticRecipients();
    assert.ok(recipients.length > 0);
    const submit = ecosystem.submitPayment.bind(ecosystem);
    const credit = ecosystem.creditInbound.bind(ecosystem);
    const jitter = (input) => input.amountCents % 5;
    ecosystem.submitPayment = async (input) => {
      if (scenario.spiDelayMs) await delay(scenario.spiDelayMs + jitter(input));
      return submit(input);
    };
    ecosystem.creditInbound = async (input) => {
      if (scenario.pspDelayMs) await delay(scenario.pspDelayMs + jitter(input));
      return credit(input);
    };
    const riskTimes = [];
    riskTrace = bank.risk.evaluatePix.bind(bank.risk);
    bank.risk.evaluatePix = (input) => {
      const at = performance.now();
      try { return riskTrace(input); }
      finally { riskTimes.push(performance.now() - at); }
    };
    const coordinator = new SeparatedPixCoordinator(bank, ecosystem);
    const decisions = [];
    const controller = policy ? new PixOutcomeController(coordinator, bank.db, realNow, policy,
      (decision) => decisions.push({ ...decision, atMs: performance.now() - start }),
      feedback?.recoveryCeiling) : null;
    const records = new Map();
    const results = new Map();
    const inFlight = new Set();
    const stageMetrics = { spi: [], psp: [] };
    const observe = (event) => {
      const row = records.get(event.transferId);
      if (!row) return;
      stageMetrics[event.stage].push(event.finishedAtMs - event.startedAtMs);
      if (event.result === "completed" && event.stage === "spi") {
        row.sent = event.startedAtMs;
        row.spiDone = event.finishedAtMs;
      }
      if (event.result === "completed" && event.stage === "psp") {
        if (row.finished !== undefined) row.duplicates++;
        row.creditStarted = event.startedAtMs;
        row.finished = event.finishedAtMs;
      }
    };
    const launch = (request) => {
      const sender = senders[request.index];
      const destination = recipients[(request.index * (scenario.seed ?? 1) + 17) % recipients.length];
      const row = { received: start + request.at, started: performance.now(), duplicates: 0 };
      results.set(request.index, row);
      const task = coordinator.enqueue({ from: sender.id, to: destination.id,
        amount: 100 + request.index % 5, idempotencyKey: "outcome:" + request.index,
        actor: sender.customer_id }).then((result) => {
        row.enqueued = performance.now();
        row.id = result.id;
        records.set(result.id, row);
      }).catch((error) => { row.error = error instanceof Error ? error.message : String(error); });
      inFlight.add(task);
      void task.finally(() => inFlight.delete(task));
    };
    start = performance.now();
    const hardStop = start + arrivals.at(-1).at + 20_000;
    let next = 0;
    let dispatch;
    let dispatchError;
    const windows = [];
    let windowStart = 0;
    let cohortIndex = 0;
    const offeredUntil = scenario.phases.reduce((sum, phase) => sum + phase.ms, 0);
    function measure(nowMs) {
      if (!feedback) return;
      while (windowStart + feedback.windowMs <= offeredUntil &&
        nowMs >= windowStart + feedback.windowMs + PIX_OUTCOME.deadlineMs) {
        const endMs = windowStart + feedback.windowMs;
        const cohortStart = cohortIndex;
        let onTime = 0;
        while (cohortIndex < arrivals.length && arrivals[cohortIndex].at < endMs) {
          const request = arrivals[cohortIndex++];
          const row = results.get(request.index);
          if (row?.finished !== undefined && row.finished - row.received <= PIX_OUTCOME.deadlineMs)
            onTime++;
        }
        const offered = cohortIndex - cohortStart;
        windowStart += feedback.windowMs;
        if (!offered) continue;
        const window = { startMs: endMs - feedback.windowMs, endMs, measuredAtMs: nowMs,
          offered, onTime };
        windows.push(window);
        if (feedback.enabled) controller.observeOutcome(window);
      }
    }
    while (performance.now() < hardStop) {
      const now = performance.now();
      while (next < arrivals.length && start + arrivals[next].at <= now) launch(arrivals[next++]);
      measure(now - start);
      if (!dispatch && (inFlight.size || records.size || next < arrivals.length)) {
        dispatch = (controller ? controller.dispatch(observe) :
          coordinator.dispatch(24, { observe })).catch((error) => { dispatchError = error; })
          .finally(() => { dispatch = undefined; });
      }
      if (dispatchError) throw dispatchError;
      if (next === arrivals.length && !inFlight.size &&
        [...results.values()].every((row) => row.finished !== undefined || row.error) &&
        (!feedback || windowStart + feedback.windowMs > offeredUntil)) break;
      await delay(Math.max(1, Math.min(10, (arrivals[next]?.at ?? Infinity) - (performance.now() - start))));
    }
    await Promise.all(inFlight);
    await dispatch;
    if (dispatchError) throw dispatchError;
    const byPhase = scenario.phases.map(({ multiplier }, phase) => {
      const cohort = arrivals.filter((row) => row.phase === phase);
      const met = cohort.filter((row) => {
        const detail = results.get(row.index);
        return detail?.finished !== undefined && detail.finished - detail.received <= PIX_OUTCOME.deadlineMs;
      }).length;
      return { multiplier, offered: cohort.length, met, rate: met / cohort.length };
    });
    const unique = records.size;
    const messages = new DatabaseSync(ecosystemPath, { readOnly: true });
    let confirmed;
    try {
      confirmed = messages.prepare("SELECT COUNT(*) n FROM psp_inbound_receipts").get().n;
    } finally { messages.close(); }
    const settled = bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers p
      JOIN pix_psp_inbound_outbox c ON c.transfer_id=p.id
      WHERE p.idempotency_key LIKE 'outcome:%' AND p.status='settled' AND p.ledger_tx_id IS NOT NULL
        AND c.acknowledged_at IS NOT NULL`).get().n;
    const protectedRecords = bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers p
      JOIN risk_decisions d ON d.id=p.risk_decision_id AND d.area='pix'
      WHERE p.idempotency_key LIKE 'outcome:%'`).get().n;
    const late = [...results.values()].filter((row) => Number.isFinite(row.finished))
      .map((row) => row.finished - row.received);
    const safety = {
      submitted: results.size, unique, settled, confirmed, protectedRecords, oldestCompleted: 0,
      duplicates: [...results.values()].reduce((total, row) => total + row.duplicates, 0),
      reconciled: bank.reconcile().ok && verifySplitSnapshots(bankPath, ecosystemPath).ok,
    };
    const oldest = scenario.phases.flatMap((_, index) => {
      const sample = arrivals.filter((entry) => entry.phase === index);
      return sample.slice(0, Math.ceil(sample.length / 10));
    });
    safety.oldestCompleted = oldest.filter((entry) => Number.isFinite(results.get(entry.index)?.finished)).length;
    safety.oldestOnTime = oldest.filter((entry) => {
      const row = results.get(entry.index);
      return Number.isFinite(row?.finished) && row.finished - row.received <= PIX_OUTCOME.deadlineMs;
    }).length;
    const observed = [...records.values()];
    const intervals = (a, b) => observed.filter((row) => Number.isFinite(row[a]) && Number.isFinite(row[b]))
      .map((row) => Math.max(0, row[b] - row[a]));
    return { byPhase, decisions, ...(feedback ? { windows } : {}), safety, oldestExpected: oldest.length,
      dispatchWork: decisions.reduce((sum, item) => sum + Math.max(0, item.to - item.from), 0),
      errors: [...results.values()].filter((row) => row.error).slice(0, 5).map((row) => row.error),
      timings: { ingress: stats(intervals("received", "started")),
        validation: stats(intervals("started", "enqueued")), risk: stats(riskTimes), queue: stats(intervals("enqueued", "sent")),
        spi: stats(stageMetrics.spi), pspQueue: stats(intervals("spiDone", "creditStarted")), psp: stats(stageMetrics.psp),
        settlement: stats(late) } };
  } finally {
    if (riskTrace) bank.risk.evaluatePix = riskTrace;
    try { await ecosystem?.close(); }
    finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
  }
}
