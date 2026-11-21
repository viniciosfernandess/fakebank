import { randomUUID } from "node:crypto";
import type { EventStore } from "../../../packages/event-store/src/index.ts";

export type BudgetModel = "claude-haiku-5-5" | "claude-sonnet-5-5";
export type BudgetPriority = 1 | 2 | 3 | 4;
export type RunKind = "round" | "product";
export interface ModelUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_input_tokens?: number | null;
  cache_creation_input_tokens?: number | null;
  cache_creation?: { ephemeral_5m_input_tokens?: number; ephemeral_1h_input_tokens?: number } | null;
  inference_geo?: string | null;
  service_tier?: "standard" | "priority" | "batch" | null;
}
export interface CostedUsage { costNusd: number; promptTokens: number; highContext: boolean; }
export interface BudgetSummary {
  runId: string; kind: RunKind; day: string; capNusd: number; spentNusd: number;
  committedNusd: number; daySpentNusd: number; dayCommittedNusd: number;
}

// Nanodollars per token. Claude API standard inference; reviewed 2026-11-11.
// https://platform.claude.com/docs/en/about-claude/pricing
const PRICES = {
  "claude-haiku-5-5": { input: 100, output: 500, read: 10, write5m: 125, write1h: 200 },
  "claude-sonnet-5-5": { input: 2000, output: 10000, read: 100, write5m: 2500, write1h: 4000 },
} as const;
const DAY_CAP = 1_500_000_000;
const ROUND_CAP = 700_000_000;
const PRODUCT_CAP = 100_000_000;
const PRODUCT_RESERVE = 100_000_000;
const FLOORS: Record<1 | 2 | 3, number> = { 1: 250_000_000, 2: 30_000_000, 3: 10_000_000 };

function tokenCount(value: number | null | undefined): number {
  if (value == null) return 0;
  if (!Number.isSafeInteger(value) || value < 0) throw new BudgetError("BUDGET_INVALID_USAGE");
  return value;
}
function writeTokens(usage: ModelUsage): { write5m: number; write1h: number } {
  const detailed = usage.cache_creation;
  if (!detailed) return { write5m: tokenCount(usage.cache_creation_input_tokens), write1h: 0 };
  const write5m = tokenCount(detailed.ephemeral_5m_input_tokens);
  const write1h = tokenCount(detailed.ephemeral_1h_input_tokens);
  const aggregate = usage.cache_creation_input_tokens;
  if (aggregate != null && tokenCount(aggregate) !== write5m + write1h)
    throw new BudgetError("BUDGET_INVALID_USAGE");
  return { write5m, write1h };
}
function safeCost(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new BudgetError("BUDGET_COST_OVERFLOW");
  return value;
}
export function priceUsage(model: BudgetModel, usage: ModelUsage): CostedUsage {
  if ((usage.inference_geo && usage.inference_geo !== "global") ||
    (usage.service_tier && usage.service_tier !== "standard"))
    throw new BudgetError("BUDGET_UNSUPPORTED_PRICING");
  const input = tokenCount(usage.input_tokens);
  const output = tokenCount(usage.output_tokens);
  const read = tokenCount(usage.cache_read_input_tokens);
  const { write5m, write1h } = writeTokens(usage);
  const promptTokens = safeCost(input + read + write5m + write1h);
  const highContext = model === "claude-haiku-5-5" && promptTokens > 100_000;
  const rate = PRICES[model];
  const multiplier = highContext ? 5 : 1;
  return { costNusd: safeCost(multiplier * (input * rate.input + output * rate.output +
    read * rate.read + write5m * rate.write5m + write1h * rate.write1h)),
    promptTokens, highContext };
}
export function worstCaseCost(model: BudgetModel, inputUpperBound: number, maxOutputTokens: number): number {
  const input = tokenCount(inputUpperBound);
  const output = tokenCount(maxOutputTokens);
  const multiplier = model === "claude-haiku-5-5" && input > 100_000 ? 5 : 1;
  // Any input token may be a one-hour cache write, which costs 2x base input.
  return safeCost(multiplier * (input * PRICES[model].write1h + output * PRICES[model].output));
}
function brtDay(date: Date): string {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: "America/Sao_Paulo",
    year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(date);
  const get = (type: string): string => parts.find((part) => part.type === type)?.value ?? "";
  return `${get("year")}-${get("month")}-${get("day")}`;
}
export class BudgetError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; }
}
interface RunRow { id: string; kind: RunKind; day: string; cap_nusd: number; status: string; }
interface ReservationRow { id: string; run_id: string; role: string; priority: BudgetPriority;
  held_nusd: number; active: number; }
interface ClaimRow { request_id: string; reservation_id: string; model: BudgetModel; worst_nusd: number; }

export class BudgetLedger {
  readonly events: EventStore;
  readonly now: () => Date;
  constructor(events: EventStore, now: () => Date = () => new Date()) {
    this.events = events; this.now = now;
    events.db.exec(`CREATE TABLE IF NOT EXISTS budget_runs (
      id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('round','product')),
      day TEXT NOT NULL, cap_nusd INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open'
    );
    CREATE INDEX IF NOT EXISTS budget_runs_day ON budget_runs(day);
    CREATE TABLE IF NOT EXISTS budget_reservations (
      id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES budget_runs(id),
      role TEXT NOT NULL, priority INTEGER NOT NULL CHECK(priority BETWEEN 1 AND 4),
      held_nusd INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS budget_claims (
      request_id TEXT PRIMARY KEY, reservation_id TEXT NOT NULL REFERENCES budget_reservations(id),
      model TEXT NOT NULL, worst_nusd INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS budget_calls (
      request_id TEXT PRIMARY KEY, reservation_id TEXT NOT NULL REFERENCES budget_reservations(id),
      model TEXT NOT NULL, input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL,
      cache_read_tokens INTEGER NOT NULL, cache_write_5m_tokens INTEGER NOT NULL,
      cache_write_1h_tokens INTEGER NOT NULL, cost_nusd INTEGER NOT NULL,
      estimate_exceeded INTEGER NOT NULL, settled_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS budget_calls_reservation ON budget_calls(reservation_id);`);
  }
  private transaction<T>(work: () => T): T {
    this.events.db.exec("BEGIN IMMEDIATE");
    try { const result = work(); this.events.db.exec("COMMIT"); return result; }
    catch (error) { this.events.db.exec("ROLLBACK"); throw error; }
  }
  private run(id: string): RunRow {
    const row = this.events.db.prepare("SELECT * FROM budget_runs WHERE id=?").get(id) as unknown as RunRow | undefined;
    if (!row) throw new BudgetError("BUDGET_UNKNOWN_RUN");
    return row;
  }
  private reservation(id: string): ReservationRow {
    const row = this.events.db.prepare("SELECT * FROM budget_reservations WHERE id=?")
      .get(id) as unknown as ReservationRow | undefined;
    if (!row || !row.active) throw new BudgetError("BUDGET_UNKNOWN_RESERVATION");
    return row;
  }
  private sum(sql: string, ...args: (string | number)[]): number {
    return (this.events.db.prepare(sql).get(...args) as { n: number }).n;
  }
  private spent(runId: string): number {
    return this.sum(`SELECT COALESCE(SUM(c.cost_nusd),0) n FROM budget_calls c
      JOIN budget_reservations r ON r.id=c.reservation_id WHERE r.run_id=?`, runId);
  }
  private held(runId: string): number {
    return this.sum(`SELECT COALESCE(SUM(MAX(r.held_nusd,
      COALESCE((SELECT SUM(c.worst_nusd) FROM budget_claims c WHERE c.reservation_id=r.id),0))),0) n
      FROM budget_reservations r WHERE r.run_id=? AND r.active=1`, runId);
  }
  private committed(runId: string): number { return this.spent(runId) + this.held(runId); }
  private dayRunIds(day: string): string[] {
    return (this.events.db.prepare("SELECT id FROM budget_runs WHERE day=?").all(day) as { id: string }[])
      .map((row) => row.id);
  }
  private dayCommitted(day: string): number {
    return this.dayRunIds(day).reduce((total, id) => total + this.committed(id), 0);
  }
  private daySpent(day: string): number {
    return this.dayRunIds(day).reduce((total, id) => total + this.spent(id), 0);
  }
  private floorRemaining(runId: string, priority: BudgetPriority): number {
    let remaining = 0;
    for (const level of [1, 2, 3] as const) {
      if (level >= priority) continue;
      const spent = this.sum(`SELECT COALESCE(SUM(c.cost_nusd),0) n FROM budget_calls c
        JOIN budget_reservations r ON r.id=c.reservation_id WHERE r.run_id=? AND r.priority=?`, runId, level);
      const held = this.sum(`SELECT COALESCE(SUM(r.held_nusd),0) n FROM budget_reservations r
        WHERE r.run_id=? AND r.priority=? AND r.active=1`, runId, level);
      remaining += Math.max(0, FLOORS[level] - spent - held);
    }
    return remaining;
  }
  openRun(id: string, kind: RunKind): BudgetSummary {
    if (!/^[a-zA-Z0-9_-]{3,100}$/.test(id)) throw new BudgetError("BUDGET_INVALID_RUN");
    return this.transaction(() => {
      const existing = this.events.db.prepare("SELECT * FROM budget_runs WHERE id=?").get(id) as unknown as RunRow | undefined;
      if (existing) {
        if (existing.kind !== kind) throw new BudgetError("BUDGET_RUN_CONFLICT");
        return this.summary(id);
      }
      const day = brtDay(this.now());
      const productDone = this.sum(`SELECT COUNT(*) n FROM budget_runs WHERE day=? AND kind='product' AND status='closed'`, day) > 0;
      const reserve = kind === "round" && !productDone ? PRODUCT_RESERVE : 0;
      const available = Math.max(0, DAY_CAP - this.dayCommitted(day) - reserve);
      const cap = Math.min(kind === "round" ? ROUND_CAP : PRODUCT_CAP, available);
      this.events.db.prepare("INSERT INTO budget_runs VALUES (?,?,?,?,'open')").run(id, kind, day, cap);
      return this.summary(id);
    });
  }
  reserve(runId: string, role: string, priority: BudgetPriority, estimateNusd: number): string | null {
    if (!role || ![1, 2, 3, 4].includes(priority)) throw new BudgetError("BUDGET_INVALID_RESERVATION");
    const estimate = safeCost(estimateNusd);
    if (estimate <= 0) throw new BudgetError("BUDGET_INVALID_RESERVATION");
    return this.transaction(() => {
      const run = this.run(runId);
      if (run.status !== "open") throw new BudgetError("BUDGET_RUN_CLOSED");
      if (this.committed(runId) + estimate + this.floorRemaining(runId, priority) > run.cap_nusd ||
        this.dayCommitted(run.day) + estimate > DAY_CAP) return null;
      const id = `reservation_${randomUUID()}`;
      this.events.db.prepare("INSERT INTO budget_reservations VALUES (?,?,?,?,?,1)")
        .run(id, runId, role, priority, estimate);
      return id;
    });
  }
  claim(reservationId: string, requestId: string, model: BudgetModel,
    inputUpperBound: number, maxOutputTokens: number): number | null {
    if (!requestId || requestId.length > 128) throw new BudgetError("BUDGET_INVALID_REQUEST");
    const worst = worstCaseCost(model, inputUpperBound, maxOutputTokens);
    return this.transaction(() => {
      const existing = this.events.db.prepare("SELECT * FROM budget_claims WHERE request_id=?")
        .get(requestId) as unknown as ClaimRow | undefined;
      if (existing) {
        if (existing.reservation_id !== reservationId || existing.model !== model || existing.worst_nusd !== worst)
          throw new BudgetError("BUDGET_REQUEST_CONFLICT");
        return existing.worst_nusd;
      }
      if (this.events.db.prepare("SELECT 1 FROM budget_calls WHERE request_id=?").get(requestId))
        throw new BudgetError("BUDGET_REQUEST_SETTLED");
      const reservation = this.reservation(reservationId);
      const run = this.run(reservation.run_id);
      if (run.status !== "open") throw new BudgetError("BUDGET_RUN_CLOSED");
      const pending = this.sum("SELECT COALESCE(SUM(worst_nusd),0) n FROM budget_claims WHERE reservation_id=?", reservationId);
      const before = Math.max(reservation.held_nusd, pending);
      const after = Math.max(reservation.held_nusd, pending + worst);
      const delta = after - before;
      if (this.committed(run.id) + delta + this.floorRemaining(run.id, reservation.priority) > run.cap_nusd ||
        this.dayCommitted(run.day) + delta > DAY_CAP) return null;
      this.events.db.prepare("INSERT INTO budget_claims VALUES (?,?,?,?)").run(requestId, reservationId, model, worst);
      return worst;
    });
  }
  settle(requestId: string, usage: ModelUsage): { costNusd: number; estimateExceeded: boolean } {
    return this.transaction(() => {
      const existing = this.events.db.prepare("SELECT cost_nusd,estimate_exceeded FROM budget_calls WHERE request_id=?")
        .get(requestId) as { cost_nusd: number; estimate_exceeded: number } | undefined;
      if (existing) return { costNusd: existing.cost_nusd, estimateExceeded: Boolean(existing.estimate_exceeded) };
      const claim = this.events.db.prepare("SELECT * FROM budget_claims WHERE request_id=?")
        .get(requestId) as unknown as ClaimRow | undefined;
      if (!claim) throw new BudgetError("BUDGET_UNKNOWN_CLAIM");
      const cost = priceUsage(claim.model, usage).costNusd;
      const { write5m, write1h } = writeTokens(usage);
      const exceeded = cost > claim.worst_nusd;
      this.events.db.prepare(`INSERT INTO budget_calls VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
        requestId, claim.reservation_id, claim.model, usage.input_tokens, usage.output_tokens,
        usage.cache_read_input_tokens ?? 0, write5m, write1h, cost, Number(exceeded), this.now().toISOString());
      this.events.db.prepare("DELETE FROM budget_claims WHERE request_id=?").run(requestId);
      this.events.db.prepare(`UPDATE budget_reservations SET held_nusd=MAX(0,held_nusd-?) WHERE id=?`)
        .run(cost, claim.reservation_id);
      return { costNusd: cost, estimateExceeded: exceeded };
    });
  }
  cancelUnbilledClaim(requestId: string): void {
    this.transaction(() => {
      if (this.events.db.prepare("SELECT 1 FROM budget_calls WHERE request_id=?").get(requestId))
        throw new BudgetError("BUDGET_REQUEST_SETTLED");
      const removed = this.events.db.prepare("DELETE FROM budget_claims WHERE request_id=?").run(requestId);
      if (removed.changes !== 1) throw new BudgetError("BUDGET_UNKNOWN_CLAIM");
    });
  }
  release(reservationId: string): void {
    this.transaction(() => {
      this.reservation(reservationId);
      if (this.events.db.prepare("SELECT 1 FROM budget_claims WHERE reservation_id=? LIMIT 1").get(reservationId))
        throw new BudgetError("BUDGET_PENDING_CLAIM");
      this.events.db.prepare("UPDATE budget_reservations SET active=0,held_nusd=0 WHERE id=?").run(reservationId);
    });
  }
  closeRun(runId: string): void {
    this.transaction(() => {
      const run = this.run(runId);
      if (run.status === "closed") return;
      if (this.events.db.prepare(`SELECT 1 FROM budget_reservations WHERE run_id=? AND active=1 LIMIT 1`)
        .get(runId)) throw new BudgetError("BUDGET_ACTIVE_RESERVATION");
      this.events.db.prepare("UPDATE budget_runs SET status='closed' WHERE id=?").run(runId);
    });
  }
  summary(runId: string): BudgetSummary {
    const run = this.run(runId);
    return { runId, kind: run.kind, day: run.day, capNusd: run.cap_nusd,
      spentNusd: this.spent(runId), committedNusd: this.committed(runId),
      daySpentNusd: this.daySpent(run.day), dayCommittedNusd: this.dayCommitted(run.day) };
  }
}
