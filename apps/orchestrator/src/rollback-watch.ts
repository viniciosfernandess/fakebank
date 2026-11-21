export type RollbackReason = "health" | "http_5xx" | "latency" | "honest_probe" |
  "false_block" | "ledger_drift" | "unrelated_critical";
export function watchDurationMs(): number {
  const minutes = Number(process.env.PATCH_WATCH_MINUTES || 3);
  if (!Number.isSafeInteger(minutes) || minutes < 1 || minutes > 60)
    throw new Error("PATCH_WATCH_MINUTES_INVALID");
  return minutes * 60_000;
}
export interface WatchSample {
  at: Date;
  requests: number;
  errors5xx: number;
  honestRequests: number;
  wronglyBlocked: number;
  p95Ms: number;
  healthOk: boolean;
  probes: number;
  probeFailures: number;
  ledgerDriftCents: number;
  attackerDriftCents: number;
  unrelatedCritical: boolean;
}
function total(rows: WatchSample[], key: keyof WatchSample): number {
  return rows.reduce((sum, row) => sum + Number(row[key]), 0);
}

export class RollbackWatch {
  readonly startedAt: number;
  readonly baseline5xxRate: number;
  readonly baselineP95Ms: number;
  readonly durationMs: number;
  private readonly samples: WatchSample[] = [];
  private readonly driftChecks = new Set<number>();
  private done = false;
  constructor(input: { startedAt: Date; baseline5xxRate: number; baselineP95Ms: number;
    durationMs?: number }) {
    if (!Number.isFinite(input.baseline5xxRate) || input.baseline5xxRate < 0 ||
      !Number.isFinite(input.baselineP95Ms) || input.baselineP95Ms <= 0)
      throw new Error("WATCH_INVALID_BASELINE");
    this.startedAt = input.startedAt.getTime();
    this.baseline5xxRate = input.baseline5xxRate;
    this.baselineP95Ms = input.baselineP95Ms;
    this.durationMs = input.durationMs ?? watchDurationMs();
    if (!Number.isSafeInteger(this.durationMs) || this.durationMs < 60_000 ||
      this.durationMs > 60 * 60_000) throw new Error("WATCH_DURATION_INVALID");
  }
  observe(sample: WatchSample): RollbackReason | null {
    if (this.done) return null;
    const now = sample.at.getTime();
    if (!Number.isFinite(now) || now < this.startedAt) throw new Error("WATCH_INVALID_TIME");
    if (now - this.startedAt > this.durationMs) { this.done = true; return null; }
    for (const value of [sample.requests, sample.errors5xx, sample.honestRequests,
      sample.wronglyBlocked, sample.p95Ms, sample.probes, sample.probeFailures,
      sample.ledgerDriftCents, sample.attackerDriftCents]) {
      if (!Number.isFinite(value) || value < 0) throw new Error("WATCH_INVALID_SAMPLE");
    }
    if (sample.errors5xx > sample.requests || sample.wronglyBlocked > sample.honestRequests ||
      sample.probeFailures > sample.probes) throw new Error("WATCH_INVALID_SAMPLE");
    this.samples.push(sample);
    const recent = (ms: number) => this.samples.filter((row) => now - row.at.getTime() <= ms);
    let reason: RollbackReason | null = null;
    if (sample.unrelatedCritical) reason = "unrelated_critical";
    else if (recent(30_000).filter((row) => !row.healthOk).length >= 3) reason = "health";
    else {
      const twoMinutes = recent(120_000);
      const requests = total(twoMinutes, "requests");
      const rate = requests ? total(twoMinutes, "errors5xx") / requests : 0;
      if (requests >= 20 && (rate > 0.02 ||
        (this.baseline5xxRate > 0 && rate > 3 * this.baseline5xxRate))) reason = "http_5xx";
      const threeMinutes = recent(180_000);
      if (!reason && now - this.startedAt >= 180_000 && threeMinutes.length >= 2 &&
        threeMinutes.every((row) => row.p95Ms > 3 * this.baselineP95Ms)) reason = "latency";
      const probeSamples = this.samples.filter((row) => row.probes > 0);
      const lastTwenty = probeSamples.slice(-20);
      if (!reason && total(lastTwenty, "probes") >= 20 && total(lastTwenty, "probeFailures") >= 2)
        reason = "honest_probe";
      const falseBlockWindow = Math.min(600_000, this.durationMs);
      const honestWindow = recent(falseBlockWindow);
      const honest = total(honestWindow, "honestRequests");
      if (!reason && now - this.startedAt >= falseBlockWindow && honest > 0 &&
        total(honestWindow, "wronglyBlocked") / honest > 0.005) reason = "false_block";
      for (const checkpoint of new Set([1, Math.min(5, this.durationMs / 60_000),
        this.durationMs / 60_000])) {
        if (now - this.startedAt >= checkpoint * 60_000 && !this.driftChecks.has(checkpoint)) {
          this.driftChecks.add(checkpoint);
          if (!reason && sample.ledgerDriftCents !== sample.attackerDriftCents) reason = "ledger_drift";
        }
      }
    }
    if (reason) this.done = true;
    return reason;
  }
  get finished(): boolean { return this.done; }
}
