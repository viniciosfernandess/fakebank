import type { DatabaseSync } from "node:sqlite";
import { MAX_PIX_DISPATCH_CONCURRENCY, type PixDispatchObservation,
  type PixDispatchStage, type SeparatedPixCoordinator } from "./separated-pix-coordinator.ts";

export const PIX_OUTCOME = Object.freeze({
  target: 0.99, deadlineMs: 5_000, loadMultiplier: 3,
});

export interface PixOutcomePolicy {
  batchSize: number;
  spiMaxConcurrency: number;
  pspMaxConcurrency: number;
}

export const CONSERVATIVE_PIX_POLICY: Readonly<PixOutcomePolicy> = Object.freeze({
  batchSize: 24, spiMaxConcurrency: 8, pspMaxConcurrency: 8,
});

export interface PixQueuePressure {
  count: number;
  oldestMs: number;
}

interface StageState {
  concurrency: number;
  serviceMs: number;
  quietBatches: number;
}

export function percentile(samples: readonly number[], fraction: number): number | null {
  if (!samples.length) return null;
  return [...samples].sort((a, b) => a - b)[Math.ceil(samples.length * fraction) - 1]!;
}

function pressure(db: DatabaseSync, now: Date): Record<PixDispatchStage, PixQueuePressure> {
  const spi = db.prepare(`SELECT COUNT(*) count,MIN(COALESCE(queued_at_real,eligible_at_real)) oldest
    FROM pix_spi_outbox o JOIN pix_transfers p ON p.id=o.transfer_id
    WHERE p.status='in_processing' AND (o.eligible_at_real IS NULL OR o.eligible_at_real<=?)`)
    .get(now.toISOString()) as { count: number; oldest: string | null };
  const psp = db.prepare(`SELECT COUNT(*) count,MIN(s.queued_at_real) oldest
    FROM pix_psp_inbound_outbox p JOIN pix_spi_outbox s ON s.transfer_id=p.transfer_id
    WHERE p.acknowledged_at IS NULL`).get() as { count: number; oldest: string | null };
  const age = (oldest: string | null) => oldest ? Math.max(0, now.getTime() - Date.parse(oldest)) : 0;
  return { spi: { count: spi.count, oldestMs: age(spi.oldest) },
    psp: { count: psp.count, oldestMs: age(psp.oldest) } };
}

export function validatePixOutcomePolicy(policy: PixOutcomePolicy): void {
  if (!Number.isSafeInteger(policy.batchSize) || policy.batchSize < 1 || policy.batchSize > 100 ||
    [policy.spiMaxConcurrency, policy.pspMaxConcurrency].some((value) =>
      !Number.isSafeInteger(value) || value < 1 || value > MAX_PIX_DISPATCH_CONCURRENCY))
    throw new Error("PIX_OUTCOME_POLICY_INVALID");
}

export interface PixOutcomeWindow {
  startMs: number;
  endMs: number;
  measuredAtMs: number;
  offered: number;
  onTime: number;
}

export interface PixOutcomeDecision {
  stage: PixDispatchStage;
  from: number;
  to: number;
  backlog: number;
  oldestMs: number;
  serviceMs: number;
  reason: "queue_pressure" | "capacity_released" | "outcome_breach";
  breachWindowEndMs?: number;
}

/** Runs the same bounded controller in the standalone dispatcher and in experiment trials. */
export class PixOutcomeController {
  private readonly state: Record<PixDispatchStage, StageState> = {
    spi: { concurrency: 1, serviceMs: 1, quietBatches: 0 },
    psp: { concurrency: 1, serviceMs: 1, quietBatches: 0 },
  };
  private busy = false;
  private lastWindowEndMs = -Infinity;
  private breachWindowEndMs: number | undefined;

  private readonly coordinator: SeparatedPixCoordinator;
  private readonly db: DatabaseSync;
  private readonly realNow: () => Date;
  private readonly policy: Readonly<PixOutcomePolicy>;
  private readonly recoveryCeiling: number;
  private readonly onDecision: ((decision: PixOutcomeDecision) => void) | undefined;

  constructor(coordinator: SeparatedPixCoordinator, db: DatabaseSync, realNow: () => Date,
    policy: Readonly<PixOutcomePolicy> = CONSERVATIVE_PIX_POLICY,
    onDecision?: (decision: PixOutcomeDecision) => void,
    recoveryCeiling = Math.max(policy.spiMaxConcurrency, policy.pspMaxConcurrency)) {
    validatePixOutcomePolicy(policy);
    if (!Number.isSafeInteger(recoveryCeiling) ||
      recoveryCeiling < Math.max(policy.spiMaxConcurrency, policy.pspMaxConcurrency) ||
      recoveryCeiling > MAX_PIX_DISPATCH_CONCURRENCY)
      throw new Error("PIX_OUTCOME_RECOVERY_CEILING_INVALID");
    this.coordinator = coordinator;
    this.db = db;
    this.realNow = realNow;
    this.policy = Object.freeze({ ...policy });
    this.onDecision = onDecision;
    this.recoveryCeiling = recoveryCeiling;
  }

  observeOutcome(window: PixOutcomeWindow): void {
    if (![window.startMs, window.endMs, window.measuredAtMs].every(Number.isFinite) ||
      window.endMs <= window.startMs || window.startMs < this.lastWindowEndMs ||
      window.measuredAtMs < window.endMs + PIX_OUTCOME.deadlineMs ||
      !Number.isSafeInteger(window.offered) || window.offered < 1 ||
      !Number.isSafeInteger(window.onTime) || window.onTime < 0 || window.onTime > window.offered)
      throw new Error("PIX_OUTCOME_WINDOW_INVALID");
    this.lastWindowEndMs = window.endMs;
    if (window.onTime * 100 < window.offered * Math.round(PIX_OUTCOME.target * 100))
      this.breachWindowEndMs = window.endMs;
  }

  private adapt(stage: PixDispatchStage, queue: PixQueuePressure,
    observations: readonly PixDispatchObservation[]): void {
    const state = this.state[stage];
    const completed = observations.filter((entry) => entry.result === "completed");
    const currentService = percentile(completed.map((entry) =>
      entry.finishedAtMs - entry.startedAtMs), 0.9);
    if (currentService !== null)
      state.serviceMs = Math.max(currentService, state.serviceMs * 0.8);
    // A failed transport needs recovery, not more in-flight work.
    if (observations.some((entry) => entry.result !== "completed")) {
      state.quietBatches = 0;
      return;
    }

    const normalMax = stage === "spi" ? this.policy.spiMaxConcurrency : this.policy.pspMaxConcurrency;
    const recovering = this.breachWindowEndMs !== undefined && this.recoveryCeiling > normalMax;
    const max = recovering ? this.recoveryCeiling : normalMax;
    const deadlineBudget = Math.max(80, Math.min(160, (PIX_OUTCOME.deadlineMs - queue.oldestMs) / 3));
    const needed = Math.max(1, Math.min(max,
      Math.ceil(queue.count * state.serviceMs / deadlineBudget)));
    state.quietBatches = queue.count <= state.concurrency ? state.quietBatches + 1 : 0;
    const next = needed > state.concurrency ? needed :
      state.quietBatches >= 4 ? Math.max(needed, Math.ceil(state.concurrency / 2)) : state.concurrency;
    if (next === state.concurrency) return;
    const from = state.concurrency;
    state.concurrency = next;
    state.quietBatches = 0;
    this.onDecision?.({ stage, from, to: next, backlog: queue.count,
      oldestMs: queue.oldestMs, serviceMs: state.serviceMs,
      reason: next <= from ? "capacity_released" : recovering && next > normalMax ?
        "outcome_breach" : "queue_pressure",
      ...(recovering && next > from && next > normalMax ?
        { breachWindowEndMs: this.breachWindowEndMs! } : {}) });
  }

  async dispatch(observe?: (entry: PixDispatchObservation) => void): Promise<void> {
    if (this.busy) throw new Error("PIX_OUTCOME_DISPATCH_BUSY");
    this.busy = true;
    const samples: Record<PixDispatchStage, PixDispatchObservation[]> = { spi: [], psp: [] };
    try {
      await this.coordinator.dispatch(this.policy.batchSize, {
        spiConcurrency: this.state.spi.concurrency,
        pspConcurrency: this.state.psp.concurrency,
        observe: (entry) => {
          samples[entry.stage].push(entry);
          observe?.(entry);
        },
      });
      const queue = pressure(this.db, this.realNow());
      this.adapt("spi", queue.spi, samples.spi);
      this.adapt("psp", { count: queue.psp.count + Math.min(queue.spi.count, this.policy.batchSize * 2),
        oldestMs: Math.max(queue.psp.oldestMs, queue.spi.oldestMs) }, samples.psp);
    } finally {
      this.busy = false;
    }
  }
}
