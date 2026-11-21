import { PIX_OUTCOME } from "../apps/world/src/pix-outcome-controller.ts";

export function inspectPixOutcome(trial, expectedPhases, { requireHeadroom = false } = {}) {
  const issues = [];
  const offered = expectedPhases.reduce((sum, phase) => sum + phase.offered, 0);
  if (trial.byPhase.length !== expectedPhases.length ||
    trial.byPhase.some((phase, index) => phase.multiplier !== expectedPhases[index]?.multiplier ||
      phase.offered !== expectedPhases[index]?.offered || !Number.isSafeInteger(phase.met) ||
      phase.met < 0 || phase.met > phase.offered))
    return { passed: false, issues: ["cohort_mismatch"] };
  for (const phase of trial.byPhase) {
    if (phase.met * 100 < phase.offered * Math.round(PIX_OUTCOME.target * 100))
      issues.push("deadline:" + phase.multiplier);
  }
  for (const field of ["submitted", "unique", "settled", "confirmed", "protectedRecords"]) {
    if (trial.safety[field] !== offered) issues.push(field);
  }
  if (trial.safety.duplicates !== 0) issues.push("duplicate_settlement");
  if (trial.safety.reconciled !== true) issues.push("reconciliation");
  if (!Number.isSafeInteger(trial.oldestExpected) || trial.oldestExpected < 1 ||
    trial.safety.oldestCompleted !== trial.oldestExpected ||
    trial.safety.oldestOnTime !== trial.oldestExpected)
    issues.push("oldest_transfers");
  if (requireHeadroom && (!Number.isFinite(trial.timings?.settlement?.p99) ||
    trial.timings.settlement.p99 > PIX_OUTCOME.deadlineMs / 2))
    issues.push("insufficient_headroom");
  return { passed: issues.length === 0, issues };
}

/** The planner sees aggregate measurements and trusted outcomes of earlier experiments. */
export function planPixPolicy(report, experimentKey, memory, tried = []) {
  const spi = report.timings.spi.p95 ?? 0;
  const psp = report.timings.psp.p95 ?? 0;
  const bothLimited = Math.min(spi, psp) >= 10 && Math.max(spi, psp) <= Math.min(spi, psp) * 2;
  const stage = bothLimited ? "combined" : spi >= psp ? "spi" : "psp";
  const earlier = memory.filter((trial) => trial.experimentKey === experimentKey && trial.stage === stage);
  const proven = earlier.findLast((trial) => trial.verdict === "promoted")?.policy;
  const rejected = new Set([...tried, ...earlier.filter((trial) => trial.verdict === "rejected")
    .map((trial) => trial.policy)]);
  const knownRejected = (candidate) =>
    [...rejected].some((policy) => JSON.stringify(policy) === JSON.stringify(candidate));
  const candidates = [proven, ...[4, 8, 16].map((capacity) => ({
    batchSize: 24, spiMaxConcurrency: stage === "psp" ? 1 : capacity,
    pspMaxConcurrency: stage === "spi" ? 1 : capacity,
  }))].filter(Boolean);
  const policy = candidates.find((candidate) => !knownRejected(candidate));
  return policy ? { stage, policy,
    hypothesis: { spi: "spi_dispatch_is_limiting_throughput", psp: "psp_credit_is_limiting_throughput",
      combined: "both_dispatch_stages_are_limiting_throughput" }[stage] } : null;
}
