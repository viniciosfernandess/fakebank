import { test } from "node:test";
import assert from "node:assert/strict";
import { inspectPixOutcome, planPixPolicy } from "../scripts/pix-outcome-review.mjs";

const expected = [{ multiplier: 3, offered: 100 }];
const passing = () => ({ byPhase: [{ multiplier: 3, offered: 100, met: 99 }],
  oldestExpected: 10, safety: { submitted: 100, unique: 100, settled: 100, confirmed: 100,
    protectedRecords: 100, duplicates: 0, reconciled: true, oldestCompleted: 10, oldestOnTime: 10 } });

test("the outcome gate uses offered requests and refuses to starve the earliest payments", () => {
  const trial = passing();
  assert.equal(inspectPixOutcome(trial, expected).passed, true);
  trial.safety.oldestOnTime = 9;
  assert.deepEqual(inspectPixOutcome(trial, expected).issues, ["oldest_transfers"]);
  trial.byPhase[0].offered = 99;
  assert.deepEqual(inspectPixOutcome(trial, expected).issues, ["cohort_mismatch"]);
});

test("the outcome gate stops promotion if accounting or policy protection regresses", () => {
  const trial = passing();
  trial.safety.reconciled = false;
  trial.safety.protectedRecords = 99;
  trial.safety.duplicates = 1;
  assert.deepEqual(inspectPixOutcome(trial, expected).issues,
    ["protectedRecords", "duplicate_settlement", "reconciliation"]);
});

test("the architect targets the measured stage and reuses only matching evidence", () => {
  const report = { timings: { spi: { p95: 3 }, psp: { p95: 25 } } };
  const first = planPixPolicy(report, "current", []);
  assert.equal(first.stage, "psp");
  assert.equal(first.policy.spiMaxConcurrency, 1);
  assert.equal(first.policy.pspMaxConcurrency, 4);
  const rejected = { ...first, experimentKey: "current", verdict: "rejected" };
  const outdated = { ...first, experimentKey: "old", verdict: "rejected",
    policy: { ...first.policy, pspMaxConcurrency: 8 } };
  const next = planPixPolicy(report, "current", [rejected, outdated]);
  assert.equal(next.policy.pspMaxConcurrency, 8);
  assert.deepEqual(planPixPolicy(report, "current",
    [rejected, { ...next, experimentKey: "current", verdict: "promoted" }]).policy, next.policy);
});

test("the architect treats concurrent SPI and PSP pressure as a shared throughput problem", () => {
  const report = { timings: { spi: { p95: 21 }, psp: { p95: 19 } } };
  const first = planPixPolicy(report, "combined", []);
  assert.equal(first.stage, "combined");
  assert.equal(first.policy.spiMaxConcurrency, 4);
  assert.equal(first.policy.pspMaxConcurrency, 4);
  const next = planPixPolicy(report, "combined", [], [first.policy]);
  assert.equal(next.policy.spiMaxConcurrency, 8);
  assert.equal(next.policy.pspMaxConcurrency, 8);
});

test("a candidate at the outcome threshold cannot be promoted without requested headroom", () => {
  const trial = { ...passing(), timings: { settlement: { p99: 2_501 } } };
  assert.equal(inspectPixOutcome(trial, expected).passed, true);
  assert.deepEqual(inspectPixOutcome(trial, expected, { requireHeadroom: true }).issues,
    ["insufficient_headroom"]);
  trial.timings.settlement.p99 = 2_500;
  assert.equal(inspectPixOutcome(trial, expected, { requireHeadroom: true }).passed, true);
});
