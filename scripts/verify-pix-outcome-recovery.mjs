import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { PIX_OUTCOME } from "../apps/world/src/pix-outcome-controller.ts";
import { pixOutcomeRevision } from "../apps/world/src/pix-outcome-policy-file.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { exportSplitSnapshots } from "./export-ecosystem-snapshot.mjs";
import { buildPixArrivals, runPixOutcomeTrial } from "./pix-outcome-trial.mjs";

const baseRate = 32;
const rampAtMs = 4_000;
const windowMs = 2_000;
const peakMs = 36_000;
const control = process.argv.includes("--control");
assert.ok(process.argv.slice(2).every((argument) => argument === "--control"));
const policy = { batchSize: 24, spiMaxConcurrency: 4, pspMaxConcurrency: 4 };
const scenario = { id: "continuous-recovery", spiDelayMs: 19, pspDelayMs: 17, seed: 91,
  phases: [{ multiplier: 1, ms: rampAtMs }, { multiplier: 4, ms: peakMs }] };
const passed = (window) => window.onTime * 100 >= window.offered * Math.round(PIX_OUTCOME.target * 100);
const root = mkdtempSync(join(tmpdir(), "bv-pix-recover-"));
const offered = buildPixArrivals(scenario.phases, baseRate);
const source = join(root, "combined.sqlite");
let bank;
try {
  bank = new Bank(source);
  seedBank(bank, { customers: offered.length * 2, accounts: offered.length * 2,
    historyTransactions: 0, openWeaknesses: false });
  bank.close();
  bank = undefined;
  exportSplitSnapshots(source, join(root, "bank.sqlite"), join(root, "ecosystem.sqlite"));

  const report = await runPixOutcomeTrial({ source: root, dir: join(root, "adaptive"),
    baseRate, scenario, policy, feedback: { windowMs, recoveryCeiling: 16, enabled: !control } });
  const { windows, decisions, safety, errors } = report;
  console.log(JSON.stringify({ revision: pixOutcomeRevision(), control, scenario, windows, decisions, safety, errors }));
  assert.deepEqual(windows.filter((window) => window.endMs <= rampAtMs).map(passed), [true, true]);
  const peak = windows.filter((window) => window.startMs >= rampAtMs);
  assert.equal(peak.length, peakMs / windowMs);
  assert.ok(peak.every((window) => window.offered === baseRate * 4 * windowMs / 1000));
  const breach = peak.find((window) => !passed(window));
  assert.ok(breach, "The load must cause a real measured breach with the engine running");
  if (control) {
    assert.ok(decisions.every((entry) => entry.reason !== "outcome_breach"));
    assert.ok(peak.slice(-3).every((window) => !passed(window)),
      "The same offered workload must stay below target without the benchmark feedback");
    console.log(JSON.stringify({ verdict: "control_confirmed", normalRate: baseRate,
      peakRate: baseRate * 4, breach, finalWindows: peak.slice(-3) }));
  } else {
    const action = decisions.find((entry) => entry.reason === "outcome_breach" &&
      entry.breachWindowEndMs === breach.endMs && entry.atMs >= breach.measuredAtMs);
    assert.ok(action, "The engine must use the measured breach to scale beyond its normal ceiling");
    const after = peak.filter((window) => window.startMs >= action.atMs);
    const recovery = after.findIndex((_, index) =>
      after.length - index >= 3 && after.slice(index).every(passed));
    assert.ok(recovery >= 0, "The engine must sustain the goal in at least three subsequent peak windows");
    for (const field of ["submitted", "unique", "settled", "confirmed", "protectedRecords"])
      assert.equal(safety[field], offered.length, field);
    assert.equal(safety.duplicates, 0);
    assert.equal(safety.reconciled, true);
    assert.equal(safety.oldestCompleted, report.oldestExpected);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ verdict: "passed", normalRate: baseRate, peakRate: baseRate * 4,
      breach, action, recovered: after.slice(recovery), safety }));
  }
} finally {
  bank?.close();
  rmSync(root, { recursive: true, force: true });
}
