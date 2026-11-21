import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdtempSync, readFileSync, renameSync, rmSync,
  writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Bank } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { PIX_OUTCOME } from "../apps/world/src/pix-outcome-controller.ts";
import { pixOutcomeRevision } from "../apps/world/src/pix-outcome-policy-file.ts";
import { exportSplitSnapshots } from "./export-ecosystem-snapshot.mjs";
import { buildPixArrivals, runPixOutcomeTrial } from "./pix-outcome-trial.mjs";

const quick = process.argv.includes("--quick");
const baseRate = 32;
const peakMs = quick ? 8_000 : 30_000;
const discovery = [{
  id: "gradual", spiDelayMs: 25, pspDelayMs: 0, seed: 1,
  phases: [{ multiplier: 1, ms: 1_500 }, { multiplier: 2, ms: 1_500 },
    { multiplier: 3, ms: peakMs }],
}, {
  id: "sudden", spiDelayMs: 0, pspDelayMs: 25, seed: 3,
  phases: [{ multiplier: 1, ms: 1_500 }, { multiplier: 3, ms: peakMs }],
}];
const reserved = {
  id: "reserved", spiDelayMs: 18, pspDelayMs: 15, seed: 41,
  phases: [{ multiplier: 1, ms: 2_000 }, { multiplier: 3, ms: peakMs },
    { multiplier: 1, ms: 1_500 }],
};
const print = (data) => console.log(JSON.stringify(data));
const roleScript = fileURLToPath(new URL("./pix-outcome-role.mjs", import.meta.url));
const askRole = (role, input) => {
  const child = spawnSync(process.execPath, ["--disable-warning=ExperimentalWarning",
    "--experimental-strip-types", roleScript, role], {
    input: JSON.stringify(input), encoding: "utf8", timeout: 5_000,
  });
  assert.equal(child.status, 0, child.error?.message ?? child.stderr);
  return JSON.parse(child.stdout);
};
const args = process.argv.slice(2).filter((arg) => arg !== "--quick");
assert.ok(args.every((arg) => arg.startsWith("--memory=") || arg.startsWith("--publish=")));
const option = (name) => {
  const raw = args.find((arg) => arg.startsWith("--" + name + "="));
  return raw ? resolve(raw.slice(name.length + 3)) : null;
};
const memoryFile = option("memory");
const publishFile = option("publish");
assert.ok(!quick || !publishFile, "Quick checks cannot promote a policy");
const memory = memoryFile && existsSync(memoryFile) ?
  readFileSync(memoryFile, "utf8").split("\n").filter(Boolean).map(JSON.parse) : [];
const revision = pixOutcomeRevision();
const remember = (entry) => {
  memory.push(entry);
  if (memoryFile) appendFileSync(memoryFile, JSON.stringify(entry) + "\n", { mode: 0o600 });
};
const root = mkdtempSync(join(tmpdir(), "bv-pix-outcome-"));
const all = [...discovery, reserved, { phases: [
  { multiplier: 1, ms: 1_250 }, { multiplier: 2, ms: 1_000 },
  { multiplier: 3, ms: peakMs }, { multiplier: 1, ms: 1_000 },
] }];
const maxTransfers = Math.max(...all.map((plan) => buildPixArrivals(plan.phases, baseRate).length));
const source = join(root, "combined.sqlite");
const run = async (scenario, name, policy, guardOptions) => {
  const trial = await runPixOutcomeTrial({ source: root, dir: join(root, scenario.id + "-" + name),
    scenario, baseRate, policy });
  const arrivals = buildPixArrivals(scenario.phases, baseRate);
  const expectedPhases = scenario.phases.map(({ multiplier }, index) => ({
    multiplier, offered: arrivals.filter((item) => item.phase === index).length,
  }));
  const verdict = askRole("guard", { trial, expectedPhases, guardOptions });
  print({ scenario: scenario.id, mode: name, quick, policy, verdict, ...trial });
  return { trial, verdict };
};
let bank;
try {
  bank = new Bank(source);
  seedBank(bank, { customers: maxTransfers * 2, accounts: maxTransfers * 2,
    historyTransactions: 0, openWeaknesses: false });
  bank.close();
  bank = undefined;
  exportSplitSnapshots(source, join(root, "bank.sqlite"), join(root, "ecosystem.sqlite"));
  const policy = { batchSize: 24, spiMaxConcurrency: 1, pspMaxConcurrency: 1 };
  const pendingPromotions = [];
  for (const scenario of discovery) {
    const baseline = await run(scenario, "baseline", null);
    if (baseline.verdict.passed) continue;
    const experimentKey = createHash("sha256")
      .update(JSON.stringify({ revision, goal: PIX_OUTCOME, baseRate, scenario })).digest("hex");
    const tried = [];
    let accepted = false;
    for (let attempt = 0; attempt < 3; attempt++) {
      const plan = askRole("architect", { report: { timings: baseline.trial.timings },
        key: experimentKey, memory: memory.filter((row) => row.experimentKey === experimentKey).slice(-32), tried });
      if (!plan) break;
      tried.push(plan.policy);
      const candidate = await run(scenario, "candidate-" + attempt, plan.policy);
      const entry = { ...plan, experimentKey, revision, scenario: scenario.id,
        recordedAt: new Date().toISOString(), result: candidate.verdict,
        benchmark: candidate.trial.byPhase };
      if (!candidate.verdict.passed) {
        remember({ ...entry, verdict: "rejected" });
        continue;
      }
      pendingPromotions.push(entry);
      policy.spiMaxConcurrency = Math.max(policy.spiMaxConcurrency, plan.policy.spiMaxConcurrency);
      policy.pspMaxConcurrency = Math.max(policy.pspMaxConcurrency, plan.policy.pspMaxConcurrency);
      accepted = true;
      break;
    }
    assert.ok(accepted, "No policy reached the outcome for " + scenario.id);
  }
  if (!quick) {
    const composition = { ...reserved, id: "composition" };
    const headroom = { requireHeadroom: true };
    const combined = await run(composition, "combined-policy", policy, headroom);
    if (!combined.verdict.passed) {
      const key = createHash("sha256").update(JSON.stringify({ revision, goal: PIX_OUTCOME,
        baseRate, composition })).digest("hex");
      let accepted = false;
      const tried = [{ ...policy }];
      remember({ experimentKey: key, stage: "combined", revision, scenario: composition.id,
        policy: { ...policy }, verdict: "rejected", result: combined.verdict,
        benchmark: combined.trial.byPhase });
      for (let attempt = 0; attempt < 3; attempt++) {
        const plan = askRole("architect", { report: { timings: combined.trial.timings },
          key, memory: memory.filter((row) => row.experimentKey === key).slice(-32), tried });
        if (!plan) break;
        const candidatePolicy = { ...plan.policy, batchSize: policy.batchSize,
          spiMaxConcurrency: Math.max(policy.spiMaxConcurrency, plan.policy.spiMaxConcurrency),
          pspMaxConcurrency: Math.max(policy.pspMaxConcurrency, plan.policy.pspMaxConcurrency) };
        tried.push(plan.policy, candidatePolicy);
        const trial = await run(composition, "combined-" + attempt, candidatePolicy, headroom);
        const entry = { ...plan, policy: candidatePolicy, experimentKey: key, revision,
          scenario: composition.id, recordedAt: new Date().toISOString(), result: trial.verdict,
          benchmark: trial.trial.byPhase };
        if (!trial.verdict.passed) {
          remember({ ...entry, verdict: "rejected" });
          continue;
        }
        pendingPromotions.push(entry);
        Object.assign(policy, candidatePolicy);
        accepted = true;
        break;
      }
      assert.ok(accepted, "No policy reached the combined-stage outcome");
    }
    const fresh = { ...reserved, spiDelayMs: 16, pspDelayMs: 18, seed: 67,
      phases: [{ multiplier: 1, ms: 1_250 }, { multiplier: 2, ms: 1_000 },
        { multiplier: 3, ms: peakMs }, { multiplier: 1, ms: 1_000 }] };
    for (const scenario of [fresh, { ...fresh, id: "reserved-ramp", spiDelayMs: 20,
      pspDelayMs: 16, seed: 103 }]) {
      const holdout = await run(scenario, "holdout", policy);
      if (!holdout.verdict.passed) remember({ revision, scenario: scenario.id,
        policy: { ...policy }, verdict: "rejected", result: holdout.verdict,
        benchmark: holdout.trial.byPhase });
      assert.ok(holdout.verdict.passed, holdout.verdict.issues.join(", "));
    }
    for (const entry of pendingPromotions) remember({ ...entry, verdict: "promoted" });
    if (publishFile) {
      const next = join(dirname(publishFile), "." + process.pid + "-pix-outcome-next.json");
      writeFileSync(next, JSON.stringify({ version: 1, goal: PIX_OUTCOME,
        revision, policy }, null, 2) + "\n", { mode: 0o600, flag: "wx" });
      try { renameSync(next, publishFile); }
      finally { rmSync(next, { force: true }); }
    }
  }
  print({ outcome: quick ? "quick-check-passed" : "verified", revision, policy,
    trained: pendingPromotions.map((item) => ({ scenario: item.scenario, stage: item.stage })) });
} finally {
  bank?.close();
  rmSync(root, { recursive: true, force: true });
}
