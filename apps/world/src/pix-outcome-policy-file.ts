import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { CONSERVATIVE_PIX_POLICY, PIX_OUTCOME, validatePixOutcomePolicy,
  type PixOutcomePolicy } from "./pix-outcome-controller.ts";

export function pixOutcomeRevision(): string {
  const hash = createHash("sha256");
  for (const file of [
    "./pix-outcome-controller.ts", "./pix-outcome-policy-file.ts", "./separated-pix-coordinator.ts",
    "./pix-outbox-commands.ts", "./bank.ts", "./risk/engine.ts",
    "../../ecosystem/src/worker.ts", "../../ecosystem/src/client.ts",
    "../../../scripts/pix-outcome-trial.mjs", "../../../scripts/pix-outcome-review.mjs",
    "../../../scripts/pix-outcome-role.mjs", "../../../scripts/verify-pix-outcome.mjs",
  ]) hash.update(readFileSync(new URL(file, import.meta.url)));
  return hash.digest("hex");
}

export function loadPixOutcomePolicy(path?: string): Readonly<PixOutcomePolicy> {
  if (!path) return CONSERVATIVE_PIX_POLICY;
  const input = JSON.parse(readFileSync(path, "utf8")) as {
    version?: number; revision?: string; goal?: typeof PIX_OUTCOME;
    policy?: PixOutcomePolicy };
  if (!input || input.version !== 1 || input.revision !== pixOutcomeRevision() ||
    input.goal?.target !== PIX_OUTCOME.target || input.goal.deadlineMs !== PIX_OUTCOME.deadlineMs ||
    input.goal.loadMultiplier !== PIX_OUTCOME.loadMultiplier || !input.policy)
    throw new Error("PIX_OUTCOME_POLICY_REVISION_MISMATCH");
  validatePixOutcomePolicy(input.policy);
  return Object.freeze({ ...input.policy });
}
