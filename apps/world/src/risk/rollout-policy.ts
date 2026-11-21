import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export interface RiskRolloutPolicy {
  version: 1;
  min_shadow_minutes: number;
  min_labeled_honest_decisions: number;
  max_incremental_false_block_rate: number;
  max_unlabeled_fraction: number;
}

export function loadRiskRolloutPolicy(path = fileURLToPath(
  new URL("../../../../rules/risk/rollout.json", import.meta.url))):
  { policy: RiskRolloutPolicy; hash: string; bytes: string } {
  const bytes = readFileSync(path, "utf8");
  const value: unknown = JSON.parse(bytes);
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("RISK_ROLLOUT_POLICY_INVALID");
  const policy = value as Record<string, unknown>;
  if (Object.keys(policy).sort().join(",") !== ["max_incremental_false_block_rate",
    "max_unlabeled_fraction", "min_labeled_honest_decisions", "min_shadow_minutes",
    "version"].join(",") || policy.version !== 1 ||
    !Number.isSafeInteger(policy.min_shadow_minutes) ||
    (policy.min_shadow_minutes as number) < 1440 ||
    !Number.isSafeInteger(policy.min_labeled_honest_decisions) ||
    (policy.min_labeled_honest_decisions as number) < 1000 ||
    typeof policy.max_incremental_false_block_rate !== "number" ||
    !Number.isFinite(policy.max_incremental_false_block_rate) ||
    policy.max_incremental_false_block_rate < 0 ||
    policy.max_incremental_false_block_rate !== 0 ||
    typeof policy.max_unlabeled_fraction !== "number" ||
    !Number.isFinite(policy.max_unlabeled_fraction) ||
    policy.max_unlabeled_fraction < 0 || policy.max_unlabeled_fraction > 0.05)
    throw new Error("RISK_ROLLOUT_POLICY_INVALID");
  return { policy: policy as unknown as RiskRolloutPolicy,
    hash: createHash("sha256").update(bytes).digest("hex"), bytes };
}
