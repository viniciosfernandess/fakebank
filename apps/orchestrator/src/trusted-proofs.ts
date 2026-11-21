import type { Area } from "../../../packages/contracts/src/index.ts";

export interface TrustedProof {
  weaknessId: string;
  area: Area;
  patchArea?: Area;
  sentinelRuleId: string;
  regressionId: string;
  source: string;
  symptoms: string[];
}

export const TRUSTED_PROOFS: readonly TrustedProof[] = [];
