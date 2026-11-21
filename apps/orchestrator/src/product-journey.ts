import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface JourneyProposal {
  id: string;
  description: string;
  expected: string;
  variant?: { base_id: string; step_index: number; field: string; value: string | number } | undefined;
}
export interface HonestJourneyScenario {
  id: string;
  area: string;
  title: string;
  steps: Record<string, unknown>[];
  clock?: string;
  seedCustomers?: number;
  seedAccounts?: number;
}
export const PRODUCT_VARIANT_FIELDS = ["amount_cents", "limit_cents", "partner_id", "merchant_id", "amountCents"] as const;
const allowedFields = new Set<string>(PRODUCT_VARIANT_FIELDS);

export function compileProductJourneys(repoRoot: string, day: number, area: string,
  proposals: JourneyProposal[]): HonestJourneyScenario[] {
  const baseIds = ["", "a", "b"].map((suffix) => `L${day}${suffix}`);
  if (proposals.length < 4 || proposals.length > 6 ||
    new Set(proposals.map((item) => item.id)).size !== proposals.length ||
    baseIds.some((id) => !proposals.some((item) => item.id === id && !item.variant)))
    throw new Error("PRODUCT_JOURNEY_SET_INVALID");
  const extras = proposals.filter((item) => !baseIds.includes(item.id));
  if (extras.length < 1 || extras.length > 3) throw new Error("PRODUCT_VARIANT_COUNT_INVALID");
  return extras.map((proposal, index) => {
    if (proposal.id !== `P${day}${String.fromCharCode(97 + index)}` ||
      !proposal.description.trim() || !proposal.expected.trim() || !proposal.variant ||
      !baseIds.includes(proposal.variant.base_id)) throw new Error("PRODUCT_VARIANT_INVALID");
    const source = JSON.parse(readFileSync(join(repoRoot, "tests", "honest",
      `${proposal.variant.base_id}.scenario.json`), "utf8")) as HonestJourneyScenario;
    if (source.id !== proposal.variant.base_id || source.area !== area ||
      !Array.isArray(source.steps)) throw new Error("PRODUCT_VARIANT_BASE_INVALID");
    const { step_index: stepIndex, field, value } = proposal.variant;
    const step = source.steps[stepIndex];
    if (!Number.isSafeInteger(stepIndex) || !step || !allowedFields.has(field))
      throw new Error("PRODUCT_VARIANT_FIELD_INVALID");
    const target = step.kind === "request" && step.body && typeof step.body === "object" ?
      step.body as Record<string, unknown> :
      step.kind === "harness" && step.action === "recordVerifiedIncome" ? step : undefined;
    const before = target?.[field];
    if (!target || typeof before !== typeof value || before === value ||
      (typeof value === "number" && (!Number.isSafeInteger(value) || value < 1 || value > 2_000_000)) ||
      (typeof value === "string" && !/^[a-zA-Z0-9_-]{3,40}$/.test(value)))
      throw new Error("PRODUCT_VARIANT_VALUE_INVALID");
    target[field] = value;
    return { ...source, id: proposal.id, title: proposal.description.trim().slice(0, 120) };
  });
}
