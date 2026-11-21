import { z } from "zod";

const text = z.string();
const count = z.number().int().nonnegative();
const amount = z.number().nonnegative();
const ratio = z.number().min(0).max(1);
export const dossierArea = z.union([z.enum(["auth", "accounts", "pix", "cards", "loans", "api_gateway", "ledger"]),
  z.string().regex(/^lab\/[a-z0-9_]+$/)]);
const entity = z.strictObject({ kind: text, id: text });
const mission = z.strictObject({ mission_id: text, area: dossierArea,
  technique_candidates: z.array(text), hypothesis: text, why_novel: text,
  expected_novelty_class: z.enum(["new_technique", "new_area", "post_patch_variant", "untried_region"]),
  preconditions_hint: z.array(text), priority: z.number().int().min(1).max(5), kill_criteria: text });

export const missionPlanBody = z.strictObject({
  missions: z.array(mission), rejected_ideas: z.array(z.strictObject({ idea: text, reason: text })),
  lateral_decisions: z.array(z.strictObject({ lateral_id: text, decision: z.enum(["accept", "drop"]),
    reason: text, mission_id: text.optional() })).optional(),
});
export const targetDossierBody = z.strictObject({
  mission_id: text, area: dossierArea,
  surface: z.array(z.strictObject({ name: text, kind: z.enum(["endpoint", "flow", "job", "flag"]),
    auth: z.enum(["none", "session", "service"]), controls_observed: z.array(text), notable_behaviors: z.array(text) })),
  weak_signals: z.array(z.strictObject({ signal: text, evidence_call_ids: z.array(text), strength: ratio })),
  honest_baseline: z.strictObject({ typical_amount_brl_p50: amount, typical_rate_per_min: amount, notes: text }),
  suggested_attack_shape: text, preconditions_observed: z.array(text),
  recommended_identity_kinds: z.array(z.enum(["new_account", "low_priv_customer", "high_balance_customer", "api_client"])),
  do_not_try: z.array(text), hypothesis_status: z.enum(["supported", "unsupported", "unclear"]),
});
export const attemptReportBody = z.strictObject({
  mission_id: text, area: dossierArea, technique_id: text,
  outcome: z.enum(["success", "partial", "fail", "aborted"]), preconditions_used: z.array(text),
  claimed_effect: z.strictObject({ kind: z.enum(["money_moved", "privilege_gained", "data_exposed",
    "limit_exceeded", "state_corrupted", "none"]), amount_brl: amount.optional(),
    entities_affected: count.optional(), effect_check_id: text.optional() }),
  evidence: z.array(z.strictObject({ tool_call_id: text, observation: text })),
  defense_observed: z.array(text), why_abstract: text,
  lateral_suggestions: z.array(z.strictObject({ hypothesis: text, area: dossierArea,
    technique_candidates: z.array(text), rationale: text })), stealth_notes: text,
});
export const impactReportBody = z.strictObject({
  breach_mission_id: text,
  pivots: z.array(z.strictObject({ from_area: dossierArea, to_area: dossierArea, mechanism_class: text })),
  impact: z.array(z.strictObject({ kind: z.enum(["money_moved", "privilege_gained", "data_exposed", "persistence"]),
    amount_brl: amount.optional(), entities: count, effect_check_id: text })),
  persistence_artifacts: z.array(z.strictObject({ kind: z.enum(["session", "api_key", "payee", "scheduled_job"]),
    ref: text })), blast_radius: z.enum(["single_account", "multi_account", "cross_area", "systemic"]),
  max_additional_loss_estimate_brl: amount, stopped_by: z.enum(["budget", "defense", "cap", "no_further_path"]),
});
export const incidentDossierBody = z.strictObject({
  incident_id: text, disposition: z.enum(["incident", "false_positive", "needs_human"]), area: dossierArea,
  summary: text, timeline: z.array(z.strictObject({ ts: text, event_ref: text, note: text })),
  root_cause_hypothesis: z.strictObject({ class: z.enum(["missing_check", "wrong_order_of_checks", "race",
    "rounding", "authz_gap", "rate_gap", "rule_gap", "state_machine_gap", "data_exposure", "unknown"]),
    description: text, confidence: ratio, suspected_paths: z.array(text) }),
  affected_entities: z.array(entity), suspected_loss_brl: amount,
  containment_actions: z.array(z.strictObject({ tool: text, args_digest: text, call_id: text,
    expires_at: text, honest_impact_estimate: z.enum(["none", "low", "medium"]) })),
  task: z.strictObject({ title: z.string().trim().min(5).max(160), kind: z.enum(["patch_code", "patch_rule"]),
    priority: z.number().int().min(1).max(3),
    acceptance_invariants: z.array(z.string().max(300)).min(1).max(5),
    do_not_break: z.array(z.string().max(300)).max(5),
    regression_test_ids: z.array(z.string().min(1).max(128)).max(10) }).nullable(),
  unresolved_questions: z.array(text),
});
export const incidentMapBody = z.strictObject({
  incident_id: text, task_id: text, area: dossierArea,
  timeline: z.array(z.strictObject({ ts: z.string().max(40),
    event_ref: z.string().max(128), observation: z.string().max(300) })).max(20),
  entities: z.array(z.strictObject({ kind: z.string().max(40), id: z.string().max(128) })).max(20),
  indicators: z.array(z.strictObject({ kind: z.enum(["account", "device", "session", "trace",
    "end_to_end_id", "rule", "transaction"]), ref: z.string().max(128),
    evidence_refs: z.array(z.string().max(128)).max(6) })).max(20),
  observed_stages: z.array(z.strictObject({ stage: z.enum(["entry", "movement", "persistence", "impact"]),
    observation: z.string().max(300), evidence_refs: z.array(z.string().max(128)).min(1).max(6) })).max(8),
  scope: z.enum(["single_account", "multi_account", "cross_institution", "systemic", "unknown"]),
  evidence_refs: z.array(z.string().max(128)).max(30),
  unresolved_questions: z.array(z.string().max(300)).max(10),
});
export const rootCauseReportBody = z.strictObject({
  incident_id: text, task_id: text, area: dossierArea,
  decision: z.enum(["verified", "needs_human"]),
  class: incidentDossierBody.shape.root_cause_hypothesis.shape.class,
  explanation: z.string().min(1).max(1600),
  flow_point: z.strictObject({ path: z.string().max(160),
    symbol: z.string().max(120), stage: z.string().max(120) }).nullable(),
  violated_invariants: z.array(z.string().max(300)).max(5),
  do_not_break: z.array(z.string().max(300)).max(5),
  regression_ids: z.array(z.string().min(1).max(128)).max(10),
  evidence_refs: z.array(z.string().max(128)).max(20), confidence: ratio,
  unresolved_questions: z.array(z.string().max(300)).max(10),
});
export const fixDesignBody = z.strictObject({
  task_id: text, attempt_no: z.number().int().min(1), approach: z.string().min(1).max(800),
  allowed_paths: z.array(z.string().min(1).max(160)).max(6),
  alternatives: z.array(z.string().max(200)).max(4),
  risks: z.array(z.string().max(200)).max(4),
  acceptance_invariants: z.array(z.string().max(300)).max(8),
  do_not_break: z.array(z.string().max(300)).max(8),
  test_plan: z.array(z.string().max(200)).max(10),
  prior_failures_addressed: z.array(z.string().max(200)).max(6),
  decision: z.enum(["build", "needs_human"]), reason: z.string().min(5).max(300),
});
export const patchDossierBody = z.strictObject({
  task_id: text, attempt_no: z.number().int().min(1), branch: text, head_sha: text,
  root_cause_confirmed: text, approach: text,
  changes: z.array(z.strictObject({ path: text, lines_changed: count, rationale: text })),
  invariants_addressed: z.array(text),
  targeted_test_runs: z.array(z.strictObject({ run_id: text, scope: text, result: z.enum(["pass", "fail"]) })),
  honest_impact_analysis: text, risks: z.array(text), rollback_note: text,
});
export const reviewVerdictBody = z.strictObject({
  task_id: text, attempt_no: z.number().int().min(1), head_sha: text,
  verdict: z.enum(["approve", "reject"]), runs: z.strictObject({ regression_run_id: text,
    honest_run_id: text, scope_check_run_id: text,
    regression: z.strictObject({ total: count, passed: count }),
    honest: z.strictObject({ total: count, passed: count, false_positive_rate: ratio }) }),
  findings: z.array(z.strictObject({ severity: z.enum(["blocker", "major", "minor"]),
    path: text.optional(), issue: text, evidence_run_id: text.optional() })),
  reasons_for_rejection: z.array(text), required_changes: z.array(text),
  residual_risk: z.enum(["low", "medium", "high"]), diff_assessment: text,
});
export const damageReportBody = z.strictObject({
  incident_id: text, check_no: z.union([z.literal(1), z.literal(2)]),
  findings: z.array(z.strictObject({ kind: z.enum(["unreversed_outflow", "external_pix_med", "balance_drift", "live_session",
    "live_key", "scheduled_job", "frozen_honest_account", "data_exposure"]), refs: z.array(text),
    amount_brl: amount, status: z.enum(["open", "clean"]), evidence_call_ids: z.array(text) })),
  total_open_brl: amount, needs_restoration: z.boolean(), invariants_checked: z.array(text),
  residual_risk: z.enum(["low", "medium", "high"]),
});
export const restorationReportBody = z.strictObject({
  incident_id: text, actions: z.array(z.strictObject({ tool: text, ref: text, amount_brl: amount.optional(),
    result: z.enum(["done", "refused", "partial"]), call_id: text, reason: text })),
  restored_brl: amount, remaining_brl: amount, honest_accounts_unfrozen: z.array(text),
  absorbed_by_bank_brl: amount, needs_human: z.boolean(),
});
export const hardeningProposalBody = z.strictObject({
  incident_id: text, decision: z.enum(["propose", "needs_human"]),
  rule: z.strictObject({ id: z.string().regex(/^[A-Z0-9_-]{1,64}$/),
    feature: z.string().min(1).max(80), operator: z.enum(["gte", "lt"]),
    value: z.number().finite().nonnegative(), points: z.number().int().min(1).max(1000),
    reason: z.string().regex(/^[A-Z0-9_-]{1,64}$/) }).nullable(),
  evidence_decision_ids: z.array(z.string().min(1).max(128)).max(50),
  rationale: z.string().min(10).max(800),
  neighboring_controls: z.array(z.string().min(1).max(160)).max(8),
  honest_impact_analysis: z.string().min(5).max(500),
  residual_risk: z.enum(["low", "medium", "high"]),
});
export const hardeningReviewBody = z.strictObject({
  incident_id: text, task_id: text, run_id: text, head_sha: text,
  verdict: z.enum(["approve", "reject"]),
  rationale: z.string().min(10).max(800),
  evidence_checked: z.array(z.string().min(1).max(128)).max(50),
  honest_impact_checked: z.boolean(),
  residual_risk: z.enum(["low", "medium", "high"]),
});
export const postmortemBody = z.strictObject({
  incident_id: text,
  summary_pt: z.string().min(10).max(280),
  learning_pt: z.string().min(10).max(280),
  residual_risk: z.enum(["low", "medium", "high"]),
  confidence: ratio,
});
export const launchBriefBody = z.strictObject({
  feature_id: text, public_title_pt: text, public_summary_pt: text,
  honest_journeys: z.array(z.strictObject({ id: text, description: text, expected: text,
    variant: z.strictObject({ base_id: text, step_index: z.number().int().nonnegative(),
      field: text, value: z.union([z.string(), z.number().int()]) }).optional() })),
  watch_list: z.array(text), launch_recommendation: z.enum(["launch", "hold"]), reason: text,
});
export const narrationBody = z.strictObject({
  headline_pt: text, summary_pt: text,
  chapters: z.array(z.strictObject({ title_pt: text, body_pt: text, event_refs: z.array(text) })),
  takeaway_for_banks_pt: text,
  safety_self_check: z.strictObject({ contains_steps: z.literal(false), contains_identifiers: z.literal(false) }),
});

export const DOSSIER_SCHEMAS = {
  historian: missionPlanBody, scout: targetDossierBody, intruder: attemptReportBody,
  exploiter: impactReportBody, investigator: incidentDossierBody,
  forensic_mapper: incidentMapBody, root_cause_analyst: rootCauseReportBody,
  architect: fixDesignBody, engineer: patchDossierBody,
  reviewer: reviewVerdictBody, damage_assessor: damageReportBody, restorer: restorationReportBody,
  hardening: hardeningProposalBody, postmortem: postmortemBody,
  product: launchBriefBody, narrator: narrationBody,
} as const;
export type DossierRole = keyof typeof DOSSIER_SCHEMAS;
export function parseDossierBody(role: DossierRole, value: unknown): unknown {
  const body = DOSSIER_SCHEMAS[role].parse(value);
  const fields = body as Record<string, unknown>;
  const length = (name: string): number => Array.isArray(fields[name]) ? fields[name].length : 0;
  const within = (name: string, low: number, high: number): void => {
    const size = length(name);
    if (size < low || size > high) throw new Error(`DOSSIER_${role.toUpperCase()}_${name.toUpperCase()}_LIMIT`);
  };
  switch (role) {
    case "historian": within("missions", 1, 5); within("rejected_ideas", 0, 3); break;
    case "scout": within("surface", 0, 8); within("weak_signals", 0, 5); break;
    case "intruder": within("evidence", 0, 6); within("lateral_suggestions", 0, 2); break;
    case "product": within("honest_journeys", 3, 6); break;
    case "narrator": within("chapters", 2, 4); break;
  }
  return body;
}
