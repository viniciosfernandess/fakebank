import { z } from "zod";
import { sanitizePublicEvent, embargoPublicEvent } from "./public-safety.ts";

export const AREAS = ["auth", "accounts", "pix", "cards", "loans", "api_gateway", "ledger"] as const;
export const ROLES = ["historian", "scout", "intruder", "exploiter", "sentinel", "investigator", "forensic_mapper", "root_cause_analyst", "architect", "engineer", "reviewer", "damage_assessor", "restorer", "hardening", "postmortem", "product", "narrator"] as const;
export const AREA = z.enum(AREAS);
export const ROLE = z.enum(ROLES);
export type Area = z.infer<typeof AREA>;
export type Role = z.infer<typeof ROLE>;
export const COMPONENTS = {
  auth: ["login_desk", "mfa_turnstile", "session_vault", "risk_sensor"],
  accounts: ["kyc_desk", "balances", "statements", "account_limits"],
  pix: ["dict_keys", "amount_gate", "night_gate", "frequency_gate", "med_desk", "antifraud"],
  cards: ["issuer", "three_ds_gate", "tokenizer", "chargeback_desk"],
  loans: ["scoring_office", "contract_archive", "collections_desk"],
  api_gateway: ["web_gate", "mobile_gate", "open_finance_gate", "partner_gate", "rate_limiter", "waf"],
  ledger: ["double_entry_book", "vault_door", "audit_tape", "reconciliation_clock", "immutable_seal"],
} as const;

const s = z.string();
const n = z.number();
const i = z.number().int();
const b = z.boolean();
const strList = z.array(s);
const sev = z.enum(["low", "medium", "high", "critical"]);
const publicInstitution = z.enum(["Banco de origem", "Banco Ipê", "Banco Aroeira",
  "Saída externa", "Instituição externa"]);
const obj = <T extends z.ZodRawShape>(shape: T) => z.strictObject(shape);
const sentinelStats = z.record(AREA, obj({ state: z.enum(["ok", "alerting", "degraded", "silent"]),
  checks_total: i.nonnegative(), alerts_24h: i.nonnegative() }));
export const TELEMETRY_FRAME = obj({ ts: s, telemetry: obj({ checked_at: s, areas: sentinelStats,
  by_area: z.partialRecord(AREA, i.nonnegative()), honest_blocked: i.nonnegative() }).nullable() });
export type LiveTelemetry = NonNullable<z.infer<typeof TELEMETRY_FRAME>["telemetry"]>;
const score = obj({ red_points: n, blue_points: n, attacks_succeeded: i, attacks_total: i,
  mttd_s: n.nullable(), mttc_s: n.nullable().optional(), mttr_s: n.nullable(),
  honest_wrongly_blocked: i, loss_cents: i, restored_cents: i });

export const PUBLIC_PAYLOADS = {
  "round.scheduled": obj({ round_no: i, starts_at: s, slot: z.enum(["09:00", "18:00", "manual"]) }),
  "round.started": obj({ round_no: i, feature_ids_live: strList, open_weaknesses_count: i }),
  "round.ended": obj({ status: z.enum(["completed", "aborted", "partial"]), score, summary_pt: s, duration_s: n, reason: s.optional() }),
  "round.aborted": obj({ reason_code: s }),
  "agent.spawned": obj({ agent_id: s, role: ROLE, area: AREA.optional(), goal_pt: s }),
  "agent.spawn_denied": obj({ role: ROLE, reason: s }),
  "agent.finished": obj({ agent_id: s, outcome: z.enum(["ok", "fallback", "escalated", "refused", "timeout", "failed", "cancelled"]), tokens: i.optional() }),
  "context.handoff": obj({ from: s, to: s, dossier_kind: s, summary_pt: s,
    kind: s.optional(), context_sha256: s.regex(/^[a-f0-9]{64}$/).optional(),
    inherited: strList.optional() }),
  "tool.called": obj({ tool: s, ok: b, kind: z.enum(["recon", "action", "investigate", "contain", "restore", "ci", "code"]), label_pt: s.optional() }),
  "integrity.violation": obj({ kind: s, area: AREA.optional(), reason_pt: s }),
  "attack.attempted": obj({ attack_id: s, class: z.enum(["fraud", "logic", "api"]), technique_label: s, target_area: AREA, persona: z.enum(["P1", "P2", "P3", "P4", "P5", "outsider"]) }),
  "attack.succeeded": obj({ attack_id: s, weakness_class_label: s, invariant_label_pt: s }),
  "attack.failed": obj({ attack_id: s, blocked_by: z.enum(["rule", "sentinel", "validation", "unknown"]), decoy: b.optional() }),
  "impact.caused": obj({ attack_id: s, loss_cents: i, exposure_cents: i, records_exposed: i, customers_affected: i, deferred: b.optional() }),
  "money_flow.disclosed": obj({ incident_id: s,
    edges: z.array(obj({ from: publicInstitution, to: publicInstitution,
      kind: z.enum(["payment", "transfer", "cashout"]) })).max(1000) }),
  "money_flow.med_updated": z.union([
    obj({ incident_id: s, disclosure_seq: i.positive(),
      status: z.enum(["open", "refunded", "resolved", "rejected"]),
      recovery: z.enum(["pending", "none", "partial", "full"]),
      institutions: z.array(obj({ name: publicInstitution,
        state: z.enum(["held", "recovered", "mixed", "released"]) })).max(50),
      accounts: z.array(obj({ name: publicInstitution, slot: i.positive(),
        state: z.enum(["held", "recovered", "mixed", "released"]) })).max(100)
        .optional() }),
    obj({ incident_id: s, disclosure_seq: i.positive(), masked: z.literal(true) }),
  ]),
  "ledger.hourly_proof": obj({ hour_start: s.datetime({ offset: true }),
    root_sha256: s.regex(/^[a-f0-9]{64}$/), entries: i.nonnegative(),
    net_cents: i }),
  "ecosystem.cross_book_check": obj({ ok: z.literal(true),
    report_sha256: s.regex(/^[a-f0-9]{64}$/) }),
  "sentinel.alert": obj({ alert_id: s, rule_id: s, severity: sev, area: AREA, pattern_label: s }),
  "sentinel.status": obj({ area: AREA, state: z.enum(["ok", "alerting", "degraded", "silent"]), last_tick_s_ago: n, alerts_24h: i }),
  "incident.opened": obj({ incident_id: s, severity: sev, area: AREA, alert_count: i, source: z.enum(["sentinel", "audit"]).optional() }),
  "incident.updated": obj({ incident_id: s, state: z.enum(["open", "contained", "patching", "awaiting_next_window", "needs_human", "resolved", "unresolved"]) }),
  "containment.applied": obj({ action: z.enum(["freeze_account", "revoke_session", "revoke_api_key", "block_route", "disable_flag", "quarantine_area"]), scope_label_pt: s, ttl_s: n.optional(), collateral_honest: i }),
  "containment.renewed": obj({ incident_id: s, actions: i.nonnegative(), ttl_s: i.positive() }),
  "task.opened": obj({ task_id: s, incident_id: s, title_pt: s, area: AREA, severity: sev }),
  "patch.proposed": obj({ task_id: s, attempt: i.min(1), files_changed: i, lines_added: i, lines_removed: i, kind: z.enum(["code", "rule"]), summary_pt: s }),
  "review.rejected": obj({ task_id: s, attempt: i, reason_pt: s, failing_suites: strList }),
  "review.approved": obj({ task_id: s, attempt: i, ci_run_id: s, checks: z.record(s, z.literal("pass")) }),
  "patch.merged": obj({ task_id: s, commit_short: s, kind: z.enum(["code", "rule"]),
    phase: z.enum(["fix", "hardening"]).optional() }),
  "deploy.succeeded": obj({ task_id: s, mode: z.enum(["hot_reload", "blue_green", "restart"]), version: s, duration_s: n, defensive_diff_public: s.optional() }),
  "deploy.rolled_back": obj({ task_id: s, reason_code: z.enum(["health", "errors", "latency", "honest_probe", "false_block", "drift", "alert"]), version_back_to: s }),
  "regression.result": obj({ run_id: s, suite: z.enum(["regression", "honest", "invariants", "decoys", "unit", "red_first"]), kind: z.enum(["proof", "ci"]).optional(), pass: i, fail: i, total: i, added_test_id: s.optional() }),
  "damage.assessed": obj({ incident_id: s, loss_cents: i, customers_affected: i, exposure_cents: i,
    summary_pt: s, blocked_cents: i.optional(), escaped_cents: i.optional() }),
  "damage.restored": obj({ incident_id: s, restored_cents: i, customers_made_whole: i,
    drift_after_cents: i, recovered_cents: i.optional(), absorbed_cents: i.optional() }),
  "postmortem.published": obj({ incident_id: s, timeline_steps: i.nonnegative(),
    summary_pt: s,
    mttd_s: n.nullable(), mtta_s: n.nullable(), mttc_s: n.nullable(),
    mttr_fix_s: n.nullable(), mttr_recovery_s: n.nullable(),
    loss_cents: i.nonnegative(), recovered_cents: i.nonnegative(),
    absorbed_cents: i.nonnegative(), permanent_actions: i.nonnegative() }),
  "postmortem.narrated": obj({ incident_id: s, summary_pt: s,
    learning_pt: s, residual_risk: z.enum(["low", "medium", "high"]) }),
  "area.quarantined": obj({ area: AREA, reason_pt: s, reason: z.enum(["rejections", "budget", "needs_human"]).optional(), task_id: s.optional() }),
  "area.released": obj({ area: AREA }),
  "feature.launched": obj({ feature_id: s, area: AREA, name_pt: s, summary_pt: s, day: i }),
  "flag.changed": obj({ key: s, enabled: b, by: s }),
  "sim.tick": obj({ minute: s, ops: i, approvals_pct: n, honest_blocked: i, false_block_rate: n,
    pix_deferred: i.nonnegative().optional(),
    by_area: z.partialRecord(AREA, i).optional(), sentinels: sentinelStats.optional(),
    risk_queue_pending: i.nonnegative().optional(), spi_reconciled: b.optional(),
    spi_available: b.optional() }),
  "sim.card_retry": obj({ outcome: z.literal("authorized") }),
  "invariant.checked": obj({ ok: b, drift_cents: i, at: s }),
  "memory.updated": obj({ entries_added: i, note_pt: s.optional() }),
  "score.updated": obj({ red: n, blue: n, delta: n, reason: s, collateral: n.optional() }),
  "health.updated": obj({ overall: n.min(0).max(100), areas: z.record(AREA, n.min(0).max(100)) }),
  "cost.updated": obj({ round_cost_usd: n, total_cost_usd: n, budget_left_usd: n, by_role: z.record(s, n).optional(), capped: b.optional() }),
  "usage.updated": obj({ agents: i.nonnegative(), turns: i.nonnegative(),
    input_tokens: i.nonnegative(), output_tokens: i.nonnegative(),
    cached_input_tokens: i.nonnegative(), wall_ms: i.nonnegative() }),
  "narration.published": obj({ text_pt: s, severity: z.enum(["info", "warn", "good", "bad"]), refs: z.array(i),
    headline_pt: s.optional(), summary_pt: s.optional(), takeaway_for_banks_pt: s.optional(),
    chapters: z.array(obj({ title_pt: s, body_pt: s, refs: z.array(i) })).optional() }),
} as const;

export type EventType = keyof typeof PUBLIC_PAYLOADS;
export const EVENT_TYPES = Object.keys(PUBLIC_PAYLOADS) as EventType[];
export interface ArenaEvent<T extends EventType = EventType> {
  id: string; seq: number; round_id: string | null; ts: string; twin_ts?: string;
  type: T; actor: { id: string; role: Role | "system" | "sim" };
  parent_actor_id?: string; area?: Area; incident_id?: string; task_id?: string;
  public_summary_pt: string; public: Record<string, unknown>; private?: Record<string, unknown>;
}
const base = obj({ id: s, seq: i.positive(), round_id: s.nullable(), ts: z.iso.datetime(), twin_ts: z.iso.datetime().optional(),
  type: z.enum(EVENT_TYPES as [EventType, ...EventType[]]), actor: obj({ id: s, role: z.union([ROLE, z.enum(["system", "sim"])]) }),
  parent_actor_id: s.optional(), area: AREA.optional(), incident_id: s.optional(), task_id: s.optional(),
  public_summary_pt: s.max(160), public: z.record(s, z.unknown()), private: z.record(s, z.unknown()).optional() });

export function parseEvent(value: unknown): ArenaEvent {
  const envelope = base.parse(value);
  const schema = PUBLIC_PAYLOADS[envelope.type];
  const publicInput = { ...envelope.public };
  // Old replay files contain this field; new events retain strict payload schemas.
  if (envelope.type === "round.started") delete publicInput.budget_usd;
  const publicPayload = schema.parse(publicInput) as Record<string, unknown>;
  return { ...envelope, public: publicPayload } as ArenaEvent;
}

export function publicView(event: ArenaEvent, disclosedAttackIds: ReadonlySet<string> = new Set()): Omit<ArenaEvent, "private"> {
  const { private: _private, ...visible } = sanitizePublicEvent(embargoPublicEvent(event, disclosedAttackIds));
  return visible;
}

export function exportPublicJsonSchemas(): Record<EventType, unknown> {
  return Object.fromEntries(EVENT_TYPES.map((type) => [type, z.toJSONSchema(PUBLIC_PAYLOADS[type])])) as Record<EventType, unknown>;
}
