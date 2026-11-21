import { createHash } from "node:crypto";
import { readLabIdentityEmptyResponse } from "../../world/src/incident-notices.ts";
import { automaticPixPosting } from "../../world/src/pix-automatic.ts";
import { hasMedCustomerCredit, readMedIncidentCompensation } from
  "../../world/src/med-incident-compensation.ts";
import { medCompletionEvidence } from "./med-completion-evidence.ts";
import { readContainedIdentityWindow, readIdentityFinancialWindow } from "./identity-session-activity.ts";
import { readIdentityPixFollowup } from "./identity-pix-followup.ts";
import { readFaultReplay } from "./fault-replay-evidence.ts";
import type { DatabaseSync } from "node:sqlite";
import type { CrossBookObservation } from "./cross-book-summary.ts";
import type { FaultId, FaultRunPublic } from "./fault-lab.ts";

export type EvidenceState = "verified" | "pending" | "inconclusive" | "not_applicable";
export interface EvidenceStage {
  state: EvidenceState;
  reason: string;
  evidence_refs: string[];
}
export interface FixtureEvaluation {
  fixture_id: FaultId;
  symptom: EvidenceStage;
  detection: EvidenceStage;
  case: EvidenceStage;
  response: EvidenceStage;
  continuity: EvidenceStage;
  customer_repair: EvidenceStage;
  reconciliation: EvidenceStage;
  watch: EvidenceStage;
  verdict: "pending" | "passed" | "inconclusive";
}
export interface FaultEvaluation {
  run_id: string;
  status: FaultRunPublic["status"];
  verdict: "pending" | "passed" | "inconclusive";
  fixtures: FixtureEvaluation[];
}

type Alert = { id: string; rule_id: string; entity: string;
  first_seen: string; last_seen: string; observed_json: string };
type Emission = { ref: string; observed: Record<string, unknown> };
type Source = { db: DatabaseSync };
type RunSource = { run(runId: string): FaultRunPublic | undefined };
const stage = (state: EvidenceState, reason: string,
  evidence_refs: string[] = []): EvidenceStage => ({ state, reason, evidence_refs });
const terminal = (run: FaultRunPublic): boolean =>
  ["stopped", "expired", "failed", "cleanup_failed"].includes(run.status);
const unknown = (run: FaultRunPublic, reason: string): EvidenceStage =>
  stage(terminal(run) ? "inconclusive" : "pending", reason);
const json = (value: string): Record<string, unknown> => {
  try {
    const parsed: unknown = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ?
      parsed as Record<string, unknown> : {};
  } catch { return {}; }
};
const table = (db: DatabaseSync, name: string): boolean => Boolean(db.prepare(
  "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name));

/** Operator-only read model. Its private fixture oracle must never reach defense agents. */
export class FaultLabEvaluator {
  private readonly source: { lab: RunSource; bank: Source; events: Source;
    reconcile?: () => { ok: boolean }; now?: () => Date };
  constructor(source: { lab: RunSource; bank: Source; events: Source;
    reconcile?: () => { ok: boolean }; now?: () => Date }) { this.source = source; }

  evaluate(runId: string, crossBook: CrossBookObservation | null = null):
    FaultEvaluation | undefined {
    const run = this.source.lab.run(runId);
    if (!run) return undefined;
    const fixtures = run.results.map((result) => this.evaluateFixture(run, result,
      crossBook));
    return { run_id: run.id, status: run.status, fixtures,
      verdict: fixtures.every((item) => item.verdict === "passed") ? "passed" :
        fixtures.some((item) => item.verdict === "pending") ? "pending" : "inconclusive" };
  }

  private alert(id: string): Alert | undefined {
    const db = this.source.bank.db;
    return table(db, "sentinel_alerts") ? db.prepare(`SELECT id,rule_id,entity,
      first_seen,last_seen,observed_json FROM sentinel_alerts WHERE id=?`)
      .get(id) as Alert | undefined : undefined;
  }
  private alertBy(rule: string, entity: string): Alert | undefined {
    const db = this.source.bank.db;
    return table(db, "sentinel_alerts") ? db.prepare(`SELECT id,rule_id,entity,
      first_seen,last_seen,observed_json FROM sentinel_alerts
      WHERE rule_id=? AND entity=?`).get(rule, entity) as Alert | undefined : undefined;
  }
  private emission(alert: Alert, run: FaultRunPublic,
    matches: (observed: Record<string, unknown>) => boolean = () => true,
    atOrAfterTwin?: string):
    Emission | undefined {
    const db = this.source.events.db;
    if (!table(db, "events") || !table(db, "event_private")) return;
    const rows = db.prepare(`SELECT e.seq,e.twin_ts,e.public_json,p.private_json
      FROM events e JOIN event_private p ON p.seq=e.seq
      WHERE e.type='sentinel.alert' AND e.ts>=? AND e.ts<=?
      ORDER BY e.seq`).all(run.started_at, run.stopped_at ?? run.expires_at) as
      { seq: number; twin_ts: string | null; public_json: string;
        private_json: string }[];
    for (const row of rows) {
      const publicData = json(row.public_json);
      const privateData = json(row.private_json);
      const observed = privateData.observed;
      if (publicData.alert_id === alert.id &&
        publicData.rule_id === alert.rule_id &&
        privateData.entity === alert.entity &&
        (!atOrAfterTwin || (row.twin_ts !== null &&
          row.twin_ts >= atOrAfterTwin)) &&
        observed && typeof observed === "object" && !Array.isArray(observed) &&
        matches(observed as Record<string, unknown>))
        return { ref: `events:${row.seq}`,
          observed: observed as Record<string, unknown> };
    }
    return;
  }
  private caseFor(alert: Alert, run: FaultRunPublic):
    { id: string; entry: number; version: number | null } | undefined {
    const db = this.source.events.db;
    if (!table(db, "defense_cases") || !table(db, "incident_case_entries")) return;
    const row = db.prepare(`SELECT e.id,e.incident_id,e.payload_json FROM
      incident_case_entries e JOIN defense_cases c ON c.incident_id=e.incident_id
      WHERE e.kind='defense.observed' AND e.created_at>=?
      AND EXISTS (SELECT 1 FROM json_each(e.payload_json,'$.alert_refs')
        WHERE value=?) ORDER BY e.id DESC LIMIT 1`)
      .get(run.started_at, `sentinel_alerts:${alert.id}`) as
      { id: number; incident_id: string; payload_json: string } | undefined;
    const rawVersion = row && json(row.payload_json).case_version;
    return row ? { id: row.incident_id, entry: row.id,
      version: Number.isSafeInteger(rawVersion) && Number(rawVersion) > 0 ?
        Number(rawVersion) : null } : undefined;
  }
  private feeRepairFor(linked: { id: string; version: number | null },
    alert: Alert): { entry: number; ledgerTxId: string; headSha: string } | undefined {
    if (!linked.version || !table(this.source.bank.db, "defense_fee_drift_repairs"))
      return;
    const entries = this.source.events.db.prepare(`SELECT id,kind,payload_json
      FROM incident_case_entries WHERE incident_id=? AND
      kind IN ('defense.code_review_approved','defense.code_bank_gate',
        'defense.code_merged',
        'defense.fee_repair_verified') ORDER BY id`).all(linked.id) as
      { id: number; kind: string; payload_json: string }[];
    const approved = entries.find((entry) => entry.kind ===
      "defense.code_review_approved");
    const gate = entries.find((entry) => entry.kind ===
      "defense.code_bank_gate" &&
      json(entry.payload_json).case_version === linked.version);
    const merged = entries.find((entry) => entry.kind === "defense.code_merged" &&
      json(entry.payload_json).case_version === linked.version);
    const repair = entries.find((entry) => entry.kind ===
      "defense.fee_repair_verified" &&
      json(entry.payload_json).case_version === linked.version);
    if (!approved || !gate || !merged || !repair ||
      !(approved.id < gate.id && gate.id < merged.id && merged.id < repair.id)) return;
    const approval = json(approved.payload_json);
    const gateResult = json(gate.payload_json);
    const promotion = json(merged.payload_json);
    const outcome = json(repair.payload_json);
    const head = approval.head_sha;
    const ci = approval.ci_run_id;
    if (typeof head !== "string" || typeof ci !== "string" ||
      head !== promotion.head_sha ||
      head !== outcome.head_sha || ci !== promotion.ci_run_id ||
      ci !== outcome.ci_run_id || ci !== gateResult.ci_run_id ||
      head !== gateResult.head_sha ||
      typeof gateResult.tests !== "number" || gateResult.tests < 1_000 ||
      !/^[a-f0-9]{64}$/.test(String(gateResult.output_sha256)) ||
      outcome.alert_id !== alert.id ||
      outcome.bank_reconciled !== true ||
      outcome.customer_repair !== "no_customer_overcharge" ||
      typeof outcome.ledger_tx_id !== "string" ||
      !table(this.source.events.db, "patch_ci_runs") ||
      !(this.source.events.db.prepare(`SELECT 1 FROM patch_ci_runs WHERE id=?
        AND candidate_sha=? AND state='merged'`).get(ci, head))) return;
    const bank = this.source.bank.db;
    const receipt = bank.prepare(`SELECT transaction_id,amount_cents,
      fee_transactions FROM defense_fee_drift_repairs WHERE incident_id=?`)
      .get(linked.id) as { transaction_id: string; amount_cents: number;
        fee_transactions: number } | undefined;
    const rounding = bank.prepare(`SELECT id,balance_cached FROM accounts
      WHERE kind='system' AND system_role='rounding'`).get() as
      { id: string; balance_cached: number } | undefined;
    const loss = bank.prepare(`SELECT id FROM accounts WHERE kind='system'
      AND system_role='bank_loss'`).get() as { id: string } | undefined;
    if (!receipt || !rounding || !loss || rounding.id !== alert.entity ||
      rounding.balance_cached !== 0 ||
      receipt.transaction_id !== outcome.ledger_tx_id ||
      receipt.amount_cents !== outcome.bank_loss_cents ||
      receipt.fee_transactions !== outcome.fee_transactions ||
      receipt.amount_cents < 500 || receipt.fee_transactions !== receipt.amount_cents ||
      this.source.reconcile?.().ok !== true) return;
    const lines = bank.prepare(`SELECT account_id,amount FROM ledger_entries
      WHERE tx_id=? AND ref_type='sentinel_incident' AND ref_id=?`)
      .all(receipt.transaction_id, linked.id) as
      { account_id: string; amount: number }[];
    if (lines.length !== 2 || !lines.some((line) =>
      line.account_id === rounding.id && line.amount === receipt.amount_cents) ||
      !lines.some((line) => line.account_id === loss.id &&
        line.amount === -receipt.amount_cents)) return;
    return { entry: repair.id, ledgerTxId: receipt.transaction_id,
      headSha: head };
  }
  private reviewedReplay(linked: { id: string; version: number | null }, alert: Alert,
    receipt: { id: number; payload_json: string }): { planId: number; reviewId: number } | undefined {
    const replay = readFaultReplay(this.source.bank.db,
      { ...alert, observed: json(alert.observed_json) });
    const provenance = json(receipt.payload_json).replay_approval as
      { run_id?: unknown; plan_entry_id?: unknown; review_entry_id?: unknown } | undefined;
    if (!linked.version || !replay || provenance?.run_id !== replay.runId ||
      typeof provenance.plan_entry_id !== "number" || typeof provenance.review_entry_id !== "number" ||
      !(provenance.plan_entry_id < provenance.review_entry_id &&
        provenance.review_entry_id < receipt.id)) return;
    const db = this.source.events.db;
    const entry = db.prepare(`SELECT payload_json,actor_id FROM incident_case_entries
      WHERE incident_id=? AND id=? AND kind=?`);
    type DossierRow = { payload_json: string; actor_id: string };
    const plan = entry.get(linked.id, provenance.plan_entry_id,
      "dossier.defense_plan") as DossierRow | undefined;
    const review = entry.get(linked.id, provenance.review_entry_id,
      "dossier.defense_review") as DossierRow | undefined;
    if (!plan || !review || !plan.actor_id.startsWith("architect_") ||
      !review.actor_id.startsWith("reviewer_")) return;
    const assessments = db.prepare(`SELECT payload_json FROM incident_case_entries
      WHERE incident_id=? AND id<? AND kind='dossier.defense_impact'`)
      .all(linked.id, provenance.review_entry_id) as { payload_json: string }[];
    const planned = json(plan.payload_json);
    const approved = json(review.payload_json);
    const refs = (value: unknown) => Array.isArray(value) &&
      replay.evidenceRefs.every((ref) => value.includes(ref));
    const scopedImpact = assessments.some((row) => {
      const impact = json(row.payload_json);
      return impact.incident_id === linked.id && impact.case_version === linked.version &&
        Array.isArray(impact.findings) && impact.findings.some((value: unknown) => {
          if (!value || typeof value !== "object") return false;
          const finding = value as Record<string, unknown>;
          return finding.kind === (replay.kind === "verify_identity_containment" ? "access" : "money_candidate") &&
            finding.entity_ref === replay.targetId && finding.amount_cents === replay.amountCents &&
            refs(finding.evidence_refs);
        });
    });
    if (!scopedImpact || planned.incident_id !== linked.id || approved.incident_id !== linked.id ||
      planned.case_version !== linked.version || approved.case_version !== linked.version ||
      typeof planned.revision !== "number" || planned.revision !== approved.revision ||
      planned.disposition !== "operational_action" || approved.verdict !== "approve" ||
      approved.customer_impact_checked !== true ||
      (approved.correction_risk !== "low" && approved.correction_risk !== "medium") ||
      !refs(planned.evidence_refs) || !refs(approved.evidence_refs)) return;
    return { planId: provenance.plan_entry_id, reviewId: provenance.review_entry_id };
  }

  private identityContainmentFor(linked: { id: string; version: number | null },
    alert: Alert): { entry: number; eventId: number; deviceId: string;
      revokedAt: string; throughEventId: number | undefined;
      containedAtReal: string | undefined; replay?: { planId: number; reviewId: number } } | undefined {
    if (!linked.version) return;
    const db = this.source.events.db;
    const entries = db.prepare(`SELECT id,kind,payload_json FROM incident_case_entries
      WHERE incident_id=? AND kind IN
        ('defense.code_review_approved','defense.code_bank_gate',
          'defense.code_merged','defense.identity_containment_verified')
      ORDER BY id`).all(linked.id) as
      { id: number; kind: string; payload_json: string }[];
    const byKind = (kind: string) => entries.find((entry) => entry.kind === kind &&
      json(entry.payload_json).case_version === linked.version);
    const approved = entries.find((entry) =>
      entry.kind === "defense.code_review_approved");
    const gate = byKind("defense.code_bank_gate");
    const merged = byKind("defense.code_merged");
    const contained = byKind("defense.identity_containment_verified");
    if (!contained) return;
    const replay = this.reviewedReplay(linked, alert, contained);
    if (!replay && (!approved || !gate || !merged ||
      !(approved.id < gate.id && gate.id < merged.id && merged.id < contained.id))) return;
    const approval = approved ? json(approved.payload_json) : {};
    const check = gate ? json(gate.payload_json) : {};
    const promotion = merged ? json(merged.payload_json) : {};
    const receipt = json(contained.payload_json);
    const head = approval.head_sha;
    const ci = approval.ci_run_id;
    const observed = json(alert.observed_json);
    const eventId = observed.source_event_id;
    const deviceId = observed.device_id;
    if (!replay && (typeof head !== "string" || typeof ci !== "string" ||
      typeof deviceId !== "string" || !Number.isSafeInteger(eventId) ||
      head !== check.head_sha || head !== promotion.head_sha ||
      head !== receipt.head_sha || ci !== check.ci_run_id ||
      ci !== promotion.ci_run_id || ci !== receipt.ci_run_id ||
      typeof check.tests !== "number" || check.tests < 1_000 ||
      !/^[a-f0-9]{64}$/.test(String(check.output_sha256)) ||
      !table(db, "patch_ci_runs") ||
      !db.prepare(`SELECT 1 FROM patch_ci_runs WHERE id=?
        AND candidate_sha=? AND state='merged'`).get(ci, head))) return;
    if (typeof deviceId !== "string" || !Number.isSafeInteger(eventId) ||
      receipt.bank_reconciled !== true || receipt.live_sessions_after !== 0 ||
      receipt.customer_impact !== "unverified" ||
      !Array.isArray(receipt.devices) || !receipt.devices.some((raw) => {
        const item = raw && typeof raw === "object" ?
          raw as Record<string, unknown> : {};
        return item.alert_id === alert.id &&
          item.customer_id === alert.entity &&
          item.device_id === deviceId && item.source_event_id === eventId;
      })) return;
    const bank = this.source.bank.db;
    const source = bank.prepare(`SELECT source,action,outcome,user_id,device_id
      FROM telemetry_events WHERE id=?`).get(Number(eventId)) as
      { source: string; action: string; outcome: string; user_id: string | null;
        device_id: string | null } | undefined;
    const device = bank.prepare(`SELECT revoked_at FROM auth_devices
      WHERE id=? AND customer_id=?`).get(deviceId, alert.entity) as
      { revoked_at: string | null } | undefined;
    const live = bank.prepare(`SELECT 1 FROM auth_sessions
      WHERE customer_id=? AND device_id=? AND revoked_at IS NULL LIMIT 1`)
      .get(alert.entity, deviceId);
    if (!source || source.source !== "auth" ||
      !["access_revoked_device", "refresh_revoked_device"].includes(source.action) ||
      source.outcome !== "success" || source.user_id !== alert.entity ||
      source.device_id !== deviceId || !device?.revoked_at || live ||
      this.source.reconcile?.().ok !== true) return;
    const watermark = Number.isSafeInteger(receipt.through_event_id) &&
      Number(receipt.through_event_id) >= Number(eventId) ?
      Number(receipt.through_event_id) : undefined;
    const containedAtReal = typeof receipt.contained_at_real === "string" &&
      Number.isFinite(Date.parse(receipt.contained_at_real)) ? receipt.contained_at_real : undefined;
    return { entry: contained.id, eventId: Number(eventId), deviceId,
      revokedAt: device.revoked_at, throughEventId: watermark, containedAtReal, ...(replay ? { replay } : {}) };
  }
  private fraudControlFor(linked: { id: string; version: number | null },
    alert: Alert, transferId: string):
    { entry: number; ledgerTxId: string; replay?: { planId: number; reviewId: number } } | undefined {
    if (!linked.version) return;
    const db = this.source.events.db;
    const entries = db.prepare(`SELECT id,kind,payload_json FROM incident_case_entries
      WHERE incident_id=? AND kind IN
        ('defense.code_review_approved','defense.code_bank_gate',
          'defense.code_merged','defense.fraud_control_verified')
      ORDER BY id`).all(linked.id) as
      { id: number; kind: string; payload_json: string }[];
    const byKind = (kind: string) => entries.find((entry) =>
      entry.kind === kind &&
      json(entry.payload_json).case_version === linked.version);
    const approved = entries.find((entry) =>
      entry.kind === "defense.code_review_approved");
    const gate = byKind("defense.code_bank_gate");
    const merged = byKind("defense.code_merged");
    const control = byKind("defense.fraud_control_verified");
    if (!control) return;
    const replay = this.reviewedReplay(linked, alert, control);
    if (!replay && (!approved || !gate || !merged ||
      !(approved.id < gate.id && gate.id < merged.id && merged.id < control.id))) return;
    const approval = approved ? json(approved.payload_json) : {};
    const check = gate ? json(gate.payload_json) : {};
    const promotion = merged ? json(merged.payload_json) : {};
    const receipt = json(control.payload_json);
    const head = approval.head_sha;
    const ci = approval.ci_run_id;
    if (!replay && (typeof head !== "string" || typeof ci !== "string" ||
      head !== check.head_sha || head !== promotion.head_sha ||
      head !== receipt.head_sha || ci !== check.ci_run_id ||
      ci !== promotion.ci_run_id || ci !== receipt.ci_run_id ||
      typeof check.tests !== "number" || check.tests < 1_000 ||
      !/^[a-f0-9]{64}$/.test(String(check.output_sha256)) ||
      !table(db, "patch_ci_runs") ||
      !db.prepare(`SELECT 1 FROM patch_ci_runs WHERE id=?
        AND candidate_sha=? AND state='merged'`).get(ci, head))) return;
    if (receipt.alert_id !== alert.id || receipt.account_id !== alert.entity ||
      receipt.transfer_id !== transferId ||
      receipt.customer_impact !== "unverified" ||
      receipt.bank_reconciled !== true ||
      typeof receipt.ledger_tx_id !== "string") return;
    const bank = this.source.bank.db;
    const transfer = bank.prepare(`SELECT status,amount,from_account,to_account,
      ledger_tx_id FROM pix_transfers WHERE id=?`).get(transferId) as
      { status: string; amount: number; from_account: string;
        to_account: string; ledger_tx_id: string | null } | undefined;
    if (!transfer || transfer.status !== "settled" ||
      transfer.amount !== 4_800 || transfer.from_account !== alert.entity ||
      transfer.to_account !== receipt.recipient_account_id ||
      transfer.ledger_tx_id !== receipt.ledger_tx_id ||
      this.source.reconcile?.().ok !== true) return;
    return { entry: control.id, ledgerTxId: transfer.ledger_tx_id!, ...(replay ? { replay } : {}) };
  }
  private responseFor(run: FaultRunPublic, fixtureId: FaultId,
    linked: { id: string; entry: number; version: number | null } | undefined,
    continuity: EvidenceStage, repair: EvidenceStage,
    reconciliation: EvidenceStage,
    symptom: EvidenceStage, entityId: string | undefined,
    alert: Alert | undefined): EvidenceStage {
    if (!linked?.version) return unknown(run, "defense_case_version_missing");
    const db = this.source.events.db;
    const rows = db.prepare(`SELECT id,kind,created_at,payload_json FROM incident_case_entries
      WHERE incident_id=? AND created_at>=? AND id>?
      ORDER BY id`).all(linked.id, run.started_at, linked.entry) as
      { id: number; kind: string; created_at: string; payload_json: string }[];
    const entries = rows.map((row) => ({ ...row, payload: json(row.payload_json) }));
    const investigation = entries.find((entry) =>
      entry.kind === "dossier.defense_investigation" &&
      entry.payload.case_version === linked.version);
    if (!investigation) return unknown(run, "defense_investigation_missing");
    const plans = entries.filter((entry) =>
      entry.kind === "dossier.defense_plan" &&
      entry.payload.case_version === linked.version &&
      entry.id > investigation.id);
    if (fixtureId === "revoked_device_access" && alert &&
      continuity.state === "verified") {
      const contained = this.identityContainmentFor(linked, alert);
      if (contained?.replay && plans.some((entry) => entry.id === contained.replay!.planId))
        return stage("verified", "reviewed_replay_identity_containment", [
          `incident_case_entries:${investigation.id}`,
          `incident_case_entries:${contained.replay.planId}`,
          `incident_case_entries:${contained.replay.reviewId}`,
          `incident_case_entries:${contained.entry}`]);
      const plan = plans.find((entry) =>
        entry.payload.disposition === "code_candidate");
      return contained && plan ? stage("verified", "reviewed_code_and_identity_containment",
        [`incident_case_entries:${investigation.id}`,
          `incident_case_entries:${plan.id}`,
          `incident_case_entries:${contained.entry}`]) :
        unknown(run, "code_or_identity_containment_unverified");
    }
    if (fixtureId === "risk_missed_hold" && alert &&
      continuity.state === "verified") {
      const receipt = table(this.source.bank.db, "lab_risk_miss_receipts") ?
        this.source.bank.db.prepare(`SELECT transfer_id FROM
          lab_risk_miss_receipts WHERE run_id=?`).get(run.id) as
          { transfer_id: string } | undefined : undefined;
      const control = receipt ? this.fraudControlFor(linked, alert,
        receipt.transfer_id) : undefined;
      if (control?.replay && plans.some((entry) => entry.id === control.replay!.planId))
        return stage("verified", "reviewed_replay_pix_control", [
          `incident_case_entries:${investigation.id}`,
          `incident_case_entries:${control.replay.planId}`,
          `incident_case_entries:${control.replay.reviewId}`,
          `incident_case_entries:${control.entry}`]);
      const plan = plans.find((entry) =>
        entry.payload.disposition === "code_candidate");
      return control && plan ? stage("verified", "reviewed_code_and_fraud_control",
        [`incident_case_entries:${investigation.id}`,
          `incident_case_entries:${plan.id}`,
          `incident_case_entries:${control.entry}`]) :
        unknown(run, "code_or_fraud_control_unverified");
    }
    if (fixtureId === "fee_rounding_drift" && alert &&
      reconciliation.state === "verified") {
      const receipt = this.feeRepairFor(linked, alert);
      const plan = plans.find((entry) =>
        entry.payload.disposition === "code_candidate");
      return receipt && plan ? stage("verified", "reviewed_code_and_fee_repair",
        [`incident_case_entries:${investigation.id}`,
          `incident_case_entries:${plan.id}`,
          `incident_case_entries:${receipt.entry}`,
          `ledger_entries:${receipt.ledgerTxId}`]) :
        unknown(run, "code_or_fee_repair_unverified");
    }
    const approved = plans.map((plan) => ({ plan,
      review: entries.find((entry) => entry.kind === "dossier.defense_review" &&
        entry.payload.case_version === linked.version &&
        entry.payload.revision === plan.payload.revision &&
        entry.payload.verdict === "approve" && entry.id > plan.id) }))
      .filter((pair) => pair.review).at(-1);
    if (!approved?.review) return unknown(run, "defense_plan_or_approved_review_missing");
    const { plan, review } = approved;
    const refs = [`incident_case_entries:${investigation.id}`,
      `incident_case_entries:${plan.id}`, `incident_case_entries:${review.id}`];
    if (plan.payload.disposition === "code_candidate")
      return unknown(run, "reviewed_code_candidate_not_applied");
    if (plan.payload.disposition === "source_recovery" &&
      ["auth_event_silence", "gateway_heartbeat_silence",
        "hourly_proof_paused", "statement_unavailable",
        "loan_offer_unavailable", "pix_automatic_mandates_unavailable",
        "kyc_status_unavailable", "kyc_submission_unavailable", "kyc_review_interrupted", "med_opening_delayed",
        "automatic_pix_execution_delayed", "med_analysis_delayed", "med_settlement_delayed",
        "med_release_delayed"].includes(fixtureId) &&
      alert && continuity.state === "verified") {
      const medAnalysis = fixtureId === "med_analysis_delayed";
      const medCompletion = fixtureId === "med_settlement_delayed" ? "med_settlement" :
        fixtureId === "med_release_delayed" ? "med_release" : null;
      const medRecovery = fixtureId === "med_opening_delayed" || medAnalysis || medCompletion;
      if (medRecovery &&
        (repair.state !== "verified" || reconciliation.state !== "verified"))
        return unknown(run, medCompletion ? "med_completion_reconciliation_pending" :
          medAnalysis ? "med_analysis_reconciliation_pending" :
          "med_opening_reconciliation_pending");
      const automatic = fixtureId === "automatic_pix_execution_delayed";
      if (automatic && (repair.state !== "verified" || reconciliation.state !== "verified"))
        return unknown(run, "automatic_pix_settlement_pending");
      const source = fixtureId === "auth_event_silence" ?
        "auth" : fixtureId === "gateway_heartbeat_silence" ?
        "gateway" : fixtureId === "statement_unavailable" ?
        "accounts_statement" : fixtureId === "loan_offer_unavailable" ?
        "loans_offer" : fixtureId === "pix_automatic_mandates_unavailable" ?
        "pix_automatic_mandates" : fixtureId === "kyc_status_unavailable" ?
        "kyc_status" : fixtureId === "kyc_submission_unavailable" ?
        "kyc_submission" : fixtureId === "kyc_review_interrupted" ? "kyc_review" :
          fixtureId === "med_opening_delayed" ?
        "med_opening" : medAnalysis ? "med_analysis" : medCompletion ??
          (automatic ? "automatic_pix_execution" : "ledger_hourly_proof");
      const customerReads = ["accounts_statement", "loans_offer", "pix_automatic_mandates",
        "kyc_status", "kyc_submission", "kyc_review"];
      const failedStatementLogId = customerReads
        .includes(source) ?
        this.emission(alert, run)?.observed.failed_log_id : null;
      const failedStatementRef = typeof failedStatementLogId === "string" ?
        `access_log:${failedStatementLogId}` : null;
      const heartbeat = source === "auth" || source === "gateway" ?
        this.source.bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE id=? AND source=? AND category='health' AND action='heartbeat'
            AND outcome='success' AND ts>? AND ts<=?`) : null;
      const reviewedHeartbeat = (refs: unknown[], recordedAt: string) =>
        refs.find((ref): ref is string => {
          const id = typeof ref === "string" ? /^telemetry_events:(\d+)$/.exec(ref)?.[1] : undefined;
          return Boolean(id && heartbeat?.get(Number(id), source,
            run.stopped_at ?? run.expires_at, recordedAt));
        });
      const required = [`sentinel_alerts:${alert.id}`,
        ...(heartbeat ? [] : continuity.evidence_refs)];
      const receipt = entries.find((entry) =>
        entry.kind === "defense.source_recovery_verified" &&
        entry.id > review.id && entry.payload.case_version === linked.version &&
        entry.payload.revision === plan.payload.revision &&
        entry.payload.source === source && entry.payload.alert_id === alert.id &&
        entry.payload.ledger_healthy === true &&
        entry.payload.bank_correction_applied === false &&
        entry.payload.customer_repair === (source === "accounts_statement" ?
          "statement_retry_succeeded" : source === "loans_offer" ?
          "loan_offer_retry_succeeded" : source === "pix_automatic_mandates" ?
          "pix_automatic_mandates_retry_succeeded" : source === "kyc_status" ?
          "kyc_status_retry_succeeded" : source === "kyc_submission" ?
          "kyc_submission_retry_succeeded" : source === "kyc_review" ?
          "kyc_review_retry_succeeded" : source === "med_opening" ?
          "med_opening_acknowledged" : medAnalysis ? "med_analysis_acknowledged" :
          medCompletion ? `${medCompletion}_acknowledged` : automatic ?
          "automatic_pix_charge_settled" : "no_linked_loss") &&
        (!automatic || entry.payload.charge_id === entityId &&
          reconciliation.evidence_refs.includes(`ledger_entries:${String(entry.payload.ledger_tx_id)}`) &&
          repair.evidence_refs.includes(`pix_transfers:${String(entry.payload.transfer_id)}`)) &&
        (!medRecovery || entry.payload.med_case_id === entityId &&
          Boolean(this.source.bank.db.prepare(`SELECT 1 FROM med_cases
            WHERE id=? AND customer_id=?`).get(entityId ?? null,
              typeof entry.payload.customer_id === "string" ? entry.payload.customer_id : null))) &&
        (!customerReads.includes(source) ||
          Boolean(failedStatementRef &&
          (entry.payload.evidence_refs as string[] | undefined)?.includes(
            failedStatementRef))) &&
        (source !== "ledger_hourly_proof" ||
          entry.payload.missing_hour_start ===
            this.emission(alert, run)?.observed.missing_hour_start) &&
        Array.isArray(entry.payload.evidence_refs) &&
        (!heartbeat || Boolean(reviewedHeartbeat(entry.payload.evidence_refs, entry.created_at))) &&
        required.every((ref) =>
          (entry.payload.evidence_refs as string[]).includes(ref)));
      return receipt ? stage("verified", "reviewed_source_recovery",
        [...refs, `incident_case_entries:${receipt.id}`,
          ...(heartbeat ? [reviewedHeartbeat(receipt.payload.evidence_refs as unknown[],
            receipt.created_at)!] : continuity.evidence_refs)]) :
        unknown(run, "source_recovery_receipt_missing_or_mismatched");
    }
    if (plan.payload.disposition === "external_recovery" &&
      ["pix_dispatch_paused", "spi_unavailable", "psp_receipt_delayed"]
        .includes(fixtureId) && alert && entityId &&
      continuity.state === "verified" && repair.state === "verified" &&
      reconciliation.state === "verified") {
      const receipt = entries.find((entry) =>
        entry.kind === "defense.queue_recovery_verified" &&
        entry.id > review.id && entry.payload.case_version === linked.version &&
        entry.payload.revision === plan.payload.revision &&
        entry.payload.phase === "recovered" &&
        entry.payload.bank_reconciled === true &&
        entry.payload.bank_correction_applied === false &&
        entry.payload.customer_repair === "payment_completed" &&
        Array.isArray(entry.payload.evidence_refs) &&
        [`sentinel_alerts:${alert.id}`, `pix_transfers:${entityId}`].every((ref) =>
          (entry.payload.evidence_refs as string[]).includes(ref)) &&
        Array.isArray(entry.payload.items) &&
        entry.payload.items.some((item) => item.transfer_id === entityId &&
          item.response_status === "ACSC" &&
          item.recipient_acknowledged === true &&
          typeof item.ledger_tx_id === "string" &&
          reconciliation.evidence_refs.includes(
            `ledger_entries:${item.ledger_tx_id}`)));
      return receipt ? stage("verified", "reviewed_payment_queue_recovery",
        [...refs, `incident_case_entries:${receipt.id}`,
          ...reconciliation.evidence_refs]) :
        unknown(run, "payment_queue_recovery_receipt_missing_or_mismatched");
    }
    if (plan.payload.disposition === "external_recovery" &&
      fixtureId === "card_issuer_offline" && alert && entityId &&
      continuity.state === "verified") {
      const outageId = Number(symptom.evidence_refs.find((ref) =>
        ref.startsWith("card_issuer_history:"))?.split(":")[1]);
      const restoredId = Number(continuity.evidence_refs.find((ref) =>
        ref.startsWith("card_issuer_history:"))?.split(":")[1]);
      const authorizationId = continuity.evidence_refs.find((ref) =>
        ref.startsWith("card_network_authorizations:"))?.split(":")[1];
      const required = [`sentinel_alerts:${alert.id}`,
        `card_issuer_history:${outageId}`, ...continuity.evidence_refs];
      const receipt = entries.find((entry) => {
        const evidence = entry.payload.evidence_refs;
        const representative = entry.payload.rejection_id;
        const sameOutage = typeof representative === "string" &&
          this.source.bank.db.prepare(`SELECT 1 FROM card_network_rejections r
            JOIN card_issuer_history down ON down.id=? AND down.available=0
            JOIN card_issuer_history up ON up.id=? AND up.available=1
            WHERE r.id=? AND r.response_code='91' AND
              r.created_at>=down.changed_at AND r.created_at<up.changed_at`)
            .get(outageId, restoredId, representative);
        return entry.kind === "defense.external_recovery_verified" &&
          entry.id > review.id && entry.payload.case_version === linked.version &&
          entry.payload.revision === plan.payload.revision &&
          entry.payload.phase === "recovered" &&
          entry.payload.issuer_available === true &&
          entry.payload.bank_correction_applied === false &&
          entry.payload.customer_repair === "not_proven" &&
          entry.payload.individual_nonfinancial_harm === "unknown" &&
          entry.payload.alert_id === alert.id &&
          sameOutage &&
          entry.payload.outage_history_id === outageId &&
          entry.payload.restored_history_id === restoredId &&
          entry.payload.authorization_id === authorizationId &&
          Array.isArray(evidence) &&
          evidence.includes(`card_network_rejections:${representative}`) &&
          required.every((ref) => evidence.includes(ref));
      });
      return receipt ? stage("verified", "reviewed_external_recovery_receipt",
        [...refs, `incident_case_entries:${receipt.id}`, ...required]) :
        unknown(run, "external_recovery_receipt_missing_or_mismatched");
    }
    if (plan.payload.disposition === "operational_action") {
      const applied = entries.find((entry) =>
        entry.kind === "defense.mitigation_decision" &&
        entry.payload.case_version === linked.version &&
        entry.payload.revision === plan.payload.revision &&
        entry.payload.applied === true && entry.id > review.id &&
        (fixtureId !== "risk_false_hold" ||
          (entry.payload.action === "release_false_pix_hold" &&
            repair.evidence_refs.includes(`incident_case_entries:${entry.id}`))));
      return applied ? stage("verified", "reviewed_operational_action_applied",
        [...refs, `incident_case_entries:${applied.id}`]) :
        unknown(run, "reviewed_operational_action_not_applied");
    }
    return unknown(run, "reviewed_plan_has_no_verified_correction");
  }
  private transfer(id: string): { id: string; status: string;
    ledger_tx_id: string | null } | undefined {
    const db = this.source.bank.db;
    return table(db, "pix_transfers") ? db.prepare(`SELECT id,status,ledger_tx_id
      FROM pix_transfers WHERE id=?`).get(id) as
      { id: string; status: string; ledger_tx_id: string | null } | undefined : undefined;
  }
  private balanced(txId: string): boolean {
    const db = this.source.bank.db;
    if (!table(db, "ledger_entries")) return false;
    const row = db.prepare(`SELECT COUNT(*) entries,COALESCE(SUM(amount),0) net
      FROM ledger_entries WHERE tx_id=?`).get(txId) as { entries: number; net: number };
    return row.entries >= 2 && row.net === 0;
  }
  private receipt(incidentId: string, holdId: string, transferId: string,
    ledgerTxId: string): string | undefined {
    const db = this.source.events.db;
    if (!table(db, "incident_case_entries")) return;
    const rows = db.prepare(`SELECT id,payload_json FROM incident_case_entries
      WHERE incident_id=? AND kind='defense.mitigation_decision'
      ORDER BY id DESC`).all(incidentId) as
      { id: number; payload_json: string }[];
    const row = rows.find((candidate) => {
      const payload = json(candidate.payload_json);
      return payload.applied === true &&
        payload.action === "release_false_pix_hold" &&
        payload.repair_status === "verified_transfer" &&
        payload.hold_id === holdId && payload.transfer_id === transferId &&
        payload.ledger_tx_id === ledgerTxId;
    });
    return row ? `incident_case_entries:${row.id}` : undefined;
  }

  private watchFor(run: FaultRunPublic, fixtureId: FaultId, alert: Alert | undefined,
    prior: EvidenceStage[], response: EvidenceStage, repair: EvidenceStage): EvidenceStage {
    if (run.status !== "expired") return stage(terminal(run) ? "inconclusive" :
      "pending", "watch_waiting_for_normal_completion");
    if (prior.some((item) => item.state === "pending" || item.state === "inconclusive"))
      return stage("pending", "watch_waiting_for_recovery");
    const stop = Date.parse(run.stopped_at ?? "");
    const now = (this.source.now ?? (() => new Date()))().getTime();
    if (!Number.isFinite(stop) || !Number.isFinite(now))
      return stage("inconclusive", "watch_clock_unavailable");
    const db = this.source.events.db;
    if (!table(db, "events")) return stage("pending", "watch_traffic_missing");
    const recoveryEntries = [...response.evidence_refs, ...repair.evidence_refs]
      .flatMap((ref) => {
        const match = /^incident_case_entries:(\d+)$/.exec(ref);
        return match ? [Number(match[1])] : [];
      });
    const latestRecovery = recoveryEntries.length > 0 ? db.prepare(`SELECT
      MAX(created_at) at FROM incident_case_entries
      WHERE id IN (SELECT value FROM json_each(?))`).get(JSON.stringify(recoveryEntries)) as
        { at: string | null } : null;
    const cardRetries = fixtureId === "card_issuer_offline" ?
      repair.evidence_refs.flatMap((ref) => {
        const match = /^events:(\d+)$/.exec(ref);
        return match ? [Number(match[1])] : [];
      }) : [];
    const latestRetry = cardRetries.length > 0 ? db.prepare(`SELECT MAX(ts) at
      FROM events WHERE type='sim.card_retry'
        AND seq IN (SELECT value FROM json_each(?))`).get(JSON.stringify(cardRetries)) as
        { at: string | null } : null;
    const watchStart = Math.max(stop, Date.parse(latestRecovery?.at ?? "") || stop,
      Date.parse(latestRetry?.at ?? "") || stop);
    if (now - watchStart < 15_000) return stage("pending", "watch_window_open");
    const from = new Date(Math.max(watchStart, now - 35_000)).toISOString();
    const until = new Date(now).toISOString();
    if (alert && db.prepare(`SELECT 1 FROM events e
      JOIN event_private p ON p.seq=e.seq WHERE e.type='sentinel.alert'
      AND e.ts>=? AND e.ts<=? AND
        json_extract(e.public_json,'$.alert_id')=? LIMIT 1`)
      .get(from, until, alert.id))
      return stage("pending", "watch_recurrence_observed");
    const rows = db.prepare(`SELECT seq,ts,public_json FROM events
      WHERE type='sim.tick' AND ts>=? AND ts<=? ORDER BY ts,seq`)
      .all(from, until) as { seq: number; ts: string; public_json: string }[];
    const area = fixtureId === "card_issuer_offline" ? "cards" :
      fixtureId === "auth_event_silence" || fixtureId === "revoked_device_access" ||
      fixtureId === "statement_unavailable" || fixtureId === "kyc_status_unavailable" ||
      fixtureId === "kyc_submission_unavailable" || fixtureId === "kyc_review_interrupted" ? "accounts" :
      fixtureId === "loan_offer_unavailable" ? null :
      fixtureId === "gateway_heartbeat_silence" ||
      fixtureId === "hourly_proof_paused" ||
      fixtureId === "fee_rounding_drift" ? null : "pix";
    if (rows.some((row) => json(row.public_json).honest_blocked !== 0))
      return stage("pending", "watch_honest_traffic_unhealthy");
    const healthy = rows.filter((row) => {
      const payload = json(row.public_json);
      return typeof payload.ops === "number" && payload.ops > 0;
    });
    const first = healthy[0];
    const last = healthy.at(-1);
    if (!first || !last || Date.parse(last.ts) - Date.parse(first.ts) < 10_000 ||
      now - Date.parse(last.ts) > 15_000 ||
      (area !== null && !healthy.some((row) => {
        const byArea = json(row.public_json).by_area;
        return byArea && typeof byArea === "object" && !Array.isArray(byArea) &&
          typeof (byArea as Record<string, unknown>)[area] === "number" &&
          Number((byArea as Record<string, unknown>)[area]) > 0;
      }))) return stage("pending", "watch_traffic_missing");
    return stage("verified", "watch_healthy_traffic_without_recurrence",
      [`events:${first.seq}`, `events:${last.seq}`]);
  }

  private crossBookVerified(run: FaultRunPublic,
    observation: CrossBookObservation | null): boolean {
    if (run.status !== "expired" || !run.stopped_at ||
      !observation?.report?.ok || !observation.proof_ref) return false;
    const checked = Date.parse(observation.checked_at);
    const now = (this.source.now ?? (() => new Date()))().getTime();
    if (!Number.isFinite(checked) || checked < Date.parse(run.stopped_at) ||
      checked > now || now - checked > 30_000 ||
      !/^events:[1-9]\d*$/.test(observation.proof_ref)) return false;
    const seq = Number(observation.proof_ref.slice("events:".length));
    if (!Number.isSafeInteger(seq) || !table(this.source.events.db, "event_private"))
      return false;
    const proof = this.source.events.db.prepare(`SELECT e.ts,e.public_json,
      p.private_json FROM events e JOIN event_private p ON p.seq=e.seq
      WHERE e.seq=? AND e.type='ecosystem.cross_book_check'`).get(seq) as
      { ts: string; public_json: string; private_json: string } | undefined;
    if (!proof || proof.ts < run.stopped_at || proof.ts > observation.checked_at)
      return false;
    const reportHash = createHash("sha256")
      .update(JSON.stringify(observation.report)).digest("hex");
    return json(proof.public_json).ok === true &&
      json(proof.public_json).report_sha256 === reportHash &&
      JSON.stringify(json(proof.private_json).report) ===
        JSON.stringify(observation.report);
  }

  private evaluateFixture(run: FaultRunPublic,
    result: FaultRunPublic["results"][number],
    crossBook: CrossBookObservation | null): FixtureEvaluation {
    const id = result.fixture_id;
    const prefix: Record<FaultId, string> = {
      auth_event_silence: "sentinel_alerts:", hourly_proof_paused: "sentinel_alerts:",
      gateway_heartbeat_silence: "sentinel_alerts:",
      statement_unavailable: "sentinel_alerts:",
      loan_offer_unavailable: "sentinel_alerts:",
      pix_automatic_mandates_unavailable: "sentinel_alerts:",
      kyc_status_unavailable: "sentinel_alerts:",
      kyc_submission_unavailable: "sentinel_alerts:",
      kyc_review_interrupted: "sentinel_alerts:",
      revoked_device_access: "sentinel_alerts:",
      risk_false_hold: "risk_pix_holds:", risk_missed_hold: "sentinel_alerts:",
      pix_dispatch_paused: "pix_spi_outbox:",
      spi_unavailable: "pix_spi_outbox:", psp_receipt_delayed: "pix_psp_inbound_outbox:",
      med_opening_delayed: "med_psp_open_outbox:",
      med_analysis_delayed: "med_dict_analysis_outbox:",
      med_settlement_delayed: "med_psp_settlement_outbox:",
      med_release_delayed: "med_psp_release_outbox:",
      automatic_pix_execution_delayed: "pix_automatic_charges:",
      card_issuer_offline: "card_network_rejections:",
      fee_rounding_drift: "sentinel_alerts:",
    };
    const ref = result.evidence_refs.find((value) => value.startsWith(prefix[id]));
    const key = ref?.slice(prefix[id].length);
    let symptom = unknown(run, "symptom_not_proven");
    let detection = unknown(run, "matching_sentinel_alert_missing");
    let continuity = unknown(run, "recovery_not_proven");
    let customer_repair = stage("not_applicable", "no_customer_loss_proven");
    let reconciliation = stage("not_applicable", "no_financial_movement_proven");
    let alert: Alert | undefined;
    const inWindow = (at: string, basis: "real" | "twin" = "twin"): boolean => {
      const bank = this.source.bank.db;
      const clock = basis === "twin" && table(bank, "runtime_clock") ?
        bank.prepare(`SELECT real_start_ms,
        twin_start_ms,speed FROM runtime_clock WHERE id=1`).get() as
        { real_start_ms: number; twin_start_ms: number; speed: number } | undefined :
        undefined;
      const twin = (real: string): string => clock ? new Date(clock.twin_start_ms +
        (Date.parse(real) - clock.real_start_ms) * clock.speed).toISOString() : real;
      return at >= twin(run.started_at) &&
        at <= twin(run.stopped_at ?? run.expires_at);
    };

    if (key && result.state === "observed") {
      const bank = this.source.bank.db;
      if (id === "fee_rounding_drift") {
        alert = this.alert(key);
        const owned = table(bank, "lab_fee_fault_receipts") &&
          bank.prepare("SELECT 1 FROM lab_fee_fault_receipts WHERE run_id=?")
            .get(run.id);
        const emission = alert?.rule_id === "S-LED-03" &&
          alert.entity === (bank.prepare(`SELECT id FROM accounts WHERE kind='system'
            AND system_role='rounding'`).get() as { id: string } | undefined)?.id ?
          this.emission(alert, run, (observed) =>
            typeof observed.drift_cents === "number" &&
            observed.drift_cents >= 500) : undefined;
        if (owned && emission) {
          symptom = stage("verified", "run_owned_rounding_drift", [ref!, emission.ref]);
          detection = stage("verified", "exact_sentinel_emission", [emission.ref]);
          reconciliation = unknown(run, "rounding_ledger_repair_not_proven");
        }
      } else if (id === "statement_unavailable") {
        alert = this.alert(key);
        const receipt = table(bank, "lab_statement_outage_receipts") ?
          bank.prepare(`SELECT customer_id,account_id,failed_log_id,
            recovered_log_id FROM lab_statement_outage_receipts
            WHERE run_id=?`).get(run.id) as { customer_id: string;
              account_id: string; failed_log_id: string;
              recovered_log_id: string | null } | undefined : undefined;
        const failed = receipt ? bank.prepare(`SELECT rowid,ts FROM access_log
          WHERE id=? AND kind='statement_own' AND status=503
            AND customer_id=? AND account_id=?`).get(receipt.failed_log_id,
              receipt.customer_id, receipt.account_id) as
              { rowid: number; ts: string } | undefined : undefined;
        const emission = receipt && failed && alert?.rule_id === "S-ACC-04" &&
          alert.entity === receipt.customer_id ? this.emission(alert, run,
            (observed) => observed.failed_log_id === receipt.failed_log_id &&
              observed.account_id === receipt.account_id) : undefined;
        if (receipt && failed && inWindow(failed.ts)) {
          symptom = stage("verified", "run_owned_statement_unavailable",
            [`access_log:${receipt.failed_log_id}`]);
          customer_repair = unknown(run, "customer_statement_access_not_restored");
        }
        if (emission) detection = stage("verified", "exact_sentinel_emission",
          [emission.ref]);
        if (receipt && failed && emission && terminal(run) &&
          receipt.recovered_log_id) {
          const recovered = bank.prepare(`SELECT rowid FROM access_log
            WHERE id=? AND kind='statement_own' AND status=200
              AND customer_id=? AND account_id=?`).get(
                receipt.recovered_log_id, receipt.customer_id,
                receipt.account_id) as { rowid: number } | undefined;
          if (recovered && recovered.rowid > failed.rowid) {
            continuity = stage("verified", "statement_access_restored",
              [`access_log:${receipt.recovered_log_id}`]);
            customer_repair = stage("verified", "customer_statement_retry_succeeded",
              [`access_log:${receipt.failed_log_id}`,
                `access_log:${receipt.recovered_log_id}`]);
          }
        }
      } else if (id === "loan_offer_unavailable" ||
        id === "pix_automatic_mandates_unavailable" || id === "kyc_status_unavailable" ||
        id === "kyc_submission_unavailable") {
        const operations = {
          loan_offer_unavailable: { name: "loan_offer", rule: "S-LOAN-04" },
          pix_automatic_mandates_unavailable: { name: "pix_automatic_mandates", rule: "S-PIX-42" },
          kyc_status_unavailable: { name: "kyc_status", rule: "S-AUTH-14" },
          kyc_submission_unavailable: { name: "kyc_submission", rule: "S-AUTH-15" },
        } as const;
        const { name: operation, rule } = operations[id];
        const action = `${operation}_own`;
        const receipts = `lab_${operation}_outage_receipts`;
        alert = this.alert(key);
        const receipt = table(bank, receipts) ?
          bank.prepare(`SELECT customer_id,failed_log_id,recovered_log_id
            ${id === "kyc_submission_unavailable" ? ",submitted_history_id" : ""}
            FROM ${receipts} WHERE run_id=?`).get(run.id) as
            { customer_id: string; failed_log_id: string;
              recovered_log_id: string | null; submitted_history_id?: number } |
                undefined : undefined;
        const failed = receipt ? bank.prepare(`SELECT rowid,ts FROM access_log
          WHERE id=? AND kind=? AND status=503
            AND customer_id=?`).get(receipt.failed_log_id,
              action, receipt.customer_id) as { rowid: number; ts: string } | undefined :
          undefined;
        const emission = receipt && failed && alert?.rule_id === rule &&
          alert.entity === receipt.customer_id ? this.emission(alert, run,
            (observed) => observed.failed_log_id === receipt.failed_log_id) :
          undefined;
        if (receipt && failed && inWindow(failed.ts)) {
          symptom = stage("verified", `run_owned_${id}`,
            [`access_log:${receipt.failed_log_id}`]);
          customer_repair = unknown(run, `customer_${operation}_access_not_restored`);
        }
        if (emission) detection = stage("verified", "exact_sentinel_emission",
          [emission.ref]);
        if (receipt && failed && emission && terminal(run) &&
          receipt.recovered_log_id) {
          const recovered = bank.prepare(`SELECT rowid,ts FROM access_log
            WHERE id=? AND kind=? AND status=200
              AND customer_id=?`).get(receipt.recovered_log_id,
                action, receipt.customer_id) as { rowid: number; ts: string } | undefined;
          const submission = id === "kyc_submission_unavailable" && recovered &&
            receipt.submitted_history_id ? bank.prepare(`SELECT id FROM kyc_history
              WHERE id=? AND customer_id=? AND event='submitted' AND reviewer IS NULL
                AND previous_tier<3 AND requested_tier=3 AND twin_at>=? AND twin_at<=?`)
              .get(receipt.submitted_history_id, receipt.customer_id, failed.ts, recovered.ts) as
              { id: number } | undefined : undefined;
          if (recovered && recovered.rowid > failed.rowid &&
            (id !== "kyc_submission_unavailable" || submission)) {
            continuity = stage("verified", `${operation}_access_restored`,
              [`access_log:${receipt.recovered_log_id}`]);
            customer_repair = stage("verified", `customer_${operation}_retry_succeeded`,
              [`access_log:${receipt.failed_log_id}`,
                `access_log:${receipt.recovered_log_id}`,
                ...(submission ? [`kyc_history:${submission.id}`] : [])]);
          }
        }
      } else if (id === "kyc_review_interrupted") {
        alert = this.alert(key);
        const failed = alert?.rule_id === "S-AUTH-16" && table(bank, "lab_kyc_review_interruptions") ?
          bank.prepare(`SELECT l.id,l.rowid,l.ts,l.customer_id,l.route,b.expires_at,b.released_at
            FROM lab_kyc_review_interruptions b JOIN access_log l
              ON l.customer_id=b.customer_id AND l.route=b.submitted_at
            WHERE b.run_id=? AND l.id=? AND l.customer_id=? AND l.kind='kyc_review' AND l.status=503`)
            .get(run.id, String(json(alert.observed_json).failed_log_id ?? ""), alert.entity) as
              { id: string; rowid: number; ts: string; customer_id: string; route: string;
                expires_at: string; released_at: string | null } | undefined : undefined;
        const emission = alert && failed && this.emission(alert, run,
          (observed) => observed.failed_log_id === failed.id);
        if (failed && inWindow(failed.ts)) {
          symptom = stage("verified", "run_owned_kyc_review_interrupted", [`access_log:${failed.id}`]);
          customer_repair = unknown(run, "customer_kyc_review_pending");
        }
        if (emission && symptom.state === "verified") {
          detection = stage("verified", "exact_sentinel_emission", [emission.ref]);
          const approved = terminal(run) && bank.prepare(`SELECT l.id log_id,h.id history_id
            FROM access_log l JOIN kyc_requests r ON r.customer_id=l.customer_id AND r.submitted_at=l.route
            JOIN kyc_history h ON h.customer_id=l.customer_id AND h.twin_at=r.approved_at
            JOIN customers c ON c.id=r.customer_id AND c.kyc_tier=r.requested_tier
            WHERE l.kind='kyc_review' AND l.status=200 AND l.customer_id=? AND l.route=?
              AND l.rowid>? AND r.status='approved' AND r.requested_tier=3 AND c.kyc_status='approved'
              AND h.event='approved' AND h.requested_tier=r.requested_tier AND h.reviewer=l.actor
              AND h.recorded_at>=? ORDER BY l.rowid LIMIT 1`)
            .get(failed.customer_id, failed.route, failed.rowid,
              failed.released_at && failed.released_at < failed.expires_at
                ? failed.released_at : failed.expires_at) as
                { log_id: string; history_id: number } | false | undefined;
          if (approved) {
            continuity = stage("verified", "kyc_review_restored", [`access_log:${approved.log_id}`]);
            customer_repair = stage("verified", "customer_kyc_review_completed",
              [`access_log:${failed.id}`, `kyc_history:${approved.history_id}`]);
          }
        }
      } else if (id === "revoked_device_access") {
        alert = this.alert(key);
        const receipt = table(bank, "lab_revoked_device_receipts") ?
          bank.prepare(`SELECT customer_id,device_id,telemetry_event_id FROM lab_revoked_device_receipts
            WHERE run_id=?`).get(run.id) as
            { customer_id: string; device_id: string;
              telemetry_event_id: number } | undefined : undefined;
        const emission = receipt && alert?.rule_id === "S-AUTH-08" &&
          alert.entity === receipt.customer_id ? this.emission(alert, run,
            (observed) => observed.source_event_id === receipt.telemetry_event_id &&
              observed.device_id === receipt.device_id &&
              observed.action === "access_revoked_device") : undefined;
        if (emission) {
          const replay = table(bank, "lab_identity_replays") && bank.prepare(
            "SELECT 1 FROM lab_identity_replays WHERE run_id=? AND telemetry_event_id=?")
            .get(run.id, receipt!.telemetry_event_id);
          symptom = stage("verified", replay ? "synthetic_revoked_device_record" :
            "run_owned_revoked_device_access",
            [ref!, `telemetry_events:${receipt!.telemetry_event_id}`]);
          detection = stage("verified", "exact_sentinel_emission", [emission.ref]);
          customer_repair = unknown(run, "access_impact_not_assessed");
        }
      } else if (id === "risk_missed_hold") {
        alert = this.alert(key);
        const receipt = table(bank, "lab_risk_miss_receipts") ?
          bank.prepare(`SELECT account_id,transfer_id,recipient_account_id
            FROM lab_risk_miss_receipts WHERE run_id=?`).get(run.id) as
            { account_id: string; transfer_id: string;
              recipient_account_id: string } | undefined : undefined;
        const transfer = receipt ? bank.prepare(`SELECT id,status,amount,
          from_account,to_account,settled_at,ledger_tx_id
          FROM pix_transfers WHERE id=?`).get(receipt.transfer_id) as
          { id: string; status: string; amount: number;
            from_account: string; to_account: string;
            settled_at: string | null; ledger_tx_id: string | null } | undefined :
          undefined;
        const owned = transfer?.status === "settled" &&
          transfer.amount === 4_800 &&
          transfer.from_account === receipt?.account_id &&
          transfer.to_account === receipt.recipient_account_id &&
          transfer.settled_at && inWindow(transfer.settled_at) &&
          alert?.rule_id === "S-PIX-02" && alert.entity === receipt.account_id;
        const emission = owned && alert ? this.emission(alert, run,
          (observed) => Number(observed.senders) >= 5 &&
            Number(observed.inbound_cents) >= 6_000 &&
            Number(observed.outbound_cents) >= 4_800,
          transfer!.settled_at!) : undefined;
        if (owned) {
          const replay = table(bank, "lab_pix_history_replays") && bank.prepare(
            "SELECT 1 FROM lab_pix_history_replays WHERE run_id=? AND account_id=?")
            .get(run.id, receipt!.account_id);
          symptom = stage("verified", replay ? "synthetic_missed_hold_record" :
            "run_owned_missed_fraud_hold",
            [`pix_transfers:${transfer!.id}`]);
          customer_repair = unknown(run, "suspicious_payment_impact_unrepaired");
          reconciliation = unknown(run, "suspicious_payment_reconciliation_unverified");
        }
        if (emission) detection = stage("verified", "exact_sentinel_emission",
          [`sentinel_alerts:${alert!.id}`, emission.ref]);
      } else if (id === "auth_event_silence" ||
        id === "gateway_heartbeat_silence" || id === "hourly_proof_paused") {
        alert = this.alert(key);
        const rule = id === "auth_event_silence" ? "S-AUTH-07" :
          id === "gateway_heartbeat_silence" ? "S-GW-07" : "S-LED-11";
        const entity = id === "auth_event_silence" ? "auth" :
          id === "gateway_heartbeat_silence" ? "gateway" : "ledger_hourly_proof";
        const emission = alert?.rule_id === rule && alert.entity === entity ?
          this.emission(alert, run) : undefined;
        if (emission) {
          symptom = stage("verified", "source_gap_observed", [ref!, emission.ref]);
          detection = stage("verified", "exact_sentinel_emission", [emission.ref]);
          if ((id === "auth_event_silence" ||
            id === "gateway_heartbeat_silence") && terminal(run) &&
            table(bank, "telemetry_events")) {
            const source = id === "auth_event_silence" ? "auth" : "gateway";
            const heartbeat = bank.prepare(`SELECT id FROM telemetry_events WHERE
              source=? AND category='health' AND action='heartbeat'
                AND outcome='success' AND ts>? ORDER BY id LIMIT 1`).get(source,
                run.stopped_at ?? run.expires_at) as
              { id: number } | undefined;
            if (heartbeat) continuity = stage("verified",
              id === "auth_event_silence" ? "auth_heartbeat_resumed" :
                "gateway_heartbeat_resumed",
              [`telemetry_events:${heartbeat.id}`]);
          }
          if (id === "hourly_proof_paused" && table(this.source.events.db, "events")) {
            const hour = emission.observed.missing_hour_start;
            const proof = typeof hour === "string" ? this.source.events.db.prepare(`SELECT
              seq FROM events WHERE type='ledger.hourly_proof'
                AND json_extract(public_json,'$.hour_start')=?
              ORDER BY seq DESC LIMIT 1`).get(hour) as { seq: number } | undefined :
              undefined;
            if (proof && typeof hour === "string") continuity = stage("verified",
              "missing_hour_proof_published", [`events:${proof.seq}`]);
          }
        }
      } else if (id === "risk_false_hold" && table(bank, "risk_pix_holds")) {
        const hold = bank.prepare(`SELECT id,status,transfer_id,balance_hold_id,reviewer
          FROM risk_pix_holds WHERE id=? AND idempotency_key=?`)
          .get(key, `sim:${run.id}:0`) as { id: string; status: string;
            transfer_id: string | null; balance_hold_id: string;
            reviewer: string | null } | undefined;
        if (hold) {
          symptom = stage("verified", "run_owned_risk_hold", [ref!]);
          alert = this.alertBy("S-PIX-41", key);
          const emission = alert ? this.emission(alert, run, (observed) =>
            observed.hold_id === key && observed.policy_outcome === "approve" &&
            typeof observed.recorded_score === "number" &&
            typeof observed.policy_score === "number" &&
            observed.recorded_score > observed.policy_score) : undefined;
          if (emission && inWindow(alert!.first_seen)) detection = stage("verified",
            "hold_specific_policy_alert", [`sentinel_alerts:${alert!.id}`,
              emission.ref]);
          customer_repair = unknown(run, "customer_transfer_not_verified");
          reconciliation = unknown(run, "transfer_ledger_not_verified");
          const transfer = hold.transfer_id ? this.transfer(hold.transfer_id) : undefined;
          const caseId = alert ? this.caseFor(alert, run)?.id : undefined;
          const receipt = caseId && transfer?.ledger_tx_id ? this.receipt(caseId,
            key, transfer.id, transfer.ledger_tx_id) : undefined;
          const released = table(bank, "balance_holds") ? bank.prepare(`SELECT
            released_at FROM balance_holds WHERE id=?`).get(hold.balance_hold_id) as
            { released_at: string | null } | undefined : undefined;
          if (hold.status === "approved" && hold.reviewer === "defense-coordinator" &&
            transfer?.status === "settled" && transfer.ledger_tx_id &&
            released?.released_at && receipt) {
            continuity = stage("verified", "held_payment_settled", [`pix_transfers:${transfer.id}`]);
            customer_repair = stage("verified", "verified_customer_transfer", [receipt]);
            if (this.balanced(transfer.ledger_tx_id) && this.source.reconcile?.().ok)
              reconciliation = stage("verified", "balanced_posting_and_bank_reconciliation",
                [`ledger_entries:${transfer.ledger_tx_id}`]);
          }
        }
      } else if (id === "automatic_pix_execution_delayed") {
        const owned = table(bank, "lab_automatic_pix_delay") && bank.prepare(`SELECT 1
          FROM lab_automatic_pix_delay d JOIN pix_automatic_charges c ON c.id=d.charge_id
          WHERE d.run_id=? AND c.id=?`).get(run.id, key);
        if (owned) {
          symptom = stage("verified", "run_owned_automatic_pix_backlog", [ref!]);
          alert = this.alertBy("S-PIX-43", key);
          const emission = alert && this.emission(alert, run, (observed) =>
            observed.kind === "automatic_payment_queue" && observed.charge_id === key);
          if (emission) detection = stage("verified", "exact_sentinel_emission", [emission.ref]);
          const posting = terminal(run) ? automaticPixPosting(this.source.bank, key) : undefined;
          if (posting) {
            continuity = stage("verified", "automatic_pix_charge_settled", [ref!]);
            customer_repair = stage("verified", "automatic_pix_customer_posting_verified",
              [`pix_transfers:${posting.transfer_id}`]);
          } else customer_repair = unknown(run, "automatic_pix_settlement_pending");
          reconciliation = posting && this.source.reconcile?.().ok &&
            this.crossBookVerified(run, crossBook) ?
            stage("verified", "bank_and_external_books_reconciled", [
              `ledger_entries:${posting.ledger_tx_id}`, crossBook!.proof_ref!]) :
            unknown(run, "cross_book_reconciliation_not_proven");
        }
      } else if (id === "med_settlement_delayed" || id === "med_release_delayed") {
        const stageName = id === "med_settlement_delayed" ? "med_settlement" : "med_release";
        const med = table(bank, prefix[id].slice(0, -1)) ?
          medCompletionEvidence(bank, stageName, key) : undefined;
        if (med?.idempotency_key === `sim:${run.id}:${id}:0` && inWindow(med.enqueued_at)) {
          symptom = stage("verified", "run_owned_med_completion_backlog", [ref!]);
          alert = this.alertBy("S-LED-12", key);
          const emission = alert && this.emission(alert, run, (observed) =>
            observed.kind === stageName && observed.command_id === key);
          if (emission) detection = stage("verified", "exact_sentinel_emission", [emission.ref]);
          if (terminal(run) && med.completed_at) {
            continuity = stage("verified", `${stageName}_acknowledged`, [ref!]);
            customer_repair = stage("verified", stageName === "med_settlement" ?
              "med_original_payer_credited" : "med_holds_released_without_refund",
              [`med_cases:${key}`, ...(med.refund_ledger_tx_id ?
                [`ledger_entries:${med.refund_ledger_tx_id}`] : [])]);
          } else customer_repair = unknown(run, "med_completion_reconciliation_pending");
          reconciliation = continuity.state === "verified" && med.original_ledger_tx_id &&
            this.balanced(med.original_ledger_tx_id) &&
            (!med.refund_ledger_tx_id || this.balanced(med.refund_ledger_tx_id)) &&
            this.source.reconcile?.().ok && this.crossBookVerified(run, crossBook) ?
            stage("verified", "bank_and_external_books_reconciled", [
              ref!, `ledger_entries:${med.original_ledger_tx_id}`,
              crossBook!.proof_ref!]) :
            unknown(run, "cross_book_reconciliation_not_proven");
        }
      } else if (id === "med_analysis_delayed") {
        const med = table(bank, "med_dict_analysis_outbox") ? bank.prepare(`SELECT
          o.approved_at,o.acknowledged_at,a.analysed_at,t.ledger_tx_id,
          EXISTS (SELECT 1 FROM med_refunds r WHERE r.case_id=m.id
            AND (a.analysed_at IS NULL OR r.created_at<a.analysed_at)) AS premature_refund
          FROM med_dict_analysis_outbox o
          JOIN med_cases m ON m.id=o.case_id AND m.transfer_id=o.transfer_id
          JOIN med_decisions d ON d.case_id=m.id AND d.decision='approved'
            AND d.maker_id<>d.checker_id AND d.decided_at<=o.approved_at
          JOIN pix_transfers t ON t.id=o.transfer_id
          JOIN accounts payer ON payer.id=t.from_account AND payer.customer_id=m.customer_id
          LEFT JOIN med_dict_analyses a ON a.case_id=m.id
          WHERE o.case_id=? AND t.idempotency_key=?`)
          .get(key, `sim:${run.id}:med_analysis_delayed:0`) as {
            approved_at: string; acknowledged_at: string | null;
            analysed_at: string | null; ledger_tx_id: string | null;
            premature_refund: number } | undefined : undefined;
        if (med && inWindow(med.approved_at)) {
          symptom = stage("verified", "run_owned_med_analysis_backlog", [ref!]);
          alert = this.alertBy("S-LED-12", key);
          const emission = alert && this.emission(alert, run, (observed) =>
            observed.kind === "med_analysis" && observed.command_id === key);
          if (emission) detection = stage("verified", "exact_sentinel_emission", [emission.ref]);
          if (terminal(run) && med.acknowledged_at && med.analysed_at &&
            med.analysed_at >= med.approved_at && med.acknowledged_at >= med.analysed_at &&
            med.premature_refund === 0) {
            continuity = stage("verified", "med_analysis_acknowledged", [ref!]);
            customer_repair = stage("verified", "med_analysis_available",
              [`med_dict_analyses:${key}`]);
          } else customer_repair = unknown(run, "med_analysis_reconciliation_pending");
          reconciliation = continuity.state === "verified" && med.ledger_tx_id &&
            this.balanced(med.ledger_tx_id) && this.source.reconcile?.().ok &&
            this.crossBookVerified(run, crossBook) ?
            stage("verified", "bank_and_external_books_reconciled", [
              ref!, `ledger_entries:${med.ledger_tx_id}`, crossBook!.proof_ref!]) :
            unknown(run, "cross_book_reconciliation_not_proven");
        }
      } else if (id === "med_opening_delayed") {
        const med = table(bank, "med_psp_open_outbox") ? bank.prepare(`SELECT
          o.created_at,o.acknowledged_at,m.status,m.refunded_cents,t.ledger_tx_id
          FROM med_psp_open_outbox o JOIN med_cases m
            ON m.id=o.case_id AND m.transfer_id=o.transfer_id
          JOIN pix_transfers t ON t.id=o.transfer_id
          JOIN accounts a ON a.id=t.from_account AND a.customer_id=m.customer_id
          WHERE o.case_id=? AND t.idempotency_key=? AND t.status='settled'`)
          .get(key, `sim:${run.id}:med_opening_delayed:0`) as {
            created_at: string; acknowledged_at: string | null; status: string;
            refunded_cents: number; ledger_tx_id: string | null } | undefined : undefined;
        if (med && inWindow(med.created_at)) {
          symptom = stage("verified", "run_owned_med_opening_backlog", [ref!]);
          alert = this.alertBy("S-LED-12", key);
          const emission = alert && this.emission(alert, run, (observed) =>
            observed.kind === "med_open" && observed.command_id === key);
          if (emission) detection = stage("verified",
            "transfer_specific_sentinel_emission", [emission.ref]);
          if (terminal(run) && med.acknowledged_at &&
            med.acknowledged_at >= med.created_at && med.status === "open" &&
            med.refunded_cents === 0) {
            continuity = stage("verified", "med_opening_acknowledged", [ref!]);
            customer_repair = stage("verified", "med_review_available", [`med_cases:${key}`]);
          } else customer_repair = unknown(run, "med_opening_reconciliation_pending");
          reconciliation = continuity.state === "verified" && med.ledger_tx_id &&
            this.balanced(med.ledger_tx_id) && this.source.reconcile?.().ok &&
            this.crossBookVerified(run, crossBook) ?
            stage("verified", "bank_and_external_books_reconciled", [
              ref!, `ledger_entries:${med.ledger_tx_id}`, crossBook!.proof_ref!]) :
            unknown(run, "cross_book_reconciliation_not_proven");
        }
      } else if (id === "pix_dispatch_paused" || id === "spi_unavailable" ||
        id === "psp_receipt_delayed") {
        const outbox = id === "psp_receipt_delayed" ?
          "pix_psp_inbound_outbox" : "pix_spi_outbox";
        if (table(bank, outbox) && bank.prepare(`SELECT transfer_id FROM ${outbox}
          WHERE transfer_id=?`).get(key)) {
          const owner = bank.prepare(`SELECT idempotency_key FROM pix_transfers
            WHERE id=?`).get(key) as { idempotency_key: string } | undefined;
          symptom = owner?.idempotency_key === `sim:${run.id}:${id}:0` ?
            stage("verified", "run_owned_payment_backlog", [ref!]) :
            unknown(run, "payment_backlog_run_attribution_missing");
          // S-LED-12 names the transfer and the pending stage; S-LED-02 is aggregate.
          alert = this.alertBy("S-LED-12", key);
          const expectedKind = id === "psp_receipt_delayed" ? "inbound" : "pix";
          const emission = symptom.state === "verified" && alert ?
            this.emission(alert, run, (observed) =>
              observed.kind === expectedKind && observed.command_id === key) : undefined;
          detection = emission && inWindow(alert!.first_seen, "real") ? stage("verified",
              "transfer_specific_sentinel_emission", [emission.ref]) :
            unknown(run, "transfer_specific_sentinel_link_missing");
          const transfer = this.transfer(key);
          const row = id === "psp_receipt_delayed" ? bank.prepare(`SELECT
            acknowledged_at AS completed FROM pix_psp_inbound_outbox WHERE transfer_id=?`)
            .get(key) as { completed: string | null } : bank.prepare(`SELECT
            response_status AS completed FROM pix_spi_outbox WHERE transfer_id=?`)
            .get(key) as { completed: string | null };
          if (transfer?.status === "settled" && row.completed &&
            (id === "psp_receipt_delayed" || row.completed === "ACSC"))
            continuity = stage("verified", "payment_flow_resumed", [ref!]);
          const pspAck = table(bank, "pix_psp_inbound_outbox") ? bank.prepare(`SELECT
            acknowledged_at FROM pix_psp_inbound_outbox WHERE transfer_id=?`)
            .get(key) as { acknowledged_at: string | null } | undefined : undefined;
          customer_repair = continuity.state === "verified" && pspAck?.acknowledged_at ?
            stage("verified", "recipient_credit_acknowledged", [
              `pix_psp_inbound_outbox:${key}`]) :
            unknown(run, "recipient_credit_not_proven");
          const ledgerTx = transfer?.ledger_tx_id;
          reconciliation = customer_repair.state === "verified" && ledgerTx &&
            this.balanced(ledgerTx) && this.source.reconcile?.().ok &&
            this.crossBookVerified(run, crossBook) ?
            stage("verified", "bank_and_external_books_reconciled", [
              `ledger_entries:${ledgerTx}`, `pix_spi_outbox:${key}`,
              `pix_psp_inbound_outbox:${key}`,
              crossBook!.proof_ref!]) :
            unknown(run, "cross_book_reconciliation_not_proven");
        }
      } else if (id === "card_issuer_offline" && table(bank, "card_network_rejections")) {
        const changedBy = `fault_lab_${run.id.replaceAll("-", "_")}`;
        const rejection = bank.prepare(`SELECT r.created_at,h.id outage_id
          FROM card_network_rejections r JOIN card_issuer_history h
            ON h.available=0 AND h.changed_by=? AND h.changed_at<=r.created_at
          WHERE r.id=? AND r.response_code='91' AND NOT EXISTS (
            SELECT 1 FROM card_issuer_history later WHERE later.id>h.id
              AND later.changed_at<=r.created_at)
          ORDER BY h.id DESC LIMIT 1`).get(changedBy, key) as
          { created_at: string; outage_id: number } | undefined;
        if (rejection) {
          symptom = stage("verified", "run_owned_issuer_decline",
            [ref!, `card_issuer_history:${rejection.outage_id}`]);
          alert = this.alertBy("S-CARD-13", "card_issuer");
          const emission = alert ? this.emission(alert, run, (observed) =>
            observed.issuer_unavailable === 1 &&
            typeof observed.declined_authorizations === "number" &&
            observed.declined_authorizations > 0, rejection.created_at) : undefined;
          if (emission)
            detection = stage("verified", "issuer_outage_decline_emission",
              [emission.ref]);
          const restored = bank.prepare(`SELECT id,changed_at FROM card_issuer_history
            WHERE available=1 AND changed_by=? AND changed_at>=?
            ORDER BY id DESC LIMIT 1`).get(changedBy, rejection.created_at) as
            { id: number; changed_at: string } | undefined;
          const accepted = restored && table(bank, "card_network_authorizations") &&
            table(bank, "card_network_messages") ?
            bank.prepare(`SELECT a.id FROM card_network_authorizations a
              WHERE a.response_code='00' AND a.created_at>=?
                AND EXISTS (SELECT 1 FROM card_network_messages m
                  WHERE m.authorization_id=a.id AND m.mti='0110'
                    AND json_extract(m.payload_json,'$.response_code')='00')
              ORDER BY a.created_at LIMIT 1`).get(restored.changed_at) as
              { id: string } | undefined : undefined;
          if (restored && accepted) continuity = stage("verified",
            "issuer_restored_and_authorization_accepted",
            [`card_issuer_history:${restored.id}`,
              `card_network_authorizations:${accepted.id}`]);
          customer_repair = unknown(run, "individual_nonfinancial_harm_unknown");
          reconciliation = stage("not_applicable", "decline_has_no_posting");
        }
      }
    }
    const linked = detection.state === "verified" && alert ?
      this.caseFor(alert, run) : undefined;
    if (id === "fee_rounding_drift" && linked && alert &&
      symptom.state === "verified") {
      const repaired = this.feeRepairFor(linked, alert);
      if (repaired) {
        const refs = [`incident_case_entries:${repaired.entry}`,
          `ledger_entries:${repaired.ledgerTxId}`];
        continuity = stage("verified", "corrected_code_running", refs);
        customer_repair = stage("verified", "no_customer_overcharge", refs);
        reconciliation = stage("verified", "bank_loss_booked_and_ledger_balanced", refs);
      }
    }
    if (id === "revoked_device_access" && linked && alert &&
      symptom.state === "verified") {
      const contained = this.identityContainmentFor(linked, alert);
      if (contained) {
        continuity = stage("verified", "revoked_device_sessions_closed",
          [`incident_case_entries:${contained.entry}`,
            `telemetry_events:${contained.eventId}`]);
        const impactRows = this.source.events.db.prepare(`SELECT id,payload_json
          FROM incident_case_entries WHERE incident_id=?
            AND kind='dossier.defense_impact' AND id>? AND id<?
          ORDER BY id DESC`).all(linked.id, linked.entry,
            contained.entry) as { id: number; payload_json: string }[];
        const impactRow = impactRows.find((row) => {
          const payload = json(row.payload_json);
          return payload.case_version === linked.version &&
            payload.customer_repair_required === "yes" &&
            Array.isArray(payload.findings) && payload.findings.some((raw) => {
              if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
              const finding = raw as Record<string, unknown>;
              return finding.kind === "access" &&
                finding.entity_ref === alert.entity &&
                finding.amount_cents === null &&
                Array.isArray(finding.evidence_refs) &&
                finding.evidence_refs.includes(`sentinel_alerts:${alert.id}`) &&
                finding.evidence_refs.includes(
                  `telemetry_events:${contained.eventId}`);
            });
        });
        const noticeEntry = this.source.events.db.prepare(`SELECT id,payload_json
          FROM incident_case_entries WHERE incident_id=?
            AND kind='defense.customer_notice' AND id>?
          ORDER BY id LIMIT 1`).get(linked.id, contained.entry) as
          { id: number; payload_json: string } | undefined;
        const noticePayload = noticeEntry ? json(noticeEntry.payload_json) : {};
        const noticeRow = table(this.source.bank.db, "identity_incident_notices") ?
          this.source.bank.db.prepare(`SELECT id FROM identity_incident_notices
            WHERE incident_id=? AND customer_id=? AND alert_id=?
              AND source_event_id=? AND device_id=?`)
            .get(linked.id, alert.entity, alert.id,
              contained.eventId, contained.deviceId) as
            { id: number } | undefined : undefined;
        const notified = impactRow && noticeRow && noticeEntry &&
          noticePayload.case_version === linked.version &&
          noticePayload.kind === "revoked_device_access" &&
          noticePayload.customer_id === alert.entity &&
          noticePayload.device_id === contained.deviceId &&
          noticePayload.source_event_id === contained.eventId &&
          noticePayload.notice_id === noticeRow.id &&
          noticePayload.customer_impact === "unverified";
        customer_repair = notified ? stage(terminal(run) ? "inconclusive" :
          "pending", "customer_notified_impact_unverified",
          [`incident_case_entries:${impactRow!.id}`,
            `incident_case_entries:${noticeEntry!.id}`,
            `identity_incident_notices:${noticeRow!.id}`]) :
          unknown(run, "access_impact_and_notice_unverified");
        reconciliation = unknown(run, "financial_impact_unassessed");
        if (notified && contained.throughEventId !== undefined) {
          const entries = this.source.events.db.prepare(`SELECT id,payload_json
            FROM incident_case_entries WHERE incident_id=? AND id>?
              AND kind='defense.identity_scope_measured' ORDER BY id`)
            .all(linked.id, contained.entry) as { id: number; payload_json: string }[];
          const scopeEntry = entries.find((entry) => {
            const payload = json(entry.payload_json);
            return payload.case_version === linked.version &&
              payload.customer_id === alert.entity && payload.device_id === contained.deviceId &&
              payload.source_event_id === contained.eventId &&
              payload.through_event_id === contained.throughEventId;
          });
          if (scopeEntry) {
            const payload = json(scopeEntry.payload_json);
            const window = {
              customerId: alert.entity, deviceId: contained.deviceId,
              sourceEventId: contained.eventId, throughEventId: contained.throughEventId,
              revokedAt: contained.revokedAt,
            };
            const scope = readContainedIdentityWindow(this.source.bank.db, window);
            const scopeRef = `incident_case_entries:${scopeEntry.id}`;
            if (scope.complete && payload.complete === true &&
              JSON.stringify(scope.observed) === JSON.stringify(payload.observed))
              customer_repair = stage(terminal(run) ? "inconclusive" : "pending",
                "customer_notified_observed_scope_verified",
                [...customer_repair.evidence_refs, scopeRef]);
            const pix = payload.pix_scope_checked === true && contained.containedAtReal &&
              payload.contained_at_real === contained.containedAtReal ?
              readIdentityPixFollowup(this.source.bank.db, {
                ...window, containedAtReal: contained.containedAtReal,
              }) : undefined;
            if (pix && (pix.commands.length || pix.truncated)) {
              const followups = this.source.events.db.prepare(`SELECT id,payload_json
                FROM incident_case_entries WHERE incident_id=? AND id>?
                  AND kind='defense.identity_pix_followup' ORDER BY id DESC`)
                .all(linked.id, scopeEntry.id) as { id: number; payload_json: string }[];
              const verified = followups.find((entry) => {
                const receipt = json(entry.payload_json);
                return receipt.case_version === linked.version &&
                  receipt.source_event_id === contained.eventId &&
                  receipt.through_event_id === window.throughEventId &&
                  receipt.contained_at_real === contained.containedAtReal &&
                  receipt.truncated === pix.truncated &&
                  JSON.stringify(receipt.commands) === JSON.stringify(pix.commands);
              });
              reconciliation = stage(terminal(run) ? "inconclusive" : "pending",
                verified ? "identity_pix_followup_impact_unverified" : "identity_pix_followup_evidence_pending",
                [scopeRef, ...(verified ? [`incident_case_entries:${verified.id}`] : [])]);
            } else if ((payload.pix_scope_checked !== true || pix) &&
              payload.financial && typeof payload.financial === "object") {
              const financial = readIdentityFinancialWindow(this.source.bank.db, window, scope);
              if (JSON.stringify(financial) === JSON.stringify(payload.financial)) {
                if (financial.no_observed_posting) {
                  reconciliation = stage("verified", "no_identity_posting_in_observed_window", [scopeRef]);
                  const response = contained.replay && pix ? readLabIdentityEmptyResponse(this.source.bank.db, {
                    customerId: alert.entity, deviceId: contained.deviceId,
                    sourceEventId: contained.eventId,
                  }) : undefined;
                  if (response !== undefined && scope.observed.length === 1 &&
                    scope.observed[0]?.response_event_id === response && payload.complete === true &&
                    JSON.stringify(scope.observed) === JSON.stringify(payload.observed)) {
                    const repairs = this.source.events.db.prepare(`SELECT id,payload_json
                      FROM incident_case_entries WHERE incident_id=? AND id>?
                        AND kind='defense.identity_replay_repair_verified'`)
                      .all(linked.id, Math.max(scopeEntry.id, noticeEntry!.id)) as
                      { id: number; payload_json: string }[];
                    const repair = repairs.find((row) => {
                      const value = json(row.payload_json);
                      return value.case_version === linked.version && value.run_id === run.id &&
                        value.customer_id === alert.entity && value.device_id === contained.deviceId &&
                        value.notice_id === noticeRow!.id && value.source_event_id === contained.eventId &&
                        value.response_event_id === response && value.through_event_id === window.throughEventId;
                    });
                    if (repair) customer_repair = stage("verified", "identity_replay_notice_and_scope_verified",
                      [...customer_repair.evidence_refs, scopeRef,
                        `telemetry_events:${response}`, `incident_case_entries:${repair.id}`]);
                  }
                }
                else if (financial.verified_postings.length)
                  reconciliation = stage(terminal(run) ? "inconclusive" : "pending",
                    "identity_linked_posting_impact_unverified", [scopeRef,
                      ...financial.verified_postings.map((posting) =>
                        `ledger_entries:${posting.ledger_tx_id}`)]);
              }
            }
          }
        }
      }
    }
    if (id === "risk_missed_hold" && linked && alert &&
      symptom.state === "verified") {
      const receipt = table(this.source.bank.db, "lab_risk_miss_receipts") ?
        this.source.bank.db.prepare(`SELECT transfer_id FROM
          lab_risk_miss_receipts WHERE run_id=?`).get(run.id) as
          { transfer_id: string } | undefined : undefined;
      const control = receipt ? this.fraudControlFor(linked, alert,
        receipt.transfer_id) : undefined;
      if (control) {
        continuity = stage("verified", control.replay ? "fraud_hold_policy_verified" :
          "fraud_hold_policy_restored",
          [`incident_case_entries:${control.entry}`]);
        if (this.balanced(control.ledgerTxId) &&
          this.source.reconcile?.().ok === true)
          reconciliation = stage("verified", "balanced_payment_posting",
            [`ledger_entries:${control.ledgerTxId}`]);
        const impactRows = this.source.events.db.prepare(`SELECT id,payload_json
          FROM incident_case_entries WHERE incident_id=?
            AND kind='dossier.defense_impact' AND id>? AND id<?
          ORDER BY id DESC`).all(linked.id, linked.entry,
            control.entry) as { id: number; payload_json: string }[];
        const impact = impactRows.find((row) => {
          const payload = json(row.payload_json);
          return payload.case_version === linked.version &&
            Array.isArray(payload.findings) && payload.findings.some((raw) => {
              if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
              const finding = raw as Record<string, unknown>;
              return finding.kind === "money_candidate" &&
                finding.entity_ref === receipt?.transfer_id &&
                finding.amount_cents === 4_800 &&
                Array.isArray(finding.evidence_refs) &&
                finding.evidence_refs.includes(`sentinel_alerts:${alert.id}`) &&
                finding.evidence_refs.includes(
                  `pix_transfers:${receipt?.transfer_id}`);
            });
        });
        customer_repair = impact ? stage(terminal(run) ? "inconclusive" :
          "pending", "suspicious_payment_impact_unverified",
          [`incident_case_entries:${impact.id}`,
            `pix_transfers:${receipt!.transfer_id}`]) :
          unknown(run, "suspicious_payment_impact_not_assessed");
        if (impact && table(this.source.bank.db, "fraud_incident_notices")) {
          const notice = this.source.bank.db.prepare(`SELECT n.id,n.customer_id
            FROM fraud_incident_notices n JOIN pix_transfers p
              ON p.id=n.transfer_id JOIN accounts a ON a.id=p.from_account
            WHERE n.incident_id=? AND n.alert_id=? AND n.transfer_id=?
              AND n.customer_id=a.customer_id AND n.kind='suspicious_pix_review'`)
            .get(linked.id, alert.id, receipt!.transfer_id) as
            { id: number; customer_id: string } | undefined;
          const rows = this.source.events.db.prepare(`SELECT id,payload_json
            FROM incident_case_entries WHERE incident_id=?
              AND kind='defense.customer_notice' AND id>?
            ORDER BY id DESC`).all(linked.id, control.entry) as
            { id: number; payload_json: string }[];
          const entry = rows.find((row) => {
            const payload = json(row.payload_json);
            return notice && payload.case_version === linked.version &&
              payload.kind === "suspicious_pix_review" &&
              payload.customer_id === notice.customer_id &&
              payload.alert_id === alert.id &&
              payload.transfer_id === receipt!.transfer_id &&
              payload.notice_id === notice.id &&
              payload.customer_impact === "unverified";
          });
          if (notice && entry) {
            customer_repair = stage(terminal(run) ? "inconclusive" :
              "pending", "suspicious_payment_customer_notified_impact_unverified",
              [`incident_case_entries:${impact.id}`,
                `incident_case_entries:${entry.id}`,
                `fraud_incident_notices:${notice.id}`]);
            const bank = this.source.bank.db;
            if (table(bank, "med_cases") && table(bank, "med_decisions") &&
              table(bank, "med_refunds")) {
              const dispute = bank.prepare(`SELECT id FROM med_cases
                WHERE transfer_id=? AND customer_id=?`).get(
                  receipt!.transfer_id, notice.customer_id) as
                  { id: string } | undefined;
              if (dispute) customer_repair = stage(terminal(run) ? "inconclusive" :
                "pending", "customer_dispute_recorded_repair_unverified",
                [`incident_case_entries:${entry.id}`,
                  `med_cases:${dispute.id}`]);
              const repairs = this.source.events.db.prepare(`SELECT id,kind,payload_json
                FROM incident_case_entries WHERE incident_id=?
                  AND kind IN ('defense.customer_repair_verified',
                    'defense.customer_dispute_outcome') AND id>?
                ORDER BY (kind='defense.customer_repair_verified') DESC,id DESC`)
                .all(linked.id, entry.id) as
                { id: number; kind: string; payload_json: string }[];
              for (const repair of repairs) {
                const payload = json(repair.payload_json);
                const full = repair.kind === "defense.customer_repair_verified";
                const evidenceRefs = Array.isArray(payload.evidence_refs) ? payload.evidence_refs : [];
                const refundIds = full ? payload.refund_ids : evidenceRefs
                  .filter((ref): ref is string => typeof ref === "string" &&
                    ref.startsWith("med_refunds:"))
                  .map((ref) => ref.slice("med_refunds:".length));
                if (payload.case_version !== linked.version ||
                  payload.customer_id !== notice.customer_id ||
                  payload.transfer_id !== receipt!.transfer_id ||
                  (full && (payload.notice_id !== notice.id || payload.bank_reconciled !== true)) ||
                  !dispute || payload.med_case_id !== dispute.id ||
                  !Array.isArray(refundIds)) continue;
                const med = bank.prepare(`SELECT m.id,m.status,m.customer_id,
                  m.claim_amount_cents,m.refunded_cents,m.unrecovered_cents,
                  p.amount,p.from_account,a.customer_id account_customer
                  FROM med_cases m JOIN pix_transfers p ON p.id=m.transfer_id
                  JOIN accounts a ON a.id=p.from_account
                  WHERE m.id=? AND m.transfer_id=?`).get(payload.med_case_id,
                    receipt!.transfer_id) as { id: string; status: string;
                    customer_id: string; claim_amount_cents: number;
                    refunded_cents: number; unrecovered_cents: number;
                    amount: number; from_account: string;
                    account_customer: string } | undefined;
                if (!med || med.customer_id !== notice.customer_id ||
                  med.account_customer !== notice.customer_id ||
                  med.amount !== med.claim_amount_cents ||
                  !Number.isSafeInteger(med.amount) || med.amount <= 0) continue;
                const rejected = !full && med.status === "rejected" &&
                  med.refunded_cents === 0 && med.unrecovered_cents === 0;
                const incomplete = med.status === "resolved" &&
                  med.refunded_cents >= 0 && med.unrecovered_cents > 0 &&
                  med.refunded_cents + med.unrecovered_cents === med.amount;
                const compensation = full && incomplete &&
                  payload.bank_compensation_cents === med.unrecovered_cents ?
                  readMedIncidentCompensation(bank, { caseId: med.id,
                    sourceAccount: med.from_account, amount: med.unrecovered_cents }) : undefined;
                const fullyRefunded = med.status === "refunded" &&
                  med.refunded_cents === med.amount && med.unrecovered_cents === 0;
                const outcome = rejected ? "claim_rejected" : incomplete ?
                  med.refunded_cents > 0 ? "partial_refund" : "no_funds_recovered" : null;
                if (full ? payload.amount_cents !== med.amount ||
                  (!fullyRefunded && (!compensation || compensation.txId !== payload.bank_compensation_tx_id)) :
                  !outcome || payload.outcome !== outcome ||
                  payload.refunded_cents !== med.refunded_cents ||
                  payload.unrecovered_cents !== (rejected ? null : med.unrecovered_cents) ||
                  !evidenceRefs.includes(`sentinel_alerts:${alert.id}`)) continue;
                if (!bank.prepare(`SELECT 1 FROM med_decisions WHERE case_id=?
                    AND decision=? AND maker_id<>checker_id
                    AND evidence_ref=?`)
                    .get(med.id, rejected ? "rejected" : "approved",
                      `sentinel_alerts:${alert.id}`)) continue;
                const refunds = bank.prepare(`SELECT id,amount,ledger_tx_id
                  FROM med_refunds WHERE case_id=? ORDER BY id`).all(med.id) as
                  { id: string; amount: number; ledger_tx_id: string }[];
                if (refunds.length !== refundIds.length ||
                  refunds.reduce((sum, item) => sum + item.amount, 0) !==
                    med.refunded_cents ||
                  new Set(refunds.map((item) => item.ledger_tx_id)).size !==
                    refunds.length) continue;
                let creditsVerified = true;
                for (const item of refunds) {
                  if (!refundIds.includes(item.id) || !Number.isSafeInteger(item.amount) ||
                    item.amount <= 0) {
                    creditsVerified = false;
                    break;
                  }
                  if (!hasMedCustomerCredit(bank, { sourceAccount: med.from_account,
                    sourceId: med.id, txId: item.ledger_tx_id, amount: item.amount,
                    kind: "med_refund", refType: "pix", refId: receipt!.transfer_id })) {
                    creditsVerified = false;
                    break;
                  }
                }
                if (!creditsVerified) continue;
                if (this.source.reconcile?.().ok !== true) continue;
                const refs = [`incident_case_entries:${repair.id}`, `med_cases:${med.id}`,
                  ...refunds.map((item) => `med_refunds:${item.id}`)];
                if (!full) {
                  const reason = rejected ? "med_claim_rejected_impact_unresolved" :
                    med.refunded_cents > 0 ? "med_partial_refund_remaining" : "med_no_funds_recovered";
                  customer_repair = stage(terminal(run) ? "inconclusive" : "pending", reason, refs);
                  break;
                }
                const compensationRef = compensation ? [`ledger_entries:${compensation.txId}`] : [];
                customer_repair = stage("verified", compensation ?
                  "approved_med_compensation_verified" : "approved_med_refund_verified",
                  [...refs, ...compensationRef]);
                reconciliation = stage("verified", "payment_and_med_refund_balanced",
                  [`ledger_entries:${control.ledgerTxId}`,
                    ...refunds.map((item) => `ledger_entries:${item.ledger_tx_id}`), ...compensationRef]);
                break;
              }
            }
          }
        }
      }
    }
    if (id === "card_issuer_offline" && linked?.version && key) {
      const impactRows = this.source.events.db.prepare(`SELECT id,payload_json
        FROM incident_case_entries WHERE incident_id=?
          AND kind='dossier.defense_impact' AND id>?
        ORDER BY id DESC`).all(linked.id, linked.entry) as
        { id: number; payload_json: string }[];
      const impact = impactRows.find((row) => {
        const payload = json(row.payload_json);
        return payload.case_version === linked.version &&
          Array.isArray(payload.findings) && payload.findings.some((raw) => {
            const finding = raw && typeof raw === "object" ?
              raw as Record<string, unknown> : {};
            return finding.kind === "service_unavailable" &&
              Array.isArray(finding.evidence_refs) &&
              finding.evidence_refs.includes(`card_network_rejections:${key}`);
          });
      });
      if (impact) {
        const findings = json(impact.payload_json).findings as unknown[];
        const customers = findings.flatMap((raw) => {
          const finding = raw && typeof raw === "object" ?
            raw as Record<string, unknown> : {};
          return finding.kind === "service_unavailable" &&
            typeof finding.entity_ref === "string" ?
            [{ id: finding.entity_ref, refs: finding.evidence_refs }] : [];
        });
        const notices = table(this.source.bank.db, "incident_customer_notices") ?
          customers.map((customer) => {
            const row = this.source.events.db.prepare(`SELECT id,payload_json
              FROM incident_case_entries WHERE incident_id=?
                AND kind='defense.customer_notice' AND id>?
              ORDER BY id DESC`).all(linked.id, impact.id) as
              { id: number; payload_json: string }[];
            return row.find((entry) => {
              const payload = json(entry.payload_json);
              const rejectionRef = `card_network_rejections:${payload.rejection_id}`;
              const noticeId = payload.notice_id;
              const rejectionId = payload.rejection_id;
              return payload.case_version === linked.version &&
                payload.customer_id === customer.id &&
                Array.isArray(customer.refs) &&
                customer.refs.includes(rejectionRef) &&
                typeof noticeId === "number" && Number.isSafeInteger(noticeId) &&
                typeof rejectionId === "string" &&
                Boolean(this.source.bank.db.prepare(`SELECT 1 FROM
                  incident_customer_notices WHERE incident_id=? AND customer_id=?
                    AND id=? AND rejection_id=? AND kind='card_issuer_recovered'`)
                  .get(linked.id, customer.id, noticeId, rejectionId));
            });
          }) : [];
        const notified = customers.length > 0 && notices.length === customers.length &&
          notices.every(Boolean);
        const retries = notified ? notices.map((notice, index) => {
          if (!notice) return null;
          const payload = json(notice.payload_json);
          const rejectionId = String(payload.rejection_id);
          const customerId = customers[index]?.id;
          const noticeId = payload.notice_id;
          if (!customerId || typeof noticeId !== "number" ||
            !Number.isSafeInteger(noticeId)) return null;
          const source = this.source.bank.db.prepare(`SELECT card_id,merchant_id,amount_cents
            FROM card_network_rejections WHERE id=?`).get(rejectionId) as
            { card_id: string | null; merchant_id: string;
              amount_cents: number } | undefined;
          const noticeRow = this.source.bank.db.prepare(`SELECT created_at FROM
            incident_customer_notices WHERE customer_id=? AND id=?
              AND rejection_id=?`).get(customerId, noticeId,
                rejectionId) as { created_at: string } | undefined;
          if (!source?.card_id || !noticeRow) return null;
          const events = this.source.events.db.prepare(`SELECT e.seq,
            p.private_json FROM events e JOIN event_private p ON p.seq=e.seq
            WHERE e.type='sim.card_retry' AND e.twin_ts>=? ORDER BY e.seq`)
            .all(noticeRow.created_at) as { seq: number; private_json: string }[];
          for (const event of events) {
            const detail = json(event.private_json);
            if (detail?.rejection_id !== rejectionId ||
              detail.customer_id !== customerId ||
              typeof detail.authorization_id !== "string") continue;
            const authorized = this.source.bank.db.prepare(`SELECT a.id FROM
              card_network_authorizations a WHERE a.id=? AND a.card_id=?
                AND a.merchant_id=? AND a.amount_cents=? AND
                a.response_code='00' AND a.created_at>=? AND EXISTS (
                  SELECT 1 FROM card_network_messages m WHERE
                    m.authorization_id=a.id AND m.mti='0110' AND
                    json_extract(m.payload_json,'$.response_code')='00')`)
              .get(detail.authorization_id, source.card_id,
                source.merchant_id, source.amount_cents,
                noticeRow.created_at) as { id: string } | undefined;
            if (authorized) return { event: event.seq, authorization: authorized.id };
          }
          return null;
        }) : [];
        const repaired = notified && retries.length === customers.length &&
          retries.every(Boolean) && continuity.state === "verified";
        customer_repair = stage(repaired ? "verified" :
          terminal(run) ? "inconclusive" : "pending",
          repaired ? "affected_customer_retry_authorized" :
            notified ? "customer_notified_retry_unproven" :
              "known_service_harm_not_repaired",
          [`incident_case_entries:${impact.id}`,
            ...notices.flatMap((notice) => notice ?
              [`incident_case_entries:${notice.id}`] : []),
            ...retries.flatMap((retry) => retry ?
              [`events:${retry.event}`,
                `card_network_authorizations:${retry.authorization}`] : [])]);
      }
    }
    const caseStage = linked ? stage("verified", "case_contains_exact_alert",
      [`incident_case:${linked.id}`, `incident_case_entries:${linked.entry}`]) :
      unknown(run, "matching_defense_case_missing");
    const response = this.responseFor(run, id, linked, continuity, customer_repair,
      reconciliation, symptom, key, alert);
    const stages = [symptom, detection, caseStage, response, continuity, customer_repair,
      reconciliation];
    const watch = this.watchFor(run, id, alert, stages, response, customer_repair);
    stages.push(watch);
    const verdict = stages.some((value) => value.state === "inconclusive") ?
      "inconclusive" : stages.some((value) => value.state === "pending") ?
      "pending" : run.status === "expired" ? "passed" :
        terminal(run) ? "inconclusive" : "pending";
    return { fixture_id: id, symptom, detection, case: caseStage, response, continuity,
      customer_repair, reconciliation, watch, verdict };
  }
}
