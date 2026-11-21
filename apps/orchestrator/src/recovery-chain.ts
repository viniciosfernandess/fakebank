import { randomUUID } from "node:crypto";
import { z } from "zod";
import { BankError, type Bank } from "../../world/src/bank.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import { IncidentCaseFile } from "../../../packages/event-store/src/incident-case-file.ts";
import type { Area } from "../../../packages/contracts/src/index.ts";
import { damageReportBody, restorationReportBody } from "../../../packages/contracts/src/dossiers.ts";
import type { AgentTool, AgentTransport } from "./agent-loop.ts";
import { agentExecutor, type AgentRuntime } from "./runtime/agent-runtime.ts";
import type { BudgetLedger } from "./budget.ts";
import { BlueInvestigation } from "./blue-investigation.ts";
import { BlueRestoration, type DamageFinding } from "./blue-restoration.ts";
import { RecoveryAux, isRestorableAuxiliary } from "./recovery-aux.ts";
import { BlueMedRecovery, type ExternalDamage } from "./blue-med-recovery.ts";
import type { EcosystemClient } from "../../ecosystem/src/client.ts";
import { publishMoneyFlowDisclosures, publishMoneyFlowMedSnapshots,
  publishSeparatedMoneyFlowMedSnapshots } from
  "./money-flow-disclosure.ts";

const id = z.string().min(1).max(128);
const brl = (cents: number): number => cents / 100;

export class RecoveryChain {
  readonly bank: Bank;
  readonly events: EventStore;
  readonly budget: BudgetLedger | undefined;
  readonly transport: AgentTransport | undefined;
  readonly runtime: AgentRuntime | undefined;
  readonly separatedMed: { project: (transferId: string, caseId?: string) =>
    ReturnType<EcosystemClient["moneyFlowProjection"]>;
    dispatchOpenings: () => Promise<number> } | undefined;
  constructor(input: { bank: Bank; events: EventStore; budget?: BudgetLedger;
    transport?: AgentTransport; runtime?: AgentRuntime;
    separatedMed?: { project: (transferId: string, caseId?: string) =>
      ReturnType<EcosystemClient["moneyFlowProjection"]>;
      dispatchOpenings: () => Promise<number> } }) {
    this.bank = input.bank; this.events = input.events;
    this.budget = input.budget; this.transport = input.transport; this.runtime = input.runtime;
    this.separatedMed = input.separatedMed;
    if (this.bank.isSeparatedEcosystem !== Boolean(this.separatedMed))
      throw new Error("RECOVERY_ECOSYSTEM_ADAPTER_REQUIRED");
  }
  async run(input: { roundId: string; incidentId: string; deadlineAt: number }): Promise<{
    status: "clean" | "restored" | "partial"; reason?: string }> {
    const restoration = new BlueRestoration(this.bank, this.events);
    const auxiliary = new RecoveryAux(this.bank, this.events);
    const med = new BlueMedRecovery(this.bank, input.incidentId, input.roundId);
    const investigation = new BlueInvestigation(this.bank, input.incidentId);
    const incident = this.bank.db.prepare("SELECT area,opened_at FROM sentinel_incidents WHERE id=?")
      .get(input.incidentId) as { area: Area; opened_at: string };
    this.events.caseFile.open(input.incidentId, incident.area, incident.opened_at);
    publishMoneyFlowDisclosures(this.bank, this.events, input.roundId, input.incidentId);
    const codexTables = this.events.db.prepare(`SELECT COUNT(*) n FROM sqlite_master
      WHERE type='table' AND name IN ('codex_usage_agents','role_tool_calls')`)
      .get() as { n: number };
    if (codexTables.n === 2) {
      const unreconciled = this.events.db.prepare(`SELECT a.agent_id
        FROM codex_usage_agents a JOIN events e
          ON e.round_id=a.run_id AND e.incident_id=? AND e.type='context.handoff'
          AND json_extract(e.public_json,'$.to')=a.agent_id
          AND json_extract(e.public_json,'$.dossier_kind')='RestorationRequest'
        WHERE a.run_id=? AND a.role='restorer'
          AND NOT EXISTS (SELECT 1 FROM incident_case_entries c
            WHERE c.incident_id=? AND c.kind='dossier.restoration' AND c.actor_id=a.agent_id)
          AND (a.status IS NULL OR a.status='ok' OR EXISTS (
            SELECT 1 FROM role_tool_calls t WHERE t.run_id=a.run_id
              AND t.agent_id=a.agent_id AND t.kind='restore'))
        LIMIT 1`).get(input.incidentId, input.roundId, input.incidentId);
      if (unreconciled)
        return { status: "partial", reason: "restorer_interrupted_requires_reconciliation" };
    }
    const to = this.bank.now().toISOString();
    const started = this.events.list({ roundId: input.roundId,
      types: ["round.started"], limit: 1 })[0]?.twin_ts;
    const startedAt = Date.parse(started ?? "");
    const openedAt = Date.parse(incident.opened_at);
    this.bank.db.exec(`CREATE TABLE IF NOT EXISTS blue_recovery_windows (
      incident_id TEXT PRIMARY KEY REFERENCES sentinel_incidents(id),
      from_ts TEXT NOT NULL
    )`);
    const priorWindow = this.bank.db.prepare(`SELECT from_ts FROM blue_recovery_windows
      WHERE incident_id=?`).get(input.incidentId) as { from_ts: string } | undefined;
    const earliestLinked = this.bank.db.prepare(`SELECT MIN(p.settled_at) first_settled
      FROM sentinel_incident_transfer_evidence e JOIN pix_transfers p ON p.id=e.transfer_id
      WHERE e.incident_id=?`).get(input.incidentId) as { first_settled: string | null };
    const linkedAt = Date.parse(earliestLinked.first_settled ?? "");
    const proposedFrom = new Date(Math.min(Number.isFinite(startedAt) ? startedAt : openedAt,
      openedAt, Number.isFinite(linkedAt) ? linkedAt : openedAt) - 10 * 60_000).toISOString();
    this.bank.db.prepare(`INSERT INTO blue_recovery_windows (incident_id,from_ts) VALUES (?,?)
      ON CONFLICT(incident_id) DO UPDATE SET from_ts=MIN(from_ts,excluded.from_ts)`)
      .run(input.incidentId, proposedFrom);
    const from = (this.bank.db.prepare("SELECT from_ts FROM blue_recovery_windows WHERE incident_id=?")
      .get(input.incidentId) as { from_ts: string }).from_ts;
    const internalFrom = new Date((Number.isFinite(startedAt) ? startedAt :
      priorWindow ? this.bank.now().getTime() : openedAt) - 10 * 60_000).toISOString();
    const externalBatch = async (at: string): Promise<ExternalDamage[]> => {
      const scanned = this.separatedMed ?
        await med.scanSeparated(from, at, this.separatedMed.project) : med.scan(from, at);
      const open = scanned.filter((finding) => finding.claimCents > 0);
      return [...open.filter((finding) => !finding.medCaseId),
        ...open.filter((finding) => finding.medCaseId)].slice(0, 50);
    };
    let findings: DamageFinding[];
    let auxiliaryFindings: ReturnType<RecoveryAux["scan"]>;
    let externalFindings: ExternalDamage[];
    let unverifiedExternal: string[];
    try {
      findings = restoration.scan({ incidentId: input.incidentId,
        roundId: input.roundId, from: internalFrom, to })
        .filter((finding) => finding.status === "open");
      auxiliaryFindings = auxiliary.scan(input.incidentId, from, to);
      externalFindings = await externalBatch(to);
      unverifiedExternal = med.unverified(from, to).slice(0, 50);
    } catch (error) {
      if (error instanceof BankError && error.code === "DEF_DAMAGE_SCAN_TRUNCATED")
        return { status: "partial", reason: "damage_scan_truncated" };
      throw error;
    }
    const loop = agentExecutor(this.events, this.budget, this.runtime, this.transport);
    const remember = (kind: string, actorId: string, payload: Record<string, unknown>): void => {
      this.events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
        kind, actorId, createdAt: new Date().toISOString(), payload });
    };
    const recordResolvedMed = async (at: string): Promise<void> => {
      for (const damage of med.financialState(from, at)) {
        if (damage.medStatus !== "resolved" && damage.medStatus !== "bank_compensated")
          continue;
        if (!damage.medCaseId && !damage.compensationId) continue;
        const restoredCents = damage.refundedCents + damage.absorbedCents;
        this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
          twin_ts: this.bank.now().toISOString(), type: "damage.restored",
          actor: { id: "med-recovery", role: "restorer" }, area: "pix",
          incident_id: input.incidentId,
          public_summary_pt: damage.compensationId ?
            "Cliente ressarcido pelo banco após prazo do MED" : "Cliente reparado pelo MED",
          public: { incident_id: input.incidentId, restored_cents: restoredCents,
            customers_made_whole: 1, drift_after_cents: this.bank.balanceDriftCents(),
            recovered_cents: damage.refundedCents, absorbed_cents: damage.absorbedCents },
          private: { med_case_id: damage.medCaseId,
            compensation_id: damage.compensationId, transfer_id: damage.transferId,
            evidence_ref: damage.evidenceRef } },
        `external:resolved:${input.incidentId}:${damage.medCaseId ?? damage.compensationId}`);
      }
      if (this.separatedMed) await publishSeparatedMoneyFlowMedSnapshots(this.bank,
        this.events, input.roundId, input.incidentId, (transferId, caseId) =>
          this.separatedMed!.project(transferId, caseId));
      else publishMoneyFlowMedSnapshots(this.bank, this.events,
        input.roundId, input.incidentId);
    };
    const handoff = (fromId: string, fromRole: "damage_assessor" | "restorer",
      toId: string, kind: string, context: Record<string, unknown>): void => {
      this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
        twin_ts: this.bank.now().toISOString(), type: "context.handoff",
        actor: { id: fromId, role: fromRole }, area: incident.area,
        incident_id: input.incidentId, public_summary_pt: "Análise de recuperação encaminhada",
        public: { from: fromId, to: toId, dossier_kind: kind,
          summary_pt: "Recuperação do incidente", context_sha256: IncidentCaseFile.digest(context),
          inherited: ["damage", "restoration"] }, private: context });
    };
    const recordExternalAssessment = (checkNo: 1 | 2 | "final", at: string): void => {
      if (!externalFindings.length) return;
      const lossCents = findings.reduce((sum, finding) => sum + finding.amountCents, 0) +
        externalFindings.reduce((sum, finding) => sum + finding.claimCents, 0);
      const snapshot = externalFindings.map((finding) => ({ transfer_id: finding.transferId,
        claim_cents: finding.claimCents, blocked_cents: finding.blockedCents,
        escaped_cents: finding.escapedCents, med_status: finding.medStatus,
        med_eligible: finding.medEligible }));
      const digest = IncidentCaseFile.digest(snapshot);
      this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
        twin_ts: this.bank.now().toISOString(), type: "damage.assessed",
        actor: { id: "damage-assessor", role: "damage_assessor" }, area: "pix",
        incident_id: input.incidentId, public_summary_pt: "Dano interbancário avaliado",
        public: { incident_id: input.incidentId, loss_cents: lossCents,
          customers_affected: new Set([...findings.map((finding) => finding.victimAccount),
            ...externalFindings.map((finding) => finding.victimAccount)]).size,
          exposure_cents: 0, summary_pt: `${externalFindings.length} Pix externo(s) pendente(s)`,
          blocked_cents: externalFindings.reduce((sum, finding) => sum + finding.blockedCents, 0),
          escaped_cents: externalFindings.reduce((sum, finding) => sum + finding.escapedCents, 0) },
        private: { from, to: at, check_no: checkNo, external_findings: snapshot } },
      `damage:med:${input.incidentId}:${input.roundId}:${checkNo}:${digest}`);
    };
    await recordResolvedMed(to);
    recordExternalAssessment(1, to);
    const assessorId = `damage_assessor_${randomUUID()}`;
    let scanCalled = false;
    const originalFindings = new Map<string, { kind: string; amountBrl: number }>();
    const traceIds = new Set(findings.map((finding) => finding.txId));
    const accountIds = new Set(findings.flatMap((finding) =>
      [finding.victimAccount, finding.attackerAccount]));
    for (const finding of externalFindings) accountIds.add(finding.victimAccount);
    const tool = <T>(name: string, kind: AgentTool["kind"], schema: z.ZodType<T>,
      description: string, execute: (value: T) => unknown): AgentTool => ({ name, kind, schema,
      description, execute: async (value: unknown) => execute(schema.parse(value)) });
    const traceSchema = z.strictObject({ tx_id: id });
    const assessorTools: AgentTool[] = [
      tool("ledger.scan_damage", "investigate", z.strictObject({ incident_id: id }),
        "List every bank-verified damage finding in this incident.", (value) => {
          if (value.incident_id !== input.incidentId) throw new Error("INCIDENT_SCOPE");
          scanCalled = true;
          return [...findings.map((finding) => ({ kind: "unreversed_outflow", ref: finding.id,
            tx_id: finding.txId, victim_account: finding.victimAccount,
            amount_brl: brl(finding.amountCents) })),
            ...externalFindings.map((finding) => ({ kind: "external_pix_med",
              ref: finding.transferId, victim_account: finding.victimAccount,
              amount_brl: brl(finding.claimCents), available_brl: brl(finding.availableCents),
              blocked_brl: brl(finding.blockedCents), escaped_brl: brl(finding.escapedCents),
              med_status: finding.medStatus })),
            ...auxiliaryFindings.map((finding) => ({ kind: finding.kind, ref: finding.ref,
              amount_brl: 0 }))];
        }),
      tool("med.status", "investigate", z.strictObject({ transfer_id: id }),
        "Show verified PSP hops, blocked funds, escaped funds and MED state for this incident.",
        (value) => {
          if (!externalFindings.some((finding) => finding.transferId === value.transfer_id))
            throw new BankError("DEF_INCIDENT_SCOPE");
          return this.separatedMed ? med.statusSeparated(value.transfer_id, from,
            this.bank.now().toISOString(), this.separatedMed.project) :
            med.status(value.transfer_id, from, this.bank.now().toISOString());
        }),
      tool("ledger.trace", "investigate", traceSchema,
        "Trace a verified damage transaction in this incident.", (value) => {
          if (!traceIds.has(value.tx_id)) throw new BankError("DEF_INCIDENT_SCOPE");
          return investigation.trace({ txId: value.tx_id, depth: 1 });
        }),
      tool("accounts.balance_check", "investigate", z.strictObject({ account_id: id }),
        "Compare an affected account's cached balance with its ledger postings.", (value) => {
          if (!accountIds.has(value.account_id)) throw new Error("ACCOUNT_SCOPE");
          const cached = this.bank.account(value.account_id).balance_cached;
          const actual = this.bank.db.prepare("SELECT COALESCE(SUM(amount),0) n FROM ledger_entries WHERE account_id=?")
            .get(value.account_id) as { n: number };
          return { account_id: value.account_id, drift_cents: cached - actual.n };
        }),
      tool("sessions.list_suspicious", "investigate", z.strictObject({}),
        "List active sessions on devices already revoked in this incident.", () =>
          auxiliaryFindings.filter((finding) => finding.kind === "live_session")),
      tool("keys.list_suspicious", "investigate", z.strictObject({}),
        "List active, used proximity keys tied to this incident.", () =>
          auxiliaryFindings.filter((finding) => finding.kind === "live_key")),
      tool("containment.list_active", "investigate", z.strictObject({}),
        "List incident containments still affecting honest accounts.", () =>
          auxiliaryFindings.filter((finding) => finding.kind === "frozen_honest_account")),
    ];
    const validDamage = (body: z.infer<typeof damageReportBody>, checkNo: 1 | 2): boolean => {
      if (!scanCalled || body.incident_id !== input.incidentId || body.check_no !== checkNo ||
        body.findings.some((finding) => (checkNo === 1 && finding.status !== "open") ||
          finding.refs.length !== 1 || finding.evidence_call_ids.length === 0) ||
        body.needs_restoration !== Boolean(findings.length || externalFindings.length || auxiliaryFindings.length))
        return false;
      const reported = body.findings.filter((finding) => finding.kind === "unreversed_outflow" &&
        finding.status === "open");
      const reportedMed = body.findings.filter((finding) => finding.kind === "external_pix_med" &&
        finding.status === "open");
      const reportedAux = body.findings.filter((finding) => finding.kind !== "unreversed_outflow" &&
        finding.kind !== "external_pix_med" &&
        finding.status === "open");
      const openRefs = new Set([...findings.map((finding) => finding.id),
        ...externalFindings.map((finding) => finding.transferId),
        ...auxiliaryFindings.map((finding) => finding.ref)]);
      const clean = body.findings.filter((finding) => finding.status === "clean");
      if (clean.some((finding) => {
        const prior = originalFindings.get(finding.refs[0]!);
        return !prior || openRefs.has(finding.refs[0]!) || prior.kind !== finding.kind ||
          Math.abs(prior.amountBrl - finding.amount_brl) >= 0.001;
      }) || new Set(body.findings.map((finding) => finding.refs[0])).size !== body.findings.length)
        return false;
      return reported.length === findings.length && findings.every((finding) =>
        reported.some((item) => item.refs.includes(finding.id) &&
          Math.abs(item.amount_brl - brl(finding.amountCents)) < 0.001)) &&
        reportedMed.length === externalFindings.length && externalFindings.every((finding) =>
          reportedMed.some((item) => item.refs.includes(finding.transferId) &&
            Math.abs(item.amount_brl - brl(finding.claimCents)) < 0.001)) &&
        reportedAux.length === auxiliaryFindings.length && auxiliaryFindings.every((finding) =>
          reportedAux.some((item) => item.kind === finding.kind &&
            item.refs.includes(finding.ref) && item.amount_brl === 0)) &&
        Math.abs(body.total_open_brl - brl(findings.reduce((sum, item) =>
          sum + item.amountCents, externalFindings.reduce((sum, item) =>
            sum + item.claimCents, 0)))) < 0.001;
    };
    const assessed = await loop.run({ runId: input.roundId, agentId: assessorId,
      role: "damage_assessor", deadlineAt: input.deadlineAt,
      goalPt: "Conferir danos restantes após a correção", snapshot: {
        incidentId: input.incidentId, window: { from, to } },
      dossier: { incidentId: input.incidentId, findingIds: findings.map((finding) => finding.id),
        externalFindings, unverifiedExternal, auxiliaryFindings },
      dossierSchema: damageReportBody,
      validateDossier: (body) => validDamage(body, 1), tools: assessorTools });
    if (assessed.status !== "ok" || !assessed.data)
      return { status: "partial", reason: `damage_assessor:${assessed.status}` };
    remember("dossier.damage_1", assessorId, { ...assessed.data });
    for (const finding of assessed.data.findings)
      originalFindings.set(finding.refs[0]!, { kind: finding.kind,
        amountBrl: finding.amount_brl });
    const otherOpen = auxiliaryFindings.some((finding) => !isRestorableAuxiliary(finding.kind));
    if (!findings.length && !externalFindings.length && !auxiliaryFindings.some((finding) =>
      isRestorableAuxiliary(finding.kind))) return unverifiedExternal.length ?
        { status: "partial", reason: "external_damage_unverified" } : otherOpen ?
          { status: "partial", reason: "irreversible_damage" } : { status: "clean" };
    const allowed = new Set(findings.map((finding) => finding.id));
    const allowedMed = new Set(externalFindings.map((finding) => finding.transferId));
    const allowedAux = new Map(auxiliaryFindings.map((finding) => [finding.ref, finding]));
    const applied = new Set<string>();
    const restorerId = `restorer_${randomUUID()}`;
    const restorerContext = { report: assessed.data, policy: { max_total_brl: 50_000 } };
    handoff(assessorId, "damage_assessor", restorerId, "RestorationRequest", restorerContext);
    const restorerTools: AgentTool[] = [
      tool("med.status", "investigate", z.strictObject({ transfer_id: id }),
        "Review scoped PSP fund trace and MED state before requesting recovery.", (value) => {
          if (!allowedMed.has(value.transfer_id)) throw new BankError("DEF_INCIDENT_SCOPE");
          return this.separatedMed ? med.statusSeparated(value.transfer_id, from,
            this.bank.now().toISOString(), this.separatedMed.project) :
            med.status(value.transfer_id, from, this.bank.now().toISOString());
        }),
      tool("med.request", "restore", z.strictObject({ transfer_id: id, evidence_ref: id }),
        "Open a verified external Pix MED case with an independent policy approval.", async (value) => {
          if (!allowedMed.has(value.transfer_id) || value.evidence_ref !== value.transfer_id)
            throw new BankError("DEF_INCIDENT_SCOPE");
          const evidenceRef = externalFindings.find((finding) =>
            finding.transferId === value.transfer_id)!.evidenceRef;
          const runRequest = () => {
            const approvalId = med.approve({ transferId: value.transfer_id, from,
              to: this.bank.now().toISOString(), evidenceRef: value.evidence_ref,
              makerId: restorerId, checkerId: "recovery-policy" });
            const opened = med.request({ transferId: value.transfer_id, from,
              to: this.bank.now().toISOString(), evidenceRef: value.evidence_ref,
              actorId: restorerId, approvalId });
            return { approvalId, opened };
          };
          const { approvalId, opened } = this.separatedMed ? runRequest() :
            this.bank.transaction(() => {
              const result = runRequest();
              med.decide({ caseId: result.opened.id, transferId: value.transfer_id,
                approvalId: result.approvalId, makerId: restorerId,
                checkerId: "recovery-policy", evidenceRef, decision: "approved" });
              return result;
            });
          let receipt = opened;
          if (this.separatedMed) {
            if (opened.status === "opening")
              await this.separatedMed.dispatchOpenings();
            const confirmed = this.bank.db.prepare("SELECT status FROM med_cases WHERE id=?")
              .get(opened.id) as { status: string } | undefined;
            if (confirmed?.status !== "open")
              throw new BankError("DEF_MED_OPENING_PENDING");
            receipt = { ...opened, status: "open" };
            med.decide({ caseId: opened.id, transferId: value.transfer_id,
              approvalId, makerId: restorerId, checkerId: "recovery-policy",
              evidenceRef, decision: "approved" });
            await publishSeparatedMoneyFlowMedSnapshots(this.bank, this.events,
              input.roundId, input.incidentId, (transferId, caseId) =>
                this.separatedMed!.project(transferId, caseId));
          } else publishMoneyFlowMedSnapshots(this.bank, this.events,
            input.roundId, input.incidentId);
          applied.add(`med.request:${value.transfer_id}`);
          return receipt;
        }),
      tool("bank.compensate_expired", "restore",
        z.strictObject({ transfer_id: id, evidence_ref: id }),
        "Compensate verified external Pix damage after the MED claim deadline; book bank loss.",
        (value) => {
          if (!allowedMed.has(value.transfer_id) || value.evidence_ref !== value.transfer_id)
            throw new BankError("DEF_INCIDENT_SCOPE");
          const approvalId = med.approve({ transferId: value.transfer_id, from,
            to: this.bank.now().toISOString(), evidenceRef: value.evidence_ref,
            makerId: restorerId, checkerId: "recovery-policy" });
          const receipt = med.compensateExpired({ transferId: value.transfer_id, from,
            to: this.bank.now().toISOString(), evidenceRef: value.evidence_ref,
            actorId: restorerId, approvalId });
          applied.add(`bank.compensate_expired:${value.transfer_id}`);
          return receipt;
        }),
      tool("ledger.trace", "investigate", traceSchema,
        "Confirm a verified damage transaction before a reversal.", (value) => {
          if (!traceIds.has(value.tx_id)) throw new BankError("DEF_INCIDENT_SCOPE");
          return investigation.trace({ txId: value.tx_id, depth: 1 });
        }),
      tool("ledger.reverse", "restore", z.strictObject({ finding_id: id, evidence_ref: id }),
        "Restore one verified finding; never debit an honest customer.", (value) => {
          if (!allowed.has(value.finding_id) || value.evidence_ref !== value.finding_id)
            throw new Error("RESTORE_SCOPE");
          const approvalId = restoration.approve({ incidentId: input.incidentId,
            findingId: value.finding_id, evidenceRef: value.evidence_ref,
            makerId: restorerId, checkerId: "recovery-policy" });
          const receipt = restoration.restore({ incidentId: input.incidentId,
            roundId: input.roundId, findingId: value.finding_id,
            evidenceRef: value.evidence_ref, actorId: restorerId, approvalId });
          applied.add(`ledger.reverse:${value.finding_id}`);
          return receipt;
        }),
      ...(["session.revoke", "key.revoke", "scheduler.cancel_job", "contain.lift",
        "account.restore_balance"] as const).map((name) =>
        tool(name, "restore", z.strictObject({ ref: id, evidence_ref: id }),
          "Close one verified, scoped non-monetary damage finding.", (value) => {
            const finding = allowedAux.get(value.ref);
            const expected = name === "session.revoke" ? "live_session" :
              name === "key.revoke" ? "live_key" : name === "scheduler.cancel_job" ?
                "scheduled_job" : name === "account.restore_balance" ?
                  "balance_drift" : "frozen_honest_account";
            if (!finding || finding.kind !== expected || value.evidence_ref !== value.ref)
              throw new Error("RESTORE_SCOPE");
            const restored = auxiliary.restore(input.incidentId, finding, value.evidence_ref,
              restorerId, from, to);
            if (restored) applied.add(`${name}:${value.ref}`);
            return { restored };
          })),
    ];
    const restored = await loop.run({ runId: input.roundId, agentId: restorerId,
      role: "restorer", deadlineAt: input.deadlineAt,
      goalPt: "Restaurar apenas danos confirmados", snapshot: { incidentId: input.incidentId },
      dossier: restorerContext,
      dossierSchema: restorationReportBody,
      validateDossier: (body) => {
        if (body.incident_id !== input.incidentId) return false;
        const rows = (this.bank.db.prepare(`SELECT id,status,amount_cents FROM blue_damage_findings
          WHERE incident_id=?`).all(input.incidentId) as
          { id: string; status: string; amount_cents: number }[])
          .filter((row) => allowed.has(row.id));
        const settled = rows.filter((row) => row.status === "restored")
          .reduce((sum, row) => sum + row.amount_cents, 0);
        const open = rows.filter((row) => row.status === "open")
          .reduce((sum, row) => sum + row.amount_cents, 0);
        const remainingAux = auxiliary.scan(input.incidentId, from, to);
        const currentExternal = med.financialState(from, this.bank.now().toISOString())
          .filter((finding) => allowedMed.has(finding.transferId) && finding.claimCents > 0);
        const externalOpen = currentExternal.reduce((sum, finding) => sum + finding.claimCents, 0);
        const externalResolved = externalFindings.reduce((sum, finding) =>
          sum + finding.claimCents, 0) - externalOpen;
        const externalAbsorbed = med.financialState(from, this.bank.now().toISOString())
          .filter((finding) => allowedMed.has(finding.transferId))
          .reduce((sum, finding) => sum + finding.absorbedCents, 0);
        const absorbed = (this.bank.db.prepare(`SELECT l.finding_id,l.bank_loss_cents
          FROM blue_restore_ledger l JOIN blue_damage_findings f ON f.id=l.finding_id
          WHERE f.incident_id=?`).all(input.incidentId) as
          { finding_id: string; bank_loss_cents: number }[])
          .filter((row) => allowed.has(row.finding_id))
          .reduce((sum, row) => sum + row.bank_loss_cents, 0);
        const unfrozen = auxiliaryFindings.filter((finding) =>
          finding.kind === "frozen_honest_account" &&
          applied.has(`contain.lift:${finding.ref}`)).map((finding) =>
          (this.bank.db.prepare("SELECT target FROM blue_containments WHERE id=?")
            .get(finding.ref) as { target: string }).target).sort();
        const reportedActions = body.actions.filter((action) => action.result === "done")
          .map((action) => `${action.tool}:${action.ref}`);
        if (reportedActions.length !== applied.size ||
          reportedActions.some((action) => !applied.has(action)) ||
          new Set(reportedActions).size !== reportedActions.length ||
          JSON.stringify([...body.honest_accounts_unfrozen].sort()) !== JSON.stringify(unfrozen))
          return false;
        return Math.abs(body.restored_brl - brl(settled + externalResolved)) < 0.001 &&
          Math.abs(body.remaining_brl - brl(open + externalOpen)) < 0.001 &&
          Math.abs(body.absorbed_by_bank_brl - brl(absorbed + externalAbsorbed)) < 0.001 &&
          body.needs_human === (open > 0 || externalOpen > 0 || remainingAux.length > 0);
      }, tools: restorerTools });
    if (restored.status !== "ok" || !restored.data)
      return { status: "partial", reason: `restorer:${restored.status}` };
    remember("dossier.restoration", restorerId, { ...restored.data });
    const secondTo = this.bank.now().toISOString();
    try {
      findings = restoration.scan({ incidentId: input.incidentId, roundId: input.roundId,
        from: internalFrom, to: secondTo, checkNo: 2 })
        .filter((finding) => finding.status === "open");
      for (const finding of findings) {
        traceIds.add(finding.txId);
        accountIds.add(finding.victimAccount);
        accountIds.add(finding.attackerAccount);
      }
      auxiliaryFindings = auxiliary.scan(input.incidentId, from, secondTo);
      externalFindings = await externalBatch(secondTo);
      unverifiedExternal = med.unverified(from, secondTo).slice(0, 50);
      for (const finding of externalFindings) accountIds.add(finding.victimAccount);
      await recordResolvedMed(secondTo);
      recordExternalAssessment(2, secondTo);
    } catch (error) {
      if (error instanceof BankError && error.code === "DEF_DAMAGE_SCAN_TRUNCATED")
        return { status: "partial", reason: "damage_scan_truncated" };
      throw error;
    }
    scanCalled = false;
    const secondAssessorId = `damage_assessor_${randomUUID()}`;
    const secondContext = { incidentId: input.incidentId, checkNo: 2,
      previous: { findings: assessed.data.findings.slice(0, 50).map((finding) => ({
        kind: finding.kind, ref: finding.refs[0], amount_brl: finding.amount_brl })),
        totalOpenBrl: assessed.data.total_open_brl },
      restoration: { restoredBrl: restored.data.restored_brl,
        absorbedByBankBrl: restored.data.absorbed_by_bank_brl },
      currentFindingIds: findings.map((finding) => finding.id),
      externalFindings,
      unverifiedExternal,
      auxiliaryFindings };
    handoff(restorerId, "restorer", secondAssessorId, "DamageRecheck", secondContext);
    const second = await loop.run({ runId: input.roundId, agentId: secondAssessorId,
      role: "damage_assessor", deadlineAt: input.deadlineAt,
      goalPt: "Reavaliar danos depois da recuperação", snapshot: {
        incidentId: input.incidentId, window: { from, to: secondTo } },
      dossier: secondContext, dossierSchema: damageReportBody,
      validateDossier: (body) => validDamage(body, 2), tools: assessorTools });
    if (second.status !== "ok" || !second.data)
      return { status: "partial", reason: `damage_recheck:${second.status}` };
    remember("dossier.damage_2", secondAssessorId, { ...second.data });
    let finalFindings: DamageFinding[];
    let finalAuxiliary: ReturnType<RecoveryAux["scan"]>;
    let finalExternal: ExternalDamage[];
    let finalUnverified: string[];
    try {
      const finalTo = this.bank.now().toISOString();
      finalFindings = restoration.scan({ incidentId: input.incidentId, roundId: input.roundId,
        from: internalFrom, to: finalTo, checkNo: "final" })
        .filter((finding) => finding.status === "open");
      finalAuxiliary = auxiliary.scan(input.incidentId, from, finalTo);
      finalExternal = (this.separatedMed ? await med.scanSeparated(from, finalTo,
        this.separatedMed.project) : med.scan(from, finalTo))
        .filter((finding) => finding.claimCents > 0);
      finalUnverified = med.unverified(from, finalTo);
      await recordResolvedMed(finalTo);
      externalFindings = finalExternal;
      findings = finalFindings;
      recordExternalAssessment("final", finalTo);
    } catch (error) {
      if (error instanceof BankError && error.code === "DEF_DAMAGE_SCAN_TRUNCATED")
        return { status: "partial", reason: "damage_scan_truncated" };
      throw error;
    }
    return finalFindings.length || finalExternal.length || finalUnverified.length || finalAuxiliary.length ? { status: "partial", reason:
      finalUnverified.length ? "external_damage_unverified" :
      finalExternal.some((finding) => finding.medStatus === "open") ? "med_review_pending" :
      finalFindings.length || finalExternal.length || finalAuxiliary.some((finding) => isRestorableAuxiliary(finding.kind)) ?
        "restoration_incomplete" : "irreversible_damage" } : { status: "restored" };
  }
}
