import { randomUUID } from "node:crypto";
import { Bank, BankError } from "../../world/src/bank.ts";
import type { EcosystemClient } from "../../ecosystem/src/client.ts";

type PspProjection = Awaited<ReturnType<EcosystemClient["moneyFlowProjection"]>>;

export interface ExternalDamage {
  transferId: string;
  endToEndId: string;
  victimAccount: string;
  victimCustomer: string;
  claimCents: number;
  availableCents: number;
  blockedCents: number;
  escapedCents: number;
  medCaseId: string | null;
  medStatus: string | null;
  medEligible: boolean;
  compensationId: string | null;
  resolveAfter: string | null;
  refundedCents: number;
  absorbedCents: number;
  evidenceRef: string;
}

interface TransferRow {
  id: string; end_to_end_id: string; from_account: string; customer_id: string;
  initiated_at: string;
  amount: number; evidence_ref: string; med_id: string | null; med_status: string | null;
  resolve_after: string | null; claim_amount_cents: number | null;
  refunded_cents: number | null; unrecovered_cents: number | null;
  compensation_id: string | null; compensation_cents: number | null;
}

export class BlueMedRecovery {
  private readonly bank: Bank;
  private readonly incidentId: string;
  private readonly roundId: string;
  constructor(bank: Bank, incidentId: string, roundId: string) {
    this.bank = bank;
    this.incidentId = incidentId;
    this.roundId = roundId;
    bank.db.exec(`CREATE TABLE IF NOT EXISTS blue_med_approvals (
      id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, transfer_id TEXT NOT NULL,
      round_id TEXT NOT NULL,
      maker_id TEXT NOT NULL, checker_id TEXT NOT NULL, claim_cents INTEGER NOT NULL,
      approved_at TEXT NOT NULL, consumed_at TEXT,
      UNIQUE(incident_id,transfer_id), CHECK(maker_id<>checker_id), CHECK(claim_cents>0)
    );
    CREATE TABLE IF NOT EXISTS sentinel_incident_transfer_evidence (
      incident_id TEXT NOT NULL REFERENCES sentinel_incidents(id),
      transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
      evidence_ref TEXT NOT NULL, linked_at TEXT NOT NULL,
      PRIMARY KEY(incident_id,transfer_id,evidence_ref)
    );
    CREATE TABLE IF NOT EXISTS blue_external_compensations (
      id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES sentinel_incidents(id),
      transfer_id TEXT NOT NULL UNIQUE REFERENCES pix_transfers(id),
      claim_cents INTEGER NOT NULL CHECK(claim_cents>0),
      ledger_tx_id TEXT NOT NULL UNIQUE, compensated_at TEXT NOT NULL
    )`);
    const columns = bank.db.prepare("PRAGMA table_info(blue_med_approvals)")
      .all() as { name: string }[];
    if (!columns.some((column) => column.name === "round_id"))
      bank.db.exec("ALTER TABLE blue_med_approvals ADD COLUMN round_id TEXT NOT NULL DEFAULT ''");
  }

  private rows(from: string, to: string): TransferRow[] {
    const start = Date.parse(from), end = Date.parse(to);
    if (!Number.isFinite(start) || !Number.isFinite(end) || start > end)
      throw new BankError("BIZ_DAMAGE_WINDOW");
    const incident = this.bank.db.prepare(`SELECT id FROM sentinel_incidents WHERE id=?
      AND state IN ('open','contained','patching','awaiting_next_window')`)
      .get(this.incidentId);
    if (!incident) throw new BankError("DEF_INCIDENT_NOT_OPEN");
    return this.bank.db.prepare(`SELECT p.id,p.end_to_end_id,p.from_account,p.initiated_at,
      src.customer_id,p.amount,e.evidence_ref,m.id med_id,m.status med_status,
      m.resolve_after,m.claim_amount_cents,m.refunded_cents,m.unrecovered_cents,
      c.id compensation_id,c.claim_cents compensation_cents
      FROM pix_transfers p
      JOIN accounts src ON src.id=p.from_account
      JOIN customers victim ON victim.id=src.customer_id AND victim.is_attacker_owned=0
      JOIN pix_spi_outbox outbound ON outbound.transfer_id=p.id
        AND outbound.end_to_end_id=p.end_to_end_id
        AND outbound.to_ispb<>outbound.from_ispb
      JOIN sentinel_incidents i ON i.id=?
      JOIN (SELECT incident_id,transfer_id,MIN(evidence_ref) evidence_ref
        FROM sentinel_incident_transfer_evidence
        WHERE evidence_ref LIKE 'red_sandbox_calls:%'
        GROUP BY incident_id,transfer_id) e ON e.incident_id=i.id AND e.transfer_id=p.id
      LEFT JOIN med_cases m ON m.transfer_id=p.id
      LEFT JOIN blue_external_compensations c ON c.transfer_id=p.id
      WHERE p.status IN ('settled','returned_partial','returned_full')
        AND p.settled_at>=? AND p.settled_at<=?
        AND (p.amount>(SELECT COALESCE(SUM(r.amount),0) FROM pix_returns r
          WHERE r.transfer_id=p.id) OR m.status='resolved' OR c.id IS NOT NULL)
      ORDER BY p.settled_at,p.id`).all(this.incidentId, from, to) as unknown as TransferRow[];
  }

  private decisionDamage(transferId: string, from: string, to: string): {
    victimAccount: string; victimCustomer: string; claimCents: number;
    medCaseId: string | null; medStatus: string | null;
    compensationId: string | null;
    medEligible: boolean } {
    const row = this.rows(from, to).find((candidate) => candidate.id === transferId);
    if (!row) throw new BankError("DEF_INCIDENT_SCOPE");
    const ordinaryReturned = (this.bank.db.prepare(`SELECT COALESCE(SUM(amount),0) n
      FROM pix_returns WHERE transfer_id=?`).get(row.id) as { n: number }).n;
    const claim = row.claim_amount_cents ?? Math.max(0, row.amount - ordinaryReturned);
    const resolved = row.med_status === "resolved" || row.compensation_id !== null;
    return { victimAccount: row.from_account, victimCustomer: row.customer_id,
      claimCents: resolved ? 0 : claim, medCaseId: row.med_id,
      medStatus: row.med_status,
      compensationId: row.compensation_id,
      medEligible: this.bank.now().getTime() - Date.parse(row.initiated_at) <=
        80 * 86_400_000 };
  }

  financialState(from: string, to: string): {
    transferId: string; claimCents: number; medCaseId: string | null;
    medStatus: string | null; compensationId: string | null;
    refundedCents: number; absorbedCents: number; evidenceRef: string }[] {
    return this.rows(from, to).map((row) => {
      const ordinaryReturned = (this.bank.db.prepare(`SELECT COALESCE(SUM(amount),0) n
        FROM pix_returns WHERE transfer_id=?`).get(row.id) as { n: number }).n;
      const claim = row.claim_amount_cents ?? Math.max(0, row.amount - ordinaryReturned);
      return { transferId: row.id,
        claimCents: row.med_status === "resolved" || row.compensation_id ? 0 : claim,
        medCaseId: row.med_id,
        medStatus: row.compensation_id ? "bank_compensated" : row.med_status,
        compensationId: row.compensation_id,
        refundedCents: row.refunded_cents ?? 0,
        absorbedCents: row.compensation_cents ?? row.unrecovered_cents ?? 0,
        evidenceRef: row.evidence_ref };
    });
  }

  private damage(row: TransferRow, available: number): ExternalDamage {
      const ordinaryReturned = (this.bank.db.prepare(`SELECT COALESCE(SUM(amount),0) n
        FROM pix_returns WHERE transfer_id=?`).get(row.id) as { n: number }).n;
      const claim = row.claim_amount_cents ?? Math.max(0, row.amount - ordinaryReturned);
      const blocked = row.med_id ? (this.bank.db.prepare(`SELECT COALESCE(SUM(blocked_cents),0) n
        FROM med_hops WHERE case_id=? AND released_at IS NULL`).get(row.med_id) as { n: number }).n : 0;
      const resolved = row.med_status === "resolved" || row.compensation_id !== null;
      const outstanding = resolved ? 0 : claim;
      const medEligible = this.bank.now().getTime() - Date.parse(row.initiated_at) <=
        80 * 86_400_000;
      return { transferId: row.id, endToEndId: row.end_to_end_id,
        victimAccount: row.from_account, victimCustomer: row.customer_id,
        claimCents: outstanding, availableCents: Math.min(outstanding, available),
        blockedCents: Math.min(outstanding, blocked),
        escapedCents: Math.max(0, outstanding - Math.min(outstanding, available)),
        medCaseId: row.med_id,
        medStatus: row.compensation_id ? "bank_compensated" : row.med_status,
        medEligible, compensationId: row.compensation_id,
        resolveAfter: row.resolve_after, refundedCents: row.refunded_cents ?? 0,
        absorbedCents: row.compensation_cents ?? row.unrecovered_cents ?? 0,
        evidenceRef: row.evidence_ref };
  }

  scan(from: string, to: string): ExternalDamage[] {
    return this.rows(from, to).map((row) => this.damage(row,
      this.bank.psp.trace(row.id).reduce((sum, hop) => sum + hop.available_cents, 0)));
  }

  private verifyProjection(row: TransferRow, projection: PspProjection): void {
    const outbound = this.bank.db.prepare(`SELECT from_ispb,to_ispb,amount_cents
      FROM pix_spi_outbox WHERE transfer_id=? AND end_to_end_id=?`)
      .get(row.id, row.end_to_end_id) as { from_ispb: string; to_ispb: string;
        amount_cents: number } | undefined;
    const first = projection.path[0];
    if (!outbound || first?.kind !== "payment" ||
      first.end_to_end_id !== row.end_to_end_id ||
      first.from_ispb !== outbound.from_ispb || first.to_ispb !== outbound.to_ispb ||
      first.amount_cents !== row.amount || outbound.amount_cents !== row.amount)
      throw new BankError("DEF_PSP_PROJECTION_DRIFT");
    const local = row.med_id ? this.bank.db.prepare(`SELECT id,account_id,
      blocked_cents,refunded_cents,released_at FROM med_hops WHERE case_id=? ORDER BY id`)
      .all(row.med_id) as { id: string; account_id: string; blocked_cents: number;
        refunded_cents: number; released_at: string | null }[] : [];
    const remote = [...projection.hops].sort((a, b) => a.id.localeCompare(b.id));
    if (local.length !== remote.length || remote.some((hop, index) => {
      const mirror = local[index];
      return !mirror || hop.id !== mirror.id || hop.case_id !== row.med_id ||
        hop.root_transfer_id !== row.id || hop.account_id !== mirror.account_id ||
        hop.blocked_cents !== mirror.blocked_cents ||
        hop.refunded_cents !== mirror.refunded_cents ||
        hop.released_at !== mirror.released_at;
    })) throw new BankError("DEF_PSP_PROJECTION_DRIFT");
    if (projection.trace.some((hop) => !Number.isSafeInteger(hop.available_cents) ||
      hop.available_cents < 0) ||
      new Set(projection.trace.map((hop) => hop.account_id)).size !==
        projection.trace.length) throw new BankError("DEF_PSP_PROJECTION_DRIFT");
  }

  async scanSeparated(from: string, to: string,
    project: (transferId: string, caseId?: string) => Promise<PspProjection>):
    Promise<ExternalDamage[]> {
    const rows = this.rows(from, to);
    const result: ExternalDamage[] = [];
    for (let offset = 0; offset < rows.length; offset += 32) {
      const batch = rows.slice(offset, offset + 32);
      result.push(...await Promise.all(batch.map(async (row) => {
        const projection = await project(row.id, row.med_id ?? undefined);
        this.verifyProjection(row, projection);
        const available = projection.trace.reduce((sum, hop) =>
          sum + hop.available_cents, 0);
        if (!Number.isSafeInteger(available))
          throw new BankError("DEF_PSP_PROJECTION_DRIFT");
        return this.damage(row, available);
      })));
    }
    return result;
  }

  async statusSeparated(transferId: string, from: string, to: string,
    project: (transferId: string, caseId?: string) => Promise<PspProjection>):
    Promise<{ damage: ExternalDamage; hops: { account_id: string; ispb: string;
      available_cents: number; blocked_cents: number }[];
      path: PspProjection["path"] }> {
    const row = this.rows(from, to).find((candidate) => candidate.id === transferId);
    if (!row) throw new BankError("DEF_INCIDENT_SCOPE");
    const projection = await project(row.id, row.med_id ?? undefined);
    this.verifyProjection(row, projection);
    const available = projection.trace.reduce((sum, hop) => sum + hop.available_cents, 0);
    if (!Number.isSafeInteger(available)) throw new BankError("DEF_PSP_PROJECTION_DRIFT");
    const damage = this.damage(row, available);
    const hops = projection.trace.map((hop) => ({ ...hop,
      blocked_cents: projection.hops.filter((hold) =>
        hold.account_id === hop.account_id && hold.released_at === null)
        .reduce((sum, hold) => sum + hold.blocked_cents, 0) }));
    return { damage, hops, path: projection.path };
  }

  unverified(from: string, to: string): string[] {
    const start = Date.parse(from), end = Date.parse(to);
    if (!Number.isFinite(start) || !Number.isFinite(end) || start > end)
      throw new BankError("BIZ_DAMAGE_WINDOW");
    const rows = this.bank.db.prepare(`SELECT DISTINCT p.id FROM pix_transfers p
      JOIN accounts src ON src.id=p.from_account
      JOIN customers victim ON victim.id=src.customer_id AND victim.is_attacker_owned=0
      JOIN pix_spi_outbox outbound ON outbound.transfer_id=p.id
        AND outbound.end_to_end_id=p.end_to_end_id
        AND outbound.to_ispb<>outbound.from_ispb
      JOIN sentinel_incident_transfer_evidence e ON e.incident_id=?
        AND e.transfer_id=p.id AND e.evidence_ref LIKE 'sentinel_alerts:%'
      LEFT JOIN med_cases m ON m.transfer_id=p.id
      LEFT JOIN blue_external_compensations c ON c.transfer_id=p.id
      WHERE p.status IN ('settled','returned_partial','returned_full')
        AND p.settled_at>=? AND p.settled_at<=?
        AND p.amount>(SELECT COALESCE(SUM(r.amount),0) FROM pix_returns r
          WHERE r.transfer_id=p.id)
        AND (m.id IS NULL OR m.status<>'resolved')
        AND c.id IS NULL
        AND NOT EXISTS (SELECT 1 FROM sentinel_incident_transfer_evidence v
          WHERE v.incident_id=e.incident_id AND v.transfer_id=p.id
            AND v.evidence_ref LIKE 'red_sandbox_calls:%')
      ORDER BY p.id`).all(this.incidentId, from, to) as { id: string }[];
    return rows.map((row) => row.id);
  }

  status(transferId: string, from: string, to: string): {
    damage: ExternalDamage; hops: { account_id: string; ispb: string;
      available_cents: number; blocked_cents: number }[];
    path: ReturnType<Bank["psp"]["path"]> } {
    const damage = this.scan(from, to).find((row) => row.transferId === transferId);
    if (!damage) throw new BankError("DEF_INCIDENT_SCOPE");
    const hops = this.bank.psp.trace(transferId).map((hop) => ({ ...hop,
      blocked_cents: damage.medCaseId ? (this.bank.db.prepare(`SELECT COALESCE(SUM(blocked_cents),0) n
        FROM med_hops WHERE case_id=? AND account_id=? AND released_at IS NULL`)
        .get(damage.medCaseId, hop.account_id) as { n: number }).n : 0 }));
    return { damage, hops, path: this.bank.psp.path(transferId) };
  }

  approve(input: { transferId: string; from: string; to: string;
    evidenceRef: string; makerId: string; checkerId: string }): string {
    if (!this.roundId || !input.makerId || !input.checkerId || input.makerId === input.checkerId ||
      input.evidenceRef !== input.transferId)
      throw new BankError("DEF_RESTORE_APPROVAL_INVALID");
    return this.bank.transaction(() => {
      const damage = this.decisionDamage(input.transferId, input.from, input.to);
      if (damage.claimCents <= 0 || damage.claimCents > 500_000)
        throw new BankError("DEF_RESTORE_APPROVAL_INVALID");
      const existing = this.bank.db.prepare(`SELECT id,round_id,maker_id,checker_id,
        claim_cents,consumed_at
        FROM blue_med_approvals WHERE incident_id=? AND transfer_id=?`)
        .get(this.incidentId, input.transferId) as { id: string; round_id: string;
          maker_id: string; checker_id: string; claim_cents: number;
          consumed_at: string | null } | undefined;
      if (damage.medCaseId) {
        if (!this.bank.isSeparatedEcosystem ||
          !["opening", "open"].includes(damage.medStatus ?? "") ||
          !existing?.consumed_at || existing.round_id !== this.roundId ||
          existing.maker_id !== input.makerId ||
          existing.checker_id !== input.checkerId ||
          existing.claim_cents !== damage.claimCents)
          throw new BankError("DEF_RESTORE_APPROVAL_INVALID");
        return existing.id;
      }
      if (existing && (existing.consumed_at || existing.checker_id !== input.checkerId))
        throw new BankError("DEF_RESTORE_APPROVAL_INVALID");
      const excludedId = existing?.id ?? "";
      const medApproved = (this.bank.db.prepare(`SELECT COALESCE(SUM(claim_cents),0) n
        FROM blue_med_approvals WHERE incident_id=? AND id<>?`)
        .get(this.incidentId, excludedId) as { n: number }).n;
      const medRound = (this.bank.db.prepare(`SELECT COALESCE(SUM(claim_cents),0) n
        FROM blue_med_approvals WHERE round_id=? AND id<>?`)
        .get(this.roundId, excludedId) as { n: number }).n;
      const medCustomer = (this.bank.db.prepare(`SELECT COALESCE(SUM(m.claim_cents),0) n
        FROM blue_med_approvals m JOIN pix_transfers p ON p.id=m.transfer_id
        JOIN accounts a ON a.id=p.from_account WHERE m.round_id=? AND a.customer_id=?
          AND m.id<>?`).get(this.roundId, damage.victimCustomer, excludedId) as { n: number }).n;
      const hasInternal = this.bank.db.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='blue_restore_ledger'`).get();
      const internalRestored = hasInternal ? (this.bank.db.prepare(`SELECT COALESCE(SUM(l.amount_cents),0) n
        FROM blue_restore_ledger l JOIN blue_damage_findings f ON f.id=l.finding_id
        WHERE f.incident_id=?`).get(this.incidentId) as { n: number }).n : 0;
      const internalRound = hasInternal ? (this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) n
        FROM blue_restore_ledger WHERE round_id=?`).get(this.roundId) as { n: number }).n : 0;
      const internalCustomer = hasInternal ? (this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) n
        FROM blue_restore_ledger WHERE round_id=? AND customer_id=?`)
        .get(this.roundId, damage.victimCustomer) as { n: number }).n : 0;
      if (medApproved + internalRestored + damage.claimCents > 5_000_000 ||
        medRound + internalRound + damage.claimCents > 5_000_000 ||
        medCustomer + internalCustomer + damage.claimCents > 500_000)
        throw new BankError("DEF_RESTORE_LIMIT");
      if (existing) {
        this.bank.db.prepare(`UPDATE blue_med_approvals SET round_id=?,maker_id=?,
          claim_cents=?,approved_at=? WHERE id=?`).run(this.roundId, input.makerId,
          damage.claimCents,
          this.bank.now().toISOString(), existing.id);
        return existing.id;
      }
      const approvalId = `medapproval_${randomUUID()}`;
      this.bank.db.prepare(`INSERT INTO blue_med_approvals VALUES (?,?,?,?,?,?,?,?,NULL)`)
        .run(approvalId, this.incidentId, input.transferId, this.roundId, input.makerId,
          input.checkerId, damage.claimCents, this.bank.now().toISOString());
      return approvalId;
    });
  }

  request(input: { transferId: string; from: string; to: string;
    evidenceRef: string; actorId: string; approvalId: string }): {
      id: string; status: string; refunded_cents: number } {
    if (!input.actorId || input.evidenceRef !== input.transferId)
      throw new BankError("DEF_RESTORE_EVIDENCE");
    return this.bank.transaction(() => {
      const damage = this.decisionDamage(input.transferId, input.from, input.to);
      if (damage.claimCents <= 0)
        throw new BankError("DEF_RESTORE_EVIDENCE");
      const approved = this.bank.db.prepare(`SELECT id,consumed_at FROM blue_med_approvals
        WHERE id=? AND incident_id=? AND transfer_id=? AND round_id=? AND maker_id=?
          AND checker_id<>? AND claim_cents=?`)
        .get(input.approvalId, this.incidentId, input.transferId, this.roundId, input.actorId,
          input.actorId, damage.claimCents) as { id: string;
            consumed_at: string | null } | undefined;
      if (!approved) throw new BankError("DEF_RESTORE_APPROVAL_REQUIRED");
      if (damage.medCaseId) {
        if (!this.bank.isSeparatedEcosystem || !approved.consumed_at ||
          !["opening", "open"].includes(damage.medStatus ?? ""))
          throw new BankError("DEF_RESTORE_EVIDENCE");
        return { id: damage.medCaseId, status: damage.medStatus!, refunded_cents: 0 };
      }
      if (approved.consumed_at) throw new BankError("DEF_RESTORE_APPROVAL_REQUIRED");
      if (!damage.medEligible) throw new BankError("BIZ_MED_EXPIRED");
      const result = this.bank.isSeparatedEcosystem ?
        this.bank.requestExternalMed(damage.victimCustomer, input.transferId) :
        this.bank.requestMed(damage.victimCustomer, input.transferId);
      if (result.status !== (this.bank.isSeparatedEcosystem ? "opening" : "open"))
        throw new BankError("DEF_RESTORE_EVIDENCE");
      this.bank.db.prepare("UPDATE blue_med_approvals SET consumed_at=? WHERE id=?")
        .run(this.bank.now().toISOString(), input.approvalId);
      return result;
    });
  }

  decide(input: { caseId: string; transferId: string; approvalId: string;
    makerId: string; checkerId: string; evidenceRef: string;
    decision: "approved" | "rejected" }): void {
    this.bank.transaction(() => {
      const caseRow = this.bank.db.prepare(`SELECT m.id FROM med_cases m
        JOIN blue_med_approvals a ON a.transfer_id=m.transfer_id
        WHERE m.id=? AND m.transfer_id=? AND m.status='open'
          AND a.id=? AND a.incident_id=? AND a.round_id=?
          AND a.maker_id=? AND a.checker_id=? AND a.consumed_at IS NOT NULL`)
        .get(input.caseId, input.transferId, input.approvalId, this.incidentId,
          this.roundId, input.makerId, input.checkerId);
      const evidence = this.bank.db.prepare(`SELECT 1 FROM
        sentinel_incident_transfer_evidence WHERE incident_id=?
        AND transfer_id=? AND evidence_ref=?`).get(this.incidentId,
          input.transferId, input.evidenceRef);
      if (!caseRow || !evidence) throw new BankError("DEF_MED_DECISION_INVALID");
      const prior = this.bank.db.prepare(`SELECT decision,maker_id,checker_id,evidence_ref
        FROM med_decisions WHERE case_id=?`).get(input.caseId) as {
          decision: string; maker_id: string; checker_id: string;
          evidence_ref: string } | undefined;
      if (prior) {
        if (prior.decision !== input.decision || prior.maker_id !== input.makerId ||
          prior.checker_id !== input.checkerId || prior.evidence_ref !== input.evidenceRef)
          throw new BankError("DEF_MED_DECISION_INVALID");
        return;
      }
      this.bank.recordMedDecision(input.caseId, input.decision, input.makerId,
        input.checkerId, input.evidenceRef);
    });
  }

  compensateExpired(input: { transferId: string; from: string; to: string;
    evidenceRef: string; actorId: string; approvalId: string }): {
      id: string; status: "bank_compensated"; absorbed_cents: number } {
    if (!input.actorId || input.evidenceRef !== input.transferId)
      throw new BankError("DEF_RESTORE_EVIDENCE");
    return this.bank.transaction(() => {
      const damage = this.decisionDamage(input.transferId, input.from, input.to);
      if (damage.claimCents <= 0 || damage.medEligible || damage.medCaseId ||
        damage.compensationId) throw new BankError("DEF_RESTORE_EVIDENCE");
      const approved = this.bank.db.prepare(`SELECT id FROM blue_med_approvals
        WHERE id=? AND incident_id=? AND transfer_id=? AND round_id=? AND maker_id=?
          AND checker_id<>? AND claim_cents=? AND consumed_at IS NULL`)
        .get(input.approvalId, this.incidentId, input.transferId, this.roundId, input.actorId,
          input.actorId, damage.claimCents);
      if (!approved) throw new BankError("DEF_RESTORE_APPROVAL_REQUIRED");
      const id = `expired_${randomUUID()}`;
      const txId = this.bank.post([
        { accountId: this.bank.systemAccountId("bank_loss"), amount: -damage.claimCents,
          kind: "expired_pix_bank_loss", actor: input.actorId,
          refType: "incident", refId: this.incidentId },
        { accountId: damage.victimAccount, amount: damage.claimCents,
          kind: "expired_pix_compensation", actor: input.actorId,
          refType: "incident", refId: this.incidentId },
      ]);
      this.bank.db.prepare(`INSERT INTO blue_external_compensations VALUES (?,?,?,?,?,?)`)
        .run(id, this.incidentId, input.transferId, damage.claimCents, txId,
          this.bank.now().toISOString());
      this.bank.db.prepare("UPDATE blue_med_approvals SET consumed_at=? WHERE id=?")
        .run(this.bank.now().toISOString(), input.approvalId);
      this.bank.reconcile();
      return { id, status: "bank_compensated", absorbed_cents: damage.claimCents };
    });
  }
}
