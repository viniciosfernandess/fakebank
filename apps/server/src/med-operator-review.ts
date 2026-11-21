import { randomUUID } from "node:crypto";
import type { Bank } from "../../world/src/bank.ts";
import { BankError } from "../../world/src/bank.ts";

export type MedDecision = "approved" | "rejected";
export type MedReviewBasis = "fraud_indicators" | "no_fraud_indicators" |
  "insufficient_evidence";

interface MedReviewRow {
  id: string; transfer_id: string; claim_amount_cents: number;
  opened_at: string; resolve_after: string;
  external_payment: number;
  analysis_required: number;
  analysed_at: string | null;
  recovery_initiated_at: string | null;
  initiation_deadline_at: string | null;
  initiation_state: "awaiting_analysis" | "pending" | "on_time" | "late" |
    "overdue" | null;
  proposal_id: string | null; proposed_decision: MedDecision | null;
  proposed_by: string | null; basis_code: MedReviewBasis | null;
  evidence_ref: string | null; evidence_summary: string | null;
  review_decision: MedDecision | null; decided_at: string | null;
}

function decodeReviewCursor(cursor: string): [string, string] {
  if (!/^[A-Za-z0-9_-]{1,512}$/.test(cursor))
    throw new BankError("DEF_MED_REVIEW_CURSOR_INVALID");
  try {
    const value: unknown = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
    if (!Array.isArray(value) || value.length !== 2 ||
      typeof value[0] !== "string" || typeof value[1] !== "string" ||
      new Date(value[0]).toISOString() !== value[0] ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(value[1]))
      throw new Error("Invalid MED review cursor");
    return [value[0], value[1]];
  } catch {
    throw new BankError("DEF_MED_REVIEW_CURSOR_INVALID");
  }
}

export class MedOperatorReview {
  private readonly bank: Bank;
  constructor(bank: Bank) {
    this.bank = bank;
    bank.db.exec(`
      CREATE TABLE IF NOT EXISTS med_operator_review_proposals (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES med_cases(id),
        transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
        evidence_ref TEXT NOT NULL,
        basis_code TEXT NOT NULL CHECK(basis_code IN
          ('fraud_indicators','no_fraud_indicators','insufficient_evidence')),
        evidence_summary TEXT NOT NULL CHECK(length(trim(evidence_summary)) BETWEEN 24 AND 500),
        maker_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        CHECK((decision='approved' AND basis_code='fraud_indicators') OR
          (decision='rejected' AND basis_code IN
            ('no_fraud_indicators','insufficient_evidence')))
      );
      CREATE INDEX IF NOT EXISTS med_operator_review_case
        ON med_operator_review_proposals(case_id);
      CREATE INDEX IF NOT EXISTS med_operator_review_queue
        ON med_cases(status,resolve_after,id);
      CREATE TABLE IF NOT EXISTS med_operator_review_confirmations (
        proposal_id TEXT PRIMARY KEY REFERENCES med_operator_review_proposals(id),
        checker_id TEXT NOT NULL,
        confirmed_at TEXT NOT NULL
      );
      CREATE TRIGGER IF NOT EXISTS med_operator_review_proposals_no_update
        BEFORE UPDATE ON med_operator_review_proposals
        BEGIN SELECT RAISE(ABORT,'MED_REVIEW_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_operator_review_proposals_no_delete
        BEFORE DELETE ON med_operator_review_proposals
        BEGIN SELECT RAISE(ABORT,'MED_REVIEW_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_operator_review_confirmations_no_update
        BEFORE UPDATE ON med_operator_review_confirmations
        BEGIN SELECT RAISE(ABORT,'MED_REVIEW_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_operator_review_confirmations_no_delete
        BEFORE DELETE ON med_operator_review_confirmations
        BEGIN SELECT RAISE(ABORT,'MED_REVIEW_IMMUTABLE'); END;
    `);
  }

  list(cursor?: string): { reviews: MedReviewRow[]; next_cursor: string | null;
    opening_sla: Omit<ReturnType<Bank["medOpeningSla"]>, "cases"> } {
    const after = cursor === undefined ? null : decodeReviewCursor(cursor);
    const rows = this.bank.db.prepare(`SELECT m.id,m.transfer_id,
      COALESCE(m.claim_amount_cents,t.amount) claim_amount_cents,
      m.opened_at,m.resolve_after,m.recovery_initiated_at,a.analysed_at,
      EXISTS(SELECT 1 FROM pix_spi_outbox o WHERE o.transfer_id=m.transfer_id)
        external_payment,
      EXISTS(SELECT 1 FROM med_dict_analysis_outbox o WHERE o.case_id=m.id)
        analysis_required,
      p.id proposal_id,p.decision proposed_decision,p.maker_id proposed_by,
      p.basis_code,p.evidence_ref,p.evidence_summary,
      d.decision review_decision,d.decided_at
      FROM med_cases m JOIN pix_transfers t ON t.id=m.transfer_id
      LEFT JOIN med_operator_review_proposals p ON p.id=(
        SELECT q.id FROM med_operator_review_proposals q WHERE q.case_id=m.id
        ORDER BY q.rowid DESC LIMIT 1)
      LEFT JOIN med_decisions d ON d.case_id=m.id
      LEFT JOIN med_dict_analyses a ON a.case_id=m.id
      WHERE m.status='open'
        ${after ? "AND (m.resolve_after>? OR (m.resolve_after=? AND m.id>?))" : ""}
      ORDER BY m.resolve_after,m.id LIMIT 101`)
      .all(...(after ? [after[0], after[0], after[1]] : [])) as unknown as MedReviewRow[];
    const now = this.bank.now().getTime();
    const reviews = rows.slice(0, 100).map((row) => {
      if (row.external_payment !== 1 || row.review_decision !== "approved" ||
        !row.decided_at)
        return { ...row, initiation_deadline_at: null, initiation_state: null };
      const decided = Date.parse(row.decided_at);
      if (row.analysis_required === 1 && row.analysed_at === null &&
        row.recovery_initiated_at === null)
        return { ...row, initiation_deadline_at: null,
          initiation_state: "awaiting_analysis" as const };
      const clockStart = Date.parse(row.analysed_at ?? row.decided_at);
      const initiated = row.recovery_initiated_at === null ? null :
        Date.parse(row.recovery_initiated_at);
      if (!Number.isFinite(decided) || (initiated !== null &&
        (!Number.isFinite(initiated) || initiated < clockStart)) ||
        !Number.isFinite(clockStart) || clockStart < decided)
        throw new BankError("INTEGRITY_MED_INITIATION_TIME");
      const deadline = clockStart + 72 * 3_600_000;
      const initiationState: MedReviewRow["initiation_state"] = initiated === null ?
        now > deadline ? "overdue" : "pending" :
        initiated > deadline ? "late" : "on_time";
      return { ...row, initiation_deadline_at: new Date(deadline).toISOString(),
        initiation_state: initiationState };
    });
    const last = reviews.at(-1);
    const { cases: _cases, ...openingSla } = this.bank.medOpeningSla();
    return { reviews, next_cursor: rows.length > 100 && last ?
      Buffer.from(JSON.stringify([last.resolve_after, last.id])).toString("base64url") :
      null, opening_sla: openingSla };
  }

  propose(caseId: string, decision: MedDecision, evidenceRef: string,
    makerId: string, basisCode: MedReviewBasis, evidenceSummary: string):
    { id: string; case_id: string; decision: MedDecision } {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(caseId) ||
      !/^[A-Za-z0-9:_-]{8,128}$/.test(evidenceRef) ||
      !["fraud_indicators", "no_fraud_indicators", "insufficient_evidence"]
        .includes(basisCode) ||
      (decision === "approved") !== (basisCode === "fraud_indicators") ||
      typeof evidenceSummary !== "string" ||
      evidenceSummary.trim().length < 24 || evidenceSummary.length > 500 ||
      /[\u0000-\u001f\u007f]/.test(evidenceSummary))
      throw new BankError("DEF_MED_REVIEW_INVALID");
    return this.bank.transaction(() => {
      const maker = this.bank.db.prepare(`SELECT role FROM operator_accounts
        WHERE id=? AND disabled_at IS NULL`).get(makerId) as { role: string } | undefined;
      const row = this.bank.db.prepare(`SELECT m.transfer_id FROM med_cases m
        WHERE m.id=? AND m.status='open'
        AND NOT EXISTS (SELECT 1 FROM med_decisions d WHERE d.case_id=m.id)`)
        .get(caseId) as { transfer_id: string } | undefined;
      if (!maker || !["maker", "admin"].includes(maker.role) || !row)
        throw new BankError("DEF_MED_REVIEW_INVALID");
      const id = `medreview_${randomUUID()}`;
      this.bank.db.prepare(`INSERT INTO med_operator_review_proposals
        (id,case_id,transfer_id,decision,evidence_ref,basis_code,evidence_summary,
        maker_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)`).run(id, caseId,
          row.transfer_id, decision, evidenceRef, basisCode,
          evidenceSummary.trim(), makerId, this.bank.now().toISOString());
      return { id, case_id: caseId, decision };
    });
  }

  confirm(proposalId: string, checkerId: string): { id: string; case_id: string;
    decision: MedDecision; status: string; refunded_cents: number } {
    if (!/^medreview_[a-f0-9-]{36}$/.test(proposalId))
      throw new BankError("DEF_MED_REVIEW_INVALID");
    const proposed = this.bank.transaction(() => {
      const checker = this.bank.db.prepare(`SELECT role FROM operator_accounts
        WHERE id=? AND disabled_at IS NULL`).get(checkerId) as { role: string } | undefined;
      const row = this.bank.db.prepare(`SELECT p.id,p.case_id,p.decision,p.evidence_ref,
        p.maker_id,m.status FROM med_operator_review_proposals p
        JOIN med_cases m ON m.id=p.case_id WHERE p.id=?`).get(proposalId) as
        { id: string; case_id: string; decision: MedDecision; evidence_ref: string;
          maker_id: string; status: string } | undefined;
      const latest = row && this.bank.db.prepare(`SELECT id FROM med_operator_review_proposals
        WHERE case_id=? ORDER BY rowid DESC LIMIT 1`).get(row.case_id) as
        { id: string } | undefined;
      const decided = row && this.bank.db.prepare(`SELECT 1 FROM med_decisions
        WHERE case_id=?`).get(row.case_id);
      if (!checker || !["reviewer", "admin"].includes(checker.role) ||
        !row || row.status !== "open" || row.maker_id === checkerId ||
        latest?.id !== row.id || decided)
        throw new BankError("DEF_MED_REVIEW_INVALID");
      this.bank.db.prepare(`INSERT INTO med_operator_review_confirmations
        (proposal_id,checker_id,confirmed_at) VALUES (?,?,?)`).run(row.id,
          checkerId, this.bank.now().toISOString());
      this.bank.recordMedDecision(row.case_id, row.decision, row.maker_id,
        checkerId, row.evidence_ref);
      return row;
    });
    const current = this.bank.db.prepare(`SELECT status,refunded_cents FROM med_cases
      WHERE id=?`).get(proposed.case_id) as { status: string; refunded_cents: number };
    return { id: proposed.id, case_id: proposed.case_id, decision: proposed.decision,
      status: current.status, refunded_cents: current.refunded_cents };
  }

  settle(caseId: string): { id: string; status: string; refunded_cents: number } {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(caseId))
      throw new BankError("DEF_MED_REVIEW_INVALID");
    return this.bank.resolveMed(caseId);
  }

  pendingReplay(): string[] {
    return (this.bank.db.prepare(`SELECT case_id FROM med_replay_outbox
      WHERE published_at IS NULL ORDER BY enqueued_at,case_id`).all() as
      { case_id: string }[]).map((row) => row.case_id);
  }

  markReplayPublished(caseId: string): void {
    this.bank.db.prepare(`UPDATE med_replay_outbox SET published_at=?
      WHERE case_id=? AND published_at IS NULL`)
      .run(this.bank.realNow().toISOString(), caseId);
  }

  isReplayPending(caseId: string): boolean {
    return Boolean(this.bank.db.prepare(`SELECT 1 FROM med_replay_outbox
      WHERE case_id=? AND published_at IS NULL`).get(caseId));
  }

}
