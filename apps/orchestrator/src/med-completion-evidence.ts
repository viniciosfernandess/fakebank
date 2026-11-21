import type { DatabaseSync } from "node:sqlite";

export const MED_COMPLETION = {
  med_settlement: { outbox: "med_psp_settlement_outbox", decision: "approved" },
  med_release: { outbox: "med_psp_release_outbox", decision: "rejected" },
} as const;
export type MedCompletionStage = keyof typeof MED_COMPLETION;

export function medCompletionEvidence(db: DatabaseSync, stage: MedCompletionStage, id: string) {
  const { outbox, decision } = MED_COMPLETION[stage];
  const settled = stage === "med_settlement";
  return db.prepare(`SELECT m.id,m.customer_id,p.idempotency_key,
      p.ledger_tx_id AS original_ledger_tx_id,o.created_at AS enqueued_at,
      ${settled ? "r.ledger_tx_id" : "NULL"} AS refund_ledger_tx_id,
      CASE WHEN o.acknowledged_at>=o.created_at
        AND EXISTS (SELECT 1 FROM med_hops h WHERE h.case_id=m.id AND h.blocked_cents>0)
        AND NOT EXISTS (SELECT 1 FROM med_hops h WHERE h.case_id=m.id
          AND (h.released_at IS NULL OR h.released_at<o.created_at
            ${settled ? "" : "OR h.refunded_cents<>0"}))
        AND ${settled ? `m.status='resolved' AND m.claim_amount_cents>0
          AND m.refunded_cents=m.claim_amount_cents AND m.unrecovered_cents=0
          AND r.amount=m.claim_amount_cents AND r.created_at>=o.created_at
          AND (SELECT COUNT(*) FROM med_refunds x WHERE x.case_id=m.id)=1
          AND (SELECT COUNT(*) FROM ledger_entries e WHERE e.tx_id=r.ledger_tx_id
            AND e.account_id=p.from_account AND e.kind='med_recovery'
            AND e.ref_id=p.id AND e.amount=m.claim_amount_cents)=1` :
        `m.status='rejected' AND m.refunded_cents=0
          AND NOT EXISTS (SELECT 1 FROM med_refunds x WHERE x.case_id=m.id)`}
        THEN o.acknowledged_at END AS completed_at
    FROM ${outbox} o
    JOIN med_cases m ON m.id=o.case_id AND m.transfer_id=o.transfer_id
    JOIN med_decisions d ON d.case_id=m.id AND d.decision=? AND d.maker_id<>d.checker_id
    JOIN pix_transfers p ON p.id=o.transfer_id
    JOIN accounts a ON a.id=p.from_account AND a.customer_id=m.customer_id
    ${settled ? "LEFT JOIN med_refunds r ON r.case_id=m.id" : ""}
    WHERE o.case_id=? AND o.created_at>=d.decided_at
    ORDER BY o.case_id LIMIT 1`).get(decision, id) as {
    id: string; customer_id: string; idempotency_key: string;
    original_ledger_tx_id: string | null; refund_ledger_tx_id: string | null;
    enqueued_at: string; completed_at: string | null;
  } | undefined;
}
