import type { DatabaseSync } from "node:sqlite";

export function hasMedCustomerCredit(db: DatabaseSync, input: {
  sourceAccount: string; sourceId: string; txId: string; amount: number;
  kind: "med_refund" | "med_incident_compensation";
  refType: "pix" | "med_case"; refId: string;
}): boolean {
  const credit = db.prepare(`SELECT l.account_id,l.amount,a.system_role FROM ledger_entries l
    JOIN accounts a ON a.id=l.account_id
    WHERE l.tx_id=? AND l.kind=? AND l.ref_type=? AND l.ref_id=? AND l.amount>0`)
    .all(input.txId, input.kind, input.refType, input.refId) as
    { account_id: string; amount: number; system_role: string | null }[];
  if (credit.length !== 1 || credit[0]!.amount !== input.amount) return false;
  if (credit[0]!.account_id === input.sourceAccount) return true;
  if (credit[0]!.system_role !== "suspense") return false;
  return Boolean(db.prepare(`SELECT 1 FROM closed_account_credits c
    JOIN accounts source ON source.id=c.source_account AND source.customer_id=c.customer_id
    WHERE c.source_kind='med_recovery' AND c.source_id=? AND c.source_account=?
      AND c.ledger_tx_id=? AND c.amount_cents=?`)
    .get(input.sourceId, input.sourceAccount, input.txId, input.amount));
}

export function readMedIncidentCompensation(db: DatabaseSync, input: {
  caseId: string; sourceAccount: string; amount: number;
}): { txId: string; amount: number } | undefined {
  if (!Number.isSafeInteger(input.amount) || input.amount <= 0) return undefined;
  const debit = db.prepare(`SELECT l.tx_id,l.amount,a.system_role FROM ledger_entries l
    JOIN accounts a ON a.id=l.account_id
    WHERE l.kind='med_incident_loss' AND l.ref_type='med_case' AND l.ref_id=?`)
    .all(input.caseId) as { tx_id: string; amount: number; system_role: string | null }[];
  if (debit.length !== 1 || debit[0]!.amount !== -input.amount ||
    debit[0]!.system_role !== "bank_loss") return undefined;
  const txId = debit[0]!.tx_id;
  const count = db.prepare("SELECT COUNT(*) n FROM ledger_entries WHERE tx_id=?")
    .get(txId) as { n: number };
  return count.n === 2 && hasMedCustomerCredit(db, {
    sourceAccount: input.sourceAccount, sourceId: `${input.caseId}:compensation`,
    txId, amount: input.amount, kind: "med_incident_compensation",
    refType: "med_case", refId: input.caseId,
  }) ? { txId, amount: input.amount } : undefined;
}
