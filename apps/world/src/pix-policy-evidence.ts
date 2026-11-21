import { Bank, brtHour, brtNightKey } from "./bank.ts";

export interface PixPolicyEvidence {
  transferId: string;
  fromAccount: string;
  amountCents: number;
  settledAt: string;
  nightExceeded: boolean;
  dailyExceeded: boolean;
  belowFloor: boolean;
}

export function pixPolicyEvidence(bank: Bank, transferId: string): PixPolicyEvidence | undefined {
  const transfer = bank.db.prepare(`SELECT p.rowid position,p.id,p.from_account,p.amount,
    p.settled_at,p.ledger_tx_id,a.customer_id,a.overdraft_limit
    FROM pix_transfers p JOIN accounts a ON a.id=p.from_account
    WHERE p.id=? AND p.status IN ('settled','returned_partial','returned_full')`).get(transferId) as {
      position: number; id: string; from_account: string; amount: number;
      settled_at: string; ledger_tx_id: string; customer_id: string | null;
      overdraft_limit: number;
    } | undefined;
  if (!transfer) return undefined;
  const postings = bank.db.prepare(`SELECT COUNT(*) n,COALESCE(SUM(amount),0) total
    FROM ledger_entries WHERE tx_id=? AND ref_type='pix' AND ref_id=?`)
    .get(transfer.ledger_tx_id, transfer.id) as { n: number; total: number };
  if (postings.n !== 2 || postings.total !== 0) return undefined;
  const balanceAfter = (bank.db.prepare(`SELECT COALESCE(SUM(amount),0) n
    FROM ledger_entries WHERE account_id=? AND rowid <=
    (SELECT MAX(rowid) FROM ledger_entries WHERE tx_id=?)`)
    .get(transfer.from_account, transfer.ledger_tx_id) as { n: number }).n;
  const at = new Date(transfer.settled_at);
  const since = new Date(at.getTime() - 86_400_000).toISOString();
  const recent = bank.db.prepare(`SELECT p.from_account,p.amount,p.settled_at
    FROM pix_transfers p JOIN accounts a ON a.id=p.from_account
    WHERE a.customer_id=? AND p.status IN ('settled','returned_partial','returned_full') AND p.rowid<=?
    AND p.settled_at>=? AND p.settled_at<=?`)
    .all(transfer.customer_id, transfer.position, since, transfer.settled_at) as
    { from_account: string; amount: number; settled_at: string }[];
  const hour = brtHour(at);
  const nightStart = at.getTime() - 12 * 60 * 60_000;
  const key = brtNightKey(at);
  const nightUsed = recent.filter((row) => Date.parse(row.settled_at) >= nightStart &&
    brtNightKey(new Date(row.settled_at)) === key)
    .reduce((sum, row) => sum + row.amount, 0);
  const dailyUsed = recent.filter((row) => row.from_account === transfer.from_account)
    .reduce((sum, row) => sum + row.amount, 0);
  return { transferId: transfer.id, fromAccount: transfer.from_account,
    amountCents: transfer.amount, settledAt: transfer.settled_at,
    nightExceeded: (hour >= 20 || hour < 6) && nightUsed > 100_000,
    dailyExceeded: transfer.customer_id !== null &&
      dailyUsed > bank.pixDailyLimit(transfer.customer_id),
    belowFloor: balanceAfter < -transfer.overdraft_limit };
}
