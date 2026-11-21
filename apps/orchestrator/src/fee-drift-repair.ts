import type { Bank } from "../../world/src/bank.ts";

export interface FeeDriftRepairReceipt {
  incidentId: string;
  transactionId: string;
  amountCents: number;
  feeTransactions: number;
}

/** Recognizes the exact undercharged-fee ledger shape before booking the bank's loss. */
export function repairFeeDrift(bank: Bank, incidentId: string): FeeDriftRepairReceipt {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(incidentId))
    throw new Error("DEF_FEE_REPAIR_INCIDENT_INVALID");
  const rounding = bank.systemAccountId("rounding");
  const fees = bank.systemAccountId("fees");
  const loss = bank.systemAccountId("bank_loss");
  bank.db.exec(`CREATE TABLE IF NOT EXISTS defense_fee_drift_repairs (
    incident_id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL,
    amount_cents INTEGER NOT NULL, fee_transactions INTEGER NOT NULL,
    created_at TEXT NOT NULL
  )`);
  return bank.transaction(() => {
    const prior = bank.db.prepare(`SELECT incident_id,transaction_id,
      amount_cents,fee_transactions FROM defense_fee_drift_repairs
      WHERE incident_id=?`).get(incidentId) as {
      incident_id: string; transaction_id: string;
      amount_cents: number; fee_transactions: number;
    } | undefined;
    if (prior) return { incidentId: prior.incident_id,
      transactionId: prior.transaction_id, amountCents: prior.amount_cents,
      feeTransactions: prior.fee_transactions };
    if (bank.isWeaknessOpen("W16")) throw new Error("DEF_FEE_REPAIR_DEFECT_ACTIVE");
    const before = bank.reconcile();
    if (before.unbalancedTx || before.accountDrift || before.belowFloor ||
      before.medDrift || before.roundingDrift < 500)
      throw new Error("DEF_FEE_REPAIR_PRECHECK_FAILED");
    const balance = bank.account(rounding).balance_cached;
    if (balance >= 0) throw new Error("DEF_FEE_REPAIR_DIRECTION_UNPROVEN");
    const candidates = bank.db.prepare(`SELECT tx_id FROM ledger_entries
      WHERE account_id=? AND kind='service_fee' AND amount=-1
      ORDER BY tx_id LIMIT 2001`).all(rounding) as { tx_id: string }[];
    if (candidates.length !== -balance || candidates.length > 2000)
      throw new Error("DEF_FEE_REPAIR_AMOUNT_UNPROVEN");
    for (const candidate of candidates) {
      const lines = bank.db.prepare(`SELECT e.account_id,e.amount,e.kind,
        e.ref_type,e.ref_id,a.kind account_kind FROM ledger_entries e
        JOIN accounts a ON a.id=e.account_id WHERE e.tx_id=?`)
        .all(candidate.tx_id) as { account_id: string; amount: number;
          kind: string; ref_type: string; ref_id: string;
          account_kind: string }[];
      const roundingLine = lines.find((line) => line.account_id === rounding);
      const feeLine = lines.find((line) => line.account_id === fees);
      const customerLine = lines.find((line) => line.account_kind !== "system");
      if (lines.length !== 3 || !roundingLine || !feeLine || !customerLine ||
        roundingLine.amount !== -1 || feeLine.amount <= 0 ||
        customerLine.amount !== 1 - feeLine.amount ||
        lines.some((line) => line.kind !== "service_fee" ||
          line.ref_type !== "fee" || line.ref_id !== roundingLine.ref_id))
        throw new Error("DEF_FEE_REPAIR_LEDGER_SHAPE_UNPROVEN");
    }
    const transactionId = bank.post([
      { accountId: loss, amount: balance, kind: "fee_drift_loss",
        actor: "defense_repair", refType: "sentinel_incident", refId: incidentId },
      { accountId: rounding, amount: -balance, kind: "fee_drift_loss",
        actor: "defense_repair", refType: "sentinel_incident", refId: incidentId },
    ]);
    if (!bank.reconcile().ok || bank.account(rounding).balance_cached !== 0)
      throw new Error("DEF_FEE_REPAIR_RECONCILIATION_FAILED");
    bank.db.prepare(`INSERT INTO defense_fee_drift_repairs VALUES (?,?,?,?,?)`)
      .run(incidentId, transactionId, -balance, candidates.length,
        bank.now().toISOString());
    return { incidentId, transactionId,
      amountCents: -balance, feeTransactions: candidates.length };
  });
}
