import type { DatabaseSync } from "node:sqlite";
import type { Bank } from "./bank.ts";
import { accountingDates } from "./accounting-dates.ts";

interface AccrualRow {
  loan_id: string; installment_no: number; value_date: string;
  amount_cents: number; ledger_tx_id: string;
}

export function installLoanInterestAccruals(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS loan_interest_accruals (
    loan_id TEXT NOT NULL, installment_no INTEGER NOT NULL,
    value_date TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
    ledger_tx_id TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
    PRIMARY KEY(loan_id,installment_no),
    FOREIGN KEY(loan_id,installment_no) REFERENCES loan_installments(loan_id,installment_no)
  );
  CREATE TRIGGER IF NOT EXISTS loan_interest_accruals_no_update
    BEFORE UPDATE ON loan_interest_accruals
    BEGIN SELECT RAISE(ABORT,'LOAN_INTEREST_ACCRUAL_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS loan_interest_accruals_no_delete
    BEFORE DELETE ON loan_interest_accruals
    BEGIN SELECT RAISE(ABORT,'LOAN_INTEREST_ACCRUAL_IMMUTABLE'); END;`);
}

function installed(db: DatabaseSync): boolean {
  return Boolean(db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='loan_interest_accruals'`).get());
}

export function loanInterestAccrued(db: DatabaseSync, loanId: string,
  installmentNo: number): boolean {
  return installed(db) && Boolean(db.prepare(`SELECT 1 FROM loan_interest_accruals
    WHERE loan_id=? AND installment_no=?`).get(loanId, installmentNo));
}

export function accrueLoanInterest(bank: Bank, loanId: string, installmentNo: number,
  amountCents: number, valueDate: string): boolean {
  if (!Number.isSafeInteger(amountCents) || amountCents <= 0)
    throw new Error("LOAN_INTEREST_ACCRUAL_AMOUNT_INVALID");
  if (loanInterestAccrued(bank.db, loanId, installmentNo)) return false;
  const installment = bank.db.prepare(`SELECT due_date,interest_cents FROM loan_installments
    WHERE loan_id=? AND installment_no=?`).get(loanId, installmentNo) as
    { due_date: string; interest_cents: number } | undefined;
  if (!installment || installment.interest_cents !== amountCents ||
    valueDate < installment.due_date)
    throw new Error("LOAN_INTEREST_ACCRUAL_CONTRACT_MISMATCH");
  const txId = bank.post([
    { accountId: bank.systemAccountId("loan_interest_receivable"), amount: -amountCents,
      kind: "loan_interest_accrual", actor: "loan_accrual_engine",
      refType: "loan", refId: loanId },
    { accountId: bank.systemAccountId("loan_interest_revenue"), amount: amountCents,
      kind: "loan_interest_accrual", actor: "loan_accrual_engine",
      refType: "loan", refId: loanId },
  ], undefined, valueDate);
  bank.db.prepare(`INSERT INTO loan_interest_accruals VALUES (?,?,?,?,?,?)`)
    .run(loanId, installmentNo, valueDate, amountCents, txId, bank.now().toISOString());
  return true;
}

export function bookLoanInterestAccruals(bank: Bank, asOfDate: string): number {
  if (!installed(bank.db)) return 0;
  const due = bank.db.prepare(`SELECT i.loan_id,i.installment_no,i.interest_cents
    FROM loan_installments i JOIN loans l ON l.id=i.loan_id
    LEFT JOIN loan_installment_payments p ON p.loan_id=i.loan_id
      AND p.installment_no=i.installment_no
    LEFT JOIN loan_interest_accruals a ON a.loan_id=i.loan_id
      AND a.installment_no=i.installment_no
    WHERE i.due_date<=? AND i.interest_cents>0 AND i.status='scheduled'
      AND a.loan_id IS NULL
      AND p.loan_id IS NULL
    ORDER BY i.loan_id,i.installment_no`).all(asOfDate) as
    { loan_id: string; installment_no: number; interest_cents: number }[];
  let booked = 0;
  for (const row of due)
    if (accrueLoanInterest(bank, row.loan_id, row.installment_no,
      row.interest_cents, asOfDate)) booked++;
  return booked;
}

export function reconcileLoanInterestAccruals(db: DatabaseSync): boolean {
  if (!installed(db)) return true;
  const receivable = db.prepare(`SELECT id,balance_cached FROM accounts
    WHERE kind='system' AND system_role='loan_interest_receivable'`).get() as
    { id: string; balance_cached: number } | undefined;
  const revenue = db.prepare(`SELECT id,balance_cached FROM accounts
    WHERE kind='system' AND system_role='loan_interest_revenue'`).get() as
    { id: string; balance_cached: number } | undefined;
  const accruals = db.prepare(`SELECT loan_id,installment_no,value_date,amount_cents,ledger_tx_id
    FROM loan_interest_accruals`).all() as unknown as AccrualRow[];
  if (accruals.length && (!receivable || !revenue)) return false;
  const entries = db.prepare(`SELECT account_id,amount,kind,ref_type,ref_id
    FROM ledger_entries WHERE tx_id=?`);
  const dates = db.prepare(`SELECT DISTINCT d.value_date FROM ledger_entries e
    JOIN ledger_accounting_view d ON d.id=e.id WHERE e.tx_id=?`);
  const installment = db.prepare(`SELECT due_date,interest_cents FROM loan_installments
    WHERE loan_id=? AND installment_no=?`);
  const payment = db.prepare(`SELECT interest_cents,interest_tx_id,paid_at
    FROM loan_installment_payments WHERE loan_id=? AND installment_no=?`);
  const hasPartials = Boolean(db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='loan_installment_partial_payments'`).get());
  const partialPayments = hasPartials ? db.prepare(`SELECT interest_cents,
    interest_tx_id,paid_at FROM loan_installment_partial_payments
    WHERE loan_id=? AND installment_no=? ORDER BY paid_at,id`) : null;
  let total = 0, collected = 0;
  const expectedTx = new Set<string>();
  for (const accrual of accruals) {
    const schedule = installment.get(accrual.loan_id, accrual.installment_no) as
      { due_date: string; interest_cents: number } | undefined;
    if (!schedule || accrual.value_date < schedule.due_date ||
      accrual.amount_cents !== schedule.interest_cents ||
      !Number.isSafeInteger(accrual.amount_cents) || accrual.amount_cents <= 0 ||
      expectedTx.has(accrual.ledger_tx_id)) return false;
    const rows = entries.all(accrual.ledger_tx_id) as
      { account_id: string; amount: number; kind: string; ref_type: string; ref_id: string }[];
    const recordedDates = dates.all(accrual.ledger_tx_id) as { value_date: string }[];
    if (rows.length !== 2 || !rows.every((row) => row.kind === "loan_interest_accrual" &&
      row.ref_type === "loan" && row.ref_id === accrual.loan_id) ||
      recordedDates.length !== 1 || recordedDates[0]!.value_date !== accrual.value_date ||
      !rows.some((row) => row.account_id === receivable!.id &&
        row.amount === -accrual.amount_cents) ||
      !rows.some((row) => row.account_id === revenue!.id &&
        row.amount === accrual.amount_cents)) return false;
    expectedTx.add(accrual.ledger_tx_id);
    total += accrual.amount_cents;
    const paid = payment.get(accrual.loan_id, accrual.installment_no) as
      { interest_cents: number; interest_tx_id: string | null; paid_at: string } | undefined;
    if (paid) {
      if (paid.interest_cents !== accrual.amount_cents ||
        accountingDates(paid.paid_at).posting_date < accrual.value_date ||
        !paid.interest_tx_id || expectedTx.has(paid.interest_tx_id)) return false;
      expectedTx.add(paid.interest_tx_id);
      collected += paid.interest_cents;
    }
    const parts = partialPayments?.all(accrual.loan_id, accrual.installment_no) as
      { interest_cents: number; interest_tx_id: string | null;
        paid_at: string }[] | undefined ?? [];
    let partialInterest = 0;
    for (const part of parts) {
      if (!Number.isSafeInteger(part.interest_cents) || part.interest_cents < 0 ||
        accountingDates(part.paid_at).posting_date < accrual.value_date ||
        (part.interest_cents > 0 && (!part.interest_tx_id ||
          expectedTx.has(part.interest_tx_id))) ||
        (part.interest_cents === 0 && part.interest_tx_id)) return false;
      if (part.interest_tx_id) expectedTx.add(part.interest_tx_id);
      partialInterest += part.interest_cents;
    }
    if (partialInterest > accrual.amount_cents ||
      (paid && partialInterest > 0)) return false;
    collected += partialInterest;
  }
  if (!Number.isSafeInteger(total) || !Number.isSafeInteger(collected)) return false;
  if (!receivable || !revenue) return true;
  const posted = db.prepare(`SELECT DISTINCT tx_id FROM ledger_entries
    WHERE account_id IN (?,?) AND kind IN
      ('loan_interest_accrual','loan_interest_payment')`)
    .all(receivable.id, revenue.id) as { tx_id: string }[];
  if (db.prepare(`SELECT 1 FROM ledger_entries WHERE
    (account_id=? AND kind NOT IN ('loan_interest_accrual','loan_interest_payment'))
    OR (account_id=? AND kind NOT IN
      ('loan_interest_accrual','result_transfer_loan_interest')) LIMIT 1`)
    .get(receivable.id, revenue.id)) return false;
  const transferred = (db.prepare(`SELECT COALESCE(SUM(amount),0) amount
    FROM ledger_entries WHERE account_id=? AND kind='result_transfer_loan_interest'`)
    .get(revenue.id) as { amount: number }).amount;
  return posted.length === expectedTx.size &&
    posted.every((row) => expectedTx.has(row.tx_id)) &&
    receivable.balance_cached === collected - total &&
    Number.isSafeInteger(transferred) && revenue.balance_cached === total + transferred;
}
