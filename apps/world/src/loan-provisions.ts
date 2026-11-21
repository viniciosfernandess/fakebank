import type { DatabaseSync } from "node:sqlite";
import type { Bank } from "./bank.ts";
import { accountingDates } from "./accounting-dates.ts";
import { assessLoanSchedule, SYNTHETIC_LOAN_POLICY_V1,
  type LoanInstallment } from "./loan-schedules.ts";

export function installLoanProvisions(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS loan_provision_positions (
    loan_id TEXT PRIMARY KEY REFERENCES loans(id),
    amount_cents INTEGER NOT NULL CHECK(amount_cents>=0),
    as_of_date TEXT NOT NULL, policy_version INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS loan_provision_changes (
    loan_id TEXT NOT NULL REFERENCES loans(id), as_of_date TEXT NOT NULL,
    previous_cents INTEGER NOT NULL, amount_cents INTEGER NOT NULL,
    delta_cents INTEGER NOT NULL, max_days_past_due INTEGER NOT NULL,
    policy_version INTEGER NOT NULL, ledger_tx_id TEXT, created_at TEXT NOT NULL,
    PRIMARY KEY(loan_id,as_of_date)
  );
  CREATE TRIGGER IF NOT EXISTS loan_provision_changes_no_update
    BEFORE UPDATE ON loan_provision_changes
    BEGIN SELECT RAISE(ABORT,'LOAN_PROVISION_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS loan_provision_changes_no_delete
    BEFORE DELETE ON loan_provision_changes
    BEGIN SELECT RAISE(ABORT,'LOAN_PROVISION_IMMUTABLE'); END;`);
}

function installed(db: DatabaseSync): boolean {
  return Boolean(db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='loan_provision_positions'`).get());
}

function assessedProvision(db: DatabaseSync, loanId: string, asOfDate: string):
  { amount_cents: number; max_days_past_due: number } | null {
  const contract = db.prepare(`SELECT l.started_at FROM loan_contracts c
    JOIN loans l ON l.id=c.loan_id WHERE c.loan_id=?`).get(loanId) as
    { started_at: string } | undefined;
  if (!contract || accountingDates(contract.started_at).posting_date > asOfDate) return null;
  const rows = db.prepare(`SELECT installment_no number,due_date,opening_principal_cents,
    principal_cents,interest_cents,payment_cents,closing_principal_cents
    FROM loan_installments WHERE loan_id=? ORDER BY installment_no`)
    .all(loanId) as unknown as LoanInstallment[];
  const payments = db.prepare(`SELECT installment_no,paid_at FROM loan_installment_payments
    WHERE loan_id=?`).all(loanId) as { installment_no: number; paid_at: string }[];
  const paidByDate = new Set(payments.filter((payment) =>
    accountingDates(payment.paid_at).posting_date <= asOfDate)
    .map((payment) => payment.installment_no));
  const hasPartials = Boolean(db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='loan_installment_partial_payments'`).get());
  const partials = hasPartials ? db.prepare(`SELECT installment_no,
    principal_cents,interest_cents,paid_at
    FROM loan_installment_partial_payments WHERE loan_id=?`).all(loanId) as {
      installment_no: number; principal_cents: number; interest_cents: number;
      paid_at: string;
    }[] : [];
  const partialPaid = new Map<number, number>();
  for (const part of partials) {
    if (accountingDates(part.paid_at).posting_date > asOfDate) continue;
    partialPaid.set(part.installment_no, (partialPaid.get(part.installment_no) ?? 0) +
      part.principal_cents + part.interest_cents);
  }
  const payoff = db.prepare(`SELECT DISTINCT e.tx_id,e.created_at FROM ledger_entries e
    WHERE e.ref_type='loan' AND e.ref_id=? AND e.kind='loan_principal_repay'
      AND NOT EXISTS (SELECT 1 FROM loan_installment_payments p
        WHERE p.principal_tx_id=e.tx_id)
      ${hasPartials ? `AND NOT EXISTS (SELECT 1 FROM loan_installment_partial_payments p
        WHERE p.principal_tx_id=e.tx_id)` : ""}`).all(loanId) as
    { tx_id: string; created_at: string }[];
  if (payoff.some((row) => accountingDates(row.created_at).posting_date <= asOfDate))
    return { amount_cents: 0, max_days_past_due: 0 };
  const assessment = assessLoanSchedule(rows,
    rows.map((row) => paidByDate.has(row.number) ? row.payment_cents :
      partialPaid.get(row.number) ?? 0), asOfDate);
  return { amount_cents: assessment.provision_cents,
    max_days_past_due: assessment.max_days_past_due };
}

export function bookLoanProvisions(bank: Bank, asOfDate: string): number {
  if (!installed(bank.db)) return 0;
  const loans = bank.db.prepare(`SELECT c.loan_id,l.started_at
    FROM loan_contracts c JOIN loans l ON l.id=c.loan_id ORDER BY c.loan_id`)
    .all() as { loan_id: string; started_at: string }[];
  let changed = 0;
  for (const loan of loans) {
    if (accountingDates(loan.started_at).posting_date > asOfDate) continue;
    const assessment = assessedProvision(bank.db, loan.loan_id, asOfDate);
    if (!assessment) throw new Error("INTEGRITY_LOAN_PROVISION_ASSESSMENT");
    const target = assessment.amount_cents;
    const previous = bank.db.prepare(`SELECT amount_cents,as_of_date
      FROM loan_provision_positions WHERE loan_id=?`).get(loan.loan_id) as
      { amount_cents: number; as_of_date: string } | undefined;
    if (previous && previous.as_of_date >= asOfDate)
      throw new Error("LOAN_PROVISION_DATE_ORDER");
    const delta = target - (previous?.amount_cents ?? 0);
    const txId = delta ? bank.post([
      { accountId: bank.systemAccountId("loan_provision_expense"), amount: -delta,
        kind: "loan_provision", actor: "loan_provision_engine",
        refType: "loan", refId: loan.loan_id },
      { accountId: bank.systemAccountId("loan_loss_allowance"), amount: delta,
        kind: "loan_provision", actor: "loan_provision_engine",
        refType: "loan", refId: loan.loan_id },
    ], undefined, asOfDate) : null;
    bank.db.prepare(`INSERT INTO loan_provision_changes VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(loan.loan_id, asOfDate, previous?.amount_cents ?? 0, target, delta,
        assessment.max_days_past_due, SYNTHETIC_LOAN_POLICY_V1.version,
        txId, bank.now().toISOString());
    bank.db.prepare(`INSERT INTO loan_provision_positions VALUES (?,?,?,?)
      ON CONFLICT(loan_id) DO UPDATE SET amount_cents=excluded.amount_cents,
      as_of_date=excluded.as_of_date,policy_version=excluded.policy_version`)
      .run(loan.loan_id, target, asOfDate, SYNTHETIC_LOAN_POLICY_V1.version);
    if (delta) changed++;
  }
  return changed;
}

export function reconcileLoanProvisions(db: DatabaseSync): boolean {
  if (!installed(db)) return true;
  const positions = db.prepare("SELECT loan_id,amount_cents,as_of_date,policy_version FROM loan_provision_positions")
    .all() as { loan_id: string; amount_cents: number; as_of_date: string; policy_version: number }[];
  const changes = db.prepare(`SELECT loan_id,as_of_date,previous_cents,amount_cents,
    delta_cents,max_days_past_due,policy_version,ledger_tx_id FROM loan_provision_changes
    ORDER BY loan_id,as_of_date`).all() as unknown as {
      loan_id: string; as_of_date: string; previous_cents: number; amount_cents: number;
      delta_cents: number; max_days_past_due: number; policy_version: number;
      ledger_tx_id: string | null;
    }[];
  const ledger = db.prepare(`SELECT account_id,amount,kind,ref_type,ref_id
    FROM ledger_entries WHERE tx_id=?`);
  const expense = db.prepare(`SELECT id,balance_cached FROM accounts
    WHERE kind='system' AND system_role='loan_provision_expense'`).get() as
    { id: string; balance_cached: number } | undefined;
  const allowance = db.prepare(`SELECT id,balance_cached FROM accounts
    WHERE kind='system' AND system_role='loan_loss_allowance'`).get() as
    { id: string; balance_cached: number } | undefined;
  if ((changes.length || positions.length) && (!expense || !allowance)) return false;
  let currentLoan = "", previous = 0;
  const last = new Map<string, typeof changes[number]>();
  for (const change of changes) {
    if (change.loan_id !== currentLoan) { currentLoan = change.loan_id; previous = 0; }
    const assessment = assessedProvision(db, change.loan_id, change.as_of_date);
    if (!assessment || assessment.amount_cents !== change.amount_cents ||
      assessment.max_days_past_due !== change.max_days_past_due) return false;
    if (change.previous_cents !== previous ||
      change.delta_cents !== change.amount_cents - previous ||
      change.amount_cents < 0 ||
      change.policy_version !== SYNTHETIC_LOAN_POLICY_V1.version) return false;
    if (change.delta_cents === 0 ? change.ledger_tx_id !== null : !change.ledger_tx_id)
      return false;
    if (change.ledger_tx_id) {
      const rows = ledger.all(change.ledger_tx_id) as { account_id: string; amount: number;
        kind: string; ref_type: string; ref_id: string }[];
      if (rows.length !== 2 || !rows.every((row) => row.kind === "loan_provision" &&
        row.ref_type === "loan" && row.ref_id === change.loan_id) ||
        !rows.some((row) => row.account_id === expense!.id &&
          row.amount === -change.delta_cents) ||
        !rows.some((row) => row.account_id === allowance!.id &&
          row.amount === change.delta_cents)) return false;
    }
    previous = change.amount_cents;
    last.set(change.loan_id, change);
  }
  if (last.size !== positions.length) return false;
  let total = 0;
  for (const position of positions) {
    const latest = last.get(position.loan_id);
    if (!latest || latest.as_of_date !== position.as_of_date ||
      latest.amount_cents !== position.amount_cents ||
      position.policy_version !== SYNTHETIC_LOAN_POLICY_V1.version) return false;
    total += position.amount_cents;
  }
  if (expense && allowance) {
    const posted = db.prepare(`SELECT DISTINCT tx_id FROM ledger_entries
      WHERE account_id IN (?,?) AND kind='loan_provision'`)
      .all(expense.id, allowance.id) as { tx_id: string }[];
    const expected = changes.flatMap((change) => change.ledger_tx_id ? [change.ledger_tx_id] : []);
    if (posted.length !== expected.length || new Set(expected).size !== expected.length ||
      posted.some((row) => !expected.includes(row.tx_id))) return false;
    if (db.prepare(`SELECT 1 FROM ledger_entries WHERE
      (account_id=? AND kind NOT IN ('loan_provision','result_transfer_loan_provision'))
      OR (account_id=? AND kind<>'loan_provision') LIMIT 1`)
      .get(expense.id, allowance.id)) return false;
  }
  const transferred = expense ? (db.prepare(`SELECT COALESCE(SUM(amount),0) amount
    FROM ledger_entries WHERE account_id=? AND kind='result_transfer_loan_provision'`)
    .get(expense.id) as { amount: number }).amount : 0;
  return Number.isSafeInteger(total) &&
    Number.isSafeInteger(transferred) &&
    (allowance?.balance_cached ?? 0) === total &&
    (expense?.balance_cached ?? 0) === -total + transferred;
}
