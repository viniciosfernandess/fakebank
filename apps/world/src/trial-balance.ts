import type { DatabaseSync } from "node:sqlite";

export interface TrialBalanceLine {
  code: string;
  description: string;
  nature: "asset" | "liability" | "equity" | "revenue" | "expense";
  balance_cents: number;
  debit_cents: number;
  credit_cents: number;
}

export const CHART_VERSION = 8;

const chart: [string, TrialBalanceLine["nature"], string, string | null][] = [
  ["1000", "asset", "Cash funding source", "cash_in"],
  ["1010", "asset", "Cash disbursement clearing", "cash_out"],
  ["1020", "asset", "Central bank PI settlement", "pix_settlement"],
  ["1030", "asset", "Card network settlement", "card_settlement"],
  ["1100", "asset", "Loan principal receivable", null],
  ["1110", "asset", "Credit card receivable", null],
  ["1120", "asset", "Loan expected loss allowance", "loan_loss_allowance"],
  ["1130", "asset", "Loan interest receivable", "loan_interest_receivable"],
  ["2000", "liability", "Customer deposits", null],
  ["2100", "liability", "Loan funding reserve", "loan_funding"],
  ["2200", "liability", "Cashback reserve", "cashback_pool"],
  ["2300", "liability", "Recovery reserve", "recovery"],
  ["2400", "liability", "Suspense", "suspense"],
  ["2600", "liability", "Customer credit card overpayments", null],
  ["2900", "equity", "Paid-in synthetic capital", "equity_capital"],
  ["2910", "equity", "Retained synthetic earnings", "retained_earnings"],
  ["3000", "revenue", "Other fee-account movements", "fees"],
  ["3010", "revenue", "Service fee income", null],
  ["3020", "revenue", "Loan origination fees net of rebates", null],
  ["3030", "revenue", "Credit card interest income", null],
  ["3040", "revenue", "Credit card IOF charges", null],
  ["3050", "revenue", "Loan interest income", "loan_interest_revenue"],
  ["3060", "revenue", "Loan late fees and mora income", null],
  ["3900", "revenue", "Rounding difference", "rounding"],
  ["4000", "expense", "Operational fraud loss", "bank_loss"],
  ["4010", "expense", "Loan expected loss provision", "loan_provision_expense"],
];

export function installChartOfAccounts(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS gl_accounts (
    code TEXT PRIMARY KEY, nature TEXT NOT NULL CHECK(nature IN ('asset','liability','equity','revenue','expense')),
    description TEXT NOT NULL, system_role TEXT UNIQUE
  );
  CREATE TABLE IF NOT EXISTS period_trial_balances (
    brt_date TEXT PRIMARY KEY REFERENCES period_closes(brt_date),
    lines_json TEXT NOT NULL, debit_cents INTEGER NOT NULL, credit_cents INTEGER NOT NULL
  );
  CREATE TRIGGER IF NOT EXISTS period_trial_balances_no_update
    BEFORE UPDATE ON period_trial_balances
    BEGIN SELECT RAISE(ABORT,'PERIOD_TRIAL_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS period_trial_balances_no_delete
    BEFORE DELETE ON period_trial_balances
    BEGIN SELECT RAISE(ABORT,'PERIOD_TRIAL_IMMUTABLE'); END;`);
  const schema = db.prepare(`SELECT sql FROM sqlite_master WHERE type='table'
    AND name='gl_accounts'`).get() as { sql: string };
  if (!schema.sql.includes("'equity'")) {
    db.exec("SAVEPOINT gl_equity_nature");
    try {
      db.exec(`CREATE TABLE gl_accounts_v7 (
        code TEXT PRIMARY KEY,
        nature TEXT NOT NULL CHECK(nature IN ('asset','liability','equity','revenue','expense')),
        description TEXT NOT NULL, system_role TEXT UNIQUE
      );
      INSERT INTO gl_accounts_v7 SELECT code,nature,description,system_role FROM gl_accounts;
      DROP TABLE gl_accounts;
      ALTER TABLE gl_accounts_v7 RENAME TO gl_accounts;
      RELEASE gl_equity_nature;`);
    } catch (error) {
      db.exec("ROLLBACK TO gl_equity_nature; RELEASE gl_equity_nature");
      throw error;
    }
  }
  const insert = db.prepare("INSERT OR IGNORE INTO gl_accounts VALUES (?,?,?,?)");
  for (const row of chart) insert.run(...row);
  const legacy = db.prepare("SELECT nature,description,system_role FROM gl_accounts WHERE code='2500'")
    .get() as { nature: string; description: string; system_role: string | null } | undefined;
  if (legacy) {
    if (legacy.nature !== "liability" || legacy.description !== "Synthetic actor funding" ||
      legacy.system_role !== "attacker_seed")
      throw new Error("INTEGRITY_GL_LEGACY_FUNDING");
    db.prepare("DELETE FROM gl_accounts WHERE code='2500'").run();
  }
  db.prepare(`UPDATE gl_accounts SET description='Other fee-account movements'
    WHERE code='3000' AND nature='revenue' AND system_role='fees'
      AND description='Fee income'`).run();
  db.prepare(`UPDATE gl_accounts SET system_role='loan_interest_revenue'
    WHERE code='3050' AND nature='revenue' AND system_role IS NULL
      AND description='Loan interest income'`).run();
}

function loanPrincipal(db: DatabaseSync): number {
  const kinds = "'loan_disbursement','flash_loan','loan_principal_repay'";
  const funding = db.prepare("SELECT id FROM accounts WHERE kind='system' AND system_role='loan_funding'")
    .all() as { id: string }[];
  if (funding.length > 1) throw new Error("INTEGRITY_LOAN_PRINCIPAL");
  const principal = db.prepare(`SELECT tx_id,account_id,amount,kind,ref_type,ref_id,reverses_tx_id
    FROM ledger_entries WHERE kind IN (${kinds})`).all() as { tx_id: string; account_id: string;
      amount: number; kind: string; ref_type: string; ref_id: string; reverses_tx_id: string | null }[];
  const fundingId = funding[0]?.id;
  if (fundingId !== undefined && db.prepare(`SELECT 1 FROM ledger_entries
    WHERE account_id=? AND ref_type='loan' AND kind NOT IN (${kinds}) LIMIT 1`).get(fundingId))
    throw new Error("INTEGRITY_LOAN_PRINCIPAL");
  const hasLoans = db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='loans'").get();
  if (!hasLoans) {
    if (principal.length !== 0) throw new Error("INTEGRITY_LOAN_PRINCIPAL");
    return 0;
  }
  const loans = db.prepare(`SELECT id,account_id,principal_cents,status,disbursement_tx_id
    FROM loans`).all() as { id: string; account_id: string; principal_cents: number;
      status: string; disbursement_tx_id: string }[];
  if (loans.length > 0 && funding.length !== 1) throw new Error("INTEGRITY_LOAN_PRINCIPAL");
  const byLoan = new Map<string, typeof principal>();
  for (const entry of principal) {
    const rows = byLoan.get(entry.ref_id) ?? [];
    rows.push(entry); byLoan.set(entry.ref_id, rows);
  }
  const transactionSize = db.prepare("SELECT COUNT(*) n FROM ledger_entries WHERE tx_id=?");
  let expectedRows = 0;
  let receivable = 0;
  for (const loan of loans) {
    if (!Number.isSafeInteger(loan.principal_cents) || loan.principal_cents <= 0 ||
      !["active", "settled", "prepaid", "refinanced"].includes(loan.status))
      throw new Error("INTEGRITY_LOAN_PRINCIPAL");
    const rows = byLoan.get(loan.id) ?? [];
    const groups = new Map<string, typeof rows>();
    for (const row of rows) {
      if (row.ref_type !== "loan" || row.reverses_tx_id !== null)
        throw new Error("INTEGRITY_LOAN_PRINCIPAL");
      const group = groups.get(row.tx_id) ?? [];
      group.push(row); groups.set(row.tx_id, group);
    }
    const check = (group: typeof rows | undefined, kind: string, amount: number): boolean =>
      group?.length === 2 && (transactionSize.get(group[0]!.tx_id) as { n: number }).n === 2 &&
      group.every((entry) => entry.kind === kind) &&
      group.some((entry) => entry.account_id === fundingId && entry.amount === amount) &&
      group.some((entry) => entry.account_id === loan.account_id && entry.amount === -amount) || false;
    const issued = groups.get(loan.disbursement_tx_id);
    if (!issued || !["loan_disbursement", "flash_loan"].includes(issued[0]!.kind) ||
      !check(issued, issued[0]!.kind, -loan.principal_cents))
      throw new Error("INTEGRITY_LOAN_PRINCIPAL");
    groups.delete(loan.disbursement_tx_id);
    let repaid = 0;
    for (const group of groups.values()) {
      const repayment = group.find((entry) => entry.account_id === fundingId)?.amount;
      if (repayment === undefined || repayment <= 0 ||
        !check(group, "loan_principal_repay", repayment))
        throw new Error("INTEGRITY_LOAN_PRINCIPAL");
      repaid += repayment;
    }
    if (!Number.isSafeInteger(repaid) || repaid > loan.principal_cents ||
      (loan.status === "active" ? repaid >= loan.principal_cents : repaid !== loan.principal_cents))
      throw new Error("INTEGRITY_LOAN_PRINCIPAL");
    expectedRows += 2 + 2 * groups.size;
    receivable -= loan.principal_cents - repaid;
    if (!Number.isSafeInteger(receivable)) throw new Error("INTEGRITY_GL_BALANCE_RANGE");
  }
  if (principal.length !== expectedRows)
    throw new Error("INTEGRITY_LOAN_PRINCIPAL");
  return receivable;
}

export function trialBalance(db: DatabaseSync): TrialBalanceLine[] {
  const unmapped = db.prepare(`SELECT COUNT(*) n FROM accounts a LEFT JOIN gl_accounts g ON
    (a.kind='system' AND
      CASE WHEN a.system_role='attacker_seed' THEN 'cash_in' ELSE a.system_role END=g.system_role)
      OR (a.kind<>'system' AND g.code='2000')
    WHERE g.code IS NULL`).get() as { n: number };
  if (unmapped.n) throw new Error("INTEGRITY_GL_ACCOUNT_UNMAPPED");
  const balances = db.prepare(`SELECT g.code,COALESCE(SUM(a.balance_cached),0) balance_cents
    FROM gl_accounts g LEFT JOIN accounts a ON
    (a.kind='system' AND
      CASE WHEN a.system_role='attacker_seed' THEN 'cash_in' ELSE a.system_role END=g.system_role)
      OR (a.kind<>'system' AND g.code='2000')
    GROUP BY g.code`).all() as { code: string; balance_cents: number }[];
  const byCode = new Map(balances.map((row) => [row.code, row.balance_cents]));
  const feeChart = db.prepare(`SELECT code,nature,system_role FROM gl_accounts
    WHERE code IN ('3000','3010','3020','3030','3040','3050','3060') ORDER BY code`).all() as
    { code: string; nature: string; system_role: string | null }[];
  if (feeChart.length !== 7 || feeChart.some((row) => row.nature !== "revenue" ||
    row.system_role !== (row.code === "3000" ? "fees" :
      row.code === "3050" ? "loan_interest_revenue" : null)))
    throw new Error("INTEGRITY_GL_ACCOUNT_UNMAPPED");
  const feeAccounts = db.prepare("SELECT id FROM accounts WHERE kind='system' AND system_role='fees'")
    .all() as { id: string }[];
  if (feeAccounts.length > 1) throw new Error("INTEGRITY_GL_FEE_ACCOUNT");
  if (feeAccounts[0]) {
    const fees = db.prepare(`SELECT COALESCE(SUM(amount),0) ledger_cents,
      COALESCE(SUM(CASE WHEN kind IN ('service_fee','result_transfer_service_fee') THEN amount ELSE 0 END),0) service_cents,
      COALESCE(SUM(CASE WHEN kind IN ('loan_fee','loan_rebate','result_transfer_loan_fee') THEN amount ELSE 0 END),0) loan_cents,
      COALESCE(SUM(CASE WHEN kind IN ('credit_card_interest','result_transfer_card_interest') THEN amount ELSE 0 END),0) interest_cents,
      COALESCE(SUM(CASE WHEN kind IN ('credit_card_iof','result_transfer_card_iof') THEN amount ELSE 0 END),0) iof_cents,
      COALESCE(SUM(CASE WHEN kind IN ('loan_interest_payment','result_transfer_loan_interest') THEN amount ELSE 0 END),0) loan_interest_cents,
      COALESCE(SUM(CASE WHEN kind IN ('loan_late_fee','loan_mora','result_transfer_loan_late') THEN amount ELSE 0 END),0) loan_late_cents
      FROM ledger_entries WHERE account_id=?`).get(feeAccounts[0].id) as
      { ledger_cents: number; service_cents: number; loan_cents: number;
        interest_cents: number; iof_cents: number; loan_interest_cents: number;
        loan_late_cents: number };
    const physical = byCode.get("3000") ?? 0;
    if (![physical, fees.ledger_cents, fees.service_cents, fees.loan_cents,
      fees.interest_cents, fees.iof_cents, fees.loan_interest_cents,
      fees.loan_late_cents].every(Number.isSafeInteger))
      throw new Error("INTEGRITY_GL_BALANCE_RANGE");
    if (fees.ledger_cents !== physical) throw new Error("INTEGRITY_GL_FEE_ACCOUNT");
    const residual = physical - fees.service_cents - fees.loan_cents -
      fees.interest_cents - fees.iof_cents - fees.loan_interest_cents - fees.loan_late_cents;
    if (![residual, fees.service_cents, fees.loan_cents, fees.interest_cents,
      fees.iof_cents, fees.loan_interest_cents, fees.loan_late_cents].every(Number.isSafeInteger))
      throw new Error("INTEGRITY_GL_BALANCE_RANGE");
    byCode.set("3000", residual);
    byCode.set("3010", fees.service_cents);
    byCode.set("3020", fees.loan_cents);
    byCode.set("3030", fees.interest_cents);
    byCode.set("3040", fees.iof_cents);
    byCode.set("3050", (byCode.get("3050") ?? 0) + fees.loan_interest_cents);
    byCode.set("3060", fees.loan_late_cents);
  }
  const receivable = loanPrincipal(db);
  const loanAccount = db.prepare("SELECT nature,system_role FROM gl_accounts WHERE code='1100'").get() as
    { nature: string; system_role: string | null } | undefined;
  const reserveAccount = db.prepare("SELECT nature,system_role FROM gl_accounts WHERE code='2100'").get() as
    { nature: string; system_role: string | null } | undefined;
  if (!loanAccount || loanAccount.nature !== "asset" || loanAccount.system_role !== null ||
    !reserveAccount || reserveAccount.nature !== "liability" || reserveAccount.system_role !== "loan_funding")
    throw new Error("INTEGRITY_GL_ACCOUNT_UNMAPPED");
  byCode.set("1100", receivable);
  const reserve = (byCode.get("2100") ?? 0) - receivable;
  if (!Number.isSafeInteger(reserve)) throw new Error("INTEGRITY_GL_BALANCE_RANGE");
  byCode.set("2100", reserve);
  const cardAccount = db.prepare("SELECT id FROM accounts WHERE kind='system' AND system_role='card_settlement'")
    .all() as { id: string }[];
  if (cardAccount.length !== 1) throw new Error("INTEGRITY_GL_CARD_ACCOUNT");
  const cardChart = db.prepare(`SELECT code,nature,system_role FROM gl_accounts
    WHERE code IN ('1030','1110','2600') ORDER BY code`).all() as
    { code: string; nature: string; system_role: string | null }[];
  if (cardChart.length !== 3 || cardChart[0]?.code !== "1030" ||
    cardChart[0].nature !== "asset" || cardChart[0].system_role !== "card_settlement" ||
    cardChart[1]?.code !== "1110" || cardChart[1].nature !== "asset" ||
    cardChart[1].system_role !== null || cardChart[2]?.code !== "2600" ||
    cardChart[2].nature !== "liability" || cardChart[2].system_role !== null)
    throw new Error("INTEGRITY_GL_ACCOUNT_UNMAPPED");
  const creditLedger = db.prepare(`SELECT ref_id,COALESCE(SUM(amount),0) total
    FROM ledger_entries WHERE account_id=? AND ref_type='credit_card'
    GROUP BY ref_id`).all(cardAccount[0]!.id) as { ref_id: string; total: number }[];
  const creditTable = db.prepare(`SELECT 1 FROM sqlite_master
    WHERE type='table' AND name='credit_card_accounts'`).get();
  if (creditLedger.length && !creditTable) throw new Error("INTEGRITY_GL_CREDIT_CARD_ORPHAN");
  const creditAccountIds = creditTable ? new Set((db.prepare("SELECT id FROM credit_card_accounts")
    .all() as { id: string }[]).map((row) => row.id)) : new Set<string>();
  let creditReceivable = 0, cardOverpayments = 0, physicalCreditNet = 0;
  for (const row of creditLedger) {
    if (!creditAccountIds.has(row.ref_id) || !Number.isSafeInteger(row.total))
      throw new Error("INTEGRITY_GL_CREDIT_CARD_ORPHAN");
    physicalCreditNet += row.total;
    if (row.total < 0) creditReceivable += row.total;
    else cardOverpayments += row.total;
  }
  if (![creditReceivable, cardOverpayments, physicalCreditNet].every(Number.isSafeInteger))
    throw new Error("INTEGRITY_GL_BALANCE_RANGE");
  const cardSettlement = (byCode.get("1030") ?? 0) - physicalCreditNet;
  if (!Number.isSafeInteger(cardSettlement)) throw new Error("INTEGRITY_GL_BALANCE_RANGE");
  byCode.set("1030", cardSettlement);
  byCode.set("1110", creditReceivable);
  byCode.set("2600", cardOverpayments);
  return (db.prepare("SELECT code,nature,description FROM gl_accounts ORDER BY code").all() as
    Pick<TrialBalanceLine, "code" | "nature" | "description">[]).map((row) => {
    const balance = byCode.get(row.code) ?? 0;
    if (!Number.isSafeInteger(balance)) throw new Error("INTEGRITY_GL_BALANCE_RANGE");
    return { ...row, balance_cents: balance,
      debit_cents: Math.max(0, -balance), credit_cents: Math.max(0, balance) };
  });
}

export const PERIOD_CUTOFF_POLICY_VERSION = 2;

export function trialBalanceAtDate(db: DatabaseSync, asOfDate: string): {
  lines: TrialBalanceLine[]; ledger_entries_count: number; ledger_sum: number;
} {
  const parsedDate = new Date(`${asOfDate}T12:00:00.000Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(asOfDate) ||
    !Number.isFinite(parsedDate.getTime()) ||
    parsedDate.toISOString().slice(0, 10) !== asOfDate)
    throw new Error("PERIOD_CUTOFF_DATE_INVALID");
  // Validate the complete current book before projecting a historical subset.
  trialBalance(db);
  const selected = `SELECT e.* FROM ledger_entries e JOIN ledger_accounting_view d ON d.id=e.id
    WHERE COALESCE(d.posting_date,
      json_extract(accounting_dates_v1(e.created_at),'$.posting_date'))<=?
      OR (e.kind IN ('loan_provision','loan_interest_accrual') AND d.value_date<=?)`;
  const query = (sql: string) => db.prepare(`WITH selected_entries AS (${selected}) ${sql}`);
  const scoped = [asOfDate, asOfDate];
  const summary = query(`SELECT COUNT(*) n,COALESCE(SUM(amount),0) total
    FROM selected_entries`).get(...scoped) as { n: number; total: number };
  if (summary.total !== 0 || !Number.isSafeInteger(summary.total) ||
    !Number.isSafeInteger(summary.n))
    throw new Error("INTEGRITY_PERIOD_CUTOFF_UNBALANCED");
  const accounts = query(`SELECT g.code,COALESCE(SUM(e.amount),0) balance_cents
    FROM selected_entries e JOIN accounts a ON a.id=e.account_id
    JOIN gl_accounts g ON (a.kind='system' AND
      CASE WHEN a.system_role='attacker_seed' THEN 'cash_in' ELSE a.system_role END=g.system_role)
      OR (a.kind<>'system' AND g.code='2000')
    GROUP BY g.code`).all(...scoped) as { code: string; balance_cents: number }[];
  const byCode = new Map(accounts.map((row) => [row.code, row.balance_cents]));
  const fees = query(`SELECT e.kind,COALESCE(SUM(e.amount),0) amount
    FROM selected_entries e JOIN accounts a ON a.id=e.account_id
    WHERE a.kind='system' AND a.system_role='fees' GROUP BY e.kind`)
    .all(...scoped) as { kind: string; amount: number }[];
  const feeKinds = new Map(fees.map((row) => [row.kind, row.amount]));
  const feeBuckets: [string, string[]][] = [
    ["3010", ["service_fee", "result_transfer_service_fee"]],
    ["3020", ["loan_fee", "loan_rebate", "result_transfer_loan_fee"]],
    ["3030", ["credit_card_interest", "result_transfer_card_interest"]],
    ["3040", ["credit_card_iof", "result_transfer_card_iof"]],
    ["3050", ["loan_interest_payment", "result_transfer_loan_interest"]],
    ["3060", ["loan_late_fee", "loan_mora", "result_transfer_loan_late"]],
  ];
  let assignedFees = 0;
  for (const [code, kinds] of feeBuckets) {
    const amount = kinds.reduce((sum, kind) => sum + (feeKinds.get(kind) ?? 0), 0);
    byCode.set(code, (byCode.get(code) ?? 0) + amount); assignedFees += amount;
  }
  byCode.set("3000", (byCode.get("3000") ?? 0) - assignedFees);
  const principal = query(`SELECT COALESCE(SUM(e.amount),0) amount FROM selected_entries e
    JOIN accounts a ON a.id=e.account_id WHERE a.kind='system'
      AND a.system_role='loan_funding' AND e.ref_type='loan'
      AND e.kind IN ('loan_disbursement','flash_loan','loan_principal_repay')`)
    .get(...scoped) as { amount: number };
  byCode.set("1100", principal.amount);
  byCode.set("2100", (byCode.get("2100") ?? 0) - principal.amount);
  const credit = query(`SELECT e.ref_id,COALESCE(SUM(e.amount),0) amount
    FROM selected_entries e JOIN accounts a ON a.id=e.account_id
    WHERE a.kind='system' AND a.system_role='card_settlement'
      AND e.ref_type='credit_card' GROUP BY e.ref_id`)
    .all(...scoped) as { ref_id: string; amount: number }[];
  const creditNet = credit.reduce((sum, row) => sum + row.amount, 0);
  byCode.set("1030", (byCode.get("1030") ?? 0) - creditNet);
  byCode.set("1110", credit.reduce((sum, row) => sum + Math.min(row.amount, 0), 0));
  byCode.set("2600", credit.reduce((sum, row) => sum + Math.max(row.amount, 0), 0));
  const lines = (db.prepare("SELECT code,nature,description FROM gl_accounts ORDER BY code")
    .all() as Pick<TrialBalanceLine, "code" | "nature" | "description">[]).map((row) => {
    const balance = byCode.get(row.code) ?? 0;
    if (!Number.isSafeInteger(balance)) throw new Error("INTEGRITY_GL_BALANCE_RANGE");
    return { ...row, balance_cents: balance,
      debit_cents: Math.max(0, -balance), credit_cents: Math.max(0, balance) };
  });
  return { lines, ledger_entries_count: summary.n, ledger_sum: summary.total };
}
