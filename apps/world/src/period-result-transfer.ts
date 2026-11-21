import type { DatabaseSync } from "node:sqlite";
import type { Bank } from "./bank.ts";
import type { TrialBalanceLine } from "./trial-balance.ts";

interface TransferPosting {
  accountId: string; amount: number; kind: string;
}

const feeBuckets = [
  ["3000", "result_transfer_other_fee"],
  ["3010", "result_transfer_service_fee"],
  ["3020", "result_transfer_loan_fee"],
  ["3030", "result_transfer_card_interest"],
  ["3040", "result_transfer_card_iof"],
  ["3050", "result_transfer_loan_interest"],
  ["3060", "result_transfer_loan_late"],
] as const;

export function installPeriodResultTransfers(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS period_result_transfers (
    brt_date TEXT PRIMARY KEY REFERENCES period_closes(brt_date),
    ledger_tx_id TEXT UNIQUE, net_income_cents INTEGER NOT NULL,
    postings_json TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TRIGGER IF NOT EXISTS period_result_transfers_no_update
    BEFORE UPDATE ON period_result_transfers
    BEGIN SELECT RAISE(ABORT,'PERIOD_RESULT_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS period_result_transfers_no_delete
    BEFORE DELETE ON period_result_transfers
    BEGIN SELECT RAISE(ABORT,'PERIOD_RESULT_IMMUTABLE'); END;`);
}

function accruedInterestIncomeAtDate(db: DatabaseSync, date: string): number {
  const row = db.prepare(`SELECT COALESCE(SUM(e.amount),0) amount
    FROM ledger_entries e JOIN accounts a ON a.id=e.account_id
    JOIN ledger_accounting_view d ON d.id=e.id
    WHERE a.kind='system' AND a.system_role='loan_interest_revenue'
      AND (COALESCE(d.posting_date,
        json_extract(accounting_dates_v1(e.created_at),'$.posting_date'))<=?
        OR (e.kind='loan_interest_accrual' AND d.value_date<=?))`)
    .get(date, date) as { amount: number };
  if (!Number.isSafeInteger(row.amount)) throw new Error("INTEGRITY_PERIOD_RESULT_RANGE");
  return row.amount;
}

function pnlNet(lines: readonly TrialBalanceLine[]): number {
  const net = lines.filter((line) => line.nature === "revenue" ||
    line.nature === "expense").reduce((sum, line) => sum + line.balance_cents, 0);
  if (!Number.isSafeInteger(net)) throw new Error("INTEGRITY_PERIOD_RESULT_RANGE");
  return net;
}

export function recordPeriodResultTransfer(bank: Bank, date: string,
  lines: readonly TrialBalanceLine[]): void {
  const byCode = new Map(lines.map((line) => [line.code, line.balance_cents]));
  const fees = bank.systemAccountId("fees");
  const postings: TransferPosting[] = [];
  const add = (accountId: string, amount: number, kind: string) => {
    if (!Number.isSafeInteger(amount)) throw new Error("INTEGRITY_PERIOD_RESULT_RANGE");
    if (amount) postings.push({ accountId, amount, kind });
  };
  const accrualIncome = accruedInterestIncomeAtDate(bank.db, date);
  for (const [code, kind] of feeBuckets) {
    const balance = byCode.get(code) ?? 0;
    add(fees, -(code === "3050" ? balance - accrualIncome : balance), kind);
  }
  add(bank.systemAccountId("loan_interest_revenue"), -accrualIncome,
    "result_transfer_loan_interest");
  for (const [code, role, kind] of [
    ["3900", "rounding", "result_transfer_rounding"],
    ["4000", "bank_loss", "result_transfer_operational_loss"],
    ["4010", "loan_provision_expense", "result_transfer_loan_provision"],
  ] as const)
    add(bank.systemAccountId(role), -(byCode.get(code) ?? 0), kind);
  const net = pnlNet(lines);
  add(bank.systemAccountId("retained_earnings"), net, "result_transfer_retained");
  if (!Number.isSafeInteger(postings.reduce((sum, row) => sum + row.amount, 0)) ||
    postings.reduce((sum, row) => sum + row.amount, 0) !== 0)
    throw new Error("INTEGRITY_PERIOD_RESULT_UNBALANCED");
  const txId = postings.length ? bank.post(postings.map((row) => ({ ...row,
    actor: "result_transfer_engine", refType: "period_close", refId: date }))) : null;
  bank.db.prepare(`INSERT INTO period_result_transfers VALUES (?,?,?,?,?)`)
    .run(date, txId, net, JSON.stringify(postings), bank.now().toISOString());
}

export function reconcilePeriodResultTransfers(db: DatabaseSync): boolean {
  const hasTable = db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='period_result_transfers'`).get();
  if (!hasTable) return true;
  const closes = db.prepare(`SELECT brt_date,chart_version FROM period_closes`)
    .all() as { brt_date: string; chart_version: number }[];
  const rows = db.prepare(`SELECT brt_date,ledger_tx_id,net_income_cents,postings_json
    FROM period_result_transfers`).all() as unknown as {
      brt_date: string; ledger_tx_id: string | null;
      net_income_cents: number; postings_json: string;
    }[];
  const closeDates = new Set(closes.map((close) => close.brt_date));
  const transferDates = new Set(rows.map((row) => row.brt_date));
  if (closes.some((close) => close.chart_version >= 8 &&
    !transferDates.has(close.brt_date))) return false;
  const expectedTransactions = new Set<string>();
  for (const row of rows) {
    if (!closeDates.has(row.brt_date) || !Number.isSafeInteger(row.net_income_cents))
      return false;
    let postings: unknown;
    let lines: unknown;
    try {
      postings = JSON.parse(row.postings_json);
      const snapshot = db.prepare(`SELECT lines_json FROM period_trial_balances
        WHERE brt_date=?`).get(row.brt_date) as { lines_json: string } | undefined;
      if (!snapshot) return false;
      lines = JSON.parse(snapshot.lines_json);
    } catch { return false; }
    if (!Array.isArray(postings) || !Array.isArray(lines) ||
      postings.some((item) => !item || typeof item !== "object" ||
        !Number.isSafeInteger(item.amount) || item.amount === 0 ||
        typeof item.accountId !== "string" || typeof item.kind !== "string" ||
        !/^result_transfer_/.test(item.kind)) ||
      lines.some((item) => !item || typeof item !== "object" ||
        typeof item.nature !== "string" || !Number.isSafeInteger(item.balance_cents)))
      return false;
    const typedPostings = postings as TransferPosting[];
    const typedLines = lines as TrialBalanceLine[];
    if (pnlNet(typedLines) !== row.net_income_cents ||
      !Number.isSafeInteger(typedPostings.reduce((sum, item) => sum + item.amount, 0)) ||
      typedPostings.reduce((sum, item) => sum + item.amount, 0) !== 0 ||
      typedPostings.filter((item) => item.kind === "result_transfer_retained").length !==
        Number(row.net_income_cents !== 0) ||
      (row.net_income_cents !== 0 && !typedPostings.some((item) =>
        item.kind === "result_transfer_retained" &&
        item.amount === row.net_income_cents))) return false;
    if (!row.ledger_tx_id) {
      if (typedPostings.length) return false;
      continue;
    }
    if (!typedPostings.length || expectedTransactions.has(row.ledger_tx_id)) return false;
    expectedTransactions.add(row.ledger_tx_id);
    const actual = db.prepare(`SELECT e.account_id,e.amount,e.kind,e.actor,e.ref_type,e.ref_id,
      e.reverses_tx_id,d.posting_date,d.value_date FROM ledger_entries e
      JOIN ledger_accounting_view d ON d.id=e.id WHERE e.tx_id=? ORDER BY e.rowid`)
      .all(row.ledger_tx_id) as unknown as {
        account_id: string; amount: number; kind: string; actor: string;
        ref_type: string; ref_id: string; reverses_tx_id: string | null;
        posting_date: string; value_date: string;
      }[];
    if (actual.length !== typedPostings.length || actual.some((entry, index) =>
      entry.account_id !== typedPostings[index]!.accountId ||
      entry.amount !== typedPostings[index]!.amount || entry.kind !== typedPostings[index]!.kind ||
      entry.actor !== "result_transfer_engine" || entry.ref_type !== "period_close" ||
      entry.ref_id !== row.brt_date || entry.reverses_tx_id !== null ||
      entry.posting_date <= row.brt_date || entry.value_date !== entry.posting_date))
      return false;
  }
  const posted = db.prepare(`SELECT DISTINCT tx_id FROM ledger_entries
    WHERE kind GLOB 'result_transfer_*'`).all() as { tx_id: string }[];
  return posted.length === expectedTransactions.size &&
    posted.every((row) => expectedTransactions.has(row.tx_id));
}
