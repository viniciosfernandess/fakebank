import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Bank } from "../apps/world/src/bank.ts";
import { installChartOfAccounts } from "../apps/world/src/trial-balance.ts";
import { LoansEngine } from "../apps/world/src/loans.ts";
import { FeePolicy } from "../apps/world/src/fees.ts";
import { FeatureRegistry } from "../apps/world/src/features.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { seedBank } from "../apps/world/src/seed.ts";

test("seeded paid-in capital is backed by cash and reported as equity", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-equity-capital-"));
  let now = new Date("2026-11-10T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const capital = bank.systemAccountId("equity_capital");
    const entries = bank.db.prepare(`SELECT account_id,amount FROM ledger_entries
      WHERE kind='seed_capital' ORDER BY amount`).all()
      .map(({ account_id, amount }) => ({ account_id, amount }));
    assert.deepEqual(entries, [
      { account_id: bank.systemAccountId("cash_in"), amount: -100_000_000 },
      { account_id: capital, amount: 100_000_000 },
    ]);
    const lines = bank.trialBalance();
    assert.deepEqual(lines.find((line) => line.code === "2900"), {
      code: "2900", description: "Paid-in synthetic capital", nature: "equity",
      balance_cents: 100_000_000, debit_cents: 0, credit_cents: 100_000_000,
    });
    assert.equal(lines.reduce((sum, line) => sum + line.balance_cents, 0), 0);
    now = new Date("2026-11-11T06:00:00Z");
    const close = bank.periodClose();
    const stored = bank.db.prepare(`SELECT lines_json,debit_cents,credit_cents
      FROM period_trial_balances WHERE brt_date=?`).get(close.brt_date);
    assert.equal(JSON.parse(stored.lines_json).find((line) => line.code === "2900")
      .credit_cents, 100_000_000);
    assert.equal(stored.debit_cents, stored.credit_cents);
    assert.equal(bank.db.prepare(`SELECT chart_version FROM period_closes
      WHERE brt_date=?`).get(close.brt_date).chart_version, 8);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("old chart constraint migrates to equity without rewriting an earlier snapshot", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(`CREATE TABLE gl_accounts (
      code TEXT PRIMARY KEY,
      nature TEXT NOT NULL CHECK(nature IN ('asset','liability','revenue','expense')),
      description TEXT NOT NULL, system_role TEXT UNIQUE
    );
    INSERT INTO gl_accounts VALUES ('1000','asset','Cash funding source','cash_in');
    INSERT INTO gl_accounts VALUES ('3050','revenue','Loan interest income',NULL);
    CREATE TABLE period_closes (brt_date TEXT PRIMARY KEY);
    INSERT INTO period_closes VALUES ('2026-11-10');
    CREATE TABLE period_trial_balances (
      brt_date TEXT PRIMARY KEY REFERENCES period_closes(brt_date),
      lines_json TEXT NOT NULL, debit_cents INTEGER NOT NULL, credit_cents INTEGER NOT NULL
    );
    INSERT INTO period_trial_balances VALUES ('2026-11-10','[{"code":"1000"}]',1,1);`);
    const oldSnapshot = db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date='2026-11-10'`).get().lines_json;
    installChartOfAccounts(db);
    installChartOfAccounts(db);
    assert.deepEqual({ ...db.prepare(`SELECT nature,system_role FROM gl_accounts
      WHERE code='2900'`).get() }, { nature: "equity", system_role: "equity_capital" });
    assert.equal(db.prepare(`SELECT system_role FROM gl_accounts WHERE code='3050'`)
      .get().system_role, "loan_interest_revenue");
    assert.equal(db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date='2026-11-10'`).get().lines_json, oldSnapshot);
    assert.throws(() => db.prepare(`UPDATE period_trial_balances SET lines_json='[]'
      WHERE brt_date='2026-11-10'`).run(), /PERIOD_TRIAL_IMMUTABLE/);
  } finally { db.close(); }
});

test("daily close stores a balanced account-level trial balance", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-trial-balance-"));
  let now = new Date("2026-11-10T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 3, accounts: 4, historyTransactions: 10 });
    const lines = bank.trialBalance();
    const deposits = lines.find((line) => line.code === "2000");
    assert.equal(deposits?.nature, "liability");
    assert.ok(deposits.credit_cents > 0);
    assert.equal(lines.reduce((sum, line) => sum + line.balance_cents, 0), 0);
    const entriesBeforeCutoff = bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n;
    now = new Date("2026-11-11T04:30:00.000Z");
    bank.post([
      { accountId: bank.systemAccountId("cash_in"), amount: -1_000,
        kind: "cash_in", actor: "test", refType: "test", refId: "after-cutoff" },
      { accountId: seedAccountId(1), amount: 1_000,
        kind: "cash_in", actor: "test", refType: "test", refId: "after-cutoff" },
    ]);
    assert.notDeepEqual(bank.trialBalance(), lines);
    now = new Date("2026-11-11T06:30:00.000Z");
    const closed = bank.periodClose();
    assert.equal(closed.brt_date, "2026-11-10");
    assert.equal(closed.ledger_entries_count, entriesBeforeCutoff);
    assert.equal(bank.db.prepare(`SELECT cutoff_policy_version FROM period_closes
      WHERE brt_date=?`).get(closed.brt_date).cutoff_policy_version, 2);
    const stored = bank.db.prepare("SELECT * FROM period_trial_balances WHERE brt_date=?")
      .get(closed.brt_date);
    assert.deepEqual(JSON.parse(stored.lines_json), lines);
    assert.equal(stored.debit_cents, stored.credit_cents);
    assert.equal(bank.periodClose().brt_date, closed.brt_date);
    assert.throws(() => bank.db.prepare(`UPDATE period_trial_balances
      SET lines_json='[]' WHERE brt_date=?`).run(closed.brt_date), /PERIOD_TRIAL_IMMUTABLE/);
    bank.db.prepare("UPDATE spi_participants SET pi_balance_cents=pi_balance_cents+1 WHERE ispb='12345678'").run();
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
    bank.db.prepare("UPDATE spi_participants SET pi_balance_cents=pi_balance_cents-1 WHERE ispb='12345678'").run();
    bank.db.prepare("UPDATE psp_accounts SET balance_cents=balance_cents+1 WHERE id='psp_ipe_ana'").run();
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
    bank.db.prepare("UPDATE psp_accounts SET balance_cents=balance_cents-1 WHERE id='psp_ipe_ana'").run();
    assert.equal(bank.periodClose().brt_date, closed.brt_date);
    bank.db.exec("DROP TRIGGER ledger_entries_no_update");
    bank.db.prepare("UPDATE ledger_entries SET kind='tampered' WHERE rowid=(SELECT MIN(rowid) FROM ledger_entries)").run();
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("legacy synthetic funding is mapped to cash-in without rewriting ledger or closed snapshots", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-legacy-funding-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-11T06:30:00Z");
  let bank = new Bank(path, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM accounts
      WHERE system_role='attacker_seed'`).get().n, 0);
    const prior = bank.periodClose();
    const snapshot = bank.db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date=?`).get(prior.brt_date).lines_json;
    bank.db.exec("DROP TABLE period_close_seals");
    bank.db.prepare("UPDATE period_closes SET chart_version=4 WHERE brt_date=?")
      .run(prior.brt_date);
    bank.db.prepare(`INSERT INTO accounts
      (id,customer_id,kind,system_role,balance_cached,overdraft_limit,status,opened_at,
       branch_code,account_number,account_digit)
      VALUES ('sys_legacy_funding',NULL,'system','attacker_seed',0,0,'active',?,NULL,NULL,NULL)`)
      .run(now.toISOString());
    now = new Date("2026-11-11T12:00:00Z");
    bank.post([
      { accountId: "sys_legacy_funding", amount: -25_000,
        kind: "funding", actor: "legacy", refType: "funding", refId: seedAccountId(1) },
      { accountId: seedAccountId(1), amount: 25_000,
        kind: "funding", actor: "legacy", refType: "funding", refId: seedAccountId(1) },
    ]);
    const cashBefore = bank.account(bank.systemAccountId("cash_in")).balance_cached;
    bank.db.prepare("INSERT INTO gl_accounts VALUES ('2500','liability','Synthetic actor funding','attacker_seed')")
      .run();
    bank.close();
    bank = new Bank(path, () => now);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM gl_accounts WHERE code='2500'").get().n, 0);
    assert.equal(bank.db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date=?`).get(prior.brt_date).lines_json, snapshot);
    assert.equal(bank.account("sys_legacy_funding").balance_cached, -25_000);
    assert.equal(bank.trialBalance().find((line) => line.code === "1000").balance_cents,
      cashBefore - 25_000);
    assert.equal(bank.trialBalance().some((line) => line.code === "2500"), false);
    assert.equal(bank.verifyLedgerChain(), true);
    now = new Date("2026-11-12T06:30:00Z");
    const next = bank.periodClose();
    const lines = JSON.parse(bank.db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date=?`).get(next.brt_date).lines_json);
    assert.equal(lines.find((line) => line.code === "1000").balance_cents, cashBefore - 25_000);
    assert.equal(lines.some((line) => line.code === "2500"), false);
    assert.equal(lines.reduce((sum, line) => sum + line.balance_cents, 0), 0);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});


test("loan principal is an asset while the funding reserve and closed snapshots remain intact", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-trial-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-11T06:30:00.000Z");
  let bank = new Bank(path, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    let loans = new LoansEngine(bank);
    const customer = seedCustomerId(1); const account = seedAccountId(1);
    const priorClose = bank.periodClose();
    const snapshot = bank.db.prepare("SELECT lines_json FROM period_trial_balances WHERE brt_date=?")
      .get(priorClose.brt_date).lines_json;
    const physical = bank.account(bank.systemAccountId("loan_funding")).balance_cached;
    const offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, account, 100_000);
    let lines = bank.trialBalance();
    assert.equal(lines.find((line) => line.code === "1100").balance_cents, -100_000);
    assert.equal(lines.find((line) => line.code === "1100").nature, "asset");
    assert.equal(lines.find((line) => line.code === "2100").balance_cents, physical);
    assert.equal(lines.reduce((n, line) => n + line.debit_cents - line.credit_cents, 0), 0);
    assert.equal(bank.account(bank.systemAccountId("loan_funding")).balance_cached, physical - 100_000);
    bank.close();
    bank = new Bank(path, () => now);
    loans = new LoansEngine(bank);
    assert.equal(bank.trialBalance().find((line) => line.code === "1100").debit_cents, 100_000);
    assert.equal(bank.db.prepare("SELECT lines_json FROM period_trial_balances WHERE brt_date=?")
      .get(priorClose.brt_date).lines_json, snapshot);
    now = new Date("2026-11-12T06:30:00.000Z");
    const activeClose = bank.periodClose();
    const activeSnapshot = JSON.parse(bank.db.prepare("SELECT lines_json FROM period_trial_balances WHERE brt_date=?")
      .get(activeClose.brt_date).lines_json);
    assert.equal(activeSnapshot.find((line) => line.code === "1100").debit_cents, 100_000);
    loans.prepay(customer, loan.id);
    lines = bank.trialBalance();
    assert.equal(lines.find((line) => line.code === "1100").balance_cents, 0);
    assert.equal(lines.find((line) => line.code === "2100").balance_cents, physical);
    now = new Date("2026-11-13T06:30:00.000Z");
    const close = bank.periodClose();
    const saved = bank.db.prepare("SELECT debit_cents,credit_cents FROM period_trial_balances WHERE brt_date=?")
      .get(close.brt_date);
    assert.equal(saved.debit_cents, saved.credit_cents);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("flash principal is classified and malformed loan references fail closed", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-flash-trial-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-11T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank); const customer = seedCustomerId(1);
    new FeatureRegistry(bank).setEnabled("emprestimo_relampago", true, "test");
    const establishedAt = "2026-11-09T09:00:00.000Z";
    bank.db.prepare(`INSERT INTO auth_devices
      (id,customer_id,fingerprint,first_seen_at,bound_at,first_seen_ip,trusted_at)
      VALUES (?,?,?,?,?,'127.0.0.1',?)`).run("established", customer, "test-fingerprint",
      establishedAt, establishedAt, establishedAt);
    const loan = loans.acceptFlash(customer, seedAccountId(1), "established", 50_000);
    assert.equal(bank.trialBalance().find((line) => line.code === "1100").debit_cents, 50_000);
    bank.db.prepare("UPDATE loans SET principal_cents=principal_cents+1 WHERE id=?").run(loan.id);
    assert.throws(() => bank.trialBalance(), /INTEGRITY_LOAN_PRINCIPAL/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("service and loan fee subaccounts conserve the physical fee balance at close", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-fee-trial-"));
  let now = new Date("2026-11-11T06:30:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1), account = seedAccountId(1);
    const charged = new FeePolicy(bank).charge(account, 10_000, 100, customer);
    const loans = new LoansEngine(bank);
    const offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, account, 100_000);
    now = new Date("2026-11-25T06:30:00.000Z");
    const rebate = loans.prepay(customer, loan.id).rebate_cents;
    const lines = bank.trialBalance();
    const line = (code) => lines.find((item) => item.code === code);
    assert.equal(line("3010").balance_cents, charged.nominal_cents);
    assert.equal(line("3020").balance_cents, loan.fee_cents - rebate);
    assert.equal(line("3000").balance_cents, 0);
    assert.equal(line("3010").nature, "revenue");
    assert.equal(line("3020").nature, "revenue");
    assert.equal(line("3000").balance_cents + line("3010").balance_cents + line("3020").balance_cents,
      bank.account(bank.systemAccountId("fees")).balance_cached);
    assert.equal(lines.reduce((sum, item) => sum + item.balance_cents, 0), 0);
    const closed = bank.periodClose();
    const saved = bank.db.prepare("SELECT lines_json,debit_cents,credit_cents FROM period_trial_balances WHERE brt_date=?")
      .get(closed.brt_date);
    const closedLines = bank.trialBalance();
    const snapshotLines = JSON.parse(saved.lines_json);
    assert.notDeepEqual(snapshotLines, closedLines);
    assert.equal(snapshotLines.find((item) => item.code === "1100").debit_cents, 100_000);
    assert.equal(closedLines.find((item) => item.code === "3010").balance_cents, 0);
    assert.equal(snapshotLines.find((item) => item.code === "3010").balance_cents,
      line("3010").balance_cents);
    assert.equal(snapshotLines.find((item) => item.code === "3020").balance_cents,
      loan.fee_cents);
    assert.ok(snapshotLines.find((item) => item.code === "4010").debit_cents > 0);
    assert.equal(saved.debit_cents, saved.credit_cents);
    assert.equal(bank.reconcile().ok, true);
    bank.db.prepare("UPDATE accounts SET balance_cached=balance_cached+1 WHERE id=?")
      .run(bank.systemAccountId("fees"));
    assert.throws(() => bank.trialBalance(), /INTEGRITY_GL_FEE_ACCOUNT/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
