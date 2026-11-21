import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Bank } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId } from "../apps/world/src/id.ts";
import { accountingDates, withAccountingValueDate } from "../apps/world/src/accounting-dates.ts";

test("accounting dates use the simulated São Paulo calendar", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-accounting-dates-"));
  let now = new Date("2026-11-14T02:30:00.000Z"); // Friday 23:30 in São Paulo.
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const account = seedAccountId(1);
    const friday = bank.fund(account, 100);
    now = new Date("2026-11-14T13:00:00.000Z"); // Saturday 10:00.
    const saturday = bank.fund(account, 200);
    now = new Date("2026-11-16T13:00:00.000Z"); // Monday 10:00.
    const monday = bank.fund(account, 300);
    const dateFor = (txId) => bank.db.prepare(`SELECT DISTINCT posting_date,value_date,business_date,
      policy_version,provenance FROM ledger_accounting_view WHERE tx_id=?`).all(txId).map((row) => ({ ...row }));
    assert.deepEqual(dateFor(friday), [{ posting_date: "2026-11-13", value_date: "2026-11-13",
      business_date: "2026-11-13", policy_version: 2, provenance: "recorded" }]);
    assert.deepEqual(dateFor(saturday), [{ posting_date: "2026-11-14", value_date: "2026-11-14",
      business_date: "2026-11-16", policy_version: 2, provenance: "recorded" }]);
    assert.deepEqual(dateFor(monday), [{ posting_date: "2026-11-16", value_date: "2026-11-16",
      business_date: "2026-11-16", policy_version: 2, provenance: "recorded" }]);
    now = new Date("2026-11-17T06:30:00.000Z");
    const close = bank.periodClose();
    assert.equal(bank.db.prepare("SELECT chart_version FROM period_closes WHERE brt_date=?")
      .get(close.brt_date).chart_version, 8);
    assert.equal(bank.db.prepare("SELECT calendar_version FROM period_closes WHERE brt_date=?")
      .get(close.brt_date).calendar_version, 2);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.verifyLedgerChain(), true);
    const entry = bank.db.prepare("SELECT entry_id FROM ledger_accounting_dates LIMIT 1").get();
    assert.throws(() => bank.db.prepare("UPDATE ledger_accounting_dates SET dates_json='{}' WHERE entry_id=?")
      .run(entry.entry_id), /ACCOUNTING_DATES_IMMUTABLE/);
    bank.db.exec("DROP TRIGGER ledger_accounting_dates_no_update");
    bank.db.prepare("UPDATE ledger_accounting_dates SET dates_json='{}' WHERE entry_id=?")
      .run(entry.entry_id);
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("older entries retain unknown value-date provenance and a missing new date blocks close", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-accounting-migrate-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-11T06:30:00.000Z");
  let bank = new Bank(path, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const prior = bank.periodClose();
    const priorLines = bank.db.prepare("SELECT lines_json FROM period_trial_balances WHERE brt_date=?")
      .get(prior.brt_date).lines_json;
    bank.close();
    const old = new DatabaseSync(path);
    try {
      old.exec("DROP TABLE period_close_seals");
      old.exec(`DROP VIEW ledger_accounting_view;
        DROP TRIGGER ledger_accounting_dates_insert;
        DROP TRIGGER ledger_accounting_dates_no_update;
        DROP TRIGGER ledger_accounting_dates_no_delete;
        DROP TRIGGER accounting_activation_no_update;
        DROP TRIGGER accounting_activation_no_delete;
        DROP TABLE ledger_accounting_dates;
        DROP TABLE accounting_activation;`);
      old.exec("ALTER TABLE period_closes DROP COLUMN chart_version");
      old.exec("ALTER TABLE period_closes DROP COLUMN calendar_version");
    } finally { old.close(); }
    now = new Date("2026-11-12T06:30:00.000Z");
    bank = new Bank(path, () => now);
    assert.deepEqual({ ...bank.db.prepare("SELECT chart_version,calendar_version FROM period_closes WHERE brt_date=?")
      .get(prior.brt_date) }, { chart_version: 1, calendar_version: 0 });
    assert.equal(bank.db.prepare("SELECT lines_json FROM period_trial_balances WHERE brt_date=?")
      .get(prior.brt_date).lines_json, priorLines);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM ledger_accounting_view WHERE provenance='legacy_unknown'")
      .get().n > 0, true);
    const tx = bank.fund(seedAccountId(1), 100);
    const newDates = bank.db.prepare("SELECT DISTINCT provenance,policy_version FROM ledger_accounting_view WHERE tx_id=?")
      .all(tx).map((row) => ({ ...row }));
    assert.deepEqual(newDates, [{ provenance: "recorded", policy_version: 2 }]);
    bank.db.exec("DROP TRIGGER ledger_accounting_dates_insert");
    bank.fund(seedAccountId(1), 100);
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("calendar v2 advances across national and bank holidays", () => {
  const cases = [
    ["2026-02-16", "2026-02-18"], // Carnival Monday.
    ["2026-02-17", "2026-02-18"], // Carnival Tuesday.
    ["2026-04-03", "2026-04-06"], // Good Friday.
    ["2026-04-21", "2026-04-22"], // Tiradentes.
    ["2026-06-04", "2026-06-05"], // Corpus Christi.
    ["2026-11-20", "2026-11-23"], // National Consciousness Day.
    ["2026-12-25", "2026-12-28"], // Christmas.
    ["2026-12-31", "2026-12-31"], // Not a national bank-market holiday.
    ["2027-01-01", "2027-01-04"], // Year boundary.
  ];
  for (const [date, expected] of cases) {
    assert.equal(accountingDates(`${date}T15:00:00.000Z`).business_date, expected, date);
  }
});

test("value date may differ from posting date and context is cleared after failure", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-value-date-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-19T15:00:00.000Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const account = seedAccountId(1);
    const tx = withAccountingValueDate(bank.db, "2026-11-20", () => bank.fund(account, 100));
    const dates = bank.db.prepare(`SELECT DISTINCT posting_date,value_date,business_date,policy_version
      FROM ledger_accounting_view WHERE tx_id=?`).all(tx).map((row) => ({ ...row }));
    assert.deepEqual(dates, [{ posting_date: "2026-11-19", value_date: "2026-11-20",
      business_date: "2026-11-23", policy_version: 2 }]);
    assert.throws(() => withAccountingValueDate(bank.db, "2026-02-30", () => bank.fund(account, 1)),
      /ACCOUNTING_VALUE_DATE_INVALID/);
    assert.throws(() => withAccountingValueDate(bank.db, "2026-11-21", () => {
      throw new Error("rollback context");
    }), /rollback context/);
    const next = bank.fund(account, 100);
    assert.equal(bank.db.prepare(`SELECT DISTINCT value_date FROM ledger_accounting_view WHERE tx_id=?`)
      .get(next).value_date, "2026-11-19");
    const explicit = bank.post([
      { accountId: bank.systemAccountId("cash_in"), amount: -100, kind: "cash_in",
        actor: "test", refType: "test", refId: "value-date" },
      { accountId: account, amount: 100, kind: "cash_in",
        actor: "test", refType: "test", refId: "value-date" },
    ], undefined, "2026-11-20");
    assert.deepEqual(bank.db.prepare(`SELECT DISTINCT posting_date,value_date,business_date
      FROM ledger_accounting_view WHERE tx_id=?`).all(explicit).map((row) => ({ ...row })),
      [{ posting_date: "2026-11-19", value_date: "2026-11-20",
        business_date: "2026-11-23" }]);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("upgrading a v1 calendar preserves recorded rows and begins v2 only for new entries", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-accounting-v1-upgrade-"));
  const path = join(dir, "bank.sqlite");
  let bank = new Bank(path, () => new Date("2026-04-03T15:00:00.000Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const original = bank.fund(seedAccountId(1), 100);
    bank.close();
    const old = new DatabaseSync(path);
    try {
      old.exec(`DROP VIEW ledger_accounting_view;
        DROP TRIGGER ledger_accounting_dates_insert;
        DROP TRIGGER ledger_accounting_dates_no_update;
        DROP TRIGGER ledger_accounting_dates_no_delete;
        CREATE TABLE old_dates (
          entry_id TEXT PRIMARY KEY REFERENCES ledger_entries(id),
          policy_version INTEGER NOT NULL CHECK(policy_version=1),
          dates_json TEXT NOT NULL CHECK(json_valid(dates_json))
        );
        INSERT INTO old_dates(entry_id,policy_version,dates_json)
        SELECT d.entry_id,1,json_object(
          'posting_date',json_extract(d.dates_json,'$.posting_date'),
          'value_date',json_extract(d.dates_json,'$.posting_date'),
          'business_date',json_extract(d.dates_json,'$.posting_date'))
        FROM ledger_accounting_dates d;`);
      old.exec(`DROP TABLE ledger_accounting_dates;
        ALTER TABLE old_dates RENAME TO ledger_accounting_dates;`);
      const before = old.prepare(`SELECT group_concat(dates_json,'|') AS bytes
        FROM ledger_accounting_dates WHERE entry_id IN
        (SELECT id FROM ledger_entries WHERE tx_id=?)`).get(original).bytes;
      old.close();
      bank = new Bank(path, () => new Date("2026-04-03T15:00:00.000Z"));
      const legacy = bank.db.prepare(`SELECT DISTINCT policy_version,business_date
        FROM ledger_accounting_view WHERE tx_id=?`).all(original).map((row) => ({ ...row }));
      assert.deepEqual(legacy, [{ policy_version: 1, business_date: "2026-04-03" }]);
      assert.equal(bank.db.prepare(`SELECT group_concat(dates_json,'|') AS bytes
        FROM ledger_accounting_dates WHERE entry_id IN
        (SELECT id FROM ledger_entries WHERE tx_id=?)`).get(original).bytes, before);
      const next = bank.fund(seedAccountId(1), 100);
      assert.deepEqual(bank.db.prepare(`SELECT DISTINCT policy_version,business_date
        FROM ledger_accounting_view WHERE tx_id=?`).all(next).map((row) => ({ ...row })),
      [{ policy_version: 2, business_date: "2026-04-06" }]);
      assert.equal(bank.reconcile().ok, true);
    } finally { if (old.isOpen) old.close(); }
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
