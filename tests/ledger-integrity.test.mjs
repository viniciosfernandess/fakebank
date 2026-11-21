import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { installLedgerIntegrity, verifyLedgerChain } from "../apps/world/src/ledger-integrity.ts";

test("ledger posting telemetry must match a balanced durable transaction", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-ledger-post-telemetry-"));
  const now = () => new Date("2026-11-13T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), now, now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const sentinel = new SentinelEngine(bank);
    const txId = bank.fund(bank.db.prepare(`SELECT id FROM accounts
      WHERE customer_id IS NOT NULL ORDER BY id LIMIT 1`).get().id, 500);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='ledger' AND action='post' AND counterparty=?`).get(txId).n, 1);
    assert.equal(sentinel.scan().some((item) => item.rule_id === "S-LED-10"), false);
    const traceId = bank.telemetry.emit({ source: "ledger", category: "transaction",
      action: "post", outcome: "success", counterparty: txId,
      amountCents: 999, message: "Balanced ledger transaction posted" });
    const event = bank.db.prepare(`SELECT id FROM telemetry_events
      WHERE trace_id=? AND source='ledger' AND action='post'`).get(traceId);
    const alert = sentinel.scan().find((item) => item.rule_id === "S-LED-10");
    assert.equal(alert?.entity, `ledger_event:${event.id}`);
    assert.equal(alert?.observed.transaction_id, txId);
    assert.equal(alert?.observed.posting_mismatch, 1);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("ledger seals detect altered metadata even when balances still reconcile", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-ledger-seals-"));
  let realMs = Date.parse("2026-11-11T06:30:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date(realMs), () => new Date(realMs));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const sentinels = new SentinelEngine(bank);
    assert.equal(bank.verifyLedgerChain(), true);
    assert.throws(() => bank.db.prepare("UPDATE ledger_seals SET entry_hash='bad' WHERE entry_rowid=(SELECT MIN(entry_rowid) FROM ledger_seals)").run(),
      /LEDGER_SEAL_APPEND_ONLY/);
    bank.db.exec("DROP TRIGGER ledger_entries_no_update");
    bank.db.prepare("UPDATE ledger_entries SET kind='tampered' WHERE rowid=(SELECT MIN(rowid) FROM ledger_entries)").run();
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.verifyLedgerChain(), false);
    assert.throws(() => bank.periodClose(),
      (error) => error instanceof BankError && error.code === "INTEGRITY_PERIOD_CLOSE_BLOCKED");
    realMs += 600_001;
    assert.ok(sentinels.scan().some((alert) => alert.rule_id === "S-LED-02"));
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("existing ledger is sealed when an older database opens", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-ledger-migrate-"));
  const path = join(dir, "bank.sqlite");
  const bank = new Bank(path);
  try { seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 10 }); }
  finally { bank.close(); }
  const oldDb = new DatabaseSync(path);
  try {
    oldDb.exec("DROP TRIGGER ledger_entries_seal; DROP TRIGGER ledger_seals_no_update; DROP TRIGGER ledger_seals_no_delete; DROP TABLE ledger_seals");
  } finally { oldDb.close(); }
  const reopened = new Bank(path);
  try {
    assert.equal(reopened.verifyLedgerChain(), true);
    assert.ok(reopened.db.prepare("SELECT COUNT(*) n FROM ledger_seals").get().n > 0);
  } finally { reopened.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("verification uses one snapshot while another connection posts", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-ledger-snapshot-"));
  const path = join(dir, "bank.sqlite");
  const reader = new Bank(path);
  seedBank(reader, { customers: 2, accounts: 2, historyTransactions: 10 });
  const writer = new Bank(path);
  let posted = false;
  const db = new Proxy(reader.db, { get(target, property) {
    if (property === "prepare") return (sql) => {
      if (sql === "SELECT COUNT(*) n FROM ledger_seals") {
        writer.fund("acc_01M73YF000C4A1RJ5SMQ8CXNWH", 100);
        posted = true;
      }
      return target.prepare(sql);
    };
    const value = Reflect.get(target, property, target);
    return typeof value === "function" ? value.bind(target) : value;
  } });
  try {
    assert.equal(verifyLedgerChain(db), true);
    assert.equal(posted, true);
    assert.equal(reader.verifyLedgerChain(), true);
  } finally { writer.close(); reader.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("sentinel startup reports an already corrupted ledger chain", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-ledger-startup-"));
  const bank = new Bank(join(dir, "bank.sqlite"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    bank.db.exec("DROP TRIGGER ledger_entries_no_update");
    bank.db.prepare("UPDATE ledger_entries SET kind='tampered' WHERE rowid=(SELECT MIN(rowid) FROM ledger_entries)").run();
    assert.ok(new SentinelEngine(bank).scan().some((alert) => alert.rule_id === "S-LED-02"));
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});


test("ledger migration excludes concurrent writes until sealing triggers are installed", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-ledger-migrate-lock-"));
  const path = join(dir, "bank.sqlite");
  const bank = new Bank(path);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const writer = new Bank(path);
  try {
    bank.db.exec("DROP TRIGGER ledger_entries_seal; DROP TABLE ledger_seals");
    let checked = false;
    const db = new Proxy(bank.db, { get(target, property) {
      if (property === "exec") return (sql) => {
        if (sql.includes("CREATE TRIGGER IF NOT EXISTS ledger_entries_no_update")) {
          assert.equal(target.isTransaction, true);
          assert.throws(() => writer.fund("acc_01M73YF000C4A1RJ5SMQ8CXNWH", 100), /locked|busy/i);
          checked = true;
        }
        return target.exec(sql);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    installLedgerIntegrity(db);
    assert.equal(checked, true);
    writer.fund("acc_01M73YF000C4A1RJ5SMQ8CXNWH", 100);
    assert.equal(bank.verifyLedgerChain(), true);
  } finally { writer.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
