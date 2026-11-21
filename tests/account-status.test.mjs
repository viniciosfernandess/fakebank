import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Bank } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId } from "../apps/world/src/id.ts";

test("account freeze records its reason and every status transition", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-account-status-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    assert.throws(() => bank.addAccount({ id: "acc_invalid_frozen", customer_id: null,
      kind: "checking", system_role: null, overdraft_limit: 0, status: "frozen" }),
    /BIZ_ACCOUNT_STATUS_INVALID/);
    bank.addAccount({ id: "acc_initial_frozen", customer_id: null, kind: "checking",
      system_role: null, overdraft_limit: 0, status: "frozen", frozen_reason: "judicial" });
    assert.equal(bank.account("acc_initial_frozen").frozen_reason, "judicial");
    const id = seedAccountId(1);
    const before = bank.account(id).balance_cached;
    assert.throws(() => bank.changeAccountStatus(id, "frozen", "reviewer"),
      /BIZ_ACCOUNT_STATUS_INVALID/);
    assert.equal(bank.changeAccountStatus(id, "frozen", "reviewer", "fraud_suspect")
      .frozen_reason, "fraud_suspect");
    assert.equal(bank.account(id).status, "frozen");
    assert.equal(bank.changeAccountStatus(id, "active", "reviewer").frozen_reason, null);
    assert.equal(bank.account(id).balance_cached, before);
    assert.throws(() => bank.changeAccountStatus(id, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_BALANCE/);
    bank.post([
      { accountId: id, amount: -before, kind: "account_test", actor: "test",
        refType: "test", refId: "account_close" },
      { accountId: bank.systemAccountId("cash_in"), amount: before,
        kind: "account_test", actor: "test", refType: "test", refId: "account_close" },
    ]);
    bank.changeAccountStatus(id, "closed", "reviewer");
    assert.throws(() => bank.changeAccountStatus(id, "active", "reviewer"),
      /BIZ_ACCOUNT_STATUS_INVALID/);
    const history = bank.db.prepare(`SELECT from_status,to_status,reason,actor
      FROM account_status_changes WHERE account_id=? ORDER BY rowid`).all(id)
      .map((row) => ({ ...row }));
    assert.deepEqual(history, [
      { from_status: "active", to_status: "frozen", reason: "fraud_suspect", actor: "reviewer" },
      { from_status: "frozen", to_status: "active", reason: null, actor: "reviewer" },
      { from_status: "active", to_status: "closed", reason: null, actor: "reviewer" },
    ]);
    assert.throws(() => bank.db.prepare(`DELETE FROM account_status_changes
      WHERE account_id=?`).run(id), /ACCOUNT_STATUS_HISTORY_IMMUTABLE/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("existing account tables gain the freeze reason column", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-account-migration-"));
  const path = join(dir, "bank.sqlite");
  const oldDb = new DatabaseSync(path);
  oldDb.exec(`CREATE TABLE accounts (
    id TEXT PRIMARY KEY, customer_id TEXT, kind TEXT NOT NULL,
    system_role TEXT, balance_cached INTEGER NOT NULL DEFAULT 0,
    overdraft_limit INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
    opened_at TEXT NOT NULL
  );`);
  oldDb.close();
  const bank = new Bank(path);
  try {
    assert.ok(bank.db.prepare("PRAGMA table_info(accounts)").all()
      .some((column) => column.name === "frozen_reason"));
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
