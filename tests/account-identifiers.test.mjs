import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { accountIdentifier } from "../apps/world/src/bank-account-number.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";

test("seeded accounts receive unique Brazilian account identifiers", () => {
  const bank = new Bank(":memory:", () => new Date("2026-11-11T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 3, accounts: 5, historyTransactions: 0 });
    const rows = bank.db.prepare(`SELECT branch_code,account_number,account_digit
      FROM accounts WHERE customer_id IS NOT NULL ORDER BY account_number`).all();
    assert.deepEqual(rows.map((row) => ({ ...row })),
      Array.from({ length: 5 }, (_, index) => accountIdentifier(index + 1)));
    assert.equal(bank.account(seedAccountId(1)).account_number, "00000001");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM accounts WHERE customer_id IS NULL
      AND account_number IS NOT NULL`).get().n, 0);
  } finally { bank.close(); }
});

test("legacy customer accounts gain stable numbers and new accounts continue the sequence", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-account-identifiers-"));
  const path = join(dir, "bank.sqlite");
  const raw = new DatabaseSync(path);
  raw.exec(`CREATE TABLE customers (
    id TEXT PRIMARY KEY, cpf TEXT NOT NULL UNIQUE, name TEXT NOT NULL, persona TEXT NOT NULL,
    kyc_tier INTEGER NOT NULL, kyc_status TEXT NOT NULL, risk_score INTEGER NOT NULL,
    is_attacker_owned INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE accounts (
    id TEXT PRIMARY KEY, customer_id TEXT REFERENCES customers(id), kind TEXT NOT NULL,
    system_role TEXT, balance_cached INTEGER NOT NULL DEFAULT 0, overdraft_limit INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL, opened_at TEXT NOT NULL
  );`);
  raw.prepare("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)").run(seedCustomerId(1),
    "00000000001", "Legacy Customer", "salaried", 2, "approved", 10, 0,
    "active", "2026-10-01T12:00:00.000Z");
  const insert = raw.prepare("INSERT INTO accounts VALUES (?,?,?,?,?,?,?,?)");
  insert.run(seedAccountId(1), seedCustomerId(1), "checking", null, 0, 0,
    "active", "2026-10-01T12:00:00.000Z");
  insert.run(seedAccountId(2), seedCustomerId(1), "checking", null, 0, 0,
    "active", "2026-10-02T12:00:00.000Z");
  raw.close();
  let bank;
  try {
    bank = new Bank(path, () => new Date("2026-11-11T12:00:00.000Z"));
    assert.deepEqual([bank.account(seedAccountId(1)).account_number,
      bank.account(seedAccountId(2)).account_number], ["00000001", "00000002"]);
    bank.close();
    bank = new Bank(path, () => new Date("2026-11-11T12:00:00.000Z"));
    assert.equal(bank.account(seedAccountId(1)).account_digit, accountIdentifier(1).account_digit);
    bank.addAccount({ id: "legacy-third", customer_id: seedCustomerId(1), kind: "checking",
      system_role: null, overdraft_limit: 0, status: "active" });
    assert.deepEqual([bank.account("legacy-third").branch_code,
      bank.account("legacy-third").account_number,
      bank.account("legacy-third").account_digit], ["0001", "00000003", "3"]);
    assert.throws(() => bank.db.prepare("UPDATE accounts SET account_number='00000008' WHERE id=?")
      .run(seedAccountId(1)), /ACCOUNT_IDENTIFIER_IMMUTABLE/);
    assert.throws(() => bank.db.prepare(`INSERT INTO accounts
      (id,customer_id,kind,system_role,balance_cached,overdraft_limit,status,opened_at)
      VALUES (?,?,?,?,?,?,?,?)`).run("unnumbered", seedCustomerId(1), "checking", null,
        0, 0, "active", "2026-11-11T12:00:00.000Z"), /ACCOUNT_IDENTIFIER_REQUIRED/);
  } finally { bank?.close(); rmSync(dir, { recursive: true, force: true }); }
});
