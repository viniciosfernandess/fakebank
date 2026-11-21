import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AccountService } from "../apps/world/src/accounts.ts";
import { Bank, BankError, syntheticCpf } from "../apps/world/src/bank.ts";
import { syntheticCnpj } from "../apps/world/src/business-document.ts";
import { parsePixKey } from "../apps/world/src/ecosystem/dict.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { seedBank } from "../apps/world/src/seed.ts";

function fixture(work) {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-business-"));
  const path = join(dir, "bank.sqlite");
  const bank = new Bank(path, () => new Date("2026-11-18T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 10, accounts: 10, historyTransactions: 0 });
    return work({ bank, path, accounts: new AccountService(bank) });
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("synthetic seeded merchants have valid, distinct CNPJ identities", () => fixture(({ bank }) => {
  const rows = bank.db.prepare(`SELECT a.id,b.cnpj,b.representative_customer_id
    FROM accounts a JOIN business_account_identity b ON b.account_id=a.id
    WHERE a.kind='merchant'`).all();
  assert.ok(rows.length > 0);
  assert.equal(new Set(rows.map((row) => row.cnpj)).size, rows.length);
  for (const row of rows) {
    assert.deepEqual(parsePixKey(row.cnpj), { type: "cnpj", value: row.cnpj });
    assert.equal(bank.account(row.id).customer_id, row.representative_customer_id);
  }
}));

test("verified business account opens atomically and keeps its identity immutable", () => fixture(
  ({ bank, accounts }) => {
    const customer = seedCustomerId(1);
    const cnpj = syntheticCnpj(20_000);
    const before = bank.db.prepare(`SELECT COUNT(*) n FROM accounts WHERE customer_id=?`)
      .get(customer).n;
    const invalid = `${cnpj.slice(0, -1)}${(Number(cnpj.at(-1)) + 1) % 10}`;
    assert.throws(() => accounts.openBusiness(customer, invalid, "Business Ltda", "reviewer_1"),
      (error) => error instanceof BankError && error.code === "BIZ_BUSINESS_IDENTITY_INVALID");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM accounts WHERE customer_id=?`)
      .get(customer).n, before);
    const opened = accounts.openBusiness(customer, cnpj, "Business Ltda", "reviewer_1");
    assert.equal(opened.account.kind, "merchant");
    assert.equal(opened.identity.cnpj, cnpj);
    assert.equal(opened.identity.representative_customer_id, customer);
    assert.throws(() => bank.registerPixKey(customer, opened.account.id, syntheticCpf(0)),
      (error) => error instanceof BankError && error.code === "DEF_PIX_KEY_DOCUMENT_MISMATCH");
    assert.throws(() => bank.registerPixKey(customer, opened.account.id, syntheticCnpj(20_001)),
      (error) => error instanceof BankError && error.code === "DEF_PIX_KEY_DOCUMENT_MISMATCH");
    assert.equal(bank.registerPixKey(customer, opened.account.id, cnpj).key, cnpj);
    assert.throws(() => bank.registerPixKey(customer, seedAccountId(1), syntheticCpf(1)),
      (error) => error instanceof BankError && error.code === "DEF_PIX_KEY_DOCUMENT_MISMATCH");
    assert.equal(bank.registerPixKey(customer, seedAccountId(1), syntheticCpf(0)).key,
      syntheticCpf(0));
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM accounts WHERE customer_id=?`)
      .get(customer).n, before + 1);
    assert.throws(() => bank.db.prepare(`UPDATE business_account_identity
      SET cnpj=? WHERE account_id=?`).run(syntheticCnpj(20_001), opened.account.id),
    /BUSINESS_IDENTITY_IMMUTABLE/);
    assert.throws(() => accounts.openBusiness(seedCustomerId(2), cnpj,
      "Duplicate Business Ltda", "reviewer_2"),
    (error) => error instanceof BankError && error.code === "BIZ_CNPJ_ALREADY_REGISTERED");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM accounts WHERE customer_id=?`)
      .get(seedCustomerId(2)).n, 1);
  }));

test("unverified merchant label keeps the personal Pix quota until CNPJ verification", () => fixture(
  ({ bank, accounts }) => {
    const customer = seedCustomerId(1);
    const id = "unverified_merchant_account";
    bank.addAccount({ id, customer_id: customer, kind: "merchant", system_role: null,
      overdraft_limit: 0, status: "active" });
    for (let index = 0; index < 5; index++)
      bank.registerPixKey(customer, id, `unverified-${index}@example.test`);
    assert.throws(() => bank.registerPixKey(customer, id, "unverified-extra@example.test"),
      (error) => error instanceof BankError && error.code === "BIZ_KEY_LIMIT");
    accounts.verifyBusiness(customer, id, syntheticCnpj(30_000),
      "Verified Business Ltda", "reviewer_1");
    for (let index = 5; index < 20; index++)
      bank.registerPixKey(customer, id, `verified-${index}@example.test`);
    assert.throws(() => bank.registerPixKey(customer, id, "verified-extra@example.test"),
      (error) => error instanceof BankError && error.code === "BIZ_KEY_LIMIT");
  }));

test("document keys cannot be ported between personal and business holders", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-business-portability-"));
  const now = new Date("2026-11-18T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const personal = seedAccountId(1);
    const cnpj = syntheticCnpj(50_000);
    const business = new AccountService(bank).openBusiness(customer, cnpj,
      "Portability Business Ltda", "reviewer_1").account.id;
    const cpf = syntheticCpf(0);
    bank.registerPixKey(customer, personal, cpf);
    bank.registerPixKey(customer, business, cnpj);
    for (const [target, key] of [[business, cpf], [personal, cnpj]])
      assert.throws(() => bank.requestPixKeyClaim(customer, target, key, "portability"),
        (error) => error instanceof BankError && error.code === "DEF_PIX_KEY_DOCUMENT_MISMATCH");
    assert.equal(bank.lookupPixKey(cpf).account_id, personal);
    assert.equal(bank.lookupPixKey(cnpj).account_id, business);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("legacy seeded merchant identity is restored on bank reopen", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-business-migration-"));
  const path = join(dir, "bank.sqlite");
  const bank = new Bank(path);
  try {
    seedBank(bank, { customers: 10, accounts: 10, historyTransactions: 0 });
    const merchant = bank.db.prepare(`SELECT id FROM accounts WHERE kind='merchant' LIMIT 1`)
      .get().id;
    assert.ok(new AccountService(bank).businessIdentity(merchant));
    bank.db.exec("DROP TABLE business_account_identity");
    bank.close();
    const reopened = new Bank(path);
    try {
      const identity = new AccountService(reopened).businessIdentity(merchant);
      assert.equal(identity.cnpj,
        syntheticCnpj(Number(reopened.account(merchant).account_number)));
      assert.equal(identity.verified_by, "synthetic_seed_migration");
      assert.equal(reopened.account(merchant).id, seedAccountId(Number(
        reopened.account(merchant).account_number)));
    } finally { reopened.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
