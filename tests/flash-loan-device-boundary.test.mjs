import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { LoansEngine } from "../apps/world/src/loans.ts";
import { FeatureRegistry } from "../apps/world/src/features.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";

test("flash loan uses exact bound-device age and keeps trusted-device proof", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-flash-device-boundary-"));
  let now = new Date("2026-11-15T15:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const features = new FeatureRegistry(bank);
    features.setEnabled("emprestimo_relampago", true, "test");
    features.patchFlaw("emprestimo_relampago", "test");
    const firstSeen = "2026-11-13T15:00:00.000Z";
    const trustedAt = "2026-11-14T15:00:00.000Z";
    const lateBound = "2026-11-15T14:50:00.000Z";
    const addDevice = (id, customer, boundAt, fingerprint) => bank.db.prepare(`INSERT INTO auth_devices
      (id,customer_id,fingerprint,first_seen_at,bound_at,first_seen_ip,trusted_at)
      VALUES (?,?,?,?,?,'127.0.0.1',?)`).run(id, customer, fingerprint, firstSeen,
        boundAt, trustedAt);
    addDevice("late-bound", seedCustomerId(1), lateBound, "late-fingerprint");
    addDevice("established", seedCustomerId(2), firstSeen, "established-fingerprint");
    const firstAccount = seedAccountId(1), secondAccount = seedAccountId(2);
    const firstBalance = bank.account(firstAccount).balance_cached;
    const ledgerCount = () => bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n;
    const before = ledgerCount();
    const cooldown = (customer, account, device) => assert.throws(
      () => loans.acceptFlash(customer, account, device, 10_000),
      (error) => error instanceof BankError && error.code === "BIZ_DEVICE_COOLDOWN");
    cooldown(seedCustomerId(1), firstAccount, "late-bound");
    cooldown(seedCustomerId(1), firstAccount, "established");
    cooldown(seedCustomerId(2), secondAccount, "established-fingerprint");
    assert.equal(ledgerCount(), before);
    assert.equal(bank.account(firstAccount).balance_cached, firstBalance);
    const established = loans.acceptFlash(seedCustomerId(2), secondAccount, "established", 10_000);
    assert.equal(established.status, "active");
    now = new Date("2026-11-16T14:49:59.999Z");
    cooldown(seedCustomerId(1), firstAccount, "late-bound");
    now = new Date("2026-11-16T14:50:00.000Z");
    assert.equal(loans.acceptFlash(seedCustomerId(1), firstAccount,
      "late-bound", 10_000).status, "active");
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
