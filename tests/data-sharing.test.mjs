import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { FeatureRegistry } from "../apps/world/src/features.ts";
import { DataSharing } from "../apps/world/src/data-sharing.ts";
import { seedBank } from "../apps/world/src/seed.ts";
test("account sharing enforces consent scope and revocation on every read", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-f6-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-11T12:00:00.000Z"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  try {
    const features = new FeatureRegistry(bank);
    const sharing = new DataSharing(bank, features);
    assert.throws(() => sharing.grant("cus_01M73YF00008HZAJHSF59KNBCW", "partner-a", ["balance"]),
      (error) => error instanceof BankError && error.code === "DEF_NOT_FOUND");
    features.setEnabled("compartilhar_dados", true, "product-review");
    features.patchFlaw("compartilhar_dados", "engineer");
    const safe = sharing.grant("cus_01M73YF00008HZAJHSF59KNBCW", "partner-a", ["balance"]);
    assert.throws(() => sharing.read(safe.token, "statement"),
      (error) => error instanceof BankError && error.code === "DEF_CONSENT_INVALID");
    assert.equal(sharing.read(safe.token, "balance").data.balance_cents, bank.account("acc_01M73YF000C4A1RJ5SMQ8CXNWH").balance_cached);
    sharing.revoke("cus_01M73YF00008HZAJHSF59KNBCW", safe.consent_id);
    assert.throws(() => sharing.read(safe.token, "balance"), { code: "DEF_CONSENT_INVALID" });
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
