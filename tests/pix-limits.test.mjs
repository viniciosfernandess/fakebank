import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, loadPixLimits } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";

test("versioned Pix limits validate their schema and database bounds", () => {
  const limits = loadPixLimits();
  assert.deepEqual(limits, { version: 1, max_transaction_cents: 2_000_000,
    max_setting_cents: 2_000_000, daily_by_tier_cents: [0, 100_000, 500_000, 1_500_000],
    night_limit_cents: 100_000, night_start_hour: 20,
    new_device_transaction_cents: 20_000, new_device_daily_cents: 100_000 });
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-limits-"));
  const path = join(dir, "limits.json");
  try {
    for (const changes of [{ version: 2 }, { max_setting_cents: 2_000_001 },
      { max_transaction_cents: -1 }, { night_limit_cents: 2_000_001 },
      { night_start_hour: 21 }, { new_device_daily_cents: 1.5 },
      { daily_by_tier_cents: [0, 1, 2] }, { unexpected: true }]) {
      writeFileSync(path, JSON.stringify({ ...limits, ...changes }));
      assert.throws(() => loadPixLimits(path), /PIX_LIMITS_INVALID/);
    }
    writeFileSync(path, JSON.stringify({ ...limits, night_limit_cents: 50_000 }));
    assert.equal(loadPixLimits(path).night_limit_cents, 50_000);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("Pix limit defaults and setting boundaries stay unchanged", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-defaults-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1); const account = seedAccountId(1);
    assert.equal(bank.pixNightSettings(customer).night_limit_cents, 100_000);
    assert.equal(bank.pixNightSettings(customer).night_start_hour, 20);
    for (const invalid of [-1, 2_000_001, 1.5]) {
      assert.throws(() => bank.requestPixNightSetting(customer, "night_limit_cents", invalid), /BIZ_PIX_LIMIT_INVALID/);
      assert.throws(() => bank.requestPixAutomaticLimit(customer, account, invalid), /BIZ_AUTOMATIC_LIMIT/);
    }
    assert.throws(() => bank.transferPix({ from: account, to: seedAccountId(2), amount: 2_000_001,
      idempotencyKey: "over-limit", actor: customer }), /BIZ_INVALID_AMOUNT/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("returned external Pix still consume gross standard and automatic daily limits", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-return-limits-"));
  const limits = { ...loadPixLimits(), daily_by_tier_cents: [0, 1_000, 1_000, 1_000] };
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"),
    undefined, { pixLimitsBytes: Buffer.from(JSON.stringify(limits)) });
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    const payment = (product, amount, idempotencyKey) => bank.transferPix({ from,
      to: "psp_ipe_ana", amount, idempotencyKey, actor: "test", product });
    const standard = payment("standard", 900, "gross-standard");
    bank.returnExternalPix(standard.id, 1, "gross-standard-partial");
    const before = bank.account(from).balance_cached;
    assert.throws(() => payment("standard", 200, "gross-standard-exceed"), /BIZ_DAILY_LIMIT/);
    assert.equal(bank.account(from).balance_cached, before);
    bank.returnExternalPix(standard.id, 899, "gross-standard-full");
    assert.throws(() => payment("standard", 200, "gross-standard-after-full"), /BIZ_DAILY_LIMIT/);
    const automatic = payment("automatic", 900, "gross-automatic");
    bank.returnExternalPix(automatic.id, 1, "gross-automatic-partial");
    assert.throws(() => payment("automatic", 200, "gross-automatic-exceed"), /BIZ_DAILY_LIMIT/);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.reconcileSpi().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("night limit counts only prior night payments and retains returned gross spending", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-return-night-"));
  const limits = { ...loadPixLimits(), daily_by_tier_cents: [0, 5_000, 5_000, 5_000],
    night_limit_cents: 1_000 };
  let now = new Date("2026-11-13T22:59:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now, undefined,
    { pixLimitsBytes: Buffer.from(JSON.stringify(limits)) });
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    const payment = (amount, idempotencyKey) => bank.transferPix({ from,
      to: "psp_ipe_ana", amount, idempotencyKey, actor: "test" });
    payment(700, "before-night");
    now = new Date("2026-11-13T23:00:00Z");
    const night = payment(500, "at-night");
    assert.equal(bank.db.prepare("SELECT night_mode FROM pix_transfers WHERE id=?")
      .get(night.id).night_mode, 1);
    bank.returnExternalPix(night.id, 1, "night-partial");
    const before = bank.account(from).balance_cached;
    assert.throws(() => payment(600, "night-exceed"), /BIZ_NIGHT_LIMIT/);
    assert.equal(bank.account(from).balance_cached, before);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
