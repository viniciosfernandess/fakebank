import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";

test("Pix channel limits separate app and scheduled spending with delayed increases", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-channels-"));
  let at = new Date("2026-11-13T12:00:00.000Z");
  const path = join(dir, "bank.sqlite");
  let bank = new Bank(path, () => at);
  const customer = seedCustomerId(1);
  const input = (key, amount, channel) => ({ from: seedAccountId(1),
    to: seedAccountId(2), amount, idempotencyKey: key, actor: customer,
    ...(channel ? { channel } : {}) });
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    assert.equal(bank.requestPixChannelLimit(customer, "app", 1_000)
      .daily_limit_cents, 1_000);
    assert.equal(bank.requestPixChannelLimit(customer, "scheduled", 900)
      .daily_limit_cents, 900);
    const app = bank.transferPix(input("app-600", 600));
    const scheduled = bank.transferPix(input("scheduled-700", 700, "scheduled"));
    assert.deepEqual(bank.db.prepare(`SELECT id,channel FROM pix_transfers
      WHERE id IN (?,?) ORDER BY channel`).all(app.id, scheduled.id).map((row) => row.channel),
    ["app", "scheduled"]);
    assert.throws(() => bank.transferPix(input("app-500", 500)),
      (error) => error instanceof BankError && error.code === "BIZ_CHANNEL_LIMIT");
    assert.throws(() => bank.transferPix(input("scheduled-300", 300, "scheduled")),
      (error) => error instanceof BankError && error.code === "BIZ_CHANNEL_LIMIT");
    assert.throws(() => bank.transferPix(input("app-600", 600, "scheduled")),
      (error) => error instanceof BankError && error.code === "BIZ_IDEMPOTENCY_CONFLICT");
    at = new Date(at.getTime() + 3_600_000);
    assert.equal(bank.requestPixChannelLimit(customer, "app", 400)
      .daily_limit_cents, 400);
    assert.throws(() => bank.transferPix(input("app-1", 1)),
      (error) => error instanceof BankError && error.code === "BIZ_CHANNEL_LIMIT");
    const increase = bank.requestPixChannelLimit(customer, "app", 2_000);
    assert.equal(increase.daily_limit_cents, 400);
    assert.equal(increase.pending.value, 2_000);
    bank.close();
    bank = new Bank(path, () => at);
    assert.equal(bank.pixChannelLimit(customer, "app").pending.value, 2_000);
    at = new Date(Date.parse(increase.pending.effective_at) - 1);
    assert.throws(() => bank.transferPix(input("app-before", 500)),
      (error) => error instanceof BankError && error.code === "BIZ_CHANNEL_LIMIT");
    at = new Date(increase.pending.effective_at);
    assert.equal(bank.pixChannelLimit(customer, "app").daily_limit_cents, 2_000);
    assert.equal(bank.transferPix(input("app-after", 1_500)).status, "settled");
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
