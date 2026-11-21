import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { FeatureRegistry } from "../apps/world/src/features.ts";
import { DynamicLimits } from "../apps/world/src/dynamic-limits.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { BlueContainment } from "../apps/orchestrator/src/blue-containment.ts";
import { seedBank } from "../apps/world/src/seed.ts";
test("dynamic limits accept verified income and disregard own-account transfers", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-f7-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-11T12:00:00.000Z"));
  seedBank(bank, { customers: 2, accounts: 3, historyTransactions: 0 });
  try {
    const features = new FeatureRegistry(bank);
    const limits = new DynamicLimits(bank, features);
    assert.throws(() => limits.recompute("cus_01M73YF00008HZAJHSF59KNBCW"),
      (error) => error instanceof BankError && error.code === "DEF_NOT_FOUND");
    features.setEnabled("limite_dinamico", true, "product-review");
    features.patchFlaw("limite_dinamico", "engineer");
    assert.equal(bank.pixDailyLimit("cus_01M73YF00008HZAJHSF59KNBCW"), 500_000);
    for (let index = 0; index < 5; index++) bank.transferPix({ from: "acc_01M73YF000F5PY1WETGMV9RFE4",
      to: "acc_01M73YF000C4A1RJ5SMQ8CXNWH", amount: 1000, idempotencyKey: `self-${index}`, actor: "cus_01M73YF00008HZAJHSF59KNBCW" });
    assert.deepEqual(limits.recompute("cus_01M73YF00008HZAJHSF59KNBCW"), { extra_cents: 0, source_count: 0, verified: true });
    assert.equal(bank.pixDailyLimit("cus_01M73YF00008HZAJHSF59KNBCW"), 500_000);
    assert.equal(new SentinelEngine(bank).scan().some((alert) =>
      alert.rule_id === "S-ACC-03"), false,
    "the corrected limit must not keep emitting a stale incident");
    for (let index = 0; index < 3; index++) limits.recordVerifiedIncome("cus_01M73YF00008HZAJHSF59KNBCW", "acc_01M73YF000C4A1RJ5SMQ8CXNWH", 10_000,
      `payroll-${index}`);
    assert.deepEqual(limits.recompute("cus_01M73YF00008HZAJHSF59KNBCW"), { extra_cents: 100_000, source_count: 3, verified: true });
    assert.equal(bank.pixDailyLimit("cus_01M73YF00008HZAJHSF59KNBCW"), 600_000);
    assert.equal(new SentinelEngine(bank).scan().some((alert) =>
      alert.rule_id === "S-ACC-03"), false,
    "verified income must not look like an unverified limit increase");
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("an unresolved unverified limit stays capped after its containment TTL", () => {
  const twinAt = new Date("2026-11-11T12:00:00.000Z");
  let realMs = twinAt.getTime();
  const bank = new Bank(":memory:", () => twinAt,
    () => new Date(realMs));
  try {
    seedBank(bank, { customers: 2, accounts: 3, historyTransactions: 0 });
    const customerId = "cus_01M73YF00008HZAJHSF59KNBCW";
    const features = new FeatureRegistry(bank);
    const limits = new DynamicLimits(bank, features);
    features.setEnabled("limite_dinamico", true, "product-review");
    features.patchFlaw("limite_dinamico", "engineer");
    // Replay a stale persisted limit from an older data directory.
    bank.db.prepare(`INSERT INTO dynamic_limits
      (customer_id,extra_cents,source_count,verified,updated_at) VALUES (?,100000,3,0,?)`)
      .run(customerId, twinAt.toISOString());
    const alert = new SentinelEngine(bank).scan().find((item) =>
      item.rule_id === "S-ACC-03" && item.entity === customerId);
    assert.ok(alert);
    const incident = bank.db.prepare(`SELECT id FROM sentinel_incidents
      WHERE area='accounts' AND entity_key=?`).get(customerId);
    assert.ok(incident);
    const containment = new BlueContainment(bank);
    const receipt = containment.apply({ incidentId: incident.id,
      actorId: "defense-coordinator", kind: "disable_flag",
      target: "limite_dinamico", reason: "Unverified limit increase",
      evidenceRefs: [`sentinel_alerts:${alert.alert_id}`], ttlMin: 1 });
    assert.equal(bank.pixDailyLimit(customerId), 500_000);
    realMs += 61_000;
    assert.equal(features.isEnabled("limite_dinamico"), true,
      "the temporary feature pause has expired");
    assert.equal(bank.pixDailyLimit(customerId), 500_000,
      "an expired pause must not reinstate an unverified increase");
    assert.throws(() => containment.lift(receipt.id, "restorer"),
      (error) => error instanceof BankError &&
        error.code === "DEF_LIMIT_REPAIR_REQUIRED");
    assert.equal(limits.recompute(customerId).verified, true);
    assert.equal(containment.lift(receipt.id, "restorer"), true);
    assert.equal(bank.pixDailyLimit(customerId), 500_000);
  } finally { bank.close(); }
});
