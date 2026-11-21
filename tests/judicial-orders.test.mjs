import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { JudicialOrders } from "../apps/world/src/judicial-orders.ts";
import { AccountLifecycle } from "../apps/world/src/account-lifecycle.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";

test("judicial order reserves funds until a separate reviewer approves release", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-judicial-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-14T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const orders = new JudicialOrders(bank);
    const accountId = seedAccountId(1);
    const initial = bank.availableBalance(accountId);
    const order = orders.request(accountId, 5_000, "CASE-2026/001", "maker_a");
    assert.equal(order.status, "pending");
    assert.throws(() => orders.review(order.id, "approve", "maker_a"),
      /BIZ_JUDICIAL_REVIEW_INVALID/);
    const active = orders.review(order.id, "approve", "reviewer_a");
    assert.equal(active.status, "active");
    assert.equal(bank.availableBalance(accountId), initial - 5_000);
    assert.throws(() => bank.releaseHold(active.hold_id, "reviewer_a"),
      /DEF_JUDICIAL_ORDER_PROTECTED/);
    assert.throws(() => orders.requestRelease(order.id, "reviewer_a"),
      /BIZ_JUDICIAL_RELEASE_INVALID/);
    orders.requestRelease(order.id, "maker_b");
    assert.throws(() => orders.reviewRelease(order.id, "approve", "maker_b"),
      /BIZ_JUDICIAL_RELEASE_INVALID/);
    assert.equal(orders.reviewRelease(order.id, "reject", "reviewer_b").status, "active");
    assert.equal(bank.availableBalance(accountId), initial - 5_000);
    orders.requestRelease(order.id, "maker_b");
    assert.equal(orders.reviewRelease(order.id, "approve", "reviewer_b").status, "released");
    assert.equal(bank.availableBalance(accountId), initial);
    assert.deepEqual(bank.db.prepare(`SELECT action FROM judicial_order_events
      WHERE order_id=? ORDER BY rowid`).all(order.id).map(({ action }) => action),
      ["requested", "activated", "release_requested", "release_rejected",
        "release_requested", "release_approved"]);
    assert.throws(() => bank.db.prepare(`DELETE FROM judicial_order_events WHERE order_id=?`)
      .run(order.id), /JUDICIAL_EVENT_IMMUTABLE/);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("judicial approval is atomic when available funds changed", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-judicial-race-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-14T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const orders = new JudicialOrders(bank);
    const accountId = seedAccountId(1);
    const amount = bank.availableBalance(accountId);
    const order = orders.request(accountId, amount, "CASE-2026/002", "maker_a");
    const competitor = orders.request(accountId, amount, "CASE-2026/003", "maker_b");
    orders.review(competitor.id, "approve", "reviewer_a");
    assert.throws(() => orders.review(order.id, "approve", "reviewer_b"),
      /BIZ_INSUFFICIENT_FUNDS/);
    assert.equal(orders.get(order.id).status, "pending");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM judicial_order_events
      WHERE order_id=?`).get(order.id).n, 1);
    assert.equal(orders.review(order.id, "reject", "reviewer_b").status, "rejected");
    const empty = "acc_judicial_pending";
    bank.addAccount({ id: empty, customer_id: seedCustomerId(1), kind: "checking",
      system_role: null, overdraft_limit: 0, status: "active" });
    const pending = orders.request(empty, 100, "CASE-2026/004", "maker_a");
    assert.throws(() => new AccountLifecycle(bank).transition(empty, "closed", "reviewer_b"),
      /BIZ_ACCOUNT_CLOSE_PENDING/);
    orders.review(pending.id, "reject", "reviewer_b");
    assert.equal(new AccountLifecycle(bank).transition(empty, "closed", "reviewer_b").status,
      "closed");
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
