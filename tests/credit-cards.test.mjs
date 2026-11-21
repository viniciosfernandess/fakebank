import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { CreditCardsEngine } from "../apps/world/src/credit-cards.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedCustomerId, seedAccountId } from "../apps/world/src/id.ts";

const customer = seedCustomerId(1), source = seedAccountId(1);
const policy = { version: 1, minimum_payment_bps: 1500,
  revolving_daily_interest_bps: 10, fixed_iof_bps: 30, daily_iof_bps: 1,
  invoice_plan_interest_bps: 250, due_days: 10 };

function withCards(work) {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-credit-"));
  let now = new Date("2026-11-11T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const cards = new CreditCardsEngine(bank, policy);
  try { work({ bank, cards, advance: (iso) => { now = new Date(iso); } }); }
  finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("credit installments and invoice payments reconcile", () => withCards(({ bank, cards, advance }) => {
  const card = cards.open(customer, 100_000, 15);
  cards.purchase(customer, card.id, "merchant-1", 30_001, 3);
  assert.equal(cards.availableLimit(customer, card.id), 69_999);
  advance("2026-11-16T12:00:00Z");
  const first = cards.closeNext(customer, card.id);
  assert.equal(first.purchases_cents, 10_001);
  cards.pay(customer, card.id, first.id, source, first.due_cents);
  advance("2026-12-16T12:00:00Z");
  const second = cards.closeNext(customer, card.id);
  assert.equal(second.purchases_cents, 10_000);
  assert.deepEqual(cards.reconcile(customer, card.id), { ok: true, mismatches: [] });
  assert.equal(bank.reconcile().ok, true);
}));

test("first statement cannot close before the account's first billing date", () =>
  withCards(({ cards, advance }) => {
    const card = cards.open(customer, 20_000, 15);
    assert.throws(() => cards.closeNext(customer, card.id), /BIZ_STATEMENT_NOT_CLOSED/);
    advance("2026-11-16T12:00:00Z");
    assert.equal(cards.closeNext(customer, card.id).closing_date, "2026-11-15");
  }));

test("billing job closes due invoices and accrues overdue debt once", () =>
  withCards(({ cards, advance }) => {
    const card = cards.open(customer, 20_000, 15);
    cards.purchase(customer, card.id, "merchant-1", 10_000);
    assert.deepEqual(cards.runBilling(), { closed: 0, accrued: 0 });
    advance("2026-11-16T12:00:00Z");
    assert.deepEqual(cards.runBilling(), { closed: 1, accrued: 0 });
    assert.deepEqual(cards.runBilling(), { closed: 0, accrued: 0 });
    advance("2026-11-27T12:00:00Z");
    assert.deepEqual(cards.runBilling(), { closed: 0, accrued: 1 });
    assert.deepEqual(cards.runBilling(), { closed: 0, accrued: 0 });
    assert.equal(cards.statements(customer, card.id).length, 1);
    assert.deepEqual(cards.reconcileAll(), { ok: true, accounts_checked: 1, mismatches: [] });
  }));

test("minimum payment, accrual and refund reconcile", () => withCards(({ bank, cards, advance }) => {
  const card = cards.open(customer, 100_000, 15);
  const purchase = cards.purchase(customer, card.id, "merchant-1", 20_000);
  advance("2026-11-16T12:00:00Z");
  const first = cards.closeNext(customer, card.id);
  cards.pay(customer, card.id, first.id, source, first.minimum_due_cents);
  advance("2026-11-27T12:00:00Z");
  assert.equal(cards.statementState(customer, first.id), "revolving");
  const assessed = cards.accrue(customer, card.id, first.id);
  assert.ok(assessed.interest_cents > 0 && assessed.iof_cents > 0);
  const beforeRefund = cards.statement(customer, first.id).due_cents;
  cards.refund(customer, card.id, purchase.id, 5_000);
  assert.equal(cards.statement(customer, first.id).due_cents, beforeRefund - 5_000);
  advance("2026-12-16T12:00:00Z");
  const second = cards.closeNext(customer, card.id);
  assert.ok(second.carryover_cents > 0);
  assert.deepEqual(cards.reconcile(customer, card.id), { ok: true, mismatches: [] });
  assert.equal(bank.reconcile().ok, true);
}));

test("refunds before close become statement credits and restore limit", () => withCards(({ cards, advance }) => {
  const card = cards.open(customer, 20_000, 15);
  const purchase = cards.purchase(customer, card.id, "merchant-1", 19_000);
  cards.refund(customer, card.id, purchase.id, 10_000);
  assert.equal(cards.availableLimit(customer, card.id), 11_000);
  advance("2026-11-16T12:00:00Z");
  const statement = cards.closeNext(customer, card.id);
  assert.equal(statement.due_cents, 9_000);
  assert.deepEqual(cards.reconcile(customer, card.id), { ok: true, mismatches: [] });
}));

test("delinquency and duplicate accrual are deterministic", () => withCards(({ cards, advance }) => {
  const card = cards.open(customer, 30_000, 15);
  cards.purchase(customer, card.id, "merchant-1", 20_000);
  advance("2026-11-16T12:00:00Z");
  const statement = cards.closeNext(customer, card.id);
  advance("2026-11-27T12:00:00Z");
  assert.equal(cards.statementState(customer, statement.id), "delinquent");
  const charged = cards.accrue(customer, card.id, statement.id).due_cents;
  assert.equal(cards.accrue(customer, card.id, statement.id).due_cents, charged);
  assert.deepEqual(cards.reconcile(customer, card.id), { ok: true, mismatches: [] });
}));

test("invoice plan moves remaining debt into future installments", () => withCards(({ bank, cards, advance }) => {
  const card = cards.open(customer, 100_000, 15);
  cards.purchase(customer, card.id, "merchant-1", 30_000);
  advance("2026-11-16T12:00:00Z");
  const first = cards.closeNext(customer, card.id);
  cards.pay(customer, card.id, first.id, source, first.minimum_due_cents);
  const plan = cards.installmentStatement(customer, card.id, first.id, 3);
  assert.deepEqual(cards.installmentStatement(customer, card.id, first.id, 3), plan);
  assert.throws(() => cards.installmentStatement(customer, card.id, first.id, 4),
    /BIZ_CREDIT_PLAN_CONFLICT/);
  assert.equal(plan.principal_cents, first.due_cents - first.minimum_due_cents);
  assert.equal(cards.statementState(customer, first.id), "financed");
  advance("2026-12-16T12:00:00Z");
  const second = cards.closeNext(customer, card.id);
  assert.equal(second.carryover_cents, 0);
  assert.ok(second.plan_cents > 0);
  assert.deepEqual(cards.reconcile(customer, card.id), { ok: true, mismatches: [] });
  assert.equal(bank.reconcile().ok, true);
}));

test("credit receivable and charges appear in the balanced daily close", () =>
  withCards(({ bank, cards, advance }) => {
    const card = cards.open(customer, 100_000, 15);
    cards.purchase(customer, card.id, "merchant-1", 20_000);
    advance("2026-11-16T12:00:00Z");
    const statement = cards.closeNext(customer, card.id);
    cards.pay(customer, card.id, statement.id, source, statement.minimum_due_cents);
    advance("2026-11-27T12:00:00Z");
    cards.accrue(customer, card.id, statement.id);
    const lines = bank.trialBalance();
    assert.equal(lines.find((line) => line.code === "1110").balance_cents,
      -cards.outstanding(customer, card.id));
    assert.ok(lines.find((line) => line.code === "3030").credit_cents > 0);
    assert.ok(lines.find((line) => line.code === "3040").credit_cents > 0);
    assert.equal(lines.reduce((sum, line) => sum + line.balance_cents, 0), 0);
    advance("2026-11-28T06:00:00Z");
    const close = bank.periodClose();
    assert.equal(bank.db.prepare("SELECT chart_version FROM period_closes WHERE brt_date=?")
      .get(close.brt_date).chart_version, 8);
    bank.db.prepare("UPDATE credit_card_statements SET due_cents=due_cents+1 WHERE id=?")
      .run(statement.id);
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
  }));

test("refund after full payment is a customer card credit liability", () =>
  withCards(({ bank, cards, advance }) => {
    const card = cards.open(customer, 30_000, 15);
    const purchase = cards.purchase(customer, card.id, "merchant-1", 10_000);
    advance("2026-11-16T12:00:00Z");
    const statement = cards.closeNext(customer, card.id);
    cards.pay(customer, card.id, statement.id, source, statement.due_cents);
    cards.refund(customer, card.id, purchase.id, 10_000);
    assert.equal(cards.outstanding(customer, card.id), -10_000);
    const lines = bank.trialBalance();
    assert.equal(lines.find((line) => line.code === "1110").balance_cents, 0);
    assert.equal(lines.find((line) => line.code === "2600").balance_cents, 10_000);
    assert.equal(lines.reduce((sum, line) => sum + line.balance_cents, 0), 0);
    assert.deepEqual(cards.reconcileAll(), { ok: true, accounts_checked: 1, mismatches: [] });
  }));
