import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "../apps/world/src/credit-cards.ts";
import { CardNetwork } from "../apps/world/src/ecosystem/card-network.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";

test("credit card uses network authorization, reserved limit, capture and invoice payment", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-credit-network-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1), deposit = seedAccountId(1);
    const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
    const cards = new CardsEngine(bank);
    const network = new CardNetwork(bank, cards);
    const account = credit.open(customer, 5_000, 15);
    const card = cards.issueCredit(customer, deposit, account.id);
    const depositBefore = bank.account(deposit).balance_cached;
    const authorize = (amount) => network.authorize({ cardId: card.id,
      merchantId: "shop_ipe", amountCents: amount, entryMode: "chip",
      cvv: cards.vault.currentCvv(card.id) });
    const first = authorize(4_000);
    assert.equal(first.response_code, "00");
    assert.equal(credit.availableLimit(customer, account.id), 1_000);
    assert.equal(authorize(1_500).response_code, "61");
    assert.equal(network.reverse(first.id).status, "reversed");
    assert.equal(credit.availableLimit(customer, account.id), 5_000);
    const second = authorize(4_000);
    assert.equal(network.capture(second.id, 3_500).status, "captured");
    assert.equal(network.capture(second.id, 3_500).status, "captured");
    assert.equal(bank.account(deposit).balance_cached, depositBefore);
    assert.equal(credit.outstanding(customer, account.id), 3_500);
    assert.equal(credit.availableLimit(customer, account.id), 1_500);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
    const lines = bank.trialBalance();
    assert.equal(lines.find((line) => line.code === "1110").balance_cents, -3_500);
    assert.equal(lines.find((line) => line.code === "1030").balance_cents, 3_500);
    cards.refund(second.id, card.id, 500);
    assert.equal(credit.outstanding(customer, account.id), 3_000);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
    now = new Date("2026-11-16T12:00:00Z");
    const statement = credit.closeNext(customer, account.id);
    assert.equal(statement.due_cents, 3_000);
    credit.pay(customer, account.id, statement.id, deposit, 3_000, "network-payment-1");
    assert.equal(credit.outstanding(customer, account.id), 0);
    assert.equal(bank.account(deposit).balance_cached, depositBefore - 3_000);
    assert.equal(credit.reconcileAll().ok, true);
    now = new Date("2026-11-17T06:00:00Z");
    assert.ok(bank.periodClose().brt_date);
    assert.equal(bank.reconcileCardSettlement().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("network installment selection allocates the captured credit purchase", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-credit-installments-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const cards = new CardsEngine(bank);
    const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
    const network = new CardNetwork(bank, cards);
    const account = credit.open(seedCustomerId(1), 10_000, 15);
    const creditCard = cards.issueCredit(seedCustomerId(1), seedAccountId(1), account.id);
    const auth = network.authorize({ cardId: creditCard.id, merchantId: "shop_ipe",
      amountCents: 3_001, installments: 3, entryMode: "chip",
      cvv: cards.vault.currentCvv(creditCard.id) });
    assert.equal(auth.response_code, "00");
    network.capture(auth.id, 3_001);
    assert.deepEqual(bank.db.prepare(`SELECT amount_cents FROM credit_card_installments
      ORDER BY installment_no`).all().map(({ amount_cents }) => amount_cents),
      [1_001, 1_000, 1_000]);
    const debit = cards.issueDebit(seedCustomerId(2), seedAccountId(2), 10_000);
    assert.throws(() => network.authorize({ cardId: debit.id, merchantId: "shop_ipe",
      amountCents: 1_000, installments: 2, entryMode: "chip",
      cvv: cards.vault.currentCvv(debit.id) }), /BIZ_INSTALLMENTS_CREDIT_ONLY/);
    assert.equal(credit.reconcileAll().ok, true);
    assert.equal(bank.reconcileCardSettlement().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

for (const winner of ["customer", "merchant"]) {
  test(`credit network dispute resolves for ${winner} with reconciled books`, () => {
    const dir = mkdtempSync(join(tmpdir(), `banco-vivo-credit-dispute-${winner}-`));
    const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"));
    try {
      seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
      const customer = seedCustomerId(1);
      const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
      const cards = new CardsEngine(bank);
      const network = new CardNetwork(bank, cards);
      const account = credit.open(customer, 5_000, 15);
      const card = cards.issueCredit(customer, seedAccountId(1), account.id);
      const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
        amountCents: 3_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
      assert.equal(auth.response_code, "00");
      network.capture(auth.id, 3_000);
      const dispute = network.openDispute(customer, auth.id, 1_000, "goods_not_received");
      assert.equal(dispute.status, "chargeback");
      assert.equal(credit.outstanding(customer, account.id), 3_000);
      assert.throws(() => cards.refund(auth.id, card.id, 500), /BIZ_DISPUTE_REFUND_CONFLICT/);
      network.advanceDispute(dispute.id, "representment");
      const resolved = network.resolveDispute(dispute.id, winner);
      assert.equal(resolved.status, winner === "customer" ? "customer_won" : "merchant_won");
      assert.equal(resolved.loss_cents, 0);
      assert.equal(credit.outstanding(customer, account.id), winner === "customer" ? 2_000 : 3_000);
      assert.equal(credit.reconcileAll().ok, true);
      assert.equal(bank.reconcileCardSettlement().ok, true);
      assert.equal(bank.reconcile().ok, true);
      assert.throws(() => network.resolveDispute(dispute.id, winner), /BIZ_DISPUTE_STAGE/);
    } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
  });
}

test("credit dispute after a paid invoice carries the customer win to the next invoice", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-credit-paid-dispute-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1), deposit = seedAccountId(1);
    const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
    const cards = new CardsEngine(bank);
    const network = new CardNetwork(bank, cards);
    const account = credit.open(customer, 5_000, 15);
    const card = cards.issueCredit(customer, deposit, account.id);
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 2_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    network.capture(auth.id, 2_000);
    now = new Date("2026-11-16T12:00:00Z");
    const statement = credit.closeNext(customer, account.id);
    credit.pay(customer, account.id, statement.id, deposit, 2_000, "paid-before-dispute");
    const dispute = network.openDispute(customer, auth.id, 500, "goods_not_received");
    network.advanceDispute(dispute.id, "representment");
    network.resolveDispute(dispute.id, "customer");
    assert.equal(credit.statement(customer, statement.id).paid_cents, 2_000);
    assert.equal(credit.account(customer, account.id).pending_credit_cents, 500);
    assert.equal(credit.outstanding(customer, account.id), -500);
    assert.equal(credit.reconcileAll().ok, true);
    assert.equal(bank.reconcileCardSettlement().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("credit purchase clears into a paid invoice and a later dispute with balanced books and no logged PAN", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-credit-full-cycle-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1), deposit = seedAccountId(1);
    const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
    const cards = new CardsEngine(bank);
    const network = new CardNetwork(bank, cards);
    const account = credit.open(customer, 10_000, 15);
    const card = cards.issueCredit(customer, deposit, account.id);
    const pan = bank.db.prepare("SELECT pan FROM card_vault WHERE card_id=?")
      .get(card.id).pan;
    assert.equal(card.last4, pan.slice(-4));
    assert.equal(JSON.stringify(card).includes(pan), false);
    const startingDeposit = bank.account(deposit).balance_cached;
    const authorization = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 3_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    assert.equal(authorization.response_code, "00");
    assert.equal(credit.availableLimit(customer, account.id), 7_000);
    assert.equal(bank.account(deposit).balance_cached, startingDeposit);
    now = new Date("2026-11-14T12:00:00Z");
    assert.deepEqual(network.clearDue(), { cleared: 1, failed: 0, expired: 0 });
    assert.equal(network.clearDue().cleared, 0);
    assert.equal(network.authorization(authorization.id).status, "captured");
    assert.equal(bank.reconcileCardSettlement().ok, true);
    now = new Date("2026-11-16T12:00:00Z");
    const statement = credit.closeNext(customer, account.id);
    assert.equal(statement.due_cents, 3_000);
    assert.equal(credit.pay(customer, account.id, statement.id, deposit,
      3_000, "full-cycle-payment").status, "paid");
    assert.equal(bank.account(deposit).balance_cached, startingDeposit - 3_000);
    const dispute = network.openDispute(customer, authorization.id, 1_000,
      "goods_not_received");
    assert.equal(credit.outstanding(customer, account.id), 0);
    network.advanceDispute(dispute.id, "representment");
    assert.equal(network.resolveDispute(dispute.id, "customer").status, "customer_won");
    assert.equal(credit.account(customer, account.id).pending_credit_cents, 1_000);
    assert.equal(credit.outstanding(customer, account.id), -1_000);
    assert.equal(credit.reconcileAll().ok, true);
    assert.equal(bank.reconcileCardSettlement().ok, true);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.trialBalance().reduce((sum, line) => sum + line.balance_cents, 0), 0);
    for (const table of ["telemetry_events", "card_network_messages", "access_log", "ledger_entries"])
      assert.equal(JSON.stringify(bank.db.prepare(`SELECT * FROM ${table}`).all()).includes(pan), false,
        `${table} exposed a full PAN`);
    now = new Date("2026-11-17T06:00:00Z");
    assert.ok(bank.periodClose().brt_date);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
