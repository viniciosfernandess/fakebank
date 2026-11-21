import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { CardNetwork } from "../apps/world/src/ecosystem/card-network.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";

function withNetwork(work, now = () => new Date("2026-11-13T12:00:00Z")) {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-network-"));
  const bank = new Bank(join(dir, "bank.sqlite"), now);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const cards = new CardsEngine(bank);
  const network = new CardNetwork(bank, cards);
  try { return work(bank, cards, network); }
  finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("daily close blocks settlement file drift even when ledger balances", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-settlement-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T06:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const cards = new CardsEngine(bank);
    const network = new CardNetwork(bank, cards);
    const card = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 1_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    network.capture(auth.id, 1_000);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
    assert.equal(bank.db.prepare(`SELECT balance_cents FROM card_acquirer_balances
      WHERE merchant_id='shop_ipe'`).get().balance_cents, 1_000);
    bank.db.prepare(`UPDATE card_acquirer_balances SET balance_cents=balance_cents+1
      WHERE merchant_id='shop_ipe'`).run();
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: false, mismatches: 1 });
    assert.ok(new SentinelEngine(bank).scan().some((item) =>
      item.rule_id === "S-LED-02" && item.entity === "card_settlement"));
    assert.throws(() => bank.periodClose(),
      (error) => error instanceof BankError && error.code === "INTEGRITY_PERIOD_CLOSE_BLOCKED");
    bank.db.prepare(`UPDATE card_acquirer_balances SET balance_cents=balance_cents-1
      WHERE merchant_id='shop_ipe'`).run();
    bank.db.prepare(`INSERT INTO card_settlement_file VALUES (?,?,?,?,?)`)
      .run("duplicate", "card_auth", auth.id, 1_000, bank.now().toISOString());
    assert.equal(bank.reconcileCardSettlement().ok, false);
    assert.throws(() => bank.periodClose(),
      (error) => error instanceof BankError && error.code === "INTEGRITY_PERIOD_CLOSE_BLOCKED");
    assert.throws(() => bank.db.prepare(`DELETE FROM card_settlement_file WHERE id='duplicate'`).run(),
      /CARD_SETTLEMENT_IMMUTABLE/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("network declines authorization when the linked account is frozen", () =>
  withNetwork((bank, cards, network) => {
    const account = seedAccountId(1);
    const card = cards.issueDebit(seedCustomerId(1), account, 10_000);
    const before = bank.account(account).balance_cached;
    bank.changeAccountStatus(account, "frozen", "reviewer", "fraud_suspect");
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 1_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    assert.equal(auth.status, "declined");
    assert.equal(auth.response_code, "05");
    assert.equal(bank.account(account).balance_cached, before);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM balance_holds
      WHERE account_id=?`).get(account).n, 0);
  }));

test("network authorization reserves available funds and capture posts only the cleared amount", () =>
  withNetwork((bank, cards, network) => {
    const account = seedAccountId(1);
    const card = cards.issueDebit(seedCustomerId(1), account, 10_000);
    const before = bank.account(account).balance_cached;
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe", amountCents: 1_000,
      entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    assert.equal(auth.response_code, "00");
    assert.equal(auth.status, "approved");
    assert.equal(auth.ledger_tx_id, null);
    assert.equal(bank.telemetry.list().find((event) => event.source === "cards" &&
      event.action === "authorize")?.card_token, card.id);
    assert.deepEqual(bank.telemetry.list().filter((event) => event.source === "network")
      .map((event) => [event.action, event.card_token]),
    [["mti_0100", card.id], ["mti_0110", card.id]]);
    const authorizationTrace = bank.telemetry.list().find((event) => event.source === "network" &&
      event.action === "mti_0100")?.trace_id;
    assert.deepEqual(new Set(bank.telemetry.trace(authorizationTrace).map((event) => event.source)),
      new Set(["risk", "network", "cards"]));
    assert.equal(bank.account(account).balance_cached, before);
    assert.equal(bank.availableBalance(account), before - 1_000);
    assert.deepEqual(network.messages(auth.id).map((message) => message.mti), ["0100", "0110"]);
    const captured = network.capture(auth.id, 700);
    assert.equal(bank.telemetry.list().find((event) => event.source === "network" &&
      event.action === "mti_0220")?.card_token, card.id);
    const captureTrace = bank.telemetry.list().find((event) => event.source === "network" &&
      event.action === "mti_0220")?.trace_id;
    assert.ok(bank.telemetry.trace(captureTrace).some((event) => event.source === "ledger"));
    assert.equal(captured.status, "captured");
    assert.equal(captured.captured_cents, 700);
    assert.equal(bank.account(account).balance_cached, before - 700);
    assert.equal(bank.availableBalance(account), before - 700);
    assert.equal(cards.card(card.id).used_cents, 700);
    assert.equal(network.capture(auth.id, 700).ledger_tx_id, captured.ledger_tx_id);
    assert.throws(() => network.capture(auth.id, 800),
      (error) => error instanceof BankError && error.code === "BIZ_CAPTURE_CONFLICT");
    cards.refund(auth.id, card.id, 700);
    assert.equal(bank.account(account).balance_cached, before);
    assert.equal(cards.card(card.id).used_cents, 0);
    assert.equal(bank.db.prepare(`SELECT balance_cents FROM card_acquirer_balances
      WHERE merchant_id='shop_ipe'`).get().balance_cents, 0);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
    assert.equal(bank.reconcile().ok, true);
    assert.equal(JSON.stringify(network.messages(auth.id)).includes("pan"), false);
  }));

test("a newly onboarded merchant receives its own reconciled acquirer position", () =>
  withNetwork((bank, cards, network) => {
    bank.db.prepare(`INSERT INTO card_merchants VALUES (?,?,?,?,?)`)
      .run("custom_market", "Custom Market", "5411", "BR", "active");
    const card = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
    const auth = network.authorize({ cardId: card.id, merchantId: "custom_market",
      amountCents: 500, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    network.capture(auth.id, 500);
    assert.equal(bank.db.prepare(`SELECT balance_cents FROM card_acquirer_balances
      WHERE merchant_id='custom_market'`).get().balance_cents, 500);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
  }));

test("acquirer book migrates existing captures and refunds only once", () =>
  withNetwork((bank, cards, network) => {
    const card = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 500, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    network.capture(auth.id, 500);
    cards.refund(auth.id, card.id, 200);
    bank.db.exec("DROP TABLE card_acquirer_balances");
    new CardNetwork(bank, cards);
    new CardNetwork(bank, cards);
    assert.equal(bank.db.prepare(`SELECT balance_cents FROM card_acquirer_balances
      WHERE merchant_id='shop_ipe'`).get().balance_cents, 300);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
  }));

test("network capture handles a bounded over-capture and reversal releases an unrelated hold", () =>
  withNetwork((bank, cards, network) => {
    const account = seedAccountId(1);
    const card = cards.issueDebit(seedCustomerId(1), account, 10_000);
    const before = bank.account(account).balance_cached;
    const first = network.authorize({ cardId: card.id, merchantId: "market_aroeira",
      amountCents: 1_000, entryMode: "contactless", cvv: cards.vault.currentCvv(card.id) });
    assert.equal(network.capture(first.id, 1_100).captured_cents, 1_100);
    const second = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 500, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    assert.equal(bank.availableBalance(account), before - 1_600);
    assert.equal(network.reverse(second.id).status, "reversed");
    assert.equal(network.reverse(second.id).status, "reversed");
    assert.equal(bank.availableBalance(account), before - 1_100);
    assert.equal(bank.account(account).balance_cached, before - 1_100);
    assert.equal(cards.card(card.id).used_cents, 1_100);
    assert.deepEqual(network.messages(second.id).map((message) => message.mti),
      ["0100", "0110", "0400"]);
    assert.throws(() => network.capture(second.id, 500),
      (error) => error instanceof BankError && error.code === "BIZ_CAPTURE_NOT_APPROVED");
  }));

test("expired network authorization releases limit usage without posting", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-expiry-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const cards = new CardsEngine(bank);
    const network = new CardNetwork(bank, cards);
    const account = seedAccountId(1);
    const card = cards.issueDebit(seedCustomerId(1), account, 10_000);
    const before = bank.account(account).balance_cached;
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 1_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    now = new Date(now.getTime() + 8 * 86_400_000);
    assert.throws(() => network.capture(auth.id, 1_000),
      (error) => error instanceof BankError && error.code === "BIZ_AUTH_EXPIRED");
    assert.equal(network.expirePending(), 1);
    assert.equal(network.authorization(auth.id).status, "expired");
    assert.equal(cards.card(card.id).used_cents, 0);
    assert.equal(bank.availableBalance(account), before);
    assert.equal(bank.account(account).balance_cached, before);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("batch clearing posts the queued capture once after the simulated day", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-clearing-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const cards = new CardsEngine(bank);
    const network = new CardNetwork(bank, cards);
    const account = seedAccountId(1);
    const card = cards.issueDebit(seedCustomerId(1), account, 10_000);
    const before = bank.account(account).balance_cached;
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 1_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    network.queueCapture(auth.id, 700);
    assert.deepEqual(network.clearDue(), { cleared: 0, failed: 0, expired: 0 });
    now = new Date(now.getTime() + 86_400_000);
    assert.deepEqual(network.clearDue(), { cleared: 1, failed: 0, expired: 0 });
    assert.equal(network.authorization(auth.id).captured_cents, 700);
    assert.equal(bank.account(account).balance_cached, before - 700);
    assert.deepEqual(network.clearDue(), { cleared: 0, failed: 0, expired: 0 });
    assert.deepEqual(network.messages(auth.id).map((message) => message.mti),
      ["0100", "0110", "0220"]);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("chargeback credits provisionally, follows representment and resolves without a double refund", () =>
  withNetwork((bank, cards, network) => {
    const customer = seedCustomerId(1);
    const account = seedAccountId(1);
    const card = cards.issueDebit(customer, account, 10_000);
    const initial = bank.account(account).balance_cached;
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 1_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    network.capture(auth.id, 1_000);
    assert.throws(() => network.openDispute(customer, auth.id, 800, "unknown"),
      (error) => error instanceof BankError && error.code === "BIZ_DISPUTE_REASON_INVALID");
    const dispute = network.openDispute(customer, auth.id, 800, "goods_not_received");
    assert.equal(dispute.reason_code, "goods_not_received");
    assert.equal(network.dispute(dispute.id).reason_code, "goods_not_received");
    const chargebackTrace = bank.telemetry.list().find((event) => event.source === "network" &&
      event.action === "mti_1440" && event.amount_cents === 800)?.trace_id;
    assert.ok(bank.telemetry.trace(chargebackTrace).some((event) => event.source === "ledger"));
    assert.equal(dispute.status, "chargeback");
    assert.equal(bank.account(account).balance_cached, initial - 200);
    assert.throws(() => cards.refund(auth.id, card.id, 800),
      (error) => error instanceof BankError && error.code === "BIZ_DISPUTE_REFUND_CONFLICT");
    assert.throws(() => network.openDispute(customer, auth.id, 100),
      (error) => error instanceof BankError && error.code === "BIZ_DISPUTE_EXISTS");
    assert.equal(network.advanceDispute(dispute.id, "representment").status, "representment");
    assert.equal(network.advanceDispute(dispute.id, "pre_arbitration").status, "pre_arbitration");
    assert.equal(network.resolveDispute(dispute.id, "customer").status, "customer_won");
    assert.equal(bank.account(account).balance_cached, initial - 200);
    assert.equal(cards.card(card.id).used_cents, 200);
    assert.throws(() => cards.refund(auth.id, card.id, 201),
      (error) => error instanceof BankError && error.code === "BIZ_REFUND_EXCEEDS_AUTH");
    cards.refund(auth.id, card.id, 200);
    assert.equal(bank.account(account).balance_cached, initial);
    assert.equal(cards.card(card.id).used_cents, 0);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
    assert.throws(() => network.resolveDispute(dispute.id, "merchant"),
      (error) => error instanceof BankError && error.code === "BIZ_DISPUTE_STAGE");
    assert.equal(bank.reconcile().ok, true);
    const pan = bank.db.prepare("SELECT pan FROM card_vault WHERE card_id=?")
      .get(card.id).pan;
    assert.equal(JSON.stringify(bank.telemetry.list()).includes(pan), false);
    assert.equal(JSON.stringify(network.messages(auth.id)).includes(pan), false);
  }));

test("merchant-winning chargeback reverses provisional credit and books an uncovered loss", () =>
  withNetwork((bank, cards, network) => {
    const customer = seedCustomerId(1);
    const account = seedAccountId(1);
    const card = cards.issueDebit(customer, account, 10_000);
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 1_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    network.capture(auth.id, 1_000);
    const dispute = network.openDispute(customer, auth.id, 1_000);
    assert.equal(dispute.reason_code, null);
    const available = bank.availableBalance(account);
    bank.post([
      { accountId: account, amount: -available, kind: "test_drain", actor: "test", refType: "test", refId: dispute.id },
      { accountId: bank.systemAccountId("fees"), amount: available, kind: "test_drain", actor: "test", refType: "test", refId: dispute.id },
    ]);
    network.advanceDispute(dispute.id, "representment");
    const final = network.resolveDispute(dispute.id, "merchant");
    assert.equal(final.loss_cents, 1_000);
    assert.equal(bank.account(account).balance_cached, 0);
    cards.refund(auth.id, card.id, 1_000);
    assert.equal(cards.card(card.id).used_cents, 0);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
    assert.equal(bank.reconcile().ok, true);
  }));

test("network declines a temporary card after its feature is disabled", () =>
  withNetwork((bank, cards, network) => {
    cards.features.setEnabled("cartao_virtual_temporario", true, "test");
    const parent = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
    const temporary = cards.createTemporaryVirtual(seedCustomerId(1), parent.id, 5_000);
    cards.features.setEnabled("cartao_virtual_temporario", false, "test");
    const result = network.authorize({ cardId: temporary.id, merchantId: "shop_ipe",
      amountCents: 100, entryMode: "ecommerce", eci: "05",
      cvv: cards.vault.currentCvv(temporary.id) });
    assert.equal(result.response_code, "05");
    assert.equal(cards.card(temporary.id).used_cents, 0);
  }));

test("customer-winning chargeback claws back the disputed purchase cashback", () =>
  withNetwork((bank, cards, network) => {
    cards.features.setEnabled("cashback", true, "test");
    cards.features.patchFlaw("cashback", "test");
    const customer = seedCustomerId(1);
    const parent = cards.issueDebit(customer, seedAccountId(1), 10_000);
    const card = cards.createVirtual(customer, parent.id, 5_000);
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 2_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    network.capture(auth.id, 2_000);
    const credited = bank.db.prepare(`SELECT credited_cents FROM cashback_records
      WHERE authorization_id=?`).get(auth.id).credited_cents;
    assert.ok(credited > 0);
    const dispute = network.openDispute(customer, auth.id, 2_000);
    network.advanceDispute(dispute.id, "representment");
    network.resolveDispute(dispute.id, "customer");
    assert.equal(bank.db.prepare(`SELECT clawed_back_cents FROM cashback_records
      WHERE authorization_id=?`).get(auth.id).clawed_back_cents, credited);
    assert.equal(cards.card(card.id).used_cents, 0);
    assert.equal(cards.card(parent.id).used_cents, 0);
    assert.equal(bank.reconcile().ok, true);
  }));

test("spent provisional credit books unrecovered cashback without a negative customer balance", () =>
  withNetwork((bank, cards, network) => {
    cards.features.setEnabled("cashback", true, "test");
    cards.features.patchFlaw("cashback", "test");
    const customer = seedCustomerId(1);
    const account = seedAccountId(1);
    const card = cards.issueDebit(customer, account, 10_000);
    const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 2_000, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
    network.capture(auth.id, 2_000);
    const credited = bank.db.prepare(`SELECT credited_cents FROM cashback_records
      WHERE authorization_id=?`).get(auth.id).credited_cents;
    const dispute = network.openDispute(customer, auth.id, 2_000);
    const priorLoss = bank.account(bank.systemAccountId("bank_loss")).balance_cached;
    const available = bank.availableBalance(account);
    bank.post([
      { accountId: account, amount: -available, kind: "test_drain", actor: "test", refType: "test", refId: dispute.id },
      { accountId: bank.systemAccountId("fees"), amount: available, kind: "test_drain", actor: "test", refType: "test", refId: dispute.id },
    ]);
    network.advanceDispute(dispute.id, "representment");
    network.resolveDispute(dispute.id, "customer");
    assert.equal(bank.account(account).balance_cached, 0);
    assert.equal(bank.db.prepare(`SELECT clawed_back_cents FROM cashback_records
      WHERE authorization_id=?`).get(auth.id).clawed_back_cents, credited);
    assert.equal(bank.account(bank.systemAccountId("bank_loss")).balance_cached,
      priorLoss - credited);
    assert.equal(bank.reconcile().ok, true);
  }));

test("network returns realistic decline codes without moving money", () => withNetwork((bank, cards, network) => {
  const card = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 1_000);
  const before = bank.account(seedAccountId(1)).balance_cached;
  const attempt = (amountCents, cvvOk = true, merchantId = "shop_ipe") =>
    network.authorize({ cardId: card.id, merchantId, amountCents, entryMode: "ecommerce",
      eci: "05", cvv: cvvOk ? cards.vault.currentCvv(card.id) : "invalid" });
  const invalidCvv = attempt(100, false);
  assert.equal(invalidCvv.response_code, "N7");
  assert.equal(bank.db.prepare("SELECT risk_blocked FROM card_network_authorizations WHERE id=?")
    .get(invalidCvv.id).risk_blocked, 0);
  assert.equal(attempt(1_001).response_code, "61");
  const foreignDisabled = attempt(100, true, "online_global");
  assert.equal(foreignDisabled.response_code, "57");
  assert.equal(bank.db.prepare("SELECT risk_blocked FROM card_network_authorizations WHERE id=?")
    .get(foreignDisabled.id).risk_blocked, 0);
  for (let index = 0; index < 7; index++) attempt(100, false);
  const riskBlocked = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
    amountCents: 100, entryMode: "ecommerce", eci: "07",
    cvv: cards.vault.currentCvv(card.id) });
  assert.equal(riskBlocked.response_code, "05");
  assert.equal(bank.db.prepare("SELECT risk_blocked FROM card_network_authorizations WHERE id=?")
    .get(riskBlocked.id).risk_blocked, 1);
  assert.equal(attempt(100).response_code, "65");
  assert.equal(bank.account(seedAccountId(1)).balance_cached, before);
  assert.equal(bank.availableBalance(seedAccountId(1)), before);
}));

test("repeated card network declines alert on the fifth same-merchant response", () =>
  withNetwork((bank, cards, network) => {
    const card = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
    const sentinel = new SentinelEngine(bank);
    const attempt = () => network.authorize({ cardId: card.id,
      merchantId: "shop_ipe", amountCents: 100, entryMode: "ecommerce",
      eci: "05", cvv: "invalid" });
    for (let index = 0; index < 4; index++)
      assert.equal(attempt().status, "declined");
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-CARD-09"), false);
    assert.equal(attempt().status, "declined");
    const alert = sentinel.scan().find((item) => item.rule_id === "S-CARD-09");
    assert.equal(alert?.entity, card.id);
    assert.equal(alert?.observed.merchant, "shop_ipe");
    assert.equal(alert?.observed.network_declines, 5);
    for (const [source, action] of [["network", "mti_0100"],
      ["network", "mti_0110"], ["cards", "authorize"]])
      assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
        WHERE source=? AND action=? AND card_token=?`)
        .get(source, action, card.id).n, 5);
    assert.equal(bank.reconcileCardSettlement().ok, true);
  }));

test("repeated card captures alert on the third same-merchant settlement", () =>
  withNetwork((bank, cards, network) => {
    const card = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
    const sentinel = new SentinelEngine(bank);
    const capture = () => {
      const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
        amountCents: 100, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
      network.capture(auth.id, 100);
    };
    capture(); capture();
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-CARD-10"), false);
    capture();
    const alert = sentinel.scan().find((item) => item.rule_id === "S-CARD-10");
    assert.equal(alert?.entity, card.id);
    assert.equal(alert?.observed.captures, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='network' AND action='mti_0220' AND card_token=?`)
      .get(card.id).n, 3);
    assert.equal(bank.reconcileCardSettlement().ok, true);
  }));

test("repeated card reversals alert on the third same-merchant reversal", () =>
  withNetwork((bank, cards, network) => {
    const card = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
    const sentinel = new SentinelEngine(bank);
    const reverse = () => {
      const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
        amountCents: 100, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
      network.reverse(auth.id);
    };
    reverse(); reverse();
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-CARD-11"), false);
    reverse();
    const alert = sentinel.scan().find((item) => item.rule_id === "S-CARD-11");
    assert.equal(alert?.entity, card.id);
    assert.equal(alert?.observed.reversals, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='network' AND action='mti_0400' AND card_token=?`)
      .get(card.id).n, 3);
    assert.equal(bank.reconcileCardSettlement().ok, true);
  }));

test("distinct card disputes alert on the third case without counting its stages", () =>
  withNetwork((bank, cards, network) => {
    const customer = seedCustomerId(1);
    const card = cards.issueDebit(customer, seedAccountId(1), 10_000);
    const sentinel = new SentinelEngine(bank);
    const dispute = () => {
      const auth = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
        amountCents: 100, entryMode: "chip", cvv: cards.vault.currentCvv(card.id) });
      network.capture(auth.id, 100);
      return network.openDispute(customer, auth.id, 100, "goods_not_received");
    };
    const first = dispute();
    dispute();
    network.advanceDispute(first.id, "representment");
    network.advanceDispute(first.id, "pre_arbitration");
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-CARD-12"), false);
    dispute();
    const alert = sentinel.scan().find((item) => item.rule_id === "S-CARD-12");
    assert.equal(alert?.entity, card.id);
    assert.equal(alert?.observed.disputes, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='network' AND action='mti_1440' AND card_token=?`)
      .get(card.id).n, 5);
    assert.equal(bank.reconcileCardSettlement().ok, true);
  }));

test("lost and stolen cards return terminal network codes without reserving funds", () =>
  withNetwork((bank, cards, network) => {
    const customer = seedCustomerId(1), account = seedAccountId(1);
    const lost = cards.issueDebit(customer, account, 10_000);
    const stolen = cards.issueDebit(customer, account, 10_000);
    const virtual = cards.createVirtual(customer, stolen.id, 2_000);
    const before = bank.account(account).balance_cached;
    cards.update(customer, lost.id, { status: "lost" });
    cards.update(customer, stolen.id, { status: "stolen" });
    const attempt = (cardId, cvv) => network.authorize({ cardId,
      merchantId: "shop_ipe", amountCents: 100, entryMode: "chip", cvv });
    assert.equal(attempt(lost.id, cards.vault.currentCvv(lost.id)).response_code, "41");
    assert.equal(attempt(virtual.id, cards.vault.currentCvv(virtual.id)).response_code, "43");
    assert.throws(() => cards.update(customer, lost.id, { status: "active" }),
      (error) => error instanceof BankError && error.code === "BIZ_CARD_REPLACEMENT_REQUIRED");
    assert.throws(() => cards.update(customer, stolen.id, { status: "blocked" }),
      (error) => error instanceof BankError && error.code === "BIZ_CARD_REPLACEMENT_REQUIRED");
    assert.equal(bank.account(account).balance_cached, before);
    assert.equal(bank.availableBalance(account), before);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM balance_holds WHERE account_id=?")
      .get(account).n, 0);
    assert.equal(bank.reconcile().ok, true);
  }));

test("unknown card and issuer outage produce private durable declines without financial writes", () =>
  withNetwork((bank, cards, network) => {
    const account = seedAccountId(1);
    const card = cards.issueDebit(seedCustomerId(1), account, 10_000);
    const before = bank.account(account).balance_cached;
    const ledgerBefore = bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n;
    const unknownToken = "missing_card_token_for_private_decline";
    const input = { merchantId: "shop_ipe", amountCents: 100, entryMode: "chip",
      cvv: "000" };
    const unknown = network.authorize({ ...input, cardId: unknownToken });
    assert.equal(unknown.response_code, "14");
    assert.equal(unknown.status, "declined");
    assert.equal("card_id" in unknown, false);
    assert.deepEqual(network.messages(unknown.id), []);
    assert.throws(() => network.authorization(unknown.id),
      (error) => error instanceof BankError && error.code === "DEF_NOT_FOUND");
    assert.equal(network.setIssuerAvailability(false, "admin_one").available, false);
    const outage = network.authorize({ ...input, cardId: card.id });
    assert.equal(outage.response_code, "91");
    assert.equal("card_id" in outage, false);
    assert.equal(new CardNetwork(bank, cards).issuerAvailability().available, false);
    assert.deepEqual(bank.db.prepare(`SELECT response_code FROM card_network_rejections
      ORDER BY rowid`).all().map((row) => row.response_code), ["14", "91"]);
    assert.deepEqual(bank.db.prepare(`SELECT card_id FROM card_network_rejections
      ORDER BY rowid`).all().map((row) => row.card_id), [null, card.id],
      "only a known card may be linked in the private rejection record");
    assert.throws(() => bank.db.prepare(`UPDATE card_network_rejections
      SET response_code='14' WHERE id=?`).run(outage.id), /CARD_NETWORK_REJECTION_IMMUTABLE/);
    assert.equal(JSON.stringify(bank.telemetry.list()).includes(unknownToken), false);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n, ledgerBefore);
    assert.equal(bank.account(account).balance_cached, before);
    assert.equal(bank.availableBalance(account), before);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM balance_holds WHERE account_id=?")
      .get(account).n, 0);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(network.setIssuerAvailability(true, "admin_one").available, true);
    const resumed = network.authorize({ ...input, cardId: card.id,
      cvv: cards.vault.currentCvv(card.id) });
    assert.equal(resumed.response_code, "00");
    network.reverse(resumed.id);
  }));

test("legacy network declines retain unknown card provenance after migration", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-rejection-migration-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-13T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const cards = new CardsEngine(bank);
    bank.db.exec(`CREATE TABLE card_merchants (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, mcc TEXT NOT NULL,
      country TEXT NOT NULL, status TEXT NOT NULL);
      CREATE TABLE card_network_rejections (
      id TEXT PRIMARY KEY, merchant_id TEXT NOT NULL,
      amount_cents INTEGER NOT NULL, response_code TEXT NOT NULL,
      created_at TEXT NOT NULL);`);
    bank.db.prepare("INSERT INTO card_merchants VALUES (?,?,?,?,?)")
      .run("shop_ipe", "Loja Ipê", "5411", "BR", "active");
    bank.db.prepare("INSERT INTO card_network_rejections VALUES (?,?,?,?,?)")
      .run("legacy_decline", "shop_ipe", 100, "91", "2026-11-13T11:59:00Z");
    new CardNetwork(bank, cards);
    const legacy = bank.db.prepare(`SELECT card_id,response_code
      FROM card_network_rejections WHERE id='legacy_decline'`).get();
    assert.equal(legacy.card_id, null);
    assert.equal(legacy.response_code, "91");
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a newly bound device reactivates a blocked card with a temporary effective limit", () => {
  let now = new Date("2026-11-13T12:00:00Z");
  withNetwork((bank, cards, network) => {
    const customer = seedCustomerId(1), account = seedAccountId(1);
    const card = cards.issueDebit(customer, account, 100_000);
    cards.authorize(card.id, "prior_merchant", 30_000);
    assert.equal(cards.card(card.id).used_cents, 30_000);
    cards.update(customer, card.id, { status: "blocked" });
    const auth = new AuthEngine(bank);
    const device = auth.enrolDevice(customer, "reactivation_device", "127.0.0.1");
    bank.db.prepare("UPDATE auth_devices SET bound_at=? WHERE id=?")
      .run(bank.now().toISOString(), device);
    assert.throws(() => cards.update(customer, card.id,
      { status: "active", limit_cents: 20_000 }),
      (error) => error instanceof BankError && error.code === "BIZ_INVALID_CARD_PATCH");
    const restored = cards.update(customer, card.id, { status: "active" }, device);
    assert.equal(restored.status, "active");
    assert.equal(restored.limit_cents, 100_000);
    assert.equal(restored.effective_limit_cents, 50_000);
    assert.equal(cards.list(customer).find((item) => item.id === card.id).effective_limit_cents, 50_000);
    assert.equal(cards.effectiveLimit(restored), 50_000);
    assert.equal(bank.db.prepare(`SELECT baseline_used_cents,cap_cents
      FROM card_reactivation_caps WHERE card_id=?`).get(card.id).baseline_used_cents, 30_000);
    assert.deepEqual(bank.db.prepare(`SELECT field,old_value,new_value FROM card_changes
      WHERE card_id=? ORDER BY rowid DESC LIMIT 1`).all(card.id).map((row) => ({ ...row })),
    [{ field: "status", old_value: "blocked", new_value: "active" }]);
    const cvv = cards.vault.currentCvv(card.id);
    assert.throws(() => cards.authorize(card.id, "legacy_merchant", 20_001),
      (error) => error instanceof BankError && error.code === "BIZ_CARD_LIMIT");
    assert.equal(network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 20_001, entryMode: "chip", cvv }).response_code, "61");
    const approved = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 20_000, entryMode: "chip", cvv });
    assert.equal(approved.response_code, "00");
    network.reverse(approved.id);
    const parent = cards.issueDebit(customer, account, 100_000);
    cards.createVirtual(customer, parent.id, 30_000);
    cards.update(customer, parent.id, { status: "blocked" });
    assert.equal(cards.update(customer, parent.id, { status: "active" }, device).status, "active");
    assert.throws(() => cards.createVirtual(customer, parent.id, 1_000),
      (error) => error instanceof BankError && error.code === "BIZ_PARENT_LIMIT");
    now = new Date("2026-11-14T11:59:59.999Z");
    assert.equal(cards.effectiveLimit(cards.card(card.id)), 50_000);
    now = new Date("2026-11-14T12:00:00.000Z");
    assert.equal(cards.effectiveLimit(cards.card(card.id)), 100_000);
    assert.equal(cards.card(card.id).effective_limit_cents, 100_000);
    const later = network.authorize({ cardId: card.id, merchantId: "shop_ipe",
      amountCents: 20_001, entryMode: "chip", cvv });
    assert.equal(later.response_code, "00");
    network.reverse(later.id);
    assert.throws(() => bank.db.prepare("DELETE FROM card_reactivation_caps WHERE card_id=?")
      .run(card.id), /CARD_REACTIVATION_CAP_IMMUTABLE/);
    assert.equal(bank.reconcile().ok, true);
  }, () => now);
});

test("vault keeps Luhn PAN out of card responses and rotates virtual CVV", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-vault-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const cards = new CardsEngine(bank);
    const network = new CardNetwork(bank, cards);
    const debit = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
    const virtual = cards.createVirtual(seedCustomerId(1), debit.id, 5_000);
    const pan = bank.db.prepare("SELECT pan FROM card_vault WHERE card_id=?")
      .get(virtual.id).pan;
    assert.match(pan, /^\d{16}$/);
    let sum = 0;
    for (let index = 0; index < 16; index++) {
      let digit = Number(pan[index]);
      if (index % 2 === 0) { digit *= 2; if (digit > 9) digit -= 9; }
      sum += digit;
    }
    assert.equal(sum % 10, 0);
    assert.equal(virtual.last4, pan.slice(-4));
    assert.equal(JSON.stringify(cards.list(seedCustomerId(1))).includes(pan), false);
    assert.equal(JSON.stringify(network.authorization(network.authorize({
      cardId: virtual.id, merchantId: "shop_ipe", amountCents: 100,
      entryMode: "ecommerce", eci: "05", cvv: cards.vault.currentCvv(virtual.id),
    }).id)).includes(pan), false);
    const oldCvv = cards.vault.currentCvv(virtual.id);
    for (let attempts = 0; attempts < 10 && cards.vault.currentCvv(virtual.id) === oldCvv; attempts++)
      now = new Date(now.getTime() + 900_000);
    assert.notEqual(cards.vault.currentCvv(virtual.id), oldCvv);
    assert.equal(cards.vault.verifyCvv(virtual.id, oldCvv), false);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("network routes require partner credentials and expose only the owner's authorization", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-network-api-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const cards = new CardsEngine(bank);
  const card = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
  const virtual = cards.createVirtual(seedCustomerId(1), card.id, 5_000);
  const auth = new AuthEngine(bank);
  auth.setPassword(seedCustomerId(1), "a-strong-test-password");
  const app = createTwinApi(bank, auth, { partnerKey: "test-partner" });
  try {
    const initialBalance = bank.account(seedAccountId(1)).balance_cached;
    const body = { card_id: card.id, merchant_id: "shop_ipe", amount_cents: 500,
      entry_mode: "chip", cvv: cards.vault.currentCvv(card.id) };
    assert.equal((await app.inject({ method: "POST", url: "/cards/network/authorize",
      payload: body })).statusCode, 403);
    assert.equal((await app.inject({ method: "POST", url: "/cards/authorize",
      headers: { "x-partner-key": "test-partner" }, payload: {
        card_id: card.id, merchant_id: "shop_ipe", amount_cents: 500 } })).statusCode, 404);
    const unknown = await app.inject({ method: "POST", url: "/cards/network/authorize",
      headers: { "x-partner-key": "test-partner" },
      payload: { ...body, card_id: "unknown_card_token" } });
    assert.equal(unknown.statusCode, 200);
    assert.equal(unknown.json().response_code, "14");
    assert.equal(JSON.stringify(unknown.json()).includes("unknown_card_token"), false);
    const approved = await app.inject({ method: "POST", url: "/cards/network/authorize",
      headers: { "x-partner-key": "test-partner" }, payload: body });
    assert.equal(approved.statusCode, 200);
    assert.equal(approved.json().response_code, "00");
    assert.equal(approved.json().amount_cents, 500);
    assert.equal(bank.account(seedAccountId(1)).balance_cached, initialBalance);
    assert.equal(bank.availableBalance(seedAccountId(1)), initialBalance - 500);
    const login = await app.inject({ method: "POST", url: "/auth/login", payload: {
      cpf: bank.customer(seedCustomerId(1)).cpf, password: "a-strong-test-password",
      device_id: "card-network-device" } });
    const challenge = login.json().challenge_id;
    const otp = await app.inject({ method: "POST", url: "/auth/otp/verify", payload: {
      challenge_id: challenge, otp: auth.simulatedOtp(challenge, seedCustomerId(1)) } });
    const headers = { authorization: `Bearer ${otp.json().access_token}` };
    const cvvUrl = `/cards/${virtual.id}/cvv`;
    assert.equal((await app.inject({ method: "GET", url: cvvUrl, headers })).statusCode, 403);
    const stepUp = await app.inject({ method: "POST", url: "/auth/step-up", headers,
      payload: { password: "a-strong-test-password" } });
    assert.equal(stepUp.statusCode, 200);
    const unboundOperations = [
      { method: "POST", url: "/cards", payload: { account_id: seedAccountId(1), limit_cents: 500 } },
      { method: "POST", url: `/cards/${card.id}/virtual`, payload: { limit_cents: 500 } },
      { method: "POST", url: `/cards/${card.id}/temporary`, payload: { limit_cents: 500 } },
      { method: "GET", url: cvvUrl },
      { method: "PATCH", url: `/cards/${card.id}`, payload: { online_enabled: false } },
      { method: "POST", url: `/cards/network/${approved.json().id}/dispute`, payload: { amount_cents: 200 } },
    ];
    for (const operation of unboundOperations) {
      const response = await app.inject({ ...operation, headers });
      assert.equal(response.statusCode, 403, operation.url);
      assert.equal(response.json().error, "DEF_DEVICE_PROOF_INVALID");
    }
    const privateKey = await bindDeviceKey(app, headers);
    const lost = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 5_000);
    const lostUrl = `/cards/${lost.id}`;
    const lostBody = { status: "lost" };
    const markedLost = await app.inject({ method: "PATCH", url: lostUrl,
      headers: await signedOperationHeaders(app, headers, privateKey, lostUrl, lostBody, "PATCH"),
      payload: lostBody });
    assert.equal(markedLost.statusCode, 200, markedLost.body);
    const lostAttempt = await app.inject({ method: "POST", url: "/cards/network/authorize",
      headers: { "x-partner-key": "test-partner" },
      payload: { ...body, card_id: lost.id, cvv: cards.vault.currentCvv(lost.id) } });
    assert.equal(lostAttempt.statusCode, 200);
    assert.equal(lostAttempt.json().response_code, "41");
    const cvvResponse = await app.inject({ method: "GET", url: cvvUrl,
      headers: await signedOperationHeaders(app, headers, privateKey, cvvUrl, undefined, "GET") });
    assert.equal(cvvResponse.statusCode, 200);
    assert.equal(cvvResponse.headers["cache-control"], "no-store");
    assert.equal(cvvResponse.json().cvv, cards.vault.currentCvv(virtual.id));
    assert.equal(JSON.stringify(cvvResponse.json()).includes("pan"), false);
    const view = await app.inject({ method: "GET",
      url: `/cards/network/${approved.json().id}`, headers });
    assert.equal(view.statusCode, 200);
    assert.deepEqual(view.json().messages.map((message) => message.mti), ["0100", "0110"]);
    const capture = await app.inject({ method: "POST",
      url: `/cards/network/${approved.json().id}/capture`,
      headers: { "x-partner-key": "test-partner" }, payload: { amount_cents: 400 } });
    assert.equal(capture.statusCode, 200);
    assert.equal(capture.json().captured_cents, 400);
    assert.equal(bank.account(seedAccountId(1)).balance_cached, initialBalance - 400);
    const disputeUrl = `/cards/network/${approved.json().id}/dispute`;
    const disputeBody = { amount_cents: 200 };
    assert.equal((await app.inject({ method: "POST", url: disputeUrl, headers,
      payload: disputeBody })).statusCode, 403);
    assert.equal(bank.account(seedAccountId(1)).balance_cached, initialBalance - 400);
    const alteredProof = await signedOperationHeaders(app, headers, privateKey, disputeUrl, disputeBody);
    assert.equal((await app.inject({ method: "POST", url: disputeUrl, headers: alteredProof,
      payload: { amount_cents: 201 } })).statusCode, 403);
    const disputeHeaders = await signedOperationHeaders(app, headers, privateKey, disputeUrl, disputeBody);
    const dispute = await app.inject({ method: "POST", url: disputeUrl,
      headers: disputeHeaders, payload: disputeBody });
    assert.equal((await app.inject({ method: "POST", url: disputeUrl,
      headers: disputeHeaders, payload: disputeBody })).statusCode, 403);
    assert.equal(dispute.statusCode, 200);
    assert.equal(dispute.json().amount_cents, 200);
    assert.equal(dispute.json().status, "chargeback");
    assert.equal(bank.account(seedAccountId(1)).balance_cached, initialBalance - 200);
    const disputeId = dispute.json().id;
    const disputeView = await app.inject({ method: "GET",
      url: `/cards/disputes/${disputeId}`, headers });
    const representment = await app.inject({ method: "POST",
      url: `/cards/disputes/${disputeId}/advance`,
      headers: { "x-partner-key": "test-partner" }, payload: { stage: "representment" } });
    const preArbitration = await app.inject({ method: "POST",
      url: `/cards/disputes/${disputeId}/advance`,
      headers: { "x-partner-key": "test-partner" }, payload: { stage: "pre_arbitration" } });
    const resolved = await app.inject({ method: "POST",
      url: `/cards/disputes/${disputeId}/resolve`,
      headers: { "x-partner-key": "test-partner" }, payload: { winner: "customer" } });
    const refund = await app.inject({ method: "POST", url: "/cards/refund",
      headers: { "x-partner-key": "test-partner" }, payload: {
        authorization_id: approved.json().id, target_card_id: card.id, amount_cents: 200 } });
    const list = await app.inject({ method: "GET", url: "/cards", headers });
    for (const response of [disputeView, representment, preArbitration, resolved, refund, list])
      assert.equal(response.statusCode, 200, response.body);
    assert.equal(resolved.json().status, "customer_won");
    assert.equal(bank.account(seedAccountId(1)).balance_cached, initialBalance);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
    const threeDsPath = "/cards/3ds/challenges";
    const threeDsBody = { card_id: virtual.id, merchant_id: "shop_ipe", amount_cents: 300 };
    const unauthenticated = await app.inject({ method: "POST",
      url: "/cards/network/authorize", headers: { "x-partner-key": "test-partner" },
      payload: { card_id: virtual.id, merchant_id: "shop_ipe", amount_cents: 300,
        entry_mode: "ecommerce", eci: "05", cvv: cards.vault.currentCvv(virtual.id) } });
    assert.equal(unauthenticated.json().response_code, "05");
    assert.equal((await app.inject({ method: "POST", url: threeDsPath,
      headers, payload: threeDsBody })).statusCode, 403);
    const issuedThreeDs = await app.inject({ method: "POST", url: threeDsPath,
      headers: await signedOperationHeaders(app, headers, privateKey, threeDsPath, threeDsBody),
      payload: threeDsBody });
    assert.equal(issuedThreeDs.statusCode, 200, issuedThreeDs.body);
    const threeDs = issuedThreeDs.json();
    const completePath = `/cards/3ds/challenges/${threeDs.id}/complete`;
    const completeBody = { nonce: threeDs.nonce };
    assert.equal((await app.inject({ method: "POST", url: completePath,
      headers, payload: completeBody })).statusCode, 403);
    const complete = await app.inject({ method: "POST", url: completePath,
      headers: await signedOperationHeaders(app, headers, privateKey, completePath, completeBody),
      payload: completeBody });
    assert.equal(complete.statusCode, 200, complete.body);
    assert.equal(complete.json().authenticated, true);
    const repeatedCompletion = await app.inject({ method: "POST", url: completePath,
      headers: await signedOperationHeaders(app, headers, privateKey, completePath, completeBody),
      payload: completeBody });
    assert.equal(repeatedCompletion.statusCode, 403);
    const authenticatedBody = { card_id: virtual.id, merchant_id: "shop_ipe",
      amount_cents: 300, entry_mode: "ecommerce", eci: "05",
      cvv: cards.vault.currentCvv(virtual.id), three_ds_challenge_id: threeDs.id };
    for (const altered of [
      { ...authenticatedBody, card_id: card.id, cvv: cards.vault.currentCvv(card.id) },
      { ...authenticatedBody, merchant_id: "market_aroeira" },
      { ...authenticatedBody, amount_cents: 301 },
    ]) {
      const mismatch = await app.inject({ method: "POST", url: "/cards/network/authorize",
        headers: { "x-partner-key": "test-partner" }, payload: altered });
      assert.equal(mismatch.json().response_code, "05");
    }
    const beforeLimitDecline = cards.card(virtual.id).used_cents;
    bank.db.prepare("UPDATE cards SET used_cents=limit_cents WHERE id=?").run(virtual.id);
    const limited = await app.inject({ method: "POST", url: "/cards/network/authorize",
      headers: { "x-partner-key": "test-partner" }, payload: authenticatedBody });
    assert.equal(limited.json().response_code, "61");
    assert.equal(bank.db.prepare("SELECT status FROM card_3ds_challenges WHERE id=?")
      .get(threeDs.id).status, "completed");
    bank.db.prepare("UPDATE cards SET used_cents=? WHERE id=?").run(beforeLimitDecline, virtual.id);
    const virtualApproved = await app.inject({ method: "POST",
      url: "/cards/network/authorize", headers: { "x-partner-key": "test-partner" },
      payload: authenticatedBody });
    assert.equal(virtualApproved.statusCode, 200);
    assert.equal(virtualApproved.json().response_code, "00");
    const replay = await app.inject({ method: "POST", url: "/cards/network/authorize",
      headers: { "x-partner-key": "test-partner" }, payload: authenticatedBody });
    assert.equal(replay.json().response_code, "05");
    assert.equal(bank.db.prepare(`SELECT status FROM card_3ds_challenges WHERE id=?`)
      .get(threeDs.id).status, "consumed");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM card_3ds_events
      WHERE challenge_id=? AND action='consumed'`).get(threeDs.id).n, 1);
    assert.equal(JSON.stringify(bank.db.prepare(`SELECT * FROM card_3ds_challenges WHERE id=?`)
      .get(threeDs.id)).includes(threeDs.nonce), false);
    assert.throws(() => bank.db.prepare(`DELETE FROM card_3ds_events
      WHERE challenge_id=?`).run(threeDs.id), /CARD_3DS_EVENT_IMMUTABLE/);
    const failedIssue = await app.inject({ method: "POST", url: threeDsPath,
      headers: await signedOperationHeaders(app, headers, privateKey, threeDsPath, threeDsBody),
      payload: threeDsBody });
    assert.equal(failedIssue.statusCode, 200, failedIssue.body);
    const failedId = failedIssue.json().id;
    const failedPath = `/cards/3ds/challenges/${failedId}/complete`;
    const wrongNonce = { nonce: "A".repeat(43) };
    const failedCompletion = await app.inject({ method: "POST", url: failedPath,
      headers: await signedOperationHeaders(app, headers, privateKey, failedPath, wrongNonce),
      payload: wrongNonce });
    assert.equal(failedCompletion.statusCode, 403);
    assert.equal(bank.db.prepare(`SELECT status FROM card_3ds_challenges WHERE id=?`)
      .get(failedId).status, "failed");
    assert.equal(bank.db.prepare(`SELECT reason FROM card_3ds_events
      WHERE challenge_id=? AND action='complete_denied'`).get(failedId).reason,
      "nonce_mismatch");
    const expiredIssue = await app.inject({ method: "POST", url: threeDsPath,
      headers: await signedOperationHeaders(app, headers, privateKey, threeDsPath, threeDsBody),
      payload: threeDsBody });
    assert.equal(expiredIssue.statusCode, 200, expiredIssue.body);
    const expired = expiredIssue.json();
    bank.db.prepare(`UPDATE card_3ds_challenges SET expires_at=? WHERE id=?`)
      .run(new Date(0).toISOString(), expired.id);
    const expiredPath = `/cards/3ds/challenges/${expired.id}/complete`;
    const expiredBody = { nonce: expired.nonce };
    const expiredCompletion = await app.inject({ method: "POST", url: expiredPath,
      headers: await signedOperationHeaders(app, headers, privateKey, expiredPath, expiredBody),
      payload: expiredBody });
    assert.equal(expiredCompletion.statusCode, 403);
    assert.equal(bank.db.prepare(`SELECT reason FROM card_3ds_events
      WHERE challenge_id=? AND action='complete_denied'`).get(expired.id).reason,
      "expired");
    const expiringIssue = await app.inject({ method: "POST", url: threeDsPath,
      headers: await signedOperationHeaders(app, headers, privateKey, threeDsPath, threeDsBody),
      payload: threeDsBody });
    assert.equal(expiringIssue.statusCode, 200, expiringIssue.body);
    const expiring = expiringIssue.json();
    const expiringPath = `/cards/3ds/challenges/${expiring.id}/complete`;
    const expiringBody = { nonce: expiring.nonce };
    assert.equal((await app.inject({ method: "POST", url: expiringPath,
      headers: await signedOperationHeaders(app, headers, privateKey, expiringPath, expiringBody),
      payload: expiringBody })).statusCode, 200);
    bank.db.prepare(`UPDATE card_3ds_challenges SET expires_at=? WHERE id=?`)
      .run(new Date(0).toISOString(), expiring.id);
    const expiredAuthorization = await app.inject({ method: "POST",
      url: "/cards/network/authorize", headers: { "x-partner-key": "test-partner" },
      payload: { ...authenticatedBody, three_ds_challenge_id: expiring.id } });
    assert.equal(expiredAuthorization.json().response_code, "05");
    assert.equal(virtualApproved.json().amount_cents, 300);
    assert.equal(bank.account(seedAccountId(1)).balance_cached, initialBalance);
    assert.equal(bank.availableBalance(seedAccountId(1)), initialBalance - 300);
    const virtualId = virtualApproved.json().id;
    const virtualCapture = await app.inject({ method: "POST",
      url: `/cards/network/${virtualId}/capture`,
      headers: { "x-partner-key": "test-partner" }, payload: { amount_cents: 300 } });
    assert.equal(virtualCapture.statusCode, 200);
    assert.equal(virtualCapture.json().captured_cents, 300);
    assert.equal(bank.account(seedAccountId(1)).balance_cached, initialBalance - 300);
    const virtualView = await app.inject({ method: "GET",
      url: `/cards/network/${virtualId}`, headers });
    const virtualDisputeUrl = `/cards/network/${virtualId}/dispute`;
    const virtualDisputeBody = { amount_cents: 100, reason_code: "fraud" };
    const virtualDispute = await app.inject({ method: "POST", url: virtualDisputeUrl,
      headers: await signedOperationHeaders(app, headers, privateKey, virtualDisputeUrl, virtualDisputeBody),
      payload: virtualDisputeBody });
    assert.equal(virtualDispute.statusCode, 200);
    assert.equal(virtualDispute.json().amount_cents, 100);
    assert.equal(virtualDispute.json().reason_code, "fraud");
    assert.equal(virtualDispute.json().status, "chargeback");
    assert.equal(bank.account(seedAccountId(1)).balance_cached, initialBalance - 200);
    const virtualDisputeId = virtualDispute.json().id;
    const virtualRepresentment = await app.inject({ method: "POST",
      url: `/cards/disputes/${virtualDisputeId}/advance`,
      headers: { "x-partner-key": "test-partner" }, payload: { stage: "representment" } });
    const virtualPreArbitration = await app.inject({ method: "POST",
      url: `/cards/disputes/${virtualDisputeId}/advance`,
      headers: { "x-partner-key": "test-partner" }, payload: { stage: "pre_arbitration" } });
    const virtualResolved = await app.inject({ method: "POST",
      url: `/cards/disputes/${virtualDisputeId}/resolve`,
      headers: { "x-partner-key": "test-partner" }, payload: { winner: "customer" } });
    const virtualRefund = await app.inject({ method: "POST", url: "/cards/refund",
      headers: { "x-partner-key": "test-partner" }, payload: {
        authorization_id: virtualId, target_card_id: virtual.id, amount_cents: 200 } });
    for (const response of [virtualCapture, virtualView, virtualDispute,
      virtualRepresentment, virtualPreArbitration, virtualResolved, virtualRefund])
      assert.equal(response.statusCode, 200, response.body);
    assert.equal(virtualResolved.json().status, "customer_won");
    assert.equal(bank.account(seedAccountId(1)).balance_cached, initialBalance);
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
    const pans = [card.id, virtual.id].map((cardId) =>
      bank.db.prepare("SELECT pan FROM card_vault WHERE card_id=?").get(cardId).pan);
    for (const pan of pans) {
      for (const [index, response] of [approved, cvvResponse, view, capture, dispute,
        disputeView, representment, preArbitration, resolved, refund, list,
        virtualApproved, virtualCapture, virtualView, virtualDispute,
        virtualRepresentment, virtualPreArbitration, virtualResolved, virtualRefund].entries())
        assert.equal(response.body.includes(pan), false, `card response ${index}`);
      assert.equal(JSON.stringify(bank.telemetry.list()).includes(pan), false);
    }
    const revokedIssue = await app.inject({ method: "POST", url: threeDsPath,
      headers: await signedOperationHeaders(app, headers, privateKey, threeDsPath, threeDsBody),
      payload: threeDsBody });
    assert.equal(revokedIssue.statusCode, 200, revokedIssue.body);
    const revokedChallenge = revokedIssue.json();
    const revokedCompletePath = `/cards/3ds/challenges/${revokedChallenge.id}/complete`;
    const revokedCompleteBody = { nonce: revokedChallenge.nonce };
    assert.equal((await app.inject({ method: "POST", url: revokedCompletePath,
      headers: await signedOperationHeaders(app, headers, privateKey, revokedCompletePath,
        revokedCompleteBody), payload: revokedCompleteBody })).statusCode, 200);
    const boundDevice = auth.deviceForAccess(otp.json().access_token).id;
    bank.db.prepare("UPDATE auth_devices SET revoked_at=? WHERE id=?")
      .run(bank.now().toISOString(), boundDevice);
    const revokedAuthorization = await app.inject({ method: "POST",
      url: "/cards/network/authorize", headers: { "x-partner-key": "test-partner" },
      payload: { ...authenticatedBody, three_ds_challenge_id: revokedChallenge.id } });
    assert.equal(revokedAuthorization.json().response_code, "05");
    assert.equal(bank.db.prepare("SELECT status FROM card_3ds_challenges WHERE id=?")
      .get(revokedChallenge.id).status, "completed");
    assert.equal(bank.reconcile().ok, true);
  } finally { await app.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
