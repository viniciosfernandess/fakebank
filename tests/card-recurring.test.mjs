import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "../apps/world/src/credit-cards.ts";
import { CardNetwork } from "../apps/world/src/ecosystem/card-network.ts";
import { CardRecurring } from "../apps/world/src/card-recurring.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { gatewayRouteTemplate, isGatewayAllowed } from "../apps/world/src/gateway.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";
import { EventStore } from "../packages/event-store/src/index.ts";
import { CampaignRuntime } from "../apps/orchestrator/src/campaign-runtime.ts";

test("signed card recurrence charges once per cycle, clears and stops after revocation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-recurring-"));
  let now = new Date("2026-11-16T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  let api;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1), other = seedCustomerId(2);
    const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
    const cards = new CardsEngine(bank);
    const account = credit.open(customer, 50_000, 15);
    const card = cards.issueCredit(customer, seedAccountId(1), account.id);
    const network = new CardNetwork(bank, cards);
    const recurring = new CardRecurring(bank, network);
    const auth = new AuthEngine(bank);
    auth.setPassword(customer, "recurring-test-password");
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "recurring-test-password", "127.0.0.1", "recurring-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    api = createTwinApi(bank, auth);
    const headers = { authorization: `Bearer ${session.access_token}` };
    auth.stepUp(session.access_token, "recurring-test-password");
    const privateKey = await bindDeviceKey(api, headers);
    const path = `/cards/${card.id}/recurring`;
    assert.equal(isGatewayAllowed(path), true);
    assert.equal(gatewayRouteTemplate(`/api/v1${path}`), "/api/v1/cards/:id/recurring");
    const body = { merchant_id: "shop_ipe", amount_cents: 5_000,
      frequency: "weekly", starts_at: "2026-11-17T12:00:00.000Z",
      idempotency_key: "weekly-merchant-1" };
    assert.equal((await api.inject({ method: "POST", url: path,
      headers, payload: body })).statusCode, 403);
    const created = await api.inject({ method: "POST", url: path,
      headers: await signedOperationHeaders(api, headers, privateKey, path, body),
      payload: body });
    assert.equal(created.statusCode, 200, created.body);
    const mandate = created.json();
    const repeated = await api.inject({ method: "POST", url: path,
      headers: await signedOperationHeaders(api, headers, privateKey, path, body),
      payload: body });
    assert.equal(repeated.json().id, mandate.id);
    const deviceId = auth.deviceForAccess(session.access_token).id;
    assert.throws(() => recurring.create(customer, deviceId,
      { cardId: card.id, merchantId: "shop_ipe", amountCents: 6_000,
        frequency: "weekly", startsAt: body.starts_at,
        idempotencyKey: body.idempotency_key }), /BIZ_CARD_RECURRING_CONFLICT/);
    assert.throws(() => recurring.create(customer, deviceId,
      { cardId: card.id, merchantId: "shop_ipe", amountCents: 20_001,
        frequency: "weekly", startsAt: body.starts_at,
        idempotencyKey: "new-device-high-mandate" }), /BIZ_NEW_DEVICE_LIMIT/);
    assert.equal(recurring.runDue().approved, 0);
    now = new Date(body.starts_at);
    assert.deepEqual(recurring.runDue(), { approved: 1, declined: 0, failed: 0 });
    assert.deepEqual(recurring.runDue(), { approved: 0, declined: 0, failed: 0 });
    assert.equal(recurring.charges(customer, mandate.id).length, 1);
    assert.throws(() => recurring.mandate(other, mandate.id), /DEF_NOT_FOUND/);
    now = new Date("2026-11-18T12:00:00Z");
    assert.deepEqual(network.clearDue(), { cleared: 1, failed: 0, expired: 0 });
    assert.equal(credit.outstanding(customer, account.id), 5_000);
    now = new Date("2026-11-24T12:00:00Z");
    assert.equal(recurring.runDue().approved, 1);
    now = new Date("2026-11-25T12:00:00Z");
    assert.equal(network.clearDue().cleared, 1);
    assert.equal(credit.outstanding(customer, account.id), 10_000);
    const charges = await api.inject({ method: "GET",
      url: `/cards/recurring/${mandate.id}/charges`, headers });
    assert.equal(charges.statusCode, 200);
    assert.deepEqual(charges.json().map((charge) => charge.cycle_index), [0, 1]);
    const revokePath = `/cards/recurring/${mandate.id}/revoke`;
    const revoked = await api.inject({ method: "POST", url: revokePath,
      headers: await signedOperationHeaders(api, headers, privateKey, revokePath) });
    assert.equal(revoked.statusCode, 200, revoked.body);
    assert.equal(revoked.json().status, "revoked");
    now = new Date("2026-12-08T12:00:00Z");
    assert.deepEqual(recurring.runDue(), { approved: 0, declined: 0, failed: 0 });
    assert.equal(recurring.charges(customer, mandate.id).length, 2);
    const monthly = recurring.create(customer, deviceId,
      { cardId: card.id, merchantId: "shop_ipe", amountCents: 5_000,
        frequency: "monthly", startsAt: "2027-01-31T12:00:00.000Z",
        idempotencyKey: "month-end-merchant-1" });
    now = new Date("2027-01-31T12:00:00Z");
    assert.equal(recurring.runDue().approved, 1);
    assert.equal(recurring.mandate(customer, monthly.id).next_due_at,
      "2027-02-28T12:00:00.000Z");
    now = new Date("2027-02-01T12:00:00Z");
    assert.equal(network.clearDue().cleared, 1);
    now = new Date("2027-02-28T12:00:00Z");
    assert.equal(recurring.runDue().approved, 1);
    assert.equal(recurring.mandate(customer, monthly.id).next_due_at,
      "2027-03-31T12:00:00.000Z");
    now = new Date("2027-03-01T12:00:00Z");
    assert.equal(network.clearDue().cleared, 1);
    now = new Date("2027-03-31T12:00:00Z");
    assert.equal(recurring.runDue().approved, 1);
    now = new Date("2027-04-01T12:00:00Z");
    assert.equal(network.clearDue().cleared, 1);
    assert.equal(credit.outstanding(customer, account.id), 25_000);
    now = new Date("2027-04-30T12:00:00Z");
    bank.changeAccountStatus(seedAccountId(1), "frozen", "reviewer", "fraud_suspect");
    assert.deepEqual(recurring.runDue(), { approved: 0, declined: 1, failed: 0 });
    assert.equal(recurring.charges(customer, monthly.id).at(-1).status, "declined");
    now = new Date("2027-05-31T12:00:00Z");
    bank.changeAccountStatus(seedAccountId(1), "active", "reviewer");
    bank.db.prepare("UPDATE card_merchants SET status='inactive' WHERE id='shop_ipe'").run();
    assert.deepEqual(recurring.runDue(), { approved: 0, declined: 0, failed: 1 });
    assert.equal(recurring.charges(customer, monthly.id).at(-1).failure_code,
      "BIZ_INVALID_MERCHANT");
    assert.equal(recurring.runDue().failed, 0);
    const pan = bank.db.prepare("SELECT pan FROM card_vault WHERE card_id=?").get(card.id).pan;
    assert.equal(JSON.stringify(bank.telemetry.list()).includes(pan), false);
    assert.equal(JSON.stringify(bank.db.prepare("SELECT * FROM card_recurring_charges").all())
      .includes(pan), false);
    assert.equal(credit.reconcileAll().ok, true);
    assert.equal(bank.reconcileCardSettlement().ok, true);
    assert.equal(bank.reconcile().ok, true);
    now = new Date("2027-06-01T06:00:00Z");
    assert.ok(bank.periodClose().brt_date);
  } finally { await api?.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("recurring charge survives bank restart without repeating the same cycle", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-recurring-restart-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-16T12:00:00Z");
  let bank = new Bank(path, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const auth = new AuthEngine(bank);
    auth.setPassword(customer, "recurring-restart-password");
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "recurring-restart-password", "127.0.0.1", "restart-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    auth.stepUp(session.access_token, "recurring-restart-password");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const keyChallenge = auth.issueDeviceEnrollmentChallenge(session.access_token);
    const device = auth.enrolCurrentDeviceKey(session.access_token,
      keyChallenge.challenge_id,
      publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
      sign(null, Buffer.from(keyChallenge.message), privateKey).toString("base64url"));
    let cards = new CardsEngine(bank);
    let network = new CardNetwork(bank, cards);
    let recurring = new CardRecurring(bank, network);
    const card = cards.issueDebit(customer, seedAccountId(1), 10_000);
    const mandate = recurring.create(customer, device.device_id, { cardId: card.id,
      merchantId: "shop_ipe", amountCents: 1_000, frequency: "weekly",
      startsAt: "2026-11-17T12:00:00.000Z", idempotencyKey: "restart-mandate-1" });
    now = new Date("2026-11-17T12:00:00Z");
    assert.equal(recurring.runDue().approved, 1);
    bank.close();
    bank = new Bank(path, () => now);
    cards = new CardsEngine(bank);
    network = new CardNetwork(bank, cards);
    recurring = new CardRecurring(bank, network);
    assert.deepEqual(recurring.runDue(), { approved: 0, declined: 0, failed: 0 });
    assert.equal(recurring.charges(customer, mandate.id).length, 1);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM card_network_authorizations").get().n, 1);
    now = new Date("2026-11-18T12:00:00Z");
    assert.equal(network.clearDue().cleared, 1);
    assert.equal(bank.reconcileCardSettlement().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("campaign cycle executes a due card recurrence once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-recurring-cycle-"));
  const events = new EventStore(join(dir, "events.sqlite"));
  let real = new Date("2026-11-16T12:00:00Z");
  const runtime = new CampaignRuntime({ dataDir: dir, events, onDemand: true,
    realNow: () => real, seed: { customers: 2, accounts: 2,
      historyTransactions: 0, openWeaknesses: false } });
  try {
    const customer = seedCustomerId(1), deposit = seedAccountId(1);
    const auth = runtime.auth;
    const password = `synthetic-${customer}-simulator-secret`;
    auth.setPassword(customer, password);
    const challenge = auth.beginLogin(runtime.bank.customer(customer).cpf,
      password, "127.0.0.1", "cycle-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    auth.stepUp(session.access_token, password);
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const keyChallenge = auth.issueDeviceEnrollmentChallenge(session.access_token);
    const device = auth.enrolCurrentDeviceKey(session.access_token,
      keyChallenge.challenge_id,
      publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
      sign(null, Buffer.from(keyChallenge.message), privateKey).toString("base64url"));
    const credit = new CreditCardsEngine(runtime.bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
    const account = credit.open(customer, 30_000, 15);
    const card = runtime.cardNetwork.cards.issueCredit(customer, deposit, account.id);
    const startsAt = new Date(runtime.bank.now().getTime() + 60_000).toISOString();
    const mandate = runtime.cardRecurring.create(customer, device.device_id,
      { cardId: card.id, merchantId: "shop_ipe", amountCents: 1_000,
        frequency: "weekly", startsAt, idempotencyKey: "cycle-runtime-1" });
    real = new Date(real.getTime() + 10_000);
    await runtime.cycle();
    assert.equal(runtime.cardRecurring.charges(customer, mandate.id).length, 1);
    assert.equal(runtime.cardRecurring.charges(customer, mandate.id)[0].status, "approved");
    assert.equal(runtime.cardRecurring.runDue().approved, 0);
    assert.equal(credit.reconcileAll().ok, true);
  } finally { await runtime.close(); events.close(); rmSync(dir, { recursive: true, force: true }); }
});
