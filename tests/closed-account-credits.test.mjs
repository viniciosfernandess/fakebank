import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AccountLifecycle } from "../apps/world/src/account-lifecycle.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { Gateway } from "../apps/world/src/gateway.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";
import { reviewMedForTest } from "./med-review-helper.mjs";

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-closed-credit-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const customer = seedCustomerId(1);
  const source = "acc_closed_credit_source";
  bank.addAccount({ id: source, customer_id: customer, kind: "checking",
    system_role: null, overdraft_limit: 0, status: "active" });
  bank.fund(source, 1000);
  return { bank, customer, source,
    advance: (date) => { now = new Date(date); },
    close: () => { bank.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("repeated closed-account credit payouts alert on the third payment", () => {
  const { bank, customer, source, close } = fixture();
  try {
    bank.fund(source, 2000);
    const transfers = [];
    for (let index = 0; index < 3; index++)
      transfers.push(bank.transferPix({ from: source, to: "psp_ipe_ana", amount: 1000,
        idempotencyKey: `closed-credit-coverage-${index}`, actor: customer }));
    new AccountLifecycle(bank).transition(source, "closed", "reviewer");
    const sentinel = new SentinelEngine(bank);
    for (let index = 0; index < 2; index++)
      bank.returnExternalPix(transfers[index].id, 1000, `closed-credit-return-${index}`);
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-34"), false);
    bank.returnExternalPix(transfers[2].id, 1000, "closed-credit-return-2");
    const returnAlert = sentinel.scan().find((item) => item.rule_id === "S-PIX-34");
    assert.equal(returnAlert?.entity, source);
    assert.equal(returnAlert?.observed.returns, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='return' AND account_id=?`).get(source).n, 3);
    const credits = bank.closedAccountCredits(customer).items;
    assert.equal(credits.length, 3);
    for (const credit of credits.slice(0, 2))
      bank.claimClosedAccountCredit(customer, credit.id, seedAccountId(1));
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-LED-09"), false);
    bank.claimClosedAccountCredit(customer, credits[2].id, seedAccountId(1));
    const alert = sentinel.scan().find((item) => item.rule_id === "S-LED-09");
    assert.equal(alert?.entity, customer);
    assert.equal(alert?.observed.payouts, 3);
    assert.equal(alert?.observed.amount_cents, 3000);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='ledger' AND action='closed_credit_payout' AND user_id=?`)
      .get(customer).n, 3);
    assert.equal(bank.closedCreditReconciliation().ok, true);
  } finally { close(); }
});

test("late external Pix return stays off closed account and pays its owner once", async () => {
  const { bank, customer, source, advance, close } = fixture();
  const auth = new AuthEngine(bank);
  auth.setPassword(customer, "closed-credit-test-password");
  const app = createTwinApi(bank, auth);
  try {
    const payment = bank.transferPix({ from: source, to: "psp_ipe_ana", amount: 1000,
      idempotencyKey: "closed-return", actor: customer });
    assert.equal(payment.status, "settled");
    new AccountLifecycle(bank).transition(source, "closed", "reviewer");
    const returned = bank.returnExternalPix(payment.id, 1000, "late-return");
    assert.equal(bank.account(source).balance_cached, 0);
    assert.equal(bank.closedCreditReconciliation().ok, true);
    assert.equal(bank.closedCreditReconciliation().pending_cents, 1000);
    const credit = bank.closedAccountCredits(customer).items[0];
    assert.equal(credit.source_id, returned.id);
    assert.equal(credit.amount_cents, 1000);
    assert.equal(bank.closedAccountCredits(seedCustomerId(2)).items.length, 0);
    assert.equal(bank.returnExternalPix(payment.id, 1000, "late-return").id, returned.id);
    assert.equal(bank.closedAccountCredits(customer).items.length, 1);
    advance("2026-11-14T06:00:00Z");
    assert.equal(bank.periodClose().brt_date, "2026-11-13");
    const login = await app.inject({ method: "POST", url: "/auth/login", payload: {
      cpf: bank.customer(customer).cpf, password: "closed-credit-test-password",
      device_id: "closed-credit-device" } });
    const challengeId = login.json().challenge_id;
    const otp = await app.inject({ method: "POST", url: "/auth/otp/verify", payload: {
      challenge_id: challengeId, otp: auth.simulatedOtp(challengeId, customer) } });
    const headers = { authorization: `Bearer ${otp.json().access_token}` };
    const gateway = new Gateway(bank, app);
    const listed = await gateway.call({ method: "GET",
      path: "/api/v1/accounts/closed-credits", headers, peerIp: "127.0.0.1" });
    assert.equal(listed.status, 200);
    assert.equal(listed.body.items[0].id, credit.id);
    const claimPath = `/api/v1/accounts/closed-credits/${credit.id}/claim`;
    const payload = { destination_account_id: seedAccountId(1) };
    assert.equal((await gateway.call({ method: "POST", path: claimPath, headers,
      body: payload, peerIp: "127.0.0.1" })).status, 403);
    assert.equal((await app.inject({ method: "POST", url: "/auth/step-up", headers,
      payload: { password: "closed-credit-test-password" } })).statusCode, 200);
    assert.equal((await gateway.call({ method: "POST", path: claimPath, headers,
      body: payload, peerIp: "127.0.0.1" })).body.error, "DEF_DEVICE_PROOF_INVALID");
    const privateKey = await bindDeviceKey(app, headers);
    const internalPath = `/accounts/closed-credits/${credit.id}/claim`;
    const claim = async (body) => gateway.call({ method: "POST", path: claimPath,
      headers: await signedOperationHeaders(app, headers, privateKey, internalPath, body),
      body, peerIp: "127.0.0.1" });
    assert.equal((await claim({ destination_account_id: seedAccountId(2) })).status, 404);
    assert.equal((await claim({ destination_account_id: source })).status, 403);
    const before = bank.account(seedAccountId(1)).balance_cached;
    const paidHeaders = await signedOperationHeaders(app, headers, privateKey,
      internalPath, payload);
    assert.equal((await gateway.call({ method: "POST", path: claimPath,
      body: { destination_account_id: source }, peerIp: "127.0.0.1",
      headers: paidHeaders })).body.error, "DEF_DEVICE_PROOF_INVALID");
    assert.equal(bank.account(seedAccountId(1)).balance_cached, before);
    assert.equal((await gateway.call({ method: "POST", path: claimPath,
      body: payload, peerIp: "127.0.0.1",
      headers: { ...paidHeaders, "x-device-signature": "A".repeat(86) } })).body.error,
    "DEF_DEVICE_PROOF_INVALID");
    const paid = await gateway.call({ method: "POST", path: claimPath,
      body: payload, peerIp: "127.0.0.1", headers: paidHeaders });
    assert.equal(paid.status, 200);
    assert.equal(paid.body.status, "paid");
    assert.equal(bank.account(seedAccountId(1)).balance_cached, before + 1000);
    assert.equal((await gateway.call({ method: "POST", path: claimPath,
      headers: paidHeaders, body: payload, peerIp: "127.0.0.1" })).body.error,
    "DEF_DEVICE_PROOF_INVALID");
    assert.equal((await claim(payload)).status, 200);
    assert.equal(bank.account(seedAccountId(1)).balance_cached, before + 1000);
    assert.equal(bank.closedAccountCredits(customer).items.length, 0);
    assert.equal(bank.closedCreditReconciliation().ok, true);
    assert.equal(bank.closedCreditReconciliation().pending_cents, 0);
  } finally { await app.close(); close(); }
});

test("MED recovery after account closure becomes an individually backed credit", () => {
  const { bank, customer, source, advance, close } = fixture();
  try {
    const payment = bank.transferPix({ from: source, to: seedAccountId(2), amount: 1000,
      idempotencyKey: "closed-med", actor: customer });
    new AccountLifecycle(bank).transition(source, "closed", "reviewer");
    const med = bank.requestMed(customer, payment.id);
    reviewMedForTest(bank, med.id, payment.id);
    advance("2026-11-20T12:00:00Z");
    assert.equal(bank.resolveMed(med.id).refunded_cents, 1000);
    assert.equal(bank.account(source).balance_cached, 0);
    assert.equal(bank.closedAccountCredits(customer).items[0].source_id, med.id);
    assert.equal(bank.closedCreditReconciliation().pending_cents, 1000);
    assert.equal(bank.closedCreditReconciliation().ok, true);
  } finally { close(); }
});

test("external MED after account closure credits suspense for the full customer claim", () => {
  const { bank, customer, source, advance, close } = fixture();
  try {
    const payment = bank.transferPix({ from: source, to: "psp_ipe_ana", amount: 1000,
      idempotencyKey: "closed-external-med", actor: customer });
    new AccountLifecycle(bank).transition(source, "closed", "reviewer");
    const med = bank.requestMed(customer, payment.id);
    reviewMedForTest(bank, med.id, payment.id);
    advance("2026-11-21T12:01:00Z");
    assert.equal(bank.resolveMed(med.id).refunded_cents, 1000);
    assert.equal(bank.account(source).balance_cached, 0);
    assert.equal(bank.closedAccountCredits(customer).items[0].amount_cents, 1000);
    assert.equal(bank.closedCreditReconciliation().pending_cents, 1000);
    assert.equal(bank.closedCreditReconciliation().ok, true);
  } finally { close(); }
});

test("suspense without a matching closed-account credit blocks period close", () => {
  const { bank, advance, close } = fixture();
  try {
    bank.post([
      { accountId: bank.systemAccountId("cash_in"), amount: -1, kind: "test",
        actor: "test", refType: "test", refId: "unbacked" },
      { accountId: bank.systemAccountId("suspense"), amount: 1, kind: "test",
        actor: "test", refType: "test", refId: "unbacked" },
    ]);
    advance("2026-11-14T06:00:00Z");
    assert.equal(bank.closedCreditReconciliation().ok, false);
    assert.ok(new SentinelEngine(bank).scan().some((alert) =>
      alert.rule_id === "S-LED-02" && alert.entity === "closed_account_credits"));
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
  } finally { close(); }
});
