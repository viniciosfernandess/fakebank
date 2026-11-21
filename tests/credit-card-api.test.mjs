import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "../apps/world/src/credit-cards.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";

test("credit statement payment and installment plan are owned and device signed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-credit-api-"));
  let now = new Date("2026-11-11T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const customer = seedCustomerId(1), other = seedCustomerId(2);
  const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
  const account = credit.open(customer, 100_000, 15);
  credit.purchase(customer, account.id, "merchant-1", 20_000);
  now = new Date("2026-11-16T12:00:00Z");
  const statement = credit.closeNext(customer, account.id);
  const auth = new AuthEngine(bank);
  auth.setPassword(customer, "credit-test-password");
  auth.setPassword(other, "other-credit-password");
  const app = createTwinApi(bank, auth);
  try {
    const login = auth.beginLogin(bank.customer(customer).cpf, "credit-test-password",
      "127.0.0.1", "credit-device");
    const session = auth.verifyOtp(login.challenge_id,
      auth.simulatedOtp(login.challenge_id, customer), "127.0.0.1");
    const headers = { authorization: `Bearer ${session.access_token}` };
    const listing = await app.inject({ method: "GET", url: "/cards/credit", headers });
    assert.equal(listing.statusCode, 200);
    assert.equal(listing.json()[0].id, account.id);
    const otherLogin = auth.beginLogin(bank.customer(other).cpf, "other-credit-password",
      "127.0.0.1", "other-device");
    const otherSession = auth.verifyOtp(otherLogin.challenge_id,
      auth.simulatedOtp(otherLogin.challenge_id, other), "127.0.0.1");
    const otherHeaders = { authorization: `Bearer ${otherSession.access_token}` };
    assert.equal((await app.inject({ method: "GET", url: `/cards/credit/${account.id}`,
      headers: otherHeaders })).statusCode, 404);
    const path = `/cards/credit/${account.id}/statements/${statement.id}/pay`;
    const payload = { source_account_id: seedAccountId(1), amount_cents: 5_000,
      idempotency_key: "credit-payment-1" };
    auth.stepUp(session.access_token, "credit-test-password");
    const unsigned = await app.inject({ method: "POST", url: path, headers, payload });
    assert.equal(unsigned.statusCode, 403);
    const privateKey = await bindDeviceKey(app, headers);
    const signed = async (body) => app.inject({ method: "POST", url: path, payload: body,
      headers: await signedOperationHeaders(app, headers, privateKey, path, body) });
    const first = await signed(payload);
    assert.equal(first.statusCode, 200);
    assert.equal(first.json().paid_cents, 5_000);
    assert.equal((await signed(payload)).statusCode, 200);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM credit_card_payments").get().n, 1);
    const conflict = await signed({ ...payload, amount_cents: 6_000 });
    assert.equal(conflict.statusCode, 400);
    assert.equal(conflict.json().error, "BIZ_CREDIT_PAYMENT_CONFLICT");
    const planPath = `/cards/credit/${account.id}/statements/${statement.id}/installment-plan`;
    const planBody = { installments: 3 };
    assert.equal((await app.inject({ method: "POST", url: planPath,
      headers, payload: planBody })).statusCode, 403);
    const plan = await app.inject({ method: "POST", url: planPath,
      headers: await signedOperationHeaders(app, headers, privateKey, planPath, planBody),
      payload: planBody });
    assert.equal(plan.statusCode, 200, plan.body);
    assert.equal(plan.json().principal_cents, 15_000);
    assert.equal(plan.json().interest_cents, 375);
    assert.equal(credit.statement(customer, statement.id).status, "financed");
    assert.equal((await app.inject({ method: "POST", url: planPath,
      headers: await signedOperationHeaders(app, headers, privateKey, planPath, planBody),
      payload: planBody })).json().id, plan.json().id);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM credit_card_invoice_plans").get().n, 1);
    assert.deepEqual(credit.reconcileAll(), { ok: true, accounts_checked: 1, mismatches: [] });
  } finally { await app.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
