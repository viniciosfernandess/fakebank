import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { CardNetwork } from "../apps/world/src/ecosystem/card-network.ts";
import { Gateway } from "../apps/world/src/gateway.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";

test("card creation, update, reversal, and clearing keep vault PANs private", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-api-privacy-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  let api;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const cards = new CardsEngine(bank);
    cards.features.setEnabled("cartao_virtual_temporario", true, "test");
    const auth = new AuthEngine(bank);
    auth.setPassword(customer, "local-card-privacy-password");
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "local-card-privacy-password", "127.0.0.1", "card-privacy-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    api = createTwinApi(bank, auth, { partnerKey: "test-partner" });
    auth.stepUp(session.access_token, "local-card-privacy-password");
    const headers = { authorization: `Bearer ${session.access_token}` };
    const privateKey = await bindDeviceKey(api, headers);
    const responses = [];
    const read = (response) => {
      assert.equal(response.statusCode, 200, response.body);
      responses.push(response.body);
      return response.json();
    };
    const signed = async (method, path, body) => ({ method, url: path,
      headers: await signedOperationHeaders(api, headers, privateKey, path, body, method),
      ...(body === undefined ? {} : { payload: body }) });
    const debit = read(await api.inject(await signed("POST", "/cards",
      { account_id: seedAccountId(1), limit_cents: 10_000 })));
    const virtual = read(await api.inject(await signed("POST", `/cards/${debit.id}/virtual`,
      { limit_cents: 5_000 })));
    const temporary = read(await api.inject(await signed("POST", `/cards/${debit.id}/temporary`,
      { limit_cents: 1_000 })));
    read(await api.inject(await signed("GET", `/cards/${virtual.id}/cvv`, undefined)));
    const gateway = new Gateway(bank, api);
    const cvvRoute = `/cards/${virtual.id}/cvv`;
    const cvvRead = await signed("GET", cvvRoute, undefined);
    const signedCvv = await gateway.call({ method: "GET", path: "/api/v1" + cvvRoute,
      headers: cvvRead.headers, peerIp: "127.0.0.1" });
    assert.equal(signedCvv.status, 200);
    const cvvLog = bank.telemetry.trace(signedCvv.request_id)
      .find((event) => event.source === "gateway");
    assert.equal(cvvLog.message, "Gateway GET /api/v1/cards/:id/cvv completed fields=cvv,expires_at");
    assert.equal(cvvLog.message.includes(signedCvv.body.cvv), false);
    assert.equal(cvvLog.message.includes(virtual.id), false);
    const deniedCvv = await gateway.call({ method: "GET", path: "/api/v1" + cvvRoute,
      headers, peerIp: "127.0.0.1" });
    assert.equal(deniedCvv.status, 403);
    assert.equal(bank.telemetry.trace(deniedCvv.request_id)
      .find((event) => event.source === "gateway").message,
    "Gateway GET /api/v1/cards/:id/cvv completed");
    read(await api.inject({ method: "GET", url: "/cards", headers }));
    const partner = { "x-partner-key": "test-partner" };
    const reverseAuth = read(await api.inject({ method: "POST",
      url: "/cards/network/authorize", headers: partner, payload: {
        card_id: debit.id, merchant_id: "shop_ipe", amount_cents: 500,
        entry_mode: "chip", cvv: cards.vault.currentCvv(debit.id) } }));
    assert.equal(reverseAuth.response_code, "00");
    const reversed = read(await api.inject({ method: "POST",
      url: `/cards/network/${reverseAuth.id}/reverse`, headers: partner }));
    assert.equal(reversed.status, "reversed");
    const queuedAuth = read(await api.inject({ method: "POST",
      url: "/cards/network/authorize", headers: partner, payload: {
        card_id: virtual.id, merchant_id: "shop_ipe", amount_cents: 300,
        entry_mode: "ecommerce", eci: "07",
        cvv: cards.vault.currentCvv(virtual.id) } }));
    assert.equal(queuedAuth.response_code, "00");
    const queued = read(await api.inject({ method: "POST",
      url: `/cards/network/${queuedAuth.id}/clearing`, headers: partner,
      payload: { amount_cents: 250 } }));
    assert.equal(queued.queued, true);
    now = new Date(now.getTime() + 86_400_000);
    const network = new CardNetwork(bank, cards);
    assert.deepEqual(network.clearDue(), { cleared: 1, failed: 0, expired: 0 });
    const cleared = read(await api.inject({ method: "GET",
      url: `/cards/network/${queuedAuth.id}`, headers }));
    assert.equal(cleared.captured_cents, 250);
    read(await api.inject(await signed("PATCH", `/cards/${debit.id}`,
      { online_enabled: false })));
    read(await api.inject({ method: "GET", url: "/cards", headers }));
    const pans = [debit.id, virtual.id, temporary.id].map((id) =>
      bank.db.prepare("SELECT pan FROM card_vault WHERE card_id=?").get(id).pan);
    for (const pan of pans) {
      for (const [index, body] of responses.entries())
        assert.equal(body.includes(pan), false, `card response ${index}`);
      assert.equal(JSON.stringify(bank.telemetry.list()).includes(pan), false);
    }
    assert.deepEqual(bank.reconcileCardSettlement(), { ok: true, mismatches: 0 });
    assert.equal(bank.reconcile().ok, true);
  } finally { await api?.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
