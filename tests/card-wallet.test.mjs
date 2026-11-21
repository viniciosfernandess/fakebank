import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "../apps/world/src/credit-cards.ts";
import { CardNetwork } from "../apps/world/src/ecosystem/card-network.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { gatewayRouteTemplate, isGatewayAllowed } from "../apps/world/src/gateway.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";

test("device-bound wallet DPAN authorizes once, settles and revokes without exposing PAN", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-card-wallet-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-16T12:00:00Z"));
  let api;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1), deposit = seedAccountId(1);
    const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
    const cards = new CardsEngine(bank);
    const account = credit.open(customer, 50_000, 15);
    const card = cards.issueCredit(customer, deposit, account.id);
    const pan = bank.db.prepare("SELECT pan FROM card_vault WHERE card_id=?").get(card.id).pan;
    const auth = new AuthEngine(bank);
    auth.setPassword(customer, "wallet-test-password");
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "wallet-test-password", "127.0.0.1", "wallet-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    api = createTwinApi(bank, auth, { partnerKey: "wallet-test-partner" });
    const headers = { authorization: `Bearer ${session.access_token}` };
    auth.stepUp(session.access_token, "wallet-test-password");
    const privateKey = await bindDeviceKey(api, headers);
    const issuePath = `/cards/${card.id}/wallet-tokens`;
    assert.equal(isGatewayAllowed(issuePath), true);
    assert.equal(gatewayRouteTemplate(`/api/v1${issuePath}`),
      "/api/v1/cards/:id/wallet-tokens");
    assert.equal((await api.inject({ method: "POST", url: issuePath,
      headers, payload: {} })).statusCode, 403);
    const issued = await api.inject({ method: "POST", url: issuePath,
      headers: await signedOperationHeaders(api, headers, privateKey, issuePath, {}),
      payload: {} });
    assert.equal(issued.statusCode, 200, issued.body);
    assert.equal(issued.headers["cache-control"], "no-store");
    const token = issued.json();
    assert.match(token.dpan, /^\d{16}$/);
    assert.notEqual(token.dpan, pan);
    assert.equal(issued.body.includes(pan), false);
    const listed = await api.inject({ method: "GET", url: issuePath, headers });
    assert.equal(listed.statusCode, 200);
    assert.equal(listed.json().length, 1);
    assert.equal(listed.body.includes(token.dpan), false);
    assert.equal(listed.body.includes(token.cryptogram_key), false);
    assert.equal(JSON.stringify(bank.db.prepare("SELECT * FROM card_wallet_tokens").all())
      .includes(token.dpan), false);
    const network = new CardNetwork(bank, cards);
    assert.throws(() => network.walletTokens(seedCustomerId(2), card.id), /DEF_NOT_FOUND/);
    assert.throws(() => network.revokeWalletToken(seedCustomerId(2), token.id), /DEF_NOT_FOUND/);
    const partner = { "x-partner-key": "wallet-test-partner" };
    const signPayment = (nonce, amount) => createHmac("sha256",
      Buffer.from(token.cryptogram_key, "hex"))
      .update(`${token.dpan}:${nonce}:shop_ipe:${amount}:1`).digest("hex");
    const payment = (nonce, amount, cryptogram = signPayment(nonce, amount)) =>
      api.inject({ method: "POST", url: "/cards/network/wallet/authorize",
        headers: partner, payload: { dpan: token.dpan, merchant_id: "shop_ipe",
          amount_cents: amount, nonce, cryptogram } });
    assert.equal((await api.inject({ method: "POST",
      url: "/cards/network/wallet/authorize", payload: { dpan: token.dpan,
        merchant_id: "shop_ipe", amount_cents: 2_000,
        nonce: "walletnonce0001", cryptogram: signPayment("walletnonce0001", 2_000) } }))
      .statusCode, 403);
    assert.equal((await payment("walletnoncehigh", 20_001)).statusCode, 400);
    assert.equal((await payment("walletnonce0001", 2_000, "0".repeat(64))).statusCode, 403);
    const approved = await payment("walletnonce0001", 2_000);
    assert.equal(approved.statusCode, 200, approved.body);
    assert.equal(approved.json().response_code, "00");
    assert.equal(approved.body.includes(token.dpan), false);
    assert.equal((await payment("walletnonce0001", 2_000)).statusCode, 403);
    network.capture(approved.json().id, 2_000);
    assert.equal(credit.outstanding(customer, account.id), 2_000);
    assert.equal(credit.reconcileAll().ok, true);
    assert.equal(bank.reconcileCardSettlement().ok, true);
    const revokePath = `/cards/wallet-tokens/${token.id}/revoke`;
    assert.equal(isGatewayAllowed(revokePath), true);
    assert.equal(isGatewayAllowed("/cards/network/wallet/authorize"), true);
    const revoked = await api.inject({ method: "POST", url: revokePath,
      headers: await signedOperationHeaders(api, headers, privateKey, revokePath) });
    assert.equal(revoked.statusCode, 200, revoked.body);
    assert.equal(revoked.json().status, "revoked");
    assert.equal((await payment("walletnonce0002", 1_000)).statusCode, 403);
    const replacement = await api.inject({ method: "POST", url: issuePath,
      headers: await signedOperationHeaders(api, headers, privateKey, issuePath, {}),
      payload: {} });
    assert.equal(replacement.statusCode, 200, replacement.body);
    const next = replacement.json();
    auth.revokeDevice(customer, "wallet-device");
    assert.equal(network.walletTokens(customer, card.id).find((item) =>
      item.id === next.id).status, "revoked");
    const nextCryptogram = createHmac("sha256", Buffer.from(next.cryptogram_key, "hex"))
      .update(`${next.dpan}:revokeddevice0001:shop_ipe:1000:1`).digest("hex");
    assert.throws(() => network.authorizeWallet({ dpan: next.dpan,
      merchantId: "shop_ipe", amountCents: 1_000, nonce: "revokeddevice0001",
      cryptogram: nextCryptogram }), /DEF_WALLET_CREDENTIAL_INVALID/);
    assert.equal(JSON.stringify(bank.telemetry.list()).includes(token.dpan), false);
    assert.equal(JSON.stringify(bank.db.prepare("SELECT * FROM card_network_messages").all())
      .includes(token.dpan), false);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM card_wallet_uses").get().n, 1);
  } finally { await api?.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
