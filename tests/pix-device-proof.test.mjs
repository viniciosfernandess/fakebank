import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedCustomerId } from "../apps/world/src/id.ts";
import { FeatureRegistry } from "../apps/world/src/features.ts";
import { PixAutomatic } from "../apps/world/src/pix-automatic.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";

test("bound device signs financial actions without reusable proof", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-device-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-14T15:00:00.000Z"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const auth = new AuthEngine(bank);
  const app = createTwinApi(bank, auth);
  try {
    const customer = seedCustomerId(1);
    const recipient = seedCustomerId(2);
    const password = "a-strong-pix-device-password";
    auth.setPassword(customer, password);
    const login = auth.beginLogin(bank.customer(customer).cpf, password,
      "127.0.0.1", "signed-pix-device");
    const session = auth.verifyOtp(login.challenge_id,
      auth.simulatedOtp(login.challenge_id, customer), "127.0.0.1");
    auth.stepUp(session.access_token, password);
    const headers = { authorization: `Bearer ${session.access_token}` };
    const privateKey = await bindDeviceKey(app, headers);
    const from = bank.db.prepare("SELECT id FROM accounts WHERE customer_id=? LIMIT 1")
      .get(customer).id;
    const to = bank.db.prepare("SELECT id FROM accounts WHERE customer_id=? LIMIT 1")
      .get(recipient).id;
    const body = { from_account: from, to_account: to, amount_cents: 500,
      idempotency_key: "signed-pix-1" };
    const before = bank.account(from).balance_cached;
    const unsigned = await app.inject({ method: "POST", url: "/pix/transfers",
      headers, payload: body });
    assert.equal(unsigned.statusCode, 403);
    assert.equal(unsigned.json().error, "DEF_DEVICE_PROOF_INVALID");
    assert.equal(bank.account(from).balance_cached, before);
    const signed = await signedOperationHeaders(app, headers, privateKey,
      "/pix/transfers", body);
    const paid = await app.inject({ method: "POST", url: "/pix/transfers",
      headers: signed, payload: body });
    assert.equal(paid.statusCode, 200, paid.body);
    assert.equal(bank.account(from).balance_cached, before - 500);
    const replay = await app.inject({ method: "POST", url: "/pix/transfers",
      headers: signed, payload: body });
    assert.equal(replay.statusCode, 403);
    assert.equal(replay.json().error, "DEF_DEVICE_PROOF_INVALID");
    assert.equal(bank.account(from).balance_cached, before - 500);
    const establishedAt = new Date(bank.now().getTime() - 24 * 60 * 60_000).toISOString();
    bank.db.prepare("UPDATE auth_devices SET first_seen_at=?,bound_at=? WHERE id=?")
      .run(establishedAt, establishedAt, auth.deviceForAccess(session.access_token).id);
    const cardBody = { account_id: from, limit_cents: 100_000 };
    const unsignedCard = await app.inject({ method: "POST", url: "/cards",
      headers, payload: cardBody });
    assert.equal(unsignedCard.statusCode, 403);
    assert.equal(unsignedCard.json().error, "DEF_DEVICE_PROOF_INVALID");
    const cardHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/cards", cardBody);
    const card = await app.inject({ method: "POST", url: "/cards",
      headers: cardHeaders, payload: cardBody });
    assert.equal(card.statusCode, 200, card.body);
    assert.equal(card.json().account_id, from);
    const reused = await app.inject({ method: "POST", url: "/cards",
      headers: cardHeaders, payload: cardBody });
    assert.equal(reused.statusCode, 403);
    const cardId = card.json().id;
    const virtualPath = `/cards/${cardId}/virtual`;
    const virtualBody = { limit_cents: 5_000 };
    const unsignedVirtual = await app.inject({ method: "POST", url: virtualPath,
      headers, payload: virtualBody });
    assert.equal(unsignedVirtual.statusCode, 403);
    const virtualHeaders = await signedOperationHeaders(app, headers, privateKey,
      virtualPath, virtualBody);
    const alteredVirtual = await app.inject({ method: "POST", url: virtualPath,
      headers: virtualHeaders, payload: { limit_cents: 6_000 } });
    assert.equal(alteredVirtual.statusCode, 403);
    const virtual = await app.inject({ method: "POST", url: virtualPath,
      headers: virtualHeaders, payload: virtualBody });
    assert.equal(virtual.statusCode, 200, virtual.body);
    assert.equal(virtual.json().parent_id, cardId);
    const cvvPath = `/cards/${virtual.json().id}/cvv`;
    const unsignedCvv = await app.inject({ method: "GET", url: cvvPath, headers });
    assert.equal(unsignedCvv.statusCode, 403);
    const cvvHeaders = await signedOperationHeaders(app, headers, privateKey,
      cvvPath, undefined, "GET");
    const cvv = await app.inject({ method: "GET", url: cvvPath, headers: cvvHeaders });
    assert.equal(cvv.statusCode, 200, cvv.body);
    assert.match(cvv.json().cvv, /^\d{3}$/);
    assert.equal(cvv.headers["cache-control"], "no-store");
    new FeatureRegistry(bank).setEnabled("cartao_virtual_temporario", true, "test");
    const temporaryPath = `/cards/${cardId}/temporary`;
    const temporaryBody = { limit_cents: 3_000 };
    const unsignedTemporary = await app.inject({ method: "POST", url: temporaryPath,
      headers, payload: temporaryBody });
    assert.equal(unsignedTemporary.statusCode, 403);
    const temporaryHeaders = await signedOperationHeaders(app, headers, privateKey,
      temporaryPath, temporaryBody);
    const temporary = await app.inject({ method: "POST", url: temporaryPath,
      headers: temporaryHeaders, payload: temporaryBody });
    assert.equal(temporary.statusCode, 200, temporary.body);
    assert.equal(temporary.json().parent_id, cardId);
    const settingsPath = `/cards/${cardId}`;
    const settingsBody = { online_enabled: false };
    const unsignedSettings = await app.inject({ method: "PATCH", url: settingsPath,
      headers, payload: settingsBody });
    assert.equal(unsignedSettings.statusCode, 403);
    const settingsHeaders = await signedOperationHeaders(app, headers, privateKey,
      settingsPath, settingsBody, "PATCH");
    const updated = await app.inject({ method: "PATCH", url: settingsPath,
      headers: settingsHeaders, payload: settingsBody });
    assert.equal(updated.statusCode, 200, updated.body);
    assert.equal(updated.json().online_enabled, 0);
    const replaySettings = await app.inject({ method: "PATCH", url: settingsPath,
      headers: settingsHeaders, payload: settingsBody });
    assert.equal(replaySettings.statusCode, 403);
    const offered = await app.inject({ method: "GET", url: "/loans/offers", headers });
    assert.equal(offered.statusCode, 200, offered.body);
    const loanBody = { offer_id: offered.json().id, account_id: from,
      amount_cents: 100_000 };
    const unsignedLoan = await app.inject({ method: "POST", url: "/loans",
      headers, payload: loanBody });
    assert.equal(unsignedLoan.statusCode, 403);
    const loanHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/loans", loanBody);
    const accepted = await app.inject({ method: "POST", url: "/loans",
      headers: loanHeaders, payload: loanBody });
    assert.equal(accepted.statusCode, 200, accepted.body);
    const replayLoan = await app.inject({ method: "POST", url: "/loans",
      headers: loanHeaders, payload: loanBody });
    assert.equal(replayLoan.statusCode, 403);
    assert.equal(replayLoan.json().error, "DEF_DEVICE_PROOF_INVALID");
    const flashBody = { account_id: from, amount_cents: 10_000 };
    const unsignedFlash = await app.inject({ method: "POST", url: "/loans/flash",
      headers, payload: flashBody });
    assert.equal(unsignedFlash.statusCode, 403);
    const flashHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/loans/flash", flashBody);
    const changedFlash = await app.inject({ method: "POST", url: "/loans/flash",
      headers: flashHeaders, payload: { ...flashBody, amount_cents: 20_000 } });
    assert.equal(changedFlash.statusCode, 403);
    const disabledFlash = await app.inject({ method: "POST", url: "/loans/flash",
      headers: flashHeaders, payload: flashBody });
    assert.equal(disabledFlash.statusCode, 404);
    const replayDisabledFlash = await app.inject({ method: "POST", url: "/loans/flash",
      headers: flashHeaders, payload: flashBody });
    assert.equal(replayDisabledFlash.statusCode, 403);
    assert.equal(replayDisabledFlash.json().error, "DEF_DEVICE_PROOF_INVALID");
    const refinancePath = `/loans/${accepted.json().id}/refinance`;
    const unsignedRefinance = await app.inject({ method: "POST", url: refinancePath, headers });
    assert.equal(unsignedRefinance.statusCode, 403);
    const refinanceHeaders = await signedOperationHeaders(app, headers, privateKey, refinancePath);
    const refinanced = await app.inject({ method: "POST", url: refinancePath,
      headers: refinanceHeaders });
    assert.equal(refinanced.statusCode, 200, refinanced.body);
    assert.equal(refinanced.json().previous.status, "refinanced");
    assert.equal(refinanced.json().next.status, "active");
    const replayRefinance = await app.inject({ method: "POST", url: refinancePath,
      headers: refinanceHeaders });
    assert.equal(replayRefinance.statusCode, 403);
    const prepayPath = `/loans/${refinanced.json().next.id}/prepay`;
    const unsignedPrepay = await app.inject({ method: "POST", url: prepayPath, headers });
    assert.equal(unsignedPrepay.statusCode, 403);
    const prepayHeaders = await signedOperationHeaders(app, headers, privateKey, prepayPath);
    const prepaid = await app.inject({ method: "POST", url: prepayPath,
      headers: prepayHeaders });
    assert.equal(prepaid.statusCode, 200, prepaid.body);
    assert.equal(prepaid.json().loan.status, "prepaid");
    const replayPrepay = await app.inject({ method: "POST", url: prepayPath,
      headers: prepayHeaders });
    assert.equal(replayPrepay.statusCode, 403);
    const features = new FeatureRegistry(bank);
    features.setEnabled("emprestimo_relampago", true, "test");
    features.patchFlaw("emprestimo_relampago", "test");
    bank.db.prepare(`INSERT INTO auth_devices
      (id,customer_id,fingerprint,first_seen_at,first_seen_ip,trusted_at,revoked_at)
      VALUES (?,?,?,?,?,?,NULL)`).run("trusted-other", customer, "trusted-other",
      "2026-11-12T15:00:00.000Z", "127.0.0.1", "2026-11-13T15:00:00.000Z");
    const claimedTrusted = { ...flashBody, device_id: "trusted-other" };
    const balanceBeforeFlash = bank.account(from).balance_cached;
    const attemptedFlash = await app.inject({ method: "POST", url: "/loans/flash",
      headers, payload: claimedTrusted });
    assert.equal(attemptedFlash.statusCode, 400);
    assert.equal(attemptedFlash.json().error, "BIZ_INVALID_REQUEST");
    const legacyLogin = auth.beginLogin(bank.customer(customer).cpf, password,
      "127.0.0.1", "legacy-flash-device");
    const legacySession = auth.verifyOtp(legacyLogin.challenge_id,
      auth.simulatedOtp(legacyLogin.challenge_id, customer), "127.0.0.1");
    const legacyHeaders = { authorization: `Bearer ${legacySession.access_token}` };
    const unboundFlash = await app.inject({ method: "POST", url: "/loans/flash",
      headers: legacyHeaders, payload: flashBody });
    assert.equal(unboundFlash.statusCode, 403);
    assert.equal(unboundFlash.json().error, "DEF_DEVICE_PROOF_INVALID");
    const unboundChallenge = await app.inject({ method: "POST",
      url: "/devices/current/operation-challenge", headers: legacyHeaders,
      payload: { method: "POST", path: "/loans/flash", body: flashBody } });
    assert.equal(unboundChallenge.statusCode, 403);
    assert.equal(unboundChallenge.json().error, "DEF_DEVICE_KEY_REQUIRED");
    const ownFlashHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/loans/flash", flashBody);
    const ownFlash = await app.inject({ method: "POST", url: "/loans/flash",
      headers: ownFlashHeaders, payload: flashBody });
    assert.equal(ownFlash.statusCode, 400);
    assert.equal(ownFlash.json().error, "BIZ_DEVICE_COOLDOWN");
    assert.equal(bank.account(from).balance_cached, balanceBeforeFlash);
    features.setEnabled("pix_agendado_recorrente", true, "test");
    const scheduleBody = { from_account: from, to_account: to, amount_cents: 500,
      execute_at: "2026-11-15T15:00:00.000Z", frequency: "once" };
    const unsignedSchedule = await app.inject({ method: "POST", url: "/pix/scheduled",
      headers, payload: scheduleBody });
    assert.equal(unsignedSchedule.statusCode, 403);
    const scheduleHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/pix/scheduled", scheduleBody);
    const alteredSchedule = await app.inject({ method: "POST", url: "/pix/scheduled",
      headers: scheduleHeaders, payload: { ...scheduleBody, amount_cents: 600 } });
    assert.equal(alteredSchedule.statusCode, 403);
    const scheduled = await app.inject({ method: "POST", url: "/pix/scheduled",
      headers: scheduleHeaders, payload: scheduleBody });
    assert.equal(scheduled.statusCode, 200, scheduled.body);
    assert.equal((await app.inject({ method: "POST", url: "/pix/scheduled",
      headers: scheduleHeaders, payload: scheduleBody })).statusCode, 403);
    const reauthorizePath = `/pix/scheduled/${scheduled.json().id}/reauthorize`;
    assert.equal((await app.inject({ method: "POST", url: reauthorizePath,
      headers })).statusCode, 403);
    const reauthorizeHeaders = await signedOperationHeaders(app, headers, privateKey,
      reauthorizePath);
    const reauthorized = await app.inject({ method: "POST", url: reauthorizePath,
      headers: reauthorizeHeaders });
    assert.equal(reauthorized.statusCode, 200, reauthorized.body);
    assert.equal(reauthorized.json().status, "active");
    assert.equal((await app.inject({ method: "POST", url: reauthorizePath,
      headers: reauthorizeHeaders })).statusCode, 403);
    const cancelSchedulePath = `/pix/scheduled/${scheduled.json().id}/cancel`;
    assert.equal((await app.inject({ method: "POST", url: cancelSchedulePath,
      headers })).statusCode, 403);
    const cancelScheduleHeaders = await signedOperationHeaders(app, headers, privateKey,
      cancelSchedulePath);
    const cancelledSchedule = await app.inject({ method: "POST", url: cancelSchedulePath,
      headers: cancelScheduleHeaders });
    assert.equal(cancelledSchedule.statusCode, 200, cancelledSchedule.body);
    assert.equal(cancelledSchedule.json().status, "cancelled");
    assert.equal((await app.inject({ method: "POST", url: cancelSchedulePath,
      headers: cancelScheduleHeaders })).statusCode, 403);
    features.setEnabled("pix_aproximacao", true, "test");
    features.patchFlaw("pix_aproximacao", "test");
    const issueBody = { from_account: from, to_account: to, amount_cents: 1_000 };
    assert.equal((await app.inject({ method: "POST", url: "/pix/proximity/tokens",
      headers, payload: issueBody })).statusCode, 403);
    const issueHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/pix/proximity/tokens", issueBody);
    const issued = await app.inject({ method: "POST", url: "/pix/proximity/tokens",
      headers: issueHeaders, payload: issueBody });
    assert.equal(issued.statusCode, 200, issued.body);
    const redeemBody = { token: issued.json().token, to_account: to, amount_cents: 1_000 };
    assert.equal((await app.inject({ method: "POST", url: "/pix/proximity/redeem",
      headers, payload: redeemBody })).statusCode, 403);
    const redeemHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/pix/proximity/redeem", redeemBody);
    assert.equal((await app.inject({ method: "POST", url: "/pix/proximity/redeem",
      headers: redeemHeaders, payload: { ...redeemBody, amount_cents: 1_100 } })).statusCode, 403);
    const beforeRedeem = bank.account(from).balance_cached;
    const redeemed = await app.inject({ method: "POST", url: "/pix/proximity/redeem",
      headers: redeemHeaders, payload: redeemBody });
    assert.equal(redeemed.statusCode, 200, redeemed.body);
    assert.equal(bank.account(from).balance_cached, beforeRedeem - 1_000);
    assert.equal((await app.inject({ method: "POST", url: "/pix/proximity/redeem",
      headers: redeemHeaders, payload: redeemBody })).statusCode, 403);
    assert.equal(bank.account(from).balance_cached, beforeRedeem - 1_000);
    bank.db.prepare("UPDATE accounts SET kind='merchant' WHERE id=?").run(to);
    const automatic = new PixAutomatic(bank);
    const offer = automatic.createOffer(recipient, to, 5_000, "weekly",
      "2026-11-16T15:00:00.000Z", undefined, false);
    const mandateBody = { from_account: from, merchant_account: to,
      max_amount_cents: 5_000, frequency: "weekly",
      starts_at: "2026-11-16T15:00:00.000Z", offer_id: offer.id };
    assert.equal((await app.inject({ method: "POST", url: "/pix/automatic/mandates",
      headers, payload: mandateBody })).statusCode, 403);
    const mandateHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/pix/automatic/mandates", mandateBody);
    assert.equal((await app.inject({ method: "POST", url: "/pix/automatic/mandates",
      headers: mandateHeaders, payload: { ...mandateBody, max_amount_cents: 6_000 } })).statusCode, 403);
    const granted = await app.inject({ method: "POST", url: "/pix/automatic/mandates",
      headers: mandateHeaders, payload: mandateBody });
    assert.equal(granted.statusCode, 200, granted.body);
    assert.equal(granted.json().status, "active");
    assert.equal((await app.inject({ method: "POST", url: "/pix/automatic/mandates",
      headers: mandateHeaders, payload: mandateBody })).statusCode, 403);
    const nightBody = { night_limit_cents: 90_000 };
    assert.equal((await app.inject({ method: "POST", url: "/pix/limits/night",
      headers, payload: nightBody })).statusCode, 403);
    const nightHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/pix/limits/night", nightBody);
    assert.equal((await app.inject({ method: "POST", url: "/pix/limits/night",
      headers: nightHeaders, payload: { night_limit_cents: 80_000 } })).statusCode, 403);
    const updatedNight = await app.inject({ method: "POST", url: "/pix/limits/night",
      headers: nightHeaders, payload: nightBody });
    assert.equal(updatedNight.statusCode, 200, updatedNight.body);
    assert.equal(bank.pixNightSettings(customer).night_limit_cents, 90_000);
    assert.equal((await app.inject({ method: "POST", url: "/pix/limits/night",
      headers: nightHeaders, payload: nightBody })).statusCode, 403);
    const automaticLimitPath = `/pix/automatic/limits/${from}`;
    const automaticLimitBody = { daily_limit_cents: 5_000 };
    assert.equal((await app.inject({ method: "POST", url: automaticLimitPath,
      headers, payload: automaticLimitBody })).statusCode, 403);
    const automaticLimitHeaders = await signedOperationHeaders(app, headers, privateKey,
      automaticLimitPath, automaticLimitBody);
    assert.equal((await app.inject({ method: "POST", url: automaticLimitPath,
      headers: automaticLimitHeaders, payload: { daily_limit_cents: 6_000 } })).statusCode, 403);
    const updatedAutomaticLimit = await app.inject({ method: "POST", url: automaticLimitPath,
      headers: automaticLimitHeaders, payload: automaticLimitBody });
    assert.equal(updatedAutomaticLimit.statusCode, 200, updatedAutomaticLimit.body);
    assert.equal(bank.pixAutomaticLimit(customer, from).daily_limit_cents, 5_000);
    assert.equal((await app.inject({ method: "POST", url: automaticLimitPath,
      headers: automaticLimitHeaders, payload: automaticLimitBody })).statusCode, 403);
    const medBody = { transfer_id: paid.json().id };
    assert.equal((await app.inject({ method: "POST", url: "/pix/med",
      headers, payload: medBody })).statusCode, 403);
    const medHeaders = await signedOperationHeaders(app, headers, privateKey,
      "/pix/med", medBody);
    assert.equal((await app.inject({ method: "POST", url: "/pix/med",
      headers: medHeaders, payload: { transfer_id: redeemed.json().id } })).statusCode, 403);
    const med = await app.inject({ method: "POST", url: "/pix/med",
      headers: medHeaders, payload: medBody });
    assert.equal(med.statusCode, 200, med.body);
    assert.equal(med.json().status, "open");
    assert.equal((await app.inject({ method: "POST", url: "/pix/med",
      headers: medHeaders, payload: medBody })).statusCode, 403);
  } finally { await app.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
