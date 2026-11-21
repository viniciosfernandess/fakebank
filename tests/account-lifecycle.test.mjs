import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AccountLifecycle } from "../apps/world/src/account-lifecycle.ts";
import { AccountService } from "../apps/world/src/accounts.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { FeatureRegistry } from "../apps/world/src/features.ts";
import { ScheduledPix } from "../apps/world/src/scheduled-pix.ts";
import { PixAutomatic } from "../apps/world/src/pix-automatic.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { Gateway } from "../apps/world/src/gateway.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";

test("operator account lifecycle protects active funds and obligations", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-account-lifecycle-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-14T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const lifecycle = new AccountLifecycle(bank);
    const system = bank.systemAccountId("cash_in");
    assert.throws(() => lifecycle.transition(system, "active", "reviewer"),
      /BIZ_ACCOUNT_STATUS_INVALID/);
    const funded = seedAccountId(1);
    assert.throws(() => lifecycle.transition(funded, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_BALANCE/);
    const holdId = bank.createHold({ accountId: funded, amount: 100, kind: "judicial",
      ref: "case_1", actor: "reviewer", expiresAt: new Date("2026-11-15T12:00:00Z") });
    lifecycle.transition(funded, "frozen", "reviewer", "judicial");
    assert.throws(() => lifecycle.transition(funded, "active", "reviewer"),
      /DEF_ACCOUNT_STATUS_PROTECTED/);
    bank.releaseHold(holdId, "reviewer");
    assert.equal(lifecycle.transition(funded, "active", "reviewer").status, "active");

    const empty = "acc_operator_close_1";
    bank.addAccount({ id: empty, customer_id: seedCustomerId(1), kind: "checking",
      system_role: null, overdraft_limit: 0, status: "active" });
    const key = bank.registerPixKey(seedCustomerId(1), empty, "close-key@example.test");
    assert.throws(() => lifecycle.transition(empty, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_PENDING/);
    bank.deregisterPixKey(seedCustomerId(1), key.id);
    const cards = new CardsEngine(bank);
    const card = cards.issueDebit(seedCustomerId(1), empty);
    assert.throws(() => lifecycle.transition(empty, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_PENDING/);
    cards.update(seedCustomerId(1), card.id, { status: "blocked" });
    const request = bank.requestManualPosting("maker", "Close account correction review", [
      { accountId: empty, amount: 100 }, { accountId: seedAccountId(2), amount: -100 },
    ]);
    assert.throws(() => lifecycle.transition(empty, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_PENDING/);
    bank.resolveManualPosting(request.id, "reviewer", "reject");
    assert.equal(lifecycle.transition(empty, "closed", "reviewer").status, "closed");
    assert.throws(() => lifecycle.transition(empty, "active", "reviewer"),
      /BIZ_ACCOUNT_STATUS_INVALID/);
    assert.deepEqual(lifecycle.history(empty).map((row) => row.to_status), ["closed"]);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("account closure waits for reauthorization and pending automatic charges", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-account-obligations-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-14T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    new ScheduledPix(bank, new FeatureRegistry(bank));
    new AuthEngine(bank);
    new PixAutomatic(bank);
    const owner = seedCustomerId(1);
    const account = "acc_pending_obligations";
    bank.addAccount({ id: account, customer_id: owner, kind: "checking",
      system_role: null, overdraft_limit: 0, status: "active" });
    const now = bank.now().toISOString();
    bank.db.prepare(`INSERT INTO scheduled_pix
      (id,customer_id,from_account,to_account,amount_cents,frequency,next_run_at,status,
       scheduled_night_mode,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`).run(
        "scheduled_close", owner, account, seedAccountId(2), 100, "once", now,
        "reauthorization_required", 0, now);
    const lifecycle = new AccountLifecycle(bank);
    assert.throws(() => lifecycle.transition(account, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_PENDING/);
    bank.db.prepare("UPDATE scheduled_pix SET status='cancelled' WHERE id='scheduled_close'").run();
    bank.db.prepare(`INSERT INTO scheduled_pix_executions
      (id,job_id,due_at,status,executed_at) VALUES (?,?,?,?,?)`)
      .run("execution_close", "scheduled_close", now, "review_pending", now);
    assert.throws(() => lifecycle.transition(account, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_PENDING/);
    bank.db.prepare(`UPDATE scheduled_pix_executions SET status='cancelled'
      WHERE id='execution_close'`).run();
    bank.db.prepare(`INSERT INTO auth_devices
      (id,customer_id,fingerprint,first_seen_at,first_seen_ip) VALUES (?,?,?,?,?)`)
      .run("device_close", owner, "test", now, "127.0.0.1");
    bank.db.prepare(`INSERT INTO pix_automatic_mandates
      (id,customer_id,from_account,merchant_account,max_amount_cents,frequency,
       starts_at,device_id,status,created_at,revoked_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .run("mandate_close", owner, account, seedAccountId(2), 100, "monthly",
        now, "device_close", "revoked", now, now);
    bank.db.prepare(`INSERT INTO pix_automatic_charges
      (id,mandate_id,cycle_start,due_at,amount_cents,status,created_at)
      VALUES (?,?,?,?,?,?,?)`).run("charge_close", "mandate_close", "2026-11-14", now,
        100, "pending", now);
    assert.throws(() => lifecycle.transition(account, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_PENDING/);
    bank.db.prepare("UPDATE pix_automatic_charges SET status='cancelled' WHERE id='charge_close'").run();
    assert.equal(lifecycle.transition(account, "closed", "reviewer").status, "closed");
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("customer closes only an empty, obligation-free account after step-up", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-customer-close-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-14T12:00:00Z"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const customer = seedCustomerId(1);
  const empty = "acc_customer_close";
  bank.addAccount({ id: empty, customer_id: customer, kind: "checking",
    system_role: null, overdraft_limit: 0, status: "active" });
  const auth = new AuthEngine(bank);
  auth.setPassword(customer, "customer-close-password");
  const app = createTwinApi(bank, auth);
  try {
    const login = await app.inject({ method: "POST", url: "/auth/login", payload: {
      cpf: bank.customer(customer).cpf, password: "customer-close-password",
      device_id: "close-device" } });
    const challengeId = login.json().challenge_id;
    const otp = await app.inject({ method: "POST", url: "/auth/otp/verify", payload: {
      challenge_id: challengeId, otp: auth.simulatedOtp(challengeId, customer) } });
    const headers = { authorization: `Bearer ${otp.json().access_token}` };
    const gateway = new Gateway(bank, app);
    const unsignedClose = (id) => gateway.call({ method: "POST",
      path: `/api/v1/accounts/${id}/close`, headers, peerIp: "127.0.0.1" });
    assert.equal((await unsignedClose(empty)).body.error, "DEF_STEP_UP_REQUIRED");
    assert.equal((await app.inject({ method: "POST", url: "/auth/step-up", headers,
      payload: { password: "customer-close-password" } })).statusCode, 200);
    assert.equal((await unsignedClose(empty)).body.error, "DEF_DEVICE_PROOF_INVALID");
    const privateKey = await bindDeviceKey(app, headers);
    assert.equal((await app.inject({ method: "POST",
      url: "/devices/current/key/challenge", headers })).json().error,
    "BIZ_DEVICE_KEY_EXISTS");
    const close = async (id) => {
      const path = `/accounts/${id}/close`;
      const signed = await signedOperationHeaders(app, headers, privateKey, path);
      return gateway.call({ method: "POST", path: `/api/v1${path}`,
        headers: signed, peerIp: "127.0.0.1" });
    };
    assert.equal((await close(seedAccountId(2))).body.error, "DEF_NOT_FOUND");
    assert.equal((await close(seedAccountId(1))).body.error, "BIZ_ACCOUNT_CLOSE_BALANCE");
    const key = bank.registerPixKey(customer, empty, "close-owner@example.test");
    assert.equal((await close(empty)).body.error, "BIZ_ACCOUNT_CLOSE_PENDING");
    bank.deregisterPixKey(customer, key.id);
    const lifecycle = new AccountLifecycle(bank);
    lifecycle.transition(empty, "frozen", "reviewer", "fraud_suspect");
    assert.equal((await close(empty)).body.error, "DEF_ACCOUNT_FROZEN");
    lifecycle.transition(empty, "active", "reviewer");
    assert.deepEqual((await close(empty)).body, { id: empty, status: "closed" });
    assert.equal(bank.account(empty).status, "closed");
    assert.throws(() => bank.fund(empty, 100), /BIZ_ACCOUNT_CLOSED/);
    assert.equal(bank.account(empty).balance_cached, 0);
    assert.deepEqual(lifecycle.history(empty).map((change) => change.to_status),
      ["closed", "active", "frozen"]);
  } finally { await app.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("closed customer cannot open an account or register a Pix key", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-closed-customer-"));
  let now = new Date("2026-11-14T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    bank.registerPixKey(seedCustomerId(2), seedAccountId(2), "closed-claim@example.test");
    const claim = bank.requestPixKeyClaim(customer, seedAccountId(1),
      "closed-claim@example.test", "ownership");
    bank.verifyPixKeyClaim(customer, claim.id,
      bank.simulatedPixKeyClaimProof(claim.id, customer));
    bank.db.prepare("UPDATE customers SET status='closed' WHERE id=?").run(customer);
    assert.throws(() => new AccountService(bank).openSecond(customer), /DEF_ACCOUNT_FROZEN/);
    assert.throws(() => bank.registerPixKey(customer, seedAccountId(1),
      "closed-customer@example.test"), /DEF_ACCOUNT_FROZEN/);
    assert.throws(() => bank.requestPixKeyClaim(customer, seedAccountId(1),
      "closed-claim@example.test", "ownership"), /DEF_ACCOUNT_FROZEN/);
    assert.throws(() => bank.fund(seedAccountId(1), 100), /DEF_ACCOUNT_FROZEN/);
    const balance = bank.account(seedAccountId(1)).balance_cached;
    assert.throws(() => bank.transferPix({ from: seedAccountId(1), to: seedAccountId(2),
      amount: 100, idempotencyKey: "closed-customer-out", actor: customer }),
    /DEF_ACCOUNT_FROZEN/);
    assert.throws(() => bank.transferPix({ from: seedAccountId(2), to: seedAccountId(1),
      amount: 100, idempotencyKey: "closed-customer-in", actor: seedCustomerId(2) }),
    /DEF_ACCOUNT_FROZEN/);
    assert.equal(bank.account(seedAccountId(1)).balance_cached, balance);
    now = new Date(now.getTime() + 7 * 86_400_000 + 1);
    assert.throws(() => bank.completePixKeyClaim(customer, claim.id), /DEF_ACCOUNT_FROZEN/);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_keys WHERE key_value=?")
      .get("closed-customer@example.test").n, 0);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
