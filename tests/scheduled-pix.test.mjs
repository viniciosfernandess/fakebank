import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { FeatureRegistry } from "../apps/world/src/features.ts";
import { ScheduledPix } from "../apps/world/src/scheduled-pix.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { EventStore } from "../packages/event-store/src/index.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";
test("authenticated scheduled Pix carries its device into execution-time limits", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-scheduled-device-"));
  let now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const auth = new AuthEngine(bank);
    const customer = seedCustomerId(1);
    auth.setPassword(customer, "a-strong-test-password");
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "a-strong-test-password", "10.0.0.1", "new-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "10.0.0.1");
    const features = new FeatureRegistry(bank);
    features.setEnabled("pix_agendado_recorrente", true, "product-review");
    features.patchFlaw("pix_agendado_recorrente", "engineer");
    const scheduled = new ScheduledPix(bank, features);
    const app = createTwinApi(bank, auth);
    try {
      const headers = { authorization: `Bearer ${session.access_token}` };
      const body = { from_account: seedAccountId(1), to_account: seedAccountId(2),
        amount_cents: 25_000, execute_at: "2026-11-12T12:00:00.000Z", frequency: "once" };
      const highValue = { ...body, amount_cents: 60_000 };
      const denied = await app.inject({ method: "POST", url: "/pix/scheduled", headers, payload: highValue });
      assert.equal(denied.statusCode, 403);
      assert.equal(denied.json().error, "DEF_STEP_UP_REQUIRED");
      assert.equal((await app.inject({ method: "POST", url: "/pix/scheduled", headers, payload: body })).json().error,
        "DEF_DEVICE_PROOF_INVALID");
      auth.stepUp(session.access_token, "a-strong-test-password");
      const key = await bindDeviceKey(app, headers);
      const create = await app.inject({ method: "POST", url: "/pix/scheduled",
        headers: await signedOperationHeaders(app, headers, key, "/pix/scheduled", body), payload: body });
      assert.equal(create.statusCode, 200);
      const job = create.json();
      assert.equal(job.initiating_device_id, auth.deviceForAccess(session.access_token).id);
      now = new Date("2026-11-12T12:00:00.000Z");
      assert.deepEqual(scheduled.executeDue(), { succeeded: 0, failed: 0 });
      assert.equal(scheduled.job(customer, job.id).status, "reauthorization_required");
      assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE actor=?")
        .get(customer).n, 0);
    } finally { await app.close(); }
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a pre-upgrade scheduled Pix needs authenticated device reauthorization", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-scheduled-legacy-device-"));
  let now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    bank.db.exec(`CREATE TABLE scheduled_pix (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      from_account TEXT NOT NULL REFERENCES accounts(id), to_account TEXT NOT NULL REFERENCES accounts(id),
      amount_cents INTEGER NOT NULL, frequency TEXT NOT NULL, next_run_at TEXT NOT NULL,
      status TEXT NOT NULL, scheduled_night_mode INTEGER NOT NULL, created_at TEXT NOT NULL
    )`);
    const features = new FeatureRegistry(bank);
    features.setEnabled("pix_agendado_recorrente", true, "product-review");
    features.patchFlaw("pix_agendado_recorrente", "engineer");
    const scheduled = new ScheduledPix(bank, features);
    const job = scheduled.schedule(seedCustomerId(1), seedAccountId(1), seedAccountId(2),
      20_000, "2026-11-12T12:00:00.000Z", "once");
    const unbound = scheduled.schedule(seedCustomerId(1), seedAccountId(1), seedAccountId(2),
      20_000, "2026-11-12T12:00:00.000Z", "once");
    assert.equal(job.initiating_device_id, null);
    now = new Date("2026-11-12T12:00:00.000Z");
    assert.deepEqual(scheduled.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(scheduled.job(seedCustomerId(1), job.id).status, "reauthorization_required");
    assert.equal(scheduled.job(seedCustomerId(1), unbound.id).status, "reauthorization_required");
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE actor=?")
      .get(seedCustomerId(1)).n, 0);
    now = new Date("2026-11-12T12:01:00.000Z");
    const auth = new AuthEngine(bank);
    auth.setPassword(seedCustomerId(1), "a-strong-test-password");
    const challenge = auth.beginLogin(bank.customer(seedCustomerId(1)).cpf,
      "a-strong-test-password", "10.0.0.1", "legacy-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, seedCustomerId(1)), "10.0.0.1");
    const app = createTwinApi(bank, auth);
    try {
      let headers = { authorization: `Bearer ${session.access_token}` };
      const path = `/pix/scheduled/${job.id}/reauthorize`;
      const request = () => app.inject({ method: "POST", url: path, headers });
      assert.equal((await request()).statusCode, 403);
      auth.stepUp(session.access_token, "a-strong-test-password");
      auth.registerCurrentDeviceForPix(session.access_token);
      assert.equal((await request()).json().error, "DEF_DEVICE_PROOF_INVALID");
      const key = await bindDeviceKey(app, headers);
      headers = await signedOperationHeaders(app, headers, key, path);
      const response = await request();
      assert.equal(response.statusCode, 200);
      assert.equal(response.json().initiating_device_id,
        auth.deviceForAccess(session.access_token).id);
    } finally { await app.close(); }
    assert.deepEqual(scheduled.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(scheduled.job(seedCustomerId(1), job.id).status, "completed");
    assert.equal(scheduled.job(seedCustomerId(1), unbound.id).status, "reauthorization_required");
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE actor=?")
      .get(seedCustomerId(1)).n, 1);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a scheduled Pix requiring step-up waits and settles after fresh authorization", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-scheduled-step-up-"));
  let now = new Date("2026-11-13T02:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 3, accounts: 3, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const auth = new AuthEngine(bank);
    auth.setPassword(customer, "a-strong-test-password");
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "a-strong-test-password", "10.0.0.1", "step-up-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "10.0.0.1");
    auth.stepUp(session.access_token, "a-strong-test-password");
    auth.registerCurrentDeviceForPix(session.access_token);
    for (let index = 0; index < 12; index++) bank.transferPix({ from: seedAccountId(1),
      to: seedAccountId(2), amount: 100, actor: customer,
      idempotencyKey: `scheduled-step-up-history-${index}` });
    const features = new FeatureRegistry(bank);
    features.setEnabled("pix_agendado_recorrente", true, "product-review");
    features.patchFlaw("pix_agendado_recorrente", "engineer");
    const scheduled = new ScheduledPix(bank, features);
    const app = createTwinApi(bank, auth);
    try {
      const headers = { authorization: `Bearer ${session.access_token}` };
      const key = await bindDeviceKey(app, headers);
      const body = { from_account: seedAccountId(1), to_account: seedAccountId(3),
        amount_cents: 100, execute_at: "2026-11-13T02:01:00.000Z", frequency: "once" };
      const created = await app.inject({ method: "POST", url: "/pix/scheduled",
        headers: await signedOperationHeaders(app, headers, key, "/pix/scheduled", body), payload: body });
      assert.equal(created.statusCode, 200);
      const job = created.json();
      now = new Date("2026-11-13T02:01:00.000Z");
      assert.deepEqual(scheduled.executeDue(), { succeeded: 0, failed: 0 });
      assert.equal(scheduled.job(customer, job.id).status, "reauthorization_required");
      assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM scheduled_pix_executions WHERE job_id=?")
        .get(job.id).n, 0);
      auth.stepUp(session.access_token, "a-strong-test-password");
      const path = `/pix/scheduled/${job.id}/reauthorize`;
      const reauthorized = await app.inject({ method: "POST", url: path,
        headers: await signedOperationHeaders(app, headers, key, path) });
      assert.equal(reauthorized.statusCode, 200);
      assert.deepEqual(scheduled.executeDue(), { succeeded: 1, failed: 0 });
      assert.equal(scheduled.job(customer, job.id).status, "completed");
      assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE idempotency_key LIKE 'scheduled:%'")
        .get().n, 1);
    } finally { await app.close(); }
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});


test("unbound devices cannot modify scheduled Pix", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-scheduled-unbound-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-11T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const auth = new AuthEngine(bank);
    const customer = seedCustomerId(1);
    const password = "a-strong-test-password";
    auth.setPassword(customer, password);
    const login = auth.beginLogin(bank.customer(customer).cpf, password, "10.0.0.1", "unbound-device");
    const session = auth.verifyOtp(login.challenge_id, auth.simulatedOtp(login.challenge_id, customer), "10.0.0.1");
    auth.stepUp(session.access_token, password);
    const app = createTwinApi(bank, auth);
    try {
      const operations = [
        ["/pix/scheduled", { from_account: seedAccountId(1), to_account: seedAccountId(2),
          amount_cents: 100, execute_at: "2026-11-12T12:00:00.000Z", frequency: "once" }],
        ["/pix/scheduled/job-1/reauthorize"],
        ["/pix/scheduled/job-1/cancel"],
      ];
      for (const [url, payload] of operations) {
        const response = await app.inject({ method: "POST", url,
          headers: { authorization: `Bearer ${session.access_token}` },
          ...(payload === undefined ? {} : { payload }) });
        assert.equal(response.statusCode, 403, `${url}: ${response.body}`);
        assert.equal(response.json().error, "DEF_DEVICE_PROOF_INVALID", url);
      }
    } finally { await app.close(); }
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
