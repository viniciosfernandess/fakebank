import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { LoansEngine } from "../apps/world/src/loans.ts";
import { FeatureRegistry } from "../apps/world/src/features.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";

async function fixture(work) {
  const dir = mkdtempSync(join(tmpdir(), "device-quarantine-"));
  let now = new Date("2026-11-14T15:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now, () => new Date("2026-11-14T15:00:00.000Z"));
  let app;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1), auth = new AuthEngine(bank), password = "a-strong-test-password";
    auth.setPassword(customer, password);
    const challenge = auth.beginLogin(bank.customer(customer).cpf, password, "127.0.0.1", "quarantine-device");
    const session = auth.verifyOtp(challenge.challenge_id, auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    auth.stepUp(session.access_token, password);
    app = createTwinApi(bank, auth);
    const headers = { authorization: `Bearer ${session.access_token}` }, key = await bindDeviceKey(app, headers);
    const request = async (method, path, body) => app.inject({ method, url: path,
      headers: await signedOperationHeaders(app, headers, key, path, body, method),
      ...(body === undefined ? {} : { payload: body }) });
    await work({ bank, auth, customer, request, device: auth.deviceForAccess(session.access_token).id,
      setNow: (value) => { now = new Date(value); } });
  } finally { await app?.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("new device limits card issuance and credit through the 24-hour boundary", async () => fixture(async (f) => {
  const { bank, customer, request } = f, account = seedAccountId(1);
  const cardBody = { account_id: account, limit_cents: 20_001 };
  let response = await request("POST", "/cards", cardBody);
  assert.equal(response.json().error, "BIZ_NEW_DEVICE_LIMIT");
  assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM cards").get().n, 0);
  response = await request("POST", "/cards", { ...cardBody, limit_cents: 20_000 });
  assert.equal(response.statusCode, 200, response.body);
  const issued = response.json();
  const increase = await request("PATCH", `/cards/${issued.id}`, { limit_cents: 20_001 });
  assert.equal(increase.json().error, "BIZ_INVALID_CARD_PATCH");
  assert.equal(new CardsEngine(bank).card(issued.id).limit_cents, 20_000);
  const parent = new CardsEngine(bank).issueDebit(customer, account, 100_000);
  new FeatureRegistry(bank).setEnabled("cartao_virtual_temporario", true, "test");
  for (const suffix of ["virtual", "temporary"]) {
    response = await request("POST", `/cards/${parent.id}/${suffix}`, { limit_cents: 20_001 });
    assert.equal(response.json().error, "BIZ_NEW_DEVICE_LIMIT");
    response = await request("POST", `/cards/${parent.id}/${suffix}`, { limit_cents: 20_000 });
    assert.equal(response.statusCode, 200, response.body);
  }
  const loans = new LoansEngine(bank), offer = loans.offer(customer);
  assert.ok(offer.max_amount_cents >= 100_001);
  const before = bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n;
  response = await request("POST", "/loans", { offer_id: offer.id, account_id: account, amount_cents: 100_001 });
  assert.equal(response.json().error, "BIZ_NEW_DEVICE_LIMIT");
  assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n, before);
  response = await request("POST", "/loans", { offer_id: offer.id, account_id: account, amount_cents: 100_000 });
  assert.equal(response.statusCode, 200, response.body);
  f.setNow("2026-11-15T14:59:59.999Z");
  assert.equal((await request("POST", "/cards", cardBody)).json().error, "BIZ_NEW_DEVICE_LIMIT");
  f.setNow("2026-11-15T15:00:00.000Z");
  response = await request("POST", "/cards", cardBody);
  assert.equal(response.statusCode, 200, response.body);
  assert.equal(bank.reconcile().ok, true);
}));

test("Pix registration retains the 24-hour cap and invalid device dates fail closed", async () => fixture(async (f) => {
  const { bank, request, device } = f;
  assert.equal((await request("POST", "/devices/current/pix-registration")).statusCode, 200);
  const payment = { from_account: seedAccountId(1), to_account: seedAccountId(2),
    amount_cents: 20_001, idempotency_key: "quarantine-pix" };
  assert.equal((await request("POST", "/pix/transfers", payment)).json().error, "BIZ_NEW_DEVICE_LIMIT");
  for (const value of ["not-a-date", "2026-11-14T15:00:00Z", "2026-11-15T15:00:00.000Z"]) {
    bank.db.prepare("UPDATE auth_devices SET first_seen_at=? WHERE id=?").run(value, device);
    const response = await request("POST", "/cards", { account_id: seedAccountId(1), limit_cents: 100 });
    assert.equal(response.json().error, "DEF_UNAUTHORIZED", value);
  }
  bank.db.prepare("UPDATE auth_devices SET first_seen_at=? WHERE id=?").run("2026-11-14T15:00:00.000Z", device);
  bank.db.prepare("UPDATE auth_devices SET bound_at=? WHERE id=?").run("invalid", device);
  assert.equal((await request("POST", "/cards", { account_id: seedAccountId(1), limit_cents: 100 })).json().error,
    "DEF_UNAUTHORIZED");
  bank.db.prepare("UPDATE auth_devices SET bound_at=? WHERE id=?").run("2026-11-14T15:00:00.000Z", device);
  f.setNow("2026-11-15T14:59:59.999Z");
  assert.equal((await request("POST", "/pix/transfers", payment)).json().error, "BIZ_NEW_DEVICE_LIMIT");
  f.setNow("2026-11-15T15:00:00.000Z");
  assert.equal((await request("POST", "/pix/transfers", payment)).statusCode, 200);
  assert.equal(bank.reconcile().ok, true);
}));

test("binding a previously seen device starts a fresh simulated 24-hour quarantine", async () => {
  const dir = mkdtempSync(join(tmpdir(), "device-late-binding-"));
  let now = new Date("2026-11-14T15:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now, () => new Date("2026-11-14T15:00:00.000Z"));
  let app;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1), auth = new AuthEngine(bank), password = "a-strong-test-password";
    auth.setPassword(customer, password);
    const challenge = auth.beginLogin(bank.customer(customer).cpf, password, "127.0.0.1", "late-binding-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    auth.stepUp(session.access_token, password);
    app = createTwinApi(bank, auth);
    now = new Date("2026-11-17T15:00:00.000Z");
    const headers = { authorization: `Bearer ${session.access_token}` };
    const key = await bindDeviceKey(app, headers);
    const device = auth.deviceForAccess(session.access_token).id;
    const dates = bank.db.prepare("SELECT first_seen_at,bound_at FROM auth_devices WHERE id=?").get(device);
    assert.equal(dates.first_seen_at, "2026-11-14T15:00:00.000Z");
    assert.equal(dates.bound_at, "2026-11-17T15:00:00.000Z");
    const body = { account_id: seedAccountId(1), limit_cents: 20_001 };
    const issue = async () => app.inject({ method: "POST", url: "/cards",
      headers: await signedOperationHeaders(app, headers, key, "/cards", body, "POST"), payload: body });
    assert.equal((await issue()).json().error, "BIZ_NEW_DEVICE_LIMIT");
    now = new Date("2026-11-18T14:59:59.999Z");
    assert.equal((await issue()).json().error, "BIZ_NEW_DEVICE_LIMIT");
    now = new Date("2026-11-18T15:00:00.000Z");
    assert.equal((await issue()).statusCode, 200);
  } finally { await app?.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("legacy bound devices retain their established age during schema migration", async () => fixture(async ({ bank, device }) => {
  const original = bank.db.prepare("SELECT first_seen_at FROM auth_devices WHERE id=?").get(device).first_seen_at;
  bank.db.exec("ALTER TABLE auth_devices DROP COLUMN bound_at");
  new AuthEngine(bank);
  const migrated = bank.db.prepare("SELECT bound_at FROM auth_devices WHERE id=?").get(device).bound_at;
  assert.equal(migrated, original);
}));

test("refinancing rolls back over-cap credit and signed card reactivation has a temporary cap", async () => fixture(async (f) => {
  const { bank, customer, request } = f;
  const loans = new LoansEngine(bank), offer = loans.offer(customer);
  const loan = loans.accept(customer, offer.id, seedAccountId(1), 150_000);
  const before = bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n;
  const rejected = await request("POST", `/loans/${loan.id}/refinance`);
  assert.equal(rejected.json().error, "BIZ_NEW_DEVICE_LIMIT");
  assert.equal(loans.loan(customer, loan.id).status, "active");
  assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n, before);
  const card = new CardsEngine(bank).issueDebit(customer, seedAccountId(1), 100_000);
  const blocked = await request("PATCH", `/cards/${card.id}`, { status: "blocked" });
  assert.equal(blocked.statusCode, 200, blocked.body);
  assert.equal(blocked.json().status, "blocked");
  const activate = await request("PATCH", `/cards/${card.id}`, { status: "active" });
  assert.equal(activate.statusCode, 200, activate.body);
  assert.equal(activate.json().limit_cents, 100_000);
  assert.equal(activate.json().effective_limit_cents, 20_000);
  f.setNow("2026-11-15T15:00:00.000Z");
  assert.equal(new CardsEngine(bank).card(card.id).effective_limit_cents, 100_000);
  assert.equal(bank.reconcile().ok, true);
}));


test("financial engines revalidate ownership and revocation inside their transaction", async () => fixture(async (f) => {
  const { bank, customer, device } = f;
  const cards = new CardsEngine(bank), loans = new LoansEngine(bank);
  const other = seedCustomerId(2), before = bank.db.prepare("SELECT COUNT(*) n FROM cards").get().n;
  assert.throws(() => cards.issueDebit(other, seedAccountId(2), 100, device), /DEF_UNAUTHORIZED/);
  const offer = loans.offer(other);
  assert.throws(() => loans.accept(other, offer.id, seedAccountId(2), 100, undefined, device), /DEF_UNAUTHORIZED/);
  bank.db.prepare("UPDATE auth_devices SET revoked_at=? WHERE id=?").run("2026-11-14T15:00:00.000Z", device);
  assert.throws(() => cards.issueDebit(customer, seedAccountId(1), 100, device), /DEF_UNAUTHORIZED/);
  assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM cards").get().n, before);
}));
