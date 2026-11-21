import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { PixAutomatic, automaticPixPosting } from "../apps/world/src/pix-automatic.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { Gateway, isGatewayAllowed } from "../apps/world/src/gateway.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { bindDeviceKey, signedOperationHeaders, signedRefresh } from "./device-proof-helper.mjs";

function setup(customers = 2, simulatedRealTime = false) {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-automatic-"));
  let now = new Date("2026-11-12T12:00:00.000Z");
  const path = join(dir, "bank.sqlite");
  const bank = new Bank(path, () => now, simulatedRealTime ? () => now : undefined);
  seedBank(bank, { customers, accounts: customers, historyTransactions: 0 });
  bank.db.prepare("UPDATE accounts SET kind='merchant' WHERE id=?").run(seedAccountId(2));
  const auth = new AuthEngine(bank);
  const publicKey = generateKeyPairSync("ed25519").publicKey
    .export({ format: "der", type: "spki" }).toString("base64url");
  bank.db.prepare(`INSERT INTO auth_devices
    (id,customer_id,fingerprint,first_seen_at,first_seen_ip,pix_registered_at,public_key,bound_at)
    VALUES (?,?,?,?,?,?,?,?)`).run("automatic-device", seedCustomerId(1), "test",
      now.toISOString(), "127.0.0.1", now.toISOString(), publicKey, now.toISOString());
  const automatic = new PixAutomatic(bank);
  return { bank, auth, automatic, dir, path, setNow: (value) => { now = new Date(value); },
    close: () => { bank.close(); rmSync(dir, { recursive: true, force: true }); } };
}

function retryOffer(automatic) {
  return automatic.createOffer(seedCustomerId(2), seedAccountId(2),
    5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, true).id;
}

test("delayed Pix Automatic charge survives scanner restart and settles exactly once", () => {
  const fixture = setup(2, true);
  const { bank, automatic, setNow } = fixture;
  try {
    const dueAt = "2026-11-14T10:00:00.000Z";
    const schedule = () => {
      const mandate = automatic.grant(seedCustomerId(1), seedAccountId(1),
        seedAccountId(2), 5_000, "weekly", dueAt, undefined, "automatic-device");
      return automatic.charge(seedCustomerId(2), mandate.id, 100, dueAt).id;
    };
    const delayed = schedule();
    const unaffected = schedule();
    let sentinel = new SentinelEngine(bank);
    setNow("2026-11-14T09:59:59.000Z");
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-43"), false);
    setNow(dueAt);
    assert.deepEqual(automatic.executeDue((id) => id === delayed), { succeeded: 1, failed: 0 });
    assert.ok(automaticPixPosting(bank, unaffected));
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-43"), false);
    setNow("2026-11-14T10:00:30.000Z");
    sentinel = new SentinelEngine(bank);
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-43"), false);
    setNow("2026-11-14T10:00:31.000Z");
    const alerts = sentinel.scan().filter((alert) => alert.rule_id === "S-PIX-43");
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].entity, delayed);
    assert.equal(alerts[0].observed.age_ms, 31_000);
    assert.equal(automaticPixPosting(bank, delayed), undefined);
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.ok(automaticPixPosting(bank, delayed));
    assert.equal(bank.reconcile().ok, true);
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-43"), false);
  } finally { fixture.close(); }
});

test("repeated Pix Automatic mandates alert on the third grant", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const sentinel = new SentinelEngine(bank);
    for (let index = 0; index < 2; index++)
      automatic.grant(seedCustomerId(1), seedAccountId(1), seedAccountId(2),
        5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-20"), false);
    automatic.grant(seedCustomerId(1), seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-20");
    assert.equal(alert?.entity, seedCustomerId(1));
    assert.equal(alert?.observed.mandates_granted, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='mandate_granted' AND user_id=?`)
      .get(seedCustomerId(1)).n, 3);
  } finally { fixture.close(); }
});

test("repeated Pix Automatic merchant offers alert on the fifth creation", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const sentinel = new SentinelEngine(bank);
    for (let index = 0; index < 4; index++)
      retryOffer(automatic);
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-21"), false);
    retryOffer(automatic);
    const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-21");
    assert.equal(alert?.entity, seedCustomerId(2));
    assert.equal(alert?.observed.offers_created, 5);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='offer_created' AND user_id=?`)
      .get(seedCustomerId(2)).n, 5);
  } finally { fixture.close(); }
});

test("repeated Pix Automatic mandates alert on the third revocation", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const sentinel = new SentinelEngine(bank);
    const mandates = [];
    for (let index = 0; index < 3; index++)
      mandates.push(automatic.grant(seedCustomerId(1), seedAccountId(1),
        seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
        undefined, "automatic-device"));
    for (const mandate of mandates.slice(0, 2))
      automatic.revoke(seedCustomerId(1), mandate.id);
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-22"), false);
    automatic.revoke(seedCustomerId(1), mandates[2].id);
    const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-22");
    assert.equal(alert?.entity, seedCustomerId(1));
    assert.equal(alert?.observed.mandates_revoked, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='mandate_revoked' AND user_id=?`)
      .get(seedCustomerId(1)).n, 3);
  } finally { fixture.close(); }
});

test("repeated Pix Automatic merchant offers alert on the fifth revocation", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const sentinel = new SentinelEngine(bank);
    const offers = [];
    for (let index = 0; index < 5; index++)
      offers.push(retryOffer(automatic));
    for (const offerId of offers.slice(0, 4))
      automatic.revokeOffer(seedCustomerId(2), offerId);
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-23"), false);
    automatic.revokeOffer(seedCustomerId(2), offers[4]);
    const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-23");
    assert.equal(alert?.entity, seedCustomerId(2));
    assert.equal(alert?.observed.offers_revoked, 5);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='offer_revoked' AND user_id=?`)
      .get(seedCustomerId(2)).n, 5);
  } finally { fixture.close(); }
});

test("repeated Pix Automatic charges alert on the third payer-merchant submission", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const sentinel = new SentinelEngine(bank);
    for (let index = 0; index < 2; index++) {
      const mandate = automatic.grant(seedCustomerId(1), seedAccountId(1),
        seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
        undefined, "automatic-device");
      automatic.charge(seedCustomerId(2), mandate.id, 1_000,
        "2026-11-14T10:00:00.000Z");
    }
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-24"), false);
    const third = automatic.grant(seedCustomerId(1), seedAccountId(1),
      seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
      undefined, "automatic-device");
    automatic.charge(seedCustomerId(2), third.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-24");
    assert.equal(alert?.entity, seedCustomerId(1));
    assert.equal(alert?.observed.merchant_account, seedAccountId(2));
    assert.equal(alert?.observed.charges_submitted, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='charge_submitted' AND user_id=?
        AND counterparty=?`).get(seedCustomerId(1), seedAccountId(2)).n, 3);
  } finally { fixture.close(); }
});

test("held automatic charge creates a source-linked Pix risk review alert", () => {
  const fixture = setup(7);
  const { bank, automatic, setNow } = fixture;
  try {
    const sentinel = new SentinelEngine(bank);
    bank.risk.setVerifiedProfile(seedCustomerId(1), "high", 50_000, "risk_reviewer");
    for (let index = 0; index < 12; index++) bank.transferPix({
      from: seedAccountId(1), to: seedAccountId(3), amount: 100,
      idempotencyKey: `automatic-risk-history-${index}`, actor: seedCustomerId(1) });
    const mandate = automatic.grant(seedCustomerId(1), seedAccountId(1),
      seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
      undefined, "automatic-device");
    const charge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    setNow("2026-11-14T10:00:00.000Z");
    for (let index = 3; index <= 7; index++) bank.transferPix({
      from: seedAccountId(index), to: seedAccountId(2), amount: 100,
      idempotencyKey: `automatic-risk-fanin-${index}`,
      actor: seedCustomerId(index) });
    bank.db.prepare("UPDATE auth_devices SET bound_at=? WHERE id='automatic-device'")
      .run(bank.now().toISOString());
    automatic.executeDue();
    assert.equal(bank.db.prepare(`SELECT status FROM pix_automatic_charges
      WHERE id=?`).get(charge.id)?.status, "review_pending");
    const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-08");
    assert.ok(alert);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='charge_held' AND account_id=?`)
      .get(seedAccountId(1)).n, 1);
  } finally { fixture.close(); }
});

test("Pix Automatic retries and failures alert only after three affected charges", () => {
  for (const count of [2, 3]) {
    const fixture = setup();
    const { bank, automatic, setNow } = fixture;
    try {
      const sentinel = new SentinelEngine(bank);
      for (let index = 0; index < count; index++) {
        const mandate = automatic.grant(seedCustomerId(1), seedAccountId(1),
          seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
          undefined, "automatic-device");
        automatic.charge(seedCustomerId(2), mandate.id, 1_000,
          "2026-11-14T10:00:00.000Z");
      }
      setNow("2026-11-14T14:00:00.000Z");
      automatic.executeDue();
      const retry = sentinel.scan().find((item) => item.rule_id === "S-PIX-25");
      assert.equal(retry?.observed.retries_scheduled, count === 3 ? 3 : undefined);
      setNow("2026-11-15T12:00:00.000Z");
      automatic.executeDue();
      const failed = sentinel.scan().find((item) => item.rule_id === "S-PIX-26");
      assert.equal(failed?.observed.charges_failed, count === 3 ? 3 : undefined);
      for (const action of ["charge_retry_scheduled", "charge_failed"])
        assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
          WHERE source='pix' AND action=? AND user_id=?`)
          .get(action, seedCustomerId(1)).n, count);
    } finally { fixture.close(); }
  }
});

test("Pix Automatic settlement volume alerts only after three payer-merchant charges", () => {
  for (const count of [2, 3]) {
    const fixture = setup();
    const { bank, automatic, setNow } = fixture;
    try {
      const sentinel = new SentinelEngine(bank);
      for (let index = 0; index < count; index++) {
        const mandate = automatic.grant(seedCustomerId(1), seedAccountId(1),
          seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
          undefined, "automatic-device");
        automatic.charge(seedCustomerId(2), mandate.id, 1_000,
          "2026-11-14T10:00:00.000Z");
      }
      setNow("2026-11-14T10:00:00.000Z");
      assert.equal(automatic.executeDue().succeeded, count);
      const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-27");
      assert.equal(alert?.observed.charges_settled, count === 3 ? 3 : undefined);
      assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
        WHERE source='pix' AND action='charge_settled' AND user_id=?
          AND counterparty=?`).get(seedCustomerId(1), seedAccountId(2)).n, count);
      assert.equal(bank.verifyLedgerChain(), true);
      assert.equal(bank.reconcileSpi().ok, true);
    } finally { fixture.close(); }
  }
});

test("Pix Automatic cancellations alert on the third committed cancellation", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const sentinel = new SentinelEngine(bank);
    const charges = [];
    for (let index = 0; index < 3; index++) {
      const mandate = automatic.grant(seedCustomerId(1), seedAccountId(1),
        seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
        undefined, "automatic-device");
      charges.push(automatic.charge(seedCustomerId(2), mandate.id, 1_000,
        "2026-11-14T10:00:00.000Z"));
    }
    for (const charge of charges.slice(0, 2))
      automatic.cancelCharge(seedCustomerId(1), charge.id);
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-28"), false);
    automatic.cancelCharge(seedCustomerId(1), charges[2].id);
    const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-28");
    assert.equal(alert?.entity, seedCustomerId(1));
    assert.equal(alert?.observed.charges_cancelled, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='charge_cancelled' AND user_id=?`)
      .get(seedCustomerId(1)).n, 3);
  } finally { fixture.close(); }
});

test("merchant post-due retry instructions alert on the third charge", () => {
  const fixture = setup();
  const { bank, automatic, setNow } = fixture;
  try {
    const sentinel = new SentinelEngine(bank);
    const charges = [];
    for (let index = 0; index < 3; index++) {
      const offerId = retryOffer(automatic);
      const mandate = automatic.grant(seedCustomerId(1), seedAccountId(1),
        seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
        undefined, "automatic-device", offerId);
      charges.push(automatic.charge(seedCustomerId(2), mandate.id, 1_000,
        "2026-11-14T10:00:00.000Z"));
    }
    setNow("2026-11-15T01:00:00.000Z");
    assert.equal(automatic.executeDue().failed, 3);
    for (const charge of charges.slice(0, 2))
      automatic.retryCharge(seedCustomerId(2), charge.id,
        "2026-11-16T10:00:00.000Z");
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-31"), false);
    automatic.retryCharge(seedCustomerId(2), charges[2].id,
      "2026-11-16T10:00:00.000Z");
    const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-31");
    assert.equal(alert?.entity, seedCustomerId(2));
    assert.equal(alert?.observed.post_due_retries, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='charge_post_due_retry' AND user_id=?`)
      .get(seedCustomerId(2)).n, 3);
  } finally { fixture.close(); }
});

test("automatic reauthorization alerts only after the third affected charge", () => {
  for (const count of [2, 3]) {
    const fixture = setup();
    const { bank, automatic, setNow } = fixture;
    try {
      const sentinel = new SentinelEngine(bank);
      bank.db.prepare("UPDATE auth_devices SET pix_registered_at=NULL WHERE id=?")
        .run("automatic-device");
      const charges = [];
      for (let index = 0; index < count; index++) {
        const mandate = automatic.grant(seedCustomerId(1), seedAccountId(1),
          seedAccountId(2), 50_000, "weekly", "2026-11-14T10:00:00.000Z",
          undefined, "automatic-device");
        charges.push(automatic.charge(seedCustomerId(2), mandate.id, 25_000,
          "2026-11-14T10:00:00.000Z"));
      }
      setNow("2026-11-14T10:00:00.000Z");
      automatic.executeDue();
      const required = sentinel.scan().find((item) => item.rule_id === "S-PIX-32");
      assert.equal(required?.observed.reauthorizations_required,
        count === 3 ? 3 : undefined);
      bank.db.prepare("UPDATE auth_devices SET pix_registered_at=? WHERE id=?")
        .run(bank.now().toISOString(), "automatic-device");
      for (const charge of charges)
        automatic.reauthorize(seedCustomerId(1), charge.id, "automatic-device");
      const reauthorized = sentinel.scan().find((item) => item.rule_id === "S-PIX-33");
      assert.equal(reauthorized?.observed.charges_reauthorized,
        count === 3 ? 3 : undefined);
      for (const action of ["charge_reauthorization_required", "charge_reauthorized"])
        assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
          WHERE source='pix' AND action=? AND user_id=?`)
          .get(action, seedCustomerId(1)).n, count);
    } finally { fixture.close(); }
  }
});

test("gateway allows only the intended Pix Automatic customer routes", () => {
  for (const path of ["/pix/automatic/offers", "/pix/automatic/offers/offer-1",
    "/pix/automatic/offers/offer-1/revoke",
    "/pix/automatic/mandates", "/pix/automatic/mandates/mandate-1",
    "/pix/automatic/mandates/mandate-1/charges",
    "/pix/automatic/mandates/mandate-1/revoke",
    "/pix/automatic/charges/charge-1/cancel",
    "/pix/automatic/charges/charge-1/merchant-cancel",
    "/pix/automatic/charges/charge-1/reauthorize",
    "/pix/automatic/charges/charge-1/retry",
    "/pix/automatic/notifications", "/pix/automatic/limits/account-1"])
    assert.equal(isGatewayAllowed(path), true, path);
  for (const path of ["/pix/automatic", "/pix/automatic/charges/charge-1",
    "/pix/automatic/offers/offer-1/delete",
    "/pix/automatic/mandates/mandate-1/unknown"])
    assert.equal(isGatewayAllowed(path), false, path);
});

test("payer can page durable notifications without crossing customer boundaries", async () => {
  const fixture = setup();
  const { bank, auth, automatic } = fixture;
  try {
    const payerId = seedCustomerId(1);
    const merchantId = seedCustomerId(2);
    const mandate = automatic.grant(payerId, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    automatic.charge(merchantId, mandate.id, 1_000, "2026-11-14T10:00:00.000Z");
    for (const id of [payerId, merchantId]) auth.setPassword(id, "a-strong-test-password");
    const sessionFor = (id) => {
      const login = auth.beginLogin(bank.customer(id).cpf, "a-strong-test-password",
        "10.0.0.1", `notification-device-${id}`);
      return auth.verifyOtp(login.challenge_id,
        auth.simulatedOtp(login.challenge_id, id), "10.0.0.1");
    };
    const payer = sessionFor(payerId);
    const merchant = sessionFor(merchantId);
    const app = createTwinApi(bank, auth);
    const gateway = new Gateway(bank, app);
    const call = (path, access) => gateway.call({ method: "GET",
      path: `/api/v1/pix/automatic/notifications${path}`,
      peerIp: "10.0.0.1",
      ...(access ? { headers: { authorization: `Bearer ${access}` } } : {}) });
    try {
      const first = await call("?limit=1", payer.access_token);
      assert.equal(first.status, 200);
      assert.equal(first.body.length, 1);
      const cursor = encodeURIComponent(first.body[0].id);
      const second = await call(`?limit=1&before=${cursor}`, payer.access_token);
      assert.equal(second.status, 200);
      assert.deepEqual([first.body[0].kind, second.body[0].kind].sort(),
        ["charge_scheduled", "mandate_granted"]);
      assert.deepEqual((await call(`?limit=1&before=${encodeURIComponent(second.body[0].id)}`,
        payer.access_token)).body, []);
      assert.equal((await call(`?before=${cursor}`, merchant.access_token)).status, 404);
      assert.equal((await call("?limit=1", merchant.access_token)).body.length, 0);
      assert.equal((await call("?limit=1")).status, 403);
      assert.equal((await call("?limit=0", payer.access_token)).status, 400);
    } finally { await app.close(); }
  } finally { fixture.close(); }
});

test("Pix Automatic enforces payer consent, merchant ownership, amount and one charge per cycle", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const start = "2026-11-14T10:00:00.000Z";
    assert.throws(() => automatic.grant(payer, seedAccountId(1), seedAccountId(1),
      5_000, "monthly", start, undefined, "automatic-device"),
    (error) => error instanceof BankError && error.code === "BIZ_AUTOMATIC_MERCHANT");
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "monthly", start, undefined, "automatic-device");
    assert.equal(automatic.list(payer).length, 1);
    assert.throws(() => automatic.mandate(merchant, mandate.id),
      (error) => error instanceof BankError && error.code === "DEF_NOT_FOUND");
    assert.throws(() => automatic.charge(payer, mandate.id, 1_000, start),
      (error) => error instanceof BankError && error.code === "DEF_NOT_FOUND");
    assert.throws(() => automatic.charge(merchant, mandate.id, 5_001, start),
      (error) => error instanceof BankError && error.code === "BIZ_AUTOMATIC_LIMIT");
    assert.throws(() => automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-14T12:00:00.000Z"),
    (error) => error instanceof BankError && error.code === "BIZ_AUTOMATIC_WINDOW");
    const charge = automatic.charge(merchant, mandate.id, 1_000, start);
    assert.equal(charge.status, "pending");
    assert.deepEqual(automatic.notifications(payer).map((notice) => notice.kind).sort(),
      ["charge_scheduled", "mandate_granted"]);
    assert.deepEqual(automatic.notifications(merchant), []);
    assert.throws(() => automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-15T10:00:00.000Z"),
    (error) => error instanceof BankError && error.code === "BIZ_AUTOMATIC_CYCLE_DUPLICATE");
    fixture.setNow(start);
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(automatic.executeDue().succeeded, 0);
    assert.equal(automatic.notifications(payer).filter((notice) =>
      notice.kind === "charge_settled").length, 1);
    assert.equal(bank.db.prepare("SELECT status,transfer_id FROM pix_automatic_charges WHERE id=?")
      .get(charge.id).status, "settled");
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE idempotency_key=?")
      .get(`automatic:${charge.id}`).n, 1);
    assert.equal(bank.reconcile().ok, true);
  } finally { fixture.close(); }
});

test("merchant instructions arrive two to ten Sao Paulo calendar days before payment", () => {
  const fixture = setup();
  try {
    const merchant = seedCustomerId(2);
    const mandate = fixture.automatic.grant(seedCustomerId(1), seedAccountId(1),
      seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
      undefined, "automatic-device");
    assert.equal(fixture.automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z").status, "pending");
    assert.equal(fixture.automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-22T10:00:00.000Z").status, "pending");
    assert.throws(() => fixture.automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-23T10:00:00.000Z"),
    (error) => error instanceof BankError && error.code ===
      "BIZ_AUTOMATIC_INSTRUCTION_WINDOW");
    fixture.setNow("2026-11-13T12:00:00.000Z");
    assert.throws(() => fixture.automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z"),
    (error) => error instanceof BankError && error.code ===
      "BIZ_AUTOMATIC_INSTRUCTION_WINDOW");
  } finally { fixture.close(); }
});

test("revocation cancels pending charges and cannot be bypassed by the merchant", () => {
  const fixture = setup();
  try {
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const mandate = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = fixture.automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    assert.equal(fixture.automatic.revoke(payer, mandate.id).status, "revoked");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    assert.deepEqual(fixture.automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(fixture.bank.db.prepare("SELECT status FROM pix_automatic_charges WHERE id=?")
      .get(charge.id).status, "cancelled");
    assert.throws(() => fixture.automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-21T12:00:00.000Z"),
    (error) => error instanceof BankError && error.code === "BIZ_AUTOMATIC_REVOKED");
  } finally { fixture.close(); }
});

test("payer can inspect and cancel a charge without revoking the mandate", () => {
  const fixture = setup();
  try {
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const mandate = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = fixture.automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    assert.equal(fixture.automatic.charges(payer, mandate.id)[0].id, charge.id);
    assert.throws(() => fixture.automatic.charges(merchant, mandate.id),
      (error) => error instanceof BankError && error.code === "DEF_NOT_FOUND");
    fixture.setNow("2026-11-14T02:59:00.000Z");
    assert.equal(fixture.automatic.cancelCharge(payer, charge.id).status, "cancelled");
    assert.equal(fixture.automatic.mandate(payer, mandate.id).status, "active");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    assert.deepEqual(fixture.automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(fixture.bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE idempotency_key=?")
      .get(`automatic:${charge.id}`).n, 0);
  } finally { fixture.close(); }
});

test("specific charge cancellation closes at midnight in Sao Paulo", () => {
  const fixture = setup();
  try {
    const payer = seedCustomerId(1);
    const mandate = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined,
      "automatic-device");
    const charge = fixture.automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-14T03:00:00.000Z");
    assert.throws(() => fixture.automatic.cancelCharge(payer, charge.id),
      (error) => error instanceof BankError && error.code ===
        "BIZ_AUTOMATIC_CANCEL_UNAVAILABLE");
    assert.equal(fixture.automatic.charges(payer, mandate.id)[0].status, "pending");
  } finally { fixture.close(); }
});

test("only the merchant can cancel its charge before 22:00 on the previous day", () => {
  const fixture = setup();
  try {
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const mandate = fixture.automatic.grant(payer, seedAccountId(1),
      seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
      undefined, "automatic-device");
    const first = fixture.automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    const next = fixture.automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-21T10:00:00.000Z");
    assert.throws(() => fixture.automatic.cancelMerchantCharge(payer, first.id),
      (error) => error instanceof BankError && error.code === "DEF_NOT_FOUND");
    fixture.setNow("2026-11-14T00:59:59.000Z");
    assert.equal(fixture.automatic.cancelMerchantCharge(merchant, first.id).error_code,
      "BIZ_AUTOMATIC_MERCHANT_CANCELLED");
    assert.equal(fixture.automatic.notifications(payer).filter((notice) =>
      notice.kind === "charge_cancelled").length, 1);
    fixture.setNow("2026-11-21T01:00:00.000Z");
    assert.throws(() => fixture.automatic.cancelMerchantCharge(merchant, next.id),
      (error) => error instanceof BankError && error.code ===
        "BIZ_AUTOMATIC_CANCEL_UNAVAILABLE");
    assert.equal(fixture.automatic.charges(payer, mandate.id).find((row) =>
      row.id === next.id).status, "pending");
  } finally { fixture.close(); }
});

test("monthly cycles preserve the Sao Paulo civil day across UTC month boundaries", () => {
  const fixture = setup();
  try {
    fixture.setNow("2027-02-25T12:00:00.000Z");
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const mandate = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "monthly", "2027-03-01T02:00:00.000Z", undefined, "automatic-device");
    assert.equal(mandate.cycle_policy, "sao_paulo_v1");
    const first = fixture.automatic.charge(merchant, mandate.id, 1_000, "2027-03-01T03:00:00.000Z");
    assert.equal(first.cycle_start, "2027-03-01T02:00:00.000Z");
    fixture.setNow("2027-03-23T12:00:00.000Z");
    const second = fixture.automatic.charge(merchant, mandate.id, 1_000, "2027-03-29T03:00:00.000Z");
    assert.equal(second.cycle_start, "2027-03-29T02:00:00.000Z");
    assert.throws(() => fixture.automatic.charge(merchant, mandate.id, 1_000, "2027-03-30T03:00:00.000Z"),
      (error) => error instanceof BankError && error.code === "BIZ_AUTOMATIC_CYCLE_DUPLICATE");
    assert.throws(() => fixture.bank.db.prepare("UPDATE pix_automatic_mandates SET cycle_policy='utc_legacy' WHERE id=?")
      .run(mandate.id), /AUTOMATIC_CYCLE_POLICY_IMMUTABLE/);
  } finally { fixture.close(); }
});

test("monthly cycles shift nonexistent Sao Paulo civil times forward across a DST gap", () => {
  const fixture = setup();
  try {
    fixture.setNow("2018-10-01T12:00:00.000Z");
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const mandate = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "monthly", "2018-10-04T03:30:00.000Z", undefined, "automatic-device");
    const first = fixture.automatic.charge(merchant, mandate.id, 1_000, "2018-10-06T04:00:00.000Z");
    assert.equal(first.cycle_start, "2018-10-04T03:30:00.000Z");
    fixture.setNow("2018-10-29T12:00:00.000Z");
    const second = fixture.automatic.charge(merchant, mandate.id, 1_000, "2018-11-04T04:00:00.000Z");
    assert.equal(second.cycle_start, "2018-11-04T03:30:00.000Z");
    assert.equal(fixture.bank.reconcile().ok, true);
  } finally { fixture.close(); }
});

test("monthly cycles choose the earlier occurrence of a repeated Sao Paulo civil time", () => {
  const fixture = setup();
  try {
    fixture.setNow("2019-01-11T12:00:00.000Z");
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const mandate = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "monthly", "2019-01-17T01:30:00.000Z", undefined, "automatic-device");
    fixture.automatic.charge(merchant, mandate.id, 1_000, "2019-01-17T03:00:00.000Z");
    fixture.setNow("2019-02-10T12:00:00.000Z");
    const second = fixture.automatic.charge(merchant, mandate.id, 1_000, "2019-02-17T03:00:00.000Z");
    assert.equal(second.cycle_start, "2019-02-17T01:30:00.000Z");
    assert.equal(fixture.bank.reconcile().ok, true);
  } finally { fixture.close(); }
});

test("post-due retry cannot cross the Sao Paulo civil cycle boundary", () => {
  const fixture = setup();
  try {
    fixture.setNow("2027-02-25T12:00:00.000Z");
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const start = "2027-03-01T02:00:00.000Z";
    const offer = fixture.automatic.createOffer(merchant, seedAccountId(2), 5_000,
      "monthly", start, undefined, true);
    const mandate = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "monthly", start, undefined, "automatic-device", offer.id);
    fixture.setNow("2027-03-20T12:00:00.000Z");
    const charge = fixture.automatic.charge(merchant, mandate.id, 1_000, "2027-03-27T03:00:00.000Z");
    fixture.bank.requestPixAutomaticLimit(payer, seedAccountId(1), 0);
    fixture.setNow("2027-03-27T03:00:00.000Z");
    assert.deepEqual(fixture.automatic.executeDue(), { succeeded: 0, failed: 0 });
    fixture.setNow("2027-03-27T21:00:00.000Z");
    assert.deepEqual(fixture.automatic.executeDue(), { succeeded: 0, failed: 1 });
    fixture.setNow("2027-03-28T00:01:00.000Z");
    assert.throws(() => fixture.automatic.retryCharge(merchant, charge.id, "2027-03-28T03:00:00.000Z"),
      (error) => error instanceof BankError && error.code === "BIZ_AUTOMATIC_RETRY_PERIOD");
    assert.equal(fixture.automatic.charges(payer, mandate.id)[0].status, "failed");
  } finally { fixture.close(); }
});

test("legacy automatic mandates keep UTC cycle identity after migration", () => {
  const fixture = setup();
  try {
    fixture.setNow("2027-02-25T12:00:00.000Z");
    const merchant = seedCustomerId(2);
    const mandate = fixture.automatic.grant(seedCustomerId(1), seedAccountId(1), seedAccountId(2),
      5_000, "monthly", "2027-03-01T02:00:00.000Z", undefined, "automatic-device");
    const first = fixture.automatic.charge(merchant, mandate.id, 1_000, "2027-03-01T03:00:00.000Z");
    fixture.bank.db.exec("DROP TRIGGER pix_automatic_cycle_policy_immutable; ALTER TABLE pix_automatic_mandates DROP COLUMN cycle_policy");
    const migrated = new PixAutomatic(fixture.bank);
    assert.equal(migrated.mandate(seedCustomerId(1), mandate.id).cycle_policy, "utc_legacy");
    assert.equal(migrated.charges(seedCustomerId(1), mandate.id)[0].cycle_start, first.cycle_start);
    fixture.setNow("2027-03-23T12:00:00.000Z");
    assert.throws(() => migrated.charge(merchant, mandate.id, 1_000, "2027-03-29T03:00:00.000Z"),
      (error) => error instanceof BankError && error.code === "BIZ_AUTOMATIC_CYCLE_DUPLICATE");
    const next = migrated.charge(merchant, mandate.id, 1_000, "2027-04-01T03:00:00.000Z");
    assert.equal(next.cycle_start, "2027-04-01T02:00:00.000Z");
    const reopened = new Bank(fixture.path, () => new Date("2027-03-23T12:00:00.000Z"));
    try {
      const afterRestart = new PixAutomatic(reopened);
      assert.equal(afterRestart.mandate(seedCustomerId(1), mandate.id).cycle_policy, "utc_legacy");
      assert.deepEqual(afterRestart.charges(seedCustomerId(1), mandate.id).map((item) => item.cycle_start).sort(),
        [first.cycle_start, next.cycle_start].sort());
    } finally { reopened.close(); }
  } finally { fixture.close(); }
});

test("a legacy UTC mandate moves only after payer authorization for a new merchant offer", () => {
  const fixture = setup();
  try {
    fixture.setNow("2027-02-25T12:00:00.000Z");
    const payer = seedCustomerId(1), merchant = seedCustomerId(2);
    const old = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "monthly", "2027-03-01T02:00:00.000Z", undefined,
      "automatic-device");
    fixture.bank.db.exec(`DROP TRIGGER pix_automatic_cycle_policy_immutable;
      ALTER TABLE pix_automatic_mandates DROP COLUMN cycle_policy`);
    const automatic = new PixAutomatic(fixture.bank);
    assert.equal(automatic.mandate(payer, old.id).cycle_policy, "utc_legacy");
    const pending = automatic.charge(merchant, old.id, 1_000,
      "2027-03-01T03:00:00.000Z");
    const offer = automatic.createOffer(merchant, seedAccountId(2), 5_000,
      "monthly", "2027-03-02T03:00:00.000Z", undefined, false);
    const changedLimit = automatic.createOffer(merchant, seedAccountId(2), 6_000,
      "monthly", "2027-03-02T03:00:00.000Z", undefined, false);
    assert.throws(() => automatic.migrateLegacyMandate(payer, old.id,
      changedLimit.id, "automatic-device"), (error) => error instanceof BankError &&
        error.code === "BIZ_AUTOMATIC_MIGRATION_PENDING");
    assert.throws(() => automatic.migrateLegacyMandate(payer, old.id, offer.id,
      "automatic-device"), (error) => error instanceof BankError &&
        error.code === "BIZ_AUTOMATIC_MIGRATION_PENDING");
    assert.equal(automatic.mandate(payer, old.id).status, "active");
    automatic.cancelCharge(payer, pending.id);
    assert.throws(() => automatic.migrateLegacyMandate(payer, old.id,
      changedLimit.id, "automatic-device"), (error) => error instanceof BankError &&
        error.code === "BIZ_AUTOMATIC_OFFER_MISMATCH");
    assert.equal(automatic.mandate(payer, old.id).status, "active");
    fixture.bank.db.exec(`CREATE TRIGGER fail_automatic_migration
      BEFORE INSERT ON pix_automatic_migrations
      BEGIN SELECT RAISE(ABORT,'MIGRATION_RECORD_FAILED'); END`);
    assert.throws(() => automatic.migrateLegacyMandate(payer, old.id, offer.id,
      "automatic-device"), /MIGRATION_RECORD_FAILED/);
    assert.equal(automatic.mandate(payer, old.id).status, "active");
    assert.equal(fixture.bank.db.prepare(`SELECT COUNT(*) n FROM pix_automatic_mandates
      WHERE offer_id=?`).get(offer.id).n, 0);
    fixture.bank.db.exec("DROP TRIGGER fail_automatic_migration");
    const replacement = automatic.migrateLegacyMandate(payer, old.id, offer.id,
      "automatic-device");
    assert.equal(replacement.cycle_policy, "sao_paulo_v1");
    assert.equal(replacement.offer_id, offer.id);
    assert.equal(automatic.mandate(payer, old.id).status, "revoked");
    assert.equal(automatic.mandate(payer, old.id).cycle_policy, "utc_legacy");
    assert.equal(automatic.migrateLegacyMandate(payer, old.id, offer.id,
      "automatic-device").id, replacement.id);
    assert.equal(fixture.bank.db.prepare(`SELECT COUNT(*) n FROM pix_automatic_migrations
      WHERE old_mandate_id=? AND new_mandate_id=? AND approved_device_id=?`)
      .get(old.id, replacement.id, "automatic-device").n, 1);
    assert.throws(() => fixture.bank.db.prepare(`UPDATE pix_automatic_migrations
      SET offer_id=? WHERE old_mandate_id=?`).run("changed", old.id),
    /AUTOMATIC_MIGRATION_IMMUTABLE/);
    assert.throws(() => automatic.migrateLegacyMandate(payer, replacement.id,
      offer.id, "automatic-device"), (error) => error instanceof BankError &&
        error.code === "BIZ_AUTOMATIC_MIGRATION_UNAVAILABLE");
    const reopened = new Bank(fixture.path, () => new Date("2027-02-25T12:00:00.000Z"));
    try {
      const afterRestart = new PixAutomatic(reopened);
      assert.equal(afterRestart.migrateLegacyMandate(payer, old.id, offer.id,
        "automatic-device").id, replacement.id);
      assert.equal(afterRestart.mandate(payer, old.id).status, "revoked");
    } finally { reopened.close(); }
    assert.throws(() => automatic.charge(merchant, old.id, 1_000,
      "2027-03-02T03:00:00.000Z"), (error) => error instanceof BankError &&
        error.code === "BIZ_AUTOMATIC_REVOKED");
    const replacementCharge = automatic.charge(merchant, replacement.id, 1_000,
      "2027-03-02T03:00:00.000Z");
    fixture.setNow("2027-03-02T03:00:00.000Z");
    assert.equal(automatic.executeDue().succeeded, 1);
    assert.equal(fixture.bank.db.prepare(`SELECT status FROM pix_automatic_charges
      WHERE id=?`).get(replacementCharge.id).status, "settled");
    assert.equal(fixture.bank.reconcile().ok, true);
  } finally { fixture.close(); }
});

test("legacy mandate migration requires payer step-up and a bound-device signature", async () => {
  const fixture = setup();
  let app;
  try {
    fixture.setNow("2027-02-25T12:00:00.000Z");
    const payer = seedCustomerId(1), merchant = seedCustomerId(2);
    const old = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "monthly", "2027-03-01T02:00:00.000Z", undefined,
      "automatic-device");
    fixture.bank.db.exec(`DROP TRIGGER pix_automatic_cycle_policy_immutable;
      ALTER TABLE pix_automatic_mandates DROP COLUMN cycle_policy`);
    const automatic = new PixAutomatic(fixture.bank);
    const offer = automatic.createOffer(merchant, seedAccountId(2), 5_000,
      "monthly", "2027-03-02T03:00:00.000Z", undefined, false);
    const password = "a-strong-test-password";
    fixture.auth.setPassword(payer, password);
    const challenge = fixture.auth.beginLogin(fixture.bank.customer(payer).cpf,
      password, "10.0.0.1", "migration-device");
    const session = fixture.auth.verifyOtp(challenge.challenge_id,
      fixture.auth.simulatedOtp(challenge.challenge_id, payer), "10.0.0.1");
    fixture.auth.stepUp(session.access_token, password);
    app = createTwinApi(fixture.bank, fixture.auth);
    const headers = { authorization: `Bearer ${session.access_token}` };
    const key = await bindDeviceKey(app, headers);
    const path = `/pix/automatic/mandates/${old.id}/migrate`;
    const body = { offer_id: offer.id };
    assert.equal(isGatewayAllowed(path), true);
    const unsigned = await app.inject({ method: "POST", url: path, headers,
      payload: body });
    assert.equal(unsigned.statusCode, 403, unsigned.body);
    assert.equal(unsigned.json().error, "DEF_DEVICE_PROOF_INVALID");
    const migrated = await app.inject({ method: "POST", url: path,
      headers: await signedOperationHeaders(app, headers, key, path, body),
      payload: body });
    assert.equal(migrated.statusCode, 200, migrated.body);
    assert.equal(migrated.json().cycle_policy, "sao_paulo_v1");
    assert.equal(automatic.mandate(payer, old.id).status, "revoked");
    const repeated = await app.inject({ method: "POST", url: path,
      headers: await signedOperationHeaders(app, headers, key, path, body),
      payload: body });
    assert.equal(repeated.statusCode, 200, repeated.body);
    assert.equal(repeated.json().id, migrated.json().id);
    assert.equal(fixture.bank.reconcile().ok, true);
  } finally { await app?.close(); fixture.close(); }
});

test("monthly cycle stays anchored after a short month", () => {
  const fixture = setup();
  try {
    const mandate = fixture.automatic.grant(seedCustomerId(1), seedAccountId(1),
      seedAccountId(2), 5_000, "monthly", "2027-01-31T10:00:00.000Z",
      undefined, "automatic-device");
    fixture.setNow("2027-02-25T12:00:00.000Z");
    const february = fixture.automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2027-02-28T10:00:00.000Z");
    fixture.setNow("2027-03-28T12:00:00.000Z");
    const march = fixture.automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2027-03-31T10:00:00.000Z");
    assert.equal(february.cycle_start, "2027-02-28T10:00:00.000Z");
    assert.equal(march.cycle_start, "2027-03-31T10:00:00.000Z");
  } finally { fixture.close(); }
});

test("quarterly, semiannual and yearly mandates keep their original day", () => {
  for (const [frequency, due] of [
    ["quarterly", "2027-04-30T10:00:00.000Z"],
    ["semiannual", "2027-07-31T10:00:00.000Z"],
    ["yearly", "2028-01-31T10:00:00.000Z"],
  ]) {
    const fixture = setup();
    try {
      const mandate = fixture.automatic.grant(seedCustomerId(1), seedAccountId(1),
        seedAccountId(2), 5_000, frequency, "2027-01-31T10:00:00.000Z",
        undefined, "automatic-device");
      fixture.setNow(new Date(Date.parse(due) - 3 * 86_400_000).toISOString());
      const charge = fixture.automatic.charge(seedCustomerId(2), mandate.id, 1_000, due);
      assert.equal(charge.cycle_start, due);
    } finally { fixture.close(); }
  }
});

test("automatic and ordinary Pix use independent daily spending pools", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const mandate = automatic.grant(seedCustomerId(1), seedAccountId(1),
      seedAccountId(2), 30_000, "weekly", "2026-11-14T10:00:00.000Z",
      undefined, "automatic-device");
    automatic.charge(seedCustomerId(2), mandate.id, 20_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    bank.db.prepare("UPDATE customers SET kyc_tier=1 WHERE id=?")
      .run(seedCustomerId(1));
    bank.transferPix({ from: seedAccountId(1), to: seedAccountId(2),
      amount: 90_000, actor: seedCustomerId(1), idempotencyKey: "ordinary-spend",
      deviceId: "automatic-device", stepUpVerified: true });
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    bank.transferPix({ from: seedAccountId(1), to: seedAccountId(2),
      amount: 9_000, actor: seedCustomerId(1), idempotencyKey: "ordinary-after-automatic",
      deviceId: "automatic-device", stepUpVerified: true });
    assert.throws(() => bank.transferPix({ from: seedAccountId(1), to: seedAccountId(2),
      amount: 81_000, actor: seedCustomerId(1), idempotencyKey: "automatic-over-limit",
      deviceId: "automatic-device", stepUpVerified: true, product: "automatic" }),
    (error) => error instanceof BankError && error.code === "BIZ_DAILY_LIMIT");
    assert.equal(bank.db.prepare(`SELECT product FROM pix_transfers
      WHERE idempotency_key LIKE 'automatic:%'`).get().product, "automatic");
    assert.equal(bank.db.prepare(`SELECT product FROM pix_transfers
      WHERE idempotency_key='ordinary-spend'`).get().product, "standard");
    assert.equal(bank.reconcile().ok, true);
  } finally { fixture.close(); }
});

test("older bank databases gain product columns without changing existing Pix", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-automatic-upgrade-"));
  const path = join(dir, "bank.sqlite");
  const now = () => new Date("2026-11-13T12:00:00.000Z");
  const initial = new Bank(path, now);
  try {
    seedBank(initial, { customers: 2, accounts: 2, historyTransactions: 0 });
    initial.transferPix({ from: seedAccountId(1), to: seedAccountId(2),
      amount: 100, actor: seedCustomerId(1), idempotencyKey: "old-pix" });
  } finally { initial.close(); }
  const legacy = new DatabaseSync(path);
  try {
    legacy.exec("ALTER TABLE pix_transfers DROP COLUMN product");
    legacy.exec("ALTER TABLE risk_pix_holds DROP COLUMN product");
  } finally { legacy.close(); }
  const reopened = new Bank(path, now);
  try {
    assert.equal(reopened.db.prepare("SELECT product FROM pix_transfers WHERE idempotency_key=?")
      .get("old-pix").product, "standard");
    assert.equal(reopened.reconcile().ok, true);
  } finally { reopened.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("payer daily automatic limit reduces immediately and increases after eight hours", () => {
  const fixture = setup();
  const { bank } = fixture;
  try {
    const payer = seedCustomerId(1);
    const account = seedAccountId(1);
    assert.equal(bank.pixAutomaticLimit(payer, account).daily_limit_cents, 500_000);
    assert.throws(() => bank.pixAutomaticLimit(seedCustomerId(2), account),
      (error) => error instanceof BankError && error.code === "DEF_NOT_FOUND");
    assert.equal(bank.requestPixAutomaticLimit(payer, account, 20_000).daily_limit_cents,
      20_000);
    const increased = bank.requestPixAutomaticLimit(payer, account, 50_000);
    assert.equal(increased.daily_limit_cents, 20_000);
    assert.equal(increased.pending.value, 50_000);
    fixture.setNow("2026-11-12T19:59:59.000Z");
    assert.equal(bank.pixAutomaticLimit(payer, account).daily_limit_cents, 20_000);
    fixture.setNow("2026-11-12T20:00:00.000Z");
    assert.equal(bank.pixAutomaticLimit(payer, account).daily_limit_cents, 50_000);
    assert.equal(bank.pixAutomaticLimit(payer, account).pending, null);
    assert.equal(bank.requestPixAutomaticLimit(payer, account, 0).daily_limit_cents, 0);
  } finally { fixture.close(); }
});

test("failed automatic charge records a scoped reason in the bank log", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    bank.requestPixAutomaticLimit(payer, seedAccountId(1), 0);
    fixture.setNow("2026-11-14T10:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(automatic.charges(payer, mandate.id)[0].next_attempt_at,
      "2026-11-14T21:00:00.000Z");
    fixture.setNow("2026-11-14T21:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 1 });
    assert.equal(bank.db.prepare("SELECT error_code FROM pix_automatic_charges WHERE id=?")
      .get(charge.id).error_code, "BIZ_DAILY_LIMIT");
    const logged = bank.db.prepare(`SELECT action,reason_codes_json FROM telemetry_events
      WHERE action='charge_failed' ORDER BY id DESC LIMIT 1`).get();
    assert.equal(logged.action, "charge_failed");
    assert.deepEqual(JSON.parse(logged.reason_codes_json), ["BIZ_DAILY_LIMIT"]);
  } finally { fixture.close(); }
});

test("evening retry settles once after an automatic limit increase", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    bank.requestPixAutomaticLimit(payer, seedAccountId(1), 0);
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(automatic.notifications(payer).some((notice) =>
      notice.kind === "charge_retry_scheduled"), true);
    bank.requestPixAutomaticLimit(payer, seedAccountId(1), 5_000);
    fixture.setNow("2026-11-14T20:59:59.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    fixture.setNow("2026-11-14T21:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(bank.db.prepare(`SELECT status,attempt_count,next_attempt_at
      FROM pix_automatic_charges WHERE id=?`).get(charge.id).attempt_count, 2);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 1);
    assert.equal(bank.reconcile().ok, true);
  } finally { fixture.close(); }
});

test("retry schedule survives a bank restart", () => {
  const fixture = setup();
  const payer = seedCustomerId(1);
  let reopened;
  try {
    const mandate = fixture.automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = fixture.automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    fixture.bank.requestPixAutomaticLimit(payer, seedAccountId(1), 0);
    assert.deepEqual(fixture.automatic.executeDue(), { succeeded: 0, failed: 0 });
    fixture.bank.requestPixAutomaticLimit(payer, seedAccountId(1), 5_000);
    fixture.bank.close();
    reopened = new Bank(fixture.path, () => new Date("2026-11-14T21:00:00.000Z"));
    const resumed = new PixAutomatic(reopened);
    assert.equal(resumed.charges(payer, mandate.id)[0].next_attempt_at,
      "2026-11-14T21:00:00.000Z");
    assert.deepEqual(resumed.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(reopened.db.prepare(`SELECT attempt_count FROM pix_automatic_charges
      WHERE id=?`).get(charge.id).attempt_count, 2);
    assert.equal(reopened.reconcile().ok, true);
  } finally { reopened?.close(); rmSync(fixture.dir, { recursive: true, force: true }); }
});

test("notification failure after settlement retries bookkeeping without a second debit", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    bank.db.exec(`CREATE TRIGGER fail_automatic_notification
      BEFORE INSERT ON pix_automatic_notifications
      WHEN NEW.kind='charge_settled'
      BEGIN SELECT RAISE(ABORT, 'NOTIFY_UNAVAILABLE'); END`);
    assert.throws(() => automatic.executeDue(), /NOTIFY_UNAVAILABLE/);
    assert.equal(bank.db.prepare(`SELECT status FROM pix_automatic_charges WHERE id=?`)
      .get(charge.id).status, "pending");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 1);
    assert.equal(automatic.notifications(payer).some((notice) =>
      notice.kind === "charge_failed"), false);
    bank.db.exec("DROP TRIGGER fail_automatic_notification");
    fixture.setNow("2026-11-15T12:00:00.000Z");
    automatic.revoke(payer, mandate.id);
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 1);
    assert.equal(automatic.notifications(payer).filter((notice) =>
      notice.kind === "charge_settled").length, 1);
    assert.equal(bank.reconcile().ok, true);
  } finally { fixture.close(); }
});

test("a missed first payment window retries in the evening without a midday debit", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-14T12:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(automatic.charges(payer, mandate.id)[0].next_attempt_at,
      "2026-11-14T21:00:00.000Z");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 0);
    fixture.setNow("2026-11-14T21:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(automatic.notifications(payer).filter((notice) =>
      notice.kind === "charge_retry_scheduled").length, 1);
  } finally { fixture.close(); }
});

test("a missed full payment day fails without a late debit", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-15T01:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 1 });
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(automatic.charges(payer, mandate.id)[0].error_code,
      "BIZ_AUTOMATIC_FIRST_WINDOW_MISSED");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 0);
    assert.equal(automatic.notifications(payer).filter((notice) =>
      notice.kind === "charge_failed").length, 1);
  } finally { fixture.close(); }
});

test("merchant-approved post-due retry settles the original charge without duplicate payment", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const offerId = retryOffer(automatic);
    assert.throws(() => bank.db.prepare(`UPDATE pix_automatic_offers
      SET post_due_retry_allowed=0 WHERE id=?`).run(offerId),
    /AUTOMATIC_OFFER_IMMUTABLE/);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined,
      "automatic-device", offerId);
    const charge = automatic.charge(merchant, mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    bank.requestPixAutomaticLimit(payer, seedAccountId(1), 0);
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    fixture.setNow("2026-11-14T21:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 1 });
    assert.throws(() => automatic.retryCharge(payer, charge.id,
      "2026-11-16T10:00:00.000Z"),
    (error) => error instanceof BankError && error.code === "DEF_NOT_FOUND");
    const retried = automatic.retryCharge(merchant, charge.id,
      "2026-11-16T10:00:00.000Z");
    assert.equal(retried.status, "pending");
    assert.equal(retried.original_due_at, "2026-11-14T10:00:00.000Z");
    assert.equal(retried.due_at, "2026-11-16T10:00:00.000Z");
    assert.equal(automatic.notifications(payer).some((notice) =>
      notice.kind === "charge_post_due_retry_1"), true);
    bank.requestPixAutomaticLimit(payer, seedAccountId(1), 5_000);
    fixture.setNow("2026-11-16T10:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 1);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_automatic_post_due_retries
      WHERE charge_id=?`).get(charge.id).n, 1);
    assert.throws(() => bank.db.prepare(`DELETE FROM pix_automatic_post_due_retries
      WHERE charge_id=?`).run(charge.id), /AUTOMATIC_RETRY_IMMUTABLE/);
    assert.equal(bank.reconcile().ok, true);
  } finally { fixture.close(); }
});

test("post-due retry instruction survives a bank restart", () => {
  const fixture = setup();
  let reopened;
  try {
    const payer = seedCustomerId(1);
    const offerId = retryOffer(fixture.automatic);
    const mandate = fixture.automatic.grant(payer, seedAccountId(1),
      seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
      undefined, "automatic-device", offerId);
    const charge = fixture.automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-15T01:00:00.000Z");
    assert.deepEqual(fixture.automatic.executeDue(), { succeeded: 0, failed: 1 });
    fixture.automatic.retryCharge(seedCustomerId(2), charge.id,
      "2026-11-15T10:00:00.000Z");
    fixture.bank.close();
    reopened = new Bank(fixture.path, () => new Date("2026-11-15T10:00:00.000Z"));
    const automatic = new PixAutomatic(reopened);
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(automatic.charges(payer, mandate.id)[0].status, "settled");
    assert.equal(reopened.db.prepare(`SELECT COUNT(*) n FROM pix_automatic_post_due_retries
      WHERE charge_id=?`).get(charge.id).n, 1);
    assert.equal(reopened.reconcile().ok, true);
  } finally { reopened?.close(); rmSync(fixture.dir, { recursive: true, force: true }); }
});

test("post-due retry requires policy and stops after three dates before the next cycle", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const disabled = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined,
      "automatic-device");
    const offerId = retryOffer(automatic);
    const enabled = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined,
      "automatic-device", offerId);
    const disabledCharge = automatic.charge(merchant, disabled.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    const charge = automatic.charge(merchant, enabled.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-15T01:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 2 });
    assert.throws(() => automatic.retryCharge(merchant, disabledCharge.id,
      "2026-11-15T10:00:00.000Z"),
    (error) => error instanceof BankError && error.code ===
      "BIZ_AUTOMATIC_RETRY_UNAVAILABLE");
    assert.throws(() => automatic.retryCharge(merchant, charge.id,
      "2026-11-21T09:00:00.000Z"),
    (error) => error instanceof BankError && error.code ===
      "BIZ_AUTOMATIC_RETRY_PERIOD");
    for (const day of [15, 16, 17]) {
      automatic.retryCharge(merchant, charge.id, `2026-11-${day}T10:00:00.000Z`);
      fixture.setNow(`2026-11-${day + 1}T01:00:00.000Z`);
      assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 1 });
    }
    assert.throws(() => automatic.retryCharge(merchant, charge.id,
      "2026-11-18T10:00:00.000Z"),
    (error) => error instanceof BankError && error.code ===
      "BIZ_AUTOMATIC_RETRY_LIMIT");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_automatic_post_due_retries
      WHERE charge_id=?`).get(charge.id).n, 3);
    assert.equal(automatic.notifications(payer).filter((notice) =>
      notice.charge_id === charge.id && notice.kind === "charge_failed").length, 4);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 0);
  } finally { fixture.close(); }
});

test("an unexpected payment error leaves the charge pending for investigation", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    const transfer = bank.transferPix.bind(bank);
    bank.transferPix = () => { throw new Error("PAYMENT_IO_FAILURE"); };
    assert.throws(() => automatic.executeDue(), /PAYMENT_IO_FAILURE/);
    bank.transferPix = transfer;
    assert.equal(automatic.charges(payer, mandate.id)[0].status, "pending");
    assert.equal(automatic.notifications(payer).some((notice) =>
      notice.kind === "charge_failed"), false);
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 1);
  } finally { fixture.close(); }
});

test("a missed evening window fails without a late debit", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    bank.requestPixAutomaticLimit(payer, seedAccountId(1), 0);
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    bank.requestPixAutomaticLimit(payer, seedAccountId(1), 5_000);
    fixture.setNow("2026-11-15T00:01:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 1 });
    assert.equal(automatic.charges(payer, mandate.id)[0].status, "failed");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 0);
  } finally { fixture.close(); }
});

test("same-day cancellation is refused and mandate revocation preserves today's retry", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, "automatic-device");
    const charge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    const nextCharge = automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-21T10:00:00.000Z");
    fixture.setNow("2026-11-14T10:00:00.000Z");
    bank.requestPixAutomaticLimit(payer, seedAccountId(1), 0);
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.throws(() => automatic.cancelCharge(payer, charge.id),
      (error) => error instanceof BankError && error.code ===
        "BIZ_AUTOMATIC_CANCEL_UNAVAILABLE");
    assert.equal(automatic.revoke(payer, mandate.id).status, "revoked");
    assert.equal(bank.db.prepare(`SELECT status FROM pix_automatic_charges WHERE id=?`)
      .get(charge.id).status, "pending");
    assert.equal(bank.db.prepare(`SELECT status FROM pix_automatic_charges WHERE id=?`)
      .get(nextCharge.id).status, "cancelled");
    bank.requestPixAutomaticLimit(payer, seedAccountId(1), 5_000);
    fixture.setNow("2026-11-14T21:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE idempotency_key=?`).get(`automatic:${charge.id}`).n, 1);
  } finally { fixture.close(); }
});

test("automatic schema migration locks concurrent constructors before inspecting legacy columns", () => {
  const fixture = setup();
  const writer = new Bank(fixture.path);
  try {
    fixture.bank.db.exec("DROP TRIGGER pix_automatic_cycle_policy_immutable; ALTER TABLE pix_automatic_mandates DROP COLUMN cycle_policy");
    let checked = false;
    const db = new Proxy(fixture.bank.db, { get(target, property) {
      if (property === "exec") return (sql) => {
        if (sql.includes("CREATE TABLE IF NOT EXISTS pix_automatic_offers")) {
          assert.equal(target.isTransaction, true);
          assert.throws(() => new PixAutomatic(writer), /locked|busy/i);
          checked = true;
        }
        return target.exec(sql);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    const proxiedBank = Object.create(fixture.bank);
    Object.defineProperty(proxiedBank, "db", { value: db });
    new PixAutomatic(proxiedBank);
    assert.equal(checked, true);
    assert.ok(fixture.bank.db.prepare("PRAGMA table_info(pix_automatic_mandates)").all()
      .some((column) => column.name === "cycle_policy"));
    assert.ok(fixture.bank.db.prepare("SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='pix_automatic_cycle_policy_immutable'").get());
    new PixAutomatic(writer);
  } finally { writer.close(); fixture.close(); }
});

test("automatic schema migration rolls back partial DDL even inside a caller transaction", () => {
  const fixture = setup();
  try {
    fixture.bank.db.exec("DROP TRIGGER pix_automatic_cycle_policy_immutable; ALTER TABLE pix_automatic_mandates DROP COLUMN cycle_policy");
    const db = new Proxy(fixture.bank.db, { get(target, property) {
      if (property === "exec") return (sql) => {
        if (sql.includes("CREATE TRIGGER IF NOT EXISTS pix_automatic_cycle_policy_immutable"))
          throw new Error("MIGRATION_TEST_FAILURE");
        return target.exec(sql);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    const proxiedBank = Object.create(fixture.bank);
    Object.defineProperty(proxiedBank, "db", { value: db });
    fixture.bank.db.exec("BEGIN IMMEDIATE");
    assert.throws(() => new PixAutomatic(proxiedBank), /MIGRATION_TEST_FAILURE/);
    assert.equal(fixture.bank.db.isTransaction, true);
    assert.equal(fixture.bank.db.prepare("PRAGMA table_info(pix_automatic_mandates)").all()
      .some((column) => column.name === "cycle_policy"), false);
    fixture.bank.db.exec("COMMIT");
    assert.equal(fixture.bank.db.prepare("PRAGMA table_info(pix_automatic_mandates)").all()
      .some((column) => column.name === "cycle_policy"), false);
    new PixAutomatic(fixture.bank);
  } finally { if (fixture.bank.db.isTransaction) fixture.bank.db.exec("ROLLBACK"); fixture.close(); }
});

test("automatic migration acquires a write lock inside a deferred caller transaction", () => {
  const fixture = setup();
  const writer = new Bank(fixture.path);
  try {
    fixture.bank.db.exec("DROP TRIGGER pix_automatic_cycle_policy_immutable; ALTER TABLE pix_automatic_mandates DROP COLUMN cycle_policy");
    let checked = false;
    const db = new Proxy(fixture.bank.db, { get(target, property) {
      if (property === "prepare") return (sql) => {
        if (!checked && sql.includes("PRAGMA table_info(pix_automatic_mandates)")) {
          assert.equal(target.isTransaction, true);
          assert.throws(() => writer.db.exec("UPDATE accounts SET balance_cached=balance_cached WHERE 1=0"), /locked|busy/i);
          checked = true;
        }
        return target.prepare(sql);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    const proxiedBank = Object.create(fixture.bank);
    Object.defineProperty(proxiedBank, "db", { value: db });
    fixture.bank.db.exec("BEGIN");
    new PixAutomatic(proxiedBank);
    assert.equal(checked, true);
    fixture.bank.db.exec("ROLLBACK");
    assert.equal(fixture.bank.db.prepare("PRAGMA table_info(pix_automatic_mandates)").all()
      .some((column) => column.name === "cycle_policy"), false);
    new PixAutomatic(fixture.bank);
  } finally { if (fixture.bank.db.isTransaction) fixture.bank.db.exec("ROLLBACK"); writer.close(); fixture.close(); }
});

test("automatic schema initial creation rolls back completely on failure", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-automatic-schema-"));
  const bank = new Bank(join(dir, "bank.sqlite"));
  try {
    const db = new Proxy(bank.db, { get(target, property) {
      if (property === "exec") return (sql) => {
        if (sql.includes("CREATE TRIGGER IF NOT EXISTS pix_automatic_cycle_policy_immutable"))
          throw new Error("MIGRATION_TEST_FAILURE");
        return target.exec(sql);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } });
    const proxiedBank = Object.create(bank);
    Object.defineProperty(proxiedBank, "db", { value: db });
    assert.throws(() => new PixAutomatic(proxiedBank), /MIGRATION_TEST_FAILURE/);
    assert.equal(bank.db.isTransaction, false);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM sqlite_master WHERE name IN ('pix_automatic_mandates','pix_automatic_charges','pix_automatic_offers')").get().n, 0);
    new PixAutomatic(bank);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("older automatic charges gain retry columns on startup", () => {
  const fixture = setup();
  let reopened;
  try {
    const mandate = fixture.automatic.grant(seedCustomerId(1), seedAccountId(1),
      seedAccountId(2), 5_000, "weekly", "2026-11-14T10:00:00.000Z",
      undefined, "automatic-device");
    const charge = fixture.automatic.charge(seedCustomerId(2), mandate.id, 1_000,
      "2026-11-14T10:00:00.000Z");
    fixture.bank.close();
    const legacy = new DatabaseSync(fixture.path);
    try {
      legacy.exec("ALTER TABLE pix_automatic_charges DROP COLUMN next_attempt_at");
      legacy.exec("ALTER TABLE pix_automatic_charges DROP COLUMN attempt_count");
      legacy.exec("ALTER TABLE pix_automatic_charges DROP COLUMN original_due_at");
      legacy.exec("ALTER TABLE pix_automatic_mandates DROP COLUMN post_due_retry_allowed");
      legacy.exec("ALTER TABLE pix_automatic_mandates DROP COLUMN offer_id");
    } finally { legacy.close(); }
    reopened = new Bank(fixture.path, () => new Date("2026-11-13T12:00:00.000Z"));
    const migrated = new PixAutomatic(reopened);
    assert.equal(migrated.charges(seedCustomerId(1), mandate.id)[0].id, charge.id);
    assert.equal(migrated.charges(seedCustomerId(1), mandate.id)[0].attempt_count, 0);
    assert.equal(migrated.charges(seedCustomerId(1), mandate.id)[0].next_attempt_at, null);
    assert.equal(migrated.charges(seedCustomerId(1), mandate.id)[0].original_due_at,
      "2026-11-14T10:00:00.000Z");
    assert.equal(migrated.mandate(seedCustomerId(1), mandate.id).post_due_retry_allowed, 0);
    assert.equal(migrated.mandate(seedCustomerId(1), mandate.id).offer_id, null);
  } finally { reopened?.close(); rmSync(fixture.dir, { recursive: true, force: true }); }
});

test("API requires payer step-up for a mandate", async () => {
  const fixture = setup();
  const { bank, auth } = fixture;
  try {
    const payer = seedCustomerId(1);
    const offer = fixture.automatic.createOffer(seedCustomerId(2), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, false);
    auth.setPassword(payer, "a-strong-test-password");
    const login = auth.beginLogin(bank.customer(payer).cpf,
      "a-strong-test-password", "10.0.0.1", "automatic-api-device");
    const session = auth.verifyOtp(login.challenge_id,
      auth.simulatedOtp(login.challenge_id, payer), "10.0.0.1");
    const app = createTwinApi(bank, auth);
    try {
      let proofHeaders = { authorization: `Bearer ${session.access_token}` };
      const request = () => app.inject({ method: "POST", url: "/pix/automatic/mandates",
        headers: proofHeaders,
        payload: { from_account: seedAccountId(1), merchant_account: seedAccountId(2),
          max_amount_cents: 5_000, frequency: "weekly",
          starts_at: "2026-11-14T10:00:00.000Z", offer_id: offer.id } });
      assert.equal((await request()).statusCode, 403);
      const limitRequest = () => app.inject({ method: "POST",
        url: `/pix/automatic/limits/${seedAccountId(1)}`,
        headers: proofHeaders,
        payload: { daily_limit_cents: 10_000 } });
      assert.equal((await limitRequest()).statusCode, 403);
      auth.stepUp(session.access_token, "a-strong-test-password");
      assert.equal((await request()).statusCode, 403);
      assert.equal((await limitRequest()).statusCode, 403);
      const key = await bindDeviceKey(app, proofHeaders);
      const mandateBody = { from_account: seedAccountId(1), merchant_account: seedAccountId(2),
        max_amount_cents: 5_000, frequency: "weekly",
        starts_at: "2026-11-14T10:00:00.000Z", offer_id: offer.id };
      proofHeaders = await signedOperationHeaders(app, proofHeaders, key, "/pix/automatic/mandates", mandateBody);
      const granted = await request();
      assert.equal(granted.statusCode, 200);
      assert.equal(granted.json().status, "active");
      proofHeaders = await signedOperationHeaders(app, { authorization: `Bearer ${session.access_token}` }, key,
        `/pix/automatic/limits/${seedAccountId(1)}`, { daily_limit_cents: 10_000 });
      assert.equal((await limitRequest()).json().daily_limit_cents, 10_000);
    } finally { await app.close(); }
  } finally { fixture.close(); }
});

test("unbound devices cannot perform Pix Automatic writes", async () => {
  const fixture = setup();
  const { bank, auth } = fixture;
  const customer = seedCustomerId(1);
  const password = "a-strong-test-password";
  try {
    auth.setPassword(customer, password);
    const login = auth.beginLogin(bank.customer(customer).cpf, password, "10.0.0.1", "unbound-device");
    const session = auth.verifyOtp(login.challenge_id, auth.simulatedOtp(login.challenge_id, customer), "10.0.0.1");
    auth.stepUp(session.access_token, password);
    const app = createTwinApi(bank, auth);
    try {
      const terms = { merchant_account: seedAccountId(2), max_amount_cents: 5_000,
        frequency: "weekly", starts_at: "2026-11-14T10:00:00.000Z" };
      const operations = [
        ["/pix/automatic/offers", { ...terms, post_due_retry_allowed: false }],
        ["/pix/automatic/offers/offer-1/revoke"],
        ["/pix/automatic/mandates", { ...terms, from_account: seedAccountId(1), offer_id: "offer-1" }],
        [`/pix/automatic/limits/${seedAccountId(1)}`, { daily_limit_cents: 10_000 }],
        ["/pix/automatic/mandates/mandate-1/revoke"],
        ["/pix/automatic/mandates/mandate-1/charges", { amount_cents: 1_000, due_at: terms.starts_at }],
        ["/pix/automatic/charges/charge-1/reauthorize"],
        ["/pix/automatic/charges/charge-1/cancel"],
        ["/pix/automatic/charges/charge-1/merchant-cancel"],
        ["/pix/automatic/charges/charge-1/retry", { due_at: terms.starts_at }],
      ];
      for (const [url, payload] of operations) {
        const response = await app.inject({ method: "POST", url,
          headers: { authorization: `Bearer ${session.access_token}` },
          ...(payload === undefined ? {} : { payload }) });
        assert.equal(response.statusCode, 403, `${url}: ${response.body}`);
        assert.equal(response.json().error, "DEF_DEVICE_PROOF_INVALID", url);
      }
    } finally { await app.close(); }
  } finally { fixture.close(); }
});

test("bound payer and merchant sign the Pix Automatic lifecycle", async () => {
  const fixture = setup();
  const { bank, auth, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const password = "a-strong-test-password";
    const app = createTwinApi(bank, auth);
    try {
      const identity = async (customer, device) => {
        auth.setPassword(customer, password);
        const login = auth.beginLogin(bank.customer(customer).cpf, password,
          "10.0.0.1", device);
        const session = auth.verifyOtp(login.challenge_id,
          auth.simulatedOtp(login.challenge_id, customer), "10.0.0.1");
        auth.stepUp(session.access_token, password);
        const headers = { authorization: `Bearer ${session.access_token}` };
        return { headers, key: await bindDeviceKey(app, headers) };
      };
      const payerIdentity = await identity(payer, "payer-lifecycle-device");
      const merchantIdentity = await identity(merchant, "merchant-lifecycle-device");
      const signedPost = async (identity, path, body) => app.inject({ method: "POST", url: path,
        headers: await signedOperationHeaders(app, identity.headers, identity.key, path, body),
        ...(body === undefined ? {} : { payload: body }) });
      const offerBody = { merchant_account: seedAccountId(2), max_amount_cents: 5_000,
        frequency: "weekly", starts_at: "2026-11-14T10:00:00.000Z",
        post_due_retry_allowed: true };
      assert.equal((await app.inject({ method: "POST", url: "/pix/automatic/offers",
        headers: merchantIdentity.headers, payload: offerBody })).statusCode, 403);
      const offer = await signedPost(merchantIdentity, "/pix/automatic/offers", offerBody);
      assert.equal(offer.statusCode, 200, offer.body);
      const mandateBody = { from_account: seedAccountId(1), merchant_account: seedAccountId(2),
        max_amount_cents: 5_000, frequency: "weekly",
        starts_at: offerBody.starts_at, offer_id: offer.json().id };
      const mandate = await signedPost(payerIdentity, "/pix/automatic/mandates", mandateBody);
      assert.equal(mandate.statusCode, 200, mandate.body);
      const chargePath = `/pix/automatic/mandates/${mandate.json().id}/charges`;
      const firstChargeBody = { amount_cents: 1_000, due_at: offerBody.starts_at };
      assert.equal((await app.inject({ method: "POST", url: chargePath,
        headers: merchantIdentity.headers, payload: firstChargeBody })).statusCode, 403);
      const firstCharge = await signedPost(merchantIdentity, chargePath, firstChargeBody);
      assert.equal(firstCharge.statusCode, 200, firstCharge.body);
      const payerCancelPath = `/pix/automatic/charges/${firstCharge.json().id}/cancel`;
      assert.equal((await app.inject({ method: "POST", url: payerCancelPath,
        headers: payerIdentity.headers })).statusCode, 403);
      const payerCancelled = await signedPost(payerIdentity, payerCancelPath);
      assert.equal(payerCancelled.statusCode, 200, payerCancelled.body);
      assert.equal(payerCancelled.json().status, "cancelled");
      const secondCharge = await signedPost(merchantIdentity, chargePath,
        { amount_cents: 1_000, due_at: "2026-11-21T10:00:00.000Z" });
      assert.equal(secondCharge.statusCode, 200, secondCharge.body);
      const merchantCancelPath = `/pix/automatic/charges/${secondCharge.json().id}/merchant-cancel`;
      assert.equal((await app.inject({ method: "POST", url: merchantCancelPath,
        headers: merchantIdentity.headers })).statusCode, 403);
      const merchantCancelled = await signedPost(merchantIdentity, merchantCancelPath);
      assert.equal(merchantCancelled.statusCode, 200, merchantCancelled.body);
      assert.equal(merchantCancelled.json().status, "cancelled");
      const mandateRevokePath = `/pix/automatic/mandates/${mandate.json().id}/revoke`;
      assert.equal((await app.inject({ method: "POST", url: mandateRevokePath,
        headers: payerIdentity.headers })).statusCode, 403);
      const revokedMandate = await signedPost(payerIdentity, mandateRevokePath);
      assert.equal(revokedMandate.statusCode, 200, revokedMandate.body);
      assert.equal(revokedMandate.json().status, "revoked");
      const offerRevokePath = `/pix/automatic/offers/${offer.json().id}/revoke`;
      assert.equal((await app.inject({ method: "POST", url: offerRevokePath,
        headers: merchantIdentity.headers })).statusCode, 403);
      const revokedOffer = await signedPost(merchantIdentity, offerRevokePath);
      assert.equal(revokedOffer.statusCode, 200, revokedOffer.body);
      assert.ok(revokedOffer.json().revoked_at);
      assert.equal(automatic.charges(payer, mandate.json().id).length, 2);
      assert.equal(bank.reconcile().ok, true);
    } finally { await app.close(); }
  } finally { fixture.close(); }
});

test("bound merchant signs a post-due retry without duplicating payment", async () => {
  const fixture = setup();
  const { bank, auth, automatic } = fixture;
  try {
    const merchant = seedCustomerId(2);
    const payer = seedCustomerId(1);
    const password = "a-strong-test-password";
    const dueAt = "2026-11-14T10:00:00.000Z";
    const offer = automatic.createOffer(merchant, seedAccountId(2),
      5_000, "weekly", dueAt, undefined, true);
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      5_000, "weekly", dueAt, undefined, "automatic-device", offer.id);
    const charge = automatic.charge(merchant, mandate.id, 1_000, dueAt);
    auth.setPassword(merchant, password);
    const login = auth.beginLogin(bank.customer(merchant).cpf, password,
      "10.0.0.2", "bound-retry-merchant");
    const session = auth.verifyOtp(login.challenge_id,
      auth.simulatedOtp(login.challenge_id, merchant), "10.0.0.2");
    auth.stepUp(session.access_token, password);
    const app = createTwinApi(bank, auth);
    try {
      const initialHeaders = { authorization: `Bearer ${session.access_token}` };
      const privateKey = await bindDeviceKey(app, initialHeaders);
      bank.requestPixAutomaticLimit(payer, seedAccountId(1), 0);
      fixture.setNow(dueAt);
      assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
      fixture.setNow("2026-11-14T21:00:00.000Z");
      assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 1 });
      assert.equal(automatic.charges(payer, mandate.id)[0].status, "failed");
      fixture.setNow("2026-11-15T12:00:00.000Z");
      const refreshed = signedRefresh(auth, session.refresh_token, privateKey);
      const headers = { authorization: `Bearer ${refreshed.access_token}` };
      const path = `/pix/automatic/charges/${charge.id}/retry`;
      const body = { due_at: "2026-11-16T10:00:00.000Z" };
      assert.equal((await app.inject({ method: "POST", url: path,
        headers, payload: body })).statusCode, 403);
      const signed = await signedOperationHeaders(app, headers, privateKey, path, body);
      assert.equal((await app.inject({ method: "POST", url: path,
        headers: signed, payload: { due_at: "2026-11-17T10:00:00.000Z" } })).statusCode, 403);
      const retried = await app.inject({ method: "POST", url: path,
        headers: signed, payload: body });
      assert.equal(retried.statusCode, 200, retried.body);
      assert.equal(retried.json().status, "pending");
      assert.equal((await app.inject({ method: "POST", url: path,
        headers: signed, payload: body })).statusCode, 403);
      bank.requestPixAutomaticLimit(payer, seedAccountId(1), 5_000);
      fixture.setNow(body.due_at);
      assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
      assert.equal(automatic.executeDue().succeeded, 0);
      assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE idempotency_key=?")
        .get(`automatic:${charge.id}`).n, 1);
    } finally { await app.close(); }
  } finally { fixture.close(); }
});

test("bound payer signs reauthorization before a pending automatic charge can settle", async () => {
  const fixture = setup();
  const { bank, auth, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const password = "a-strong-test-password";
    const dueAt = "2026-11-14T10:00:00.000Z";
    const offer = automatic.createOffer(merchant, seedAccountId(2),
      50_000, "weekly", dueAt, undefined, false);
    auth.setPassword(payer, password);
    const login = auth.beginLogin(bank.customer(payer).cpf, password,
      "10.0.0.1", "bound-automatic-device");
    const session = auth.verifyOtp(login.challenge_id,
      auth.simulatedOtp(login.challenge_id, payer), "10.0.0.1");
    auth.stepUp(session.access_token, password);
    const app = createTwinApi(bank, auth);
    try {
      const initialHeaders = { authorization: `Bearer ${session.access_token}` };
      const privateKey = await bindDeviceKey(app, initialHeaders);
      const body = { from_account: seedAccountId(1), merchant_account: seedAccountId(2),
        max_amount_cents: 50_000, frequency: "weekly", starts_at: dueAt, offer_id: offer.id };
      const grantHeaders = await signedOperationHeaders(app, initialHeaders, privateKey,
        "/pix/automatic/mandates", body);
      const granted = await app.inject({ method: "POST", url: "/pix/automatic/mandates",
        headers: grantHeaders, payload: body });
      assert.equal(granted.statusCode, 200, granted.body);
      const charge = automatic.charge(merchant, granted.json().id, 25_000, dueAt);
      fixture.setNow(dueAt);
      assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
      assert.equal(automatic.charges(payer, granted.json().id)[0].status,
        "reauthorization_required");
      const refreshed = signedRefresh(auth, session.refresh_token, privateKey);
      auth.stepUp(refreshed.access_token, password);
      auth.registerCurrentDeviceForPix(refreshed.access_token);
      const headers = { authorization: `Bearer ${refreshed.access_token}` };
      const path = `/pix/automatic/charges/${charge.id}/reauthorize`;
      const unsigned = await app.inject({ method: "POST", url: path, headers });
      assert.equal(unsigned.statusCode, 403);
      const signed = await signedOperationHeaders(app, headers, privateKey, path);
      const reauthorized = await app.inject({ method: "POST", url: path, headers: signed });
      assert.equal(reauthorized.statusCode, 200, reauthorized.body);
      assert.equal(reauthorized.json().status, "pending");
      assert.equal((await app.inject({ method: "POST", url: path, headers: signed })).statusCode, 403);
      assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 },
        JSON.stringify(automatic.charges(payer, granted.json().id)[0]));
      assert.equal(automatic.executeDue().succeeded, 0);
      assert.equal(automatic.charges(payer, granted.json().id)[0].status, "settled");
      assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE idempotency_key=?")
        .get(`automatic:${charge.id}`).n, 1);
    } finally { await app.close(); }
  } finally { fixture.close(); }
});

test("late automatic reauthorization waits for the evening window", () => {
  const fixture = setup();
  const { bank, automatic } = fixture;
  try {
    const payer = seedCustomerId(1);
    const merchant = seedCustomerId(2);
    const dueAt = "2026-11-14T10:00:00.000Z";
    const offer = automatic.createOffer(merchant, seedAccountId(2),
      50_000, "weekly", dueAt, undefined, false);
    bank.db.prepare("UPDATE auth_devices SET pix_registered_at=NULL WHERE id=?")
      .run("automatic-device");
    const mandate = automatic.grant(payer, seedAccountId(1), seedAccountId(2),
      50_000, "weekly", dueAt, undefined, "automatic-device", offer.id);
    const charge = automatic.charge(merchant, mandate.id, 25_000, dueAt);
    fixture.setNow(dueAt);
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(automatic.charges(payer, mandate.id)[0].status, "reauthorization_required");
    fixture.setNow("2026-11-14T12:00:00.000Z");
    bank.db.prepare("UPDATE auth_devices SET pix_registered_at=? WHERE id=?")
      .run(bank.now().toISOString(), "automatic-device");
    automatic.reauthorize(payer, charge.id, "automatic-device");
    assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 0 });
    assert.equal(automatic.charges(payer, mandate.id)[0].status, "pending");
    assert.equal(automatic.charges(payer, mandate.id)[0].next_attempt_at,
      "2026-11-14T21:00:00.000Z");
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE idempotency_key=?")
      .get(`automatic:${charge.id}`).n, 0);
    fixture.setNow("2026-11-14T21:00:00.000Z");
    assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
    assert.equal(automatic.charges(payer, mandate.id)[0].status, "settled");
    assert.equal(bank.reconcile().ok, true);
  } finally { fixture.close(); }
});

test("authenticated merchant can request an allowed post-due retry", async () => {
  const fixture = setup();
  const { bank, auth, automatic } = fixture;
  try {
    const payerId = seedCustomerId(1);
    const merchantId = seedCustomerId(2);
    for (const id of [payerId, merchantId])
      auth.setPassword(id, "a-strong-test-password");
    const sessionFor = (id, device) => {
      const login = auth.beginLogin(bank.customer(id).cpf,
        "a-strong-test-password", "10.0.0.1", device);
      return auth.verifyOtp(login.challenge_id,
        auth.simulatedOtp(login.challenge_id, id), "10.0.0.1");
    };
    const payer = sessionFor(payerId, "payer-retry-device");
    const merchant = sessionFor(merchantId, "merchant-retry-device");
    auth.stepUp(payer.access_token, "a-strong-test-password");
    auth.stepUp(merchant.access_token, "a-strong-test-password");
    const app = createTwinApi(bank, auth);
    try {
      const headers = (session) => ({ authorization: `Bearer ${session.access_token}` });
      const keys = new Map();
      keys.set(payer.access_token, await bindDeviceKey(app, headers(payer)));
      keys.set(merchant.access_token, await bindDeviceKey(app, headers(merchant)));
      const signedInject = async (request) => {
        const token = request.headers.authorization.slice(7);
        const key = keys.get(token);
        if (key) request.headers = await signedOperationHeaders(app, request.headers, key,
          request.url, request.payload);
        return app.inject(request);
      };
      const offerPayload = { merchant_account: seedAccountId(2),
        max_amount_cents: 5_000, frequency: "weekly",
        starts_at: "2026-11-14T10:00:00.000Z",
        post_due_retry_allowed: true };
      const unsteppedMerchant = sessionFor(merchantId, "merchant-unstepped-device");
      const deniedOffer = await signedInject({ method: "POST", url: "/pix/automatic/offers",
        headers: headers(unsteppedMerchant), payload: offerPayload });
      assert.equal(deniedOffer.statusCode, 403);
      const offer = await signedInject({ method: "POST", url: "/pix/automatic/offers",
        headers: headers(merchant), payload: offerPayload });
      assert.equal(offer.statusCode, 200);
      const visibleOffer = await app.inject({ method: "GET",
        url: `/pix/automatic/offers/${offer.json().id}`, headers: headers(payer) });
      assert.equal(visibleOffer.statusCode, 200);
      assert.equal(visibleOffer.json().post_due_retry_allowed, 1);
      assert.equal(Object.hasOwn(visibleOffer.json(), "merchant_customer_id"), false);
      const forged = await signedInject({ method: "POST", url: "/pix/automatic/mandates",
        headers: headers(payer), payload: { from_account: seedAccountId(1),
          merchant_account: seedAccountId(2), max_amount_cents: 5_000,
          frequency: "weekly", starts_at: "2026-11-14T10:00:00.000Z",
          post_due_retry_allowed: true } });
      assert.equal(forged.statusCode, 400);
      const mismatched = await signedInject({ method: "POST", url: "/pix/automatic/mandates",
        headers: headers(payer), payload: { from_account: seedAccountId(1),
          merchant_account: seedAccountId(2), max_amount_cents: 4_000,
          frequency: "weekly", starts_at: "2026-11-14T10:00:00.000Z",
          offer_id: offer.json().id } });
      assert.equal(mismatched.statusCode, 400);
      assert.equal(mismatched.json().error, "BIZ_AUTOMATIC_OFFER_MISMATCH");
      const granted = await signedInject({ method: "POST", url: "/pix/automatic/mandates",
        headers: headers(payer), payload: { from_account: seedAccountId(1),
          merchant_account: seedAccountId(2), max_amount_cents: 5_000,
          frequency: "weekly", starts_at: "2026-11-14T10:00:00.000Z",
          offer_id: offer.json().id } });
      assert.equal(granted.statusCode, 200);
      assert.equal(granted.json().post_due_retry_allowed, 1);
      assert.equal(granted.json().offer_id, offer.json().id);
      const revokeOfferUrl = `/pix/automatic/offers/${offer.json().id}/revoke`;
      const wrongRevoker = await signedInject({ method: "POST", url: revokeOfferUrl,
        headers: headers(payer) });
      assert.equal(wrongRevoker.statusCode, 404);
      const revokedOffer = await signedInject({ method: "POST", url: revokeOfferUrl,
        headers: headers(merchant) });
      assert.equal(revokedOffer.statusCode, 200);
      assert.ok(revokedOffer.json().revoked_at);
      const revokedAgain = await signedInject({ method: "POST", url: revokeOfferUrl,
        headers: headers(merchant) });
      assert.equal(revokedAgain.json().revoked_at, revokedOffer.json().revoked_at);
      const payerOfferAfterRevoke = await app.inject({ method: "GET",
        url: `/pix/automatic/offers/${offer.json().id}`, headers: headers(payer) });
      assert.equal(payerOfferAfterRevoke.json().revoked_at,
        revokedOffer.json().revoked_at);
      const existingMandate = await app.inject({ method: "GET",
        url: `/pix/automatic/mandates/${granted.json().id}`, headers: headers(payer) });
      assert.equal(existingMandate.json().status, "active");
      const newGrant = await signedInject({ method: "POST", url: "/pix/automatic/mandates",
        headers: headers(payer), payload: { from_account: seedAccountId(1),
          merchant_account: seedAccountId(2), max_amount_cents: 5_000,
          frequency: "weekly", starts_at: "2026-11-14T10:00:00.000Z",
          offer_id: offer.json().id } });
      assert.equal(newGrant.statusCode, 400);
      assert.equal(newGrant.json().error, "BIZ_AUTOMATIC_OFFER_REVOKED");
      const charged = await signedInject({ method: "POST",
        url: `/pix/automatic/mandates/${granted.json().id}/charges`,
        headers: headers(merchant), payload: { amount_cents: 1_000,
          due_at: "2026-11-14T10:00:00.000Z" } });
      assert.equal(charged.statusCode, 200);
      fixture.setNow("2026-11-15T01:00:00.000Z");
      assert.deepEqual(automatic.executeDue(), { succeeded: 0, failed: 1 });
      const retryUrl = `/pix/automatic/charges/${charged.json().id}/retry`;
      const freshPayer = sessionFor(payerId, "payer-retry-fresh-device");
      const freshMerchant = sessionFor(merchantId, "merchant-retry-fresh-device");
      auth.stepUp(freshPayer.access_token, "a-strong-test-password");
      auth.stepUp(freshMerchant.access_token, "a-strong-test-password");
      keys.set(freshPayer.access_token, await bindDeviceKey(app, headers(freshPayer)));
      keys.set(freshMerchant.access_token, await bindDeviceKey(app, headers(freshMerchant)));
      const payerRetry = await signedInject({ method: "POST", url: retryUrl,
        headers: headers(freshPayer),
        payload: { due_at: "2026-11-15T10:00:00.000Z" } });
      assert.equal(payerRetry.statusCode, 404);
      const merchantRetry = await signedInject({ method: "POST", url: retryUrl,
        headers: headers(freshMerchant),
        payload: { due_at: "2026-11-15T10:00:00.000Z" } });
      assert.equal(merchantRetry.statusCode, 200);
      assert.equal(merchantRetry.json().status, "pending");
      const inbox = await app.inject({ method: "GET",
        url: "/pix/automatic/notifications",
        headers: headers(freshPayer) });
      assert.equal(inbox.statusCode, 200);
      assert.equal(inbox.json().some((notice) =>
        notice.kind === "charge_post_due_retry_1"), true);
    } finally { await app.close(); }
  } finally { fixture.close(); }
});

test("payer and merchant complete an authenticated automatic payment", async () => {
  const fixture = setup();
  const { bank, auth, automatic } = fixture;
  try {
    const offer = automatic.createOffer(seedCustomerId(2), seedAccountId(2),
      5_000, "weekly", "2026-11-14T10:00:00.000Z", undefined, false);
    const sessionFor = (customer, device) => {
      auth.setPassword(customer, "a-strong-test-password");
      const login = auth.beginLogin(bank.customer(customer).cpf,
        "a-strong-test-password", "10.0.0.1", device);
      return auth.verifyOtp(login.challenge_id,
        auth.simulatedOtp(login.challenge_id, customer), "10.0.0.1");
    };
    const payer = sessionFor(seedCustomerId(1), "payer-device");
    const merchant = sessionFor(seedCustomerId(2), "merchant-device");
    auth.stepUp(payer.access_token, "a-strong-test-password");
    auth.registerCurrentDeviceForPix(payer.access_token);
    auth.stepUp(merchant.access_token, "a-strong-test-password");
    const app = createTwinApi(bank, auth);
    try {
      const headers = (session) => ({ authorization: `Bearer ${session.access_token}` });
      const keys = new Map();
      keys.set(payer.access_token, await bindDeviceKey(app, headers(payer)));
      keys.set(merchant.access_token, await bindDeviceKey(app, headers(merchant)));
      const signedInject = async (request) => {
        const token = request.headers.authorization.slice(7);
        request.headers = await signedOperationHeaders(app, request.headers, keys.get(token),
          request.url, request.payload);
        return app.inject(request);
      };
      const granted = await signedInject({ method: "POST", url: "/pix/automatic/mandates",
        headers: headers(payer), payload: { from_account: seedAccountId(1),
          merchant_account: seedAccountId(2), max_amount_cents: 5_000,
          frequency: "weekly", starts_at: "2026-11-14T10:00:00.000Z",
          offer_id: offer.id } });
      assert.equal(granted.statusCode, 200);
      const mandate = granted.json();
      const wrongMerchant = await signedInject({ method: "POST",
        url: `/pix/automatic/mandates/${mandate.id}/charges`, headers: headers(payer),
        payload: { amount_cents: 1_000, due_at: "2026-11-14T10:00:00.000Z" } });
      assert.equal(wrongMerchant.statusCode, 404);
      const charged = await signedInject({ method: "POST",
        url: `/pix/automatic/mandates/${mandate.id}/charges`, headers: headers(merchant),
        payload: { amount_cents: 1_000, due_at: "2026-11-14T10:00:00.000Z" } });
      assert.equal(charged.statusCode, 200);
      fixture.setNow("2026-11-14T10:00:00.000Z");
      assert.deepEqual(automatic.executeDue(), { succeeded: 1, failed: 0 });
      const refreshedPayer = sessionFor(seedCustomerId(1), "payer-refreshed-device");
      auth.stepUp(refreshedPayer.access_token, "a-strong-test-password");
      keys.set(refreshedPayer.access_token, await bindDeviceKey(app, headers(refreshedPayer)));
      const history = await app.inject({ method: "GET",
        url: `/pix/automatic/mandates/${mandate.id}/charges`, headers: headers(refreshedPayer) });
      assert.equal(history.statusCode, 200);
      assert.equal(history.json()[0].status, "settled");
      const inbox = await app.inject({ method: "GET",
        url: "/pix/automatic/notifications", headers: headers(refreshedPayer) });
      assert.equal(inbox.statusCode, 200);
      assert.equal(inbox.json().some((notice) => notice.kind === "charge_settled"), true);
      const gateway = new Gateway(bank, app);
      const gatewayInbox = await gateway.call({ method: "GET",
        path: "/api/v1/pix/automatic/notifications",
        headers: headers(refreshedPayer), peerIp: "10.0.0.1" });
      assert.equal(gatewayInbox.status, 200);
      assert.equal(gatewayInbox.body.some((notice) =>
        notice.kind === "charge_settled"), true);
      const deniedGatewayInbox = await gateway.call({ method: "GET",
        path: "/api/v1/pix/automatic/notifications", peerIp: "10.0.0.1" });
      assert.equal(deniedGatewayInbox.status, 403);
      const refreshedMerchant = sessionFor(seedCustomerId(2), "merchant-refreshed-device");
      auth.stepUp(refreshedMerchant.access_token, "a-strong-test-password");
      keys.set(refreshedMerchant.access_token, await bindDeviceKey(app, headers(refreshedMerchant)));
      const merchantInbox = await app.inject({ method: "GET",
        url: "/pix/automatic/notifications", headers: headers(refreshedMerchant) });
      assert.equal(merchantInbox.statusCode, 200);
      assert.deepEqual(merchantInbox.json(), []);
      const future = await signedInject({ method: "POST",
        url: `/pix/automatic/mandates/${mandate.id}/charges`,
        headers: headers(refreshedMerchant),
        payload: { amount_cents: 1_000, due_at: "2026-11-21T10:00:00.000Z" } });
      assert.equal(future.statusCode, 200);
      const cancellationUrl = `/pix/automatic/charges/${future.json().id}/merchant-cancel`;
      const wrongCanceller = await signedInject({ method: "POST", url: cancellationUrl,
        headers: headers(refreshedPayer) });
      assert.equal(wrongCanceller.statusCode, 404);
      const cancelled = await signedInject({ method: "POST", url: cancellationUrl,
        headers: headers(refreshedMerchant) });
      assert.equal(cancelled.statusCode, 200);
      assert.equal(cancelled.json().status, "cancelled");
      const payerAfterCancellation = await app.inject({ method: "GET",
        url: "/pix/automatic/notifications", headers: headers(refreshedPayer) });
      assert.equal(payerAfterCancellation.json().some((notice) =>
        notice.kind === "charge_cancelled"), true);
      assert.equal(bank.reconcile().ok, true);
    } finally { await app.close(); }
  } finally { fixture.close(); }
});
