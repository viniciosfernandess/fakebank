import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, BankError, syntheticCpf } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { Gateway } from "../apps/world/src/gateway.ts";
import { AccountService } from "../apps/world/src/accounts.ts";
import { OnboardingService } from "../apps/world/src/onboarding.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId } from "../apps/world/src/id.ts";

function fixture(work) {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-onboarding-"));
  const path = join(dir, "bank.sqlite");
  const now = () => new Date("2026-11-18T12:00:00.000Z");
  const bank = new Bank(path, now, now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const auth = new AuthEngine(bank);
    return work({ bank, path, now, onboarding: new OnboardingService(bank, auth) });
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
}

function eligibleApplication(onboarding) {
  for (let index = 500; index < 600; index++) {
    const application = onboarding.apply({ cpf: syntheticCpf(index),
      name: `Applicant ${index}`, persona: "salaried", password: "synthetic-password-123" });
    if (application.bureau_score >= 20) return application;
  }
  throw new Error("No eligible synthetic bureau record");
}

test("customer applies through gateway and reaches an active account after review", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-onboarding-api-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-18T12:00:00.000Z"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const auth = new AuthEngine(bank);
  const app = createTwinApi(bank, auth);
  const gateway = new Gateway(bank, app);
  try {
    const cpf = syntheticCpf(500);
    const body = { cpf, name: "New Digital Customer", persona: "salaried",
      password: "synthetic-password-123" };
    const applied = await gateway.call({ method: "POST",
      path: "/api/v1/onboarding/apply", body, peerIp: "127.0.0.1" });
    assert.equal(applied.status, 200);
    assert.equal(applied.body.status, "pending");
    assert.equal("bureau_score" in applied.body, false);
    const customerId = applied.body.customer_id;
    const accountId = applied.body.account_id;
    assert.equal(bank.account(accountId).status, "under_review");
    const login = await gateway.call({ method: "POST", path: "/api/v1/auth/login",
      body: { cpf, password: body.password, device_id: "new-customer-device" },
      peerIp: "127.0.0.1" });
    assert.equal(login.status, 200);
    const otp = await gateway.call({ method: "POST", path: "/api/v1/auth/otp/verify",
      body: { challenge_id: login.body.challenge_id,
        otp: auth.simulatedOtp(login.body.challenge_id, customerId) },
      peerIp: "127.0.0.1" });
    assert.equal(otp.status, 200);
    const headers = { authorization: `Bearer ${otp.body.access_token}` };
    const pending = await gateway.call({ method: "GET", path: "/api/v1/accounts",
      headers, peerIp: "127.0.0.1" });
    assert.equal(pending.body.find((account) => account.id === accountId).status,
      "under_review");
    const onboarding = new OnboardingService(bank, auth);
    onboarding.attestLiveness(customerId, true, "verifier_1");
    onboarding.review(customerId, "approve", "reviewer_1");
    const active = await gateway.call({ method: "GET", path: "/api/v1/accounts",
      headers, peerIp: "127.0.0.1" });
    assert.equal(active.body.find((account) => account.id === accountId).status,
      "active");
    for (let index = 0; index < 2; index++)
      await gateway.call({ method: "POST", path: "/api/v1/onboarding/apply",
        body: { ...body, cpf: syntheticCpf(501 + index) }, peerIp: "127.0.0.1" });
    const limited = await gateway.call({ method: "POST",
      path: "/api/v1/onboarding/apply", body: { ...body, cpf: syntheticCpf(503) },
      peerIp: "127.0.0.1" });
    assert.equal(limited.status, 429);
    assert.equal(limited.body.error, "BIZ_ONBOARDING_RATE_LIMIT");
  } finally { await app.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("onboarding keeps a new account under review until independent evidence and decision", () => fixture(
  ({ bank, path, now, onboarding }) => {
    const application = eligibleApplication(onboarding);
    const { customer_id: customerId, account_id: accountId } = application;
    assert.equal(bank.account(accountId).status, "under_review");
    assert.equal(bank.customer(customerId).kyc_tier, 0);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM auth_passwords WHERE customer_id=?")
      .get(customerId).n, 1);
    assert.throws(() => new AccountService(bank).openSecond(customerId),
      (error) => error instanceof BankError && error.code === "DEF_ACCOUNT_FROZEN");
    assert.throws(() => bank.changeAccountStatus(accountId, "active", "operator_1"),
      (error) => error instanceof BankError && error.code === "DEF_ONBOARDING_REVIEW_REQUIRED");
    assert.throws(() => bank.submitKyc(customerId, 2),
      (error) => error instanceof BankError && error.code === "DEF_ONBOARDING_REVIEW_REQUIRED");
    bank.fund(accountId, 5_000);
    assert.equal(bank.account(accountId).balance_cached, 5_000);
    assert.equal(bank.availableBalance(accountId), 0);
    assert.throws(() => bank.transferPix({ from: accountId, to: seedAccountId(1),
      amount: 100, idempotencyKey: "onboarding-pending", actor: customerId }),
    (error) => error instanceof BankError && error.code === "DEF_ACCOUNT_FROZEN");
    assert.throws(() => onboarding.review(customerId, "approve", "reviewer_1"),
      (error) => error instanceof BankError && error.code === "DEF_ONBOARDING_EVIDENCE_REQUIRED");
    onboarding.attestLiveness(customerId, true, "verifier_1");
    assert.throws(() => onboarding.review(customerId, "approve", "verifier_1"),
      (error) => error instanceof BankError && error.code === "DEF_ONBOARDING_REVIEW_SEPARATION");
    assert.equal(onboarding.review(customerId, "approve", "reviewer_1").status, "approved");
    assert.equal(bank.account(accountId).status, "active");
    assert.equal(bank.availableBalance(accountId), 5_000);
    assert.equal(bank.customer(customerId).kyc_tier, 1);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM kyc_history WHERE customer_id=?")
      .get(customerId).n, 2);
    const ledgerBefore = bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n;
    const reopened = new Bank(path, now, now);
    try {
      assert.equal(reopened.account(accountId).status, "active");
      assert.equal(new OnboardingService(reopened, new AuthEngine(reopened))
        .application(customerId).status, "approved");
      assert.equal(reopened.db.prepare("SELECT COUNT(*) n FROM ledger_entries").get().n,
        ledgerBefore);
      assert.throws(() => reopened.db.exec("DELETE FROM onboarding_events"),
        /ONBOARDING_HISTORY_IMMUTABLE/);
    } finally { reopened.close(); }
  }));

test("rejected liveness leaves the account frozen and cannot be approved later", () => fixture(
  ({ bank, onboarding }) => {
    const application = onboarding.apply({ cpf: syntheticCpf(700),
      name: "Rejected Applicant", persona: "gig", password: "synthetic-password-456" });
    onboarding.attestLiveness(application.customer_id, false, "verifier_2");
    assert.throws(() => onboarding.review(application.customer_id, "approve", "reviewer_2"),
      (error) => error instanceof BankError && error.code === "DEF_ONBOARDING_EVIDENCE_REQUIRED");
    assert.equal(onboarding.review(application.customer_id, "reject", "reviewer_2").status,
      "rejected");
    assert.equal(bank.account(application.account_id).status, "frozen");
    assert.equal(bank.account(application.account_id).frozen_reason, "kyc");
    assert.throws(() => bank.submitKyc(application.customer_id, 2),
      (error) => error instanceof BankError && error.code === "DEF_ONBOARDING_REVIEW_REQUIRED");
    assert.throws(() => bank.changeAccountStatus(application.account_id, "active", "reviewer_3"),
      (error) => error instanceof BankError && error.code === "DEF_ONBOARDING_REVIEW_REQUIRED");
    assert.throws(() => onboarding.review(application.customer_id, "approve", "reviewer_3"),
      (error) => error instanceof BankError && error.code === "BIZ_ONBOARDING_NOT_PENDING");
    assert.throws(() => bank.db.exec("UPDATE onboarding_events SET actor='changed'"),
      /ONBOARDING_HISTORY_IMMUTABLE/);
  }));

test("synthetic bureau floor and immutable evidence prevent an unsupported approval", () => fixture(
  ({ bank, onboarding }) => {
    const before = bank.db.prepare("SELECT COUNT(*) n FROM customers").get().n;
    assert.throws(() => onboarding.apply({ cpf: "00000000000",
      name: "Invalid Applicant", persona: "salaried", password: "synthetic-password-789" }),
    (error) => error instanceof BankError && error.code === "BIZ_INVALID_CPF");
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM customers").get().n, before);
    const application = onboarding.apply({ cpf: syntheticCpf(608),
      name: "Low Bureau Applicant", persona: "student", password: "synthetic-password-789" });
    assert.equal(application.bureau_score, 17);
    assert.throws(() => bank.db.prepare(`UPDATE onboarding_applications
      SET bureau_score=100 WHERE customer_id=?`).run(application.customer_id),
    /ONBOARDING_APPLICATION_IMMUTABLE/);
    const original = bank.db.prepare(`SELECT * FROM onboarding_applications
      WHERE customer_id=?`).get(application.customer_id);
    assert.throws(() => bank.db.prepare(`INSERT OR REPLACE INTO onboarding_applications
      (customer_id,account_id,bureau_score,liveness_status,liveness_verifier,
       status,submitted_at,reviewed_at,reviewer) VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(original.customer_id, original.account_id, 100, original.liveness_status,
        original.liveness_verifier, original.status, original.submitted_at,
        original.reviewed_at, original.reviewer), /ONBOARDING_APPLICATION_IMMUTABLE/);
    assert.throws(() => bank.db.prepare(`UPDATE onboarding_applications
      SET status='approved',reviewed_at=?,reviewer='reviewer_1' WHERE customer_id=?`)
      .run(bank.now().toISOString(), application.customer_id),
    /ONBOARDING_APPLICATION_TERMINAL/);
    onboarding.attestLiveness(application.customer_id, true, "verifier_1");
    assert.throws(() => onboarding.review(application.customer_id, "approve", "reviewer_1"),
      (error) => error instanceof BankError && error.code === "DEF_ONBOARDING_EVIDENCE_REQUIRED");
    assert.equal(onboarding.review(application.customer_id, "reject", "reviewer_1").status,
      "rejected");
  }));

test("onboarding rolls back account creation and approval when audit persistence fails", () => fixture(
  ({ bank, onboarding }) => {
    const before = bank.db.prepare("SELECT COUNT(*) n FROM customers").get().n;
    bank.db.exec(`CREATE TRIGGER fail_onboarding_event BEFORE INSERT ON onboarding_events
      BEGIN SELECT RAISE(ABORT,'AUDIT_FAILURE'); END`);
    assert.throws(() => onboarding.apply({ cpf: syntheticCpf(800),
      name: "Rollback Applicant", persona: "gig", password: "synthetic-password-789" }),
    /AUDIT_FAILURE/);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM customers").get().n, before);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM onboarding_applications").get().n, 0);
    bank.db.exec("DROP TRIGGER fail_onboarding_event");
    const application = onboarding.apply({ cpf: syntheticCpf(500),
      name: "Approved Applicant", persona: "salaried", password: "synthetic-password-789" });
    onboarding.attestLiveness(application.customer_id, true, "verifier_1");
    bank.db.exec(`CREATE TRIGGER fail_approval_event BEFORE INSERT ON onboarding_events
      WHEN NEW.event='approved' BEGIN SELECT RAISE(ABORT,'AUDIT_FAILURE'); END`);
    assert.throws(() => onboarding.review(application.customer_id, "approve", "reviewer_1"),
      /AUDIT_FAILURE/);
    assert.equal(onboarding.application(application.customer_id).status, "pending");
    assert.equal(bank.account(application.account_id).status, "under_review");
    assert.equal(bank.customer(application.customer_id).kyc_tier, 0);
    assert.equal(bank.db.prepare(`SELECT status FROM kyc_requests WHERE customer_id=?`)
      .get(application.customer_id).status, "submitted");
  }));
