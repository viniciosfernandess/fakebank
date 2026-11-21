import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { Gateway, gatewayRouteTemplate } from "../apps/world/src/gateway.ts";
import { LoansEngine } from "../apps/world/src/loans.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";
import { exportSplitSnapshots } from "../scripts/export-ecosystem-snapshot.mjs";
import { verifySplitSnapshots } from "../scripts/verify-split-snapshot.mjs";

test("new loans persist customer-owned Price and SAC schedules without rewriting a prepaid contract", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-contracts-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    for (const [index, method, term] of [[1, "PRICE", 12], [2, "SAC", 6]]) {
      const customer = seedCustomerId(index), deposit = seedAccountId(index);
      const offer = loans.offer(customer);
      const loan = loans.accept(customer, offer.id, deposit, 50_000, undefined, undefined,
        { method, term_months: term });
      const stored = loans.contract(customer, loan.id);
      assert.equal(stored.contract.method, method);
      assert.equal(stored.contract.term_months, term);
      assert.equal(stored.contract.rate_bps_month, offer.rate_bps_month);
      assert.equal(stored.installments.length, term);
      assert.equal(stored.installments.reduce((sum, item) => sum + item.principal_cents, 0), 50_000);
      assert.equal(stored.installments.at(-1).closing_principal_cents, 0);
      assert.equal(stored.installments[0].due_date, "2026-12-13");
      assert.equal(loan.due_at.slice(0, 10), stored.installments.at(-1).due_date);
      assert.throws(() => bank.db.prepare("UPDATE loan_contracts SET rate_bps_month=0 WHERE loan_id=?")
        .run(loan.id), /LOAN_CONTRACT_IMMUTABLE/);
      assert.throws(() => bank.db.prepare(`UPDATE loan_installments SET principal_cents=0
        WHERE loan_id=? AND installment_no=1`).run(loan.id), /LOAN_SCHEDULE_IMMUTABLE/);
      assert.throws(() => loans.contract(seedCustomerId(index === 1 ? 2 : 1), loan.id),
        /DEF_NOT_FOUND/);
      if (index === 1) {
        loans.prepay(customer, loan.id);
        const after = loans.contract(customer, loan.id);
        assert.ok(after.installments.every((item) => item.status === "prepaid"));
        assert.equal(after.installments.reduce((sum, item) => sum + item.paid_cents, 0), 0);
      }
    }
    assert.equal(bank.trialBalance().reduce((sum, line) => sum + line.balance_cents, 0), 0);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("loan quote discloses schedule and fee without booking a contract", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-quote-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () =>
    new Date("2026-11-13T12:00:00Z"));
  let app;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const quote = loans.quote(customer, offer.id, 40_000,
      { method: "SAC", term_months: 3 });
    assert.equal(quote.principal_cents, 40_000);
    assert.equal(quote.fee_cents, 800);
    assert.equal(quote.installments.length, 3);
    assert.equal(quote.installments.reduce((total, item) =>
      total + item.payment_cents, 0), quote.total_installments_cents);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM loans").get().n, 0);
    assert.throws(() => loans.quote(seedCustomerId(2), offer.id, 40_000,
      { method: "SAC", term_months: 3 }), /DEF_NOT_FOUND/);
    const auth = new AuthEngine(bank);
    auth.setPassword(customer, "loan-quote-password");
    app = createTwinApi(bank, auth);
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "loan-quote-password", "127.0.0.1", "loan-quote-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    assert.equal(gatewayRouteTemplate("/api/v1/loans/quote"),
      "/api/v1/loans/quote");
    const response = await app.inject({ method: "POST", url: "/loans/quote",
      headers: { authorization: `Bearer ${session.access_token}` },
      payload: { offer_id: offer.id, amount_cents: 40_000,
        method: "SAC", term_months: 3 } });
    assert.equal(response.statusCode, 200, response.body);
    assert.equal(response.json().total_installments_cents,
      quote.total_installments_cents);
    assert.equal(bank.reconcile().ok, true);
    bank.db.prepare(`UPDATE customers SET kyc_tier=0,kyc_status='submitted'
      WHERE id=?`).run(customer);
    assert.throws(() => loans.quote(customer, offer.id, 40_000,
      { method: "SAC", term_months: 3 }), /BIZ_LOAN_INELIGIBLE/);
    assert.throws(() => loans.accept(customer, offer.id, seedAccountId(1),
      40_000), /BIZ_LOAN_INELIGIBLE/);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM loans").get().n, 0);
  } finally { await app?.close(); bank.close();
    rmSync(dir, { recursive: true, force: true }); }
});

test("contract route is customer-scoped through the gateway", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-contract-api-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const loans = new LoansEngine(bank);
  const customer = seedCustomerId(1), other = seedCustomerId(2);
  const offer = loans.offer(customer);
  const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000);
  const auth = new AuthEngine(bank);
  auth.setPassword(customer, "loan-contract-password");
  auth.setPassword(other, "other-loan-password");
  const app = createTwinApi(bank, auth);
  try {
    const login = (id, password) => {
      const challenge = auth.beginLogin(bank.customer(id).cpf, password, "127.0.0.1", `device-${id}`);
      return auth.verifyOtp(challenge.challenge_id,
        auth.simulatedOtp(challenge.challenge_id, id), "127.0.0.1").access_token;
    };
    const gateway = new Gateway(bank, app);
    const path = `/api/v1/loans/${loan.id}/contract`;
    const read = async (token) => gateway.call({ method: "GET", path, peerIp: "127.0.0.1",
      headers: { authorization: `Bearer ${token}` } });
    assert.equal(gatewayRouteTemplate(path), "/api/v1/loans/:id/contract");
    const owned = await read(login(customer, "loan-contract-password"));
    assert.equal(owned.status, 200);
    assert.equal(owned.body.contract.method, "PRICE");
    assert.equal(owned.body.installments.length, 12);
    assert.equal((await read(login(other, "other-loan-password"))).status, 404);
  } finally { await app.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("overdue SAC installment posts principal, interest and late charges before prepayment", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-payments-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), deposit = seedAccountId(1);
    const offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, deposit, 40_000, undefined, undefined,
      { method: "SAC", term_months: 2 });
    const first = loans.contract(customer, loan.id).installments[0];
    now = new Date("2026-12-16T12:00:00Z");
    assert.throws(() => loans.payInstallment(customer, loan.id, 2), /BIZ_LOAN_INSTALLMENT_ORDER/);
    const paid = loans.payInstallment(customer, loan.id, 1);
    assert.equal(paid.installment.status, "paid");
    assert.equal(paid.amount_cents,
      first.payment_cents + paid.late_fee_cents + paid.mora_cents);
    assert.ok(paid.late_fee_cents > 0);
    assert.ok(paid.mora_cents > 0);
    assert.throws(() => loans.payInstallment(customer, loan.id, 1), /BIZ_LOAN_INSTALLMENT_ORDER/);
    const lines = bank.trialBalance();
    assert.equal(lines.find((line) => line.code === "1100").balance_cents,
      -(40_000 - first.principal_cents));
    assert.equal(lines.find((line) => line.code === "3050").balance_cents, first.interest_cents);
    assert.equal(lines.find((line) => line.code === "3060").balance_cents,
      paid.late_fee_cents + paid.mora_cents);
    const prepayment = loans.prepay(customer, loan.id);
    assert.equal(prepayment.loan.status, "prepaid");
    assert.equal(loans.contract(customer, loan.id).installments[1].status, "prepaid");
    assert.equal(bank.trialBalance().find((line) => line.code === "1100").balance_cents, 0);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("partial overdue payments allocate interest first and survive close and completion", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-partial-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(path, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1);
    const offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000,
      undefined, undefined, { method: "SAC", term_months: 2 });
    assert.throws(() => loans.payInstallmentAmount(customer, loan.id, 1, 1_000),
      /BIZ_LOAN_PARTIAL_NOT_OVERDUE/);
    now = new Date("2026-12-16T12:00:00Z");
    const first = loans.payInstallmentAmount(customer, loan.id, 1, 10_000,
      "partial-first");
    assert.equal(JSON.stringify(loans.payInstallmentAmount(customer, loan.id, 1,
      10_000, "partial-first")), JSON.stringify(first));
    assert.throws(() => loans.payInstallmentAmount(customer, loan.id, 1,
      9_000, "partial-first"), /BIZ_IDEMPOTENCY_CONFLICT/);
    assert.equal(first.installment.status, "scheduled");
    assert.ok(first.installment.paid_cents > 0);
    assert.ok(first.late_fee_cents > 0);
    assert.ok(first.mora_cents > 0);
    now = new Date("2026-12-15T12:00:00Z");
    assert.throws(() => loans.payInstallmentAmount(customer, loan.id, 1, 1_000),
      /BIZ_LOAN_PAYMENT_DATE_ORDER/);
    now = new Date("2026-12-16T12:00:00Z");
    assert.equal(bank.reconcile().ok, true);
    now = new Date("2026-12-17T06:00:00Z");
    bank.periodClose();
    assert.equal(bank.reconcile().ok, true);
    now = new Date("2026-12-20T12:00:00Z");
    const second = loans.payInstallmentAmount(customer, loan.id, 1, 5_000);
    assert.equal(second.late_fee_cents, 0);
    assert.ok(second.mora_cents > 0);
    assert.equal(bank.reconcile().ok, true);
    const complete = loans.payInstallment(customer, loan.id, 1);
    assert.equal(complete.installment.status, "paid");
    assert.equal(loans.contract(customer, loan.id).installments[0].paid_cents,
      loans.contract(customer, loan.id).installments[0].payment_cents);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM loan_installment_partial_payments
      WHERE loan_id=?`).get(loan.id).n, 3);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(loans.prepay(customer, loan.id).loan.status, "prepaid");
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); }
  const reopened = new Bank(path, () => now);
  try { assert.equal(reopened.reconcile().ok, true); }
  finally { reopened.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("pending partial installment survives restart without duplicate collection", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-partial-restart-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-13T12:00:00Z");
  let bank = new Bank(path, () => now);
  let loanId;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    loanId = loans.accept(customer, offer.id, seedAccountId(1), 40_000).id;
    now = new Date("2026-12-16T12:00:00Z");
    loans.payInstallmentAmount(customer, loanId, 1, 2_000, "restart-partial");
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); }
  bank = new Bank(path, () => now);
  try {
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(loans.payInstallmentAmount(customer, loanId, 1, 2_000,
      "restart-partial").amount_cents, 2_000);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM loan_installment_partial_payments
      WHERE loan_id=?`).get(loanId).n, 1);
    assert.equal(loans.payInstallment(customer, loanId, 1).installment.status, "paid");
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("split snapshot carries an outstanding partial loan into the local bank", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-partial-split-"));
  const sourcePath = join(dir, "source.sqlite");
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  let now = new Date("2026-11-13T12:00:00Z");
  const source = new Bank(sourcePath, () => now);
  let loanId;
  try {
    seedBank(source, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(source);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    loanId = loans.accept(customer, offer.id, seedAccountId(1), 40_000).id;
    now = new Date("2026-12-16T12:00:00Z");
    loans.payInstallmentAmount(customer, loanId, 1, 2_000, "split-partial");
    assert.equal(source.reconcile().ok, true);
  } finally { source.close(); }
  try {
    exportSplitSnapshots(sourcePath, bankPath, ecosystemPath);
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
    const bank = new Bank(bankPath, () => now, () => now,
      { ecosystemMode: "separated" });
    try {
      const loans = new LoansEngine(bank);
      assert.equal(bank.reconcile().ok, true);
      assert.ok(loans.contract(seedCustomerId(1), loanId).installments[0].paid_cents > 0);
      assert.equal(loans.payInstallmentAmount(seedCustomerId(1), loanId, 1,
        2_000, "split-partial").amount_cents, 2_000);
      assert.equal(bank.reconcile().ok, true);
    } finally { bank.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("installment payment requires the owner's exact device signature", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-pay-api-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const loans = new LoansEngine(bank);
  const customer = seedCustomerId(1);
  const offer = loans.offer(customer);
  const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000);
  const auth = new AuthEngine(bank);
  auth.setPassword(customer, "loan-payment-password");
  const app = createTwinApi(bank, auth);
  try {
    const challenge = auth.beginLogin(bank.customer(customer).cpf, "loan-payment-password",
      "127.0.0.1", "loan-payment-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    const headers = { authorization: `Bearer ${session.access_token}` };
    auth.stepUp(session.access_token, "loan-payment-password");
    const privateKey = await bindDeviceKey(app, headers);
    const path = `/loans/${loan.id}/installments/1/pay`;
    assert.equal((await app.inject({ method: "POST", url: path, headers })).statusCode, 403);
    const signedHeaders = await signedOperationHeaders(app, headers, privateKey, path, undefined);
    const paid = await app.inject({ method: "POST", url: path, headers: signedHeaders });
    assert.equal(paid.statusCode, 200);
    assert.equal(paid.json().installment.status, "paid");
    assert.equal((await app.inject({ method: "POST", url: path,
      headers: signedHeaders })).statusCode, 403);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM loan_installment_payments").get().n, 1);
  } finally { await app.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("partial installment route is customer scoped and signed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-partial-api-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const loans = new LoansEngine(bank);
  const customer = seedCustomerId(1);
  const offer = loans.offer(customer);
  const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000);
  const auth = new AuthEngine(bank);
  auth.setPassword(customer, "loan-partial-password");
  const app = createTwinApi(bank, auth);
  try {
    now = new Date("2026-12-16T12:00:00Z");
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "loan-partial-password", "127.0.0.1", "loan-partial-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    const headers = { authorization: `Bearer ${session.access_token}` };
    auth.stepUp(session.access_token, "loan-partial-password");
    const privateKey = await bindDeviceKey(app, headers);
    const path = `/loans/${loan.id}/installments/1/partial-pay`;
    const body = { amount_cents: 2_000, idempotency_key: "api-partial-first" };
    assert.equal(gatewayRouteTemplate(`/api/v1${path}`),
      "/api/v1/loans/:id/installments/:id/partial-pay");
    assert.equal((await app.inject({ method: "POST", url: path,
      headers, payload: body })).statusCode, 403);
    const signed = await signedOperationHeaders(app, headers, privateKey, path, body);
    const paid = await app.inject({ method: "POST", url: path,
      headers: signed, payload: body });
    assert.equal(paid.statusCode, 200, paid.body);
    assert.equal(paid.json().installment.status, "scheduled");
    assert.ok(paid.json().installment.paid_cents > 0);
    assert.equal((await app.inject({ method: "POST", url: path,
      headers: signed, payload: body })).statusCode, 403);
    const retryHeaders = await signedOperationHeaders(app, headers, privateKey, path, body);
    const retry = await app.inject({ method: "POST", url: path,
      headers: retryHeaders, payload: body });
    assert.equal(retry.statusCode, 200);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM loan_installment_partial_payments
      WHERE loan_id=?`).get(loan.id).n, 1);
    assert.equal(bank.reconcile().ok, true);
  } finally { await app.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("all scheduled payments settle the loan without a second principal write", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-settled-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1);
    const offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000, undefined,
      undefined, { method: "PRICE", term_months: 2 });
    now = new Date("2026-12-13T12:00:00Z");
    assert.equal(loans.payInstallment(customer, loan.id, 1).loan.status, "active");
    now = new Date("2027-01-13T12:00:00Z");
    assert.equal(loans.payInstallment(customer, loan.id, 2).loan.status, "settled");
    assert.equal(bank.trialBalance().find((line) => line.code === "1100").balance_cents, 0);
    assert.equal(bank.db.prepare(`SELECT SUM(principal_cents) n FROM loan_installment_payments
      WHERE loan_id=?`).get(loan.id).n, 40_000);
    assert.throws(() => loans.prepay(customer, loan.id), /BIZ_LOAN_NOT_ACTIVE/);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("daily close rejects a schedule change that has no matching loan payment", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-close-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000);
    now = new Date("2026-11-17T06:00:00Z");
    assert.ok(bank.periodClose().brt_date);
    bank.db.prepare(`UPDATE loan_installments SET paid_cents=1
      WHERE loan_id=? AND installment_no=1`).run(loan.id);
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("daily provision follows loan aging and releases after repayment", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-provision-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000);
    now = new Date("2026-11-17T06:00:00Z");
    const firstClose = bank.periodClose();
    assert.equal(bank.trialBalance().find((line) => line.code === "1120").balance_cents, 400);
    assert.equal(bank.trialBalance().find((line) => line.code === "4010").balance_cents, 0);
    assert.equal(JSON.parse(bank.db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date=?`).get(firstClose.brt_date).lines_json)
      .find((line) => line.code === "4010").balance_cents, -400);
    bank.periodClose();
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM loan_provision_changes").get().n, 1);
    now = new Date("2026-12-17T06:00:00Z");
    bank.periodClose();
    assert.equal(bank.trialBalance().find((line) => line.code === "1120").balance_cents, 2_000);
    assert.equal(bank.db.prepare("SELECT MAX(max_days_past_due) n FROM loan_provision_changes")
      .get().n, 3);
    now = new Date("2026-12-18T04:00:00Z");
    loans.payInstallment(customer, loan.id, 1);
    loans.prepay(customer, loan.id);
    now = new Date("2026-12-18T06:00:00Z");
    bank.periodClose();
    assert.equal(bank.trialBalance().find((line) => line.code === "1120").balance_cents, 2_000);
    now = new Date("2026-12-19T06:00:00Z");
    bank.periodClose();
    assert.equal(bank.trialBalance().find((line) => line.code === "1120").balance_cents, 0);
    assert.equal(bank.trialBalance().find((line) => line.code === "4010").balance_cents, 0);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM loan_provision_changes").get().n, 4);
    bank.db.prepare("UPDATE loan_provision_positions SET amount_cents=1 WHERE loan_id=?")
      .run(loan.id);
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
    bank.db.prepare("UPDATE loan_provision_positions SET amount_cents=0 WHERE loan_id=?")
      .run(loan.id);
    bank.db.exec("DROP TRIGGER loan_provision_changes_no_update");
    bank.db.prepare(`UPDATE loan_provision_changes SET max_days_past_due=999
      WHERE loan_id=? AND as_of_date='2026-12-16'`).run(loan.id);
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("due loan interest accrues at close and payment clears the receivable once", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-interest-accrual-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000);
    const interest = loans.contract(customer, loan.id).installments[0].interest_cents;
    now = new Date("2026-12-15T06:00:00Z");
    const first = bank.periodClose();
    assert.equal(first.brt_date, "2026-12-14");
    assert.equal(bank.trialBalance().find((line) => line.code === "1130").balance_cents,
      -interest);
    assert.equal(bank.trialBalance().find((line) => line.code === "3050").balance_cents, 0);
    assert.equal(JSON.parse(bank.db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date=?`).get(first.brt_date).lines_json)
      .find((line) => line.code === "3050").balance_cents, interest);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM loan_interest_accruals
      WHERE loan_id=?`).get(loan.id).n, 1);
    now = new Date("2026-12-15T12:00:00Z");
    loans.payInstallment(customer, loan.id, 1);
    assert.equal(bank.trialBalance().find((line) => line.code === "1130").balance_cents, 0);
    assert.equal(bank.trialBalance().find((line) => line.code === "3050").balance_cents, 0);
    now = new Date("2026-12-16T06:00:00Z");
    bank.periodClose();
    assert.equal(bank.reconcile().ok, true);
    now = new Date("2026-12-15T06:00:00Z");
    assert.equal(bank.periodClose().brt_date, first.brt_date);
    bank.db.exec("DROP TRIGGER loan_interest_accruals_no_update");
    bank.db.prepare(`UPDATE loan_interest_accruals SET amount_cents=amount_cents+1
      WHERE loan_id=?`).run(loan.id);
    assert.throws(() => bank.periodClose(), /INTEGRITY_PERIOD_CLOSE_BLOCKED/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("payment after due but before close preserves the due-date receivable snapshot", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-interest-cutoff-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000);
    const interest = loans.contract(customer, loan.id).installments[0].interest_cents;
    now = new Date("2026-12-14T04:00:00Z");
    loans.payInstallment(customer, loan.id, 1);
    assert.equal(bank.trialBalance().find((line) => line.code === "1130").balance_cents, 0);
    now = new Date("2026-12-14T06:00:00Z");
    const close = bank.periodClose();
    assert.equal(close.brt_date, "2026-12-13");
    const lines = JSON.parse(bank.db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date=?`).get(close.brt_date).lines_json);
    assert.equal(lines.find((line) => line.code === "1130").balance_cents, -interest);
    assert.equal(lines.find((line) => line.code === "3050").balance_cents, interest);
    assert.equal(bank.trialBalance().find((line) => line.code === "3050").balance_cents, 0);
    assert.equal(bank.periodClose().brt_date, close.brt_date);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("prepaid future installments never accrue forgiven interest", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-prepaid-interest-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000);
    now = new Date("2026-11-14T12:00:00Z");
    loans.prepay(customer, loan.id);
    now = new Date("2027-01-16T06:00:00Z");
    bank.periodClose();
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM loan_interest_accruals
      WHERE loan_id=?`).get(loan.id).n, 0);
    assert.equal(bank.trialBalance().find((line) => line.code === "1130").balance_cents, 0);
    assert.equal(bank.trialBalance().find((line) => line.code === "3050").balance_cents, 0);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a restarted bank accrues an older loan without opening the loan module", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-accrual-restart-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-13T12:00:00Z");
  let bank = new Bank(path, () => now);
  let interest;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000);
    interest = loans.contract(customer, loan.id).installments[0].interest_cents;
    bank.db.exec("DROP TABLE loan_interest_accruals");
    bank.close();
    now = new Date("2026-12-15T06:00:00Z");
    bank = new Bank(path, () => now);
    assert.equal(bank.periodClose().brt_date, "2026-12-14");
    assert.equal(bank.trialBalance().find((line) => line.code === "1130").balance_cents,
      -interest);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM loan_interest_accruals")
      .get().n, 1);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("prepayment and refinancing preserve due installment charges until they are paid", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-due-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000, undefined,
      undefined, { method: "SAC", term_months: 2 });
    const before = bank.account(loan.account_id).balance_cached;
    now = new Date("2026-12-16T12:00:00Z");
    assert.throws(() => loans.prepay(customer, loan.id), /BIZ_LOAN_DUE_INSTALLMENT/);
    assert.throws(() => loans.refinance(customer, loan.id), /BIZ_LOAN_DUE_INSTALLMENT/);
    assert.equal(bank.account(loan.account_id).balance_cached, before);
    assert.equal(loans.loan(customer, loan.id).status, "active");
    assert.equal(loans.contract(customer, loan.id).installments[0].status, "scheduled");
    const paid = loans.payInstallment(customer, loan.id, 1);
    assert.ok(paid.late_fee_cents > 0);
    assert.ok(paid.mora_cents > 0);
    assert.equal(loans.prepay(customer, loan.id).loan.status, "prepaid");
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("chart migration adds loan accounting accounts without rewriting an older close", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-provision-migrate-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-14T06:00:00Z");
  const first = new Bank(path, () => now);
  let snapshot;
  try {
    seedBank(first, { customers: 2, accounts: 2, historyTransactions: 0 });
    const close = first.periodClose();
    snapshot = first.db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date=?`).get(close.brt_date).lines_json;
    first.db.exec("DROP TABLE period_close_seals");
    first.db.prepare("UPDATE period_closes SET chart_version=5 WHERE brt_date=?")
      .run(close.brt_date);
    first.db.prepare("UPDATE gl_accounts SET system_role=NULL WHERE code='3050'").run();
    first.db.prepare(`DELETE FROM accounts WHERE system_role IN
      ('loan_loss_allowance','loan_provision_expense',
       'loan_interest_receivable','loan_interest_revenue')`).run();
  } finally { first.close(); }
  now = new Date("2026-11-15T06:00:00Z");
  const reopened = new Bank(path, () => now);
  try {
    const rows = reopened.db.prepare(`SELECT system_role,balance_cached FROM accounts
      WHERE system_role IN ('loan_loss_allowance','loan_provision_expense',
        'loan_interest_receivable','loan_interest_revenue')`).all();
    assert.equal(rows.length, 4);
    assert.ok(rows.every((row) => row.balance_cached === 0));
    assert.equal(reopened.db.prepare("SELECT system_role FROM gl_accounts WHERE code='3050'")
      .get().system_role, "loan_interest_revenue");
    assert.equal(reopened.db.prepare(`SELECT lines_json FROM period_trial_balances
      WHERE brt_date='2026-11-13'`).get().lines_json, snapshot);
    assert.equal(reopened.db.prepare(`SELECT chart_version FROM period_closes
      WHERE brt_date='2026-11-13'`).get().chart_version, 5);
    const next = reopened.periodClose();
    assert.equal(reopened.db.prepare(`SELECT chart_version FROM period_closes
      WHERE brt_date=?`).get(next.brt_date).chart_version, 8);
    assert.equal(reopened.reconcile().ok, true);
  } finally { reopened.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("refinancing after an installment carries only unpaid principal", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-refinance-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const original = loans.accept(customer, offer.id, seedAccountId(1), 40_000, undefined,
      undefined, { method: "SAC", term_months: 2 });
    now = new Date("2026-12-13T12:00:00Z");
    const payment = loans.payInstallment(customer, original.id, 1);
    const remaining = 40_000 - payment.installment.principal_cents;
    const renewed = loans.refinance(customer, original.id);
    assert.equal(renewed.previous.status, "refinanced");
    assert.equal(renewed.next.principal_cents, remaining);
    assert.equal(loans.contract(customer, original.id).installments[1].status, "prepaid");
    assert.equal(loans.contract(customer, renewed.next.id).contract.method, "PRICE");
    assert.equal(bank.trialBalance().find((line) => line.code === "1100").balance_cents,
      -remaining);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("overdue loan renegotiation finances the payoff and preserves both contracts", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-renegotiate-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(path, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), account = seedAccountId(1);
    const offer = loans.offer(customer);
    const previous = loans.accept(customer, offer.id, account, 40_000,
      undefined, undefined, { method: "SAC", term_months: 3 });
    assert.deepEqual(loans.list(seedCustomerId(2)), []);
    const available = bank.availableBalance(account);
    bank.post([
      { accountId: account, amount: -available, kind: "test_transfer",
        actor: customer, refType: "test", refId: "drain" },
      { accountId: seedAccountId(2), amount: available, kind: "test_transfer",
        actor: customer, refType: "test", refId: "drain" },
    ]);
    now = new Date("2026-12-16T12:00:00Z");
    assert.equal(bank.availableBalance(account), 0);
    const result = loans.renegotiate(customer, previous.id, undefined,
      { method: "SAC", term_months: 6 });
    assert.equal(result.previous.status, "refinanced");
    assert.equal(result.next.status, "active");
    assert.equal(result.next.principal_cents - result.next.fee_cents,
      result.payoff_cents);
    assert.equal(result.financed_fee_cents, result.next.fee_cents);
    assert.equal(loans.contract(customer, previous.id).installments[0].status, "paid");
    assert.ok(loans.contract(customer, previous.id).installments.slice(1)
      .every((item) => item.status === "prepaid"));
    assert.equal(loans.contract(customer, result.next.id).contract.term_months, 6);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM loan_renegotiations").get().n, 1);
    assert.equal(JSON.stringify(loans.renegotiate(customer, previous.id, undefined,
      { method: "SAC", term_months: 6 })), JSON.stringify(result));
    assert.throws(() => loans.renegotiate(customer, previous.id),
      /BIZ_IDEMPOTENCY_CONFLICT/);
    now = new Date("2026-12-17T06:00:00Z");
    bank.periodClose();
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("renegotiation payoff includes the balance after a partial installment", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-partial-renegotiate-"));
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const loans = new LoansEngine(bank);
    const customer = seedCustomerId(1), offer = loans.offer(customer);
    const previous = loans.accept(customer, offer.id, seedAccountId(1),
      40_000, undefined, undefined, { method: "SAC", term_months: 2 });
    now = new Date("2026-12-16T12:00:00Z");
    loans.payInstallmentAmount(customer, previous.id, 1, 5_000);
    const terms = { method: "PRICE", term_months: 6 };
    const quote = loans.renegotiationQuote(customer, previous.id, terms);
    const result = loans.renegotiate(customer, previous.id, undefined, terms);
    assert.equal(result.payoff_cents, quote.payoff_cents);
    assert.equal(result.next.principal_cents, quote.new_principal_cents);
    assert.equal(loans.contract(customer, previous.id).installments[0].status, "paid");
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("renegotiation route requires a fresh device proof and reconciles after restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-loan-renegotiate-api-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(path, () => now);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const loans = new LoansEngine(bank);
  const customer = seedCustomerId(1);
  const offer = loans.offer(customer);
  const loan = loans.accept(customer, offer.id, seedAccountId(1), 40_000,
    undefined, undefined, { method: "PRICE", term_months: 2 });
  const auth = new AuthEngine(bank);
  auth.setPassword(customer, "renegotiation-password");
  const app = createTwinApi(bank, auth);
  try {
    now = new Date("2026-12-16T12:00:00Z");
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "renegotiation-password", "127.0.0.1", "renegotiation-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    const headers = { authorization: `Bearer ${session.access_token}` };
    auth.stepUp(session.access_token, "renegotiation-password");
    const privateKey = await bindDeviceKey(app, headers);
    const listedBefore = await app.inject({ method: "GET", url: "/loans", headers });
    assert.equal(listedBefore.statusCode, 200);
    assert.deepEqual(listedBefore.json().map((item) => item.id), [loan.id]);
    const route = `/loans/${loan.id}/renegotiate`;
    const body = { method: "PRICE", term_months: 6 };
    const preview = await app.inject({ method: "POST",
      url: `/loans/${loan.id}/renegotiation-quote`, headers, payload: body });
    assert.equal(preview.statusCode, 200, preview.body);
    assert.ok(preview.json().payoff_cents > 0);
    assert.equal(preview.json().installments.length, 6);
    assert.equal(gatewayRouteTemplate(`/api/v1${route}`),
      "/api/v1/loans/:id/renegotiate");
    assert.equal((await app.inject({ method: "POST", url: route,
      headers, payload: body })).statusCode, 403);
    const signedHeaders = await signedOperationHeaders(app, headers, privateKey,
      route, body);
    const response = await app.inject({ method: "POST", url: route,
      headers: signedHeaders, payload: body });
    assert.equal(response.statusCode, 200, response.body);
    assert.equal(response.json().previous.status, "refinanced");
    assert.equal(response.json().payoff_cents, preview.json().payoff_cents);
    const listedAfter = await app.inject({ method: "GET", url: "/loans", headers });
    assert.equal(listedAfter.statusCode, 200);
    assert.deepEqual(new Set(listedAfter.json().map((item) => item.id)),
      new Set([loan.id, response.json().next.id]));
    assert.equal((await app.inject({ method: "POST", url: route,
      headers: signedHeaders, payload: body })).statusCode, 403);
    assert.equal(bank.reconcile().ok, true);
  } finally { await app.close(); bank.close(); }
  const reopened = new Bank(path, () => now);
  try {
    assert.equal(reopened.reconcile().ok, true);
    assert.equal(reopened.db.prepare("SELECT COUNT(*) n FROM loan_renegotiations")
      .get().n, 1);
  } finally { reopened.close(); rmSync(dir, { recursive: true, force: true }); }
});
