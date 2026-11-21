import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AccountService } from "../apps/world/src/accounts.ts";
import { AccountLifecycle } from "../apps/world/src/account-lifecycle.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { Bank } from "../apps/world/src/bank.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { Gateway } from "../apps/world/src/gateway.ts";
import { syntheticCnpj } from "../apps/world/src/business-document.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";

function fixture(work) {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-salary-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-18T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 10, accounts: 10, historyTransactions: 0 });
    return work(bank, new AccountService(bank));
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
}

test("prepaid payment account can spend only its funded balance", () => fixture((bank, accounts) => {
  const owner = seedCustomerId(1);
  const payment = accounts.openPayment(owner);
  assert.equal(payment.kind, "payment");
  assert.equal(payment.overdraft_limit, 0);
  assert.equal(bank.availableBalance(payment.id), 0);
  assert.throws(() => bank.transferPix({ from: payment.id, to: seedAccountId(2),
    amount: 1, actor: owner, idempotencyKey: "prepaid-empty" }),
  /BIZ_INSUFFICIENT_FUNDS/);
  bank.fund(payment.id, 1_000);
  const cards = new CardsEngine(bank);
  const card = cards.issueDebit(owner, payment.id, 1_000);
  cards.authorize(card.id, "merchant-test", 100);
  assert.equal(bank.account(payment.id).balance_cached, 900);
  bank.transferPix({ from: payment.id, to: seedAccountId(2),
    amount: 700, actor: owner, idempotencyKey: "prepaid-funded" });
  assert.equal(bank.account(payment.id).balance_cached, 200);
  assert.throws(() => bank.transferPix({ from: payment.id, to: seedAccountId(2),
    amount: 201, actor: owner, idempotencyKey: "prepaid-over" }),
  /BIZ_INSUFFICIENT_FUNDS/);
  assert.equal(bank.reconcile().ok, true);
}));

test("employer opens salary account, pays once, and employee ports only to own account", () => fixture(
  (bank, accounts) => {
    const employerAccount = bank.db.prepare(`SELECT a.id,a.customer_id
      FROM accounts a JOIN business_account_identity b ON b.account_id=a.id
      WHERE a.kind='merchant' AND a.customer_id<>? LIMIT 1`)
      .get(seedCustomerId(1));
    assert.ok(employerAccount);
    const employee = seedCustomerId(1);
    const salary = accounts.openSalary(employerAccount.customer_id,
      employerAccount.id, employee);
    assert.equal(salary.kind, "salary");
    assert.equal(accounts.salaryEmployer(salary.id).employer_account_id,
      employerAccount.id);
    assert.throws(() => bank.registerPixKey(employee, salary.id,
      "salary@example.test"), /DEF_SALARY_ACCOUNT_RESTRICTED/);
    assert.throws(() => new CardsEngine(bank).issueDebit(employee, salary.id),
      /BIZ_CARD_ACCOUNT_INVALID/);
    assert.throws(() => bank.fund(salary.id, 100), /DEF_SALARY_ACCOUNT_RESTRICTED/);
    assert.throws(() => bank.post([
      { accountId: bank.systemAccountId("cash_in"), amount: -100,
        kind: "funding", actor: "seed", refType: "funding", refId: "invalid" },
      { accountId: salary.id, amount: 100,
        kind: "funding", actor: "seed", refType: "funding", refId: "invalid" },
    ]), /DEF_SALARY_ACCOUNT_RESTRICTED/);
    assert.throws(() => bank.transferPix({ from: seedAccountId(2),
      to: salary.id, amount: 100, actor: seedCustomerId(2),
      idempotencyKey: "salary-outsider" }), /DEF_SALARY_ACCOUNT_RESTRICTED/);
    assert.throws(() => accounts.paySalary(seedCustomerId(2), seedAccountId(2),
      salary.id, 100, "wrong-employer"), /DEF_SALARY_EMPLOYER_REQUIRED/);
    const paid = accounts.paySalary(employerAccount.customer_id,
      employerAccount.id, salary.id, 5_000, "payroll-1");
    assert.deepEqual(accounts.paySalary(employerAccount.customer_id,
      employerAccount.id, salary.id, 5_000, "payroll-1"), paid);
    assert.throws(() => accounts.paySalary(employee, employerAccount.id,
      salary.id, 5_000, "payroll-1"), /DEF_NOT_FOUND/);
    assert.throws(() => accounts.paySalary(employerAccount.customer_id,
      employerAccount.id, salary.id, 5_001, "payroll-1"),
    /BIZ_IDEMPOTENCY_CONFLICT/);
    assert.equal(bank.account(salary.id).balance_cached, 5_000);
    assert.throws(() => bank.transferPix({ from: salary.id,
      to: seedAccountId(2), amount: 100, actor: employee,
      idempotencyKey: "salary-external" }), /DEF_SALARY_ACCOUNT_RESTRICTED/);
    assert.throws(() => accounts.portSalary(employee, salary.id,
      seedAccountId(2), 100, "wrong-destination"), /DEF_NOT_FOUND/);
    const port = accounts.portSalary(employee, salary.id,
      seedAccountId(1), 4_000, "port-1");
    assert.deepEqual(accounts.portSalary(employee, salary.id,
      seedAccountId(1), 4_000, "port-1"), port);
    assert.throws(() => accounts.portSalary(seedCustomerId(2), salary.id,
      seedAccountId(1), 4_000, "port-1"), /DEF_NOT_FOUND/);
    assert.equal(bank.account(salary.id).balance_cached, 1_000);
    assert.throws(() => accounts.portSalary(employee, salary.id,
      seedAccountId(1), 1_001, "port-over"), /BIZ_INSUFFICIENT_FUNDS/);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM salary_payments`).get().n, 1);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM salary_portabilities`).get().n, 1);
    assert.throws(() => bank.db.prepare(`DELETE FROM salary_payments`).run(),
      /SALARY_PAYMENT_IMMUTABLE/);
    assert.throws(() => new AccountLifecycle(bank).transition(employerAccount.id,
      "closed", "reviewer"), /BIZ_ACCOUNT_CLOSE_BALANCE/);
  }));

test("active salary binding keeps employer account open until employee closes it", () => fixture(
  (bank, accounts) => {
    const employerCustomer = seedCustomerId(1);
    const employeeCustomer = seedCustomerId(2);
    const business = accounts.openBusiness(employerCustomer,
      syntheticCnpj(80_000), "Payroll Ltda", "reviewer").account;
    const salary = accounts.openSalary(employerCustomer, business.id,
      employeeCustomer);
    const lifecycle = new AccountLifecycle(bank);
    accounts.setSalaryPortabilityInstruction(employeeCustomer, salary.id,
      seedAccountId(2));
    assert.throws(() => lifecycle.transition(salary.id, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_PENDING/);
    accounts.setSalaryPortabilityInstruction(employeeCustomer, salary.id, null);
    assert.throws(() => lifecycle.transition(business.id, "closed", "reviewer"),
      /BIZ_ACCOUNT_CLOSE_PENDING/);
    assert.equal(lifecycle.transition(salary.id, "closed", "reviewer").status,
      "closed");
    assert.equal(lifecycle.transition(business.id, "closed", "reviewer").status,
      "closed");
  }));

test("standing salary portability moves each payroll atomically and can be cancelled", () => fixture(
  (bank, accounts) => {
    const employer = bank.db.prepare(`SELECT a.id,a.customer_id FROM accounts a
      JOIN business_account_identity b ON b.account_id=a.id
      WHERE a.kind='merchant' AND a.customer_id<>? LIMIT 1`)
      .get(seedCustomerId(1));
    assert.ok(employer);
    const employee = seedCustomerId(1);
    const destination = seedAccountId(1);
    const salary = accounts.openSalary(employer.customer_id, employer.id, employee);
    assert.equal(accounts.salaryPortabilityInstruction(employee, salary.id), null);
    assert.throws(() => accounts.portSalary(employee, salary.id, destination,
      1, "salary_auto_reserved"), /BIZ_SALARY_PORTABILITY_INVALID/);
    const instruction = accounts.setSalaryPortabilityInstruction(employee,
      salary.id, destination);
    assert.equal(instruction.destination_account_id, destination);
    assert.throws(() => bank.db.prepare(`UPDATE salary_portability_instructions
      SET destination_account_id=? WHERE account_id=?`)
      .run(seedAccountId(2), salary.id), /SALARY_INSTRUCTION_INVALID/);
    assert.throws(() => bank.db.prepare(`DELETE FROM salary_portability_instructions
      WHERE account_id=?`).run(salary.id), /SALARY_INSTRUCTION_IMMUTABLE/);
    assert.deepEqual(accounts.setSalaryPortabilityInstruction(employee,
      salary.id, destination), instruction);
    assert.throws(() => accounts.setSalaryPortabilityInstruction(seedCustomerId(2),
      salary.id, destination), /DEF_NOT_FOUND/);
    const before = bank.account(destination).balance_cached;
    bank.fund(employer.id, 8_000);
    const first = accounts.paySalary(employer.customer_id, employer.id,
      salary.id, 3_000, "standing-payroll-1");
    assert.deepEqual(accounts.paySalary(employer.customer_id, employer.id,
      salary.id, 3_000, "standing-payroll-1"), first);
    assert.equal(bank.account(salary.id).balance_cached, 0);
    assert.equal(bank.account(destination).balance_cached, before + 3_000);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM salary_portabilities
      WHERE salary_account_id=?`).get(salary.id).n, 1);
    bank.changeAccountStatus(destination, "frozen", "reviewer", "fraud_suspect");
    accounts.paySalary(employer.customer_id, employer.id,
      salary.id, 2_000, "standing-payroll-2");
    assert.equal(bank.account(salary.id).balance_cached, 2_000);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM salary_portabilities
      WHERE salary_account_id=?`).get(salary.id).n, 1);
    bank.changeAccountStatus(destination, "active", "reviewer");
    accounts.paySalary(employer.customer_id, employer.id,
      salary.id, 500, "standing-payroll-3");
    assert.equal(bank.account(salary.id).balance_cached, 0);
    assert.equal(bank.account(destination).balance_cached, before + 5_500);
    accounts.setSalaryPortabilityInstruction(employee, salary.id, null);
    accounts.paySalary(employer.customer_id, employer.id,
      salary.id, 1_000, "standing-payroll-4");
    assert.equal(bank.account(salary.id).balance_cached, 1_000);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM
      salary_portability_instruction_events WHERE account_id=?`)
      .get(salary.id).n, 2);
    assert.throws(() => bank.db.prepare(`DELETE FROM
      salary_portability_instruction_events WHERE account_id=?`).run(salary.id),
    /SALARY_INSTRUCTION_IMMUTABLE/);
    assert.equal(bank.reconcile().ok, true);
  }));

test("standing salary portability survives a bank restart", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-salary-restart-"));
  const path = join(dir, "bank.sqlite");
  const now = () => new Date("2026-11-18T12:00:00.000Z");
  let bank = new Bank(path, now);
  try {
    seedBank(bank, { customers: 3, accounts: 3, historyTransactions: 0 });
    const employee = seedCustomerId(1);
    const employerCustomer = seedCustomerId(2);
    const accounts = new AccountService(bank);
    const employer = accounts.openBusiness(employerCustomer,
      syntheticCnpj(80_002), "Restart Payroll Ltda", "reviewer").account;
    const salary = accounts.openSalary(employerCustomer, employer.id, employee);
    accounts.setSalaryPortabilityInstruction(employee, salary.id, seedAccountId(1));
    bank.fund(employer.id, 2_000);
    bank.close();
    bank = new Bank(path, now);
    const reopened = new AccountService(bank);
    const before = bank.account(seedAccountId(1)).balance_cached;
    reopened.paySalary(employerCustomer, employer.id, salary.id, 1_000,
      "restart-payroll");
    assert.equal(bank.account(salary.id).balance_cached, 0);
    assert.equal(bank.account(seedAccountId(1)).balance_cached, before + 1_000);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("signed customer routes open payment account and port salary with owner isolation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-salary-api-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-18T12:00:00.000Z"));
  seedBank(bank, { customers: 3, accounts: 3, historyTransactions: 0 });
  const accounts = new AccountService(bank);
  const employer = seedCustomerId(1);
  const employee = seedCustomerId(2);
  const paymentCustomer = seedCustomerId(3);
  const business = accounts.openBusiness(employer,
    syntheticCnpj(80_001), "Customer Payroll Ltda", "reviewer").account;
  const salary = accounts.openSalary(employer, business.id, employee);
  bank.fund(business.id, 2_000);
  accounts.paySalary(employer, business.id, salary.id, 1_000, "api-payroll");
  const auth = new AuthEngine(bank);
  for (const customer of [employee, paymentCustomer])
    auth.setPassword(customer, "customer-password-123");
  const app = createTwinApi(bank, auth);
  const gateway = new Gateway(bank, app);
  try {
    async function session(customer) {
      const login = await app.inject({ method: "POST", url: "/auth/login", payload: {
        cpf: bank.customer(customer).cpf, password: "customer-password-123",
        device_id: `device-${customer}` } });
      assert.equal(login.statusCode, 200);
      const challengeId = login.json().challenge_id;
      const otp = await app.inject({ method: "POST", url: "/auth/otp/verify", payload: {
        challenge_id: challengeId, otp: auth.simulatedOtp(challengeId, customer) } });
      assert.equal(otp.statusCode, 200);
      const headers = { authorization: `Bearer ${otp.json().access_token}` };
      const stepUp = await app.inject({ method: "POST", url: "/auth/step-up", headers,
        payload: { password: "customer-password-123" } });
      assert.equal(stepUp.statusCode, 200);
      return { headers, privateKey: await bindDeviceKey(app, headers) };
    }
    const paymentSession = await session(paymentCustomer);
    const paymentPath = "/accounts/payment";
    const paymentHeaders = await signedOperationHeaders(app,
      paymentSession.headers, paymentSession.privateKey, paymentPath);
    const opened = await gateway.call({ method: "POST", path: `/api/v1${paymentPath}`,
      headers: paymentHeaders, peerIp: "127.0.0.1" });
    assert.equal(opened.status, 200);
    assert.equal(opened.body.kind, "payment");
    const employeeSession = await session(employee);
    const salaryPath = `/accounts/${salary.id}/salary-port`;
    const body = { destination_account_id: seedAccountId(2),
      amount_cents: 600, idempotency_key: "api-port" };
    const salaryHeaders = await signedOperationHeaders(app,
      employeeSession.headers, employeeSession.privateKey, salaryPath, body);
    const port = await gateway.call({ method: "POST", path: `/api/v1${salaryPath}`,
      headers: salaryHeaders, body, peerIp: "127.0.0.1" });
    assert.equal(port.status, 200);
    assert.equal(bank.account(salary.id).balance_cached, 400);
    const outsiderHeaders = await signedOperationHeaders(app,
      paymentSession.headers, paymentSession.privateKey, salaryPath, body);
    const outsider = await gateway.call({ method: "POST", path: `/api/v1${salaryPath}`,
      headers: outsiderHeaders, body, peerIp: "127.0.0.1" });
    assert.equal(outsider.body.error, "DEF_NOT_FOUND");
    const instructionPath = `/accounts/${salary.id}/salary-portability`;
    const instructionBody = { destination_account_id: seedAccountId(2) };
    const unsigned = await gateway.call({ method: "POST",
      path: `/api/v1${instructionPath}`, headers: employeeSession.headers,
      body: instructionBody, peerIp: "127.0.0.1" });
    assert.equal(unsigned.status, 403);
    const instructionHeaders = await signedOperationHeaders(app,
      employeeSession.headers, employeeSession.privateKey,
      instructionPath, instructionBody);
    const instruction = await gateway.call({ method: "POST",
      path: `/api/v1${instructionPath}`, headers: instructionHeaders,
      body: instructionBody, peerIp: "127.0.0.1" });
    assert.equal(instruction.status, 200);
    assert.equal(instruction.body.destination_account_id, seedAccountId(2));
    const readInstruction = await gateway.call({ method: "GET",
      path: `/api/v1${instructionPath}`, headers: employeeSession.headers,
      peerIp: "127.0.0.1" });
    assert.equal(readInstruction.body.destination_account_id, seedAccountId(2));
    const outsiderRead = await gateway.call({ method: "GET",
      path: `/api/v1${instructionPath}`, headers: paymentSession.headers,
      peerIp: "127.0.0.1" });
    assert.equal(outsiderRead.body.error, "DEF_NOT_FOUND");
    const before = bank.account(seedAccountId(2)).balance_cached;
    accounts.paySalary(employer, business.id, salary.id, 500, "api-payroll-2");
    assert.equal(bank.account(salary.id).balance_cached, 0);
    assert.equal(bank.account(seedAccountId(2)).balance_cached, before + 900);
    assert.equal(bank.reconcile().ok, true);
  } finally { await app.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
