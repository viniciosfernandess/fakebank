import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { AccountService } from "../apps/world/src/accounts.ts";
import { LoansEngine } from "../apps/world/src/loans.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from
  "../apps/world/src/credit-cards.ts";
import { CampaignRuntime } from "../apps/orchestrator/src/campaign-runtime.ts";
import { EventStore } from "../packages/event-store/src/index.ts";
import { exportSplitSnapshots } from "./export-ecosystem-snapshot.mjs";
import { verifySplitSnapshots } from "./verify-split-snapshot.mjs";
import { SourceHealthWatchdog } from "./source-health-watchdog.mjs";

const smoke = process.env.SEPARATED_DAY_SMOKE === "1";
const diagnostic = process.env.SEPARATED_DAY_DIAGNOSTIC === "1";
const canaries = process.env.SEPARATED_DAY_CANARIES === "1";
const watchdogEnabled = process.env.SEPARATED_DAY_WATCHDOG === "1";
const ticks = smoke ? 12 : 720;
const root = mkdtempSync(join(tmpdir(), "banco-vivo-separated-day-"));
const sourcePath = join(root, "combined.sqlite");
const bankPath = join(root, "bank.sqlite");
const ecosystemPath = join(root, "ecosystem.sqlite");
const realStart = Date.parse("2026-11-11T12:00:00.000Z");
let realMs = realStart;
let source;
let runtime;
let events;
let watchdog;
try {
  source = new Bank(sourcePath, () => new Date(realStart), () => new Date(realStart));
  seedBank(source, { customers: smoke ? 100 : 12_000,
    accounts: smoke ? 120 : 14_500,
    historyTransactions: smoke || diagnostic ? 0 : 400_000,
    openWeaknesses: false });
  source.close();
  source = undefined;
  exportSplitSnapshots(sourcePath, bankPath, ecosystemPath);
  events = new EventStore(join(root, "events.sqlite"));
  runtime = await CampaignRuntime.openSeparated({ dataDir: root, events,
    startBrtDate: "2026-11-11", onDemand: true,
    plantCanaries: canaries,
    realNow: () => new Date(realMs) });
  if (watchdogEnabled) watchdog = new SourceHealthWatchdog(root, () => realMs);
  const bank = runtime.bank;
  const auth = runtime.auth;
  const accounts = new AccountService(bank);
  const salaryEmployee = bank.db.prepare(`SELECT a.customer_id,a.id account_id
    FROM accounts a JOIN customers c ON c.id=a.customer_id
    WHERE a.status='active' AND a.kind='checking' AND c.kyc_tier>=1
      AND (SELECT COUNT(*) FROM accounts own WHERE own.customer_id=a.customer_id
        AND own.status<>'closed')=1 ORDER BY a.id LIMIT 1`).get();
  const salaryEmployer = bank.db.prepare(`SELECT a.id,a.customer_id
    FROM accounts a JOIN business_account_identity b ON b.account_id=a.id
    WHERE a.kind='merchant' AND a.status='active' AND a.customer_id<>?
    ORDER BY a.id LIMIT 1`).get(salaryEmployee?.customer_id);
  assert.ok(salaryEmployee && salaryEmployer);
  const salaryAccount = accounts.openSalary(salaryEmployer.customer_id,
    salaryEmployer.id, salaryEmployee.customer_id);
  accounts.setSalaryPortabilityInstruction(salaryEmployee.customer_id,
    salaryAccount.id, salaryEmployee.account_id);
  bank.fund(salaryEmployer.id, 2_000);
  const salaryBefore = bank.account(salaryEmployee.account_id).balance_cached;
  accounts.paySalary(salaryEmployer.customer_id, salaryEmployer.id,
    salaryAccount.id, 1_000, "separated-day-payroll");
  assert.equal(bank.account(salaryAccount.id).balance_cached, 0);
  assert.equal(bank.account(salaryEmployee.account_id).balance_cached, salaryBefore + 1_000);
  const loans = new LoansEngine(bank);
  const loanCustomer = seedCustomerId(3);
  const loanOffer = loans.offer(loanCustomer);
  const loan = loans.accept(loanCustomer, loanOffer.id, seedAccountId(3), 5_000,
    undefined, undefined, { method: "SAC", term_months: 6 });
  const recurringCustomer = seedCustomerId(1);
  const recurringPassword = `synthetic-${recurringCustomer}-simulator-secret`;
  auth.setPassword(recurringCustomer, recurringPassword);
  const login = auth.beginLogin(bank.customer(recurringCustomer).cpf,
    recurringPassword, "127.0.0.1", "day-gate-recurring-device");
  const session = auth.verifyOtp(login.challenge_id,
    auth.simulatedOtp(login.challenge_id, recurringCustomer), "127.0.0.1");
  auth.stepUp(session.access_token, recurringPassword);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const enrollment = auth.issueDeviceEnrollmentChallenge(session.access_token);
  const device = auth.enrolCurrentDeviceKey(session.access_token,
    enrollment.challenge_id,
    publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
    sign(null, Buffer.from(enrollment.message), privateKey).toString("base64url"));
  const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
  const cards = new CardsEngine(bank);
  const creditAccount = credit.open(recurringCustomer, 30_000, 15);
  const card = cards.issueCredit(recurringCustomer, seedAccountId(1), creditAccount.id);
  const mandate = runtime.cardRecurring.create(recurringCustomer, device.device_id, {
    cardId: card.id, merchantId: "shop_ipe", amountCents: 1_000,
    frequency: "weekly", startsAt: bank.now().toISOString(),
    idempotencyKey: "separated-day-card-recurrence" });
  let operations = 0;
  let wronglyBlocked = 0;
  let pixOperations = 0;
  let pixDeferred = 0;
  const started = performance.now();
  for (let tick = 0; tick < ticks; tick++) {
    await runtime.cycle();
    const minute = new Date(Math.floor(realMs / 10_000) * 10_000).toISOString();
    const row = bank.db.prepare(`SELECT ops,honest_blocked,by_area_json FROM sim_ticks
      WHERE minute=?`).get(minute);
    assert.ok(row, `Missing simulator tick ${tick}`);
    operations += row.ops;
    wronglyBlocked += row.honest_blocked;
    pixOperations += JSON.parse(row.by_area_json).pix ?? 0;
    pixDeferred += bank.db.prepare(`SELECT COUNT(*) n FROM sim_deferred_pix
      WHERE minute=?`).get(minute).n;
    realMs += 3_000;
    await runtime.dispatchPendingPix();
    await runtime.scanTelemetryStream();
    if (watchdog) {
      watchdog.tick();
      await runtime.scanSentinels();
    }
    realMs += 7_000;
    if ((tick + 1) % 60 === 0)
      process.stderr.write(`Separated day: ${tick + 1}/${ticks} ticks, ${operations} operations\n`);
  }
  await runtime.dispatchPendingPix();
  await runtime.scanTelemetryStream();
  if (watchdog) {
    watchdog.tick();
    await runtime.scanSentinels();
  }
  runtime.hourlyLedgerProofs.publishCompleted();
  const hourlyProofs = runtime.hourlyLedgerProofs.verify();
  assert.equal(hourlyProofs, smoke ? 0 : 24);
  const finalClearing = runtime.cardNetwork.clearDue();
  const loanPayoff = loans.prepay(loanCustomer, loan.id);
  assert.equal(loanPayoff.loan.status, "prepaid");
  assert.ok(loans.contract(loanCustomer, loan.id).installments.every((item) =>
    item.status === "prepaid"));
  const split = verifySplitSnapshots(bankPath, ecosystemPath);
  const alerts = bank.db.prepare("SELECT COUNT(*) n FROM sentinel_alerts").get().n;
  const alertDetails = bank.db.prepare(`SELECT rule_id,entity,observed_json,
    first_seen,last_seen FROM sentinel_alerts ORDER BY first_seen`).all();
  const externalPix = split.external_transfers;
  const cardCharges = runtime.cardRecurring.charges(recurringCustomer, mandate.id);
  const clearedCards = bank.db.prepare(`SELECT COUNT(*) n FROM card_clearing_items
    WHERE authorization_id=? AND status='cleared'`)
    .get(cardCharges[0]?.result_id ?? "").n;
  const bankIntegrity = bank.reconcile();
  const cardIntegrity = bank.reconcileCardSettlement();
  const creditIntegrity = credit.reconcileAll();
  assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM salary_payments
    WHERE salary_account_id=?`).get(salaryAccount.id).n, 1);
  assert.equal(bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) cents
    FROM salary_portabilities WHERE salary_account_id=?`)
    .get(salaryAccount.id).cents, 1_000);
  assert.equal(wronglyBlocked, 0);
  assert.equal(alerts, 0, JSON.stringify(alertDetails));
  assert.ok(operations >= (smoke ? 1 : 40_000), `Too few operations: ${operations}`);
  assert.ok(externalPix >= (smoke ? 0 : 1_000), `Too few external Pix: ${externalPix}`);
  assert.equal(pixDeferred, bank.db.prepare("SELECT COUNT(*) n FROM sim_deferred_pix").get().n);
  assert.equal(split.ok, true, JSON.stringify(split));
  assert.equal(bankIntegrity.ok, true, JSON.stringify(bankIntegrity));
  assert.equal(cardIntegrity.ok, true, JSON.stringify(cardIntegrity));
  assert.equal(creditIntegrity.ok, true, JSON.stringify(creditIntegrity));
  assert.equal(cardCharges.length, 1);
  assert.equal(cardCharges[0].status, "approved");
  assert.equal(clearedCards, smoke ? 0 : 1);
  assert.equal(finalClearing.failed, 0);
  assert.equal(finalClearing.expired, 0);
  assert.ok(finalClearing.cleared >= (smoke ? 0 : 1));
  assert.equal(credit.outstanding(recurringCustomer, creditAccount.id),
    smoke ? 0 : 1_000);
  process.stdout.write(JSON.stringify({ smoke, diagnostic, canaries,
    watchdogEnabled, ticks, hourlyProofs,
    operations, wronglyBlocked,
    alerts, pixOperations, pixDeferred, externalPix, cardCharges: cardCharges.length,
    clearedCards, finalClearing, split, bankIntegrity, cardIntegrity, creditIntegrity,
    elapsedSeconds: Math.round((performance.now() - started) / 1000) }) + "\n");
} finally {
  watchdog?.close();
  await runtime?.close();
  events?.close();
  source?.close();
  rmSync(root, { recursive: true, force: true });
}
