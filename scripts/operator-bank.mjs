import { closeSync, constants, existsSync, fstatSync, openSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { Bank } from "../apps/world/src/bank.ts";
import { AccountLifecycle } from "../apps/world/src/account-lifecycle.ts";
import { AccountService } from "../apps/world/src/accounts.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { OnboardingService } from "../apps/world/src/onboarding.ts";
import { JudicialOrders } from "../apps/world/src/judicial-orders.ts";
import { OperatorAuth } from "../apps/world/src/operator-auth.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "../apps/world/src/credit-cards.ts";
import { CardNetwork } from "../apps/world/src/ecosystem/card-network.ts";
import { PspNoticeAccess } from "../apps/world/src/ecosystem/psp-notice-access.ts";
import { EcosystemClient } from "../apps/ecosystem/src/client.ts";
import { SeparatedPixCoordinator } from "../apps/world/src/separated-pix-coordinator.ts";
import { EventStore } from "../packages/event-store/src/index.ts";

const usage = `Usage: pnpm operator <command>
  bootstrap <admin-id>
  enroll <new-id> <admin|maker|reviewer> <admin-id>
  change-password <operator-id>
  disable <target-id> <admin-id>
  account <account-id>
  account-status <account-id> <active|frozen|closed> <reason|-> <operator-id>
  onboarding-apply <private-json-file> <maker-id>
  onboarding-pending [cursor]
  onboarding-status <customer-id>
  onboarding-liveness <customer-id> <pass|fail> <maker-id>
  onboarding-review <customer-id> <approve|reject> <reviewer-id>
  kyc-pending [cursor]
  kyc-approve <customer-id> <requested-tier> <submitted-at> <reviewer-id>
  business-open <customer-id> <private-json-file> <reviewer-id>
  business-verify <customer-id> <account-id> <private-json-file> <reviewer-id>
  business-status <account-id>
  payment-open <customer-id> <admin-id>
  salary-open <employer-customer-id> <employer-account-id> <employee-customer-id> <admin-id>
  salary-pay <employer-customer-id> <employer-account-id> <salary-account-id> <amount-cents> <idempotency-key> <admin-id>
  salary-port <employee-customer-id> <salary-account-id> <destination-account-id> <amount-cents> <idempotency-key> <admin-id>
  salary-status <account-id>
  judicial-request <account-id> <amount-cents> <case-reference> <maker-id>
  judicial-review <order-id> <approve|reject> <checker-id>
  judicial-release <order-id> <maker-id>
  judicial-release-review <order-id> <approve|reject> <checker-id>
  judicial-order <order-id>
  credit-open <customer-id> <deposit-account-id> <limit-cents> <closing-day> <admin-id>
  credit-close <customer-id> <credit-id> <operator-id>
  risk-profile <customer-id>
  set-risk-profile <customer-id> <low|medium|high> <verified-income-cents> <admin-id>
  risk-promote <pix|cards> <rule-id> <from-iso> <to-iso> <admin-id>
  risk-disable <pix|cards> <rule-id> <admin-id>
  risk-emergency <pix|cards> <rule-id> <evidence-json-file> <admin-id>
  holds [cursor]
  review-hold <hold-id> <approve|reject> <reviewer-id>
  cautelar-holds [cursor]
  review-cautelar <hold-id> <release|return> <reviewer-id>
  psp-notice-provision <identity-id> <psp-account-id> <spki-public-key-file> <admin-id>
  psp-notice-revoke <identity-id> <admin-id>
  psp-notice-reprovision <identity-id> <new-spki-public-key-file> <admin-id>
  spi-status
  spi-history [cursor]
  spi-availability <online|offline> <admin-id>
  card-issuer-status
  card-issuer-history [cursor]
  card-issuer-availability <online|offline> <admin-id>
  manual-pending [cursor]
  manual-request <json-file>
  manual-review <request-id> <approve|reject> <checker-id>
Set OPERATOR_ID for list commands. Passwords are read from the terminal or stdin, never arguments.`;
const [command, ...args] = process.argv.slice(2);
const valid = command === "bootstrap" && args.length === 1 ||
  command === "enroll" && args.length === 3 ||
  command === "change-password" && args.length === 1 ||
  command === "disable" && args.length === 2 ||
  command === "account" && args.length === 1 ||
  command === "account-status" && args.length === 4 ||
  command === "onboarding-apply" && args.length === 2 ||
  command === "onboarding-pending" && args.length <= 1 ||
  command === "onboarding-status" && args.length === 1 ||
  command === "onboarding-liveness" && args.length === 3 &&
    ["pass", "fail"].includes(args[1]) ||
  command === "onboarding-review" && args.length === 3 &&
    ["approve", "reject"].includes(args[1]) ||
  command === "kyc-pending" && args.length <= 1 ||
  command === "kyc-approve" && args.length === 4 && ["2", "3"].includes(args[1]) ||
  command === "business-open" && args.length === 3 ||
  command === "business-verify" && args.length === 4 ||
  command === "business-status" && args.length === 1 ||
  command === "payment-open" && args.length === 2 ||
  command === "salary-open" && args.length === 4 ||
  command === "salary-pay" && args.length === 6 ||
  command === "salary-port" && args.length === 6 ||
  command === "salary-status" && args.length === 1 ||
  command === "judicial-request" && args.length === 4 ||
  command === "judicial-review" && args.length === 3 ||
  command === "judicial-release" && args.length === 2 ||
  command === "judicial-release-review" && args.length === 3 ||
  command === "judicial-order" && args.length === 1 ||
  command === "credit-open" && args.length === 5 ||
  command === "credit-close" && args.length === 3 ||
  command === "risk-profile" && args.length === 1 ||
  command === "set-risk-profile" && args.length === 4 ||
  command === "risk-promote" && args.length === 5 ||
  command === "risk-disable" && args.length === 3 ||
  command === "risk-emergency" && args.length === 4 ||
  command === "holds" && args.length <= 1 ||
  command === "review-hold" && args.length === 3 ||
  command === "cautelar-holds" && args.length <= 1 ||
  command === "review-cautelar" && args.length === 3 &&
    ["release", "return"].includes(args[1]) ||
  command === "psp-notice-provision" && args.length === 4 ||
  command === "psp-notice-revoke" && args.length === 2 ||
  command === "psp-notice-reprovision" && args.length === 3 ||
  command === "spi-status" && args.length === 0 ||
  command === "spi-history" && args.length <= 1 ||
  command === "spi-availability" && args.length === 2 &&
    ["online", "offline"].includes(args[0]) ||
  command === "card-issuer-status" && args.length === 0 ||
  command === "card-issuer-history" && args.length <= 1 ||
  command === "card-issuer-availability" && args.length === 2 &&
    ["online", "offline"].includes(args[0]) ||
  command === "manual-pending" && args.length <= 1 ||
  command === "manual-request" && args.length === 1 ||
  command === "manual-review" && args.length === 3;
if (!valid) {
  console.error(usage);
  process.exit(1);
}

const dataDir = resolve(process.env.DATA_DIR ?? "data");
const bankPath = join(dataDir, "bank.sqlite");
if (!existsSync(bankPath)) {
  console.error(`Bank database not found: ${bankPath}`);
  process.exit(1);
}
function cursor(value) {
  if (value === undefined) return 0;
  if (!/^(?:0|[1-9]\d*)$/.test(value) || !Number.isSafeInteger(Number(value)))
    throw new Error("OPERATOR_CURSOR_INVALID");
  return Number(value);
}
function page(rows, map = (row) => row) {
  const visible = rows.slice(0, 100);
  return { items: visible.map(({ row_cursor, ...row }) => map(row)),
    next_cursor: rows.length > 100 ? visible.at(-1).row_cursor : null };
}
async function readPasswords(count, labels = []) {
  if (!process.stdin.isTTY) {
    let input = "";
    for await (const chunk of process.stdin) {
      input += chunk;
      if (input.length > 1024) throw new Error("OPERATOR_PASSWORD_INPUT_TOO_LARGE");
    }
    const lines = input.replace(/\r\n/g, "\n").split("\n");
    if (lines.length < count || lines.slice(0, count).some((line) => !line))
      throw new Error("OPERATOR_PASSWORD_REQUIRED");
    return lines.slice(0, count);
  }
  const silent = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  const terminal = createInterface({ input: process.stdin, output: silent, terminal: true });
  try {
    const passwords = [];
    for (let index = 0; index < count; index++) {
      process.stderr.write(labels[index] ?? (index === 0 ? "Operator password: " :
        "New operator password: "));
      passwords.push(await terminal.question(""));
      process.stderr.write("\n");
    }
    return passwords;
  } finally { terminal.close(); }
}
function readPrivateJson(path) {
  const descriptor = openSync(resolve(path), constants.O_RDONLY | constants.O_NOFOLLOW);
  let input;
  try {
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.uid !== process.getuid() ||
      metadata.size > 2048 || (metadata.mode & 0o077) !== 0)
      throw new Error("PRIVATE_INPUT_FILE_UNSAFE");
    input = JSON.parse(readFileSync(descriptor, "utf8"));
  } finally { closeSync(descriptor); }
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new Error("PRIVATE_INPUT_INVALID");
  return input;
}
let clockAnchor;
const twinNow = () => clockAnchor ? new Date(clockAnchor.twin_start_ms +
  (Date.now() - clockAnchor.real_start_ms) * clockAnchor.speed) : new Date();
const ecosystemMode = process.env.BANK_ECOSYSTEM_MODE ??
  (existsSync(join(dataDir, "ecosystem.sqlite")) ? "separated" : "embedded");
if (ecosystemMode !== "embedded" && ecosystemMode !== "separated")
  throw new Error("ECOSYSTEM_MODE_INVALID");
const bank = new Bank(bankPath, twinNow, undefined, { ecosystemMode });
let ecosystem;
try {
  if (bank.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_clock'").get())
    clockAnchor = bank.db.prepare("SELECT real_start_ms,twin_start_ms,speed FROM runtime_clock WHERE id=1")
      .get();
  const operators = new OperatorAuth(bank);
  const accounts = new AccountLifecycle(bank);
  const accountProducts = new AccountService(bank);
  const onboarding = new OnboardingService(bank, new AuthEngine(bank));
  const judicial = new JudicialOrders(bank);
  const credit = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
  const authenticate = async (id, roles) => {
    if (typeof id !== "string" || !id) throw new Error("OPERATOR_ID_REQUIRED");
    const [password] = await readPasswords(1);
    const identity = operators.authenticate(id, password);
    operators.require(identity, roles);
    return identity;
  };
  const noticeAccess = async () => {
    if (ecosystemMode === "embedded") return new PspNoticeAccess(bank);
    ecosystem ??= await EcosystemClient.start(join(dataDir, "ecosystem.sqlite"));
    return ecosystem;
  };
  let result;
  switch (command) {
    case "bootstrap": {
      const [password] = await readPasswords(1);
      result = operators.bootstrap(args[0], password);
      break;
    }
    case "enroll": {
      const [id, role, adminId] = args;
      const [adminPassword, newPassword] = await readPasswords(2);
      operators.require(operators.authenticate(adminId, adminPassword), ["admin"]);
      result = operators.add(adminId, id, role, newPassword);
      break;
    }
    case "change-password": {
      const [currentPassword, newPassword] = await readPasswords(2);
      operators.changePassword(args[0], currentPassword, newPassword);
      result = { id: args[0], password_changed: true };
      break;
    }
    case "disable": {
      const [targetId, adminId] = args;
      await authenticate(adminId, ["admin"]);
      operators.disable(adminId, targetId);
      result = { id: targetId, disabled: true };
      break;
    }
    case "account": {
      await authenticate(process.env.OPERATOR_ID, ["admin", "maker", "reviewer"]);
      const account = bank.account(args[0]);
      result = { id: account.id, customer_id: account.customer_id, status: account.status,
        frozen_reason: account.frozen_reason ?? null, balance_cents: account.balance_cached,
        available_cents: bank.availableBalance(account.id), history: accounts.history(account.id) };
      break;
    }
    case "account-status": {
      const [accountId, status, textReason, actor] = args;
      await authenticate(actor, ["admin", "reviewer"]);
      const account = accounts.transition(accountId, status, actor,
        textReason === "-" ? null : textReason);
      result = { id: account.id, status: account.status,
        frozen_reason: account.frozen_reason ?? null };
      break;
    }
    case "onboarding-apply": {
      const [inputPath, maker] = args;
      const [operatorPassword, applicantPassword] = await readPasswords(2,
        ["Maker password: ", "New customer password: "]);
      operators.require(operators.authenticate(maker, operatorPassword), ["admin", "maker"]);
      const { cpf, name, persona } = readPrivateJson(inputPath);
      result = onboarding.apply({ cpf, name, persona, password: applicantPassword });
      break;
    }
    case "business-open": {
      const [customerId, inputPath, reviewer] = args;
      await authenticate(reviewer, ["admin", "reviewer"]);
      const { cnpj, legal_name } = readPrivateJson(inputPath);
      result = accountProducts.openBusiness(customerId, cnpj, legal_name, reviewer);
      break;
    }
    case "business-verify": {
      const [customerId, accountId, inputPath, reviewer] = args;
      await authenticate(reviewer, ["admin", "reviewer"]);
      const { cnpj, legal_name } = readPrivateJson(inputPath);
      result = accountProducts.verifyBusiness(customerId, accountId, cnpj, legal_name, reviewer);
      break;
    }
    case "business-status": {
      await authenticate(process.env.OPERATOR_ID, ["admin", "maker", "reviewer"]);
      const account = bank.account(args[0]);
      result = { id: account.id, kind: account.kind, status: account.status,
        identity: accountProducts.businessIdentity(account.id) };
      break;
    }
    case "payment-open": {
      const [customerId, adminId] = args;
      await authenticate(adminId, ["admin"]);
      result = accountProducts.openPayment(customerId);
      break;
    }
    case "salary-open": {
      const [employerCustomerId, employerAccountId, employeeCustomerId, adminId] = args;
      await authenticate(adminId, ["admin"]);
      result = accountProducts.openSalary(employerCustomerId,
        employerAccountId, employeeCustomerId);
      break;
    }
    case "salary-pay": {
      const [employerCustomerId, employerAccountId, salaryAccountId,
        amountText, idempotencyKey, adminId] = args;
      await authenticate(adminId, ["admin"]);
      result = accountProducts.paySalary(employerCustomerId, employerAccountId,
        salaryAccountId, Number(amountText), idempotencyKey);
      break;
    }
    case "salary-port": {
      const [employeeCustomerId, salaryAccountId, destinationAccountId,
        amountText, idempotencyKey, adminId] = args;
      await authenticate(adminId, ["admin"]);
      result = accountProducts.portSalary(employeeCustomerId, salaryAccountId,
        destinationAccountId, Number(amountText), idempotencyKey);
      break;
    }
    case "salary-status": {
      await authenticate(process.env.OPERATOR_ID, ["admin", "maker", "reviewer"]);
      const account = bank.account(args[0]);
      result = { id: account.id, kind: account.kind, status: account.status,
        balance_cents: account.balance_cached,
        employer: accountProducts.salaryEmployer(account.id) };
      break;
    }
    case "onboarding-pending": {
      await authenticate(process.env.OPERATOR_ID, ["admin", "maker", "reviewer"]);
      result = page(bank.db.prepare(`SELECT rowid row_cursor,customer_id,account_id,
        bureau_score,liveness_status,submitted_at FROM onboarding_applications
        WHERE status='pending' AND rowid>? ORDER BY rowid LIMIT 101`)
        .all(cursor(args[0])));
      break;
    }
    case "onboarding-status": {
      await authenticate(process.env.OPERATOR_ID, ["admin", "maker", "reviewer"]);
      const application = onboarding.application(args[0]);
      result = { ...application, events: bank.db.prepare(`SELECT event,actor,twin_at,recorded_at
        FROM onboarding_events WHERE customer_id=? ORDER BY rowid`).all(args[0]) };
      break;
    }
    case "onboarding-liveness": {
      const [customerId, outcome, maker] = args;
      await authenticate(maker, ["admin", "maker"]);
      result = onboarding.attestLiveness(customerId, outcome === "pass", maker);
      break;
    }
    case "onboarding-review": {
      const [customerId, decision, reviewer] = args;
      await authenticate(reviewer, ["admin", "reviewer"]);
      result = onboarding.review(customerId, decision, reviewer);
      break;
    }
    case "kyc-pending": {
      await authenticate(process.env.OPERATOR_ID, ["reviewer"]);
      result = page(bank.db.prepare(`SELECT r.rowid row_cursor,r.customer_id,
        c.kyc_tier current_tier,r.requested_tier,r.submitted_at FROM kyc_requests r
        JOIN customers c ON c.id=r.customer_id
        WHERE r.status='submitted' AND r.requested_tier IN (2,3)
          AND NOT EXISTS (SELECT 1 FROM onboarding_applications a
            WHERE a.customer_id=r.customer_id AND a.status<>'approved')
          AND r.rowid>? ORDER BY r.rowid LIMIT 101`).all(cursor(args[0])));
      break;
    }
    case "kyc-approve": {
      const [customerId, tier, submittedAt, reviewer] = args;
      await authenticate(reviewer, ["reviewer"]);
      const marker = join(dataDir, "fault-lab.marker");
      const lab = existsSync(marker) &&
        readFileSync(marker, "utf8") === "banco-vivo-fault-lab-v1\n";
      result = bank.transaction(() => {
        const pending = bank.db.prepare(`SELECT 1 FROM kyc_requests WHERE
          customer_id=? AND status='submitted' AND requested_tier=? AND submitted_at=?`)
          .get(customerId, Number(tier), submittedAt);
        if (!pending) throw new Error("BIZ_KYC_REVIEW_REQUEST_CHANGED");
        if (lab && bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_kyc_review_interruptions'`).get() &&
          bank.db.prepare(`SELECT 1 FROM lab_kyc_review_interruptions
            WHERE customer_id=? AND submitted_at=? AND released_at IS NULL AND expires_at>?`)
            .get(customerId, submittedAt, bank.realNow().toISOString())) {
          bank.log({ actor: reviewer, kind: "kyc_review", customerId,
            route: submittedAt, status: 503 });
          return null;
        }
        bank.approveKyc(customerId, reviewer);
        bank.log({ actor: reviewer, kind: "kyc_review", customerId,
          route: submittedAt, status: 200 });
        const { kyc_tier, kyc_status } = bank.customer(customerId);
        return { customer_id: customerId, kyc_tier, kyc_status };
      });
      if (!result) throw new Error("BIZ_KYC_REVIEW_TEMPORARILY_UNAVAILABLE");
      break;
    }
    case "judicial-request": {
      const [accountId, amountText, reference, maker] = args;
      await authenticate(maker, ["admin", "maker"]);
      if (!/^[1-9]\d*$/.test(amountText) || !Number.isSafeInteger(Number(amountText)))
        throw new Error("BIZ_JUDICIAL_ORDER_INVALID");
      result = judicial.request(accountId, Number(amountText), reference, maker);
      break;
    }
    case "judicial-review": {
      const [id, decision, checker] = args;
      await authenticate(checker, ["admin", "reviewer"]);
      result = judicial.review(id, decision, checker);
      break;
    }
    case "judicial-release": {
      const [id, maker] = args;
      await authenticate(maker, ["admin", "maker"]);
      result = judicial.requestRelease(id, maker);
      break;
    }
    case "judicial-release-review": {
      const [id, decision, checker] = args;
      await authenticate(checker, ["admin", "reviewer"]);
      result = judicial.reviewRelease(id, decision, checker);
      break;
    }
    case "judicial-order": {
      await authenticate(process.env.OPERATOR_ID, ["admin", "maker", "reviewer"]);
      const order = judicial.get(args[0]);
      const events = bank.db.prepare(`SELECT action,actor,created_at FROM judicial_order_events
        WHERE order_id=? ORDER BY rowid`).all(order.id);
      result = { ...order, events };
      break;
    }
    case "credit-open": {
      const [customerId, depositAccountId, limitText, closingText, admin] = args;
      await authenticate(admin, ["admin"]);
      if (!/^[1-9]\d*$/.test(limitText) || !/^(?:[1-9]|1\d|2[0-8])$/.test(closingText) ||
        !Number.isSafeInteger(Number(limitText))) throw new Error("BIZ_INVALID_LIMIT");
      result = bank.transaction(() => {
        const account = credit.open(customerId, Number(limitText), Number(closingText));
        const card = new CardsEngine(bank).issueCredit(customerId, depositAccountId, account.id);
        return { account, card };
      });
      break;
    }
    case "credit-close": {
      const [customerId, creditId, operator] = args;
      await authenticate(operator, ["admin", "reviewer"]);
      result = credit.closeNext(customerId, creditId);
      break;
    }
    case "risk-profile": {
      await authenticate(process.env.OPERATOR_ID, ["admin", "reviewer"]);
      const profile = bank.risk.profile(args[0]);
      const history = bank.db.prepare(`SELECT actor,risk_tier,verified_income_cents,
        declared_income_cents,changed_at FROM customer_risk_profile_changes
        WHERE customer_id=? ORDER BY rowid DESC LIMIT 20`).all(args[0]);
      result = { ...profile, history };
      break;
    }
    case "set-risk-profile": {
      const [customerId, tier, incomeText, adminId] = args;
      await authenticate(adminId, ["admin"]);
      if (!/^(?:0|[1-9]\d*)$/.test(incomeText) ||
        !Number.isSafeInteger(Number(incomeText))) throw new Error("RISK_PROFILE_INVALID");
      result = bank.risk.setVerifiedProfile(customerId, tier, Number(incomeText), adminId);
      break;
    }
    case "risk-promote": {
      const [area, ruleId, from, to, adminId] = args;
      await authenticate(adminId, ["admin"]);
      bank.risk.promoteShadowRule(area, ruleId, from, to, adminId);
      result = { area, rule_id: ruleId, action: "promote" };
      break;
    }
    case "risk-disable": {
      const [area, ruleId, adminId] = args;
      await authenticate(adminId, ["admin"]);
      bank.risk.disableShadowRule(area, ruleId, adminId);
      result = { area, rule_id: ruleId, action: "disable" };
      break;
    }
    case "risk-emergency": {
      const [area, ruleId, evidencePath, adminId] = args;
      await authenticate(adminId, ["admin"]);
      const file = resolve(evidencePath);
      if (statSync(file).size > 4096) throw new Error("RISK_ROLLOUT_EVIDENCE_TOO_LARGE");
      const evidence = JSON.parse(readFileSync(file, "utf8"));
      if (!evidence || typeof evidence !== "object" || Array.isArray(evidence) ||
        Object.keys(evidence).sort().join(",") !==
          "head_sha,incident_id,reviewer_id,run_id,task_id")
        throw new Error("RISK_ROLLOUT_EMERGENCY_EVIDENCE_INVALID");
      const eventsPath = join(resolve(process.env.DATA_DIR ?? "data"), "events.sqlite");
      if (!existsSync(eventsPath)) throw new Error("RISK_ROLLOUT_CASE_FILE_UNAVAILABLE");
      const events = new EventStore(eventsPath);
      try {
        const history = events.caseFile.history(evidence.incident_id);
        const ci = history.find((entry) => entry.kind === "hardening.ci" &&
          entry.payload.task_id === evidence.task_id &&
          entry.payload.run_id === evidence.run_id &&
          entry.payload.head_sha === evidence.head_sha &&
          entry.payload.red_first === "pass" && entry.payload.typecheck === true &&
          entry.payload.world_tests === true);
        const review = history.find((entry) => entry.kind === "dossier.hardening_review" &&
          entry.actor_id === evidence.reviewer_id &&
          entry.payload.incident_id === evidence.incident_id &&
          entry.payload.task_id === evidence.task_id &&
          entry.payload.run_id === evidence.run_id &&
          entry.payload.head_sha === evidence.head_sha &&
          entry.payload.verdict === "approve" &&
          entry.payload.honest_impact_checked === true);
        const merge = history.find((entry) => entry.kind === "patch.merged" &&
          entry.payload.public?.task_id === evidence.task_id &&
          entry.payload.public?.commit_short === evidence.head_sha.slice(0, 12) &&
          entry.payload.private?.run_id === evidence.run_id &&
          entry.payload.private?.rule_id === ruleId);
        if (!ci || !review || !merge || !(ci.id < review.id && review.id < merge.id))
          throw new Error("RISK_ROLLOUT_EMERGENCY_EVIDENCE_INVALID");
      } finally { events.close(); }
      bank.risk.activateEmergencyRule(area, ruleId, adminId, evidence);
      result = { area, rule_id: ruleId, action: "emergency_activate" };
      break;
    }
    case "holds":
      await authenticate(process.env.OPERATOR_ID, ["admin", "reviewer"]);
      {
        const now = twinNow();
        const isoNow = now.toISOString();
        const dueBy = new Date(now.getTime() + 3_600_000).toISOString();
        const summary = bank.db.prepare(`SELECT COUNT(*) pending_total,
          SUM(CASE WHEN h.expires_at<=? THEN 1 ELSE 0 END) due_within_hour,
          SUM(CASE WHEN h.expires_at<=? AND ack.hold_id IS NULL THEN 1 ELSE 0 END)
            unacknowledged_due_within_hour
          FROM risk_pix_holds h LEFT JOIN risk_pix_review_acknowledgements ack
            ON ack.hold_id=h.id
          WHERE h.status='pending' AND h.expires_at>?`)
          .get(dueBy, dueBy, isoNow);
        result = { ...page(bank.db.prepare(`SELECT h.rowid row_cursor,h.id,h.from_account,
          h.to_account,h.amount_cents,h.created_at,h.expires_at,h.status,
          ack.reviewer acknowledged_by,ack.acknowledged_at
          FROM risk_pix_holds h LEFT JOIN risk_pix_review_acknowledgements ack
            ON ack.hold_id=h.id
          WHERE h.status='pending' AND h.expires_at>? AND h.rowid>?
          ORDER BY h.rowid LIMIT 101`).all(isoNow, cursor(args[0])), (row) => ({
            ...row, remaining_seconds: Math.max(0,
              Math.ceil((Date.parse(row.expires_at) - now.getTime()) / 1000)),
          })), pending_total: summary.pending_total,
          due_within_hour: summary.due_within_hour ?? 0,
          unacknowledged_due_within_hour: summary.unacknowledged_due_within_hour ?? 0,
          twin_now: isoNow };
      }
      break;
    case "review-hold": {
      const [id, decision, reviewer] = args;
      await authenticate(reviewer, ["admin", "reviewer"]);
      const resolved = ecosystemMode === "separated" ?
        await new SeparatedPixCoordinator(bank, await noticeAccess())
          .resolveRiskHold(id, decision, reviewer) :
        bank.resolveRiskPixHold(id, decision, reviewer);
      result = { id: resolved.hold.id, status: resolved.hold.status,
        transfer_id: resolved.transfer?.id ?? null };
      break;
    }
    case "cautelar-holds":
      await authenticate(process.env.OPERATOR_ID, ["admin", "reviewer"]);
      result = page(bank.db.prepare(`SELECT rowid row_cursor,id,account_id,
        root_transfer_id,amount_cents,reason,created_at,expires_at
        FROM psp_cautelar_holds WHERE status='active' AND expires_at>?
        AND rowid>? ORDER BY rowid LIMIT 101`)
        .all(twinNow().toISOString(), cursor(args[0])));
      break;
    case "review-cautelar": {
      const [id, resolution, reviewer] = args;
      await authenticate(reviewer, ["admin", "reviewer"]);
      const resolved = bank.resolvePspCautelar(id, resolution, reviewer);
      result = { id: resolved.hold.id, status: resolved.hold.status,
        resolved_by: resolved.hold.resolved_by,
        returned_cents: resolved.returned?.amount ?? 0 };
      break;
    }
    case "psp-notice-provision": {
      const [identityId, accountId, keyFile, adminId] = args;
      await authenticate(adminId, ["admin"]);
      const file = resolve(keyFile);
      if (statSync(file).size > 1024) throw new Error("PSP_NOTICE_KEY_FILE_TOO_LARGE");
      await (await noticeAccess()).provision(identityId, accountId,
        readFileSync(file, "utf8").trim(), adminId);
      result = { identity_id: identityId, account_id: accountId, provisioned: true };
      break;
    }
    case "psp-notice-revoke": {
      const [identityId, adminId] = args;
      await authenticate(adminId, ["admin"]);
      await (await noticeAccess()).revoke(identityId, adminId);
      result = { identity_id: identityId, revoked: true };
      break;
    }
    case "psp-notice-reprovision": {
      const [identityId, keyFile, adminId] = args;
      await authenticate(adminId, ["admin"]);
      const file = resolve(keyFile);
      if (statSync(file).size > 1024) throw new Error("PSP_NOTICE_KEY_FILE_TOO_LARGE");
      await (await noticeAccess()).reprovision(identityId,
        readFileSync(file, "utf8").trim(), adminId);
      result = { identity_id: identityId, reprovisioned: true };
      break;
    }
    case "spi-status":
      await authenticate(process.env.OPERATOR_ID, ["admin", "reviewer"]);
      result = ecosystemMode === "separated" ?
        await (await noticeAccess()).spiAvailability() : bank.spi.availability();
      break;
    case "spi-history":
      await authenticate(process.env.OPERATOR_ID, ["admin", "reviewer"]);
      result = ecosystemMode === "separated" ?
        page(await (await noticeAccess()).spiAvailabilityHistory(cursor(args[0]))) :
        page(bank.db.prepare(`SELECT id row_cursor,id,available,changed_at,changed_by
          FROM spi_runtime_history WHERE id>? ORDER BY id LIMIT 101`)
          .all(cursor(args[0])), ({ available, ...row }) => ({ ...row,
            available: Boolean(available) }));
      break;
    case "spi-availability": {
      const [status, actor] = args;
      await authenticate(actor, ["admin"]);
      result = ecosystemMode === "separated" ?
        await (await noticeAccess()).spiSetAvailability(status === "online", actor) :
        bank.spi.setAvailability(status === "online", actor);
      break;
    }
    case "card-issuer-status":
      await authenticate(process.env.OPERATOR_ID, ["admin", "reviewer"]);
      result = new CardNetwork(bank, new CardsEngine(bank)).issuerAvailability();
      break;
    case "card-issuer-history":
      await authenticate(process.env.OPERATOR_ID, ["admin", "reviewer"]);
      new CardNetwork(bank, new CardsEngine(bank));
      result = page(bank.db.prepare(`SELECT id row_cursor,id,available,changed_at,changed_by
        FROM card_issuer_history WHERE id>? ORDER BY id LIMIT 101`)
        .all(cursor(args[0])), ({ available, ...row }) => ({ ...row,
          available: Boolean(available) }));
      break;
    case "card-issuer-availability": {
      const [status, actor] = args;
      await authenticate(actor, ["admin"]);
      result = new CardNetwork(bank, new CardsEngine(bank))
        .setIssuerAvailability(status === "online", actor);
      break;
    }
    case "manual-pending":
      await authenticate(process.env.OPERATOR_ID, ["admin", "maker", "reviewer"]);
      result = page(bank.db.prepare(`SELECT rowid row_cursor,id,maker_id,reason,
        lines_json,created_at FROM manual_posting_requests
        WHERE status='pending' AND rowid>? ORDER BY rowid LIMIT 101`)
        .all(cursor(args[0])), ({ lines_json, ...row }) => ({
          ...row, lines: JSON.parse(lines_json) }));
      break;
    case "manual-request": {
      const file = resolve(args[0]);
      if (statSync(file).size > 16_384) throw new Error("MANUAL_REQUEST_FILE_TOO_LARGE");
      const input = JSON.parse(readFileSync(file, "utf8"));
      await authenticate(input.maker_id, ["admin", "maker"]);
      const request = bank.requestManualPosting(input.maker_id, input.reason, input.lines);
      result = { id: request.id, status: request.status, maker_id: request.maker_id };
      break;
    }
    case "manual-review": {
      const [id, decision, checker] = args;
      await authenticate(checker, ["admin", "reviewer"]);
      const request = bank.resolveManualPosting(id, checker, decision);
      result = { id: request.id, status: request.status,
        checker_id: request.checker_id, ledger_tx_id: request.ledger_tx_id };
      break;
    }
  }
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(error?.code ?? error?.message ?? String(error));
  process.exitCode = 1;
} finally {
  await ecosystem?.close();
  bank.close();
}
