import Fastify, { type FastifyInstance, type FastifyReply } from "fastify";
import { z } from "zod";
import { AuthEngine } from "./auth.ts";
import { Bank, BankError } from "./bank.ts";
import { JACARANDA_ISPB } from "./pix-id.ts";
import { CardsEngine } from "./cards.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "./credit-cards.ts";
import { CardNetwork } from "./ecosystem/card-network.ts";
import { CardRecurring } from "./card-recurring.ts";
import { LoansEngine } from "./loans.ts";
import { parseDecimalCents } from "./money.ts";
import { FeatureRegistry } from "./features.ts";
import { ScheduledPix } from "./scheduled-pix.ts";
import { PixAutomatic } from "./pix-automatic.ts";
import { ProximityPix } from "./proximity-pix.ts";
import { DataSharing } from "./data-sharing.ts";
import { DynamicLimits } from "./dynamic-limits.ts";
import { AccountService } from "./accounts.ts";
import { AccountLifecycle } from "./account-lifecycle.ts";
import { OnboardingService } from "./onboarding.ts";
import { timingSafeEqual } from "node:crypto";
import { setTraceIdentity } from "./telemetry.ts";
import { PspNoticeAccess } from "./ecosystem/psp-notice-access.ts";
import type { EcosystemClient } from "../../ecosystem/src/client.ts";
import type { SeparatedPixCoordinator } from "./separated-pix-coordinator.ts";
import { PUBLIC_TARIFF_SCHEDULE } from "./tariff-schedule.ts";
import { installIncidentNotices, listIncidentNotices } from "./incident-notices.ts";
import { readMedIncidentCompensation } from "./med-incident-compensation.ts";

const loginBody = z.strictObject({ cpf: z.string().length(11), password: z.string().max(256), device_id: z.string().min(1).max(128) });
const otpBody = z.strictObject({ challenge_id: z.string().min(1), otp: z.string().regex(/^\d{6}$/),
  device_public_key: z.string().min(1).optional(), device_signature: z.string().min(1).optional() });
const refreshBody = z.strictObject({ refresh_token: z.string().min(1),
  challenge_id: z.string().min(1).optional(), signature: z.string().min(1).optional() });
const pixBase = { from_account: z.string().min(1), to_account: z.string().min(1),
  idempotency_key: z.string().min(1).max(128) };
const pixBody = z.union([z.strictObject({ ...pixBase, amount_cents: z.number().int().positive() }),
  z.strictObject({ ...pixBase, amount: z.string() })]);
const pixNightLimitBody = z.union([
  z.strictObject({ night_limit_cents: z.number().int().min(0).max(2_000_000) }),
  z.strictObject({ night_start_hour: z.union([z.literal(20), z.literal(22)]) }),
]);
const keyBody = z.strictObject({ account_id: z.string().min(1), key: z.string().min(3).max(255) });
const keyClaimBody = z.strictObject({ key: z.string().min(3).max(255),
  to_account: z.string().min(1), kind: z.enum(["portability", "ownership"]) });
const medBody = z.strictObject({ transfer_id: z.string().min(1) });
const kycBody = z.strictObject({ tier: z.union([z.literal(2), z.literal(3)]) });
const issueCardBody = z.strictObject({ account_id: z.string().min(1), limit_cents: z.number().int().positive().max(2_000_000) });
const virtualCardBody = z.strictObject({ limit_cents: z.number().int().positive(), expires_at: z.iso.datetime().optional() });
const cardPatchBody = z.strictObject({ status: z.enum(["active", "blocked", "lost", "stolen"]).optional(),
  online_enabled: z.boolean().optional(), international_enabled: z.boolean().optional(), limit_cents: z.number().int().positive().optional() });
const creditPaymentBody = z.strictObject({ source_account_id: z.string().min(1).max(128),
  amount_cents: z.number().int().positive(), idempotency_key: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/) });
const creditPlanBody = z.strictObject({ installments: z.number().int().min(2).max(24) });
const acceptLoanBody = z.strictObject({ offer_id: z.string().min(1), account_id: z.string().min(1),
  amount_cents: z.number().int().positive(), declared_income_cents: z.number().int().nonnegative().optional(),
  method: z.enum(["PRICE", "SAC"]).optional(), term_months: z.number().int().min(1).max(60).optional() });
const scheduleBody = z.strictObject({ from_account: z.string().min(1), to_account: z.string().min(1),
  amount_cents: z.number().int().positive(), execute_at: z.iso.datetime(),
  frequency: z.enum(["once", "weekly", "monthly"]) });
const automaticMandateBody = z.strictObject({ from_account: z.string().min(1),
  merchant_account: z.string().min(1), max_amount_cents: z.number().int().positive(),
  frequency: z.enum(["weekly", "monthly", "quarterly", "semiannual", "yearly"]),
  starts_at: z.iso.datetime(),
  ends_at: z.iso.datetime().optional(), offer_id: z.string().min(1) });
const automaticOfferBody = z.strictObject({ merchant_account: z.string().min(1),
  max_amount_cents: z.number().int().positive(),
  frequency: z.enum(["weekly", "monthly", "quarterly", "semiannual", "yearly"]),
  starts_at: z.iso.datetime(), ends_at: z.iso.datetime().optional(),
  post_due_retry_allowed: z.boolean() });
const automaticChargeBody = z.strictObject({ amount_cents: z.number().int().positive(),
  due_at: z.iso.datetime() });
const automaticRetryBody = z.strictObject({ due_at: z.iso.datetime() });

function peerIp(headers: Record<string, unknown>): string {
  const value = headers["x-twin-source-ip"];
  return typeof value === "string" && /^\d{1,3}(\.\d{1,3}){3}$/.test(value) ? value : "127.0.0.1";
}

export interface TwinRoute { method: string; path: string; }
const twinRoutes = new WeakMap<FastifyInstance, TwinRoute[]>();
export function getTwinRoutes(app: FastifyInstance): TwinRoute[] {
  return [...(twinRoutes.get(app) ?? [])].sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
}

export function createTwinApi(bank: Bank, auth: AuthEngine = new AuthEngine(bank),
  options: { partnerKey?: string; legacyCardAuthorizations?: boolean;
    labStatementUnavailable?: (customerId: string, accountId: string) => boolean;
    labLoanOfferUnavailable?: (customerId: string) => boolean;
    labPixAutomaticMandatesUnavailable?: (customerId: string) => boolean;
    labKycStatusUnavailable?: (customerId: string) => boolean;
    labKycSubmissionUnavailable?: (customerId: string) => boolean;
    pspNotices?: Pick<EcosystemClient, "beginLogin" | "completeLogin" |
      "beginOperation" | "notices" | "logout">;
    pixCoordinator?: Pick<SeparatedPixCoordinator, "enqueue" | "transferInternal" |
      "paymentMessages" | "medCaseProjection" | "requestMed" | "lookupExternalKey"> } = {}): FastifyInstance {
  if (bank.isSeparatedEcosystem && (!options.pspNotices || !options.pixCoordinator))
    throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
  const app = Fastify({ logger: false, bodyLimit: 64 * 1024 });
  const registered: TwinRoute[] = [];
  twinRoutes.set(app, registered);
  app.addHook("onRoute", (route) => {
    for (const method of Array.isArray(route.method) ? route.method : [route.method])
      if (method !== "HEAD") registered.push({ method, path: route.url });
  });
  const cards = new CardsEngine(bank);
  const creditCards = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
  const cardNetwork = new CardNetwork(bank, cards);
  installIncidentNotices(bank.db);
  const cardRecurring = new CardRecurring(bank, cardNetwork);
  const loans = new LoansEngine(bank);
  const features = new FeatureRegistry(bank);
  const scheduled = new ScheduledPix(bank, features);
  const automatic = new PixAutomatic(bank);
  const proximity = new ProximityPix(bank, features);
  const sharing = new DataSharing(bank, features);
  const dynamicLimits = new DynamicLimits(bank, features);
  const accounts = new AccountService(bank);
  const onboarding = new OnboardingService(bank, auth);
  const accountLifecycle = new AccountLifecycle(bank);
  const pspNotices = options.pspNotices ?? new PspNoticeAccess(bank);
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof BankError) {
      if (error.code.startsWith("INTEGRITY_") || error.code.startsWith("ECOSYSTEM_")) {
        reply.code(500).send({ error: "INTERNAL_ERROR" });
        return;
      }
      const status = error.code === "BIZ_SPI_UNAVAILABLE" ? 503 :
        ["BIZ_RATE_LIMIT", "BIZ_PSP_NOTICE_RATE_LIMIT"].includes(error.code) ? 429 : error.code.startsWith("DEF_")
        ? (error.code === "DEF_NOT_FOUND" ? 404 : 403) : 400;
      reply.code(status).send({ error: error.code,
        ...(error.risk ? { risk_score: error.risk.score,
          reason_codes: error.risk.reasonCodes,
          ...(error.risk.holdId ? { hold_id: error.risk.holdId } : {}) } : {}) });
      return;
    }
    if (error instanceof z.ZodError) { reply.code(400).send({ error: "BIZ_INVALID_REQUEST" }); return; }
    reply.code(500).send({ error: "INTERNAL_ERROR" });
  });
  function principal(header: string | undefined): string {
    const token = header?.match(/^Bearer (\S+)$/)?.[1];
    const identity = token ? auth.traceIdentityForAccess(token) : undefined;
    if (!identity) throw new BankError("DEF_UNAUTHORIZED");
    setTraceIdentity(identity);
    return identity.userId;
  }
  app.get("/tariffs", async () => PUBLIC_TARIFF_SCHEDULE);
  function pspSession(header: string | undefined): string {
    const token = header?.match(/^Bearer ([A-Za-z0-9_-]{43})$/)?.[1];
    if (!token) throw new BankError("DEF_PSP_NOTICE_ACCESS");
    return token;
  }
  function pspProof(headers: Record<string, unknown>): { challengeId: string; signature: string } {
    const challengeId = headers["x-psp-challenge"], signature = headers["x-psp-signature"];
    if (typeof challengeId !== "string" || typeof signature !== "string")
      throw new BankError("DEF_PSP_NOTICE_ACCESS");
    return { challengeId, signature };
  }
  app.post("/psp/notices/login-challenge", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const { identity_id, client_nonce, signature } = z.strictObject({
      identity_id: z.string().min(3).max(80),
      client_nonce: z.string().regex(/^[A-Za-z0-9_-]{32}$/),
      signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
    }).parse(request.body);
    return pspNotices.beginLogin(identity_id, client_nonce, signature);
  });
  app.post("/psp/notices/login", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const body = z.strictObject({ identity_id: z.string().min(3).max(80),
      challenge_id: z.string().min(1), signature: z.string().min(1) }).parse(request.body);
    return pspNotices.completeLogin(body.identity_id, body.challenge_id, body.signature);
  });
  app.post("/psp/notices/operation-challenge", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const body = z.strictObject({ method: z.enum(["GET", "POST"]),
      cursor: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
      limit: z.number().int().min(1).max(50).optional() }).parse(request.body);
    if (body.method === "POST" && (body.cursor !== undefined || body.limit !== undefined))
      throw new BankError("BIZ_PSP_NOTICE_QUERY_INVALID");
    return pspNotices.beginOperation(pspSession(request.headers.authorization), body.method,
      body.method === "GET" ? { cursor: body.cursor ?? null, limit: body.limit ?? 20 } : {});
  });
  app.get("/psp/notices", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const query = z.strictObject({ cursor: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
      limit: z.coerce.number().int().min(1).max(50).optional() }).parse(request.query);
    const proof = pspProof(request.headers);
    return pspNotices.notices(pspSession(request.headers.authorization), proof.challengeId,
      proof.signature, query.cursor ?? null, query.limit ?? 20);
  });
  app.post("/psp/notices/logout", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const proof = pspProof(request.headers);
    await pspNotices.logout(pspSession(request.headers.authorization), proof.challengeId,
      proof.signature);
    return { revoked: true };
  });
  function requirePartner(header: string | undefined): void {
    const expected = options.partnerKey;
    if (!expected || !header) throw new BankError("DEF_UNAUTHORIZED");
    const a = Buffer.from(header); const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new BankError("DEF_UNAUTHORIZED");
  }
  function requireDeviceProof(access: string, headers: Record<string, unknown>,
    path: string, body: unknown, method = "POST"): void {
    const challenge = headers["x-device-challenge"];
    const signature = headers["x-device-signature"];
    if (typeof challenge !== "string" || typeof signature !== "string")
      throw new BankError("DEF_DEVICE_PROOF_INVALID");
    auth.verifyDeviceOperation(access, challenge, signature, method, path, body);
  }
  app.post("/auth/login", async (request) => {
    const body = loginBody.parse(request.body);
    return auth.beginLogin(body.cpf, body.password, peerIp(request.headers), body.device_id);
  });
  app.post("/onboarding/apply", async (request) => {
    const body = z.strictObject({ cpf: z.string().regex(/^\d{11}$/),
      name: z.string().min(3).max(120),
      persona: z.enum(["salaried", "merchant", "student", "retiree",
        "gig", "saver", "night_owl"]),
      password: z.string().min(12).max(256) }).parse(request.body);
    const application = onboarding.apply(body);
    return { customer_id: application.customer_id,
      account_id: application.account_id, status: application.status };
  });
  app.post("/auth/otp", async (request) => {
    const body = otpBody.parse(request.body);
    if (Boolean(body.device_public_key) !== Boolean(body.device_signature))
      throw new BankError("DEF_DEVICE_PROOF_INVALID");
    return auth.verifyOtp(body.challenge_id, body.otp, peerIp(request.headers),
      body.device_public_key && body.device_signature ?
        { publicKey: body.device_public_key, signature: body.device_signature } : undefined);
  });
  app.post("/auth/otp/verify", async (request) => {
    const body = otpBody.parse(request.body);
    if (Boolean(body.device_public_key) !== Boolean(body.device_signature))
      throw new BankError("DEF_DEVICE_PROOF_INVALID");
    return auth.verifyOtp(body.challenge_id, body.otp, peerIp(request.headers),
      body.device_public_key && body.device_signature ?
        { publicKey: body.device_public_key, signature: body.device_signature } : undefined);
  });
  app.post("/auth/refresh/challenge", async (request) =>
    auth.beginRefresh(z.strictObject({ refresh_token: z.string().min(1) }).parse(request.body).refresh_token));
  app.post("/auth/refresh", async (request) => {
    const body = refreshBody.parse(request.body);
    if (Boolean(body.challenge_id) !== Boolean(body.signature))
      throw new BankError("DEF_DEVICE_PROOF_INVALID");
    return auth.refresh(body.refresh_token, body.challenge_id && body.signature ?
      { challengeId: body.challenge_id, signature: body.signature } : undefined);
  });
  app.post("/auth/step-up", async (request) => {
    principal(request.headers.authorization);
    const { password } = z.strictObject({ password: z.string().max(256) }).parse(request.body);
    return auth.stepUp(request.headers.authorization!.slice(7), password);
  });
  app.post("/auth/password", async (request) => {
    principal(request.headers.authorization);
    const body = z.strictObject({ current_password: z.string().max(256),
      new_password: z.string().min(12).max(256) }).parse(request.body);
    const access = request.headers.authorization!.slice(7);
    requireDeviceProof(access, request.headers, "/auth/password", body);
    auth.changePassword(access,
      body.current_password, body.new_password);
    return { changed: true, login_required: true };
  });
  app.post("/auth/devices/:id/revoke", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(request.headers.authorization!.slice(7), request.headers,
      `/auth/devices/${id}/revoke`, undefined);
    auth.revokeDevice(customer, id);
    return { revoked: true };
  });
  app.post("/auth/logout", async (request) => {
    const customer = principal(request.headers.authorization);
    auth.revokeAccess(customer, request.headers.authorization!.slice(7));
    return { logged_out: true };
  });
  app.get("/devices", async (request) => auth.listDevices(principal(request.headers.authorization)));
  app.get("/devices/current/security-notices", async (request, reply) => {
    principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const query = z.strictObject({ before: z.coerce.number().int().positive().optional(),
      limit: z.coerce.number().int().min(1).max(100).optional() }).parse(request.query);
    requireDeviceProof(access, request.headers, "/devices/current/security-notices", query, "GET");
    reply.header("Cache-Control", "no-store");
    return auth.deviceSecurityNotices(access, query.before, query.limit);
  });
  app.post("/devices", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const body = z.strictObject({ device_id: z.string().min(3).max(128) }).parse(request.body);
    requireDeviceProof(access, request.headers, "/devices", body);
    const id = auth.enrolDevice(customer, body.device_id, peerIp(request.headers));
    return { device_id: id, status: "cooldown" };
  });
  app.post("/devices/current/pix-registration", async (request) => {
    principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    requireDeviceProof(access, request.headers,
      "/devices/current/pix-registration", undefined);
    return auth.registerCurrentDeviceForPix(access);
  });
  app.post("/devices/current/key/challenge", async (request) => {
    principal(request.headers.authorization);
    return auth.issueDeviceEnrollmentChallenge(request.headers.authorization!.slice(7));
  });
  app.post("/devices/current/key", async (request) => {
    principal(request.headers.authorization);
    const body = z.strictObject({ challenge_id: z.string().min(1),
      public_key: z.string().min(40).max(180), signature: z.string().min(80).max(100) })
      .parse(request.body);
    return auth.enrolCurrentDeviceKey(request.headers.authorization!.slice(7),
      body.challenge_id, body.public_key, body.signature);
  });
  app.post("/devices/current/operation-challenge", async (request) => {
    principal(request.headers.authorization);
    const body = z.strictObject({ method: z.enum(["GET", "POST", "PATCH", "DELETE"]), path: z.string().min(1).max(256),
      body: z.unknown().optional() }).parse(request.body);
    return auth.issueDeviceOperationChallenge(request.headers.authorization!.slice(7),
      body.method, body.path, body.body);
  });
  app.delete("/devices/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/devices/${id}`, undefined, "DELETE");
    auth.revokeDevice(customer, id);
    return { revoked: true };
  });
  app.get("/accounts", async (request) => {
    const customer = principal(request.headers.authorization);
    const accounts = bank.db.prepare(`SELECT id,kind,balance_cached,status,branch_code,
      account_number,account_digit FROM accounts WHERE customer_id=? ORDER BY id`)
      .all(customer) as { id: string; kind: string; balance_cached: number; status: string;
        branch_code: string; account_number: string; account_digit: string }[];
    return accounts.map((account) => ({ ...account, ispb: JACARANDA_ISPB,
      available_balance_cents: bank.availableBalance(account.id) }));
  });
  app.post("/accounts", async (request) => {
    const customer = principal(request.headers.authorization);
    requireDeviceProof(request.headers.authorization!.slice(7), request.headers,
      "/accounts", undefined);
    return { ...accounts.openSecond(customer), ispb: JACARANDA_ISPB };
  });
  app.post("/accounts/payment", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    requireDeviceProof(access, request.headers, "/accounts/payment", undefined);
    return { ...accounts.openPayment(customer), ispb: JACARANDA_ISPB };
  });
  app.post("/accounts/:id/salary-port", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = z.strictObject({ destination_account_id: z.string().min(1),
      amount_cents: z.number().int().positive(),
      idempotency_key: z.string().min(1).max(128) }).parse(request.body);
    requireDeviceProof(access, request.headers, `/accounts/${id}/salary-port`, body);
    return accounts.portSalary(customer, id, body.destination_account_id,
      body.amount_cents, body.idempotency_key);
  });
  app.get("/accounts/:id/salary-portability", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    return accounts.salaryPortabilityInstruction(customer, id) ??
      { account_id: id, destination_account_id: null, updated_at: null };
  });
  app.post("/accounts/:id/salary-portability", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = z.strictObject({ destination_account_id: z.string().min(1).nullable() })
      .parse(request.body);
    requireDeviceProof(access, request.headers, `/accounts/${id}/salary-portability`, body);
    return accounts.setSalaryPortabilityInstruction(customer, id,
      body.destination_account_id);
  });
  app.get("/accounts/closed-credits", async (request) => {
    const customer = principal(request.headers.authorization);
    const { after } = z.strictObject({ after: z.coerce.number().int().min(0).optional() })
      .parse(request.query);
    return bank.closedAccountCredits(customer, after);
  });
  app.post("/accounts/closed-credits/:id/claim", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access))
      throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const { destination_account_id } = z.strictObject({ destination_account_id: z.string().min(1) })
      .parse(request.body);
    requireDeviceProof(access, request.headers,
      `/accounts/closed-credits/${id}/claim`, { destination_account_id });
    return bank.claimClosedAccountCredit(customer, id, destination_account_id);
  });
  app.post("/accounts/:id/close", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access))
      throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    if (bank.ownAccount(customer, id).status !== "active" ||
      bank.customer(customer).status !== "active")
      throw new BankError("DEF_ACCOUNT_FROZEN");
    requireDeviceProof(access, request.headers, `/accounts/${id}/close`, undefined);
    const account = accountLifecycle.transition(id, "closed", customer);
    return { id: account.id, status: account.status };
  });
  app.get("/accounts/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const account = bank.ownAccount(customer, id);
    return { id: account.id, kind: account.kind, ispb: JACARANDA_ISPB,
      branch_code: account.branch_code, account_number: account.account_number,
      account_digit: account.account_digit, balance_cents: account.balance_cached,
      available_balance_cents: bank.availableBalance(id),
      overdraft_limit_cents: account.overdraft_limit, daily_pix_limit_cents: bank.pixDailyLimit(customer),
      status: account.status };
  });
  app.post("/accounts/limits/recompute", async (request) => {
    const customer = principal(request.headers.authorization);
    requireDeviceProof(request.headers.authorization!.slice(7), request.headers,
      "/accounts/limits/recompute", undefined);
    return dynamicLimits.recompute(customer);
  });
  app.get("/accounts/:id/statement", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const query = z.strictObject({ from: z.iso.datetime().optional(), to: z.iso.datetime().optional(),
      limit: z.coerce.number().int().min(1).max(100).optional() }).parse(request.query);
    if (options.labStatementUnavailable?.(customer, id)) {
      bank.ownAccount(customer, id);
      bank.log({ actor: customer, kind: "statement_own", customerId: customer,
        accountId: id, route: "statement", status: 503 });
      return reply.code(503).send({ error: "BIZ_STATEMENT_UNAVAILABLE" });
    }
    return bank.statement(id, customer, query.limit ?? 20, query.from, query.to);
  });
  function submitKyc(customer: string, tier: 2 | 3, reply: FastifyReply) {
    if (options.labKycSubmissionUnavailable?.(customer)) {
      bank.log({ actor: customer, kind: "kyc_submission_own", customerId: customer,
        route: "kyc_submission", status: 503 });
      return reply.code(503).send({ error: "BIZ_KYC_SUBMISSION_UNAVAILABLE" });
    }
    return bank.transaction(() => {
      bank.submitKyc(customer, tier);
      bank.log({ actor: customer, kind: "kyc_submission_own", customerId: customer,
        route: "kyc_submission", status: 200 });
      return { status: "submitted" };
    });
  }
  app.post("/kyc/upgrade", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const body = kycBody.parse(request.body);
    requireDeviceProof(request.headers.authorization!.slice(7), request.headers, "/kyc/upgrade", body);
    return submitKyc(customer, body.tier, reply);
  });
  app.post("/kyc/documents", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const body = kycBody.parse(request.body);
    requireDeviceProof(request.headers.authorization!.slice(7), request.headers, "/kyc/documents", body);
    return submitKyc(customer, body.tier, reply);
  });
  app.get("/kyc/status", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    if (options.labKycStatusUnavailable?.(customer)) {
      bank.log({ actor: customer, kind: "kyc_status_own", customerId: customer,
        route: "kyc_status", status: 503 });
      return reply.code(503).send({ error: "BIZ_KYC_STATUS_UNAVAILABLE" });
    }
    const identity = bank.customer(customer);
    bank.log({ actor: customer, kind: "kyc_status_own", customerId: customer,
      route: "kyc_status", status: 200 });
    return { tier: identity.kyc_tier, status: identity.kyc_status };
  });
  app.get("/customers/me", async (request) => accounts.contact(principal(request.headers.authorization)));
  app.patch("/customers/me", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    const patch = z.strictObject({ email: z.email().optional(), phone: z.string().optional() }).parse(request.body);
    requireDeviceProof(access, request.headers, "/customers/me", patch, "PATCH");
    return accounts.updateContact(customer, patch, device.id);
  });
  app.post("/pix/keys", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const body = keyBody.parse(request.body);
    requireDeviceProof(access, request.headers, "/pix/keys", body);
    return bank.registerPixKey(customer, body.account_id, body.key);
  });
  app.post("/pix/keys/:id/deregister", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/keys/${id}/deregister`, undefined);
    return bank.deregisterPixKey(customer, id);
  });
  app.get("/pix/keys/:key", async (request) => {
    principal(request.headers.authorization);
    const { key } = z.strictObject({ key: z.string().min(1).max(256) }).parse(request.params);
    const external = bank.isSeparatedEcosystem ?
      await options.pixCoordinator!.lookupExternalKey(key, bank.now()) : undefined;
    return bank.lookupPixKey(key, request.headers.authorization ?? "direct",
      principal(request.headers.authorization), external);
  });
  app.get("/pix/keys/lookup", async (request) => {
    principal(request.headers.authorization);
    const { key } = z.strictObject({ key: z.string().min(1).max(256) }).parse(request.query);
    const external = bank.isSeparatedEcosystem ?
      await options.pixCoordinator!.lookupExternalKey(key, bank.now()) : undefined;
    return bank.lookupPixKey(key, request.headers.authorization ?? "direct",
      principal(request.headers.authorization), external);
  });
  app.post("/pix/keys/claims", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const body = keyClaimBody.parse(request.body);
    requireDeviceProof(access, request.headers, "/pix/keys/claims", body);
    return bank.requestPixKeyClaim(customer, body.to_account, body.key, body.kind);
  });
  app.get("/pix/keys/claims/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    return bank.pixKeyClaim(customer, id);
  });
  app.post("/pix/keys/claims/:id/verify", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = z.strictObject({ code: z.string().regex(/^\d{6}$/) }).parse(request.body);
    requireDeviceProof(access, request.headers, `/pix/keys/claims/${id}/verify`, body);
    return bank.verifyPixKeyClaim(customer, id, body.code);
  });
  app.post("/pix/keys/claims/:id/reissue", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/keys/claims/${id}/reissue`, undefined);
    return bank.reissuePixKeyClaimProof(customer, id);
  });
  app.post("/pix/keys/claims/:id/complete", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/keys/claims/${id}/complete`, undefined);
    return bank.completePixKeyClaim(customer, id);
  });
  app.post("/pix/keys/claims/:id/close", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/keys/claims/${id}/close`, undefined);
    return bank.closePixKeyClaim(customer, id);
  });
  app.get("/pix/limits/night", async (request) =>
    bank.pixNightSettings(principal(request.headers.authorization)));
  app.post("/pix/limits/night", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const body = pixNightLimitBody.parse(request.body);
    requireDeviceProof(access, request.headers, "/pix/limits/night", body);
    return "night_limit_cents" in body
      ? bank.requestPixNightSetting(customer, "night_limit_cents", body.night_limit_cents)
      : bank.requestPixNightSetting(customer, "night_start_hour", body.night_start_hour);
  });
  app.get("/pix/limits/channels/:channel", async (request) => {
    const customer = principal(request.headers.authorization);
    const { channel } = z.strictObject({ channel: z.enum(["app", "scheduled"]) })
      .parse(request.params);
    return bank.pixChannelLimit(customer, channel);
  });
  app.post("/pix/limits/channels/:channel", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const { channel } = z.strictObject({ channel: z.enum(["app", "scheduled"]) })
      .parse(request.params);
    const body = z.strictObject({ daily_limit_cents: z.number().int().min(0) })
      .parse(request.body);
    requireDeviceProof(access, request.headers, `/pix/limits/channels/${channel}`, body);
    return bank.requestPixChannelLimit(customer, channel, body.daily_limit_cents);
  });
  app.post("/pix/transfers", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const body = pixBody.parse(request.body);
    bank.ownAccount(customer, body.from_account);
    const amount = "amount" in body ? parseDecimalCents(body.amount) : body.amount_cents;
    const steppedUp = auth.hasStepUp(access);
    if (bank.requiresPixStepUp(body.from_account, body.to_account, amount) && !steppedUp)
      throw new BankError("DEF_STEP_UP_REQUIRED");
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    requireDeviceProof(access, request.headers, "/pix/transfers", body);
    const input = { from: body.from_account, to: body.to_account, amount,
      idempotencyKey: body.idempotency_key, actor: customer, deviceId: device.id,
      stepUpVerified: steppedUp };
    if (bank.isSeparatedEcosystem) {
      const internal = bank.db.prepare(`SELECT 1 FROM accounts
        WHERE id=? AND customer_id IS NOT NULL`).get(body.to_account);
      const result = internal ? await options.pixCoordinator!.transferInternal(input) :
        await options.pixCoordinator!.enqueue(input);
      if (result.status === "in_processing") reply.code(202);
      return result;
    }
    if (bank.spi.account(body.to_account)) {
      const result = bank.enqueueExternalPix(input);
      if (result.status === "in_processing") reply.code(202);
      return result;
    }
    return bank.transferPixWithRace(input);
  });
  app.get("/pix/transfers", async (request) => {
    const customer = principal(request.headers.authorization);
    const query = z.strictObject({ limit: z.coerce.number().int().min(1).max(100).optional(),
      before: z.string().min(1).optional() }).parse(request.query);
    let cursor: { initiated_at: string; id: string } | undefined;
    if (query.before) {
      cursor = bank.db.prepare(`SELECT p.initiated_at,p.id FROM pix_transfers p
        JOIN accounts a ON a.id=p.from_account WHERE p.id=? AND a.customer_id=?`)
        .get(query.before, customer) as { initiated_at: string; id: string } | undefined;
      if (!cursor) throw new BankError("DEF_NOT_FOUND");
    }
    return bank.db.prepare(`SELECT p.id,p.end_to_end_id,p.from_account,p.to_account,
      p.amount,p.status,p.initiated_at,p.settled_at,m.id med_case_id,m.status med_status,
      CASE WHEN p.spi_command_version=2 AND p.status<>'rejected'
        THEN CASE WHEN o.acknowledged_at IS NULL THEN 'pending' ELSE 'credited' END
        ELSE NULL END psp_credit_status
      FROM pix_transfers p JOIN accounts a ON a.id=p.from_account
      LEFT JOIN med_cases m ON m.transfer_id=p.id
      LEFT JOIN pix_psp_inbound_outbox o ON o.transfer_id=p.id
      WHERE a.customer_id=? AND (? IS NULL OR p.initiated_at<? OR
        (p.initiated_at=? AND p.id<?))
      ORDER BY p.initiated_at DESC,p.id DESC LIMIT ?`)
      .all(customer, cursor?.id ?? null, cursor?.initiated_at ?? null,
        cursor?.initiated_at ?? null, cursor?.id ?? null, query.limit ?? 20);
  });
  app.get("/risk/decisions", async (request) => {
    const customer = principal(request.headers.authorization);
    const query = z.strictObject({ limit: z.coerce.number().int().min(1).max(100).optional() })
      .parse(request.query);
    const rows = bank.db.prepare(`SELECT id,area,entity_id,amount_cents,score,outcome,
      reason_codes_json,trace_id,created_at FROM risk_decisions WHERE customer_id=?
      ORDER BY created_at DESC,id DESC LIMIT ?`).all(customer, query.limit ?? 20) as
      { id: string; area: string; entity_id: string; amount_cents: number;
        score: number; outcome: string; reason_codes_json: string; trace_id: string;
        created_at: string }[];
    return rows.map(({ reason_codes_json, ...row }) => ({ ...row,
      reason_codes: JSON.parse(reason_codes_json) as string[] }));
  });
  app.get("/risk/holds", async (request) => {
    const customer = principal(request.headers.authorization);
    bank.expireRiskPixHolds();
    return bank.db.prepare(`SELECT h.id,h.from_account,h.to_account,h.amount_cents,
      h.status,h.created_at,h.expires_at,h.resolved_at
      FROM risk_pix_holds h JOIN accounts a ON a.id=h.from_account
      WHERE a.customer_id=? ORDER BY h.created_at DESC,h.id DESC LIMIT 100`)
      .all(customer);
  });
  app.post("/pix/med", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const body = medBody.parse(request.body);
    requireDeviceProof(access, request.headers, "/pix/med", body);
    const result = bank.isSeparatedEcosystem ?
      options.pixCoordinator!.requestMed(customer, body.transfer_id) :
      bank.requestMed(customer, body.transfer_id);
    if (result.status === "opening") reply.code(202);
    return result;
  });
  app.get("/pix/med/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const row = bank.db.prepare(`SELECT m.id,m.transfer_id,p.from_account,p.to_account,m.status,m.opened_at,m.resolve_after,
      m.refunded_cents,m.unrecovered_cents,
      d.decision review_decision,
      COALESCE(m.claim_amount_cents,p.amount) claim_amount_cents
      FROM med_cases m JOIN pix_transfers p ON p.id=m.transfer_id
      LEFT JOIN med_decisions d ON d.case_id=m.id
      WHERE m.id=? AND m.customer_id=?`)
      .get(id, customer) as { id: string; transfer_id: string; from_account: string; to_account: string; status: string;
        opened_at: string; resolve_after: string; refunded_cents: number;
        unrecovered_cents: number; claim_amount_cents: number;
        review_decision: "approved" | "rejected" | null } | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    const { review_decision, from_account, to_account, ...details } = row;
    const compensation = row.status === "resolved" ? readMedIncidentCompensation(bank.db, {
      caseId: row.id, sourceAccount: from_account, amount: row.unrecovered_cents,
    }) : undefined;
    const customerCase = { ...details,
      ...(compensation ? { bank_compensated_cents: compensation.amount } : {}) };
    const reviewState = row.status === "opening" ? "opening_psp" :
      row.status === "rejection_pending_psp" ? "rejection_pending_psp" :
      row.status === "settlement_pending_psp" ? "settlement_pending_psp" :
      row.status === "open" ? review_decision === "approved" ?
      row.resolve_after <= bank.now().toISOString() ? "approved_overdue_settlement" :
        "approved_pending_settlement" :
      row.resolve_after <= bank.now().toISOString() ? "review_overdue" : "awaiting_review" :
      row.status === "rejected" ? "rejected" : "complete";
    if (bank.isSeparatedEcosystem) {
      if (["opening", "rejection_pending_psp", "settlement_pending_psp"]
        .includes(row.status))
        return { ...customerCase, review_state: reviewState, hops: [], path: [] };
      const bankHops = bank.db.prepare(`SELECT id,case_id,root_transfer_id,account_id,
        blocked_cents,refunded_cents,created_at,released_at
        FROM med_hops WHERE case_id=? ORDER BY id`).all(id);
      const external = !bank.db.prepare("SELECT 1 FROM accounts WHERE id=?")
        .get(to_account);
      if (!external) {
        if (bankHops.length) throw new BankError("INTEGRITY_MED_HOP_MIRROR");
        return { ...customerCase, review_state: reviewState, hops: [], path: [] };
      }
      const projection = await options.pixCoordinator!.medCaseProjection(id, row.transfer_id);
      const mirror = projection.hops.map(({ ispb: _ispb, ...hop }) => hop);
      if (JSON.stringify(bankHops) !== JSON.stringify(mirror))
        throw new BankError("INTEGRITY_MED_HOP_MIRROR");
      return { ...customerCase, review_state: reviewState,
        hops: projection.hops.map(({ ispb, blocked_cents, refunded_cents }) =>
          ({ ispb, blocked_cents, refunded_cents })), path: projection.path };
    }
    const hops = bank.db.prepare(`SELECT a.ispb,h.blocked_cents,h.refunded_cents
      FROM med_hops h JOIN psp_accounts a ON a.id=h.account_id
      WHERE h.case_id=? ORDER BY h.id`).all(id);
    return { ...customerCase, review_state: reviewState,
      hops, path: bank.psp.path(row.transfer_id) };
  });
  app.post("/pix/scheduled", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const body = scheduleBody.parse(request.body);
    bank.ownAccount(customer, body.from_account);
    if (bank.requiresPixStepUp(body.from_account, body.to_account, body.amount_cents) &&
      !auth.hasStepUp(access))
      throw new BankError("DEF_STEP_UP_REQUIRED");
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    requireDeviceProof(access, request.headers, "/pix/scheduled", body);
    return scheduled.schedule(customer, body.from_account, body.to_account, body.amount_cents,
      body.execute_at, body.frequency, device.id);
  });
  app.get("/pix/scheduled/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    return scheduled.job(customer, id);
  });
  app.post("/pix/scheduled/:id/reauthorize", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/scheduled/${id}/reauthorize`, undefined);
    return scheduled.reauthorize(customer, id, device.id);
  });
  app.post("/pix/scheduled/:id/cancel", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/scheduled/${id}/cancel`, undefined);
    scheduled.cancel(customer, id);
    return { status: "cancelled" };
  });
  app.post("/pix/automatic/offers", async (request) => {
    const merchant = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access))
      throw new BankError("DEF_STEP_UP_REQUIRED");
    const body = automaticOfferBody.parse(request.body);
    requireDeviceProof(access, request.headers, "/pix/automatic/offers", body);
    return automatic.createOffer(merchant, body.merchant_account,
      body.max_amount_cents, body.frequency, body.starts_at, body.ends_at,
      body.post_due_retry_allowed);
  });
  app.get("/pix/automatic/offers/:id", async (request) => {
    principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const { merchant_customer_id: _merchantCustomerId, ...terms } = automatic.offer(id);
    return terms;
  });
  app.post("/pix/automatic/offers/:id/revoke", async (request) => {
    const merchant = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access))
      throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/automatic/offers/${id}/revoke`, undefined);
    return automatic.revokeOffer(merchant, id);
  });
  app.post("/pix/automatic/mandates", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    const body = automaticMandateBody.parse(request.body);
    requireDeviceProof(access, request.headers, "/pix/automatic/mandates", body);
    return automatic.grant(customer, body.from_account, body.merchant_account,
      body.max_amount_cents, body.frequency, body.starts_at, body.ends_at, device.id,
      body.offer_id);
  });
  app.get("/pix/automatic/mandates", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    if (options.labPixAutomaticMandatesUnavailable?.(customer)) {
      bank.log({ actor: customer, kind: "pix_automatic_mandates_own", customerId: customer,
        route: "pix_automatic_mandates", status: 503 });
      return reply.code(503).send({ error: "BIZ_PIX_AUTOMATIC_MANDATES_UNAVAILABLE" });
    }
    const mandates = automatic.list(customer);
    bank.log({ actor: customer, kind: "pix_automatic_mandates_own", customerId: customer,
      route: "pix_automatic_mandates", status: 200 });
    return mandates;
  });
  app.get("/pix/automatic/notifications", async (request) => {
    const customer = principal(request.headers.authorization);
    const query = z.strictObject({ before: z.string().min(1).max(128).optional(),
      limit: z.coerce.number().int().min(1).max(100).optional() }).parse(request.query);
    return automatic.notifications(customer, query);
  });
  app.get("/incidents/notices", async (request) => {
    const customer = principal(request.headers.authorization);
    const query = z.strictObject({ before: z.coerce.number().int().positive().optional(),
      limit: z.coerce.number().int().min(1).max(100).optional() }).parse(request.query);
    return listIncidentNotices(bank.db, customer, query.before, query.limit);
  });
  app.get("/pix/automatic/limits/:accountId", async (request) => {
    const customer = principal(request.headers.authorization);
    const { accountId } = z.strictObject({ accountId: z.string().min(1) }).parse(request.params);
    return bank.pixAutomaticLimit(customer, accountId);
  });
  app.post("/pix/automatic/limits/:accountId", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access))
      throw new BankError("DEF_STEP_UP_REQUIRED");
    const { accountId } = z.strictObject({ accountId: z.string().min(1) }).parse(request.params);
    const body = z.strictObject({ daily_limit_cents: z.number().int()
      .min(0).max(2_000_000) }).parse(request.body);
    requireDeviceProof(access, request.headers, `/pix/automatic/limits/${accountId}`, body);
    return bank.requestPixAutomaticLimit(customer, accountId, body.daily_limit_cents);
  });
  app.get("/pix/automatic/mandates/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    return automatic.mandate(customer, id);
  });
  app.post("/pix/automatic/mandates/:id/revoke", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/automatic/mandates/${id}/revoke`, undefined);
    return automatic.revoke(customer, id);
  });
  app.post("/pix/automatic/mandates/:id/migrate", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = z.strictObject({ offer_id: z.string().min(1) }).parse(request.body);
    requireDeviceProof(access, request.headers, `/pix/automatic/mandates/${id}/migrate`, body);
    return automatic.migrateLegacyMandate(customer, id, body.offer_id, device.id);
  });
  app.get("/pix/automatic/mandates/:id/charges", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    return automatic.charges(customer, id);
  });
  app.post("/pix/automatic/mandates/:id/charges", async (request) => {
    const merchant = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = automaticChargeBody.parse(request.body);
    requireDeviceProof(access, request.headers, `/pix/automatic/mandates/${id}/charges`, body);
    return automatic.charge(merchant, id, body.amount_cents, body.due_at);
  });
  app.post("/pix/automatic/charges/:id/reauthorize", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/automatic/charges/${id}/reauthorize`, undefined);
    return automatic.reauthorize(customer, id, device.id);
  });
  app.post("/pix/automatic/charges/:id/cancel", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/automatic/charges/${id}/cancel`, undefined);
    return automatic.cancelCharge(customer, id);
  });
  app.post("/pix/automatic/charges/:id/merchant-cancel", async (request) => {
    const merchant = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/pix/automatic/charges/${id}/merchant-cancel`, undefined);
    return automatic.cancelMerchantCharge(merchant, id);
  });
  app.post("/pix/automatic/charges/:id/retry", async (request) => {
    const merchant = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = automaticRetryBody.parse(request.body);
    requireDeviceProof(access, request.headers, `/pix/automatic/charges/${id}/retry`, body);
    return automatic.retryCharge(merchant, id, body.due_at);
  });
  app.post("/pix/proximity/tokens", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const body = z.strictObject({ from_account: z.string().min(1), to_account: z.string().min(1),
      amount_cents: z.number().int().positive() }).parse(request.body);
    requireDeviceProof(access, request.headers, "/pix/proximity/tokens", body);
    return proximity.issue(customer, body.from_account, body.to_account, body.amount_cents);
  });
  app.post("/pix/proximity/redeem", async (request) => {
    const customer = principal(request.headers.authorization);
    const body = z.strictObject({ token: z.string().min(1), to_account: z.string().min(1),
      amount_cents: z.number().int().positive() }).parse(request.body);
    const access = request.headers.authorization!.slice(7);
    requireDeviceProof(access, request.headers, "/pix/proximity/redeem", body);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return proximity.redeem(customer, body.token, body.to_account, body.amount_cents,
      { deviceId: device.id, stepUpVerified: auth.hasStepUp(access) });
  });
  app.get("/pix/transfers/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const row = bank.db.prepare(`SELECT p.id,p.end_to_end_id,p.from_account,p.to_account,
      p.amount,p.status,p.initiated_at,p.settled_at,
      CASE WHEN p.spi_command_version=2 AND p.status<>'rejected'
        THEN CASE WHEN o.acknowledged_at IS NULL THEN 'pending' ELSE 'credited' END
        ELSE NULL END psp_credit_status
      FROM pix_transfers p LEFT JOIN pix_psp_inbound_outbox o ON o.transfer_id=p.id
      WHERE p.id=?`).get(id) as { id: string; end_to_end_id: string; from_account: string; to_account: string;
        amount: number; status: string; initiated_at: string; settled_at: string;
        psp_credit_status: "pending" | "credited" | null } | undefined;
    if (!row || !bank.db.prepare(`SELECT 1 FROM accounts WHERE id IN (?,?)
      AND customer_id=? LIMIT 1`).get(row.from_account, row.to_account, customer))
      throw new BankError("DEF_NOT_FOUND");
    const status_history = bank.db.prepare(`SELECT status,changed_at,reason FROM pix_status_history
      WHERE transfer_id=? ORDER BY id`).all(id);
    const returns = bank.db.prepare(`SELECT id,amount,reason,status,created_at FROM pix_returns
      WHERE transfer_id=? ORDER BY created_at,id`).all(id);
    const spi_messages = bank.isSeparatedEcosystem ?
      await options.pixCoordinator!.paymentMessages(row.end_to_end_id) :
      bank.spi.messages(row.end_to_end_id);
    return { ...row, status_history, spi_messages, returns };
  });
  app.get("/cards", async (request) => cards.list(principal(request.headers.authorization)));
  app.get("/cards/credit", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    reply.header("Cache-Control", "no-store");
    return creditCards.list(customer).map(({ policy_json, ...account }) => ({ ...account,
      policy: JSON.parse(policy_json) as unknown,
      outstanding_cents: creditCards.outstanding(customer, account.id),
      available_limit_cents: creditCards.availableLimit(customer, account.id) }));
  });
  app.get("/cards/credit/:id", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    const { policy_json, ...account } = creditCards.account(customer, id);
    reply.header("Cache-Control", "no-store");
    return { ...account, policy: JSON.parse(policy_json) as unknown,
      outstanding_cents: creditCards.outstanding(customer, id),
      available_limit_cents: creditCards.availableLimit(customer, id) };
  });
  app.get("/cards/credit/:id/statements", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    reply.header("Cache-Control", "no-store");
    return creditCards.statements(customer, id);
  });
  app.get("/cards/credit/:id/statements/:statementId", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const { id, statementId } = z.strictObject({ id: z.string().min(1).max(128),
      statementId: z.string().min(1).max(128) }).parse(request.params);
    const statement = creditCards.statement(customer, statementId);
    if (statement.credit_id !== id) throw new BankError("DEF_NOT_FOUND");
    reply.header("Cache-Control", "no-store");
    return { ...statement, state: creditCards.statementState(customer, statementId) };
  });
  app.post("/cards/credit/:id/statements/:statementId/pay", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id, statementId } = z.strictObject({ id: z.string().min(1).max(128),
      statementId: z.string().min(1).max(128) }).parse(request.params);
    const body = creditPaymentBody.parse(request.body);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    requireDeviceProof(access, request.headers,
      `/cards/credit/${id}/statements/${statementId}/pay`, body);
    return creditCards.pay(customer, id, statementId, body.source_account_id,
      body.amount_cents, body.idempotency_key);
  });
  app.post("/cards/credit/:id/statements/:statementId/installment-plan", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id, statementId } = z.strictObject({ id: z.string().min(1).max(128),
      statementId: z.string().min(1).max(128) }).parse(request.params);
    const body = creditPlanBody.parse(request.body);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    requireDeviceProof(access, request.headers,
      `/cards/credit/${id}/statements/${statementId}/installment-plan`, body);
    return creditCards.installmentStatement(customer, id, statementId, body.installments);
  });
  app.post("/cards", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const body = issueCardBody.parse(request.body);
    requireDeviceProof(access, request.headers, "/cards", body);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return cards.issueDebit(customer, body.account_id, body.limit_cents, device.id);
  });
  app.post("/cards/:id/virtual", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = virtualCardBody.parse(request.body);
    requireDeviceProof(access, request.headers, `/cards/${id}/virtual`, body);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return cards.createVirtual(customer, id, body.limit_cents, body.expires_at, device.id);
  });
  app.post("/cards/:id/temporary", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = z.strictObject({ limit_cents: z.number().int().positive() }).parse(request.body);
    requireDeviceProof(access, request.headers, `/cards/${id}/temporary`, body);
    const { limit_cents } = body;
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return cards.createTemporaryVirtual(customer, id, limit_cents, device.id);
  });
  app.get("/cards/:id/cvv", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    if (!auth.hasStepUp(access))
      throw new BankError("DEF_STEP_UP_REQUIRED");
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const card = cards.ownCard(customer, id);
    if (card.kind !== "virtual" || card.status !== "active") throw new BankError("DEF_NOT_FOUND");
    requireDeviceProof(access, request.headers, `/cards/${id}/cvv`, undefined, "GET");
    reply.header("Cache-Control", "no-store");
    return { cvv: cards.vault.currentCvv(id), expires_at: new Date(
      (Math.floor(bank.now().getTime() / 900_000) + 1) * 900_000).toISOString() };
  });
  app.get("/cards/:id/wallet-tokens", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    reply.header("Cache-Control", "no-store");
    return cardNetwork.walletTokens(customer, id);
  });
  app.post("/cards/:id/wallet-tokens", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    const body = z.strictObject({}).parse(request.body ?? {});
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    requireDeviceProof(access, request.headers, `/cards/${id}/wallet-tokens`, body);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    reply.header("Cache-Control", "no-store");
    return cardNetwork.issueWalletToken(customer, id, device.id);
  });
  app.post("/cards/wallet-tokens/:id/revoke", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    requireDeviceProof(access, request.headers, `/cards/wallet-tokens/${id}/revoke`, undefined);
    return cardNetwork.revokeWalletToken(customer, id);
  });
  app.get("/cards/:id/recurring", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    reply.header("Cache-Control", "no-store");
    return cardRecurring.list(customer, id);
  });
  app.post("/cards/:id/recurring", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    const body = z.strictObject({ merchant_id: z.string().min(1).max(128),
      amount_cents: z.number().int().positive().max(2_000_000),
      frequency: z.enum(["weekly", "monthly"]), starts_at: z.iso.datetime(),
      ends_at: z.iso.datetime().optional(),
      idempotency_key: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/) }).parse(request.body);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    requireDeviceProof(access, request.headers, `/cards/${id}/recurring`, body);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return cardRecurring.create(customer, device.id, { cardId: id,
      merchantId: body.merchant_id, amountCents: body.amount_cents,
      frequency: body.frequency, startsAt: body.starts_at,
      ...(body.ends_at === undefined ? {} : { endsAt: body.ends_at }),
      idempotencyKey: body.idempotency_key });
  });
  app.get("/cards/recurring/:id", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    reply.header("Cache-Control", "no-store");
    return cardRecurring.mandate(customer, id);
  });
  app.get("/cards/recurring/:id/charges", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    reply.header("Cache-Control", "no-store");
    return cardRecurring.charges(customer, id);
  });
  app.post("/cards/recurring/:id/revoke", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    requireDeviceProof(access, request.headers, `/cards/recurring/${id}/revoke`, undefined);
    return cardRecurring.revoke(customer, id);
  });
  app.post("/cards/3ds/challenges", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const body = z.strictObject({ card_id: z.string().min(1).max(128),
      merchant_id: z.string().min(1).max(128),
      amount_cents: z.number().int().positive().max(2_000_000) }).parse(request.body);
    requireDeviceProof(access, request.headers, "/cards/3ds/challenges", body);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return cardNetwork.issueThreeDsChallenge(customer, device.id, body.card_id,
      body.merchant_id, body.amount_cents);
  });
  app.post("/cards/3ds/challenges/:id/complete", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1).max(128) }).parse(request.params);
    const body = z.strictObject({ nonce: z.string().min(1).max(128) }).parse(request.body);
    requireDeviceProof(access, request.headers, `/cards/3ds/challenges/${id}/complete`, body);
    if (!auth.hasStepUp(access)) throw new BankError("DEF_STEP_UP_REQUIRED");
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return cardNetwork.completeThreeDsChallenge(customer, device.id, id, body.nonce);
  });
  if (options.legacyCardAuthorizations) app.post("/cards/authorize", async (request) => {
    requirePartner(request.headers["x-partner-key"] as string | undefined);
    const body = z.strictObject({ card_id: z.string().min(1), merchant_id: z.string().min(1).max(128),
      amount_cents: z.number().int().positive() }).parse(request.body);
    return cards.authorize(body.card_id, body.merchant_id, body.amount_cents);
  });
  app.post("/cards/network/authorize", async (request) => {
    requirePartner(request.headers["x-partner-key"] as string | undefined);
    const body = z.strictObject({ card_id: z.string().min(1).max(128), merchant_id: z.string().min(1),
      amount_cents: z.number().int().positive(),
      entry_mode: z.enum(["chip", "contactless", "ecommerce"]),
      eci: z.string().max(2).optional(), cvv: z.string().regex(/^\d{3}$/),
      installments: z.number().int().min(1).max(24).optional(),
      three_ds_challenge_id: z.string().min(1).max(128).optional() }).parse(request.body);
    return cardNetwork.authorize({ cardId: body.card_id, merchantId: body.merchant_id,
      amountCents: body.amount_cents, entryMode: body.entry_mode,
      ...(body.eci === undefined ? {} : { eci: body.eci }), cvv: body.cvv,
      ...(body.installments === undefined ? {} : { installments: body.installments }),
      ...(body.three_ds_challenge_id === undefined ? {} :
        { threeDsChallengeId: body.three_ds_challenge_id }) });
  });
  app.post("/cards/network/wallet/authorize", async (request) => {
    requirePartner(request.headers["x-partner-key"] as string | undefined);
    const body = z.strictObject({ dpan: z.string().regex(/^\d{16}$/),
      merchant_id: z.string().min(1).max(128),
      amount_cents: z.number().int().positive().max(2_000_000),
      nonce: z.string().regex(/^[A-Za-z0-9_-]{12,64}$/),
      cryptogram: z.string().regex(/^[a-f0-9]{64}$/),
      installments: z.number().int().min(1).max(24).optional() }).parse(request.body);
    return cardNetwork.authorizeWallet({ dpan: body.dpan,
      merchantId: body.merchant_id, amountCents: body.amount_cents,
      nonce: body.nonce, cryptogram: body.cryptogram,
      ...(body.installments === undefined ? {} : { installments: body.installments }) });
  });
  app.post("/cards/network/:id/capture", async (request) => {
    requirePartner(request.headers["x-partner-key"] as string | undefined);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const { amount_cents } = z.strictObject({ amount_cents: z.number().int().positive() })
      .parse(request.body);
    return cardNetwork.capture(id, amount_cents);
  });
  app.post("/cards/network/:id/clearing", async (request) => {
    requirePartner(request.headers["x-partner-key"] as string | undefined);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const { amount_cents } = z.strictObject({ amount_cents: z.number().int().positive() })
      .parse(request.body);
    cardNetwork.queueCapture(id, amount_cents);
    return { queued: true };
  });
  app.post("/cards/network/:id/reverse", async (request) => {
    requirePartner(request.headers["x-partner-key"] as string | undefined);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    return cardNetwork.reverse(id);
  });
  app.get("/cards/network/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const authorization = cardNetwork.authorization(id);
    cards.ownCard(customer, authorization.card_id);
    return { ...authorization, messages: cardNetwork.messages(id) };
  });
  app.post("/cards/network/:id/dispute", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = z.strictObject({ amount_cents: z.number().int().positive(),
      reason_code: z.enum(["fraud", "merchant_dispute", "goods_not_received"]).optional() }).parse(request.body);
    requireDeviceProof(request.headers.authorization!.slice(7), request.headers,
      `/cards/network/${id}/dispute`, body);
    return cardNetwork.openDispute(customer, id, body.amount_cents, body.reason_code);
  });
  app.get("/cards/disputes/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const dispute = cardNetwork.dispute(id);
    if (dispute.customer_id !== customer) throw new BankError("DEF_NOT_FOUND");
    return dispute;
  });
  app.post("/cards/disputes/:id/advance", async (request) => {
    requirePartner(request.headers["x-partner-key"] as string | undefined);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const { stage } = z.strictObject({ stage: z.enum(["representment", "pre_arbitration"]) })
      .parse(request.body);
    return cardNetwork.advanceDispute(id, stage);
  });
  app.post("/cards/disputes/:id/resolve", async (request) => {
    requirePartner(request.headers["x-partner-key"] as string | undefined);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const { winner } = z.strictObject({ winner: z.enum(["customer", "merchant"]) })
      .parse(request.body);
    return cardNetwork.resolveDispute(id, winner);
  });
  app.post("/cards/refund", async (request) => {
    requirePartner(request.headers["x-partner-key"] as string | undefined);
    const body = z.strictObject({ authorization_id: z.string().min(1), target_card_id: z.string().min(1),
      amount_cents: z.number().int().positive() }).parse(request.body);
    return cards.refund(body.authorization_id, body.target_card_id, body.amount_cents);
  });
  app.patch("/cards/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = cardPatchBody.parse(request.body);
    requireDeviceProof(access, request.headers, `/cards/${id}`, body, "PATCH");
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return cards.update(customer, id, body, device.id);
  });
  app.get("/loans/offers", async (request, reply) => {
    const customer = principal(request.headers.authorization);
    if (options.labLoanOfferUnavailable?.(customer)) {
      bank.log({ actor: customer, kind: "loan_offer_own", customerId: customer,
        route: "loans_offers", status: 503 });
      return reply.code(503).send({ error: "BIZ_LOAN_OFFER_UNAVAILABLE" });
    }
    const offer = loans.offer(customer);
    bank.log({ actor: customer, kind: "loan_offer_own", customerId: customer,
      route: "loans_offers", status: 200 });
    return offer;
  });
  app.post("/loans/quote", async (request) => {
    const customer = principal(request.headers.authorization);
    const body = z.strictObject({ offer_id: z.string().min(1),
      amount_cents: z.number().int().positive(),
      method: z.enum(["PRICE", "SAC"]),
      term_months: z.number().int().min(1).max(60) }).parse(request.body);
    return loans.quote(customer, body.offer_id, body.amount_cents, body);
  });
  app.get("/loans", async (request) => loans.list(principal(request.headers.authorization)));
  app.post("/loans", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const body = acceptLoanBody.parse(request.body);
    requireDeviceProof(access, request.headers, "/loans", body);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return loans.accept(customer, body.offer_id, body.account_id, body.amount_cents,
      body.declared_income_cents, device.id,
      { method: body.method ?? "PRICE", term_months: body.term_months ?? 12 });
  });
  app.post("/loans/flash", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const body = z.strictObject({ account_id: z.string().min(1),
      amount_cents: z.number().int().positive().max(100_000) }).parse(request.body);
    requireDeviceProof(access, request.headers, "/loans/flash", body);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return loans.acceptFlash(customer, body.account_id, device.id, body.amount_cents);
  });
  app.get("/loans/:id", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    return loans.loan(customer, id);
  });
  app.get("/loans/:id/contract", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    return loans.contract(customer, id);
  });
  app.post("/loans/:id/installments/:number/pay", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id, number } = z.strictObject({ id: z.string().min(1),
      number: z.coerce.number().int().positive() }).parse(request.params);
    requireDeviceProof(access, request.headers, `/loans/${id}/installments/${number}/pay`, undefined);
    return loans.payInstallment(customer, id, number);
  });
  app.post("/loans/:id/installments/:number/partial-pay", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id, number } = z.strictObject({ id: z.string().min(1),
      number: z.coerce.number().int().positive() }).parse(request.params);
    const body = z.strictObject({ amount_cents: z.number().int().positive(),
      idempotency_key: z.string().min(1).max(128) })
      .parse(request.body);
    requireDeviceProof(access, request.headers,
      `/loans/${id}/installments/${number}/partial-pay`, body);
    return loans.payInstallmentAmount(customer, id, number, body.amount_cents,
      body.idempotency_key);
  });
  app.post("/loans/:id/prepay", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/loans/${id}/prepay`, undefined);
    return loans.prepay(customer, id);
  });
  app.post("/loans/:id/refinance", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(access, request.headers, `/loans/${id}/refinance`, undefined);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return loans.refinance(customer, id, device.id);
  });
  app.post("/loans/:id/renegotiation-quote", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = z.strictObject({ method: z.enum(["PRICE", "SAC"]),
      term_months: z.number().int().min(1).max(60) }).parse(request.body);
    return loans.renegotiationQuote(customer, id, body);
  });
  app.post("/loans/:id/renegotiate", async (request) => {
    const customer = principal(request.headers.authorization);
    const access = request.headers.authorization!.slice(7);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    const body = z.strictObject({ method: z.enum(["PRICE", "SAC"]),
      term_months: z.number().int().min(1).max(60) }).parse(request.body);
    requireDeviceProof(access, request.headers, `/loans/${id}/renegotiate`, body);
    const device = auth.deviceForAccess(access);
    if (!device) throw new BankError("DEF_UNAUTHORIZED");
    return loans.renegotiate(customer, id, device.id, body);
  });
  app.post("/data-sharing/consents", async (request) => {
    const customer = principal(request.headers.authorization);
    const body = z.strictObject({ partner_id: z.string().min(3).max(64),
      scopes: z.array(z.enum(["balance", "statement"])).min(1).max(2) }).parse(request.body);
    requireDeviceProof(request.headers.authorization!.slice(7), request.headers,
      "/data-sharing/consents", body);
    return sharing.grant(customer, body.partner_id, body.scopes);
  });
  app.post("/data-sharing/consents/:id/revoke", async (request) => {
    const customer = principal(request.headers.authorization);
    const { id } = z.strictObject({ id: z.string().min(1) }).parse(request.params);
    requireDeviceProof(request.headers.authorization!.slice(7), request.headers,
      `/data-sharing/consents/${id}/revoke`, undefined);
    sharing.revoke(customer, id);
    return { revoked: true };
  });
  app.get("/data-sharing/read", async (request) => {
    const query = z.strictObject({ token: z.string().min(1),
      scope: z.enum(["balance", "statement"]) }).parse(request.query);
    return sharing.read(query.token, query.scope);
  });
  return app;
}
