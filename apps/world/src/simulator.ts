import { createHash, randomUUID, sign } from "node:crypto";
import { Bank, brtHour, parsePixLimits } from "./bank.ts";
import { DEVICE_QUARANTINE_V1, deviceQuarantine } from "./device-quarantine.ts";
import { AuthEngine } from "./auth.ts";
import { Gateway, type GatewayCall, type GatewayResult } from "./gateway.ts";
import { CardsEngine } from "./cards.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "./credit-cards.ts";
import { accountingDates } from "./accounting-dates.ts";
import type { SentinelSummary } from "./sentinels.ts";
import type { Area } from "../../../packages/contracts/src/index.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import { SimulatorDeviceKeys } from "./simulator-device-keys.ts";
import { ensureSyntheticRecipients } from "./seed.ts";

type Persona = "salaried" | "merchant" | "student" | "retiree" | "gig" | "saver" | "night_owl";
interface SimCustomer { id: string; cpf: string; persona: Persona; account_id: string; }
interface Session { access: string; refresh: string; expiresAt: number; }
export interface SimTick { minute: string; ops: number; approved: number; honest_blocked: number;
  false_block_rate: number; by_area: Record<string, number>; pix_deferred?: number; }
export interface SimulatorEcosystem {
  externalRecipients: { id: string; pixKey: string }[];
  dispatchPendingPix: () => Promise<unknown>;
  spiStatus: () => Promise<{ available: boolean; reconciled?: boolean }>;
}
const HOURLY_RATES = [3, 3, 3, 3, 3, 3, 18, 18, 18, 40, 40, 40, 70, 70,
  35, 35, 35, 35, 90, 90, 90, 90, 20, 20];
const SYNTHETIC_REGIONS = ["BR-SP", "BR-RJ", "BR-MG", "BR-PR", "BR-RS", "BR-BA", "BR-PE", "BR-DF"] as const;
export function expectedAreaRate(area: string, now: Date): number {
  const fraction = area === "accounts" ? 0.45 : area === "pix" ? 0.35 :
    area === "cards" || area === "loans" ? 0.10 : 0;
  return (HOURLY_RATES[brtHour(now)] ?? 3) * fraction;
}
function seededRandom(text: string): () => number {
  const digest = createHash("sha256").update(text).digest();
  let state = digest.readUInt32BE(0);
  return () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 0x1_0000_0000; };
}
function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid Twin response");
  return value as Record<string, unknown>;
}
export class CustomerSimulator {
  readonly bank: Bank;
  readonly auth: AuthEngine;
  readonly gateway: Gateway;
  readonly events: EventStore | undefined;
  private readonly partnerKey: string | undefined;
  private readonly cards: CardsEngine | undefined;
  private readonly creditCards: CreditCardsEngine;
  private readonly clockSpeed: number;
  private readonly maxOpsPerTick: number | undefined;
  private lastCreditBillingDate: string | null = null;
  private readonly customers: SimCustomer[];
  private readonly externalRecipients: { id: string; pixKey: string }[];
  private readonly dispatchPendingPix: () => Promise<unknown>;
  private readonly ecosystemStatus: SimulatorEcosystem["spiStatus"] | undefined;
  private readonly sessions = new Map<string, Session>();
  readonly deviceKeys: SimulatorDeviceKeys;
  constructor(bank: Bank, auth: AuthEngine, gateway: Gateway, events?: EventStore,
    partnerKey?: string, deviceKeyPath?: string, clockSpeed = 1,
    ecosystem?: SimulatorEcosystem, excludedCustomerIds: ReadonlySet<string> = new Set(),
    maxOpsPerTick?: number) {
    if (!Number.isFinite(clockSpeed) || clockSpeed <= 0 || clockSpeed > 64)
      throw new Error("SIMULATOR_CLOCK_SPEED_INVALID");
    if (maxOpsPerTick !== undefined &&
      (!Number.isSafeInteger(maxOpsPerTick) || maxOpsPerTick < 1 ||
        maxOpsPerTick > 1_000)) throw new Error("SIMULATOR_OPERATION_LIMIT_INVALID");
    this.bank = bank; this.auth = auth; this.gateway = gateway; this.events = events;
    this.clockSpeed = clockSpeed;
    this.maxOpsPerTick = maxOpsPerTick;
    this.partnerKey = partnerKey;
    this.cards = partnerKey ? new CardsEngine(bank) : undefined;
    this.creditCards = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
    this.deviceKeys = new SimulatorDeviceKeys(deviceKeyPath);
    bank.db.exec(`CREATE TABLE IF NOT EXISTS sim_ticks (
      minute TEXT PRIMARY KEY, ops INTEGER NOT NULL, approved INTEGER NOT NULL,
      honest_blocked INTEGER NOT NULL, false_block_rate REAL NOT NULL, by_area_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sim_deferred_pix (
      minute TEXT NOT NULL, customer_id TEXT NOT NULL, operation_index INTEGER NOT NULL,
      reason TEXT NOT NULL, PRIMARY KEY(minute,customer_id,operation_index)
    );
    CREATE TABLE IF NOT EXISTS sim_blocked_customers (
      minute TEXT NOT NULL, customer_id TEXT NOT NULL, area TEXT NOT NULL DEFAULT 'accounts',
      PRIMARY KEY(minute, customer_id, area)
    );
    CREATE TABLE IF NOT EXISTS sim_risk_labels (
      decision_id TEXT PRIMARY KEY REFERENCES risk_decisions(id),
      label TEXT NOT NULL CHECK(label='honest'),
      source TEXT NOT NULL CHECK(source='customer_simulator_v1'),
      request_id TEXT NOT NULL, labeled_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS sim_risk_labels_no_update BEFORE UPDATE ON sim_risk_labels
      BEGIN SELECT RAISE(ABORT, 'SIM_RISK_LABEL_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS sim_risk_labels_no_delete BEFORE DELETE ON sim_risk_labels
      BEGIN SELECT RAISE(ABORT, 'SIM_RISK_LABEL_IMMUTABLE'); END;
    `);
    const blockedColumns = bank.db.prepare("PRAGMA table_info(sim_blocked_customers)")
      .all() as { name: string }[];
    if (!blockedColumns.some((column) => column.name === "area"))
      bank.db.exec("ALTER TABLE sim_blocked_customers ADD COLUMN area TEXT NOT NULL DEFAULT 'accounts'");
    const candidates = bank.db.prepare(`SELECT c.id,c.cpf,c.persona,MIN(a.id) account_id FROM customers c
      JOIN accounts a ON a.customer_id=c.id WHERE c.status='active' AND a.status='active'
      GROUP BY c.id ORDER BY c.id`).all() as unknown as SimCustomer[];
    this.customers = candidates.filter((row) => !excludedCustomerIds.has(row.id));
    if (this.customers.length < 2) throw new Error("Simulator needs at least two customers");
    if (bank.isSeparatedEcosystem) {
      if (!ecosystem || ecosystem.externalRecipients.length === 0)
        throw new Error("SIMULATOR_ECOSYSTEM_REQUIRED");
      this.externalRecipients = ecosystem.externalRecipients;
      this.dispatchPendingPix = ecosystem.dispatchPendingPix;
      this.ecosystemStatus = ecosystem.spiStatus;
    } else {
      if (ecosystem) throw new Error("SIMULATOR_ECOSYSTEM_MODE_INVALID");
      ensureSyntheticRecipients(bank);
      this.externalRecipients = (bank.db.prepare(`SELECT id,pix_key FROM psp_accounts
        WHERE id LIKE 'psp_sim_%' ORDER BY id`).all() as { id: string; pix_key: string }[])
        .map((row) => ({ id: row.id, pixKey: row.pix_key }));
      this.dispatchPendingPix = async () => { bank.dispatchPendingPix(); };
      this.ecosystemStatus = undefined;
    }
  }
  private ip(customerId: string): string {
    const number = createHash("sha256").update(customerId).digest().readUInt32BE(0);
    return `10.${number >>> 16 & 255}.${number >>> 8 & 255}.${number & 255}`;
  }
  private call(input: GatewayCall): Promise<GatewayResult> {
    return this.gateway.call({ ...input,
      headers: { ...input.headers, "user-agent": "BancoVivoSyntheticClient/1.0" } });
  }
  private bindSyntheticGeo(customerId: string, access: string): void {
    const identity = this.auth.traceIdentityForAccess(access);
    if (!identity || identity.userId !== customerId) throw new Error("Simulator session identity mismatch");
    const number = createHash("sha256").update(customerId).digest().readUInt32BE(0);
    const region = SYNTHETIC_REGIONS[number % SYNTHETIC_REGIONS.length]!;
    const result = this.bank.db.prepare(`UPDATE auth_devices SET synthetic_geo=?
      WHERE id=? AND customer_id=?`).run(region, identity.deviceId, customerId);
    if (result.changes !== 1) throw new Error("Simulator device identity mismatch");
  }
  private async session(customer: SimCustomer): Promise<string> {
    const cached = this.sessions.get(customer.id);
    if (cached && cached.expiresAt > this.bank.now().getTime() + 30_000) return cached.access;
    if (cached) {
      const challenge = await this.call({ method: "POST", path: "/api/v1/auth/refresh/challenge",
        peerIp: this.ip(customer.id), body: { refresh_token: cached.refresh } });
      let proof: { challenge_id: string; signature: string } | undefined;
      if (challenge.status === 200) {
        const offered = object(challenge.body);
        if (offered.proof_required === true) {
          const key = this.deviceKeys.forCustomer(customer.id);
          proof = { challenge_id: String(offered.challenge_id),
            signature: sign(null, Buffer.from(String(offered.message)), key.privateKey)
              .toString("base64url") };
        }
      }
      const refreshed = challenge.status === 200 ? await this.call({ method: "POST",
        path: "/api/v1/auth/refresh", peerIp: this.ip(customer.id),
        body: { refresh_token: cached.refresh, ...proof } }) : challenge;
      if (refreshed.status === 200) {
        const body = object(refreshed.body);
        this.sessions.set(customer.id, { access: String(body.access_token), refresh: String(body.refresh_token),
          expiresAt: Date.parse(String(body.expires_at)) });
        return String(body.access_token);
      }
    }
    const password = `synthetic-${customer.id}-simulator-secret`;
    const hasPassword = this.bank.db.prepare("SELECT 1 FROM auth_passwords WHERE customer_id=?").get(customer.id);
    if (!hasPassword) this.auth.setPassword(customer.id, password);
    const login = await this.call({ method: "POST", path: "/api/v1/auth/login", peerIp: this.ip(customer.id),
      body: { cpf: customer.cpf, password, device_id: `sim-device-${customer.id}` } });
    if (login.status !== 200) throw new Error(`Simulator login failed: ${login.status}`);
    const challengeId = String(object(login.body).challenge_id);
    const message = String(object(login.body).device_proof_message);
    const deviceKey = this.deviceKeys.forCustomer(customer.id);
    const otp = this.auth.simulatedOtp(challengeId, customer.id);
    const verified = await this.call({ method: "POST", path: "/api/v1/auth/otp/verify",
      peerIp: this.ip(customer.id), body: { challenge_id: challengeId, otp,
        device_public_key: deviceKey.publicKey,
        device_signature: sign(null, Buffer.from(message), deviceKey.privateKey).toString("base64url") } });
    if (verified.status !== 200) throw new Error(`Simulator OTP failed: ${verified.status}`);
    const body = object(verified.body);
    const session = { access: String(body.access_token), refresh: String(body.refresh_token),
      expiresAt: Date.parse(String(body.expires_at)) };
    this.bindSyntheticGeo(customer.id, session.access);
    this.sessions.set(customer.id, session);
    return session.access;
  }
  close(): void { this.deviceKeys.close(); }
  async probeOwnStatement(customerId: string, accountId: string):
    Promise<{ status: number; requestId: string }> {
    const customer = this.customers.find((item) => item.id === customerId);
    if (!customer) throw new Error("SIM_STATEMENT_CUSTOMER_UNAVAILABLE");
    this.bank.ownAccount(customerId, accountId);
    const access = await this.session(customer);
    const result = await this.call({ method: "GET",
      path: `/api/v1/accounts/${accountId}/statement`,
      headers: { authorization: `Bearer ${access}` },
      peerIp: this.ip(customer.id) });
    return { status: result.status, requestId: result.request_id };
  }
  async probeOwnLoanOffer(customerId: string):
    Promise<{ status: number; requestId: string }> {
    const customer = this.customers.find((item) => item.id === customerId);
    if (!customer) throw new Error("SIM_LOAN_CUSTOMER_UNAVAILABLE");
    const access = await this.session(customer);
    const result = await this.call({ method: "GET",
      path: "/api/v1/loans/offers",
      headers: { authorization: `Bearer ${access}` },
      peerIp: this.ip(customer.id) });
    return { status: result.status, requestId: result.request_id };
  }
  async probeOwnPixAutomaticMandates(customerId: string):
    Promise<{ status: number; requestId: string }> {
    const customer = this.customers.find((item) => item.id === customerId);
    if (!customer) throw new Error("SIM_PIX_AUTOMATIC_CUSTOMER_UNAVAILABLE");
    const access = await this.session(customer);
    const result = await this.call({ method: "GET",
      path: "/api/v1/pix/automatic/mandates",
      headers: { authorization: `Bearer ${access}` },
      peerIp: this.ip(customer.id) });
    return { status: result.status, requestId: result.request_id };
  }
  async probeOwnKycStatus(customerId: string):
    Promise<{ status: number; requestId: string }> {
    const customer = this.customers.find((item) => item.id === customerId);
    if (!customer) throw new Error("SIM_KYC_CUSTOMER_UNAVAILABLE");
    const access = await this.session(customer);
    const result = await this.call({ method: "GET",
      path: "/api/v1/kyc/status",
      headers: { authorization: `Bearer ${access}` },
      peerIp: this.ip(customer.id) });
    return { status: result.status, requestId: result.request_id };
  }
  async probeOwnKycSubmission(customerId: string): Promise<{ status: number; requestId: string }> {
    const customer = this.customers.find((item) => item.id === customerId);
    if (!customer) throw new Error("SIM_KYC_CUSTOMER_UNAVAILABLE");
    const access = await this.session(customer);
    const headers = { authorization: `Bearer ${access}` };
    const peerIp = this.ip(customer.id);
    const path = "/kyc/documents";
    const body = { tier: 3 };
    const challenge = await this.call({ method: "POST",
      path: "/api/v1/devices/current/operation-challenge", headers, peerIp,
      body: { method: "POST", path, body } });
    if (challenge.status !== 200) throw new Error("SIM_KYC_SUBMISSION_CHALLENGE_FAILED");
    const proof = object(challenge.body);
    const signature = sign(null, Buffer.from(String(proof.message)),
      this.deviceKeys.forCustomer(customer.id).privateKey).toString("base64url");
    const response = await this.call({ method: "POST", path: `/api/v1${path}`, peerIp, body,
      headers: { ...headers, "x-device-challenge": String(proof.challenge_id),
        "x-device-signature": signature } });
    return { status: response.status, requestId: response.request_id };
  }
  private async operation(customer: SimCustomer, recipient: SimCustomer, roll: number, index: number, minute: string): Promise<{ area: string; result: GatewayResult }> {
    const access = await this.session(customer);
    const headers = { authorization: `Bearer ${access}` };
    const peerIp = this.ip(customer.id);
    if (roll < 0.45) return { area: "accounts", result: await this.call({ method: "GET",
      path: `/api/v1/accounts/${customer.account_id}`, headers, peerIp }) };
    if (roll < 0.8) {
      const amountCents = [500, 1000, 2000, 5000][index % 4]!;
      const identity = this.auth.deviceForAccess(access);
      const device = identity && deviceQuarantine(this.bank.db, customer.id, identity.id, this.bank.now());
      if (identity && device && (device.quarantined || !device.pixRegistered)) {
        const limits = parsePixLimits(this.bank.pixLimitsSnapshot().bytes);
        const since = new Date(this.bank.now().getTime() - 86_400_000).toISOString();
        const used = (this.bank.db.prepare(`SELECT COALESCE(SUM(amount),0) n FROM pix_transfers
          WHERE initiating_device_id=? AND status IN
            ('in_processing','settled','returned_partial','returned_full')
            AND COALESCE(settled_at,initiated_at)>=?`).get(identity.id, since) as { n: number }).n;
        if (amountCents > limits.new_device_transaction_cents || used + amountCents > limits.new_device_daily_cents) {
          this.bank.db.prepare(`INSERT OR IGNORE INTO sim_deferred_pix
            (minute,customer_id,operation_index,reason) VALUES (?,?,?,'device_limit')`).run(minute, customer.id, index);
          return { area: "accounts", result: await this.call({ method: "GET",
            path: `/api/v1/accounts/${customer.account_id}`, headers, peerIp }) };
        }
      }
      const externalRoll = (roll - 0.765) / (0.8 - 0.765);
      const externalRecipient = externalRoll >= 0 && this.externalRecipients.length > 0
        ? this.externalRecipients[Math.min(this.externalRecipients.length - 1,
          Math.floor(externalRoll * this.externalRecipients.length))] : undefined;
      let toAccount = recipient.account_id;
      if (externalRecipient) {
        const lookup = await this.call({ method: "GET",
          path: `/api/v1/pix/keys/lookup?key=${encodeURIComponent(externalRecipient.pixKey)}`,
          headers, peerIp });
        if (lookup.status !== 200) return { area: "pix", result: lookup };
        const destination = object(lookup.body).account_id;
        if (destination !== externalRecipient.id)
          throw new Error("Simulator DICT destination mismatch");
        toAccount = externalRecipient.id;
      }
      const body = { from_account: customer.account_id,
        to_account: toAccount,
        amount_cents: amountCents, idempotency_key: `sim:${minute}:${index}` };
      const key = this.deviceKeys.forCustomer(customer.id);
      for (let attempt = 0; attempt < 2; attempt++) {
        const challenge = await this.call({ method: "POST",
          path: "/api/v1/devices/current/operation-challenge", headers, peerIp,
          body: { method: "POST", path: "/pix/transfers", body } });
        if (challenge.status !== 200) return { area: "pix", result: challenge };
        const proof = object(challenge.body);
        const result = await this.call({ method: "POST", path: "/api/v1/pix/transfers",
          headers: { ...headers, "x-device-challenge": String(proof.challenge_id),
            "x-device-signature": sign(null, Buffer.from(String(proof.message)), key.privateKey)
              .toString("base64url") }, peerIp, body });
        const responseError = result.body && typeof result.body === "object" &&
          !Array.isArray(result.body) ?
          (result.body as Record<string, unknown>).error : undefined;
        if (result.status !== 403 || responseError !== "DEF_STEP_UP_REQUIRED" ||
          attempt !== 0) return { area: "pix", result };
        const elevated = await this.call({ method: "POST", path: "/api/v1/auth/step-up",
          headers, peerIp,
          body: { password: `synthetic-${customer.id}-simulator-secret` } });
        if (elevated.status !== 200) return { area: "pix", result: elevated };
      }
      throw new Error("Simulator step-up retry exhausted");
    }
    if (roll < 0.9) {
      if (!this.partnerKey || !this.cards || roll < 0.85)
        return { area: "cards", result: await this.call({ method: "GET",
          path: "/api/v1/cards", headers, peerIp }) };
      let card = this.bank.db.prepare(`SELECT id FROM cards WHERE customer_id=? AND account_id=?
        AND kind='debit' AND status='active' ORDER BY created_at,id LIMIT 1`)
        .get(customer.id, customer.account_id) as { id: string } | undefined;
      if (!card) {
        const body = { account_id: customer.account_id, limit_cents: DEVICE_QUARANTINE_V1.card_limit_cents };
        const challenge = await this.call({ method: "POST",
          path: "/api/v1/devices/current/operation-challenge", headers, peerIp,
          body: { method: "POST", path: "/cards", body } });
        if (challenge.status !== 200) return { area: "cards", result: challenge };
        const proof = object(challenge.body);
        const key = this.deviceKeys.forCustomer(customer.id);
        const issued = await this.call({ method: "POST", path: "/api/v1/cards",
          headers: { ...headers, "x-device-challenge": String(proof.challenge_id),
            "x-device-signature": sign(null, Buffer.from(String(proof.message)), key.privateKey)
              .toString("base64url") }, peerIp, body });
        if (issued.status !== 200) return { area: "cards", result: issued };
        card = { id: String(object(issued.body).id) };
      }
      return { area: "cards", result: await this.call({ method: "POST",
        path: "/api/v1/cards/network/authorize",
        headers: { ...headers, "x-partner-key": this.partnerKey }, peerIp,
        body: { card_id: card.id, merchant_id: index % 2 ? "shop_ipe" : "market_aroeira",
          amount_cents: index % 2 ? 500 : 1_000, entry_mode: "chip",
          cvv: this.cards.vault.currentCvv(card.id) } }) };
    }
    return { area: "loans", result: await this.call({ method: "GET",
      path: "/api/v1/loans/offers", headers, peerIp }) };
  }
  async honestProbe(): Promise<boolean> {
    const customer = this.customers[0]!;
    const access = await this.session(customer);
    const result = await this.call({ method: "GET",
      path: `/api/v1/accounts/${customer.account_id}`,
      headers: { authorization: `Bearer ${access}` }, peerIp: this.ip(customer.id) });
    return result.status === 200;
  }
  async localFaultProbe(kind: "external_pix" | "card_authorization" | "risk_hold",
    runId?: string,
    fixtureId?: "pix_dispatch_paused" | "spi_unavailable" | "psp_receipt_delayed" |
      "med_opening_delayed" | "med_analysis_delayed" | "med_settlement_delayed" | "med_release_delayed"):
    Promise<{ status: number }> {
    const customer = this.customers[0]!;
    const recipient = this.customers[1]!;
    if (kind === "risk_hold") {
      if (!runId || !/^[0-9a-f-]{36}$/.test(runId))
        throw new Error("SIMULATOR_LOCAL_PROBE_RUN_INVALID");
      const probeKey = `sim:${runId}:0`;
      this.bank.risk.setLocalFalseHoldProbeKey(probeKey);
      try {
        const operation = await this.operation(customer, recipient, 0.5, 0, runId);
        const requestId = operation.result.request_id;
        if (typeof requestId === "string") {
          const decision = this.bank.db.prepare(`SELECT id FROM risk_decisions
            WHERE trace_id=? AND customer_id=? AND area='pix' ORDER BY rowid DESC LIMIT 1`)
            .get(requestId, customer.id) as { id: string } | undefined;
          if (decision) this.bank.db.prepare(`INSERT OR IGNORE INTO sim_risk_labels
            (decision_id,label,source,request_id,labeled_at)
            VALUES (?,'honest','customer_simulator_v1',?,?)`)
            .run(decision.id, requestId, this.bank.now().toISOString());
        }
        return { status: operation.result.status };
      } finally { this.bank.risk.setLocalFalseHoldProbeKey(null); }
    }
    const roll = kind === "external_pix" ? 0.79 : 0.87;
    if (kind === "external_pix" && (!runId ||
      !/^[0-9a-f-]{36}$/.test(runId) || !fixtureId))
      throw new Error("SIMULATOR_LOCAL_PROBE_FIXTURE_INVALID");
    const probeKey = kind === "external_pix" ? `${runId}:${fixtureId}` :
      randomUUID().replaceAll("-", "");
    const operation = await this.operation(customer, recipient, roll, 0, probeKey);
    return { status: operation.result.status };
  }
  async retryNotifiedCardPurchases(): Promise<void> {
    if (!this.partnerKey || !this.cards || !this.events) return;
    if ((this.bank.db.prepare("SELECT available FROM card_issuer_state WHERE id=1")
      .get() as { available: number } | undefined)?.available !== 1) return;
    this.bank.db.exec(`CREATE TABLE IF NOT EXISTS sim_card_retries (
      rejection_id TEXT PRIMARY KEY REFERENCES card_network_rejections(id),
      customer_id TEXT NOT NULL REFERENCES customers(id),
      status TEXT NOT NULL CHECK(status IN ('claimed','authorized','declined','unknown')),
      authorization_id TEXT REFERENCES card_network_authorizations(id),
      claimed_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )`);
    const pending = this.bank.db.prepare(`SELECT n.customer_id,r.id rejection_id,
      r.card_id,r.merchant_id,r.amount_cents FROM incident_customer_notices n
      JOIN card_network_rejections r ON r.id=n.rejection_id
      JOIN cards c ON c.id=r.card_id AND c.customer_id=n.customer_id
      WHERE n.kind='card_issuer_recovered' AND r.response_code='91'
        AND NOT EXISTS (SELECT 1 FROM sim_card_retries s WHERE s.rejection_id=r.id)
      ORDER BY n.created_at,n.customer_id LIMIT 8`).all() as {
        customer_id: string; rejection_id: string; card_id: string;
        merchant_id: string; amount_cents: number }[];
    for (const item of pending) {
      const customer = this.customers.find((candidate) => candidate.id === item.customer_id);
      if (!customer) continue;
      const now = this.bank.realNow().toISOString();
      const claim = this.bank.db.prepare(`INSERT OR IGNORE INTO sim_card_retries
        (rejection_id,customer_id,status,claimed_at,updated_at)
        VALUES (?,?,'claimed',?,?)`).run(item.rejection_id,customer.id,now,now);
      if (claim.changes !== 1) continue;
      let status: "authorized" | "declined" | "unknown" = "unknown";
      let authorizationId: string | null = null;
      try {
        const access = await this.session(customer);
        const result = await this.call({ method: "POST",
          path: "/api/v1/cards/network/authorize",
          headers: { authorization: `Bearer ${access}`,
            "x-partner-key": this.partnerKey }, peerIp: this.ip(customer.id),
          body: { card_id: item.card_id, merchant_id: item.merchant_id,
            amount_cents: item.amount_cents, entry_mode: "chip",
            cvv: this.cards.vault.currentCvv(item.card_id) } });
        const body = result.status === 200 ? object(result.body) : {};
        const id = typeof body.id === "string" ? body.id : null;
        const verified = id ? this.bank.db.prepare(`SELECT id FROM
          card_network_authorizations WHERE id=? AND card_id=? AND merchant_id=?
            AND amount_cents=? AND response_code='00'`).get(id,item.card_id,
              item.merchant_id,item.amount_cents) as { id: string } | undefined :
          undefined;
        if (verified) {
          status = "authorized";
          authorizationId = verified.id;
          this.events.append({ round_id: null, ts: this.bank.realNow().toISOString(),
            twin_ts: this.bank.now().toISOString(), type: "sim.card_retry",
            actor: { id: "customer-simulator", role: "sim" }, area: "cards",
            public_summary_pt: "Cliente sintético tentou novamente o cartão",
            public: { outcome: "authorized" },
            private: { rejection_id: item.rejection_id,
              authorization_id: authorizationId, customer_id: customer.id } },
          `sim.card_retry:${item.rejection_id}`);
        } else status = "declined";
      } catch {
        status = "unknown";
      } finally {
        this.bank.db.prepare(`UPDATE sim_card_retries SET status=?,authorization_id=?,
          updated_at=? WHERE rejection_id=? AND status='claimed'`).run(status,
            authorizationId,this.bank.realNow().toISOString(),item.rejection_id);
      }
    }
  }
  async contestNotifiedLabPix(): Promise<number> {
    const pending = this.bank.db.prepare(`SELECT n.customer_id,n.transfer_id
      FROM fraud_incident_notices n
      JOIN pix_transfers p ON p.id=n.transfer_id
      JOIN accounts a ON a.id=p.from_account AND a.customer_id=n.customer_id
      JOIN sentinel_alerts s ON s.id=n.alert_id AND s.rule_id='S-PIX-02'
      WHERE n.kind='suspicious_pix_review' AND p.status='settled'
        AND p.idempotency_key LIKE 'lab:%:missed_hold'
        AND NOT EXISTS (SELECT 1 FROM med_cases m WHERE m.transfer_id=p.id)
      ORDER BY n.created_at,n.id LIMIT 8`).all() as {
        customer_id: string; transfer_id: string }[];
    const historyReplays = this.bank.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='lab_pix_history_replays'`).get();
    const replayOwner = historyReplays ? this.bank.db.prepare(`SELECT c.id,c.cpf,c.persona,
      r.account_id FROM lab_pix_history_replays p
      JOIN lab_risk_miss_receipts r ON r.run_id=p.run_id AND r.account_id=p.account_id
      JOIN customers c ON c.id=r.customer_id AND c.status='active'
      JOIN accounts a ON a.id=r.account_id AND a.customer_id=c.id
      JOIN pix_transfers t ON t.id=r.transfer_id AND t.from_account=a.id
        AND t.to_account=r.recipient_account_id AND t.actor='synthetic_pix_history'
      WHERE r.customer_id=? AND r.transfer_id=?`) : undefined;
    let opened = 0;
    for (const item of pending) {
      const customer = this.customers.find((candidate) => candidate.id === item.customer_id) ??
        replayOwner?.get(item.customer_id, item.transfer_id) as SimCustomer | undefined;
      if (!customer) continue;
      await this.submitMed(customer, item.transfer_id);
      opened++;
    }
    return opened;
  }
  async submitLabExternalMed(transferId: string): Promise<string> {
    return this.submitMed(this.customers[0]!, transferId);
  }
  private async submitMed(customer: SimCustomer, transferId: string): Promise<string> {
    const access = await this.session(customer);
    const headers = { authorization: `Bearer ${access}` };
    const peerIp = this.ip(customer.id);
    const body = { transfer_id: transferId };
    const key = this.deviceKeys.forCustomer(customer.id);
    for (let attempt = 0; attempt < 2; attempt++) {
      const challenge = await this.call({ method: "POST",
        path: "/api/v1/devices/current/operation-challenge", headers, peerIp,
        body: { method: "POST", path: "/pix/med", body } });
      if (challenge.status !== 200)
        throw new Error(`Simulator MED challenge failed: ${challenge.status}`);
      const proof = object(challenge.body);
      const result = await this.call({ method: "POST", path: "/api/v1/pix/med",
        headers: { ...headers, "x-device-challenge": String(proof.challenge_id),
          "x-device-signature": sign(null, Buffer.from(String(proof.message)),
            key.privateKey).toString("base64url") }, peerIp, body });
      const responseError = result.body && typeof result.body === "object" &&
        !Array.isArray(result.body) ?
        (result.body as Record<string, unknown>).error : undefined;
      if (result.status === 403 && responseError === "DEF_STEP_UP_REQUIRED" &&
        attempt === 0) {
        const elevated = await this.call({ method: "POST", path: "/api/v1/auth/step-up",
          headers, peerIp,
          body: { password: `synthetic-${customer.id}-simulator-secret` } });
        if (elevated.status !== 200)
          throw new Error(`Simulator MED step-up failed: ${elevated.status}`);
        continue;
      }
      if (result.status !== 200 && result.status !== 202)
        throw new Error(`Simulator MED request failed: ${result.status}`);
      const caseId = object(result.body).id;
      if (typeof caseId !== "string" || !this.bank.db.prepare(`SELECT 1 FROM med_cases
        WHERE id=? AND transfer_id=? AND customer_id=?`).get(caseId,
          transferId, customer.id))
        throw new Error("Simulator MED response identity mismatch");
      return caseId;
    }
    throw new Error("Simulator MED retry exhausted");
  }
  publish(tick: SimTick, sentinels?: Record<Area, SentinelSummary>,
    spiStatus?: { available: boolean; reconciled?: boolean }): void {
    if (!this.events) return;
    const riskQueuePending = (this.bank.db.prepare(`SELECT COUNT(*) count FROM risk_pix_holds
      WHERE status='pending' AND expires_at>?`).get(this.bank.now().toISOString()) as { count: number }).count;
    if (this.bank.isSeparatedEcosystem && !spiStatus)
      throw new Error("SIMULATOR_ECOSYSTEM_STATUS_REQUIRED");
    const spiReconciled = spiStatus?.reconciled ??
      (this.bank.isSeparatedEcosystem ? undefined : this.bank.reconcileSpi().ok);
    const spiAvailable = spiStatus?.available ??
      (this.bank.isSeparatedEcosystem ? undefined : this.bank.spi.availability().available);
    this.events.append({ round_id: null, ts: this.bank.realNow().toISOString(), twin_ts: this.bank.now().toISOString(),
      type: "sim.tick", actor: { id: "customer-simulator", role: "sim" }, area: "accounts",
      public_summary_pt: `${tick.ops} operações simuladas`, public: {
        minute: tick.minute, ops: tick.ops, approvals_pct: tick.ops ? tick.approved * 100 / tick.ops : 100,
        honest_blocked: tick.honest_blocked, false_block_rate: tick.false_block_rate, pix_deferred: tick.pix_deferred ?? 0,
        by_area: tick.by_area, risk_queue_pending: riskQueuePending,
        ...(spiReconciled === undefined ? {} : { spi_reconciled: spiReconciled }),
        ...(spiAvailable === undefined ? {} : { spi_available: spiAvailable }),
        ...(sentinels ? { sentinels } : {}),
      } }, `sim.tick:${tick.minute}`);
  }
  async publishCurrent(tick: SimTick, sentinels?: Record<Area, SentinelSummary>): Promise<void> {
    const status = await this.ecosystemStatus?.();
    this.publish(tick, sentinels, status);
  }
  async tick(emit = true): Promise<SimTick> {
    const now = this.bank.now();
    const billingDate = accountingDates(now.toISOString()).posting_date;
    if (this.lastCreditBillingDate !== billingDate) {
      this.creditCards.runBilling();
      this.lastCreditBillingDate = billingDate;
    }
    const realNow = this.bank.realNow();
    const bucket = new Date(Math.floor(realNow.getTime() / 10_000) * 10_000);
    const minute = bucket.toISOString();
    const prior = this.bank.db.prepare("SELECT ops,approved,honest_blocked,false_block_rate,by_area_json FROM sim_ticks WHERE minute=?")
      .get(minute) as { ops: number; approved: number; honest_blocked: number; false_block_rate: number; by_area_json: string } | undefined;
    if (prior) {
      const pixDeferred = (this.bank.db.prepare("SELECT COUNT(*) n FROM sim_deferred_pix WHERE minute=?")
        .get(minute) as { n: number }).n;
      const result = { minute, ops: prior.ops, approved: prior.approved, honest_blocked: prior.honest_blocked,
        false_block_rate: prior.false_block_rate, by_area: JSON.parse(prior.by_area_json) as Record<string, number>,
        pix_deferred: pixDeferred };
      if (emit) await this.publishCurrent(result);
      return result;
    }
    const hour = brtHour(now);
    const weekend = ["Sat", "Sun"].includes(new Intl.DateTimeFormat("en-US", { timeZone: "America/Sao_Paulo", weekday: "short" }).format(now));
    const perMinute = Math.round((HOURLY_RATES[hour] ?? 3) * (weekend ? 0.7 : 1));
    const slot = Math.floor(bucket.getUTCSeconds() / 10);
    const scheduledOps = Math.floor(perMinute * (slot + 1) * this.clockSpeed / 6) -
      Math.floor(perMinute * slot * this.clockSpeed / 6);
    const ops = this.maxOpsPerTick === undefined ? scheduledOps :
      Math.min(scheduledOps, this.maxOpsPerTick);
    const random = seededRandom(minute);
    const byArea: Record<string, number> = {};
    let approved = 0; let honestBlocked = 0;
    for (let index = 0; index < ops; index++) {
      const customer = this.customers[Math.floor(random() * this.customers.length)]!;
      let recipient = this.customers[Math.floor(random() * this.customers.length)]!;
      if (recipient.id === customer.id) recipient = this.customers[(this.customers.indexOf(customer) + 1) % this.customers.length]!;
      const { area, result } = await this.operation(customer, recipient, random(), index, minute);
      if ((area === "pix" || area === "cards") && typeof result.request_id === "string") {
        const decisions = this.bank.db.prepare(`SELECT id FROM risk_decisions
          WHERE trace_id=? AND customer_id=? AND area=?`).all(result.request_id, customer.id, area) as
          { id: string }[];
        for (const decision of decisions)
          this.bank.db.prepare(`INSERT INTO sim_risk_labels
            (decision_id,label,source,request_id,labeled_at)
            VALUES (?,'honest','customer_simulator_v1',?,?)`)
            .run(decision.id, result.request_id, this.bank.now().toISOString());
      }
      byArea[area] = (byArea[area] ?? 0) + 1;
      if (result.status >= 200 && result.status < 300) approved++;
      const error = result.body !== null && typeof result.body === "object" && !Array.isArray(result.body)
        ? (result.body as Record<string, unknown>).error : undefined;
      if (result.status === 429 || result.status >= 500 ||
        (typeof error === "string" && (error.startsWith("DEF_") ||
          error.startsWith("BIZ_RISK_") || error === "BIZ_FRAUD_DESTINATION" ||
          error === "BIZ_RATE_LIMIT" || error === "BIZ_NEW_DEVICE_LIMIT"))) {
        honestBlocked++;
        this.bank.db.prepare("INSERT OR IGNORE INTO sim_blocked_customers (minute,customer_id,area) VALUES (?,?,?)")
          .run(minute, customer.id, area);
      }
    }
    await this.dispatchPendingPix();
    const since = new Date(realNow.getTime() - 10 * 60_000).toISOString();
    const rolling = this.bank.db.prepare("SELECT COALESCE(SUM(ops),0) ops,COALESCE(SUM(honest_blocked),0) blocked FROM sim_ticks WHERE minute>=?")
      .get(since) as { ops: number; blocked: number };
    const rate = (rolling.blocked + honestBlocked) / Math.max(1, rolling.ops + ops);
    this.bank.db.prepare("INSERT INTO sim_ticks VALUES (?,?,?,?,?,?)")
      .run(minute, ops, approved, honestBlocked, rate, JSON.stringify(byArea));
    const pixDeferred = (this.bank.db.prepare("SELECT COUNT(*) n FROM sim_deferred_pix WHERE minute=?")
      .get(minute) as { n: number }).n;
    const result = { minute, ops, approved, honest_blocked: honestBlocked, false_block_rate: rate,
      by_area: byArea, pix_deferred: pixDeferred };
    if (emit) await this.publishCurrent(result);
    return result;
  }
}
