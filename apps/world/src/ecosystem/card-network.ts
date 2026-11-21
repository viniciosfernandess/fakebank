import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { newId } from "../id.ts";
import { Bank, BankError } from "../bank.ts";
import { CardsEngine } from "../cards.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "../credit-cards.ts";
import { currentTrace, withTrace } from "../telemetry.ts";
import { DEVICE_QUARANTINE_V1, deviceQuarantine } from "../device-quarantine.ts";

export type CardResponseCode = "00" | "05" | "14" | "41" | "43" | "51" | "54" | "57" | "59" | "61" | "65" | "91" | "N7";
export type CardEntryMode = "chip" | "contactless" | "ecommerce";
export interface Card3dsChallenge {
  id: string; card_id: string; merchant_id: string; amount_cents: number;
  nonce: string; expires_at: string;
}
type Stored3dsChallenge = Omit<Card3dsChallenge, "nonce"> & {
  customer_id: string; device_id: string; nonce_hash: string;
  status: "issued" | "completed" | "consumed" | "failed";
};
const hashNonce = (nonce: string): string => createHash("sha256").update(nonce).digest("hex");
export interface NetworkAuthorization {
  id: string; card_id: string; merchant_id: string; amount_cents: number;
  captured_cents: number; status: "approved" | "declined" | "captured" | "reversed" | "expired";
  response_code: CardResponseCode; ledger_tx_id: string | null;
  mcc: string; country: string; currency: "BRL"; entry_mode: CardEntryMode;
  eci: string | null; cvv_ok: boolean; created_at: string; expires_at: string;
}
export interface NetworkRejection {
  id: string; merchant_id: string; amount_cents: number;
  status: "declined"; response_code: "14" | "91"; created_at: string;
}
export type CardDisputeReason = "fraud" | "merchant_dispute" | "goods_not_received";
export interface CardDispute {
  id: string; authorization_id: string; customer_id: string; amount_cents: number;
  status: "chargeback" | "representment" | "pre_arbitration" | "customer_won" | "merchant_won";
  provisional_tx_id: string; final_tx_id: string | null; loss_cents: number;
  reason_code: CardDisputeReason | null;
  opened_at: string; updated_at: string;
}
export interface WalletToken { id: string; card_id: string; device_id: string;
  dpan_last4: string; status: "active" | "revoked"; created_at: string; revoked_at: string | null; }
export interface WalletProvisioning extends WalletToken { dpan: string; cryptogram_key: string; }

function walletDpan(): string {
  const prefix = `489001${String(randomInt(0, 1_000_000_000)).padStart(9, "0")}`;
  let sum = 0;
  for (let index = prefix.length - 1, position = 0; index >= 0; index--, position++) {
    let digit = Number(prefix[index]);
    if (position % 2 === 0) { digit *= 2; if (digit > 9) digit -= 9; }
    sum += digit;
  }
  return prefix + String((10 - sum % 10) % 10);
}

const walletDpanHash = (dpan: string): string => createHash("sha256").update(dpan).digest("hex");

export class CardNetwork {
  readonly bank: Bank;
  readonly cards: CardsEngine;
  readonly creditCards: CreditCardsEngine;
  private traced<T>(work: () => T): T {
    return withTrace(currentTrace() ?? newId("trace", this.bank.now().getTime()), work);
  }
  constructor(bank: Bank, cards: CardsEngine) {
    this.bank = bank; this.cards = cards;
    this.creditCards = new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
    bank.transaction(() => {
    const settlementFileExists = Boolean(bank.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='card_settlement_file'`).get());
    const acquirerBookExists = Boolean(bank.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='card_acquirer_balances'`).get());
    bank.db.exec(`CREATE TABLE IF NOT EXISTS card_merchants (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, mcc TEXT NOT NULL,
      country TEXT NOT NULL CHECK(length(country)=2), status TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS card_network_authorizations (
      id TEXT PRIMARY KEY, card_id TEXT NOT NULL REFERENCES cards(id),
      account_id TEXT NOT NULL REFERENCES accounts(id),
      root_card_id TEXT NOT NULL REFERENCES cards(id),
      merchant_id TEXT NOT NULL REFERENCES card_merchants(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      installment_count INTEGER NOT NULL DEFAULT 1 CHECK(installment_count BETWEEN 1 AND 24),
      captured_cents INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL, response_code TEXT NOT NULL,
      hold_id TEXT REFERENCES balance_holds(id), ledger_tx_id TEXT,
      mcc TEXT NOT NULL, country TEXT NOT NULL, currency TEXT NOT NULL,
      entry_mode TEXT NOT NULL, eci TEXT, cvv_ok INTEGER NOT NULL,
      risk_blocked INTEGER NOT NULL DEFAULT 0 CHECK(risk_blocked IN (0,1)),
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS card_network_auth_card_time
      ON card_network_authorizations(card_id,created_at);
    CREATE INDEX IF NOT EXISTS card_network_auth_merchant_time
      ON card_network_authorizations(merchant_id,created_at);
    CREATE TABLE IF NOT EXISTS card_3ds_challenges (
      id TEXT PRIMARY KEY, card_id TEXT NOT NULL REFERENCES cards(id),
      customer_id TEXT NOT NULL REFERENCES customers(id),
      device_id TEXT NOT NULL REFERENCES auth_devices(id),
      merchant_id TEXT NOT NULL REFERENCES card_merchants(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      nonce_hash TEXT NOT NULL, status TEXT NOT NULL
        CHECK(status IN ('issued','completed','consumed','failed')),
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
      completed_at TEXT, consumed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS card_3ds_customer_time
      ON card_3ds_challenges(customer_id,created_at);
    CREATE TABLE IF NOT EXISTS card_3ds_events (
      id INTEGER PRIMARY KEY, challenge_id TEXT,
      card_id TEXT NOT NULL, merchant_id TEXT NOT NULL,
      amount_cents INTEGER NOT NULL, action TEXT NOT NULL,
      reason TEXT, authorization_id TEXT, created_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS card_3ds_events_no_update
      BEFORE UPDATE ON card_3ds_events BEGIN
        SELECT RAISE(ABORT, 'CARD_3DS_EVENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS card_3ds_events_no_delete
      BEFORE DELETE ON card_3ds_events BEGIN
        SELECT RAISE(ABORT, 'CARD_3DS_EVENT_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS card_network_messages (
      id INTEGER PRIMARY KEY, authorization_id TEXT NOT NULL REFERENCES card_network_authorizations(id),
      mti TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS card_network_dispute_window
      ON card_network_messages(created_at,authorization_id) WHERE mti='1440';
    CREATE TABLE IF NOT EXISTS card_network_rejections (
      id TEXT PRIMARY KEY, merchant_id TEXT NOT NULL REFERENCES card_merchants(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      response_code TEXT NOT NULL CHECK(response_code IN ('14','91')),
      created_at TEXT NOT NULL,
      card_id TEXT REFERENCES cards(id)
    );
    CREATE INDEX IF NOT EXISTS card_network_rejections_merchant_time
      ON card_network_rejections(merchant_id,created_at);
    CREATE TRIGGER IF NOT EXISTS card_network_rejections_no_update
      BEFORE UPDATE ON card_network_rejections BEGIN
        SELECT RAISE(ABORT, 'CARD_NETWORK_REJECTION_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS card_network_rejections_no_delete
      BEFORE DELETE ON card_network_rejections BEGIN
        SELECT RAISE(ABORT, 'CARD_NETWORK_REJECTION_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS card_issuer_state (
      id INTEGER PRIMARY KEY CHECK(id=1), available INTEGER NOT NULL CHECK(available IN (0,1)),
      changed_at TEXT NOT NULL, changed_by TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS card_issuer_history (
      id INTEGER PRIMARY KEY, available INTEGER NOT NULL CHECK(available IN (0,1)),
      changed_at TEXT NOT NULL, changed_by TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS card_issuer_history_no_update
      BEFORE UPDATE ON card_issuer_history BEGIN
        SELECT RAISE(ABORT, 'CARD_ISSUER_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS card_issuer_history_no_delete
      BEFORE DELETE ON card_issuer_history BEGIN
        SELECT RAISE(ABORT, 'CARD_ISSUER_HISTORY_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS card_clearing_items (
      authorization_id TEXT PRIMARY KEY REFERENCES card_network_authorizations(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      due_at TEXT NOT NULL, status TEXT NOT NULL,
      processed_at TEXT, error_code TEXT
    );
    CREATE TABLE IF NOT EXISTS card_disputes (
      id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE REFERENCES card_network_authorizations(id),
      customer_id TEXT NOT NULL REFERENCES customers(id), amount_cents INTEGER NOT NULL,
      status TEXT NOT NULL, provisional_tx_id TEXT NOT NULL, final_tx_id TEXT,
      loss_cents INTEGER NOT NULL DEFAULT 0, opened_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS card_settlement_file (
      id TEXT PRIMARY KEY, ref_type TEXT NOT NULL CHECK(ref_type IN ('card_auth','card_dispute')),
      ref_id TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents<>0),
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS card_wallet_tokens (
      id TEXT PRIMARY KEY, card_id TEXT NOT NULL REFERENCES cards(id),
      customer_id TEXT NOT NULL REFERENCES customers(id),
      device_id TEXT NOT NULL REFERENCES auth_devices(id),
      dpan_hash TEXT NOT NULL UNIQUE, dpan_last4 TEXT NOT NULL,
      cryptogram_key TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','revoked')),
      created_at TEXT NOT NULL, revoked_at TEXT,
      CHECK((status='active' AND revoked_at IS NULL) OR
        (status='revoked' AND revoked_at IS NOT NULL))
    );
    CREATE INDEX IF NOT EXISTS card_wallet_customer ON card_wallet_tokens(customer_id,card_id);
    CREATE TABLE IF NOT EXISTS card_wallet_uses (
      token_id TEXT NOT NULL REFERENCES card_wallet_tokens(id), nonce TEXT NOT NULL,
      result_id TEXT NOT NULL, PRIMARY KEY(token_id,nonce)
    );
    CREATE TRIGGER IF NOT EXISTS card_wallet_uses_no_update
      BEFORE UPDATE ON card_wallet_uses BEGIN
        SELECT RAISE(ABORT, 'CARD_WALLET_USE_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS card_wallet_uses_no_delete
      BEFORE DELETE ON card_wallet_uses BEGIN
        SELECT RAISE(ABORT, 'CARD_WALLET_USE_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS card_acquirer_balances (
      merchant_id TEXT PRIMARY KEY REFERENCES card_merchants(id), balance_cents INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS card_settlement_ref
      ON card_settlement_file(ref_type,ref_id,amount_cents);`);
    if (!(bank.db.prepare("PRAGMA table_info(card_disputes)").all() as
      { name: string }[]).some((column) => column.name === "reason_code"))
      bank.db.exec("ALTER TABLE card_disputes ADD COLUMN reason_code TEXT");
    if (!(bank.db.prepare("PRAGMA table_info(card_network_authorizations)").all() as
      { name: string }[]).some((column) => column.name === "risk_blocked"))
      bank.db.exec(`ALTER TABLE card_network_authorizations
        ADD COLUMN risk_blocked INTEGER NOT NULL DEFAULT 0 CHECK(risk_blocked IN (0,1))`);
    if (!(bank.db.prepare("PRAGMA table_info(card_network_authorizations)").all() as
      { name: string }[]).some((column) => column.name === "installment_count"))
      bank.db.exec(`ALTER TABLE card_network_authorizations ADD COLUMN installment_count
        INTEGER NOT NULL DEFAULT 1 CHECK(installment_count BETWEEN 1 AND 24)`);
    if (!(bank.db.prepare("PRAGMA table_info(card_network_rejections)").all() as
      { name: string }[]).some((column) => column.name === "card_id"))
      bank.db.exec("ALTER TABLE card_network_rejections ADD COLUMN card_id TEXT REFERENCES cards(id)");
    bank.db.exec(`CREATE INDEX IF NOT EXISTS card_network_rejections_card_time
      ON card_network_rejections(card_id,created_at) WHERE card_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS card_network_rejections_response_time
      ON card_network_rejections(response_code,created_at)`);
    if (!settlementFileExists) bank.db.prepare(`INSERT INTO card_settlement_file
      (id,ref_type,ref_id,amount_cents,created_at)
      SELECT l.id,l.ref_type,l.ref_id,l.amount,l.created_at FROM ledger_entries l
      WHERE l.account_id=? AND ((l.ref_type='card_auth' AND l.ref_id IN
        (SELECT id FROM card_network_authorizations)) OR (l.ref_type='card_dispute'
        AND l.ref_id IN (SELECT id FROM card_disputes)))`).run(bank.systemAccountId("card_settlement"));
    bank.db.exec(`CREATE TRIGGER IF NOT EXISTS card_settlement_no_update
      BEFORE UPDATE ON card_settlement_file BEGIN
        SELECT RAISE(ABORT, 'CARD_SETTLEMENT_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS card_settlement_no_delete
      BEFORE DELETE ON card_settlement_file BEGIN
        SELECT RAISE(ABORT, 'CARD_SETTLEMENT_IMMUTABLE'); END;`);
    const insert = bank.db.prepare("INSERT OR IGNORE INTO card_merchants VALUES (?,?,?,?,?)");
    insert.run("shop_ipe", "Loja Ipê", "5411", "BR", "active");
    insert.run("market_aroeira", "Mercado Aroeira", "5999", "BR", "active");
    insert.run("online_global", "Global Online", "5732", "US", "active");
    bank.db.prepare(`INSERT OR IGNORE INTO card_issuer_state
      (id,available,changed_at,changed_by) VALUES (1,1,?,'bootstrap')`)
      .run(bank.now().toISOString());
    bank.db.exec(`INSERT OR IGNORE INTO card_acquirer_balances (merchant_id,balance_cents)
      SELECT id,0 FROM card_merchants`);
    if (!acquirerBookExists) {
      const totals = bank.db.prepare(`SELECT merchant_id,SUM(amount) amount FROM (
        SELECT a.merchant_id,l.amount FROM ledger_entries l
          JOIN card_network_authorizations a ON a.id=l.ref_id
          WHERE l.account_id=? AND l.ref_type='card_auth'
        UNION ALL
        SELECT a.merchant_id,l.amount FROM ledger_entries l
          JOIN card_disputes d ON d.id=l.ref_id
          JOIN card_network_authorizations a ON a.id=d.authorization_id
          WHERE l.account_id=? AND l.ref_type='card_dispute'
      ) GROUP BY merchant_id`).all(bank.systemAccountId("card_settlement"),
        bank.systemAccountId("card_settlement")) as { merchant_id: string; amount: number }[];
      const update = bank.db.prepare(`UPDATE card_acquirer_balances SET balance_cents=?
        WHERE merchant_id=?`);
      for (const row of totals) update.run(row.amount, row.merchant_id);
    }
    });
  }

  // Confirms this card-network producer can write to its card telemetry path.
  heartbeat(): void {
    this.bank.telemetry.emit({ source: "cards", category: "health", action: "heartbeat",
      outcome: "success", message: "Card network telemetry heartbeat" });
  }

  private record(id: string, mti: "0100" | "0110" | "0220" | "0400" | "1440",
    payload: Record<string, unknown>): void {
    this.bank.db.prepare(`INSERT INTO card_network_messages
      (authorization_id,mti,payload_json,created_at) VALUES (?,?,?,?)`)
      .run(id, mti, JSON.stringify(payload), this.bank.now().toISOString());
    const auth = this.bank.db.prepare(`SELECT a.card_id,a.account_id,a.merchant_id,
      a.amount_cents,c.customer_id FROM card_network_authorizations a
      JOIN cards c ON c.id=a.card_id WHERE a.id=?`).get(id) as {
      card_id: string; account_id: string; merchant_id: string;
      amount_cents: number; customer_id: string;
    };
    this.bank.telemetry.emit({ source: "network", category: "payment",
      action: `mti_${mti}`, outcome: mti === "0110" && payload.approved === false ?
        "failure" : "success", userId: auth.customer_id, accountId: auth.account_id,
      cardToken: auth.card_id, counterparty: auth.merchant_id,
      amountCents: typeof payload.amount_cents === "number" ? payload.amount_cents :
        auth.amount_cents, message: `Card network message ${mti}` });
  }

  private settlement(refType: "card_auth" | "card_dispute", refId: string,
    amountCents: number): void {
    this.bank.db.prepare(`INSERT INTO card_settlement_file
      (id,ref_type,ref_id,amount_cents,created_at) VALUES (?,?,?,?,?)`)
      .run(newId("clearing", this.bank.now().getTime()), refType, refId, amountCents,
        this.bank.now().toISOString());
  }

  authorization(id: string): NetworkAuthorization {
    const row = this.bank.db.prepare(`SELECT id,card_id,merchant_id,amount_cents,
      captured_cents,status,response_code,ledger_tx_id,mcc,country,currency,
      entry_mode,eci,cvv_ok,created_at,expires_at FROM card_network_authorizations WHERE id=?`)
      .get(id) as (Omit<NetworkAuthorization, "cvv_ok"> & { cvv_ok: number }) | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    return { ...row, cvv_ok: Boolean(row.cvv_ok) };
  }

  walletTokens(customerId: string, cardId: string): WalletToken[] {
    this.cards.ownCard(customerId, cardId);
    return this.bank.db.prepare(`SELECT t.id,t.card_id,t.device_id,t.dpan_last4,
      CASE WHEN t.status='active' AND d.revoked_at IS NULL THEN 'active'
        ELSE 'revoked' END status,t.created_at,
      COALESCE(t.revoked_at,d.revoked_at) revoked_at
      FROM card_wallet_tokens t JOIN auth_devices d ON d.id=t.device_id
      WHERE t.customer_id=? AND t.card_id=? ORDER BY t.created_at,t.id`)
      .all(customerId, cardId) as unknown as WalletToken[];
  }

  issueWalletToken(customerId: string, cardId: string, deviceId: string): WalletProvisioning {
    return this.bank.transaction(() => {
      const card = this.cards.ownCard(customerId, cardId);
      if (!this.boundThreeDsDevice(customerId, deviceId))
        throw new BankError("DEF_WALLET_DEVICE_INVALID");
      if (card.status !== "active" || this.bank.account(card.account_id).status !== "active")
        throw new BankError("BIZ_CARD_NOT_ACTIVE");
      if (this.bank.db.prepare(`SELECT 1 FROM card_wallet_tokens WHERE card_id=?
        AND device_id=? AND status='active'`).get(cardId, deviceId))
        throw new BankError("BIZ_WALLET_TOKEN_EXISTS");
      const active = (this.bank.db.prepare(`SELECT COUNT(*) n FROM card_wallet_tokens t
        JOIN auth_devices d ON d.id=t.device_id
        WHERE t.card_id=? AND t.status='active' AND d.revoked_at IS NULL`)
        .get(cardId) as { n: number }).n;
      if (active >= 5) throw new BankError("BIZ_WALLET_TOKEN_LIMIT");
      let dpan = "";
      for (let attempt = 0; attempt < 5; attempt++) {
        const candidate = walletDpan();
        if (!this.bank.db.prepare("SELECT 1 FROM card_wallet_tokens WHERE dpan_hash=?")
          .get(walletDpanHash(candidate))) { dpan = candidate; break; }
      }
      if (!dpan) throw new BankError("DEF_WALLET_TOKEN_UNAVAILABLE");
      const key = randomBytes(32).toString("hex");
      const id = newId("wallet", this.bank.now().getTime());
      const createdAt = this.bank.now().toISOString();
      this.bank.db.prepare(`INSERT INTO card_wallet_tokens
        (id,card_id,customer_id,device_id,dpan_hash,dpan_last4,cryptogram_key,
        status,created_at,revoked_at) VALUES (?,?,?,?,?,?,?,'active',?,NULL)`)
        .run(id, cardId, customerId, deviceId, walletDpanHash(dpan),
          dpan.slice(-4), key, createdAt);
      return { id, card_id: cardId, device_id: deviceId, dpan_last4: dpan.slice(-4),
        status: "active" as const, created_at: createdAt, revoked_at: null,
        dpan, cryptogram_key: key };
    });
  }

  revokeWalletToken(customerId: string, tokenId: string): WalletToken {
    return this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT id,card_id,device_id,dpan_last4,status,
        created_at,revoked_at FROM card_wallet_tokens WHERE id=? AND customer_id=?`)
        .get(tokenId, customerId) as WalletToken | undefined;
      if (!row) throw new BankError("DEF_NOT_FOUND");
      if (row.status === "revoked") return row;
      const revokedAt = this.bank.now().toISOString();
      this.bank.db.prepare(`UPDATE card_wallet_tokens SET status='revoked',revoked_at=?
        WHERE id=?`).run(revokedAt, tokenId);
      return { ...row, status: "revoked", revoked_at: revokedAt };
    });
  }

  authorizeWallet(input: { dpan: string; merchantId: string; amountCents: number;
    nonce: string; cryptogram: string; installments?: number }): NetworkAuthorization | NetworkRejection {
    if (!/^\d{16}$/.test(input.dpan) || !/^[A-Za-z0-9_-]{12,64}$/.test(input.nonce) ||
      !/^[a-f0-9]{64}$/.test(input.cryptogram))
      throw new BankError("DEF_WALLET_CREDENTIAL_INVALID");
    return this.bank.transaction(() => {
      const token = this.bank.db.prepare(`SELECT t.id,t.card_id,t.customer_id,t.device_id,t.cryptogram_key,
        t.status,d.revoked_at device_revoked_at,d.public_key
        FROM card_wallet_tokens t JOIN auth_devices d ON d.id=t.device_id
        WHERE t.dpan_hash=?`).get(walletDpanHash(input.dpan)) as { id: string;
          card_id: string; customer_id: string; device_id: string; cryptogram_key: string;
          status: string; device_revoked_at: string | null;
          public_key: string | null } | undefined;
      if (!token || token.status !== "active" || token.device_revoked_at || !token.public_key)
        throw new BankError("DEF_WALLET_CREDENTIAL_INVALID");
      const device = deviceQuarantine(this.bank.db, token.customer_id,
        token.device_id, this.bank.now());
      if (!device) throw new BankError("DEF_WALLET_CREDENTIAL_INVALID");
      if (device.quarantined && input.amountCents > DEVICE_QUARANTINE_V1.card_limit_cents)
        throw new BankError("BIZ_NEW_DEVICE_LIMIT");
      const expected = createHmac("sha256", Buffer.from(token.cryptogram_key, "hex"))
        .update(`${input.dpan}:${input.nonce}:${input.merchantId}:${input.amountCents}:${input.installments ?? 1}`)
        .digest();
      if (!timingSafeEqual(expected, Buffer.from(input.cryptogram, "hex")) ||
        this.bank.db.prepare(`SELECT 1 FROM card_wallet_uses WHERE token_id=? AND nonce=?`)
          .get(token.id, input.nonce)) throw new BankError("DEF_WALLET_CREDENTIAL_INVALID");
      const result = this.authorize({ cardId: token.card_id,
        merchantId: input.merchantId, amountCents: input.amountCents,
        entryMode: "contactless", cvv: this.cards.vault.currentCvv(token.card_id),
        ...(input.installments === undefined ? {} : { installments: input.installments }) });
      this.bank.db.prepare(`INSERT INTO card_wallet_uses VALUES (?,?,?)`)
        .run(token.id, input.nonce, result.id);
      return result;
    });
  }

  issuerAvailability(): { available: boolean; changed_at: string; changed_by: string } {
    const row = this.bank.db.prepare(`SELECT available,changed_at,changed_by
      FROM card_issuer_state WHERE id=1`).get() as
      { available: number; changed_at: string; changed_by: string };
    return { ...row, available: Boolean(row.available) };
  }

  private threeDsEvent(input: { challengeId?: string | null; cardId: string;
    merchantId: string; amountCents: number; action: string; reason?: string | null;
    authorizationId?: string | null }): void {
    this.bank.db.prepare(`INSERT INTO card_3ds_events
      (challenge_id,card_id,merchant_id,amount_cents,action,reason,authorization_id,created_at)
      VALUES (?,?,?,?,?,?,?,?)`).run(input.challengeId ?? null, input.cardId,
      input.merchantId, input.amountCents, input.action, input.reason ?? null,
      input.authorizationId ?? null, this.bank.realNow().toISOString());
    this.bank.telemetry.emit({ source: "cards", category: "security",
      action: "three_ds_event", outcome: input.reason ? "failure" : "success",
      cardToken: input.cardId, counterparty: input.merchantId,
      amountCents: input.amountCents, message: "Card 3DS state change" });
  }

  private boundThreeDsDevice(customerId: string, deviceId: string): boolean {
    const device = this.bank.db.prepare(`SELECT customer_id,public_key,bound_at,revoked_at
      FROM auth_devices WHERE id=?`).get(deviceId) as { customer_id: string;
        public_key: string | null; bound_at: string | null; revoked_at: string | null } | undefined;
    return Boolean(device && device.customer_id === customerId && device.public_key &&
      device.bound_at && !device.revoked_at);
  }

  issueThreeDsChallenge(customerId: string, deviceId: string, cardId: string,
    merchantId: string, amountCents: number): Card3dsChallenge {
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0 || amountCents > 2_000_000)
      throw new BankError("BIZ_INVALID_AMOUNT");
    return this.bank.transaction(() => {
      if (!this.boundThreeDsDevice(customerId, deviceId)) throw new BankError("DEF_UNAUTHORIZED");
      const card = this.cards.ownCard(customerId, cardId);
      const merchant = this.bank.db.prepare(`SELECT status FROM card_merchants WHERE id=?`)
        .get(merchantId) as { status: string } | undefined;
      if (!merchant || merchant.status !== "active") throw new BankError("BIZ_INVALID_MERCHANT");
      if (card.status !== "active" || !card.online_enabled ||
        this.bank.account(card.account_id).status !== "active")
        throw new BankError("BIZ_CARD_NOT_ACTIVE");
      const now = this.bank.realNow();
      const active = this.bank.db.prepare(`SELECT COUNT(*) n FROM card_3ds_challenges
        WHERE customer_id=? AND status IN ('issued','completed') AND expires_at>?`)
        .get(customerId, now.toISOString()) as { n: number };
      if (active.n >= 10) throw new BankError("BIZ_3DS_CHALLENGE_LIMIT");
      const challenge = { id: newId("3ds", now.getTime()), card_id: cardId,
        merchant_id: merchantId, amount_cents: amountCents,
        nonce: randomBytes(32).toString("base64url"),
        expires_at: new Date(now.getTime() + 2 * 60_000).toISOString() };
      this.bank.db.prepare(`INSERT INTO card_3ds_challenges
        (id,card_id,customer_id,device_id,merchant_id,amount_cents,
         nonce_hash,status,created_at,expires_at) VALUES (?,?,?,?,?,?,?,'issued',?,?)`)
        .run(challenge.id, cardId, customerId, deviceId, merchantId, amountCents,
          hashNonce(challenge.nonce), now.toISOString(), challenge.expires_at);
      this.threeDsEvent({ challengeId: challenge.id, cardId, merchantId, amountCents,
        action: "issued" });
      return challenge;
    });
  }

  completeThreeDsChallenge(customerId: string, deviceId: string, id: string,
    nonce: string): { challenge_id: string; authenticated: true; expires_at: string } {
    const result = this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT id,card_id,customer_id,device_id,
        merchant_id,amount_cents,nonce_hash,status,expires_at
        FROM card_3ds_challenges WHERE id=?`).get(id) as Stored3dsChallenge | undefined;
      if (!row) return null;
      let reason: string | null = null;
      if (row.customer_id !== customerId || row.device_id !== deviceId ||
        !this.boundThreeDsDevice(customerId, deviceId))
        reason = "identity_mismatch";
      else if (row.status !== "issued") reason = "not_issued";
      else if (row.expires_at <= this.bank.realNow().toISOString()) reason = "expired";
      else if (typeof nonce !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(nonce) ||
        !timingSafeEqual(Buffer.from(row.nonce_hash, "hex"),
          Buffer.from(hashNonce(nonce), "hex"))) reason = "nonce_mismatch";
      if (reason) {
        this.threeDsEvent({ challengeId: id, cardId: row.card_id,
          merchantId: row.merchant_id, amountCents: row.amount_cents,
          action: "complete_denied", reason });
        if (reason === "nonce_mismatch" && row.customer_id === customerId &&
          row.device_id === deviceId)
          this.bank.db.prepare(`UPDATE card_3ds_challenges SET status='failed'
            WHERE id=? AND status='issued'`).run(id);
        return null;
      }
      const updated = this.bank.db.prepare(`UPDATE card_3ds_challenges
        SET status='completed',completed_at=? WHERE id=? AND status='issued'`)
        .run(this.bank.realNow().toISOString(), id);
      if (updated.changes !== 1) return null;
      this.threeDsEvent({ challengeId: id, cardId: row.card_id,
        merchantId: row.merchant_id, amountCents: row.amount_cents,
        action: "completed" });
      return { challenge_id: id, authenticated: true as const, expires_at: row.expires_at };
    });
    if (!result) throw new BankError("DEF_3DS_CHALLENGE_INVALID");
    return result;
  }

  setIssuerAvailability(available: boolean, actor: string): ReturnType<CardNetwork["issuerAvailability"]> {
    if (typeof available !== "boolean" || typeof actor !== "string" ||
      !/^[A-Za-z0-9_-]{1,80}$/.test(actor)) throw new BankError("BIZ_ISSUER_CONTROL_INVALID");
    return this.bank.transaction(() => {
      const current = this.issuerAvailability();
      if (current.available === available) return current;
      const changedAt = this.bank.now().toISOString();
      this.bank.db.prepare(`UPDATE card_issuer_state SET available=?,changed_at=?,changed_by=?
        WHERE id=1`).run(Number(available), changedAt, actor);
      this.bank.db.prepare(`INSERT INTO card_issuer_history
        (available,changed_at,changed_by) VALUES (?,?,?)`).run(Number(available), changedAt, actor);
      return this.issuerAvailability();
    });
  }

  private rejection(id: string): NetworkRejection {
    const row = this.bank.db.prepare(`SELECT id,merchant_id,amount_cents,response_code,created_at
      FROM card_network_rejections WHERE id=?`).get(id) as NetworkRejection | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    return { ...row, status: "declined" };
  }

  private recordProtocolRejection(input: { cardId: string; merchantId: string; amountCents: number },
    code: "14" | "91"): NetworkRejection {
    const id = newId("netrej", this.bank.now().getTime());
    const validCard = this.bank.db.prepare("SELECT id FROM cards WHERE id=?")
      .get(input.cardId) as { id: string } | undefined;
    this.bank.db.prepare(`INSERT INTO card_network_rejections
      (id,merchant_id,amount_cents,response_code,created_at,card_id)
      VALUES (?,?,?,?,?,?)`).run(id, input.merchantId, input.amountCents,
        code, this.bank.now().toISOString(), validCard?.id ?? null);
    this.bank.telemetry.emit({ source: "network", category: "payment", action: "mti_0100",
      outcome: "success", counterparty: input.merchantId, amountCents: input.amountCents,
      message: "Card network authorization request" });
    this.bank.telemetry.emit({ source: "network", category: "payment", action: "mti_0110",
      outcome: "failure", counterparty: input.merchantId, amountCents: input.amountCents,
      message: `Card network response ${code}` });
    this.bank.telemetry.emit({ source: "cards", category: "payment", action: "authorize",
      outcome: "failure", counterparty: input.merchantId, amountCents: input.amountCents,
      message: `Card network response ${code}` });
    return this.rejection(id);
  }

  messages(id: string): { mti: string; payload: Record<string, unknown> }[] {
    const rows = this.bank.db.prepare(`SELECT mti,payload_json FROM card_network_messages
      WHERE authorization_id=? ORDER BY id`).all(id) as { mti: string; payload_json: string }[];
    return rows.map((row) => ({ mti: row.mti,
      payload: JSON.parse(row.payload_json) as Record<string, unknown> }));
  }

  authorize(input: { cardId: string; merchantId: string; amountCents: number;
    entryMode: CardEntryMode; eci?: string | null; cvv: string;
    threeDsChallengeId?: string | null; installments?: number }): NetworkAuthorization | NetworkRejection {
    if (!Number.isSafeInteger(input.amountCents) || input.amountCents <= 0 ||
      input.amountCents > 2_000_000) throw new BankError("BIZ_INVALID_AMOUNT");
    if (!input.cardId || input.cardId.length > 128) throw new BankError("BIZ_INVALID_CARD_TOKEN");
    const installments = input.installments ?? 1;
    if (!Number.isSafeInteger(installments) || installments < 1 || installments > 24 ||
      input.amountCents < installments) throw new BankError("BIZ_CREDIT_INSTALLMENTS_INVALID");
    return this.traced(() => this.bank.transaction(() => {
      const merchant = this.bank.db.prepare(`SELECT id,mcc,country,status FROM card_merchants WHERE id=?`)
        .get(input.merchantId) as { id: string; mcc: string; country: string;
          status: string } | undefined;
      if (!merchant || merchant.status !== "active") throw new BankError("BIZ_INVALID_MERCHANT");
      if (!this.issuerAvailability().available) return this.recordProtocolRejection(input, "91");
      if (!this.bank.db.prepare("SELECT 1 FROM cards WHERE id=?").get(input.cardId))
        return this.recordProtocolRejection(input, "14");
      this.bank.db.prepare(`INSERT OR IGNORE INTO card_acquirer_balances
        (merchant_id,balance_cents) VALUES (?,0)`).run(merchant.id);
      const card = this.cards.card(input.cardId);
      const creditId = this.cards.creditAccountId(card.id);
      if ((card.kind === "credit") !== Boolean(creditId))
        throw new BankError("INTEGRITY_CREDIT_CARD_LINK");
      if (!creditId && installments !== 1)
        throw new BankError("BIZ_INSTALLMENTS_CREDIT_ONLY");
      const cvvOk = this.cards.vault.verifyCvv(card.id, input.cvv);
      const root = card.parent_id ? this.cards.card(card.parent_id) : card;
      const temporary = this.bank.db.prepare(`SELECT capture_count FROM temporary_cards WHERE card_id=?`)
        .get(card.id) as { capture_count: number } | undefined;
      const now = this.bank.now();
      const expiresAt = new Date(now.getTime() + 7 * 86_400_000);
      const recent = (this.bank.db.prepare(`SELECT COUNT(*) n FROM card_network_authorizations
        WHERE card_id=? AND created_at>=?`).get(card.id,
          new Date(now.getTime() - 60_000).toISOString()) as { n: number }).n;
      const risk = this.bank.risk.evaluateCard({ customerId: card.customer_id,
        accountId: card.account_id, cardId: card.id, merchantId: merchant.id,
        amountCents: input.amountCents, cvvOk });
      let code: CardResponseCode = "00";
      let riskBlocked = false;
      if (card.status === "lost" || root.status === "lost") code = "41";
      else if (card.status === "stolen" || root.status === "stolen") code = "43";
      else if (this.bank.account(card.account_id).status !== "active" ||
        card.status !== "active" || root.status !== "active" ||
        (temporary && !this.cards.features.isEnabled("cartao_virtual_temporario"))) code = "05";
      else if (!card.online_enabled || (merchant.country !== "BR" && !card.international_enabled)) code = "57";
      else if (card.expires_at && Date.parse(card.expires_at) <= now.getTime()) code = "54";
      else if (temporary && temporary.capture_count >= 1) code = "05";
      else if (!cvvOk) code = "N7";
      else if (risk.outcome === "decline" || risk.outcome === "hold") {
        code = "59"; riskBlocked = true;
      } else if (input.entryMode === "ecommerce" && input.eci === "00") code = "59";
      else if (risk.outcome === "step_up" && input.eci !== "05") {
        code = "05"; riskBlocked = true;
      }
      else if (recent >= 10) code = "65";
      else if (creditId ? this.creditCards.availableLimit(card.customer_id, creditId) < input.amountCents
        : card.used_cents + input.amountCents > this.cards.effectiveLimit(card) ||
          root.used_cents + input.amountCents > this.cards.effectiveLimit(root)) code = "61";
      else if (!creditId && this.bank.availableBalance(card.account_id) < input.amountCents) code = "51";
      const id = newId("netauth", now.getTime());
      if (input.eci === "05") {
        const challenge = input.threeDsChallengeId ? this.bank.db.prepare(`SELECT
          c.id,c.card_id,c.merchant_id,c.amount_cents,c.status,c.expires_at,
          d.revoked_at device_revoked_at,d.public_key device_public_key
          FROM card_3ds_challenges c JOIN auth_devices d ON d.id=c.device_id
          WHERE c.id=?`).get(input.threeDsChallengeId) as
          Pick<Stored3dsChallenge, "id" | "card_id" | "merchant_id" | "amount_cents" |
            "status" | "expires_at"> & { device_revoked_at: string | null;
              device_public_key: string | null } | undefined : undefined;
        const valid = input.entryMode === "ecommerce" && challenge?.card_id === card.id &&
          challenge.merchant_id === merchant.id &&
          challenge.amount_cents === input.amountCents && challenge.status === "completed" &&
          !challenge.device_revoked_at && Boolean(challenge.device_public_key) &&
          challenge.expires_at > this.bank.realNow().toISOString();
        if (valid && challenge && code !== "00") {
          this.threeDsEvent({ challengeId: challenge.id, cardId: card.id,
            merchantId: merchant.id, amountCents: input.amountCents,
            action: "authorize_denied", reason: "authorization_declined",
            authorizationId: id });
        } else if (valid && challenge) {
          const consumed = this.bank.db.prepare(`UPDATE card_3ds_challenges
            SET status='consumed',consumed_at=? WHERE id=? AND status='completed' AND expires_at>?`)
            .run(this.bank.realNow().toISOString(), challenge.id,
              this.bank.realNow().toISOString());
          if (consumed.changes === 1) this.threeDsEvent({ challengeId: challenge.id,
            cardId: card.id, merchantId: merchant.id, amountCents: input.amountCents,
            action: "consumed", authorizationId: id });
          else {
            this.threeDsEvent({ challengeId: challenge.id, cardId: card.id,
              merchantId: merchant.id, amountCents: input.amountCents,
              action: "authorize_denied", reason: "already_consumed_or_expired",
              authorizationId: id });
            if (code === "00") code = "05";
          }
        } else {
          this.threeDsEvent({ challengeId: input.threeDsChallengeId ?? null, cardId: card.id,
            merchantId: merchant.id, amountCents: input.amountCents,
            action: "authorize_denied", reason: "challenge_mismatch_or_unavailable",
            authorizationId: id });
          if (code === "00") code = "05";
        }
      }
      const status = code === "00" ? "approved" : "declined";
      const holdId = code === "00" && !creditId ? this.bank.createHold({ accountId: card.account_id,
        amount: input.amountCents, kind: "card_auth", ref: id,
        actor: input.merchantId, expiresAt }) : null;
      if (code === "00" && creditId)
        this.creditCards.reserve(card.customer_id, creditId, id, input.amountCents, expiresAt);
      this.bank.db.prepare(`INSERT INTO card_network_authorizations
        (id,card_id,account_id,root_card_id,merchant_id,amount_cents,
         status,response_code,hold_id,mcc,country,currency,entry_mode,eci,cvv_ok,
         risk_blocked,created_at,expires_at,installment_count)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(id, card.id, card.account_id, root.id, merchant.id, input.amountCents,
          status, code, holdId, merchant.mcc, merchant.country, "BRL", input.entryMode,
          input.eci ?? null, Number(cvvOk), Number(riskBlocked), now.toISOString(),
          expiresAt.toISOString(), installments);
      if (code === "00") {
        if (!creditId) {
          this.bank.db.prepare("UPDATE cards SET used_cents=used_cents+? WHERE id=?")
            .run(input.amountCents, card.id);
          if (card.parent_id) this.bank.db.prepare("UPDATE cards SET used_cents=used_cents+? WHERE id=?")
            .run(input.amountCents, root.id);
        }
        if (temporary) this.bank.db.prepare(`UPDATE temporary_cards
          SET capture_count=capture_count+1 WHERE card_id=?`).run(card.id);
        this.bank.db.prepare(`INSERT INTO card_clearing_items
          (authorization_id,amount_cents,due_at,status) VALUES (?,?,?,'pending')`)
          .run(id, input.amountCents, new Date(now.getTime() + 86_400_000).toISOString());
      }
      this.record(id, "0100", { card_token: card.id, merchant_id: merchant.id,
        amount_cents: input.amountCents, mcc: merchant.mcc, country: merchant.country,
        currency: "BRL", entry_mode: input.entryMode, eci: input.eci ?? null,
        cvv_ok: cvvOk, installments });
      this.record(id, "0110", { response_code: code, approved: code === "00" });
      this.bank.telemetry.emit({ source: "cards", category: "payment", action: "authorize",
        outcome: code === "00" ? "success" : "failure", userId: card.customer_id,
        accountId: card.account_id, amountCents: input.amountCents, cardToken: card.id,
        message: `Card network response ${code}` });
      return this.authorization(id);
    }));
  }

  capture(id: string, amountCents: number): NetworkAuthorization {
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0) throw new BankError("BIZ_INVALID_AMOUNT");
    return this.traced(() => this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT card_id,account_id,root_card_id,merchant_id,
        amount_cents,captured_cents,status,hold_id,expires_at,installment_count FROM card_network_authorizations
        WHERE id=?`).get(id) as { card_id: string; account_id: string; root_card_id: string;
          merchant_id: string; amount_cents: number; captured_cents: number;
          status: string; hold_id: string | null; expires_at: string;
          installment_count: number } | undefined;
      if (!row) throw new BankError("DEF_NOT_FOUND");
      if (row.status === "captured") {
        if (row.captured_cents !== amountCents) throw new BankError("BIZ_CAPTURE_CONFLICT");
        return this.authorization(id);
      }
      const creditId = this.cards.creditAccountId(row.card_id);
      const creditHold = creditId ? this.bank.db.prepare(`SELECT amount_cents,expires_at,released_at
        FROM credit_card_network_holds WHERE authorization_id=? AND credit_id=?`)
        .get(id, creditId) as { amount_cents: number; expires_at: string;
          released_at: string | null } | undefined : undefined;
      if (row.status !== "approved" || (creditId ? !creditHold || creditHold.released_at !== null
        : !row.hold_id)) throw new BankError("BIZ_CAPTURE_NOT_APPROVED");
      if (row.expires_at <= this.bank.now().toISOString()) throw new BankError("BIZ_AUTH_EXPIRED");
      if (amountCents > Math.ceil(row.amount_cents * 1.15)) throw new BankError("BIZ_CAPTURE_EXCEEDS_TOLERANCE");
      const delta = amountCents - row.amount_cents;
      const card = this.cards.card(row.card_id); const root = this.cards.card(row.root_card_id);
      if (delta > 0 && (creditId ? this.creditCards.availableLimit(card.customer_id, creditId) < delta
        : this.bank.availableBalance(row.account_id) < delta ||
          card.used_cents + delta > this.cards.effectiveLimit(card) ||
          root.used_cents + delta > this.cards.effectiveLimit(root)))
        throw new BankError("BIZ_CAPTURE_LIMIT");
      if (creditId ? !this.creditCards.releaseReservation(id) :
        !this.bank.releaseHold(row.hold_id!, "card_network"))
        throw new BankError("INTEGRITY_CARD_HOLD_MISSING");
      const ledgerTxId = creditId ? (() => {
        this.bank.post([
          { accountId: this.bank.systemAccountId("card_settlement"), amount: amountCents,
            kind: "card_network_credit_settlement", actor: row.merchant_id,
            refType: "card_auth", refId: id },
          { accountId: this.bank.systemAccountId("cash_out"), amount: -amountCents,
            kind: "card_network_credit_settlement", actor: row.merchant_id,
            refType: "card_auth", refId: id },
        ]);
        return this.creditCards.purchase(card.customer_id, creditId, row.merchant_id,
          amountCents, row.installment_count, id).ledger_tx_id;
      })() : this.bank.post([
        { accountId: row.account_id, amount: -amountCents, kind: "card_purchase",
          actor: row.merchant_id, refType: "card_auth", refId: id },
        { accountId: this.bank.systemAccountId("card_settlement"), amount: amountCents,
          kind: "card_purchase", actor: row.merchant_id, refType: "card_auth", refId: id },
      ]);
      this.settlement("card_auth", id, amountCents);
      this.bank.db.prepare(`UPDATE card_acquirer_balances
        SET balance_cents=balance_cents+? WHERE merchant_id=?`)
        .run(amountCents, row.merchant_id);
      if (!creditId) {
        this.bank.db.prepare("UPDATE cards SET used_cents=used_cents+? WHERE id=?")
          .run(delta, row.card_id);
        if (row.root_card_id !== row.card_id) this.bank.db.prepare(
          "UPDATE cards SET used_cents=used_cents+? WHERE id=?").run(delta, row.root_card_id);
      }
      this.bank.db.prepare(`UPDATE card_network_authorizations SET status='captured',
        captured_cents=?,ledger_tx_id=? WHERE id=?`).run(amountCents, ledgerTxId, id);
      this.bank.db.prepare(`UPDATE card_clearing_items SET status='cleared',processed_at=?,
        amount_cents=?,error_code=NULL WHERE authorization_id=?`)
        .run(this.bank.now().toISOString(), amountCents, id);
      this.bank.db.prepare(`INSERT INTO card_authorizations VALUES (?,?,?,?,?,?,?)`)
        .run(id, row.card_id, amountCents, row.merchant_id, "approved",
          ledgerTxId, this.bank.now().toISOString());
      if (!creditId) this.cards.cashback.onPurchase(id, card.customer_id, row.account_id, amountCents);
      this.record(id, "0220", { amount_cents: amountCents, settlement: "captured" });
      return this.authorization(id);
    }));
  }

  reverse(id: string): NetworkAuthorization {
    return this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT card_id,root_card_id,amount_cents,status,
        hold_id FROM card_network_authorizations WHERE id=?`).get(id) as
        { card_id: string; root_card_id: string; amount_cents: number;
          status: string; hold_id: string | null } | undefined;
      if (!row) throw new BankError("DEF_NOT_FOUND");
      if (row.status === "reversed") return this.authorization(id);
      const creditId = this.cards.creditAccountId(row.card_id);
      if (row.status !== "approved" || (creditId ? !this.bank.db.prepare(`SELECT 1
        FROM credit_card_network_holds WHERE authorization_id=? AND released_at IS NULL`)
        .get(id) : !row.hold_id)) throw new BankError("BIZ_REVERSAL_NOT_PENDING");
      if (creditId) this.creditCards.releaseReservation(id);
      else {
        this.bank.releaseHold(row.hold_id!, "card_network");
        this.bank.db.prepare("UPDATE cards SET used_cents=used_cents-? WHERE id=?")
          .run(row.amount_cents, row.card_id);
        if (row.root_card_id !== row.card_id) this.bank.db.prepare(
          "UPDATE cards SET used_cents=used_cents-? WHERE id=?").run(row.amount_cents, row.root_card_id);
      }
      this.bank.db.prepare("UPDATE card_network_authorizations SET status='reversed' WHERE id=?")
        .run(id);
      this.bank.db.prepare(`UPDATE card_clearing_items SET status='cancelled',processed_at=?
        WHERE authorization_id=?`).run(this.bank.now().toISOString(), id);
      this.record(id, "0400", { reversed: true });
      return this.authorization(id);
    });
  }

  expirePending(): number {
    const rows = this.bank.db.prepare(`SELECT id FROM card_network_authorizations
      WHERE status='approved' AND expires_at<=?`).all(this.bank.now().toISOString()) as { id: string }[];
    for (const row of rows) this.bank.transaction(() => {
      const current = this.bank.db.prepare(`SELECT card_id,root_card_id,amount_cents,hold_id,status
        FROM card_network_authorizations WHERE id=?`).get(row.id) as
        { card_id: string; root_card_id: string; amount_cents: number;
          hold_id: string | null; status: string } | undefined;
      if (!current || current.status !== "approved") return;
      const creditId = this.cards.creditAccountId(current.card_id);
      if (creditId) this.creditCards.releaseReservation(row.id);
      else {
        if (current.hold_id) this.bank.releaseHold(current.hold_id, "card_network_expiry");
        this.bank.db.prepare("UPDATE cards SET used_cents=used_cents-? WHERE id=?")
          .run(current.amount_cents, current.card_id);
        if (current.root_card_id !== current.card_id) this.bank.db.prepare(
          "UPDATE cards SET used_cents=used_cents-? WHERE id=?")
          .run(current.amount_cents, current.root_card_id);
      }
      this.bank.db.prepare("UPDATE card_network_authorizations SET status='expired' WHERE id=?")
        .run(row.id);
      this.bank.db.prepare(`UPDATE card_clearing_items SET status='expired',processed_at=?
        WHERE authorization_id=?`).run(this.bank.now().toISOString(), row.id);
    });
    return rows.length;
  }

  queueCapture(id: string, amountCents: number): void {
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0) throw new BankError("BIZ_INVALID_AMOUNT");
    this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT a.status,a.amount_cents,a.expires_at,i.status item_status
        FROM card_network_authorizations a JOIN card_clearing_items i ON i.authorization_id=a.id
        WHERE a.id=?`).get(id) as { status: string; amount_cents: number;
          expires_at: string; item_status: string } | undefined;
      if (!row) throw new BankError("DEF_NOT_FOUND");
      if (row.status !== "approved" || row.item_status !== "pending")
        throw new BankError("BIZ_CAPTURE_NOT_APPROVED");
      if (row.expires_at <= this.bank.now().toISOString()) throw new BankError("BIZ_AUTH_EXPIRED");
      if (amountCents > Math.ceil(row.amount_cents * 1.15))
        throw new BankError("BIZ_CAPTURE_EXCEEDS_TOLERANCE");
      this.bank.db.prepare(`UPDATE card_clearing_items SET amount_cents=? WHERE authorization_id=?`)
        .run(amountCents, id);
    });
  }

  clearDue(): { cleared: number; failed: number; expired: number } {
    const expired = this.expirePending();
    const rows = this.bank.db.prepare(`SELECT authorization_id,amount_cents FROM card_clearing_items
      WHERE status='pending' AND due_at<=? ORDER BY due_at,authorization_id`)
      .all(this.bank.now().toISOString()) as { authorization_id: string; amount_cents: number }[];
    let cleared = 0; let failed = 0;
    for (const row of rows) {
      try { this.capture(row.authorization_id, row.amount_cents); cleared++; }
      catch (error) {
        if (!(error instanceof BankError)) throw error;
        failed++;
        this.bank.db.prepare(`UPDATE card_clearing_items SET status='failed',processed_at=?,error_code=?
          WHERE authorization_id=? AND status='pending'`)
          .run(this.bank.now().toISOString(), error.code, row.authorization_id);
      }
    }
    return { cleared, failed, expired };
  }

  dispute(id: string): CardDispute {
    const row = this.bank.db.prepare("SELECT * FROM card_disputes WHERE id=?")
      .get(id) as CardDispute | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    return row;
  }

  openDispute(customerId: string, authorizationId: string, amountCents: number,
    reasonCode: CardDisputeReason | null = null): CardDispute {
    if (reasonCode !== null && !["fraud", "merchant_dispute", "goods_not_received"].includes(reasonCode))
      throw new BankError("BIZ_DISPUTE_REASON_INVALID");
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0) throw new BankError("BIZ_INVALID_AMOUNT");
    return this.traced(() => this.bank.transaction(() => {
      const auth = this.bank.db.prepare(`SELECT a.status,a.captured_cents,a.account_id,a.card_id,
        c.customer_id,c.kind card_kind FROM card_network_authorizations a
        JOIN cards c ON c.id=a.card_id WHERE a.id=?`)
        .get(authorizationId) as { status: string; captured_cents: number;
          account_id: string; card_id: string; customer_id: string;
          card_kind: string } | undefined;
      if (!auth || auth.customer_id !== customerId) throw new BankError("DEF_NOT_FOUND");
      if (auth.status !== "captured") throw new BankError("BIZ_DISPUTE_NOT_CLEARED");
      const creditId = this.cards.creditAccountId(auth.card_id);
      if ((auth.card_kind === "credit") !== Boolean(creditId))
        throw new BankError("INTEGRITY_CREDIT_CARD_LINK");
      const existing = this.bank.db.prepare("SELECT 1 FROM card_disputes WHERE authorization_id=?")
        .get(authorizationId);
      if (existing) throw new BankError("BIZ_DISPUTE_EXISTS");
      const refunded = (this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) amount
        FROM card_refunds WHERE authorization_id=?`).get(authorizationId) as { amount: number }).amount;
      if (amountCents > auth.captured_cents - refunded) throw new BankError("BIZ_DISPUTE_EXCEEDS_PURCHASE");
      if (creditId) {
        const purchase = this.bank.db.prepare(`SELECT amount_cents,refunded_cents
          FROM credit_card_purchases WHERE network_authorization_id=? AND credit_id=?`)
          .get(authorizationId, creditId) as { amount_cents: number;
            refunded_cents: number } | undefined;
        if (!purchase) throw new BankError("INTEGRITY_CREDIT_CARD_NETWORK");
        if (amountCents > purchase.amount_cents - purchase.refunded_cents)
          throw new BankError("BIZ_DISPUTE_EXCEEDS_PURCHASE");
      }
      const caseId = newId("dispute", this.bank.now().getTime());
      const provisionalTxId = this.bank.post([
        { accountId: this.bank.systemAccountId("card_settlement"), amount: -amountCents,
          kind: "card_chargeback", actor: customerId, refType: "card_dispute", refId: caseId },
        { accountId: creditId ? this.bank.systemAccountId("cash_out") : auth.account_id,
          amount: amountCents,
          kind: "card_chargeback", actor: customerId, refType: "card_dispute", refId: caseId },
      ]);
      this.settlement("card_dispute", caseId, -amountCents);
      this.bank.db.prepare(`UPDATE card_acquirer_balances
        SET balance_cents=balance_cents-? WHERE merchant_id=?`)
        .run(amountCents, (this.bank.db.prepare(`SELECT merchant_id FROM card_network_authorizations
          WHERE id=?`).get(authorizationId) as { merchant_id: string }).merchant_id);
      const now = this.bank.now().toISOString();
      this.bank.db.prepare(`INSERT INTO card_disputes
        (id,authorization_id,customer_id,amount_cents,status,provisional_tx_id,opened_at,updated_at,reason_code)
        VALUES (?,?,?,?,'chargeback',?,?,?,?)`)
        .run(caseId, authorizationId, customerId, amountCents, provisionalTxId, now, now, reasonCode);
      this.record(authorizationId, "1440", { dispute_id: caseId, amount_cents: amountCents,
        stage: "chargeback", reason_code: reasonCode });
      return this.dispute(caseId);
    }));
  }

  advanceDispute(id: string, stage: "representment" | "pre_arbitration"): CardDispute {
    return this.bank.transaction(() => {
      const dispute = this.dispute(id);
      if ((stage === "representment" && dispute.status !== "chargeback") ||
        (stage === "pre_arbitration" && dispute.status !== "representment"))
        throw new BankError("BIZ_DISPUTE_STAGE");
      this.bank.db.prepare("UPDATE card_disputes SET status=?,updated_at=? WHERE id=?")
        .run(stage, this.bank.now().toISOString(), id);
      this.record(dispute.authorization_id, "1440", { dispute_id: id, stage });
      return this.dispute(id);
    });
  }

  resolveDispute(id: string, winner: "customer" | "merchant"): CardDispute {
    return this.traced(() => this.bank.transaction(() => {
      const dispute = this.dispute(id);
      if (dispute.status !== "representment" && dispute.status !== "pre_arbitration")
        throw new BankError("BIZ_DISPUTE_STAGE");
      let finalTxId: string | null = null;
      let loss = 0;
      const auth = this.bank.db.prepare(`SELECT a.card_id,a.root_card_id,a.account_id,
        c.kind card_kind FROM card_network_authorizations a
        JOIN cards c ON c.id=a.card_id WHERE a.id=?`).get(dispute.authorization_id) as
        { card_id: string; root_card_id: string; account_id: string; card_kind: string };
      const creditId = this.cards.creditAccountId(auth.card_id);
      if ((auth.card_kind === "credit") !== Boolean(creditId))
        throw new BankError("INTEGRITY_CREDIT_CARD_LINK");
      if (winner === "customer") {
        if (creditId) {
          const purchase = this.bank.db.prepare(`SELECT id FROM credit_card_purchases
            WHERE network_authorization_id=? AND credit_id=?`)
            .get(dispute.authorization_id, creditId) as { id: string } | undefined;
          if (!purchase) throw new BankError("INTEGRITY_CREDIT_CARD_NETWORK");
          this.creditCards.refund(dispute.customer_id, creditId, purchase.id, dispute.amount_cents);
          finalTxId = (this.bank.db.prepare(`SELECT ledger_tx_id FROM credit_card_refunds
            WHERE purchase_id=? ORDER BY rowid DESC LIMIT 1`).get(purchase.id) as
            { ledger_tx_id: string }).ledger_tx_id;
        } else {
          this.cards.cashback.onRefund(dispute.authorization_id, dispute.amount_cents);
          this.bank.db.prepare("UPDATE cards SET used_cents=MAX(0,used_cents-?) WHERE id=?")
            .run(dispute.amount_cents, auth.card_id);
          if (auth.root_card_id !== auth.card_id) this.bank.db.prepare(
            "UPDATE cards SET used_cents=MAX(0,used_cents-?) WHERE id=?")
            .run(dispute.amount_cents, auth.root_card_id);
        }
      }
      if (winner === "merchant") {
        const recoverable = creditId ? dispute.amount_cents : Math.min(dispute.amount_cents,
          Math.max(0, this.bank.availableBalance(auth.account_id)));
        loss = dispute.amount_cents - recoverable;
        finalTxId = this.bank.post([
          ...(recoverable ? [{ accountId: creditId ? this.bank.systemAccountId("cash_out") : auth.account_id,
            amount: -recoverable,
            kind: "card_chargeback_reversal", actor: "network", refType: "card_dispute", refId: id }] : []),
          ...(loss ? [{ accountId: this.bank.systemAccountId("bank_loss"), amount: -loss,
            kind: "card_chargeback_loss", actor: "network", refType: "card_dispute", refId: id }] : []),
          { accountId: this.bank.systemAccountId("card_settlement"), amount: dispute.amount_cents,
            kind: "card_chargeback_reversal", actor: "network", refType: "card_dispute", refId: id },
        ]);
        this.settlement("card_dispute", id, dispute.amount_cents);
        this.bank.db.prepare(`UPDATE card_acquirer_balances
          SET balance_cents=balance_cents+? WHERE merchant_id=?`)
          .run(dispute.amount_cents, (this.bank.db.prepare(`SELECT merchant_id
            FROM card_network_authorizations WHERE id=?`).get(dispute.authorization_id) as
            { merchant_id: string }).merchant_id);
      }
      this.bank.db.prepare(`UPDATE card_disputes SET status=?,final_tx_id=?,loss_cents=?,updated_at=?
        WHERE id=?`).run(winner === "customer" ? "customer_won" : "merchant_won",
          finalTxId, loss, this.bank.now().toISOString(), id);
      this.record(dispute.authorization_id, "1440", { dispute_id: id,
        stage: winner === "customer" ? "customer_won" : "merchant_won", loss_cents: loss });
      return this.dispute(id);
    }));
  }
}
