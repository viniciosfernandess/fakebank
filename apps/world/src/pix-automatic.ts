import { newId } from "./id.ts";
import { Bank, BankError, brtHour, type PixResult,
  type PixTransferInput } from "./bank.ts";

export type AutomaticFrequency = "weekly" | "monthly" | "quarterly" | "semiannual" | "yearly";
type CyclePolicy = "utc_legacy" | "sao_paulo_v1";
export interface PixAutomaticOffer {
  id: string; merchant_customer_id: string; merchant_account: string;
  max_amount_cents: number; frequency: AutomaticFrequency;
  starts_at: string; ends_at: string | null;
  post_due_retry_allowed: number; created_at: string; revoked_at: string | null;
}
export interface PixAutomaticMandate {
  id: string; customer_id: string; from_account: string; merchant_account: string;
  max_amount_cents: number; frequency: AutomaticFrequency; starts_at: string;
  ends_at: string | null; device_id: string; status: "active" | "revoked";
  offer_id: string | null; post_due_retry_allowed: number; cycle_policy: CyclePolicy;
  created_at: string; revoked_at: string | null;
}
export interface PixAutomaticCharge {
  id: string; mandate_id: string; cycle_start: string; due_at: string;
  original_due_at: string;
  amount_cents: number; status: "pending" | "settled" | "failed" | "review_pending" | "reauthorization_required" | "cancelled";
  transfer_id: string | null; hold_id: string | null; error_code: string | null;
  authorization_expires_at: string | null;
  attempt_count: number; next_attempt_at: string | null;
}
export interface PixAutomaticNotification { id: string; customer_id: string;
  mandate_id: string; charge_id: string | null; kind: string; message_pt: string;
  created_at: string; }

function brtDate(date: Date): string {
  const parts = new Intl.DateTimeFormat("en-US", { timeZone: "America/Sao_Paulo",
    year: "numeric", month: "2-digit", day: "2-digit" }).formatToParts(date);
  const part = (type: string) => parts.find((item) => item.type === type)?.value ?? "";
  return `${part("year")}-${part("month")}-${part("day")}`;
}

function eveningRetry(dueAt: string, now: Date): string | null {
  const day = brtDate(new Date(dueAt));
  if (brtDate(now) !== day) return null;
  // The Twin uses modern Sao Paulo time (UTC-3) for its simulated campaign.
  const evening = Date.parse(`${day}T21:00:00.000Z`);
  const end = evening + 3 * 3_600_000;
  const attempt = Math.max(evening, now.getTime() + 60_000);
  return attempt < end ? new Date(attempt).toISOString() : null;
}

const saoPauloParts = new Intl.DateTimeFormat("en-GB", { timeZone: "America/Sao_Paulo",
  year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  second: "2-digit", hourCycle: "h23" });
function localParts(date: Date): { year: number; month: number; day: number; hour: number; minute: number; second: number } {
  const parts = saoPauloParts.formatToParts(date);
  const part = (type: string) => Number(parts.find((item) => item.type === type)?.value);
  return { year: part("year"), month: part("month") - 1, day: part("day"),
    hour: part("hour"), minute: part("minute"), second: part("second") };
}
function cycleAt(start: Date, frequency: AutomaticFrequency, index: number, policy: CyclePolicy): Date {
  if (frequency === "weekly") return new Date(start.getTime() + index * 7 * 86_400_000);
  if (index === 0) return new Date(start);
  const local = policy === "sao_paulo_v1" ? localParts(start) : {
    year: start.getUTCFullYear(), month: start.getUTCMonth(), day: start.getUTCDate(),
    hour: start.getUTCHours(), minute: start.getUTCMinutes(), second: start.getUTCSeconds() };
  const months = frequency === "monthly" ? 1 : frequency === "quarterly" ? 3 :
    frequency === "semiannual" ? 6 : 12;
  const month = local.month + index * months;
  const last = new Date(Date.UTC(local.year, month + 1, 0)).getUTCDate();
  const civil = Date.UTC(local.year, month, Math.min(local.day, last),
    local.hour, local.minute, local.second, start.getUTCMilliseconds());
  if (policy === "utc_legacy") return new Date(civil);
  const representedCivil = (instant: number): number => {
    const actual = localParts(new Date(instant));
    return Date.UTC(actual.year, actual.month, actual.day, actual.hour,
      actual.minute, actual.second, start.getUTCMilliseconds());
  };
  // Inspect offsets on both sides of the intended date. In an overlap, choose
  // the earlier occurrence; in a gap, shift forward by the offset change.
  const offsets = new Set([-86_400_000, 0, 86_400_000].map((delta) => {
    const sample = civil + delta;
    return representedCivil(sample) - sample;
  }));
  const candidates = [...offsets].map((offset) => {
    const instant = civil - offset;
    return { instant, represented: representedCivil(instant) };
  });
  const exact = candidates.filter((candidate) => candidate.represented === civil)
    .sort((left, right) => left.instant - right.instant)[0];
  if (exact) return new Date(exact.instant);
  const afterGap = candidates.filter((candidate) => candidate.represented > civil)
    .sort((left, right) => left.represented - right.represented || left.instant - right.instant)[0];
  if (afterGap) return new Date(afterGap.instant);
  throw new BankError("BIZ_AUTOMATIC_PERIOD");
}

export function automaticPixPosting(bank: Pick<Bank, "db">, chargeId: string):
  { transfer_id: string; ledger_tx_id: string; customer_id: string } | undefined {
  return bank.db.prepare(`SELECT p.id transfer_id,p.ledger_tx_id,m.customer_id
    FROM pix_automatic_charges c JOIN pix_automatic_mandates m ON m.id=c.mandate_id
    JOIN pix_transfers p ON p.id=c.transfer_id AND p.from_account=m.from_account
      AND p.to_account=m.merchant_account AND p.amount=c.amount_cents
      AND p.actor=m.customer_id AND p.idempotency_key='automatic:' || c.id
    WHERE c.id=? AND c.status='settled' AND p.status='settled' AND p.ledger_tx_id IS NOT NULL
      AND (SELECT COUNT(*) FROM ledger_entries e WHERE e.tx_id=p.ledger_tx_id)=2
      AND EXISTS (SELECT 1 FROM ledger_entries e WHERE e.tx_id=p.ledger_tx_id
        AND e.account_id=m.from_account AND e.amount=-c.amount_cents)
      AND EXISTS (SELECT 1 FROM ledger_entries e WHERE e.tx_id=p.ledger_tx_id
        AND e.account_id=m.merchant_account AND e.amount=c.amount_cents)`)
    .get(chargeId) as { transfer_id: string; ledger_tx_id: string; customer_id: string } | undefined;
}

export class PixAutomatic {
  readonly bank: Bank;
  private readonly transferInternal: ((input: PixTransferInput) => PixResult) | undefined;
  constructor(bank: Bank, transferInternal?: (input: PixTransferInput) => PixResult) {
    this.bank = bank;
    this.transferInternal = transferInternal;
    bank.transaction(() => {
      bank.db.exec("SAVEPOINT automatic_schema");
      try {
        this.installSchema();
        bank.db.exec("RELEASE automatic_schema");
      } catch (error) {
        bank.db.exec("ROLLBACK TO automatic_schema");
        bank.db.exec("RELEASE automatic_schema");
        throw error;
      }
    });
  }

  private installSchema(): void {
    const bank = this.bank;
    bank.db.exec(`CREATE TABLE IF NOT EXISTS pix_automatic_offers (
      id TEXT PRIMARY KEY, merchant_customer_id TEXT NOT NULL REFERENCES customers(id),
      merchant_account TEXT NOT NULL REFERENCES accounts(id),
      max_amount_cents INTEGER NOT NULL CHECK(max_amount_cents > 0),
      frequency TEXT NOT NULL CHECK(frequency IN
        ('weekly','monthly','quarterly','semiannual','yearly')),
      starts_at TEXT NOT NULL, ends_at TEXT,
      post_due_retry_allowed INTEGER NOT NULL CHECK(post_due_retry_allowed IN (0,1)),
      created_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS pix_automatic_offers_no_update
      BEFORE UPDATE ON pix_automatic_offers
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_OFFER_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS pix_automatic_offers_no_delete
      BEFORE DELETE ON pix_automatic_offers
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_OFFER_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS pix_automatic_offer_revocations (
      offer_id TEXT PRIMARY KEY REFERENCES pix_automatic_offers(id),
      merchant_customer_id TEXT NOT NULL REFERENCES customers(id),
      revoked_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS pix_automatic_offer_revocations_no_update
      BEFORE UPDATE ON pix_automatic_offer_revocations
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_OFFER_REVOCATION_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS pix_automatic_offer_revocations_no_delete
      BEFORE DELETE ON pix_automatic_offer_revocations
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_OFFER_REVOCATION_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS pix_automatic_mandates (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      offer_id TEXT REFERENCES pix_automatic_offers(id),
      from_account TEXT NOT NULL REFERENCES accounts(id),
      merchant_account TEXT NOT NULL REFERENCES accounts(id),
      max_amount_cents INTEGER NOT NULL CHECK(max_amount_cents > 0),
      frequency TEXT NOT NULL CHECK(frequency IN
        ('weekly','monthly','quarterly','semiannual','yearly')),
      starts_at TEXT NOT NULL, ends_at TEXT, device_id TEXT NOT NULL REFERENCES auth_devices(id),
      status TEXT NOT NULL CHECK(status IN ('active','revoked')),
      post_due_retry_allowed INTEGER NOT NULL DEFAULT 0 CHECK(post_due_retry_allowed IN (0,1)),
      cycle_policy TEXT NOT NULL DEFAULT 'utc_legacy' CHECK(cycle_policy IN ('utc_legacy','sao_paulo_v1')),
      created_at TEXT NOT NULL, revoked_at TEXT
    );
    CREATE TABLE IF NOT EXISTS pix_automatic_charges (
      id TEXT PRIMARY KEY, mandate_id TEXT NOT NULL REFERENCES pix_automatic_mandates(id),
      cycle_start TEXT NOT NULL, due_at TEXT NOT NULL, original_due_at TEXT,
      amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
      status TEXT NOT NULL, transfer_id TEXT, hold_id TEXT, error_code TEXT,
      created_at TEXT NOT NULL, resolved_at TEXT, authorization_expires_at TEXT,
      attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT,
      UNIQUE(mandate_id,cycle_start)
    );
    CREATE INDEX IF NOT EXISTS pix_automatic_charges_due
      ON pix_automatic_charges(status,due_at);
    CREATE TABLE IF NOT EXISTS pix_automatic_post_due_retries (
      charge_id TEXT NOT NULL REFERENCES pix_automatic_charges(id),
      due_at TEXT NOT NULL, requested_at TEXT NOT NULL,
      PRIMARY KEY(charge_id,due_at)
    );
    CREATE TRIGGER IF NOT EXISTS pix_automatic_post_due_retries_no_update
      BEFORE UPDATE ON pix_automatic_post_due_retries
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_RETRY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS pix_automatic_post_due_retries_no_delete
      BEFORE DELETE ON pix_automatic_post_due_retries
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_RETRY_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS pix_automatic_notifications (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      mandate_id TEXT NOT NULL REFERENCES pix_automatic_mandates(id),
      charge_id TEXT REFERENCES pix_automatic_charges(id),
      kind TEXT NOT NULL, message_pt TEXT NOT NULL, created_at TEXT NOT NULL,
      UNIQUE(charge_id,kind)
    );
    CREATE INDEX IF NOT EXISTS pix_automatic_notifications_customer
      ON pix_automatic_notifications(customer_id,created_at);
    CREATE TRIGGER IF NOT EXISTS pix_automatic_notifications_no_update
      BEFORE UPDATE ON pix_automatic_notifications
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_NOTIFICATION_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS pix_automatic_notifications_no_delete
      BEFORE DELETE ON pix_automatic_notifications
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_NOTIFICATION_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS pix_automatic_migrations (
      old_mandate_id TEXT PRIMARY KEY REFERENCES pix_automatic_mandates(id),
      new_mandate_id TEXT NOT NULL UNIQUE REFERENCES pix_automatic_mandates(id),
      offer_id TEXT NOT NULL REFERENCES pix_automatic_offers(id),
      approved_device_id TEXT NOT NULL REFERENCES auth_devices(id),
      created_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS pix_automatic_migrations_no_update
      BEFORE UPDATE ON pix_automatic_migrations
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_MIGRATION_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS pix_automatic_migrations_no_delete
      BEFORE DELETE ON pix_automatic_migrations
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_MIGRATION_IMMUTABLE'); END;`);
    const columns = bank.db.prepare("PRAGMA table_info(pix_automatic_charges)")
      .all() as { name: string }[];
    if (!columns.some((column) => column.name === "attempt_count"))
      bank.db.exec("ALTER TABLE pix_automatic_charges ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0");
    if (!columns.some((column) => column.name === "next_attempt_at"))
      bank.db.exec("ALTER TABLE pix_automatic_charges ADD COLUMN next_attempt_at TEXT");
    if (!columns.some((column) => column.name === "original_due_at"))
      bank.db.exec("ALTER TABLE pix_automatic_charges ADD COLUMN original_due_at TEXT");
    bank.db.exec("UPDATE pix_automatic_charges SET original_due_at=due_at WHERE original_due_at IS NULL");
    const mandateColumns = bank.db.prepare("PRAGMA table_info(pix_automatic_mandates)")
      .all() as { name: string }[];
    if (!mandateColumns.some((column) => column.name === "post_due_retry_allowed"))
      bank.db.exec(`ALTER TABLE pix_automatic_mandates ADD COLUMN
        post_due_retry_allowed INTEGER NOT NULL DEFAULT 0`);
    if (!mandateColumns.some((column) => column.name === "offer_id"))
      bank.db.exec("ALTER TABLE pix_automatic_mandates ADD COLUMN offer_id TEXT REFERENCES pix_automatic_offers(id)");
    if (!mandateColumns.some((column) => column.name === "cycle_policy"))
      bank.db.exec("ALTER TABLE pix_automatic_mandates ADD COLUMN cycle_policy TEXT NOT NULL DEFAULT 'utc_legacy' CHECK(cycle_policy IN ('utc_legacy','sao_paulo_v1'))");
    bank.db.exec(`CREATE TRIGGER IF NOT EXISTS pix_automatic_cycle_policy_immutable
      BEFORE UPDATE OF cycle_policy ON pix_automatic_mandates
      WHEN NEW.cycle_policy<>OLD.cycle_policy
      BEGIN SELECT RAISE(ABORT, 'AUTOMATIC_CYCLE_POLICY_IMMUTABLE'); END;`);
  }

  offer(id: string): PixAutomaticOffer {
    const row = this.bank.db.prepare(`SELECT o.*,r.revoked_at
      FROM pix_automatic_offers o LEFT JOIN pix_automatic_offer_revocations r
        ON r.offer_id=o.id WHERE o.id=?`)
      .get(id) as PixAutomaticOffer | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    return row;
  }

  createOffer(merchantCustomerId: string, merchantAccount: string,
    maxAmount: number, frequency: AutomaticFrequency, startsAt: string,
    endsAt: string | undefined, postDueRetryAllowed: boolean): PixAutomaticOffer {
    const merchant = this.bank.ownAccount(merchantCustomerId, merchantAccount);
    if (merchant.kind !== "merchant" || merchant.status !== "active")
      throw new BankError("BIZ_AUTOMATIC_MERCHANT");
    if (!Number.isSafeInteger(maxAmount) || maxAmount <= 0 || maxAmount > 2_000_000)
      throw new BankError("BIZ_INVALID_AMOUNT");
    const start = Date.parse(startsAt);
    const end = endsAt ? Date.parse(endsAt) : null;
    if (!Number.isFinite(start) || start <= this.bank.now().getTime() ||
      start > this.bank.now().getTime() + 365 * 86_400_000 ||
      end !== null && (!Number.isFinite(end) || end < start))
      throw new BankError("BIZ_AUTOMATIC_PERIOD");
    const id = newId("offer", this.bank.now().getTime());
    return this.bank.transaction(() => {
      this.bank.db.prepare(`INSERT INTO pix_automatic_offers
        (id,merchant_customer_id,merchant_account,max_amount_cents,frequency,
          starts_at,ends_at,post_due_retry_allowed,created_at)
        VALUES (?,?,?,?,?,?,?,?,?)`).run(id, merchantCustomerId, merchantAccount,
          maxAmount, frequency, new Date(start).toISOString(),
          end === null ? null : new Date(end).toISOString(),
          postDueRetryAllowed ? 1 : 0, this.bank.now().toISOString());
      this.bank.telemetry.emit({ source: "pix", category: "automatic",
        action: "offer_created", outcome: "success", userId: merchantCustomerId,
        accountId: merchantAccount, amountCents: maxAmount,
        message: "Automatic Pix merchant offer created" });
      return this.offer(id);
    });
  }

  revokeOffer(merchantCustomerId: string, offerId: string): PixAutomaticOffer {
    return this.bank.transaction(() => {
      const offer = this.offer(offerId);
      if (offer.merchant_customer_id !== merchantCustomerId)
        throw new BankError("DEF_NOT_FOUND");
      if (offer.revoked_at) return offer;
      this.bank.db.prepare(`INSERT INTO pix_automatic_offer_revocations
        (offer_id,merchant_customer_id,revoked_at) VALUES (?,?,?)`)
        .run(offerId, merchantCustomerId, this.bank.now().toISOString());
      this.bank.telemetry.emit({ source: "pix", category: "automatic",
        action: "offer_revoked", outcome: "success", userId: merchantCustomerId,
        accountId: offer.merchant_account,
        message: "Automatic Pix merchant offer revoked" });
      return this.offer(offerId);
    });
  }

  mandate(customerId: string, id: string): PixAutomaticMandate {
    const row = this.bank.db.prepare(`SELECT * FROM pix_automatic_mandates
      WHERE id=? AND customer_id=?`).get(id, customerId) as PixAutomaticMandate | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    return row;
  }

  list(customerId: string): PixAutomaticMandate[] {
    return this.bank.db.prepare(`SELECT * FROM pix_automatic_mandates WHERE customer_id=?
      ORDER BY created_at DESC,id DESC LIMIT 100`).all(customerId) as unknown as PixAutomaticMandate[];
  }

  notifications(customerId: string, options: { before?: string | undefined;
    limit?: number | undefined } = {}): PixAutomaticNotification[] {
    this.bank.customer(customerId);
    const cursor = options.before ? this.bank.db.prepare(`SELECT id,created_at
      FROM pix_automatic_notifications WHERE id=? AND customer_id=?`)
      .get(options.before, customerId) as { id: string; created_at: string } | undefined : undefined;
    if (options.before && !cursor) throw new BankError("DEF_NOT_FOUND");
    const rows = this.bank.db.prepare(`SELECT id,customer_id,mandate_id,charge_id,kind,
      message_pt,created_at FROM pix_automatic_notifications WHERE customer_id=?
      AND (? IS NULL OR created_at<? OR (created_at=? AND id<?))
      ORDER BY created_at DESC,id DESC LIMIT ?`).all(customerId,
        cursor?.created_at ?? null, cursor?.created_at ?? null,
        cursor?.created_at ?? null, cursor?.id ?? null, options.limit ?? 100) as unknown as
      PixAutomaticNotification[];
    return rows.map((row) => ({ ...row,
      kind: row.kind.replace(/_post_due_\d+$/, "") }));
  }

  private notify(customerId: string, mandateId: string, chargeId: string | null,
    kind: string, messagePt: string): void {
    let storedKind = kind;
    if (chargeId && (kind === "charge_failed" || kind === "charge_retry_scheduled")) {
      const { count } = this.bank.db.prepare(`SELECT COUNT(*) count
        FROM pix_automatic_post_due_retries WHERE charge_id=?`).get(chargeId) as
        { count: number };
      if (count) storedKind = `${kind}_post_due_${count}`;
    }
    this.bank.db.prepare(`INSERT OR IGNORE INTO pix_automatic_notifications
      (id,customer_id,mandate_id,charge_id,kind,message_pt,created_at)
      VALUES (?,?,?,?,?,?,?)`).run(newId("notice", this.bank.now().getTime()),
        customerId, mandateId, chargeId, storedKind, messagePt, this.bank.now().toISOString());
  }

  charges(customerId: string, mandateId: string): PixAutomaticCharge[] {
    this.mandate(customerId, mandateId);
    return this.bank.db.prepare(`SELECT id,mandate_id,cycle_start,due_at,amount_cents,
      original_due_at,status,transfer_id,hold_id,error_code,authorization_expires_at,
      attempt_count,next_attempt_at
      FROM pix_automatic_charges WHERE mandate_id=? ORDER BY due_at DESC,id DESC LIMIT 100`)
      .all(mandateId) as unknown as PixAutomaticCharge[];
  }

  cancelCharge(customerId: string, chargeId: string): PixAutomaticCharge {
    return this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT c.* FROM pix_automatic_charges c
        JOIN pix_automatic_mandates m ON m.id=c.mandate_id
        WHERE c.id=? AND m.customer_id=?`).get(chargeId, customerId) as
        PixAutomaticCharge | undefined;
      if (!row) throw new BankError("DEF_NOT_FOUND");
      if (row.status !== "pending")
        throw new BankError("BIZ_AUTOMATIC_CANCEL_UNAVAILABLE");
      if (brtDate(this.bank.now()) >= brtDate(new Date(row.due_at)))
        throw new BankError("BIZ_AUTOMATIC_CANCEL_UNAVAILABLE");
      this.bank.db.prepare(`UPDATE pix_automatic_charges SET status='cancelled',
        error_code='BIZ_AUTOMATIC_CANCELLED',authorization_expires_at=NULL,
        next_attempt_at=NULL,resolved_at=? WHERE id=?`)
        .run(this.bank.now().toISOString(), chargeId);
      this.notify(customerId, row.mandate_id, chargeId, "charge_cancelled",
        "Cobrança automática cancelada.");
      this.bank.telemetry.emit({ source: "pix", category: "automatic",
        action: "charge_cancelled", outcome: "success", userId: customerId,
        message: "Automatic Pix charge cancelled by payer" });
      return this.bank.db.prepare(`SELECT * FROM pix_automatic_charges WHERE id=?`)
        .get(chargeId) as unknown as PixAutomaticCharge;
    });
  }

  cancelMerchantCharge(merchantCustomerId: string, chargeId: string): PixAutomaticCharge {
    return this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT c.*,m.customer_id payer_customer_id,
        m.from_account,m.merchant_account FROM pix_automatic_charges c
        JOIN pix_automatic_mandates m ON m.id=c.mandate_id
        JOIN accounts a ON a.id=m.merchant_account
        WHERE c.id=? AND a.customer_id=?`).get(chargeId, merchantCustomerId) as
        (PixAutomaticCharge & { payer_customer_id: string; from_account: string;
          merchant_account: string }) | undefined;
      if (!row) throw new BankError("DEF_NOT_FOUND");
      if (row.status !== "pending")
        throw new BankError("BIZ_AUTOMATIC_CANCEL_UNAVAILABLE");
      const previousDay = new Date(Date.parse(brtDate(new Date(row.due_at))) -
        86_400_000).toISOString().slice(0, 10);
      const today = brtDate(this.bank.now());
      if (today > previousDay || today === previousDay && brtHour(this.bank.now()) >= 22)
        throw new BankError("BIZ_AUTOMATIC_CANCEL_UNAVAILABLE");
      this.bank.db.prepare(`UPDATE pix_automatic_charges SET status='cancelled',
        error_code='BIZ_AUTOMATIC_MERCHANT_CANCELLED',authorization_expires_at=NULL,
        next_attempt_at=NULL,resolved_at=? WHERE id=?`)
        .run(this.bank.now().toISOString(), chargeId);
      this.notify(row.payer_customer_id, row.mandate_id, chargeId, "charge_cancelled",
        "Cobrança automática cancelada pelo recebedor.");
      this.bank.telemetry.emit({ source: "pix", category: "automatic",
        action: "charge_cancelled", outcome: "success", userId: merchantCustomerId,
        accountId: row.from_account, counterparty: row.merchant_account,
        reasonCodes: ["BIZ_AUTOMATIC_MERCHANT_CANCELLED"],
        message: "Automatic Pix charge cancelled by merchant" });
      return this.bank.db.prepare(`SELECT * FROM pix_automatic_charges WHERE id=?`)
        .get(chargeId) as unknown as PixAutomaticCharge;
    });
  }

  grant(customerId: string, from: string, merchant: string, maxAmount: number,
    frequency: AutomaticFrequency, startsAt: string, endsAt: string | undefined,
    deviceId: string, offerId?: string): PixAutomaticMandate {
    const payer = this.bank.ownAccount(customerId, from);
    const payee = this.bank.account(merchant);
    if (payer.status !== "active" || payee.status !== "active")
      throw new BankError("DEF_ACCOUNT_FROZEN");
    if (payee.kind !== "merchant" || payee.customer_id === customerId)
      throw new BankError("BIZ_AUTOMATIC_MERCHANT");
    if (!Number.isSafeInteger(maxAmount) || maxAmount <= 0 || maxAmount > 2_000_000)
      throw new BankError("BIZ_INVALID_AMOUNT");
    const start = Date.parse(startsAt);
    const end = endsAt ? Date.parse(endsAt) : null;
    if (!Number.isFinite(start) || start <= this.bank.now().getTime() ||
      start > this.bank.now().getTime() + 365 * 86_400_000 ||
      (end !== null && (!Number.isFinite(end) || end < start)))
      throw new BankError("BIZ_AUTOMATIC_PERIOD");
    const device = this.bank.db.prepare(`SELECT customer_id,revoked_at FROM auth_devices WHERE id=?`)
      .get(deviceId) as { customer_id: string; revoked_at: string | null } | undefined;
    if (!device || device.customer_id !== customerId || device.revoked_at)
      throw new BankError("DEF_UNAUTHORIZED");
    const offer = offerId ? this.offer(offerId) : null;
    if (offer?.revoked_at) throw new BankError("BIZ_AUTOMATIC_OFFER_REVOKED");
    if (offer && (offer.merchant_account !== merchant ||
      offer.merchant_customer_id !== payee.customer_id ||
      offer.max_amount_cents !== maxAmount || offer.frequency !== frequency ||
      offer.starts_at !== new Date(start).toISOString() ||
      offer.ends_at !== (end === null ? null : new Date(end).toISOString())))
      throw new BankError("BIZ_AUTOMATIC_OFFER_MISMATCH");
    const id = newId("mandate", this.bank.now().getTime());
    return this.bank.transaction(() => {
      this.bank.db.prepare(`INSERT INTO pix_automatic_mandates
        (id,customer_id,offer_id,from_account,merchant_account,max_amount_cents,frequency,
          starts_at,ends_at,device_id,status,post_due_retry_allowed,cycle_policy,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,'active',?,'sao_paulo_v1',?)`).run(id, customerId, offerId ?? null,
          from, merchant,
          maxAmount, frequency, new Date(start).toISOString(), end === null ? null :
            new Date(end).toISOString(), deviceId, offer?.post_due_retry_allowed ?? 0,
          this.bank.now().toISOString());
      this.notify(customerId, id, null, "mandate_granted",
        "Autorização de Pix Automático concedida.");
      this.bank.telemetry.emit({ source: "pix", category: "automatic",
        action: "mandate_granted", outcome: "success", userId: customerId,
        accountId: from, counterparty: merchant, deviceId,
        message: "Automatic Pix mandate granted" });
      return this.mandate(customerId, id);
    });
  }

  revoke(customerId: string, id: string): PixAutomaticMandate {
    return this.bank.transaction(() => {
      const mandate = this.mandate(customerId, id);
      if (mandate.status === "revoked") return mandate;
      const today = brtDate(this.bank.now());
      const nextDayStart = new Date(Date.parse(`${today}T03:00:00.000Z`) +
        86_400_000).toISOString();
      this.bank.db.prepare(`UPDATE pix_automatic_mandates SET status='revoked',revoked_at=?
        WHERE id=?`).run(this.bank.now().toISOString(), id);
      this.bank.db.prepare(`UPDATE pix_automatic_charges SET status='cancelled',
        error_code='BIZ_AUTOMATIC_REVOKED',next_attempt_at=NULL,resolved_at=?
        WHERE mandate_id=? AND due_at>=? AND status IN ('pending','reauthorization_required')`)
        .run(this.bank.now().toISOString(), id, nextDayStart);
      const held = this.bank.db.prepare(`SELECT id,hold_id FROM pix_automatic_charges
        WHERE mandate_id=? AND due_at>=? AND status='review_pending'`)
        .all(id, nextDayStart) as
        { id: string; hold_id: string }[];
      for (const charge of held) {
        const hold = this.bank.riskPixHold(charge.hold_id);
        if (!hold) throw new BankError("INTEGRITY_RISK_HOLD_MISSING");
        if (hold.status === "pending") this.bank.resolveRiskPixHold(hold.id, "reject", "mandate_revoked");
        if (hold.status !== "approved") this.bank.db.prepare(`UPDATE pix_automatic_charges
          SET status='cancelled',error_code='BIZ_AUTOMATIC_REVOKED',resolved_at=? WHERE id=?`)
          .run(this.bank.now().toISOString(), charge.id);
      }
      this.notify(customerId, id, null, "mandate_revoked",
        "Autorização cancelada. Cobranças futuras foram canceladas.");
      this.bank.telemetry.emit({ source: "pix", category: "automatic",
        action: "mandate_revoked", outcome: "success", userId: customerId,
        accountId: mandate.from_account, counterparty: mandate.merchant_account,
        message: "Automatic Pix mandate revoked" });
      return this.mandate(customerId, id);
    });
  }

  migrateLegacyMandate(customerId: string, id: string, offerId: string,
    deviceId: string): PixAutomaticMandate {
    return this.bank.transaction(() => {
      const old = this.mandate(customerId, id);
      const existing = this.bank.db.prepare(`SELECT new_mandate_id,offer_id
        FROM pix_automatic_migrations WHERE old_mandate_id=?`).get(id) as
        { new_mandate_id: string; offer_id: string } | undefined;
      if (existing) {
        if (existing.offer_id !== offerId)
          throw new BankError("BIZ_AUTOMATIC_MIGRATION_CONFLICT");
        return this.mandate(customerId, existing.new_mandate_id);
      }
      if (old.cycle_policy !== "utc_legacy" || old.status !== "active")
        throw new BankError("BIZ_AUTOMATIC_MIGRATION_UNAVAILABLE");
      if (this.bank.db.prepare(`SELECT 1 FROM pix_automatic_charges
        WHERE mandate_id=? AND status IN
          ('pending','review_pending','reauthorization_required') LIMIT 1`).get(id))
        throw new BankError("BIZ_AUTOMATIC_MIGRATION_PENDING");
      const offer = this.offer(offerId);
      if (offer.merchant_account !== old.merchant_account ||
        offer.max_amount_cents !== old.max_amount_cents ||
        offer.frequency !== old.frequency)
        throw new BankError("BIZ_AUTOMATIC_OFFER_MISMATCH");
      const replacement = this.grant(customerId, old.from_account,
        old.merchant_account, offer.max_amount_cents, offer.frequency,
        offer.starts_at, offer.ends_at ?? undefined, deviceId, offerId);
      this.revoke(customerId, id);
      this.bank.db.prepare(`INSERT INTO pix_automatic_migrations
        (old_mandate_id,new_mandate_id,offer_id,approved_device_id,created_at)
        VALUES (?,?,?,?,?)`).run(id, replacement.id, offerId, deviceId,
          this.bank.now().toISOString());
      return replacement;
    });
  }

  reauthorize(customerId: string, chargeId: string, deviceId: string): PixAutomaticCharge {
    return this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT c.*,m.status mandate_status,
        m.customer_id,m.device_id FROM pix_automatic_charges c
        JOIN pix_automatic_mandates m ON m.id=c.mandate_id
        WHERE c.id=? AND m.customer_id=?`).get(chargeId, customerId) as
        (PixAutomaticCharge & { mandate_status: string; customer_id: string;
          device_id: string }) | undefined;
      if (!row) throw new BankError("DEF_NOT_FOUND");
      if (row.mandate_status !== "active" || row.status !== "reauthorization_required")
        throw new BankError("BIZ_AUTOMATIC_REAUTH_UNAVAILABLE");
      const device = this.bank.db.prepare(`SELECT customer_id,revoked_at FROM auth_devices WHERE id=?`)
        .get(deviceId) as { customer_id: string; revoked_at: string | null } | undefined;
      if (!device || device.customer_id !== customerId || device.revoked_at)
        throw new BankError("DEF_UNAUTHORIZED");
      this.bank.db.prepare(`UPDATE pix_automatic_mandates SET device_id=? WHERE id=?`)
        .run(deviceId, row.mandate_id);
      this.bank.db.prepare(`UPDATE pix_automatic_charges SET status='pending',
        error_code=NULL,authorization_expires_at=? WHERE id=?`)
        .run(new Date(this.bank.now().getTime() + 5 * 60_000).toISOString(), chargeId);
      this.notify(customerId, row.mandate_id, chargeId, "charge_reauthorized",
        "Cobrança automática reautorizada.");
      this.bank.telemetry.emit({ source: "pix", category: "automatic",
        action: "charge_reauthorized", outcome: "success", userId: customerId,
        message: "Automatic Pix charge reauthorized by payer" });
      return this.bank.db.prepare(`SELECT * FROM pix_automatic_charges WHERE id=?`)
        .get(chargeId) as unknown as PixAutomaticCharge;
    });
  }

  charge(merchantCustomerId: string, mandateId: string, amount: number,
    dueAt: string): PixAutomaticCharge {
    return this.bank.transaction(() => {
      const mandate = this.bank.db.prepare(`SELECT * FROM pix_automatic_mandates WHERE id=?`)
        .get(mandateId) as PixAutomaticMandate | undefined;
      if (!mandate || this.bank.account(mandate.merchant_account).customer_id !== merchantCustomerId)
        throw new BankError("DEF_NOT_FOUND");
      if (mandate.status !== "active") throw new BankError("BIZ_AUTOMATIC_REVOKED");
      if (!Number.isSafeInteger(amount) || amount <= 0 || amount > mandate.max_amount_cents)
        throw new BankError("BIZ_AUTOMATIC_LIMIT");
      const due = Date.parse(dueAt);
      if (!Number.isFinite(due) || due < this.bank.now().getTime() ||
        due > this.bank.now().getTime() + 365 * 86_400_000 ||
        due < Date.parse(mandate.starts_at) ||
        (mandate.ends_at && due > Date.parse(mandate.ends_at)))
        throw new BankError("BIZ_AUTOMATIC_PERIOD");
      const daysAhead = (Date.parse(brtDate(new Date(due))) -
        Date.parse(brtDate(this.bank.now()))) / 86_400_000;
      if (daysAhead < 2 || daysAhead > 10)
        throw new BankError("BIZ_AUTOMATIC_INSTRUCTION_WINDOW");
      if (brtHour(new Date(due)) >= 8) throw new BankError("BIZ_AUTOMATIC_WINDOW");
      const start = new Date(mandate.starts_at);
      let index = 0;
      while (cycleAt(start, mandate.frequency, index + 1, mandate.cycle_policy).getTime() <= due) index++;
      const cycle = cycleAt(start, mandate.frequency, index, mandate.cycle_policy);
      if (this.bank.db.prepare(`SELECT 1 FROM pix_automatic_charges
        WHERE mandate_id=? AND cycle_start=?`).get(mandateId, cycle.toISOString()))
        throw new BankError("BIZ_AUTOMATIC_CYCLE_DUPLICATE");
      const id = newId("charge", this.bank.now().getTime());
      this.bank.db.prepare(`INSERT INTO pix_automatic_charges
        (id,mandate_id,cycle_start,due_at,original_due_at,amount_cents,status,created_at)
        VALUES (?,?,?,?,?,?,'pending',?)`).run(id, mandateId, cycle.toISOString(),
          new Date(due).toISOString(), new Date(due).toISOString(), amount,
          this.bank.now().toISOString());
      this.notify(mandate.customer_id, mandateId, id, "charge_scheduled",
        "Nova cobrança automática agendada.");
      this.bank.telemetry.emit({ source: "pix", category: "automatic",
        action: "charge_submitted", outcome: "success", userId: mandate.customer_id,
        accountId: mandate.from_account, counterparty: mandate.merchant_account,
        amountCents: amount, message: "Automatic Pix charge submitted" });
      return this.bank.db.prepare(`SELECT * FROM pix_automatic_charges WHERE id=?`)
        .get(id) as unknown as PixAutomaticCharge;
    });
  }

  retryCharge(merchantCustomerId: string, chargeId: string,
    dueAt: string): PixAutomaticCharge {
    return this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT c.*,m.customer_id payer_customer_id,
        m.from_account,m.merchant_account,m.starts_at,m.ends_at,m.frequency,m.cycle_policy,
        m.status mandate_status,m.post_due_retry_allowed
        FROM pix_automatic_charges c
        JOIN pix_automatic_mandates m ON m.id=c.mandate_id
        JOIN accounts a ON a.id=m.merchant_account
        WHERE c.id=? AND a.customer_id=?`).get(chargeId, merchantCustomerId) as
        (PixAutomaticCharge & { payer_customer_id: string; from_account: string;
          merchant_account: string; starts_at: string; ends_at: string | null;
          frequency: AutomaticFrequency; cycle_policy: CyclePolicy; mandate_status: string;
          post_due_retry_allowed: number }) | undefined;
      if (!row) throw new BankError("DEF_NOT_FOUND");
      if (row.mandate_status !== "active" || !row.post_due_retry_allowed ||
        row.status !== "failed" || ![
          "BIZ_INSUFFICIENT_FUNDS", "BIZ_DAILY_LIMIT", "BIZ_AUTOMATIC_RETRY_WINDOW",
          "BIZ_AUTOMATIC_FIRST_WINDOW_MISSED",
        ].includes(row.error_code ?? "") ||
        this.bank.db.prepare(`SELECT 1 FROM pix_transfers
          WHERE from_account=? AND idempotency_key=?`).get(
            row.from_account, `automatic:${chargeId}`))
        throw new BankError("BIZ_AUTOMATIC_RETRY_UNAVAILABLE");
      const due = Date.parse(dueAt);
      if (!Number.isFinite(due) || due <= this.bank.now().getTime() ||
        brtHour(new Date(due)) >= 8)
        throw new BankError("BIZ_AUTOMATIC_RETRY_PERIOD");
      const originalDay = brtDate(new Date(row.original_due_at));
      const retryDay = brtDate(new Date(due));
      const daysAfter = (Date.parse(retryDay) - Date.parse(originalDay)) / 86_400_000;
      const daysAhead = (Date.parse(retryDay) - Date.parse(brtDate(this.bank.now()))) /
        86_400_000;
      let nextCycleIndex = 0;
      const start = new Date(row.starts_at);
      while (cycleAt(start, row.frequency, nextCycleIndex, row.cycle_policy).getTime() <=
        Date.parse(row.cycle_start)) nextCycleIndex++;
      const nextCycleDay = brtDate(cycleAt(start, row.frequency, nextCycleIndex, row.cycle_policy));
      if (daysAfter < 1 || daysAfter > 7 || daysAhead < 1 ||
        retryDay >= nextCycleDay ||
        row.ends_at && due > Date.parse(row.ends_at))
        throw new BankError("BIZ_AUTOMATIC_RETRY_PERIOD");
      const { count } = this.bank.db.prepare(`SELECT COUNT(*) count FROM
        pix_automatic_post_due_retries WHERE charge_id=?`).get(chargeId) as
        { count: number };
      if (count >= 3 || this.bank.db.prepare(`SELECT 1 FROM pix_automatic_post_due_retries
        WHERE charge_id=? AND due_at=?`).get(chargeId, new Date(due).toISOString()))
        throw new BankError("BIZ_AUTOMATIC_RETRY_LIMIT");
      this.bank.db.prepare(`INSERT INTO pix_automatic_post_due_retries
        (charge_id,due_at,requested_at) VALUES (?,?,?)`).run(chargeId,
          new Date(due).toISOString(), this.bank.now().toISOString());
      this.bank.db.prepare(`UPDATE pix_automatic_charges SET status='pending',
        due_at=?,attempt_count=0,next_attempt_at=NULL,error_code=NULL,resolved_at=NULL
        WHERE id=?`).run(new Date(due).toISOString(), chargeId);
      this.notify(row.payer_customer_id, row.mandate_id, chargeId,
        `charge_post_due_retry_${count + 1}`,
        "Nova tentativa de cobrança automática agendada pelo recebedor.");
      this.bank.telemetry.emit({ source: "pix", category: "automatic",
        action: "charge_post_due_retry", outcome: "success",
        userId: merchantCustomerId, accountId: row.from_account,
        counterparty: row.merchant_account, amountCents: row.amount_cents,
        message: "Automatic Pix post-due retry instructed by merchant" });
      return this.bank.db.prepare(`SELECT * FROM pix_automatic_charges WHERE id=?`)
        .get(chargeId) as unknown as PixAutomaticCharge;
    });
  }

  private reconcileReviews(): void {
    const rows = this.bank.db.prepare(`SELECT c.id,c.mandate_id,
      m.customer_id,h.status hold_status,h.transfer_id
      FROM pix_automatic_charges c JOIN risk_pix_holds h ON h.id=c.hold_id
      JOIN pix_automatic_mandates m ON m.id=c.mandate_id
      WHERE c.status='review_pending' AND h.status<>'pending'`).all() as
      { id: string; mandate_id: string; customer_id: string;
        hold_status: string; transfer_id: string | null }[];
    for (const row of rows) this.bank.transaction(() => {
      const settled = row.hold_status === "approved" && Boolean(row.transfer_id);
      this.bank.db.prepare(`UPDATE pix_automatic_charges
        SET status=?,transfer_id=?,error_code=?,resolved_at=? WHERE id=?`)
        .run(settled ? "settled" : "failed", row.transfer_id,
          settled ? null : `BIZ_RISK_${row.hold_status.toUpperCase()}`,
          this.bank.now().toISOString(), row.id);
      this.notify(row.customer_id, row.mandate_id, row.id,
        settled ? "charge_settled" : "charge_failed",
        settled ? "Cobrança automática liquidada." :
          "Cobrança automática não liquidada após análise.");
    });
  }

  executeDue(paused?: (chargeId: string) => boolean): { succeeded: number; failed: number } {
    this.bank.expireRiskPixHolds();
    this.reconcileReviews();
    const rows = this.bank.db.prepare(`SELECT c.*,m.customer_id,m.from_account,
      m.merchant_account,m.max_amount_cents,m.ends_at,m.device_id,
      m.status mandate_status,m.revoked_at
      FROM pix_automatic_charges c JOIN pix_automatic_mandates m ON m.id=c.mandate_id
      WHERE c.status='pending' AND COALESCE(c.next_attempt_at,c.due_at)<=?
      ORDER BY COALESCE(c.next_attempt_at,c.due_at),c.id LIMIT 100`)
      .all(this.bank.now().toISOString()) as unknown as (PixAutomaticCharge & {
        customer_id: string; from_account: string; merchant_account: string;
        max_amount_cents: number; ends_at: string | null; device_id: string;
        mandate_status: string; revoked_at: string | null })[];
    let succeeded = 0; let failed = 0;
    for (const row of rows) {
      if (paused?.(row.id)) continue;
      const settledEarlier = Boolean(this.bank.db.prepare(`SELECT 1 FROM pix_transfers
        WHERE from_account=? AND idempotency_key=? AND status IN
          ('settled','returned_partial','returned_full')`).get(
            row.from_account, `automatic:${row.id}`));
      if (!settledEarlier && row.next_attempt_at === null &&
        (brtDate(this.bank.now()) !== brtDate(new Date(row.due_at)) ||
          brtHour(this.bank.now()) >= 8)) {
        const retryAt = row.attempt_count < 2 ? eveningRetry(row.due_at, this.bank.now()) : null;
        this.bank.transaction(() => {
          if (retryAt) {
            this.bank.db.prepare(`UPDATE pix_automatic_charges SET attempt_count=attempt_count+1,
              next_attempt_at=?,error_code='BIZ_AUTOMATIC_FIRST_WINDOW_MISSED'
              WHERE id=? AND status='pending'`).run(retryAt, row.id);
            this.notify(row.customer_id, row.mandate_id, row.id, "charge_retry_scheduled",
              "Cobrança não liquidada pela manhã. Nova tentativa será feita hoje entre 18h e 21h.");
          } else {
            this.bank.db.prepare(`UPDATE pix_automatic_charges SET status='failed',
              error_code='BIZ_AUTOMATIC_FIRST_WINDOW_MISSED',resolved_at=?
              WHERE id=? AND status='pending'`)
              .run(this.bank.now().toISOString(), row.id);
            this.notify(row.customer_id, row.mandate_id, row.id, "charge_failed",
              "Cobrança automática não liquidada após a janela de pagamento.");
          }
          this.bank.telemetry.emit({ source: "pix", category: "automatic",
            action: retryAt ? "charge_retry_scheduled" : "charge_failed",
            outcome: "failure", severity: "warn",
            userId: row.customer_id, accountId: row.from_account,
            counterparty: row.merchant_account, amountCents: row.amount_cents,
            reasonCodes: ["BIZ_AUTOMATIC_FIRST_WINDOW_MISSED"],
            message: "Automatic Pix first payment window expired" });
        });
        if (!retryAt) failed++;
        continue;
      }
      if (!settledEarlier && row.next_attempt_at !== null && (brtDate(this.bank.now()) !== brtDate(new Date(row.due_at)) ||
        brtHour(this.bank.now()) < 18 || brtHour(this.bank.now()) >= 21)) {
        this.bank.transaction(() => {
          this.bank.db.prepare(`UPDATE pix_automatic_charges SET status='failed',
            error_code='BIZ_AUTOMATIC_RETRY_WINDOW',resolved_at=?,next_attempt_at=NULL
            WHERE id=? AND status='pending'`)
            .run(this.bank.now().toISOString(), row.id);
          this.notify(row.customer_id, row.mandate_id, row.id, "charge_failed",
            "Cobrança automática não liquidada após a última tentativa.");
          this.bank.telemetry.emit({ source: "pix", category: "automatic",
            action: "charge_failed", outcome: "failure", severity: "warn",
            userId: row.customer_id, accountId: row.from_account,
            counterparty: row.merchant_account, amountCents: row.amount_cents,
            reasonCodes: ["BIZ_AUTOMATIC_RETRY_WINDOW"],
            message: "Automatic Pix retry window expired" });
        });
        failed++;
        continue;
      }
      const activeForDueDay = row.mandate_status === "active" ||
        row.revoked_at && brtDate(new Date(row.revoked_at)) === brtDate(new Date(row.due_at));
      if (!settledEarlier && (!activeForDueDay || row.amount_cents > row.max_amount_cents ||
        (row.ends_at && row.due_at > row.ends_at))) {
        this.bank.transaction(() => {
          this.bank.db.prepare(`UPDATE pix_automatic_charges SET status='cancelled',
            error_code='BIZ_AUTOMATIC_REVOKED',resolved_at=? WHERE id=? AND status='pending'`)
            .run(this.bank.now().toISOString(), row.id);
          this.notify(row.customer_id, row.mandate_id, row.id, "charge_cancelled",
            "Cobrança automática cancelada após revogação.");
        });
        continue;
      }
      let transfer: PixResult;
      try {
        const input = { from: row.from_account,
          to: row.merchant_account, amount: row.amount_cents,
          idempotencyKey: `automatic:${row.id}`, actor: row.customer_id,
          deviceId: row.device_id, product: "automatic" as const,
          stepUpVerified: Boolean(row.authorization_expires_at &&
            row.authorization_expires_at > this.bank.now().toISOString()) };
        transfer = this.transferInternal ? this.transferInternal(input) :
          this.bank.transferPix(input);
      } catch (error) {
        if (!(error instanceof BankError) || error.code.startsWith("INTEGRITY_") ||
          error.code === "BIZ_IDEMPOTENCY_CONFLICT") throw error;
        const code = error.code;
        const holdId = code === "BIZ_RISK_HOLD"
          ? error.risk?.holdId : undefined;
        const retryAt = row.next_attempt_at === null && row.attempt_count <= 1 &&
          brtHour(this.bank.now()) < 8 &&
          (code === "BIZ_INSUFFICIENT_FUNDS" || code === "BIZ_DAILY_LIMIT")
          ? eveningRetry(row.due_at, this.bank.now()) : null;
        if (retryAt) {
          this.bank.transaction(() => {
            this.bank.db.prepare(`UPDATE pix_automatic_charges SET attempt_count=attempt_count+1,
              next_attempt_at=?,error_code=? WHERE id=? AND status='pending'`)
              .run(retryAt, code, row.id);
            this.notify(row.customer_id, row.mandate_id, row.id, "charge_retry_scheduled",
              "Cobrança não liquidada. Nova tentativa será feita hoje entre 18h e 21h.");
            this.bank.telemetry.emit({ source: "pix", category: "automatic",
              action: "charge_retry_scheduled", outcome: "failure", severity: "warn",
              userId: row.customer_id, accountId: row.from_account,
              counterparty: row.merchant_account, amountCents: row.amount_cents,
              reasonCodes: [code], message: "Automatic Pix charge will retry this evening" });
          });
          continue;
        }
        const status = holdId ? "review_pending" : code === "DEF_STEP_UP_REQUIRED" ||
          code === "DEF_UNAUTHORIZED" || code === "BIZ_NEW_DEVICE_LIMIT"
          ? "reauthorization_required" : "failed";
        this.bank.transaction(() => {
          this.bank.db.prepare(`UPDATE pix_automatic_charges SET status=?,hold_id=?,
            error_code=?,resolved_at=?,authorization_expires_at=NULL,
            attempt_count=attempt_count+1,next_attempt_at=NULL
            WHERE id=? AND status='pending'`)
            .run(status, holdId ?? null, holdId ? null : code,
              status === "failed" ? this.bank.now().toISOString() : null, row.id);
          this.notify(row.customer_id, row.mandate_id, row.id,
            status === "review_pending" ? "charge_held" :
              status === "reauthorization_required" ? "charge_reauthorization_required" :
                "charge_failed",
            status === "review_pending" ? "Cobrança em análise de segurança." :
              status === "reauthorization_required" ?
                "Cobrança requer nova autorização." : "Cobrança automática não liquidada.");
          this.bank.telemetry.emit({ source: "pix", category: "automatic",
            action: status === "review_pending" ? "charge_held" :
              status === "reauthorization_required" ? "charge_reauthorization_required" :
                "charge_failed", outcome: "failure", severity: "warn",
            userId: row.customer_id, accountId: row.from_account,
            counterparty: row.merchant_account, amountCents: row.amount_cents,
            reasonCodes: [code], message: "Automatic Pix charge needs attention" });
        });
        if (status === "failed") failed++;
        continue;
      }
      if (transfer.status !== "settled" && transfer.status !== "returned_partial" &&
        transfer.status !== "returned_full")
        throw new BankError("BIZ_AUTOMATIC_SETTLEMENT_REJECTED");
      this.bank.transaction(() => {
        this.bank.db.prepare(`UPDATE pix_automatic_charges SET status='settled',
          transfer_id=?,resolved_at=?,authorization_expires_at=NULL,
          attempt_count=attempt_count+1,next_attempt_at=NULL,error_code=NULL
          WHERE id=? AND status='pending'`)
          .run(transfer.id, this.bank.now().toISOString(), row.id);
        this.notify(row.customer_id, row.mandate_id, row.id, "charge_settled",
          "Cobrança automática liquidada.");
        this.bank.telemetry.emit({ source: "pix", category: "automatic",
          action: "charge_settled", outcome: "success", userId: row.customer_id,
          accountId: row.from_account, counterparty: row.merchant_account,
          amountCents: row.amount_cents, e2eId: transfer.end_to_end_id,
          message: "Automatic Pix charge settled" });
      });
      succeeded++;
    }
    return { succeeded, failed };
  }
}
