import { newId } from "./id.ts";
import { Bank, BankError } from "./bank.ts";
import { DEVICE_QUARANTINE_V1, deviceQuarantine } from "./device-quarantine.ts";
import { CardNetwork } from "./ecosystem/card-network.ts";

export type CardRecurringFrequency = "weekly" | "monthly";
export interface CardRecurringMandate {
  id: string; customer_id: string; card_id: string; merchant_id: string;
  amount_cents: number; frequency: CardRecurringFrequency;
  starts_at: string; ends_at: string | null; next_index: number;
  next_due_at: string; status: "active" | "revoked" | "completed";
  idempotency_key: string; created_at: string; revoked_at: string | null;
}
export interface CardRecurringCharge {
  id: string; mandate_id: string; cycle_index: number; due_at: string;
  status: "approved" | "declined" | "failed";
  result_id: string | null; response_code: string | null;
  failure_code: string | null; created_at: string;
}

const saoPauloParts = new Intl.DateTimeFormat("en-GB", { timeZone: "America/Sao_Paulo",
  year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  second: "2-digit", hourCycle: "h23" });
function localParts(date: Date): { year: number; month: number; day: number;
  hour: number; minute: number; second: number } {
  const parts = saoPauloParts.formatToParts(date);
  const value = (type: string): number => Number(parts.find((part) => part.type === type)?.value);
  return { year: value("year"), month: value("month") - 1, day: value("day"),
    hour: value("hour"), minute: value("minute"), second: value("second") };
}
function cycleAt(start: string, frequency: CardRecurringFrequency, index: number): string {
  const first = new Date(start);
  if (index === 0) return first.toISOString();
  const local = localParts(first);
  const month = frequency === "monthly" ? local.month + index : local.month;
  const day = frequency === "monthly" ? Math.min(local.day,
    new Date(Date.UTC(local.year, month + 1, 0)).getUTCDate()) : local.day + 7 * index;
  const civil = Date.UTC(local.year, month, day, local.hour, local.minute,
    local.second, first.getUTCMilliseconds());
  const representedCivil = (instant: number): number => {
    const actual = localParts(new Date(instant));
    return Date.UTC(actual.year, actual.month, actual.day, actual.hour,
      actual.minute, actual.second, first.getUTCMilliseconds());
  };
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
  if (exact) return new Date(exact.instant).toISOString();
  const afterGap = candidates.filter((candidate) => candidate.represented > civil)
    .sort((left, right) => left.represented - right.represented || left.instant - right.instant)[0];
  if (afterGap) return new Date(afterGap.instant).toISOString();
  throw new BankError("BIZ_CARD_RECURRING_PERIOD");
}

export class CardRecurring {
  readonly bank: Bank;
  readonly network: CardNetwork;
  constructor(bank: Bank, network: CardNetwork) {
    this.bank = bank; this.network = network;
    bank.db.exec(`CREATE TABLE IF NOT EXISTS card_recurring_mandates (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      card_id TEXT NOT NULL REFERENCES cards(id),
      merchant_id TEXT NOT NULL REFERENCES card_merchants(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      frequency TEXT NOT NULL CHECK(frequency IN ('weekly','monthly')),
      starts_at TEXT NOT NULL, ends_at TEXT,
      next_index INTEGER NOT NULL DEFAULT 0 CHECK(next_index>=0),
      next_due_at TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('active','revoked','completed')),
      idempotency_key TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT,
      UNIQUE(customer_id,idempotency_key)
    );
    CREATE INDEX IF NOT EXISTS card_recurring_due
      ON card_recurring_mandates(status,next_due_at);
    CREATE TABLE IF NOT EXISTS card_recurring_charges (
      id TEXT PRIMARY KEY, mandate_id TEXT NOT NULL REFERENCES card_recurring_mandates(id),
      cycle_index INTEGER NOT NULL, due_at TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('approved','declined','failed')),
      result_id TEXT, response_code TEXT, failure_code TEXT,
      created_at TEXT NOT NULL, UNIQUE(mandate_id,cycle_index)
    );
    CREATE TRIGGER IF NOT EXISTS card_recurring_charges_no_update
      BEFORE UPDATE ON card_recurring_charges BEGIN
        SELECT RAISE(ABORT, 'CARD_RECURRING_CHARGE_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS card_recurring_charges_no_delete
      BEFORE DELETE ON card_recurring_charges BEGIN
        SELECT RAISE(ABORT, 'CARD_RECURRING_CHARGE_IMMUTABLE'); END;`);
  }

  mandate(customerId: string, id: string): CardRecurringMandate {
    const row = this.bank.db.prepare(`SELECT * FROM card_recurring_mandates
      WHERE id=? AND customer_id=?`).get(id, customerId) as unknown as
      CardRecurringMandate | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    return row;
  }

  list(customerId: string, cardId: string): CardRecurringMandate[] {
    this.network.cards.ownCard(customerId, cardId);
    return this.bank.db.prepare(`SELECT * FROM card_recurring_mandates
      WHERE customer_id=? AND card_id=? ORDER BY created_at,id`)
      .all(customerId, cardId) as unknown as CardRecurringMandate[];
  }

  charges(customerId: string, mandateId: string): CardRecurringCharge[] {
    this.mandate(customerId, mandateId);
    return this.bank.db.prepare(`SELECT * FROM card_recurring_charges
      WHERE mandate_id=? ORDER BY cycle_index`).all(mandateId) as unknown as CardRecurringCharge[];
  }

  create(customerId: string, deviceId: string, input: { cardId: string; merchantId: string;
    amountCents: number; frequency: CardRecurringFrequency; startsAt: string;
    endsAt?: string; idempotencyKey: string }): CardRecurringMandate {
    if (!Number.isSafeInteger(input.amountCents) || input.amountCents <= 0 ||
      input.amountCents > 2_000_000 || !["weekly", "monthly"].includes(input.frequency) ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(input.idempotencyKey))
      throw new BankError("BIZ_CARD_RECURRING_INVALID");
    const startMs = Date.parse(input.startsAt), endMs = input.endsAt === undefined ? null :
      Date.parse(input.endsAt);
    if (!Number.isFinite(startMs) || (endMs !== null &&
      (!Number.isFinite(endMs) || endMs < startMs || endMs > startMs + 5 * 366 * 86_400_000)))
      throw new BankError("BIZ_CARD_RECURRING_DATE");
    const startsAt = new Date(startMs).toISOString();
    const endsAt = endMs === null ? null : new Date(endMs).toISOString();
    return this.bank.transaction(() => {
      const prior = this.bank.db.prepare(`SELECT * FROM card_recurring_mandates
        WHERE customer_id=? AND idempotency_key=?`).get(customerId, input.idempotencyKey) as
        unknown as CardRecurringMandate | undefined;
      if (prior) {
        if (prior.card_id !== input.cardId || prior.merchant_id !== input.merchantId ||
          prior.amount_cents !== input.amountCents || prior.frequency !== input.frequency ||
          prior.starts_at !== startsAt || prior.ends_at !== endsAt)
          throw new BankError("BIZ_CARD_RECURRING_CONFLICT");
        return prior;
      }
      if (startMs < this.bank.now().getTime()) throw new BankError("BIZ_CARD_RECURRING_DATE");
      const card = this.network.cards.ownCard(customerId, input.cardId);
      if (!["debit", "credit"].includes(card.kind) || card.status !== "active" ||
        this.bank.account(card.account_id).status !== "active")
        throw new BankError("BIZ_CARD_NOT_ACTIVE");
      const device = deviceQuarantine(this.bank.db, customerId, deviceId, this.bank.now());
      if (!device) throw new BankError("DEF_UNAUTHORIZED");
      if (device.quarantined && input.amountCents > DEVICE_QUARANTINE_V1.card_limit_cents)
        throw new BankError("BIZ_NEW_DEVICE_LIMIT");
      if (!this.bank.db.prepare(`SELECT 1 FROM card_merchants WHERE id=? AND status='active'`)
        .get(input.merchantId)) throw new BankError("BIZ_INVALID_MERCHANT");
      const id = newId("card_mandate", this.bank.now().getTime());
      this.bank.db.prepare(`INSERT INTO card_recurring_mandates
        (id,customer_id,card_id,merchant_id,amount_cents,frequency,
        starts_at,ends_at,next_index,next_due_at,status,idempotency_key,created_at,revoked_at)
        VALUES (?,?,?,?,?,?,?,?,0,?,'active',?,?,NULL)`)
        .run(id, customerId, input.cardId, input.merchantId, input.amountCents,
          input.frequency, startsAt, endsAt, startsAt, input.idempotencyKey,
          this.bank.now().toISOString());
      return this.mandate(customerId, id);
    });
  }

  revoke(customerId: string, id: string): CardRecurringMandate {
    return this.bank.transaction(() => {
      const row = this.mandate(customerId, id);
      if (row.status !== "active") return row;
      this.bank.db.prepare(`UPDATE card_recurring_mandates
        SET status='revoked',revoked_at=? WHERE id=?`)
        .run(this.bank.now().toISOString(), id);
      return this.mandate(customerId, id);
    });
  }

  private advance(row: CardRecurringMandate): void {
    const nextIndex = row.next_index + 1;
    const nextDue = cycleAt(row.starts_at, row.frequency, nextIndex);
    this.bank.db.prepare(`UPDATE card_recurring_mandates SET
      next_index=?,next_due_at=?,status=? WHERE id=? AND next_index=? AND status='active'`)
      .run(nextIndex, nextDue, row.ends_at && nextDue > row.ends_at ? "completed" : "active",
        row.id, row.next_index);
  }

  runDue(limit = 100): { approved: number; declined: number; failed: number } {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
      throw new BankError("BIZ_CARD_RECURRING_LIMIT");
    const totals = { approved: 0, declined: 0, failed: 0 };
    const now = this.bank.now().toISOString();
    for (let index = 0; index < limit; index++) {
      const due = this.bank.db.prepare(`SELECT * FROM card_recurring_mandates
        WHERE status='active' AND next_due_at<=? ORDER BY next_due_at,id LIMIT 1`)
        .get(now) as unknown as CardRecurringMandate | undefined;
      if (!due) break;
      try {
        const outcome = this.bank.transaction(() => {
          const current = this.bank.db.prepare(`SELECT * FROM card_recurring_mandates
            WHERE id=? AND status='active' AND next_due_at<=?`).get(due.id, now) as
            unknown as CardRecurringMandate | undefined;
          if (!current) return null;
          if (current.ends_at && current.next_due_at > current.ends_at) {
            this.bank.db.prepare(`UPDATE card_recurring_mandates SET status='completed'
              WHERE id=?`).run(current.id);
            return null;
          }
          const result = this.network.authorize({ cardId: current.card_id,
            merchantId: current.merchant_id, amountCents: current.amount_cents,
            entryMode: "ecommerce", eci: "07",
            cvv: this.network.cards.vault.currentCvv(current.card_id) });
          const status = result.response_code === "00" ? "approved" : "declined";
          this.bank.db.prepare(`INSERT INTO card_recurring_charges
            (id,mandate_id,cycle_index,due_at,status,result_id,response_code,
            failure_code,created_at) VALUES (?,?,?,?,?,?,?,NULL,?)`)
            .run(newId("card_charge", this.bank.now().getTime()), current.id,
              current.next_index, current.next_due_at, status, result.id,
              result.response_code, now);
          this.advance(current);
          return status;
        });
        if (outcome) totals[outcome]++;
      } catch (error) {
        if (!(error instanceof BankError) || error.code.startsWith("INTEGRITY_") ||
          error.code === "BIZ_CARD_RECURRING_PERIOD") throw error;
        const recorded = this.bank.transaction(() => {
          const current = this.bank.db.prepare(`SELECT * FROM card_recurring_mandates
            WHERE id=? AND status='active' AND next_due_at<=?`).get(due.id, now) as
            unknown as CardRecurringMandate | undefined;
          if (!current) return false;
          this.bank.db.prepare(`INSERT INTO card_recurring_charges
            (id,mandate_id,cycle_index,due_at,status,result_id,response_code,
            failure_code,created_at) VALUES (?,?,?,?,'failed',NULL,NULL,?,?)`)
            .run(newId("card_charge", this.bank.now().getTime()), current.id,
              current.next_index, current.next_due_at, error.code, now);
          this.advance(current);
          return true;
        });
        if (recorded) totals.failed++;
      }
    }
    return totals;
  }
}
