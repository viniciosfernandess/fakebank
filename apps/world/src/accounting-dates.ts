import type { DatabaseSync } from "node:sqlite";

export const ACCOUNTING_CALENDAR_VERSION = 2;
// CMN Resolution 4,880/2020, art. 6: national holidays, Carnival Monday/Tuesday,
// and Corpus Christi are non-business days for financial-market operations.
const valueDates = new WeakMap<DatabaseSync, string>();
const fixedHolidays = new Set(["01-01", "04-21", "05-01", "09-07", "10-12", "11-02", "11-15", "12-25"]);
const civilDate = new Intl.DateTimeFormat("en-US", {
  timeZone: "America/Sao_Paulo", year: "numeric", month: "2-digit", day: "2-digit",
});

function saoPauloDate(timestamp: string): string {
  const instant = new Date(timestamp);
  if (!Number.isFinite(instant.getTime())) throw new Error("ACCOUNTING_TIMESTAMP_INVALID");
  const parts = civilDate.formatToParts(instant);
  const part = (name: string): string => parts.find((item) => item.type === name)?.value ?? "";
  return `${part("year")}-${part("month")}-${part("day")}`;
}

function isoDate(date: Date): string { return date.toISOString().slice(0, 10); }

function validateCivilDate(date: string): void {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) ||
    !Number.isFinite(new Date(`${date}T12:00:00.000Z`).getTime()) ||
    isoDate(new Date(`${date}T12:00:00.000Z`)) !== date)
    throw new Error("ACCOUNTING_VALUE_DATE_INVALID");
}

function shift(date: string, days: number): string {
  const result = new Date(`${date}T12:00:00.000Z`);
  result.setUTCDate(result.getUTCDate() + days);
  return isoDate(result);
}

function easter(year: number): string {
  const a = year % 19, b = Math.floor(year / 100), c = year % 100;
  const d = Math.floor(b / 4), e = b % 4, f = Math.floor((b + 8) / 25);
  const g = Math.floor((b - f + 1) / 3), h = (19 * a + b - d - g + 15) % 30;
  const i = Math.floor(c / 4), k = c % 4, l = (32 + 2 * e + 2 * i - h - k) % 7;
  const m = Math.floor((a + 11 * h + 22 * l) / 451);
  const month = Math.floor((h + l - 7 * m + 114) / 31);
  const day = ((h + l - 7 * m + 114) % 31) + 1;
  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

function bankHoliday(date: string): boolean {
  if (date.slice(5) === "11-20" && Number(date.slice(0, 4)) >= 2024) return true;
  if (fixedHolidays.has(date.slice(5))) return true;
  const movable = easter(Number(date.slice(0, 4)));
  return date === shift(movable, -48) || date === shift(movable, -47)
    || date === shift(movable, -2) || date === shift(movable, 60);
}

function nextBusinessDate(date: string, holidays: boolean): string {
  let result = date;
  for (;;) {
    const weekday = new Date(`${result}T12:00:00.000Z`).getUTCDay();
    if (weekday !== 0 && weekday !== 6 && (!holidays || !bankHoliday(result))) return result;
    result = shift(result, 1);
  }
}

function accountingDatesV1(timestamp: string) {
  const date = saoPauloDate(timestamp);
  return { posting_date: date, value_date: date, business_date: nextBusinessDate(date, false) };
}

export function accountingDates(timestamp: string, valueDate?: string | null): {
  posting_date: string; value_date: string; business_date: string;
} {
  const postingDate = saoPauloDate(timestamp);
  const effectiveValueDate = valueDate ?? postingDate;
  validateCivilDate(effectiveValueDate);
  return { posting_date: postingDate, value_date: effectiveValueDate,
    business_date: nextBusinessDate(effectiveValueDate, true) };
}

export function withAccountingValueDate<T>(db: DatabaseSync, valueDate: string, work: () => T): T {
  validateCivilDate(valueDate);
  const previous = valueDates.get(db);
  valueDates.set(db, valueDate);
  try { return work(); }
  finally {
    if (previous === undefined) valueDates.delete(db);
    else valueDates.set(db, previous);
  }
}

export function installAccountingDates(db: DatabaseSync): void {
  const cache = new Map<string, string>();
  db.function("accounting_dates_v1", { deterministic: true }, (timestamp) => {
    if (typeof timestamp !== "string") throw new Error("ACCOUNTING_TIMESTAMP_INVALID");
    const key = /^\d{4}-\d{2}-\d{2}T\d{2}:/.test(timestamp) && timestamp.endsWith("Z")
      ? timestamp.slice(0, 13) : timestamp;
    let dates = cache.get(key);
    if (!dates) {
      dates = JSON.stringify(accountingDatesV1(timestamp));
      if (cache.size > 2_048) cache.clear();
      cache.set(key, dates);
    }
    return dates;
  });
  db.function("accounting_dates_v2", { deterministic: true }, (timestamp, valueDate) => {
    if (typeof timestamp !== "string") throw new Error("ACCOUNTING_TIMESTAMP_INVALID");
    if (valueDate !== null && typeof valueDate !== "string")
      throw new Error("ACCOUNTING_VALUE_DATE_INVALID");
    return JSON.stringify(accountingDates(timestamp, valueDate));
  });
  db.function("accounting_current_value_date", () => valueDates.get(db) ?? null);
  db.exec("BEGIN IMMEDIATE");
  try {
  const activationExists = Boolean(db.prepare(`SELECT 1 FROM sqlite_master
    WHERE type='table' AND name='accounting_activation'`).get());
  const table = db.prepare(`SELECT sql FROM sqlite_master
    WHERE type='table' AND name='ledger_accounting_dates'`).get() as { sql: string } | undefined;
  if (table?.sql.includes("policy_version=1")) {
    db.exec(`DROP VIEW IF EXISTS ledger_accounting_view;
      DROP TRIGGER IF EXISTS ledger_accounting_dates_insert;
      DROP TRIGGER IF EXISTS ledger_accounting_dates_no_update;
      DROP TRIGGER IF EXISTS ledger_accounting_dates_no_delete;
      CREATE TABLE ledger_accounting_dates_v2 (
        entry_id TEXT PRIMARY KEY REFERENCES ledger_entries(id),
        policy_version INTEGER NOT NULL CHECK(policy_version IN (1,2)),
        dates_json TEXT NOT NULL CHECK(json_valid(dates_json))
      );
      INSERT INTO ledger_accounting_dates_v2 SELECT entry_id,policy_version,dates_json
        FROM ledger_accounting_dates;
      DROP TABLE ledger_accounting_dates;
      ALTER TABLE ledger_accounting_dates_v2 RENAME TO ledger_accounting_dates;`);
  }
  db.exec(`CREATE TABLE IF NOT EXISTS ledger_accounting_dates (
    entry_id TEXT PRIMARY KEY REFERENCES ledger_entries(id),
    policy_version INTEGER NOT NULL CHECK(policy_version IN (1,2)),
    dates_json TEXT NOT NULL CHECK(json_valid(dates_json))
  );
  CREATE TABLE IF NOT EXISTS accounting_activation (
    id INTEGER PRIMARY KEY CHECK(id=1), first_new_rowid INTEGER NOT NULL
  );`);
  if (!activationExists) db.exec(`INSERT INTO accounting_activation(id,first_new_rowid)
    VALUES (1,COALESCE((SELECT MAX(rowid)+1 FROM ledger_entries),1));`);
  if (!db.prepare("SELECT 1 FROM accounting_activation WHERE id=1").get())
    throw new Error("INTEGRITY_ACCOUNTING_ACTIVATION_MISSING");
  db.exec(`
  CREATE TRIGGER IF NOT EXISTS accounting_activation_no_update
    BEFORE UPDATE ON accounting_activation BEGIN
      SELECT RAISE(ABORT,'ACCOUNTING_ACTIVATION_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS accounting_activation_no_delete
    BEFORE DELETE ON accounting_activation BEGIN
      SELECT RAISE(ABORT,'ACCOUNTING_ACTIVATION_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS ledger_accounting_dates_no_update
    BEFORE UPDATE ON ledger_accounting_dates BEGIN
      SELECT RAISE(ABORT,'ACCOUNTING_DATES_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS ledger_accounting_dates_no_delete
    BEFORE DELETE ON ledger_accounting_dates BEGIN
      SELECT RAISE(ABORT,'ACCOUNTING_DATES_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS ledger_accounting_dates_insert
    AFTER INSERT ON ledger_entries BEGIN
      INSERT INTO ledger_accounting_dates(entry_id,policy_version,dates_json)
        VALUES (NEW.id,2,accounting_dates_v2(NEW.created_at,accounting_current_value_date()));
    END;
  CREATE VIEW IF NOT EXISTS ledger_accounting_view AS
    SELECT e.id,e.tx_id,e.created_at,
      json_extract(d.dates_json,'$.posting_date') posting_date,
      json_extract(d.dates_json,'$.value_date') value_date,
      json_extract(d.dates_json,'$.business_date') business_date,
      d.policy_version,
      CASE WHEN d.entry_id IS NULL THEN 'legacy_unknown' ELSE 'recorded' END provenance
    FROM ledger_entries e LEFT JOIN ledger_accounting_dates d ON d.entry_id=e.id;`);
  db.exec("COMMIT");
  } catch (error) { db.exec("ROLLBACK"); throw error; }
}

export function verifyAccountingDates(db: DatabaseSync): boolean {
  const activation = db.prepare("SELECT first_new_rowid FROM accounting_activation WHERE id=1")
    .get() as { first_new_rowid: number } | undefined;
  if (!activation || !Number.isSafeInteger(activation.first_new_rowid) || activation.first_new_rowid < 1)
    return false;
  const missing = db.prepare(`SELECT 1 FROM ledger_entries e
    LEFT JOIN ledger_accounting_dates d ON d.entry_id=e.id
    WHERE e.rowid >= ?
      AND d.entry_id IS NULL LIMIT 1`).get(activation.first_new_rowid);
  const orphan = db.prepare(`SELECT 1 FROM ledger_accounting_dates d
    LEFT JOIN ledger_entries e ON e.id=d.entry_id WHERE e.id IS NULL LIMIT 1`).get();
  const inconsistent = db.prepare(`SELECT 1 FROM ledger_entries e
    JOIN ledger_accounting_dates d ON d.entry_id=e.id
    WHERE e.rowid>=? AND (d.policy_version NOT IN (1,2)
      OR (d.policy_version=1 AND d.dates_json<>accounting_dates_v1(e.created_at))
      OR (d.policy_version=2 AND d.dates_json<>accounting_dates_v2(
        e.created_at,json_extract(d.dates_json,'$.value_date')))) LIMIT 1`)
    .get(activation.first_new_rowid);
  return !missing && !orphan && !inconsistent;
}
