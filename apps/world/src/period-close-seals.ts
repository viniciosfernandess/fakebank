import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

export type CloseSealProvenance = "recorded" | "legacy_imported" | "legacy_missing";

interface CloseRow {
  brt_date: string; closed_at: string; ledger_entries_count: number;
  ledger_sum: number; integrity_json: string; chart_version: number;
  calendar_version: number; cutoff_policy_version: number;
}
interface TrialRow {
  lines_json: string; debit_cents: number; credit_cents: number;
}

function closeRows(db: DatabaseSync, date: string):
  { close: CloseRow; trial: TrialRow | undefined } | null {
  const close = db.prepare(`SELECT brt_date,closed_at,ledger_entries_count,ledger_sum,
    integrity_json,chart_version,calendar_version,cutoff_policy_version
    FROM period_closes WHERE brt_date=?`).get(date) as unknown as CloseRow | undefined;
  if (!close) return null;
  const trial = db.prepare(`SELECT lines_json,debit_cents,credit_cents
    FROM period_trial_balances WHERE brt_date=?`).get(date) as
    TrialRow | undefined;
  return { close, trial };
}

function validTrial(trial: TrialRow): boolean {
  if (!Number.isSafeInteger(trial.debit_cents) || !Number.isSafeInteger(trial.credit_cents) ||
    trial.debit_cents < 0 || trial.debit_cents !== trial.credit_cents) return false;
  let lines: unknown;
  try { lines = JSON.parse(trial.lines_json); }
  catch { return false; }
  if (!Array.isArray(lines) || lines.length === 0) return false;
  const seen = new Set<string>();
  let debit = 0, credit = 0;
  for (const line of lines) {
    if (!line || typeof line !== "object") return false;
    const row = line as Record<string, unknown>;
    if (typeof row.code !== "string" || !/^\d{4}$/.test(row.code) ||
      seen.has(row.code) || typeof row.description !== "string" ||
      !["asset", "liability", "equity", "revenue", "expense"].includes(String(row.nature)) ||
      !Number.isSafeInteger(row.balance_cents) ||
      row.debit_cents !== Math.max(0, -(row.balance_cents as number)) ||
      row.credit_cents !== Math.max(0, row.balance_cents as number)) return false;
    seen.add(row.code);
    debit += row.debit_cents as number;
    credit += row.credit_cents as number;
  }
  return Number.isSafeInteger(debit) && Number.isSafeInteger(credit) &&
    debit === trial.debit_cents && credit === trial.credit_cents;
}

function digest(rows: { close: CloseRow; trial: TrialRow | undefined }): string {
  const { close, trial } = rows;
  return createHash("sha256").update(JSON.stringify([
    close.brt_date, close.closed_at, close.ledger_entries_count, close.ledger_sum,
    close.integrity_json, close.chart_version, close.calendar_version,
    close.cutoff_policy_version, trial?.lines_json ?? null,
    trial?.debit_cents ?? null, trial?.credit_cents ?? null,
  ])).digest("hex");
}

export function verifyPeriodCloseSeal(db: DatabaseSync, date: string):
  CloseSealProvenance | null {
  const rows = closeRows(db, date);
  const seal = db.prepare(`SELECT sha256,provenance FROM period_close_seals
    WHERE brt_date=?`).get(date) as
    { sha256: string; provenance: CloseSealProvenance } | undefined;
  if (!rows || !seal || !["recorded", "legacy_imported", "legacy_missing"]
    .includes(seal.provenance) || seal.sha256 !== digest(rows)) return null;
  if (rows.trial ? !validTrial(rows.trial) || seal.provenance === "legacy_missing"
    : seal.provenance !== "legacy_missing") return null;
  return seal.provenance;
}

export function installPeriodCloseSeals(db: DatabaseSync): void {
  const existed = Boolean(db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='period_close_seals'`).get());
  db.exec("SAVEPOINT period_close_seal_install");
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS period_close_seals (
      brt_date TEXT PRIMARY KEY REFERENCES period_closes(brt_date),
      sha256 TEXT NOT NULL CHECK(length(sha256)=64),
      provenance TEXT NOT NULL CHECK(provenance IN
        ('recorded','legacy_imported','legacy_missing')),
      sealed_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS period_close_seals_no_update
      BEFORE UPDATE ON period_close_seals
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_SEAL_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS period_close_seals_no_delete
      BEFORE DELETE ON period_close_seals
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_SEAL_IMMUTABLE'); END;`);
    const dates = db.prepare(`SELECT brt_date FROM period_closes ORDER BY brt_date`)
      .all() as { brt_date: string }[];
    const insert = db.prepare(`INSERT INTO period_close_seals VALUES (?,?,?,?)`);
    for (const { brt_date } of dates) {
      const rows = closeRows(db, brt_date)!;
      const present = db.prepare(`SELECT 1 FROM period_close_seals WHERE brt_date=?`)
        .get(brt_date);
      if (!present) {
        if (existed || (rows.trial && !validTrial(rows.trial)))
          throw new Error("INTEGRITY_PERIOD_CLOSE_SEAL");
        insert.run(brt_date, digest(rows), rows.trial ? "legacy_imported" : "legacy_missing",
          new Date().toISOString());
      }
      if (!verifyPeriodCloseSeal(db, brt_date))
        throw new Error("INTEGRITY_PERIOD_CLOSE_SEAL");
    }
    const orphan = db.prepare(`SELECT 1 FROM period_close_seals s
      LEFT JOIN period_closes c ON c.brt_date=s.brt_date
      WHERE c.brt_date IS NULL LIMIT 1`).get();
    if (orphan) throw new Error("INTEGRITY_PERIOD_CLOSE_SEAL");
    db.exec("RELEASE period_close_seal_install");
  } catch (error) {
    db.exec("ROLLBACK TO period_close_seal_install; RELEASE period_close_seal_install");
    throw error;
  }
}

export function recordPeriodCloseSeal(db: DatabaseSync, date: string,
  sealedAt: string): string {
  const rows = closeRows(db, date);
  if (!rows?.trial || !validTrial(rows.trial))
    throw new Error("INTEGRITY_PERIOD_CLOSE_SEAL");
  const sha256 = digest(rows);
  db.prepare(`INSERT INTO period_close_seals VALUES (?,?,?,?)`)
    .run(date, sha256, "recorded", sealedAt);
  return sha256;
}
