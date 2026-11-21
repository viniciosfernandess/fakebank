import type { DatabaseSync } from "node:sqlite";
import type { Bank } from "../../world/src/bank.ts";
import { verifyPeriodCloseSeal } from "../../world/src/period-close-seals.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";

type Provenance = "recorded" | "legacy_imported";
type Outcome = "committed" | "aborted";
interface Attempt {
  id: number; brt_date: string; sha256: string; provenance: Provenance;
  outcome: Outcome | null;
}

function localSeals(bankDb: DatabaseSync): Map<string, string> {
  const seals = new Map<string, string>();
  const rows = bankDb.prepare(`SELECT c.brt_date,s.sha256 FROM period_closes c
    LEFT JOIN period_close_seals s ON s.brt_date=c.brt_date ORDER BY c.brt_date`)
    .all() as { brt_date: string; sha256: string | null }[];
  for (const row of rows) {
    const provenance = verifyPeriodCloseSeal(bankDb, row.brt_date);
    if (!row.sha256 || !provenance || provenance === "legacy_missing")
      throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_LOCAL");
    seals.set(row.brt_date, row.sha256);
  }
  return seals;
}

function attempts(eventsDb: DatabaseSync): Attempt[] {
  return eventsDb.prepare(`SELECT a.id,a.brt_date,a.sha256,a.provenance,o.outcome
    FROM period_close_anchor_attempts a
    LEFT JOIN period_close_anchor_outcomes o ON o.attempt_id=a.id
    ORDER BY a.id`).all() as unknown as Attempt[];
}

function outcome(eventsDb: DatabaseSync, attemptId: number, value: Outcome,
  now: () => Date): void {
  eventsDb.prepare(`INSERT INTO period_close_anchor_outcomes
    (attempt_id,outcome,decided_at) VALUES (?,?,?)`)
    .run(attemptId, value, now().toISOString());
}

export function verifyPeriodCloseAnchors(bankDb: DatabaseSync, eventsDb: DatabaseSync,
  now: () => Date = () => new Date(), mode: "recover" | "strict" = "recover"): number {
  const state = eventsDb.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='period_close_anchor_state'`).get();
  if (!state || !eventsDb.prepare("SELECT 1 FROM period_close_anchor_state WHERE id=1").get())
    throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_STATE");
  const seals = localSeals(bankDb);
  const committed = new Map<string, string>();
  for (const row of attempts(eventsDb)) {
    if (!Number.isSafeInteger(row.id) || !/^\d{4}-\d{2}-\d{2}$/.test(row.brt_date) ||
      !/^[a-f0-9]{64}$/.test(row.sha256) ||
      !["recorded", "legacy_imported"].includes(row.provenance) ||
      row.outcome !== null && !["committed", "aborted"].includes(row.outcome))
      throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_RECORD");
    const local = seals.get(row.brt_date);
    if (row.outcome === null) {
      if (mode === "strict") throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_PENDING");
      if (local && local !== row.sha256)
        throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_MISMATCH");
      outcome(eventsDb, row.id, local ? "committed" : "aborted", now);
      row.outcome = local ? "committed" : "aborted";
    }
    if (row.outcome === "committed") {
      if (local !== row.sha256 || committed.has(row.brt_date))
        throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_MISMATCH");
      committed.set(row.brt_date, row.sha256);
    }
  }
  for (const [date, sha256] of seals)
    if (committed.get(date) !== sha256)
      throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_MISSING");
  return committed.size;
}

export class PeriodCloseAnchorStore {
  private readonly bank: Bank;
  private readonly events: EventStore;
  private readonly now: () => Date;

  constructor(bank: Bank, events: EventStore, now: () => Date = () => new Date()) {
    this.bank = bank; this.events = events; this.now = now;
    const registered = Boolean(bank.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='period_close_anchor_registry'`).get() &&
      bank.db.prepare("SELECT 1 FROM period_close_anchor_registry WHERE id=1").get());
    const initialized = Boolean(events.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='period_close_anchor_state'`).get());
    if (registered && !initialized)
      throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_STATE");
    events.db.exec(`CREATE TABLE IF NOT EXISTS period_close_anchor_state (
      id INTEGER PRIMARY KEY CHECK(id=1), initialized_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS period_close_anchor_state_no_update
      BEFORE UPDATE ON period_close_anchor_state
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_ANCHOR_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS period_close_anchor_state_no_delete
      BEFORE DELETE ON period_close_anchor_state
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_ANCHOR_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS period_close_anchor_attempts (
      id INTEGER PRIMARY KEY, brt_date TEXT NOT NULL, sha256 TEXT NOT NULL,
      provenance TEXT NOT NULL CHECK(provenance IN ('recorded','legacy_imported')),
      prepared_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS period_close_anchor_attempts_no_update
      BEFORE UPDATE ON period_close_anchor_attempts
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_ANCHOR_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS period_close_anchor_attempts_no_delete
      BEFORE DELETE ON period_close_anchor_attempts
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_ANCHOR_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS period_close_anchor_outcomes (
      attempt_id INTEGER PRIMARY KEY REFERENCES period_close_anchor_attempts(id),
      outcome TEXT NOT NULL CHECK(outcome IN ('committed','aborted')),
      decided_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS period_close_anchor_outcomes_no_update
      BEFORE UPDATE ON period_close_anchor_outcomes
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_ANCHOR_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS period_close_anchor_outcomes_no_delete
      BEFORE DELETE ON period_close_anchor_outcomes
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_ANCHOR_IMMUTABLE'); END;`);
    if (!initialized) {
      if (attempts(events.db).length)
        throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_STATE");
      events.db.exec("BEGIN IMMEDIATE");
      try {
        for (const [date, sha256] of localSeals(bank.db)) {
          const result = events.db.prepare(`INSERT INTO period_close_anchor_attempts
            (brt_date,sha256,provenance,prepared_at) VALUES (?,?,'legacy_imported',?)`)
            .run(date, sha256, now().toISOString());
          outcome(events.db, Number(result.lastInsertRowid), "committed", now);
        }
        events.db.prepare("INSERT INTO period_close_anchor_state VALUES (1,?)")
          .run(now().toISOString());
        events.db.exec("COMMIT");
      } catch (error) {
        events.db.exec("ROLLBACK");
        throw error;
      }
    }
    this.verify();
    bank.db.exec(`CREATE TABLE IF NOT EXISTS period_close_anchor_registry (
      id INTEGER PRIMARY KEY CHECK(id=1), registered_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS period_close_anchor_registry_no_update
      BEFORE UPDATE ON period_close_anchor_registry
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_ANCHOR_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS period_close_anchor_registry_no_delete
      BEFORE DELETE ON period_close_anchor_registry
      BEGIN SELECT RAISE(ABORT,'PERIOD_CLOSE_ANCHOR_IMMUTABLE'); END;`);
    bank.db.prepare(`INSERT OR IGNORE INTO period_close_anchor_registry
      (id,registered_at) VALUES (1,?)`).run(now().toISOString());
    bank.configurePeriodCloseAnchor({
      verify: () => this.verify(),
      prepare: (date, sha256) => this.prepare(date, sha256),
      confirm: (date, sha256) => this.confirm(date, sha256),
    });
  }

  verify(): void {
    verifyPeriodCloseAnchors(this.bank.db, this.events.db, this.now);
  }

  prepare(date: string, sha256: string): void {
    const previous = attempts(this.events.db).filter((row) => row.brt_date === date);
    if (previous.some((row) => row.outcome === "committed" ||
      row.outcome === null && row.sha256 !== sha256))
      throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_CONFLICT");
    if (previous.some((row) => row.outcome === null && row.sha256 === sha256)) return;
    this.events.db.prepare(`INSERT INTO period_close_anchor_attempts
      (brt_date,sha256,provenance,prepared_at) VALUES (?,?,'recorded',?)`)
      .run(date, sha256, this.now().toISOString());
  }

  confirm(date: string, sha256: string): void {
    const local = localSeals(this.bank.db).get(date);
    if (local !== sha256) throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_MISMATCH");
    const row = attempts(this.events.db).reverse().find((entry) =>
      entry.brt_date === date && entry.sha256 === sha256 && entry.outcome !== "aborted");
    if (!row) throw new Error("INTEGRITY_PERIOD_CLOSE_ANCHOR_MISSING");
    if (row.outcome === null) outcome(this.events.db, row.id, "committed", this.now);
  }
}
