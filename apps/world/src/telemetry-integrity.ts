import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

const GENESIS = "0".repeat(64);
const FIELDS = ["id", "ts", "twin_ts", "trace_id", "span_id", "source", "category",
  "action", "outcome", "severity", "user_id", "account_id", "source_ip",
  "device_id", "session_id", "user_agent", "geo", "amount_cents", "counterparty",
  "e2e_id", "message", "redacted", "risk_score", "reason_codes_json",
  "card_token", "rule_id"] as const;

function eventHash(previous: string, values: unknown[]): string {
  return createHash("sha256").update(JSON.stringify([previous, ...values])).digest("hex");
}

export function installTelemetryIntegrity(db: DatabaseSync): void {
  db.function("telemetry_hash", { deterministic: true, varargs: true }, (...values) => {
    const [previous, ...event] = values;
    if (typeof previous !== "string") throw new Error("TELEMETRY_HASH_PREVIOUS_INVALID");
    return eventHash(previous, event);
  });
  db.exec("BEGIN IMMEDIATE");
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS telemetry_seals (
      event_id INTEGER PRIMARY KEY REFERENCES telemetry_events(id),
      prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS telemetry_seal_state (
      id INTEGER PRIMARY KEY CHECK(id=1), installed_at TEXT NOT NULL
    );`);
    const installed = db.prepare("SELECT 1 FROM telemetry_seal_state WHERE id=1").get();
    const events = (db.prepare("SELECT COUNT(*) n FROM telemetry_events").get() as { n: number }).n;
    const seals = (db.prepare("SELECT COUNT(*) n FROM telemetry_seals").get() as { n: number }).n;
    if (!installed && events && !seals) {
      const insert = db.prepare("INSERT INTO telemetry_seals VALUES (?,?,?)");
      let previous = GENESIS;
      for (const row of db.prepare(`SELECT ${FIELDS.join(",")} FROM telemetry_events ORDER BY id`)
        .iterate() as Iterable<Record<string, unknown>>) {
        const hash = eventHash(previous, FIELDS.map((field) => row[field]));
        insert.run(row.id as number, previous, hash);
        previous = hash;
      }
      db.prepare("INSERT INTO telemetry_seal_state VALUES (1,?)")
        .run(new Date().toISOString());
    } else if (!installed) {
      db.prepare("INSERT INTO telemetry_seal_state VALUES (1,?)")
        .run(new Date().toISOString());
    }
    db.exec(`CREATE TRIGGER IF NOT EXISTS telemetry_events_no_update
      BEFORE UPDATE ON telemetry_events BEGIN SELECT RAISE(ABORT,'TELEMETRY_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS telemetry_events_no_delete
      BEFORE DELETE ON telemetry_events BEGIN SELECT RAISE(ABORT,'TELEMETRY_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS telemetry_seals_no_update
      BEFORE UPDATE ON telemetry_seals BEGIN SELECT RAISE(ABORT,'TELEMETRY_SEAL_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS telemetry_seals_no_delete
      BEFORE DELETE ON telemetry_seals BEGIN SELECT RAISE(ABORT,'TELEMETRY_SEAL_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS telemetry_seal_state_no_update
        BEFORE UPDATE ON telemetry_seal_state BEGIN SELECT RAISE(ABORT,'TELEMETRY_SEAL_STATE_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS telemetry_seal_state_no_delete
        BEFORE DELETE ON telemetry_seal_state BEGIN SELECT RAISE(ABORT,'TELEMETRY_SEAL_STATE_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS telemetry_events_seal
      AFTER INSERT ON telemetry_events BEGIN
        SELECT RAISE(ABORT,'TELEMETRY_ID_NONMONOTONIC') WHERE
          NEW.id<=COALESCE((SELECT MAX(event_id) FROM telemetry_seals),0);
        INSERT INTO telemetry_seals(event_id,prev_hash,entry_hash)
        VALUES (NEW.id,
          COALESCE((SELECT entry_hash FROM telemetry_seals ORDER BY event_id DESC LIMIT 1),'${GENESIS}'),
          telemetry_hash(
            COALESCE((SELECT entry_hash FROM telemetry_seals ORDER BY event_id DESC LIMIT 1),'${GENESIS}'),
            ${FIELDS.map((field) => `NEW.${field}`).join(",")}));
      END;`);
    db.exec("COMMIT");
  } catch (error) { db.exec("ROLLBACK"); throw error; }
}

export function verifyTelemetryChain(db: DatabaseSync): boolean {
  const ownsSnapshot = !db.isTransaction;
  if (ownsSnapshot) db.exec("BEGIN");
  try {
    let previous = GENESIS;
    let count = 0;
    for (const row of db.prepare(`SELECT ${FIELDS.map((field) => `e.${field}`).join(",")},
      s.event_id seal_event_id,s.prev_hash,s.entry_hash FROM telemetry_events e
      LEFT JOIN telemetry_seals s ON s.event_id=e.id ORDER BY e.id`)
      .iterate() as Iterable<Record<string, unknown>>) {
      if (row.seal_event_id !== row.id || row.prev_hash !== previous ||
        row.entry_hash !== eventHash(previous, FIELDS.map((field) => row[field]))) return false;
      previous = row.entry_hash as string;
      count++;
    }
    return (db.prepare("SELECT COUNT(*) n FROM telemetry_seals").get() as { n: number }).n === count;
  } finally { if (ownsSnapshot) db.exec("ROLLBACK"); }
}

export function verifyTelemetryTail(db: DatabaseSync, limit = 32): boolean {
  const rows = (db.prepare(`SELECT ${FIELDS.map((field) => `e.${field}`).join(",")},
    s.event_id seal_event_id,s.prev_hash,s.entry_hash FROM telemetry_events e
    LEFT JOIN telemetry_seals s ON s.event_id=e.id ORDER BY e.id DESC LIMIT ?`)
    .all(limit) as Record<string, unknown>[]).reverse();
  if (!rows.length) return true;
  const firstId = rows[0]!.id as number;
  let previous = (db.prepare(`SELECT entry_hash FROM telemetry_seals
    WHERE event_id<? ORDER BY event_id DESC LIMIT 1`).get(firstId) as
    { entry_hash: string } | undefined)?.entry_hash ?? GENESIS;
  for (const row of rows) {
    if (row.seal_event_id !== row.id || row.prev_hash !== previous ||
        row.entry_hash !== eventHash(previous, FIELDS.map((field) => row[field]))) return false;
    previous = row.entry_hash as string;
  }
  return true;
}
