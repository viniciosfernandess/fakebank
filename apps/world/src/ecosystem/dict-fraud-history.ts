import { DatabaseSync } from "node:sqlite";

export interface DictFraudCounter {
  known: boolean;
  history_complete_90d: boolean;
  history_complete_12m: boolean;
  marks_90d: number | null;
  marks_12m: number | null;
}

export function installDictFraudHistory(db: DatabaseSync, now: Date): void {
  db.exec("BEGIN IMMEDIATE");
  try {
    const legacy = Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='pix_keys'").get());
    db.exec(`CREATE TABLE IF NOT EXISTS dict_fraud_history_state (
    id INTEGER PRIMARY KEY CHECK(id=1), started_at TEXT NOT NULL,
    complete_from_origin INTEGER NOT NULL CHECK(complete_from_origin IN (0,1))
  );
  CREATE TRIGGER IF NOT EXISTS dict_fraud_history_state_no_replace BEFORE INSERT ON dict_fraud_history_state
    WHEN EXISTS (SELECT 1 FROM dict_fraud_history_state WHERE id=NEW.id)
    BEGIN SELECT RAISE(ABORT,'DICT_FRAUD_HISTORY_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS dict_fraud_history_state_no_update BEFORE UPDATE ON dict_fraud_history_state
    BEGIN SELECT RAISE(ABORT,'DICT_FRAUD_HISTORY_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS dict_fraud_history_state_no_delete BEFORE DELETE ON dict_fraud_history_state
    BEGIN SELECT RAISE(ABORT,'DICT_FRAUD_HISTORY_IMMUTABLE'); END;
  CREATE TABLE IF NOT EXISTS dict_fraud_events (
    id TEXT PRIMARY KEY, operation_id TEXT UNIQUE, source TEXT NOT NULL CHECK(source IN ('local','synthetic_psp')),
    key_value TEXT NOT NULL, account_id TEXT NOT NULL, customer_id TEXT, cpf TEXT,
    action TEXT NOT NULL CHECK(action IN ('marked','cleared')), actor TEXT NOT NULL, occurred_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS dict_fraud_operations (
    operation_id TEXT PRIMARY KEY, key_value TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL
  );
  CREATE TRIGGER IF NOT EXISTS dict_fraud_operations_no_replace BEFORE INSERT ON dict_fraud_operations
    WHEN EXISTS (SELECT 1 FROM dict_fraud_operations WHERE operation_id=NEW.operation_id)
    BEGIN SELECT RAISE(ABORT,'DICT_FRAUD_HISTORY_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS dict_fraud_operations_no_update BEFORE UPDATE ON dict_fraud_operations
    BEGIN SELECT RAISE(ABORT,'DICT_FRAUD_HISTORY_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS dict_fraud_operations_no_delete BEFORE DELETE ON dict_fraud_operations
    BEGIN SELECT RAISE(ABORT,'DICT_FRAUD_HISTORY_IMMUTABLE'); END;
  CREATE INDEX IF NOT EXISTS dict_fraud_events_key ON dict_fraud_events(key_value,occurred_at);
  CREATE INDEX IF NOT EXISTS dict_fraud_events_account ON dict_fraud_events(account_id,occurred_at);
  CREATE INDEX IF NOT EXISTS dict_fraud_events_cpf ON dict_fraud_events(cpf,occurred_at);
  CREATE TRIGGER IF NOT EXISTS dict_fraud_events_no_replace BEFORE INSERT ON dict_fraud_events
    WHEN EXISTS (SELECT 1 FROM dict_fraud_events WHERE id=NEW.id OR
      (NEW.operation_id IS NOT NULL AND operation_id=NEW.operation_id))
    BEGIN SELECT RAISE(ABORT,'DICT_FRAUD_HISTORY_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS dict_fraud_events_no_update BEFORE UPDATE ON dict_fraud_events
    BEGIN SELECT RAISE(ABORT,'DICT_FRAUD_HISTORY_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS dict_fraud_events_no_delete BEFORE DELETE ON dict_fraud_events
    BEGIN SELECT RAISE(ABORT,'DICT_FRAUD_HISTORY_IMMUTABLE'); END;`);
  db.prepare("INSERT INTO dict_fraud_history_state SELECT 1,?,? WHERE NOT EXISTS (SELECT 1 FROM dict_fraud_history_state WHERE id=1)")
    .run(now.toISOString(), Number(!legacy));
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function twelveMonthsBefore(now: Date): Date {
  const result = new Date(now);
  result.setUTCFullYear(result.getUTCFullYear() - 1);
  // Clamp leap day to the last day of February.
  if (now.getUTCMonth() === 1 && result.getUTCMonth() !== 1) result.setUTCDate(0);
  return result;
}

export function dictFraudCounter(db: DatabaseSync, now: Date,
  dimension: "key_value" | "account_id" | "cpf", value: string | undefined): DictFraudCounter {
  if (value === undefined) return { known: false, history_complete_90d: false,
    history_complete_12m: false, marks_90d: null, marks_12m: null };
  const since90 = new Date(now.getTime() - 90 * 86_400_000).toISOString();
  const since12 = twelveMonthsBefore(now).toISOString();
  const state = db.prepare("SELECT started_at,complete_from_origin FROM dict_fraud_history_state WHERE id=1")
    .get() as { started_at: string; complete_from_origin: number };
  const count = db.prepare(`SELECT COUNT(*) n FROM dict_fraud_events
    WHERE ${dimension}=? AND action='marked' AND occurred_at>=? AND occurred_at<=?`);
  return { known: true,
    history_complete_90d: state.started_at <= now.toISOString() && (Boolean(state.complete_from_origin) || state.started_at < since90),
    history_complete_12m: state.started_at <= now.toISOString() && (Boolean(state.complete_from_origin) || state.started_at < since12),
    marks_90d: (count.get(value, since90, now.toISOString()) as { n: number }).n,
    marks_12m: (count.get(value, since12, now.toISOString()) as { n: number }).n };
}
