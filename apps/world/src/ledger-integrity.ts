import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

const genesis = "0".repeat(64);
const fields = "id,tx_id,account_id,amount,kind,actor,ref_type,ref_id,created_at,reverses_tx_id";
const newFields = fields.split(",").map((field) => `NEW.${field}`).join(",");

function entryHash(previous: string, values: unknown[]): string {
  return createHash("sha256").update(JSON.stringify([previous, ...values])).digest("hex");
}

export function installLedgerIntegrity(db: DatabaseSync): void {
  db.function("ledger_hash", { deterministic: true, varargs: true }, (...values) => {
    const [previous, ...entry] = values;
    if (typeof previous !== "string") throw new Error("LEDGER_HASH_PREVIOUS_INVALID");
    return entryHash(previous, entry);
  });
  db.exec("BEGIN IMMEDIATE");
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS ledger_seals (
      entry_id TEXT PRIMARY KEY REFERENCES ledger_entries(id),
      entry_rowid INTEGER NOT NULL UNIQUE, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
    );`);
    const entries = (db.prepare("SELECT COUNT(*) n FROM ledger_entries").get() as { n: number }).n;
    const seals = (db.prepare("SELECT COUNT(*) n FROM ledger_seals").get() as { n: number }).n;
    if (entries && !seals) {
      const insert = db.prepare("INSERT INTO ledger_seals VALUES (?,?,?,?)");
      let previous = genesis;
      for (const row of db.prepare(`SELECT rowid,${fields} FROM ledger_entries ORDER BY rowid`).iterate() as
        Iterable<Record<string, unknown>>) {
        const values = fields.split(",").map((field) => row[field]);
        const hash = entryHash(previous, values);
        insert.run(row.id as string, row.rowid as number, previous, hash);
        previous = hash;
      }
    } else if (seals !== entries) throw new Error("INTEGRITY_LEDGER_SEAL_COUNT");
    db.exec(`CREATE TRIGGER IF NOT EXISTS ledger_entries_no_update
      BEFORE UPDATE ON ledger_entries BEGIN SELECT RAISE(ABORT,'LEDGER_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS ledger_entries_no_delete
      BEFORE DELETE ON ledger_entries BEGIN SELECT RAISE(ABORT,'LEDGER_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS ledger_seals_no_update
      BEFORE UPDATE ON ledger_seals BEGIN SELECT RAISE(ABORT,'LEDGER_SEAL_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS ledger_seals_no_delete
      BEFORE DELETE ON ledger_seals BEGIN SELECT RAISE(ABORT,'LEDGER_SEAL_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS ledger_entries_seal
      AFTER INSERT ON ledger_entries BEGIN
        INSERT INTO ledger_seals(entry_id,entry_rowid,prev_hash,entry_hash)
        VALUES (NEW.id,NEW.rowid,
          COALESCE((SELECT entry_hash FROM ledger_seals ORDER BY entry_rowid DESC LIMIT 1),'${genesis}'),
          ledger_hash(COALESCE((SELECT entry_hash FROM ledger_seals ORDER BY entry_rowid DESC LIMIT 1),'${genesis}'),
            ${newFields}));
      END;`);
    db.exec("COMMIT");
  } catch (error) { db.exec("ROLLBACK"); throw error; }
}

export function verifyLedgerChain(db: DatabaseSync): boolean {
  const ownsSnapshot = !db.isTransaction;
  if (ownsSnapshot) db.exec("BEGIN");
  try {
    let previous = genesis;
    let count = 0;
    let valid = true;
    for (const row of db.prepare(`SELECT e.rowid,${fields.split(",").map((field) => `e.${field}`).join(",")},
      s.entry_rowid,s.prev_hash,s.entry_hash FROM ledger_entries e
      LEFT JOIN ledger_seals s ON s.entry_id=e.id ORDER BY e.rowid`).iterate() as
      Iterable<Record<string, unknown>>) {
      const values = fields.split(",").map((field) => row[field]);
      if (row.entry_rowid !== row.rowid || row.prev_hash !== previous ||
        row.entry_hash !== entryHash(previous, values)) { valid = false; break; }
      previous = row.entry_hash as string;
      count++;
    }
    const seals = (db.prepare("SELECT COUNT(*) n FROM ledger_seals").get() as { n: number }).n;
    return valid && seals === count;
  } finally { if (ownsSnapshot) db.exec("ROLLBACK"); }
}
