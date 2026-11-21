import { createHash, randomUUID } from "node:crypto";
import { chmodSync, closeSync, copyFileSync, existsSync, fsyncSync, linkSync, mkdirSync, openSync,
  readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type { Bank } from "../../world/src/bank.ts";
import { verifyLedgerChain } from "../../world/src/ledger-integrity.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";

const GENESIS = "0".repeat(64);
const ANCHOR_INTERVAL = 1_000;
const HASH = /^[a-f0-9]{64}$/;

export interface LedgerAnchor {
  sequence: number;
  entry_rowid: number;
  entry_id: string | null;
  entry_hash: string;
  previous_anchor_hash: string;
  created_at: string;
  provenance: "baseline" | "checkpoint";
  anchor_hash: string;
}

function anchorHash(row: Omit<LedgerAnchor, "anchor_hash">): string {
  return createHash("sha256").update(JSON.stringify(["ledger-anchor-v1", row.sequence,
    row.entry_rowid, row.entry_id, row.entry_hash, row.previous_anchor_hash,
    row.created_at, row.provenance])).digest("hex");
}

export function ledgerTip(db: DatabaseSync): Pick<LedgerAnchor, "entry_rowid" | "entry_id" | "entry_hash"> {
  const row = db.prepare(`SELECT entry_rowid,entry_id,entry_hash FROM ledger_seals
    ORDER BY entry_rowid DESC LIMIT 1`).get() as
    { entry_rowid: number; entry_id: string; entry_hash: string } | undefined;
  return row ?? { entry_rowid: 0, entry_id: null, entry_hash: GENESIS };
}

function filename(sequence: number): string {
  return `${String(sequence).padStart(9, "0")}.json`;
}

function readAnchors(eventsDb: DatabaseSync): LedgerAnchor[] {
  if (!eventsDb.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='ledger_anchors'`).get()) return [];
  return eventsDb.prepare(`SELECT sequence,entry_rowid,entry_id,entry_hash,
    previous_anchor_hash,created_at,provenance,anchor_hash
    FROM ledger_anchors ORDER BY sequence`).all() as unknown as LedgerAnchor[];
}

export function verifyLedgerAnchors(bankDb: DatabaseSync, eventsDb: DatabaseSync,
  directory: string): LedgerAnchor | null {
  const rows = readAnchors(eventsDb);
  if (!rows.length) {
    if (existsSync(directory) && readdirSync(directory).some((name) => name.endsWith(".json")))
      throw new Error("INTEGRITY_LEDGER_ANCHOR_EVENT_MISSING");
    return null;
  }
  if (!existsSync(directory)) throw new Error("INTEGRITY_LEDGER_ANCHOR_FILE_MISSING");
  const files = readdirSync(directory).filter((name) => name.endsWith(".json")).sort();
  if (files.length !== rows.length || files.some((name, index) => name !== filename(index + 1)))
    throw new Error("INTEGRITY_LEDGER_ANCHOR_FILE_SET");
  let previous = GENESIS;
  let lastRowid = -1;
  for (const [index, row] of rows.entries()) {
    if (!Number.isSafeInteger(row.sequence) || row.sequence !== index + 1 ||
      !Number.isSafeInteger(row.entry_rowid) || row.entry_rowid < 0 ||
      row.entry_rowid <= lastRowid && row.sequence !== 1 ||
      !HASH.test(row.entry_hash) || !HASH.test(row.previous_anchor_hash) ||
      !HASH.test(row.anchor_hash) || row.previous_anchor_hash !== previous ||
      row.anchor_hash !== anchorHash(row) ||
      (row.sequence === 1 ? row.provenance !== "baseline" : row.provenance !== "checkpoint") ||
      !Number.isFinite(Date.parse(row.created_at)))
      throw new Error("INTEGRITY_LEDGER_ANCHOR_CHAIN");
    if (row.entry_rowid === 0) {
      if (row.entry_id !== null || row.entry_hash !== GENESIS)
        throw new Error("INTEGRITY_LEDGER_ANCHOR_HISTORY");
    } else {
      const seal = bankDb.prepare(`SELECT entry_id,entry_hash FROM ledger_seals
        WHERE entry_rowid=?`).get(row.entry_rowid) as
        { entry_id: string; entry_hash: string } | undefined;
      if (!seal || seal.entry_id !== row.entry_id || seal.entry_hash !== row.entry_hash)
        throw new Error("INTEGRITY_LEDGER_ANCHOR_HISTORY");
    }
    const file = join(directory, filename(row.sequence));
    if (statSync(file).mode & 0o222 || readFileSync(file, "utf8") !== `${JSON.stringify(row)}\n`)
      throw new Error("INTEGRITY_LEDGER_ANCHOR_FILE_MISMATCH");
    previous = row.anchor_hash;
    lastRowid = row.entry_rowid;
  }
  return rows.at(-1)!;
}

export class LedgerAnchorStore {
  readonly directory: string;
  private readonly bank: Bank;
  private readonly events: EventStore;
  private readonly now: () => Date;
  private snapshotCopyActive = false;

  constructor(bank: Bank, events: EventStore, directory: string,
    now: () => Date = () => new Date()) {
    this.bank = bank;
    this.events = events;
    this.directory = directory;
    this.now = now;
    events.db.exec(`CREATE TABLE IF NOT EXISTS ledger_anchors (
        sequence INTEGER PRIMARY KEY CHECK(sequence>0),
        entry_rowid INTEGER NOT NULL UNIQUE CHECK(entry_rowid>=0),
        entry_id TEXT, entry_hash TEXT NOT NULL,
        previous_anchor_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        provenance TEXT NOT NULL CHECK(provenance IN ('baseline','checkpoint')),
        anchor_hash TEXT NOT NULL UNIQUE
      );
      CREATE TRIGGER IF NOT EXISTS ledger_anchors_no_update BEFORE UPDATE ON ledger_anchors
        BEGIN SELECT RAISE(ABORT,'LEDGER_ANCHOR_APPEND_ONLY'); END;
      CREATE TRIGGER IF NOT EXISTS ledger_anchors_no_delete BEFORE DELETE ON ledger_anchors
        BEGIN SELECT RAISE(ABORT,'LEDGER_ANCHOR_APPEND_ONLY'); END;`);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const last = this.verify();
    if (!verifyLedgerChain(bank.db)) throw new Error("INTEGRITY_LEDGER_CHAIN_INVALID");
    if (!last) {
      this.writeAnchor(ledgerTip(bank.db), "baseline");
    }
  }

  verify(): LedgerAnchor | null {
    return verifyLedgerAnchors(this.bank.db, this.events.db, this.directory);
  }

  async withSnapshotCopy<T>(copy: () => Promise<T>): Promise<T> {
    if (this.snapshotCopyActive) throw new Error("SNAPSHOT_LEDGER_ANCHOR_BUSY");
    this.snapshotCopyActive = true;
    try { return await copy(); }
    finally { this.snapshotCopyActive = false; }
  }

  checkpoint(force = false): LedgerAnchor {
    const last = this.verify();
    if (!last) throw new Error("INTEGRITY_LEDGER_ANCHOR_MISSING");
    const tip = ledgerTip(this.bank.db);
    if (tip.entry_rowid < last.entry_rowid)
      throw new Error("INTEGRITY_LEDGER_ANCHOR_HISTORY");
    if (this.snapshotCopyActive) return last;
    if (tip.entry_rowid === last.entry_rowid ||
      !force && tip.entry_rowid - last.entry_rowid < ANCHOR_INTERVAL) return last;
    return this.checkpointAt(tip);
  }

  checkpointAt(tip: ReturnType<typeof ledgerTip>): LedgerAnchor {
    const last = this.verify();
    if (!last || tip.entry_rowid < last.entry_rowid)
      throw new Error("INTEGRITY_LEDGER_ANCHOR_HISTORY");
    if (tip.entry_rowid === last.entry_rowid) {
      if (tip.entry_hash !== last.entry_hash || tip.entry_id !== last.entry_id)
        throw new Error("INTEGRITY_LEDGER_ANCHOR_HISTORY");
      return last;
    }
    const liveSeal = this.bank.db.prepare(`SELECT entry_id,entry_hash FROM ledger_seals
      WHERE entry_rowid=?`).get(tip.entry_rowid) as
      { entry_id: string; entry_hash: string } | undefined;
    if (!liveSeal || liveSeal.entry_id !== tip.entry_id || liveSeal.entry_hash !== tip.entry_hash ||
      !verifyLedgerChain(this.bank.db)) throw new Error("INTEGRITY_LEDGER_CHAIN_INVALID");
    return this.writeAnchor(tip, "checkpoint");
  }

  copyFiles(destination: string, count: number): void {
    this.verify();
    if (!Number.isSafeInteger(count) || count < 1) throw new Error("INTEGRITY_LEDGER_ANCHOR_COUNT");
    mkdirSync(destination, { mode: 0o700 });
    for (let sequence = 1; sequence <= count; sequence++) {
      const target = join(destination, filename(sequence));
      copyFileSync(join(this.directory, filename(sequence)), target);
      chmodSync(target, 0o444);
    }
  }

  private writeAnchor(tip: ReturnType<typeof ledgerTip>,
    provenance: LedgerAnchor["provenance"]): LedgerAnchor {
    const prior = readAnchors(this.events.db).at(-1);
    const fields = { sequence: (prior?.sequence ?? 0) + 1,
      ...tip, previous_anchor_hash: prior?.anchor_hash ?? GENESIS,
      created_at: this.now().toISOString(), provenance };
    const row: LedgerAnchor = { ...fields, anchor_hash: anchorHash(fields) };
    const file = join(this.directory, filename(row.sequence));
    const temporary = join(this.directory, `.tmp-${randomUUID()}`);
    const handle = openSync(temporary, "wx", 0o600);
    try {
      writeFileSync(handle, `${JSON.stringify(row)}\n`);
      fsyncSync(handle);
    } finally { closeSync(handle); }
    try {
      chmodSync(temporary, 0o444);
      this.events.db.prepare(`INSERT INTO ledger_anchors
        (sequence,entry_rowid,entry_id,entry_hash,previous_anchor_hash,
          created_at,provenance,anchor_hash) VALUES (?,?,?,?,?,?,?,?)`)
        .run(row.sequence, row.entry_rowid, row.entry_id, row.entry_hash,
          row.previous_anchor_hash, row.created_at, row.provenance, row.anchor_hash);
      linkSync(temporary, file);
      rmSync(temporary);
    } catch (error) {
      if (existsSync(temporary)) rmSync(temporary);
      throw error;
    }
    return row;
  }
}
