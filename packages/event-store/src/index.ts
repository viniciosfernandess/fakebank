import { DatabaseSync } from "node:sqlite";
import { createHash, randomBytes } from "node:crypto";
import { parseEvent, publicView, type ArenaEvent, type EventType } from "../../contracts/src/index.ts";
import { initialWorld, reduceWorld, shouldKeyframe, REDUCER_VERSION, type WorldState } from "../../world-reducer/src/index.ts";
import { decodeKeyframe, encodeKeyframe } from "../../world-reducer/src/keyframes.ts";
import { IncidentCaseFile } from "./incident-case-file.ts";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function ulid(now = Date.now()): string {
  let time = BigInt(now);
  let first = "";
  for (let index = 0; index < 10; index++) { first = ALPHABET[Number(time % 32n)] + first; time /= 32n; }
  const bytes = randomBytes(16);
  let last = "";
  for (let index = 0; index < 16; index++) last += ALPHABET[bytes[index]! % 32];
  return first + last;
}

function integrityHash(db: DatabaseSync, seq: number, previousHash: string): string {
  const row = db.prepare(`SELECT e.*, p.private_json FROM events e
    LEFT JOIN event_private p ON p.seq=e.seq WHERE e.seq=?`).get(seq);
  if (!row) throw new Error("EVENT_INTEGRITY_MISSING_EVENT");
  const fields = ["seq", "id", "round_id", "ts", "twin_ts", "type", "actor_id",
    "actor_role", "parent_actor_id", "area", "incident_id", "task_id", "summary_pt",
    "public_json", "idem", "private_json"];
  return createHash("sha256").update(JSON.stringify(["event-chain-v1", previousHash,
    ...fields.map((field) => row[field] ?? null)])).digest("hex");
}

export function verifyEventIntegrity(db: DatabaseSync):
  { ok: true; lastSeq: number; hash: string } | { ok: false; seq: number } {
  const ownsSnapshot = !db.isTransaction;
  if (ownsSnapshot) db.exec("BEGIN");
  try {
    const rows = db.prepare(`SELECT e.seq, i.previous_hash, i.hash FROM events e
      LEFT JOIN event_integrity i ON i.seq=e.seq ORDER BY e.seq`).all() as
      { seq: number; previous_hash: string | null; hash: string | null }[];
    let previousHash = "";
    let lastSeq = 0;
    for (const row of rows) {
      if (row.seq !== lastSeq + 1 || row.previous_hash !== previousHash ||
          row.hash !== integrityHash(db, row.seq, previousHash)) return { ok: false, seq: row.seq };
      previousHash = row.hash;
      lastSeq = row.seq;
    }
    const count = db.prepare("SELECT COUNT(*) AS n FROM event_integrity").get() as { n: number };
    if (count.n !== rows.length) return { ok: false, seq: lastSeq + 1 };
    return { ok: true, lastSeq, hash: previousHash };
  } finally { if (ownsSnapshot) db.exec("ROLLBACK"); }
}

export type EventInput = Omit<ArenaEvent, "id" | "seq">;
export interface EventQuery { after?: number; before?: number; roundId?: string; types?: EventType[]; limit?: number; }
export interface RoundIndex { round_id: string; round_no: number; first_seq: number; last_seq: number | null; status: string; score_json: string | null; headline_pt: string | null; }
export class EventStore {
  readonly db: DatabaseSync;
  readonly caseFile: IncidentCaseFile;
  private readonly listeners = new Set<(event: ArenaEvent) => void>();
  private world: WorldState = initialWorld();
  private lastKeyframeSeq = 0;
  private lastKeyframeAt = 0;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;
      CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, round_id TEXT, ts TEXT NOT NULL,
        twin_ts TEXT, type TEXT NOT NULL, actor_id TEXT NOT NULL, actor_role TEXT NOT NULL,
        parent_actor_id TEXT, area TEXT, incident_id TEXT, task_id TEXT, summary_pt TEXT NOT NULL,
        public_json TEXT NOT NULL, idem TEXT UNIQUE
      );
      CREATE TABLE IF NOT EXISTS event_private (
        seq INTEGER PRIMARY KEY REFERENCES events(seq), private_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS keyframes (
        seq INTEGER PRIMARY KEY, round_id TEXT, ts TEXT NOT NULL,
        reducer_version INTEGER NOT NULL, state_gz BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS rounds (
        round_id TEXT PRIMARY KEY, round_no INTEGER NOT NULL, first_seq INTEGER NOT NULL,
        last_seq INTEGER, status TEXT NOT NULL, score_json TEXT, headline_pt TEXT
      );
      CREATE INDEX IF NOT EXISTS ev_round ON events(round_id,seq);
      CREATE INDEX IF NOT EXISTS ev_type ON events(type,seq);
      CREATE INDEX IF NOT EXISTS ev_incident_type ON events(incident_id,type,seq);
      CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append only'); END;
      CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append only'); END;
      CREATE TRIGGER IF NOT EXISTS private_no_update BEFORE UPDATE ON event_private BEGIN SELECT RAISE(ABORT,'append only'); END;
      CREATE TRIGGER IF NOT EXISTS private_no_delete BEFORE DELETE ON event_private BEGIN SELECT RAISE(ABORT,'append only'); END;
    `);
    this.initializeIntegrity();
    const integrity = this.verifyIntegrity();
    if (!integrity.ok) { this.db.close(); throw new Error(`EVENT_INTEGRITY_INVALID:${integrity.seq}`); }
    this.caseFile = new IncidentCaseFile(this.db);
    this.caseFile.syncAllEvents();
    const frame = this.nearestKeyframe(this.latestSeq());
    if (frame && frame.reducer_version === REDUCER_VERSION) {
      this.world = decodeKeyframe(frame.state_gz);
      this.lastKeyframeSeq = frame.seq;
      this.lastKeyframeAt = Date.parse(this.get(frame.seq)?.ts ?? "") || 0;
    }
    let after = this.world.seq;
    while (true) {
      const batch = this.list({ after, limit: 500 });
      for (const event of batch) this.world = reduceWorld(this.world, publicView(event));
      if (batch.length < 500) break;
      after = batch.at(-1)!.seq;
    }
  }

  latestSeq(): number {
    return (this.db.prepare("SELECT COALESCE(MAX(seq),0) AS n FROM events").get() as { n: number }).n;
  }

  append(input: EventInput, idem?: string): ArenaEvent {
    if (idem) {
      const existing = this.db.prepare("SELECT seq FROM events WHERE idem=?").get(idem) as { seq: number } | undefined;
      if (existing) return this.get(existing.seq)!;
    }
    this.db.exec("BEGIN IMMEDIATE");
    let event: ArenaEvent;
    try {
      const seq = this.latestSeq() + 1;
      event = parseEvent({ ...input, id: ulid(new Date(input.ts).getTime()), seq });
      this.db.prepare(`INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        seq, event.id, event.round_id, event.ts, event.twin_ts ?? null, event.type,
        event.actor.id, event.actor.role, event.parent_actor_id ?? null, event.area ?? null,
        event.incident_id ?? null, event.task_id ?? null, event.public_summary_pt,
        JSON.stringify(event.public), idem ?? null,
      );
      if (event.private) this.db.prepare("INSERT INTO event_private VALUES (?,?)").run(seq, JSON.stringify(event.private));
      this.appendIntegrity(seq);
      this.updateRoundIndex(event);
      if (event.incident_id) {
        this.caseFile.ensureFromEvent(event.incident_id, event.area ?? null, event.ts);
        this.caseFile.syncEvents(event.incident_id);
      }
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    this.world = reduceWorld(this.world, publicView(event));
    if (shouldKeyframe(this.lastKeyframeSeq, this.lastKeyframeAt, event)) {
      this.saveKeyframe(event.seq, event.round_id, event.ts, REDUCER_VERSION, encodeKeyframe(this.world));
      this.lastKeyframeSeq = event.seq;
      this.lastKeyframeAt = Date.parse(event.ts);
    }
    for (const listener of this.listeners) listener(publicView(event));
    return event;
  }

  private appendIntegrity(seq: number): void {
    const previous = this.db.prepare("SELECT hash FROM event_integrity ORDER BY seq DESC LIMIT 1")
      .get() as { hash: string } | undefined;
    const previousHash = previous?.hash ?? "";
    this.db.prepare("INSERT INTO event_integrity (seq,previous_hash,hash) VALUES (?,?,?)")
      .run(seq, previousHash, integrityHash(this.db, seq, previousHash));
  }

  private initializeIntegrity(): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const exists = this.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_integrity'").get();
      this.db.exec(`CREATE TABLE IF NOT EXISTS event_integrity_state (
        id INTEGER PRIMARY KEY CHECK(id=1), installed_at TEXT NOT NULL
      )`);
      const installed = this.db.prepare("SELECT 1 FROM event_integrity_state WHERE id=1").get();
      if (!exists) {
        this.db.exec(`CREATE TABLE event_integrity (
          seq INTEGER PRIMARY KEY REFERENCES events(seq), previous_hash TEXT NOT NULL, hash TEXT NOT NULL
        )`);
        if (!installed) {
          const rows = this.db.prepare("SELECT seq FROM events ORDER BY seq").all() as { seq: number }[];
          for (const row of rows) this.appendIntegrity(row.seq);
        }
      }
      if (!installed) this.db.prepare("INSERT INTO event_integrity_state VALUES (1,?)")
        .run(new Date().toISOString());
      this.db.exec(`
        CREATE TRIGGER IF NOT EXISTS event_integrity_no_update BEFORE UPDATE ON event_integrity BEGIN SELECT RAISE(ABORT,'append only'); END;
        CREATE TRIGGER IF NOT EXISTS event_integrity_no_delete BEFORE DELETE ON event_integrity BEGIN SELECT RAISE(ABORT,'append only'); END;
        CREATE TRIGGER IF NOT EXISTS event_integrity_state_no_update BEFORE UPDATE ON event_integrity_state BEGIN SELECT RAISE(ABORT,'append only'); END;
        CREATE TRIGGER IF NOT EXISTS event_integrity_state_no_delete BEFORE DELETE ON event_integrity_state BEGIN SELECT RAISE(ABORT,'append only'); END;
        CREATE TRIGGER IF NOT EXISTS private_no_late_insert BEFORE INSERT ON event_private
          WHEN EXISTS (SELECT 1 FROM event_integrity WHERE seq=NEW.seq)
          BEGIN SELECT RAISE(ABORT,'append only'); END;
      `);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  verifyIntegrity(): ReturnType<typeof verifyEventIntegrity> {
    return verifyEventIntegrity(this.db);
  }

  private updateRoundIndex(event: ArenaEvent): void {
    if (!event.round_id) return;
    if (event.type === "round.started") {
      this.db.prepare("INSERT OR IGNORE INTO rounds VALUES (?,?,?,NULL,'started',NULL,NULL)")
        .run(event.round_id, Number(event.public.round_no), event.seq);
    } else if (event.type === "round.ended") {
      this.db.prepare("UPDATE rounds SET last_seq=?,status=?,score_json=?,headline_pt=? WHERE round_id=?")
        .run(event.seq, String(event.public.status), JSON.stringify(event.public.score),
          String(event.public.summary_pt), event.round_id);
    }
  }

  get(seq: number): ArenaEvent | undefined {
    const row = this.db.prepare("SELECT * FROM events WHERE seq=?").get(seq) as Record<string, unknown> | undefined;
    return row ? this.fromRow(row) : undefined;
  }

  getPrivate(seq: number): Record<string, unknown> | undefined {
    const row = this.db.prepare("SELECT private_json FROM event_private WHERE seq=?")
      .get(seq) as { private_json: string } | undefined;
    return row ? JSON.parse(row.private_json) as Record<string, unknown> : undefined;
  }

  list(query: EventQuery = {}): ArenaEvent[] {
    const terms = ["seq>?", "seq<?"];
    const values: (string | number)[] = [query.after ?? 0, query.before ?? 9_007_199_254_740_991];
    if (query.roundId) { terms.push("round_id=?"); values.push(query.roundId); }
    if (query.types?.length) { terms.push(`type IN (${query.types.map(() => "?").join(",")})`); values.push(...query.types); }
    const limit = Math.min(Math.max(query.limit ?? 500, 1), 500);
    const rows = this.db.prepare(`SELECT * FROM events WHERE ${terms.join(" AND ")} ORDER BY seq LIMIT ?`)
      .all(...values, limit) as Record<string, unknown>[];
    return rows.map((row) => this.fromRow(row));
  }

  listPublic(query: EventQuery = {}): Omit<ArenaEvent, "private">[] {
    return this.list(query).map((event) => publicView(event));
  }

  rounds(): RoundIndex[] {
    return this.db.prepare("SELECT * FROM rounds ORDER BY round_no DESC").all() as unknown as RoundIndex[];
  }

  saveKeyframe(seq: number, roundId: string | null, ts: string, reducerVersion: number, stateGz: Uint8Array): void {
    this.db.prepare("INSERT OR REPLACE INTO keyframes VALUES (?,?,?,?,?)").run(seq, roundId, ts, reducerVersion, stateGz);
  }

  nearestKeyframe(seq: number): { seq: number; reducer_version: number; state_gz: Uint8Array } | undefined {
    return this.db.prepare("SELECT seq,reducer_version,state_gz FROM keyframes WHERE seq<=? ORDER BY seq DESC LIMIT 1")
      .get(seq) as { seq: number; reducer_version: number; state_gz: Uint8Array } | undefined;
  }

  subscribe(listener: (event: ArenaEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private fromRow(row: Record<string, unknown>): ArenaEvent {
    return parseEvent({ id: row.id, seq: row.seq, round_id: row.round_id, ts: row.ts,
      ...(row.twin_ts ? { twin_ts: row.twin_ts } : {}), type: row.type,
      actor: { id: row.actor_id, role: row.actor_role },
      ...(row.parent_actor_id ? { parent_actor_id: row.parent_actor_id } : {}),
      ...(row.area ? { area: row.area } : {}), ...(row.incident_id ? { incident_id: row.incident_id } : {}),
      ...(row.task_id ? { task_id: row.task_id } : {}), public_summary_pt: row.summary_pt,
      public: JSON.parse(String(row.public_json)),
    });
  }

  close(): void { this.db.close(); }
}
