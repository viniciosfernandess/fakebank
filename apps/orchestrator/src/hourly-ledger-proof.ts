import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { Bank } from "../../world/src/bank.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";

const HOUR_MS = 3_600_000;
const MAX_HOURS_PER_TICK = 24;

interface LedgerEntry {
  id: string; tx_id: string; account_id: string; amount: number;
  kind: string; actor: string; ref_type: string; ref_id: string;
  created_at: string; reverses_tx_id: string | null;
}

export interface HourlyLedgerProof {
  hour_start: string; root_sha256: string; entries: number;
  net_cents: number;
}

function hourStart(date: Date): string {
  const time = date.getTime();
  if (!Number.isFinite(time)) throw new Error("LEDGER_PROOF_CLOCK_INVALID");
  return new Date(Math.floor(time / HOUR_MS) * HOUR_MS).toISOString();
}

function digest(...parts: readonly Uint8Array[]): Buffer {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

export function computeHourlyLedgerProof(db: DatabaseSync,
  hour: string): HourlyLedgerProof {
  const start = Date.parse(hour);
  if (!Number.isFinite(start) || hourStart(new Date(start)) !== hour)
    throw new Error("LEDGER_PROOF_HOUR_INVALID");
  const end = new Date(start + HOUR_MS).toISOString();
  const leaves: Buffer[] = [];
  let netCents = 0;
  for (const row of db.prepare(`SELECT id,tx_id,account_id,amount,kind,actor,
    ref_type,ref_id,created_at,reverses_tx_id FROM ledger_entries
    WHERE created_at>=? AND created_at<? ORDER BY created_at,id`)
    .iterate(hour, end) as Iterable<LedgerEntry>) {
    if (!Number.isSafeInteger(row.amount)) throw new Error("LEDGER_PROOF_AMOUNT_INVALID");
    netCents += row.amount;
    if (!Number.isSafeInteger(netCents)) throw new Error("LEDGER_PROOF_AMOUNT_INVALID");
    leaves.push(digest(Buffer.from("BV_LEDGER_LEAF_V1\0"), Buffer.from(JSON.stringify([
      row.id, row.tx_id, row.account_id, row.amount, row.kind, row.actor,
      row.ref_type, row.ref_id, row.created_at, row.reverses_tx_id,
    ]))));
  }
  let level = leaves;
  if (!level.length) level = [digest(Buffer.from("BV_LEDGER_EMPTY_V1"))];
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let index = 0; index < level.length; index += 2)
      next.push(digest(Buffer.from("BV_LEDGER_NODE_V1\0"), level[index]!,
        level[index + 1] ?? level[index]!));
    level = next;
  }
  return { hour_start: hour, root_sha256: level[0]!.toString("hex"),
    entries: leaves.length, net_cents: netCents };
}

export class HourlyLedgerProofStore {
  private readonly bank: Bank;
  private readonly events: EventStore;
  private readonly firstHour: string;
  constructor(bank: Bank, events: EventStore) {
    this.bank = bank;
    this.events = events;
    bank.db.exec(`CREATE INDEX IF NOT EXISTS ledger_created_hour
      ON ledger_entries(created_at,id)`);
    events.db.exec(`CREATE TABLE IF NOT EXISTS hourly_ledger_proof_state (
      id INTEGER PRIMARY KEY CHECK(id=1),first_hour TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS hourly_ledger_proof_state_no_update
      BEFORE UPDATE ON hourly_ledger_proof_state
      BEGIN SELECT RAISE(ABORT,'HOURLY_LEDGER_PROOF_STATE_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS hourly_ledger_proof_state_no_delete
      BEFORE DELETE ON hourly_ledger_proof_state
      BEGIN SELECT RAISE(ABORT,'HOURLY_LEDGER_PROOF_STATE_IMMUTABLE'); END;`);
    let state = events.db.prepare(`SELECT first_hour FROM hourly_ledger_proof_state
      WHERE id=1`).get() as { first_hour: string } | undefined;
    if (!state) {
      if (events.db.prepare(`SELECT 1 FROM events WHERE type='ledger.hourly_proof' LIMIT 1`)
        .get()) throw new Error("INTEGRITY_HOURLY_LEDGER_PROOF_STATE");
      const firstHour = hourStart(bank.now());
      events.db.prepare(`INSERT INTO hourly_ledger_proof_state VALUES (1,?)`)
        .run(firstHour);
      state = { first_hour: firstHour };
    }
    this.firstHour = state.first_hour;
    if (hourStart(new Date(this.firstHour)) !== this.firstHour ||
      Date.parse(this.firstHour) > Date.parse(hourStart(bank.now())))
      throw new Error("INTEGRITY_HOURLY_LEDGER_PROOF_STATE");
    this.verify();
  }

  verify(): number {
    const rows = this.events.db.prepare(`SELECT public_json FROM events
      WHERE type='ledger.hourly_proof' ORDER BY seq`).all() as
      { public_json: string }[];
    let previous = Date.parse(this.firstHour) - HOUR_MS;
    for (const row of rows) {
      const recorded = JSON.parse(row.public_json) as HourlyLedgerProof;
      const time = Date.parse(recorded.hour_start);
      if (!Number.isFinite(time) || time !== previous + HOUR_MS ||
        JSON.stringify(computeHourlyLedgerProof(this.bank.db, recorded.hour_start)) !==
          JSON.stringify(recorded) || recorded.net_cents !== 0)
        throw new Error("INTEGRITY_HOURLY_LEDGER_PROOF");
      previous = time;
    }
    return rows.length;
  }

  publishCompleted(): number {
    const current = Date.parse(hourStart(this.bank.now()));
    const last = this.events.db.prepare(`SELECT json_extract(public_json,'$.hour_start') hour
      FROM events WHERE type='ledger.hourly_proof' ORDER BY seq DESC LIMIT 1`)
      .get() as { hour: string } | undefined;
    let next = last ? Date.parse(last.hour) + HOUR_MS : Date.parse(this.firstHour);
    let published = 0;
    if (next < current) this.verify();
    while (next < current && published < MAX_HOURS_PER_TICK) {
      const proof = computeHourlyLedgerProof(this.bank.db, new Date(next).toISOString());
      if (proof.net_cents !== 0) throw new Error("INTEGRITY_HOURLY_LEDGER_UNBALANCED");
      this.events.append({ round_id: null, ts: new Date().toISOString(),
        twin_ts: new Date(next + HOUR_MS).toISOString(),
        type: "ledger.hourly_proof", actor: { id: "ledger-proof", role: "system" },
        area: "ledger", public_summary_pt: "Prova horária do razão publicada",
        public: { ...proof } }, `ledger-hour:${proof.hour_start}`);
      published++;
      next += HOUR_MS;
    }
    return published;
  }
}
