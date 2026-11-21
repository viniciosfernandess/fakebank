import { EventStore } from "../../../packages/event-store/src/index.ts";
import { campaignSchedule, type FeatureSlot, type RoundSlot } from "./schedule.ts";

export interface StoredSlot extends RoundSlot { state: "scheduled" | "running" | "closed";
  claimedAt: string | null; closedAt: string | null; }
export interface StoredFeature extends FeatureSlot { endsAt: string;
  state: "scheduled" | "running" | "launched" | "skipped";
  claimedAt: string | null; closedAt: string | null; reason: string | null; }

export class CampaignScheduleStore {
  readonly events: EventStore;
  constructor(events: EventStore) {
    this.events = events;
    events.db.exec(`CREATE TABLE IF NOT EXISTS campaign_slots (
      round_id TEXT PRIMARY KEY, start_brt_date TEXT NOT NULL, round_no INTEGER NOT NULL UNIQUE,
      day INTEGER NOT NULL, slot TEXT NOT NULL, starts_at TEXT NOT NULL,
      ends_at TEXT NOT NULL, state TEXT NOT NULL, claimed_at TEXT, closed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS campaign_due ON campaign_slots(state,starts_at);
    CREATE TABLE IF NOT EXISTS campaign_features (
      feature_id TEXT PRIMARY KEY, start_brt_date TEXT NOT NULL, day INTEGER NOT NULL UNIQUE,
      starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, state TEXT NOT NULL,
      claimed_at TEXT, closed_at TEXT, reason TEXT
    );
    CREATE INDEX IF NOT EXISTS campaign_feature_due ON campaign_features(state,starts_at);`);
  }
  prepare(startBrtDate: string): StoredSlot[] {
    const schedule = campaignSchedule(startBrtDate);
    const existing = this.events.db.prepare("SELECT DISTINCT start_brt_date FROM campaign_slots")
      .all() as { start_brt_date: string }[];
    if (existing.some((row) => row.start_brt_date !== startBrtDate))
      throw new Error("CAMPAIGN_ALREADY_PREPARED");
    this.events.db.exec("BEGIN IMMEDIATE");
    try {
      const insert = this.events.db.prepare(`INSERT OR IGNORE INTO campaign_slots
        VALUES (?,?,?,?,?,?,?,'scheduled',NULL,NULL)`);
      for (const slot of schedule.rounds) insert.run(slot.roundId, startBrtDate, slot.roundNo,
        slot.day, slot.slot, slot.startsAt, slot.endsAt);
      const insertFeature = this.events.db.prepare(`INSERT OR IGNORE INTO campaign_features
        VALUES (?,?,?,?,?,'scheduled',NULL,NULL,NULL)`);
      for (const feature of schedule.features) insertFeature.run(feature.featureId, startBrtDate,
        feature.day, feature.startsAt, new Date(Date.parse(feature.startsAt) + 40 * 60_000).toISOString());
      this.events.db.exec("COMMIT");
    } catch (error) { this.events.db.exec("ROLLBACK"); throw error; }
    return this.list();
  }
  list(): StoredSlot[] {
    const rows = this.events.db.prepare("SELECT * FROM campaign_slots ORDER BY round_no")
      .all() as { round_id: string; round_no: number; day: number; slot: RoundSlot["slot"];
        starts_at: string; ends_at: string; state: StoredSlot["state"]; claimed_at: string | null;
        closed_at: string | null }[];
    return rows.map((row) => ({ roundId: row.round_id, roundNo: row.round_no, day: row.day,
      slot: row.slot, startsAt: row.starts_at, endsAt: row.ends_at,
      state: row.state, claimedAt: row.claimed_at, closedAt: row.closed_at }));
  }
  features(): StoredFeature[] {
    const rows = this.events.db.prepare("SELECT * FROM campaign_features ORDER BY day")
      .all() as { feature_id: string; day: number; starts_at: string; ends_at: string;
        state: StoredFeature["state"]; claimed_at: string | null; closed_at: string | null;
        reason: string | null }[];
    return rows.map((row) => ({ featureId: row.feature_id, day: row.day,
      startsAt: row.starts_at, endsAt: row.ends_at, state: row.state,
      claimedAt: row.claimed_at, closedAt: row.closed_at, reason: row.reason }));
  }
  claimDueFeature(now: Date): StoredFeature | undefined {
    if (this.events.db.prepare("SELECT 1 FROM campaign_features WHERE state='running' LIMIT 1").get())
      return undefined;
    const row = this.events.db.prepare(`SELECT feature_id FROM campaign_features WHERE state='scheduled'
      AND starts_at<=? AND ends_at>? ORDER BY starts_at LIMIT 1`)
      .get(now.toISOString(), now.toISOString()) as { feature_id: string } | undefined;
    if (!row) return undefined;
    const changed = this.events.db.prepare(`UPDATE campaign_features SET state='running',claimed_at=?
      WHERE feature_id=? AND state='scheduled'`).run(now.toISOString(), row.feature_id);
    return changed.changes ? this.features().find((item) => item.featureId === row.feature_id) : undefined;
  }
  closeFeature(featureId: string, state: "launched" | "skipped", now: Date, reason?: string): void {
    const changed = this.events.db.prepare(`UPDATE campaign_features SET state=?,closed_at=?,reason=?
      WHERE feature_id=? AND state='running'`).run(state, now.toISOString(), reason ?? null, featureId);
    if (!changed.changes) throw new Error("CAMPAIGN_FEATURE_NOT_RUNNING");
  }
  expireFeatures(now: Date): StoredFeature[] {
    const missed = this.features().filter((slot) => slot.state === "scheduled" &&
      Date.parse(slot.endsAt) <= now.getTime());
    for (const slot of missed) this.events.db.prepare(`UPDATE campaign_features SET state='skipped',
      closed_at=?,reason='missed_window' WHERE feature_id=? AND state='scheduled'`)
      .run(now.toISOString(), slot.featureId);
    return missed;
  }
  claimDue(now: Date): StoredSlot | undefined {
    if (this.events.db.prepare("SELECT 1 FROM campaign_slots WHERE state='running' LIMIT 1").get())
      return undefined;
    const slot = this.events.db.prepare(`SELECT round_id FROM campaign_slots WHERE state='scheduled'
      AND starts_at<=? AND ends_at>? ORDER BY starts_at LIMIT 1`)
      .get(now.toISOString(), now.toISOString()) as { round_id: string } | undefined;
    if (!slot) return undefined;
    const result = this.events.db.prepare(`UPDATE campaign_slots SET state='running',claimed_at=?
      WHERE round_id=? AND state='scheduled'`).run(now.toISOString(), slot.round_id);
    if (!result.changes) return undefined;
    return this.list().find((item) => item.roundId === slot.round_id);
  }
  claimOnDemand(now: Date): StoredSlot | undefined {
    this.events.db.exec("BEGIN IMMEDIATE");
    try {
      if (this.events.db.prepare("SELECT 1 FROM campaign_slots WHERE state='running' LIMIT 1").get()) {
        this.events.db.exec("COMMIT"); return undefined;
      }
      const next = this.events.db.prepare(`SELECT round_id FROM campaign_slots
        WHERE state='scheduled' ORDER BY round_no LIMIT 1`).get() as
        { round_id: string } | undefined;
      if (!next) { this.events.db.exec("COMMIT"); return undefined; }
      const startedAt = now.toISOString();
      const endsAt = new Date(now.getTime() + 40 * 60_000).toISOString();
      this.events.db.prepare(`UPDATE campaign_slots SET state='running',slot='manual',
        starts_at=?,ends_at=?,claimed_at=? WHERE round_id=? AND state='scheduled'`)
        .run(startedAt, endsAt, startedAt, next.round_id);
      const slot = this.list().find((item) => item.roundId === next.round_id);
      this.events.db.exec("COMMIT");
      return slot;
    } catch (error) { this.events.db.exec("ROLLBACK"); throw error; }
  }
  close(roundId: string, now: Date): void {
    const indexed = this.events.rounds().find((round) => round.round_id === roundId);
    if (!indexed || indexed.status === "started") throw new Error("CAMPAIGN_ROUND_NOT_ENDED");
    this.events.db.prepare(`UPDATE campaign_slots SET state='closed',closed_at=COALESCE(closed_at,?)
      WHERE round_id=? AND state<>'closed'`).run(now.toISOString(), roundId);
  }
  recover(now: Date): { missingStartEvents: StoredSlot[]; expired: StoredSlot[];
    open: StoredSlot[]; completedUnclosed: StoredSlot[]; missed: StoredSlot[] } {
    const indexed = new Map(this.events.rounds().map((round) => [round.round_id, round]));
    const slots = this.list();
    const running = slots.filter((slot) => slot.state === "running");
    return { missingStartEvents: running.filter((slot) => !indexed.has(slot.roundId)),
      expired: running.filter((slot) => Date.parse(slot.endsAt) <= now.getTime() &&
        indexed.get(slot.roundId)?.status === "started"),
      open: running.filter((slot) => Date.parse(slot.endsAt) > now.getTime() &&
        indexed.get(slot.roundId)?.status === "started"),
      completedUnclosed: running.filter((slot) => indexed.has(slot.roundId) &&
        indexed.get(slot.roundId)?.status !== "started"),
      missed: slots.filter((slot) => slot.state === "scheduled" && Date.parse(slot.endsAt) <= now.getTime()) };
  }
}
