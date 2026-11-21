import type { EventStore } from "../../../../packages/event-store/src/index.ts";

const quotaPattern = /(?:rate[ -]?limit|usage[ -]?limit|quota|too many requests|\b429\b)/i;

export class CodexQuotaGate {
  private readonly events: EventStore;
  private readonly now: () => Date;
  constructor(events: EventStore, now: () => Date = () => new Date()) {
    this.events = events;
    this.now = now;
    events.db.exec(`CREATE TABLE IF NOT EXISTS codex_quota_pause (
      id INTEGER PRIMARY KEY CHECK(id=1), paused_until TEXT NOT NULL,
      reason TEXT NOT NULL, detected_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS codex_quota_history (
      id INTEGER PRIMARY KEY, detected_at TEXT NOT NULL UNIQUE, paused_until TEXT NOT NULL,
      reason TEXT NOT NULL
    );
    INSERT OR IGNORE INTO codex_quota_history (detected_at,paused_until,reason)
      SELECT detected_at,paused_until,reason FROM codex_quota_pause;`);
  }
  resumeAt(): string | null {
    const row = this.events.db.prepare("SELECT paused_until FROM codex_quota_pause WHERE id=1")
      .get() as { paused_until: string } | undefined;
    if (!row) return null;
    if (Date.parse(row.paused_until) > this.now().getTime()) return row.paused_until;
    this.events.db.prepare("DELETE FROM codex_quota_pause WHERE id=1").run();
    return null;
  }
  noteFailure(message: string): string | null {
    if (!quotaPattern.test(message)) return null;
    const retry = /retry[ -]?after\s+(\d+)\s*(seconds?|minutes?)/i.exec(message);
    const duration = retry ? Number(retry[1]) * (retry[2]!.toLowerCase().startsWith("minute") ? 60_000 : 1_000)
      : 5 * 60_000;
    const waitMs = Math.min(24 * 60 * 60_000, Math.max(30_000, duration));
    const now = this.now();
    const resumeAt = new Date(now.getTime() + waitMs).toISOString();
    this.events.db.exec("BEGIN IMMEDIATE");
    try {
      this.resumeAt();
      const current = this.events.db.prepare("SELECT detected_at FROM codex_quota_pause WHERE id=1")
        .get() as { detected_at: string } | undefined;
      const detectedAt = current?.detected_at ?? now.toISOString();
      this.events.db.prepare(`INSERT INTO codex_quota_pause VALUES (1,?,?,?)
        ON CONFLICT(id) DO UPDATE SET paused_until=MAX(paused_until,excluded.paused_until),
        reason=excluded.reason,detected_at=excluded.detected_at`)
        .run(resumeAt, "codex_rate_limit", detectedAt);
      this.events.db.prepare(`INSERT INTO codex_quota_history
        (detected_at,paused_until,reason) VALUES (?,?,?)
        ON CONFLICT(detected_at) DO UPDATE SET paused_until=MAX(paused_until,excluded.paused_until)`)
        .run(detectedAt, resumeAt, "codex_rate_limit");
      this.events.db.exec("COMMIT");
    } catch (error) {
      this.events.db.exec("ROLLBACK");
      throw error;
    }
    return this.resumeAt();
  }
}
