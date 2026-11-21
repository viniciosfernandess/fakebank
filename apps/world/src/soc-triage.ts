import type { DatabaseSync } from "node:sqlite";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { Area } from "../../../packages/contracts/src/index.ts";

type Severity = "low" | "medium" | "high" | "critical";
interface RulePolicy { id: string; area: Area; severity: Severity; owner: string;
  version: number; }
export interface AlertTriage {
  alert_id: string;
  owner_role: string;
  status: "pending" | "acknowledged" | "escalated";
  sla_seconds: number;
  policy_version: number;
  rule_version: number;
  queued_at_real: string;
  due_at_real: string;
  queue_seconds: number;
  acknowledged_by: string | null;
  acknowledged_at_real: string | null;
  escalated_at_real: string | null;
}

const POLICY_VERSION = 1;
const SLA_BY_SEVERITY: Record<Severity, number> = {
  critical: 60, high: 300, medium: 900, low: 3600,
};

export class SocTriage {
  private readonly db: DatabaseSync;
  private readonly realNow: () => Date;
  private readonly events: EventStore | undefined;

  constructor(db: DatabaseSync, realNow: () => Date, rules: readonly RulePolicy[],
    events?: EventStore) {
    this.db = db; this.realNow = realNow; this.events = events;
    db.function("soc_real_now", () => this.realNow().toISOString());
    db.exec(`CREATE TABLE IF NOT EXISTS sentinel_triage_policy (
      rule_id TEXT PRIMARY KEY, area TEXT NOT NULL, severity TEXT NOT NULL,
      owner_role TEXT NOT NULL, sla_seconds INTEGER NOT NULL CHECK(sla_seconds>0),
      version INTEGER NOT NULL, rule_version INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS sentinel_alert_triage (
      alert_id TEXT PRIMARY KEY REFERENCES sentinel_alerts(id),
      area TEXT NOT NULL, severity TEXT NOT NULL, owner_role TEXT NOT NULL,
      sla_seconds INTEGER NOT NULL, policy_version INTEGER NOT NULL,
      queued_at_real TEXT NOT NULL, due_at_real TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending','acknowledged','escalated')),
      acknowledged_by TEXT, acknowledged_at_real TEXT, escalated_at_real TEXT,
      rule_version INTEGER NOT NULL DEFAULT 1,
      CHECK((acknowledged_by IS NULL)=(acknowledged_at_real IS NULL))
    );
    CREATE INDEX IF NOT EXISTS sentinel_triage_due
      ON sentinel_alert_triage(status,due_at_real);
    CREATE TABLE IF NOT EXISTS sentinel_triage_escalation_outbox (
      alert_id TEXT PRIMARY KEY REFERENCES sentinel_alert_triage(alert_id),
      published_at TEXT
    );`);
    for (const table of ["sentinel_triage_policy", "sentinel_alert_triage"])
      if (!(db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[])
        .some((column) => column.name === "rule_version"))
        db.exec(`ALTER TABLE ${table} ADD COLUMN rule_version INTEGER NOT NULL DEFAULT 1`);
    const upsert = db.prepare(`INSERT INTO sentinel_triage_policy
      (rule_id,area,severity,owner_role,sla_seconds,version,rule_version)
      VALUES (?,?,?,?,?,?,?)
      ON CONFLICT(rule_id) DO UPDATE SET area=excluded.area,severity=excluded.severity,
      owner_role=excluded.owner_role,sla_seconds=excluded.sla_seconds,
      version=excluded.version,rule_version=excluded.rule_version`);
    for (const rule of rules) upsert.run(rule.id, rule.area, rule.severity,
      rule.owner, SLA_BY_SEVERITY[rule.severity], POLICY_VERSION, rule.version);
    // Historical alerts lacked a real-clock queue timestamp; migration starts their SLA now.
    db.exec(`INSERT OR IGNORE INTO sentinel_alert_triage
      (alert_id,area,severity,owner_role,sla_seconds,policy_version,
        queued_at_real,due_at_real,status,acknowledged_by,acknowledged_at_real,
        escalated_at_real,rule_version)
      SELECT a.id,COALESCE(p.area,'api_gateway'),COALESCE(p.severity,'high'),
        COALESCE(p.owner_role,'platform_oncall'),COALESCE(p.sla_seconds,300),
        COALESCE(p.version,${POLICY_VERSION}),
        soc_real_now(),
        strftime('%Y-%m-%dT%H:%M:%fZ',soc_real_now(),
          '+' || COALESCE(p.sla_seconds,300) || ' seconds'),
        'pending',NULL,NULL,NULL,COALESCE(p.rule_version,1)
      FROM sentinel_alerts a LEFT JOIN sentinel_triage_policy p ON p.rule_id=a.rule_id;
    DROP TRIGGER IF EXISTS main.sentinel_alert_triage_insert;
    DROP TRIGGER IF EXISTS temp.sentinel_alert_triage_insert;
    CREATE TEMP TRIGGER sentinel_alert_triage_insert
      AFTER INSERT ON main.sentinel_alerts BEGIN
        INSERT INTO sentinel_alert_triage
          (alert_id,area,severity,owner_role,sla_seconds,policy_version,
            queued_at_real,due_at_real,status,acknowledged_by,acknowledged_at_real,
            escalated_at_real,rule_version)
        SELECT NEW.id,COALESCE(p.area,'api_gateway'),COALESCE(p.severity,'high'),
          COALESCE(p.owner_role,'platform_oncall'),COALESCE(p.sla_seconds,300),
          COALESCE(p.version,${POLICY_VERSION}),
          soc_real_now(),
          strftime('%Y-%m-%dT%H:%M:%fZ',soc_real_now(),
            '+' || COALESCE(p.sla_seconds,300) || ' seconds'),
          'pending',NULL,NULL,NULL,COALESCE(p.rule_version,1)
        FROM (SELECT 1) LEFT JOIN sentinel_triage_policy p ON p.rule_id=NEW.rule_id;
      END;`);
  }

  get(alertId: string): AlertTriage | null {
    const row = this.db.prepare(`SELECT alert_id,owner_role,status,sla_seconds,policy_version,rule_version,
      queued_at_real,due_at_real,acknowledged_by,acknowledged_at_real,escalated_at_real
      FROM sentinel_alert_triage WHERE alert_id=?`).get(alertId) as
      Omit<AlertTriage, "queue_seconds"> | undefined;
    if (!row) return null;
    const end = row.acknowledged_at_real ?? this.realNow().toISOString();
    return { ...row, queue_seconds: Math.max(0,
      Math.floor((Date.parse(end) - Date.parse(row.queued_at_real)) / 1000)) };
  }

  acknowledge(alertId: string, operatorId: string): AlertTriage {
    if (!alertId || !operatorId || operatorId.length > 128)
      throw new Error("SOC_TRIAGE_INPUT_INVALID");
    const existing = this.get(alertId);
    if (!existing) throw new Error("SOC_ALERT_NOT_FOUND");
    if (existing.acknowledged_by && existing.acknowledged_by !== operatorId)
      throw new Error("SOC_ALERT_ALREADY_ACKNOWLEDGED");
    if (!existing.acknowledged_by) this.db.prepare(`UPDATE sentinel_alert_triage
      SET status='acknowledged',acknowledged_by=?,acknowledged_at_real=?
      WHERE alert_id=? AND status IN ('pending','escalated')`).run(
      operatorId, this.realNow().toISOString(), alertId);
    const result = this.get(alertId)!;
    if (result.acknowledged_by !== operatorId)
      throw new Error("SOC_ALERT_ALREADY_ACKNOWLEDGED");
    return result;
  }

  escalateDue(): number {
    const now = this.realNow().toISOString();
    const due = this.db.prepare(`SELECT alert_id FROM sentinel_alert_triage
      WHERE status='pending' AND due_at_real<=? ORDER BY due_at_real LIMIT 100`)
      .all(now) as { alert_id: string }[];
    const ownsTransaction = !this.db.isTransaction;
    if (due.length) {
      if (ownsTransaction) this.db.exec("BEGIN IMMEDIATE");
      try {
        for (const row of due) {
          const changed = this.db.prepare(`UPDATE sentinel_alert_triage
            SET status='escalated',escalated_at_real=?
            WHERE alert_id=? AND status='pending' AND due_at_real<=?`)
            .run(now, row.alert_id, now);
          if (changed.changes) this.db.prepare(`INSERT OR IGNORE INTO sentinel_triage_escalation_outbox
            VALUES (?,NULL)`).run(row.alert_id);
        }
        if (ownsTransaction) this.db.exec("COMMIT");
      } catch (error) {
        if (ownsTransaction) this.db.exec("ROLLBACK");
        throw error;
      }
    }
    if (!ownsTransaction) return due.length;
    const pending = this.db.prepare(`SELECT o.alert_id,t.area,t.severity,t.owner_role,
      t.due_at_real FROM sentinel_triage_escalation_outbox o
      JOIN sentinel_alert_triage t ON t.alert_id=o.alert_id
      WHERE o.published_at IS NULL ORDER BY t.due_at_real LIMIT 100`).all() as
      { alert_id: string; area: Area; severity: Severity; owner_role: string;
        due_at_real: string }[];
    for (const row of pending) {
      if (!this.events) break;
      const alert = this.db.prepare("SELECT rule_id FROM sentinel_alerts WHERE id=?")
        .get(row.alert_id) as { rule_id: string };
      try {
        this.events.append({ round_id: null, ts: this.realNow().toISOString(),
          type: "sentinel.alert",
          actor: { id: "sentinel-triage", role: "sentinel" }, area: row.area,
          public_summary_pt: "Prazo de triagem do SOC excedido",
          public: { alert_id: row.alert_id, rule_id: alert.rule_id,
            severity: row.severity, area: row.area, pattern_label: "TRIAGE_SLA_EXCEEDED" },
          private: { owner_role: row.owner_role, due_at_real: row.due_at_real } },
        `soc-triage-escalation:${row.alert_id}`);
        this.db.prepare(`UPDATE sentinel_triage_escalation_outbox SET published_at=?
          WHERE alert_id=?`).run(this.realNow().toISOString(), row.alert_id);
      } catch { /* Keep the durable outbox row for the next scan. */ }
    }
    return due.length;
  }
}
