import { Bank, BankError } from "./bank.ts";
import { FEATURES } from "./catalog.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";

export class FeatureRegistry {
  readonly bank: Bank;
  readonly events: EventStore | undefined;
  constructor(bank: Bank, events?: EventStore) {
    this.bank = bank; this.events = events;
    bank.db.exec(`CREATE TABLE IF NOT EXISTS feature_flags (
      id TEXT PRIMARY KEY, day INTEGER NOT NULL, enabled INTEGER NOT NULL,
      flaw_open INTEGER NOT NULL, launched_at TEXT, changed_by TEXT NOT NULL
    );`);
    const insert = bank.db.prepare("INSERT OR IGNORE INTO feature_flags VALUES (?,?,0,0,NULL,'bootstrap')");
    for (const feature of FEATURES) insert.run(feature.id, feature.day);
  }
  isEnabled(id: string): boolean {
    const row = this.bank.db.prepare("SELECT enabled FROM feature_flags WHERE id=?").get(id) as { enabled: number } | undefined;
    if (!row) throw new BankError("BIZ_UNKNOWN_FEATURE");
    const containment = this.bank.db.prepare(`SELECT 1 FROM blue_containments WHERE kind='disable_flag'
      AND target=? AND lifted_at IS NULL AND expires_at>? LIMIT 1`)
      .get(id, this.bank.realNow().toISOString());
    return row.enabled === 1 && !containment;
  }
  isFlawOpen(id: string): boolean {
    const row = this.bank.db.prepare("SELECT flaw_open FROM feature_flags WHERE id=?").get(id) as { flaw_open: number } | undefined;
    if (!row) throw new BankError("BIZ_UNKNOWN_FEATURE");
    return row.flaw_open === 1;
  }
  setEnabled(id: string, enabled: boolean, by: string,
    launchCopy?: { titlePt: string; summaryPt: string }): void {
    const feature = FEATURES.find((item) => item.id === id);
    if (!feature) throw new BankError("BIZ_UNKNOWN_FEATURE");
    const prior = (this.bank.db.prepare("SELECT enabled FROM feature_flags WHERE id=?")
      .get(id) as { enabled: number }).enabled === 1;
    if (prior === enabled) return;
    this.bank.db.prepare("UPDATE feature_flags SET enabled=?,launched_at=COALESCE(launched_at,?),changed_by=? WHERE id=?")
      .run(Number(enabled), this.bank.now().toISOString(), by, id);
    this.events?.append({ round_id: null, ts: new Date().toISOString(), twin_ts: this.bank.now().toISOString(),
      type: "flag.changed", actor: { id: by, role: "system" }, area: feature.area,
      public_summary_pt: `${id}: ${enabled ? "ativado" : "desativado"}`,
      public: { key: id, enabled, by } });
    if (enabled) this.events?.append({ round_id: null, ts: new Date().toISOString(), twin_ts: this.bank.now().toISOString(),
      type: "feature.launched", actor: { id: by, role: "product" }, area: feature.area,
      public_summary_pt: launchCopy?.summaryPt ?? `${id} lançado`, public: { feature_id: id, area: feature.area,
        name_pt: launchCopy?.titlePt ?? id.replaceAll("_", " "),
        summary_pt: launchCopy?.summaryPt ?? `${id} disponível`, day: feature.day } });
  }
  patchFlaw(id: string, by: string): void {
    if (!FEATURES.some((item) => item.id === id)) throw new BankError("BIZ_UNKNOWN_FEATURE");
    this.bank.db.prepare("UPDATE feature_flags SET flaw_open=0,changed_by=? WHERE id=?").run(by, id);
  }
}
