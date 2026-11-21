import { AREAS, type Area } from "../../../packages/contracts/src/index.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { Bank } from "../../world/src/bank.ts";
import { areaHealth, overallHealth } from "./scoring.ts";

interface BreachRow { area: Area; verified_money_cents: number; patched_by: string | null;
  patch_round: number | null; regression_test_id: string | null;
  claim_kind: string | null; entities: number | null; }
export interface HealthSnapshot { overall: number; areas: Record<Area, number>; }

function severity(row: BreachRow): number {
  if (row.area === "ledger" || row.verified_money_cents > 1_000_000) return 40;
  if (row.verified_money_cents > 100_000 || row.claim_kind === "privilege_gained") return 25;
  if (row.verified_money_cents > 0 || (row.claim_kind === "data_exposed" && (row.entities ?? 0) > 1))
    return 10;
  return 4;
}

export class HealthTracker {
  readonly bank: Bank;
  readonly events: EventStore;
  readonly realNow: () => Date;
  private last: HealthSnapshot | undefined;
  private lastEmittedMs = -Infinity;
  constructor(bank: Bank, events: EventStore, realNow: () => Date = () => new Date()) {
    this.bank = bank; this.events = events; this.realNow = realNow;
  }

  snapshot(): HealthSnapshot {
    const hasMemory = this.bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='attack_memory'`).get();
    const hasEffects = this.bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='red_sandbox_effect_checks'`).get();
    const breaches = hasMemory ? this.bank.db.prepare(`SELECT m.area,m.verified_money_cents,
      m.patched_by,m.patch_round,m.regression_test_id,${hasEffects ? "c.claim_kind,c.entities" :
        "NULL claim_kind,NULL entities"} FROM attack_memory m
      ${hasEffects ? "LEFT JOIN red_sandbox_effect_checks c ON c.id=m.effect_check_id" : ""}
      WHERE m.outcome IN ('success','partial')`).all() as unknown as BreachRow[] : [];
    const roundNo = Math.max(1, ...this.events.rounds().map((round) => round.round_no));
    const quarantine = new Set<Area>();
    for (const event of this.events.db.prepare(`SELECT area,type FROM events WHERE
      type IN ('area.quarantined','area.released') ORDER BY seq`).all() as
      { area: Area; type: string }[]) {
      if (!AREAS.includes(event.area)) continue;
      if (event.type === "area.quarantined") quarantine.add(event.area);
      else quarantine.delete(event.area);
    }
    const blocked = new Map<Area, number>();
    const hasBlocked = this.bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='sim_blocked_customers'`).get();
    if (hasBlocked) {
      const since = new Date(this.realNow().getTime() - 86_400_000).toISOString();
      for (const row of this.bank.db.prepare(`SELECT area,COUNT(DISTINCT customer_id) n
        FROM sim_blocked_customers WHERE minute>=? GROUP BY area`).all(since) as
        { area: Area; n: number }[]) blocked.set(row.area, row.n);
    }
    const restored = new Map<Area, number>();
    const hasIncidents = this.bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='sentinel_incidents'`).get();
    for (const row of this.events.db.prepare(`SELECT incident_id,public_json FROM events
      WHERE type='damage.restored'`).all() as { incident_id: string | null; public_json: string }[]) {
      const incident = row.incident_id && hasIncidents ? this.bank.db.prepare(`SELECT area FROM sentinel_incidents WHERE id=?`)
        .get(row.incident_id) as { area: Area } | undefined : undefined;
      const area = incident?.area ?? "ledger";
      const value = Number((JSON.parse(row.public_json) as { restored_cents?: number }).restored_cents ?? 0);
      restored.set(area, (restored.get(area) ?? 0) + value);
    }
    const areas = Object.fromEntries(AREAS.map((area) => {
      const own = breaches.filter((row) => row.area === area);
      const open = own.filter((row) => !row.patched_by);
      const probation = own.filter((row) => row.patched_by &&
        row.patch_round !== null && row.patch_round >= roundNo - 1);
      const loss = Math.max(0, own.reduce((sum, row) => sum + row.verified_money_cents, 0) -
        (restored.get(area) ?? 0));
      const regressions = new Set(own.map((row) => row.regression_test_id).filter(Boolean)).size;
      return [area, areaHealth({ openSeverityWeight: open.reduce((sum, row) => sum + severity(row), 0),
        probationSeverityWeight: probation.reduce((sum, row) => sum + severity(row), 0),
        quarantined: quarantine.has(area), wronglyBlockedLast24h: blocked.get(area) ?? 0,
        unrecoveredLossBrl: loss / 100, regressionTests: regressions })];
    })) as Record<Area, number>;
    return { overall: overallHealth(areas), areas };
  }

  update(): HealthSnapshot {
    const health = this.snapshot();
    const now = this.realNow();
    const changed = !this.last || Math.abs(health.overall - this.last.overall) >= 0.1 ||
      AREAS.some((area) => Math.abs(health.areas[area] - this.last!.areas[area]) >= 0.1);
    if (changed || now.getTime() - this.lastEmittedMs >= 60_000) {
      this.events.append({ round_id: null, ts: now.toISOString(), twin_ts: this.bank.now().toISOString(),
        type: "health.updated", actor: { id: "bank-health", role: "system" },
        public_summary_pt: "Saúde do banco atualizada", public: { ...health } });
      this.last = health;
      this.lastEmittedMs = now.getTime();
    }
    return health;
  }
}
