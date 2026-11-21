import { randomUUID } from "node:crypto";
import type { Area } from "../../../packages/contracts/src/index.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import { Bank, BankError } from "../../world/src/bank.ts";
import { FEATURES } from "../../world/src/catalog.ts";
import { isGatewayAllowed } from "../../world/src/gateway.ts";

export type ContainmentKind = "freeze_account" | "block_route" | "disable_flag" | "revoke_session";
export interface ContainmentAction {
  incidentId: string;
  actorId: string;
  kind: ContainmentKind;
  target: string;
  reason: string;
  evidenceRefs: string[];
  ttlMin?: number;
  direction?: "inbound" | "outbound" | "both";
}
export interface ContainmentReceipt { id: string; expiresAt: string; honestCustomersAffected: number; }

export class BlueContainment {
  readonly bank: Bank;
  readonly events: EventStore | undefined;
  constructor(bank: Bank, events?: EventStore) { this.bank = bank; this.events = events; }

  hasActive(incidentId: string): boolean {
    const rows = this.bank.db.prepare(`SELECT expires_at FROM blue_containments
      WHERE incident_id=? AND kind IN ('freeze_account','block_route','disable_flag')
        AND lifted_at IS NULL`).all(incidentId) as { expires_at: string }[];
    const now = this.bank.realNow().toISOString();
    return rows.length > 0 && rows.every((row) => row.expires_at > now);
  }

  renewAwaiting(incidentId: string): number {
    const incident = this.bank.db.prepare("SELECT area,state FROM sentinel_incidents WHERE id=?")
      .get(incidentId) as { area: Area; state: string } | undefined;
    if (!incident || !["open", "awaiting_next_window", "needs_human"].includes(incident.state))
      throw new BankError("DEF_INCIDENT_NOT_AWAITING");
    const now = this.bank.realNow();
    const protective = this.bank.db.prepare(`SELECT id,expires_at FROM blue_containments
      WHERE incident_id=? AND kind IN ('freeze_account','block_route','disable_flag')
        AND lifted_at IS NULL`).all(incidentId) as { id: string; expires_at: string }[];
    if (["open", "awaiting_next_window"].includes(incident.state) &&
      protective.some((row) => row.expires_at <= now.toISOString())) return 0;
    const active = protective.filter((row) => row.expires_at > now.toISOString());
    if (!active.length) return 0;
    if (active.every((row) => Date.parse(row.expires_at) - now.getTime() > 10 * 60_000))
      return active.length;
    const expiry = new Date(now.getTime() + 30 * 60_000).toISOString();
    const updated = this.bank.transaction(() => {
      const statement = this.bank.db.prepare(`UPDATE blue_containments SET expires_at=?
        WHERE id=? AND lifted_at IS NULL AND expires_at>?`);
      return active.reduce((count, row) => count + Number(statement.run(expiry, row.id,
        now.toISOString()).changes), 0);
    });
    if (updated) this.events?.append({ round_id: null, ts: now.toISOString(),
      twin_ts: this.bank.now().toISOString(), type: "containment.renewed",
      actor: { id: "containment-keeper", role: "system" }, area: incident.area,
      incident_id: incidentId, public_summary_pt: "Contenção renovada enquanto a correção aguarda",
      public: { incident_id: incidentId, actions: updated, ttl_s: 1800 } });
    return updated;
  }

  renewAwaitingAll(): void {
    const rows = this.bank.db.prepare(`SELECT id,area,state FROM sentinel_incidents
      WHERE state IN ('awaiting_next_window','needs_human')`)
      .all() as { id: string; area: Area; state: string }[];
    if (this.bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='blue_tasks'`).get())
      rows.push(...this.bank.db.prepare(`SELECT i.id,i.area,i.state FROM sentinel_incidents i
        WHERE i.state='open' AND EXISTS (SELECT 1 FROM blue_tasks t
          WHERE t.incident_id=i.id AND t.state='open')
          AND EXISTS (SELECT 1 FROM blue_containments c
            WHERE c.incident_id=i.id AND c.lifted_at IS NULL
              AND c.kind IN ('freeze_account','block_route','disable_flag'))`)
        .all() as { id: string; area: Area; state: string }[]);
    for (const row of rows) {
      if (this.renewAwaiting(row.id)) continue;
      if (row.state === "needs_human") continue;
      this.bank.db.prepare("UPDATE sentinel_incidents SET state='needs_human' WHERE id=?")
        .run(row.id);
      this.events?.append({ round_id: null, ts: this.bank.realNow().toISOString(),
        twin_ts: this.bank.now().toISOString(), type: "incident.updated",
        actor: { id: "containment-keeper", role: "system" }, area: row.area,
        incident_id: row.id, public_summary_pt: "Contenção expirada; análise humana necessária",
        public: { incident_id: row.id, state: "needs_human" } });
    }
  }

  private validate(input: ContainmentAction): void {
    const incident = this.bank.db.prepare("SELECT state FROM sentinel_incidents WHERE id=?")
      .get(input.incidentId) as { state: string } | undefined;
    if (!incident || !["open", "awaiting_next_window"].includes(incident.state))
      throw new BankError("DEF_INCIDENT_NOT_OPEN");
    if (!input.actorId || input.actorId.length > 128 || !input.reason.trim() || input.reason.length > 500 ||
      input.evidenceRefs.length < 1 || input.evidenceRefs.length > 8 ||
      input.evidenceRefs.some((ref) => !/^[a-zA-Z0-9:_-]{3,128}$/.test(ref)))
      throw new BankError("BIZ_INVALID_CONTAINMENT");
    if (input.kind === "freeze_account") {
      if (!input.direction) throw new BankError("BIZ_DIRECTION_REQUIRED");
      this.bank.account(input.target);
    } else if (input.kind === "block_route") {
      const match = input.target.match(/^(GET|POST|PATCH|PUT|DELETE) (\/api\/v1\/[^?#]+)$/);
      if (!match || !match[2] || !isGatewayAllowed(match[2].slice("/api/v1".length)) ||
        /^\/api\/v1\/(?:auth\/login|health)(?:\/|$)/.test(match[2]))
        throw new BankError("DEF_ROUTE_PROTECTED");
    } else if (input.kind === "disable_flag") {
      if (!FEATURES.some((feature) => feature.id === input.target && feature.disableSafe))
        throw new BankError("DEF_FLAG_NOT_DISABLE_SAFE");
    } else {
      const session = this.bank.db.prepare("SELECT id FROM auth_sessions WHERE id=?")
        .get(input.target) as { id: string } | undefined;
      if (!session) throw new BankError("DEF_SESSION_NOT_FOUND");
    }
  }

  estimate(input: Pick<ContainmentAction, "kind" | "target">): number {
    if (input.kind === "freeze_account") {
      const row = this.bank.db.prepare(`SELECT COUNT(DISTINCT customer_id) n FROM accounts
        WHERE id=? AND customer_id IS NOT NULL AND customer_id IN
        (SELECT id FROM customers WHERE is_attacker_owned=0)`).get(input.target) as { n: number };
      return row.n;
    }
    if (input.kind === "revoke_session") {
      const row = this.bank.db.prepare(`SELECT COUNT(DISTINCT s.customer_id) n FROM auth_sessions s
        JOIN customers c ON c.id=s.customer_id WHERE s.id=? AND c.is_attacker_owned=0`)
        .get(input.target) as { n: number };
      return row.n;
    }
    if (input.kind === "disable_flag") {
      const row = this.bank.db.prepare("SELECT COUNT(*) n FROM customers WHERE is_attacker_owned=0 AND status='active'")
        .get() as { n: number };
      return row.n;
    }
    const route = input.target.split(" ")[1] ?? "";
    const row = this.bank.db.prepare(`SELECT COUNT(DISTINCT customer_id) n FROM access_log
      WHERE route=? AND customer_id IS NOT NULL AND ts>=?`).get(route,
        new Date(this.bank.now().getTime() - 86_400_000).toISOString()) as { n: number };
    return row.n;
  }

  apply(input: ContainmentAction): ContainmentReceipt {
    this.validate(input);
    const ttl = input.ttlMin ?? 30;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 30) throw new BankError("DEF_CONTAINMENT_TTL");
    const now = this.bank.realNow().toISOString();
    const expiresAt = new Date(Date.parse(now) + ttl * 60_000).toISOString();
    const receipt = this.bank.transaction(() => {
      const count = this.bank.db.prepare("SELECT COUNT(*) n FROM blue_containments WHERE incident_id=?")
        .get(input.incidentId) as { n: number };
      if (count.n >= 4) throw new BankError("DEF_CONTAINMENT_LIMIT");
      const duplicate = this.bank.db.prepare(`SELECT id FROM blue_containments WHERE incident_id=? AND kind=?
        AND target=? AND direction IS ? AND lifted_at IS NULL AND expires_at>?`)
        .get(input.incidentId, input.kind, input.target, input.direction ?? null, now);
      if (duplicate) throw new BankError("DEF_CONTAINMENT_DUPLICATE");
      if (input.kind === "block_route") {
        const active = this.bank.db.prepare(`SELECT COUNT(*) n FROM blue_containments WHERE kind='block_route'
          AND lifted_at IS NULL AND expires_at>?`).get(now) as { n: number };
        if (active.n >= 3) throw new BankError("DEF_ROUTE_LIMIT");
      }
      const id = `contain_${randomUUID()}`;
      this.bank.db.prepare("INSERT INTO blue_containments VALUES (?,?,?,?,?,?,?,?,?,?,NULL)")
        .run(id, input.incidentId, input.actorId, input.kind, input.target, input.direction ?? null,
          input.reason, JSON.stringify(input.evidenceRefs), now, expiresAt);
      if (input.kind === "revoke_session") this.bank.db.prepare("UPDATE auth_sessions SET revoked_at=? WHERE id=?")
        .run(now, input.target);
      return { id, expiresAt, honestCustomersAffected: this.estimate(input) };
    });
    const incident = this.bank.db.prepare("SELECT area FROM sentinel_incidents WHERE id=?")
      .get(input.incidentId) as { area: Area };
    this.events?.append({ round_id: null, ts: now, twin_ts: this.bank.now().toISOString(),
      type: "containment.applied", actor: { id: input.actorId, role: "investigator" },
      area: incident.area, incident_id: input.incidentId,
      public_summary_pt: `Contenção aplicada em ${incident.area}`,
      public: { action: input.kind, scope_label_pt: input.kind.replaceAll("_", " "),
        ttl_s: ttl * 60, collateral_honest: receipt.honestCustomersAffected },
      private: { containment_id: receipt.id, target: input.target, direction: input.direction ?? null,
        reason: input.reason, evidence_refs: input.evidenceRefs } });
    return receipt;
  }

  lift(id: string, actorId: string): boolean {
    if (!actorId || actorId.length > 128) throw new BankError("BIZ_INVALID_ACTOR");
    const action = this.bank.db.prepare(`SELECT kind,target FROM blue_containments
      WHERE id=? AND lifted_at IS NULL`).get(id) as
      { kind: ContainmentKind; target: string } | undefined;
    if (action?.kind === "disable_flag" &&
      action.target === "limite_dinamico" &&
      this.bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
        AND name='dynamic_limits'`).get() &&
      this.bank.db.prepare(`SELECT 1 FROM dynamic_limits
        WHERE verified=0 AND extra_cents>0 LIMIT 1`).get())
      throw new BankError("DEF_LIMIT_REPAIR_REQUIRED");
    const result = this.bank.db.prepare("UPDATE blue_containments SET lifted_at=? WHERE id=? AND lifted_at IS NULL")
      .run(this.bank.realNow().toISOString(), id);
    return result.changes === 1;
  }
}
