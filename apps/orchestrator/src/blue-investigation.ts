import { z } from "zod";
import { Bank, BankError } from "../../world/src/bank.ts";
import type { Area } from "../../../packages/contracts/src/index.ts";

const id = z.string().min(1).max(128);
const iso = z.iso.datetime({ offset: true });
export const logInput = z.strictObject({ area: z.enum(["auth", "accounts", "pix", "cards", "loans", "api_gateway", "ledger"]),
  from: iso, to: iso, filters: z.strictObject({ kind: id.optional(), customerId: id.optional(),
    accountId: id.optional(), status: z.number().int().optional() }).optional(), limit: z.number().int().min(1).max(50) });
export const queryInput = z.discriminatedUnion("name", [
  z.strictObject({ name: z.literal("balance_drift"), args: z.strictObject({ accountId: id.optional() }) }),
  z.strictObject({ name: z.literal("tx_by_actor"), args: z.strictObject({ actor: id }) }),
  z.strictObject({ name: z.literal("entries_for_account"), args: z.strictObject({ accountId: id }) }),
  z.strictObject({ name: z.literal("system_account_delta"), args: z.strictObject({ role: id, from: iso, to: iso }) }),
  z.strictObject({ name: z.literal("large_movements"), args: z.strictObject({ minCents: z.number().int().positive(),
    from: iso, to: iso }) }),
  z.strictObject({ name: z.literal("reversals_for"), args: z.strictObject({ txId: id }) }),
]);
export type NamedLedgerQuery = z.infer<typeof queryInput>;
export type LogQuery = z.infer<typeof logInput>;

function window(from: string, to: string): void {
  if (Date.parse(from) > Date.parse(to) || Date.parse(to) - Date.parse(from) > 90 * 86_400_000)
    throw new BankError("BIZ_QUERY_WINDOW");
}

export class BlueInvestigation {
  readonly bank: Bank;
  readonly incidentId: string;
  readonly area: Area;
  constructor(bank: Bank, incidentId: string) {
    const incident = bank.db.prepare("SELECT area,state FROM sentinel_incidents WHERE id=?")
      .get(incidentId) as { area: Area; state: string } | undefined;
    if (!incident || !["open", "awaiting_next_window"].includes(incident.state))
      throw new BankError("DEF_INCIDENT_NOT_OPEN");
    this.bank = bank; this.incidentId = incidentId; this.area = incident.area;
  }
  private check(): void {
    const state = this.bank.db.prepare("SELECT state FROM sentinel_incidents WHERE id=?")
      .get(this.incidentId) as { state: string } | undefined;
    if (!state || !["open", "awaiting_next_window"].includes(state.state))
      throw new BankError("DEF_INCIDENT_NOT_OPEN");
  }
  alertFacts(): Record<string, unknown>[] {
    this.check();
    const alerts = this.bank.db.prepare(`SELECT a.id,a.rule_id,a.entity,a.observed_json,a.window_s,a.first_seen,a.last_seen,a.count
      FROM sentinel_alerts a JOIN sentinel_incidents i ON i.id=? WHERE a.entity=i.entity_key OR a.entity IN
      (SELECT id FROM accounts WHERE customer_id=i.entity_key)
      OR a.entity IN (SELECT id FROM cards WHERE customer_id=i.entity_key)
      OR a.entity IN (SELECT id FROM loans WHERE customer_id=i.entity_key)
      OR a.entity IN (SELECT ca.id FROM card_authorizations ca
        JOIN cards c ON c.id=ca.card_id WHERE c.customer_id=i.entity_key)
      OR a.entity IN (SELECT id FROM med_cases WHERE customer_id=i.entity_key)
      ORDER BY a.last_seen DESC,a.id ASC`).all(this.incidentId) as Record<string, unknown>[];
    return alerts.map(({ observed_json, ...row }) => ({ ...row,
      observed: JSON.parse(String(observed_json)) }));
  }
  alerts(): { incident: Record<string, unknown>; alerts: Record<string, unknown>[];
    total: number; truncated: boolean } {
    const incident = this.bank.db.prepare(`SELECT id,entity_key,area,severity,state,alert_count,opened_at,last_seen_at
      FROM sentinel_incidents WHERE id=?`).get(this.incidentId) as Record<string, unknown>;
    const all = this.alertFacts();
    return { incident, alerts: all.slice(0, 30), total: all.length,
      truncated: all.length > 30 };
  }
  issuerStatus(): { incidentId: string; alertId: string;
    phase: "outage_confirmed" | "restored_awaiting_authorization" | "recovered";
    issuerAvailable: boolean; outageHistoryId: number; rejectionId: string;
    restoredHistoryId: number | null; authorizationId: string | null;
    availabilityHistory: Array<{ id: number; available: boolean; changedAt: string }>;
    rejectionsByCode: Array<{ code: string; count: number }>;
    acceptedAfterRestoreCount: number;
    evidenceRefs: string[] } | null {
    this.check();
    const incident = this.bank.db.prepare(`SELECT area,entity_key,opened_at FROM sentinel_incidents
      WHERE id=?`).get(this.incidentId) as
      { area: string; entity_key: string; opened_at: string } | undefined;
    if (incident?.area !== "cards" || incident.entity_key !== "card_issuer") return null;
    const alert = this.bank.db.prepare(`SELECT id,first_seen,observed_json
      FROM sentinel_alerts WHERE rule_id='S-CARD-13' AND entity='card_issuer'
      ORDER BY first_seen DESC LIMIT 1`).get() as
      { id: string; first_seen: string; observed_json: string } | undefined;
    if (!alert || alert.first_seen < incident.opened_at ||
      !this.alertFacts().some((item) => item.id === alert.id)) return null;
    const observed = JSON.parse(alert.observed_json) as Record<string, unknown>;
    if (observed.issuer_unavailable !== 1 ||
      typeof observed.declined_authorizations !== "number" ||
      observed.declined_authorizations < 1) return null;
    const outage = this.bank.db.prepare(`SELECT h.id history_id,r.id rejection_id
      FROM card_issuer_history h JOIN card_network_rejections r
        ON r.response_code='91' AND r.created_at>=h.changed_at
        AND r.created_at<=?
      WHERE h.available=0 AND h.changed_at<=?
        AND NOT EXISTS (SELECT 1 FROM card_issuer_history later
          WHERE later.id>h.id AND later.changed_at<=?)
      ORDER BY r.created_at DESC,r.id DESC LIMIT 1`).get(alert.first_seen,
        alert.first_seen, alert.first_seen) as
      { history_id: number; rejection_id: string } | undefined;
    if (!outage) return null;
    const state = this.bank.db.prepare(`SELECT available,changed_at FROM card_issuer_state
      WHERE id=1`).get() as { available: number; changed_at: string } | undefined;
    const restored = state?.available === 1 ? this.bank.db.prepare(`SELECT id,changed_at
      FROM card_issuer_history WHERE available=1 AND changed_at=? AND id>?
      ORDER BY id DESC LIMIT 1`).get(state.changed_at, outage.history_id) as
      { id: number; changed_at: string } | undefined : undefined;
    const deadline = new Date(Date.parse(alert.first_seen) + 24 * 60 * 60_000)
      .toISOString();
    const availabilityHistory = (this.bank.db.prepare(`SELECT id,available,changed_at
      FROM card_issuer_history WHERE id>=? ORDER BY id LIMIT 20`)
      .all(outage.history_id) as Array<{ id: number; available: number;
        changed_at: string }>).map((item) => ({ id: item.id,
          available: item.available === 1, changedAt: item.changed_at }));
    const rejectionsByCode = (this.bank.db.prepare(`SELECT response_code code,
      COUNT(*) count FROM card_network_rejections WHERE created_at>=?
        AND created_at<=? GROUP BY response_code ORDER BY response_code`)
      .all(availabilityHistory[0]!.changedAt, this.bank.now().toISOString()) as
      Array<{ code: string; count: number }>);
    const accepted = restored && restored.changed_at >= alert.first_seen &&
      restored.changed_at <= this.bank.now().toISOString() ?
      this.bank.db.prepare(`SELECT a.id FROM card_network_authorizations a
        WHERE a.response_code='00' AND a.created_at>? AND a.created_at<=?
          AND a.created_at<=?
          AND EXISTS (SELECT 1 FROM card_network_messages m
            WHERE m.authorization_id=a.id AND m.mti='0110'
              AND m.created_at>=a.created_at
              AND json_extract(m.payload_json,'$.response_code')='00')
        ORDER BY a.created_at,a.id LIMIT 1`).get(restored.changed_at, deadline,
          this.bank.now().toISOString()) as
      { id: string } | undefined : undefined;
    const evidenceRefs = [`sentinel_alerts:${alert.id}`,
      `card_issuer_history:${outage.history_id}`,
      `card_network_rejections:${outage.rejection_id}`];
    if (restored) evidenceRefs.push(`card_issuer_history:${restored.id}`);
    if (accepted) evidenceRefs.push(`card_network_authorizations:${accepted.id}`);
    const acceptedAfterRestoreCount = restored ? (this.bank.db.prepare(`SELECT COUNT(*) n
      FROM card_network_authorizations a WHERE a.response_code='00'
        AND a.created_at>? AND a.created_at<=? AND a.created_at<=?
        AND EXISTS (SELECT 1 FROM card_network_messages m
          WHERE m.authorization_id=a.id AND m.mti='0110'
            AND m.created_at>=a.created_at
            AND json_extract(m.payload_json,'$.response_code')='00')`)
      .get(restored.changed_at, deadline, this.bank.now().toISOString()) as
      { n: number }).n : 0;
    return { incidentId: this.incidentId, alertId: alert.id,
      phase: accepted ? "recovered" : restored ?
        "restored_awaiting_authorization" : "outage_confirmed",
      issuerAvailable: state?.available === 1,
      outageHistoryId: outage.history_id, rejectionId: outage.rejection_id,
      restoredHistoryId: restored?.id ?? null, availabilityHistory,
      rejectionsByCode, acceptedAfterRestoreCount,
      authorizationId: accepted?.id ?? null, evidenceRefs };
  }
  logs(input: LogQuery): Record<string, unknown>[] {
    this.check();
    const parsed = logInput.parse(input);
    if (parsed.area !== this.area && parsed.area !== "ledger") throw new BankError("DEF_AREA_SCOPE");
    window(parsed.from, parsed.to);
    const prefixes: Record<Area, string[]> = {
      auth: ["/auth/", "auth.", "/api/v1/auth/"], accounts: ["/accounts", "statement", "accounts.", "/api/v1/accounts"],
      pix: ["/pix/", "pix.", "/api/v1/pix/"], cards: ["/cards", "cards.", "/api/v1/cards"],
      loans: ["/loans", "loans.", "/api/v1/loans"], api_gateway: ["/api/", "gateway."], ledger: ["ledger."] };
    const routes = prefixes[parsed.area];
    const filters = parsed.filters ?? {};
    const routeClause = routes.map(() => "route LIKE ?").join(" OR ");
    const sql = `SELECT id,ts,actor,kind,customer_id,account_id,route,status FROM access_log
      WHERE ts>=? AND ts<=? AND (${routeClause})
      AND (? IS NULL OR kind=?) AND (? IS NULL OR customer_id=?)
      AND (? IS NULL OR account_id=?) AND (? IS NULL OR status=?)
      ORDER BY ts DESC,id DESC LIMIT ?`;
    return this.bank.db.prepare(sql).all(parsed.from, parsed.to, ...routes.map((route) => `${route}%`),
      filters.kind ?? null, filters.kind ?? null, filters.customerId ?? null, filters.customerId ?? null,
      filters.accountId ?? null, filters.accountId ?? null, filters.status ?? null, filters.status ?? null,
      parsed.limit) as Record<string, unknown>[];
  }
  ledger(input: NamedLedgerQuery): Record<string, unknown>[] {
    this.check();
    const query = queryInput.parse(input);
    switch (query.name) {
      case "balance_drift": return this.bank.db.prepare(`SELECT a.id account_id,a.balance_cached,
        COALESCE(SUM(e.amount),0) ledger_balance,a.balance_cached-COALESCE(SUM(e.amount),0) drift
        FROM accounts a LEFT JOIN ledger_entries e ON e.account_id=a.id
        WHERE (? IS NULL OR a.id=?) GROUP BY a.id HAVING drift<>0
        ORDER BY ABS(drift) DESC LIMIT 50`).all(query.args.accountId ?? null, query.args.accountId ?? null) as Record<string, unknown>[];
      case "tx_by_actor": return this.bank.db.prepare(`SELECT tx_id,MIN(created_at) ts,COUNT(*) entries,SUM(amount) net
        FROM ledger_entries WHERE actor=? GROUP BY tx_id ORDER BY ts DESC LIMIT 50`)
        .all(query.args.actor) as Record<string, unknown>[];
      case "entries_for_account": return this.bank.db.prepare(`SELECT id,tx_id,amount,kind,actor,ref_type,ref_id,created_at,reverses_tx_id
        FROM ledger_entries WHERE account_id=? ORDER BY created_at DESC,id DESC LIMIT 50`)
        .all(query.args.accountId) as Record<string, unknown>[];
      case "system_account_delta": {
        window(query.args.from, query.args.to);
        return this.bank.db.prepare(`SELECT a.id account_id,COALESCE(SUM(e.amount),0) delta_cents,COUNT(e.id) entries
          FROM accounts a LEFT JOIN ledger_entries e ON e.account_id=a.id AND e.created_at>=? AND e.created_at<=?
          WHERE a.kind='system' AND a.system_role=? GROUP BY a.id LIMIT 50`)
          .all(query.args.from, query.args.to, query.args.role) as Record<string, unknown>[];
      }
      case "large_movements": {
        window(query.args.from, query.args.to);
        return this.bank.db.prepare(`SELECT id,tx_id,account_id,amount,kind,actor,created_at FROM ledger_entries
          WHERE ABS(amount)>=? AND created_at>=? AND created_at<=?
          ORDER BY ABS(amount) DESC,id DESC LIMIT 50`).all(query.args.minCents,
          query.args.from, query.args.to) as Record<string, unknown>[];
      }
      case "reversals_for": return this.bank.db.prepare(`SELECT id,tx_id,account_id,amount,created_at
        FROM ledger_entries WHERE reverses_tx_id=? ORDER BY created_at DESC LIMIT 50`)
        .all(query.args.txId) as Record<string, unknown>[];
    }
  }
  trace(input: { accountId?: string; txId?: string; depth: 1 | 2 }): Record<string, unknown>[] {
    this.check();
    if ((input.accountId ? 1 : 0) + (input.txId ? 1 : 0) !== 1 || ![1, 2].includes(input.depth))
      throw new BankError("BIZ_TRACE_INPUT");
    const txIds = input.txId ? [id.parse(input.txId)] : (this.bank.db.prepare(`SELECT DISTINCT tx_id
      FROM ledger_entries WHERE account_id=? ORDER BY created_at DESC LIMIT 10`)
      .all(id.parse(input.accountId)) as { tx_id: string }[]).map((row) => row.tx_id);
    if (!txIds.length) return [];
    const placeholders = txIds.map(() => "?").join(",");
    const first = this.bank.db.prepare(`SELECT tx_id,account_id,amount,kind,actor,ref_id,created_at,reverses_tx_id
      FROM ledger_entries WHERE tx_id IN (${placeholders}) ORDER BY created_at DESC LIMIT 50`)
      .all(...txIds) as Record<string, unknown>[];
    if (input.depth === 1 || !input.accountId) return first;
    const neighbors = [...new Set(first.map((row) => String(row.account_id)))].filter((account) => account !== input.accountId).slice(0, 5);
    if (!neighbors.length) return first;
    const secondIds = this.bank.db.prepare(`SELECT DISTINCT tx_id FROM ledger_entries WHERE account_id IN
      (${neighbors.map(() => "?").join(",")}) ORDER BY created_at DESC LIMIT 10`).all(...neighbors) as { tx_id: string }[];
    const extra = secondIds.map((row) => row.tx_id).filter((txId) => !txIds.includes(txId));
    if (!extra.length) return first;
    return [...first, ...(this.bank.db.prepare(`SELECT tx_id,account_id,amount,kind,actor,ref_id,created_at,reverses_tx_id
      FROM ledger_entries WHERE tx_id IN (${extra.map(() => "?").join(",")}) ORDER BY created_at DESC LIMIT ?`)
      .all(...extra, 50 - first.length) as Record<string, unknown>[])].slice(0, 50);
  }
  profile(entityId: string): Record<string, unknown> {
    this.check();
    const entity = id.parse(entityId);
    const customer = this.bank.db.prepare(`SELECT c.id,c.created_at,c.status,c.persona FROM customers c
      WHERE c.id=? OR c.id=(SELECT customer_id FROM accounts WHERE id=?)`).get(entity, entity) as
      { id: string; created_at: string; status: string; persona: string } | undefined;
    if (!customer) throw new BankError("DEF_NOT_FOUND");
    const history = this.bank.db.prepare(`SELECT COUNT(*) n,COALESCE(SUM(p.amount),0) total_cents
      FROM pix_transfers p JOIN accounts a ON a.id=p.from_account
      WHERE a.customer_id=? AND p.status='settled' AND p.settled_at>=?`)
      .get(customer.id, new Date(this.bank.now().getTime() - 30 * 86_400_000).toISOString()) as { n: number; total_cents: number };
    const ageDays = Math.max(0, Math.floor((this.bank.now().getTime() - Date.parse(customer.created_at)) / 86_400_000));
    return { customer_id: customer.id, age_days: ageDays, status: customer.status,
      historical_pattern_digest: { pix_out_30d: history.n, pix_out_cents_30d: history.total_cents },
      honesty_signals: { established: ageDays >= 30, regular_activity: history.n >= 3 },
      note: "Signals are not ground truth" };
  }
}
