import { DatabaseSync } from "node:sqlite";
import { existsSync } from "node:fs";
import { newId } from "./id.ts";
import { BehaviorProfiles } from "./behavior-profiles.ts";
import { SocTriage } from "./soc-triage.ts";
import { Bank } from "./bank.ts";
import { pixPolicyEvidence } from "./pix-policy-evidence.ts";
import { ScheduledPix } from "./scheduled-pix.ts";
import { AuthEngine } from "./auth.ts";
import { CardsEngine } from "./cards.ts";
import { LoansEngine } from "./loans.ts";
import { ProximityPix } from "./proximity-pix.ts";
import { FeatureRegistry } from "./features.ts";
import { DataSharing } from "./data-sharing.ts";
import { DynamicLimits } from "./dynamic-limits.ts";
import { AccountService } from "./accounts.ts";
import { evaluateRiskRules, loadRules } from "./risk/engine.ts";
import { AREAS, type Area } from "../../../packages/contracts/src/index.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { CrossBookReport } from "../../ecosystem/src/verifier-client.ts";
import type { SpiMessage } from "./ecosystem/spi.ts";

export type Severity = "low" | "medium" | "high" | "critical";
export interface SeparatedSentinelSources {
  crossBook: CrossBookReport;
  activeCautelar: { account_id: string; holds: number; blocked_cents: number }[];
}
export interface Rule { id: string; area: Area; severity: Severity;
  version: number; owner: string; }
const RULE_OWNERS: Record<Area, string> = {
  auth: "identity_oncall", accounts: "identity_oncall", pix: "payments_oncall",
  cards: "cards_oncall", loans: "credit_oncall", api_gateway: "platform_oncall",
  ledger: "finance_oncall",
};
const RULE_DEFINITIONS: readonly (Pick<Rule, "id" | "area" | "severity"> &
  Partial<Pick<Rule, "version" | "owner">>)[] = [
  { id: "S-AUTH-01", area: "auth", severity: "medium" },
  { id: "S-AUTH-02", area: "auth", severity: "high" },
  { id: "S-AUTH-03", area: "auth", severity: "high" },
  { id: "S-AUTH-04", area: "auth", severity: "medium" },
  { id: "S-AUTH-05", area: "auth", severity: "high" },
  { id: "S-AUTH-06", area: "auth", severity: "high" },
  { id: "S-AUTH-07", area: "auth", severity: "critical" },
  { id: "S-AUTH-08", area: "auth", severity: "critical" },
  { id: "S-AUTH-09", area: "auth", severity: "medium" },
  { id: "S-AUTH-10", area: "auth", severity: "high" },
  { id: "S-AUTH-11", area: "auth", severity: "medium" },
  { id: "S-AUTH-12", area: "auth", severity: "high" },
  { id: "S-AUTH-13", area: "auth", severity: "high" },
  { id: "S-AUTH-14", area: "auth", severity: "medium" },
  { id: "S-AUTH-15", area: "auth", severity: "medium" },
  { id: "S-AUTH-16", area: "auth", severity: "medium" },
  { id: "S-ACC-01", area: "accounts", severity: "high" },
  { id: "S-ACC-02", area: "accounts", severity: "high" },
  { id: "S-ACC-03", area: "accounts", severity: "high" },
  { id: "S-ACC-04", area: "accounts", severity: "medium" },
  { id: "S-PIX-01", area: "pix", severity: "critical" },
  { id: "S-PIX-02", area: "pix", severity: "high" },
  { id: "S-PIX-03", area: "pix", severity: "high" },
  { id: "S-PIX-04", area: "pix", severity: "critical" },
  { id: "S-PIX-05", area: "pix", severity: "medium" },
  { id: "S-PIX-06", area: "pix", severity: "high" },
  { id: "S-PIX-07", area: "pix", severity: "high" },
  { id: "S-PIX-08", area: "pix", severity: "high" },
  { id: "S-PIX-09", area: "pix", severity: "critical" },
  { id: "S-PIX-10", area: "pix", severity: "critical" },
  { id: "S-PIX-11", area: "pix", severity: "critical" },
  { id: "S-PIX-12", area: "pix", severity: "critical" },
  { id: "S-PIX-13", area: "pix", severity: "low" },
  { id: "S-PIX-14", area: "pix", severity: "high" },
  { id: "S-PIX-15", area: "pix", severity: "medium" },
  { id: "S-PIX-16", area: "pix", severity: "high" },
  { id: "S-PIX-17", area: "pix", severity: "high" },
  { id: "S-PIX-18", area: "pix", severity: "high" },
  { id: "S-PIX-19", area: "pix", severity: "high" },
  { id: "S-PIX-20", area: "pix", severity: "medium" },
  { id: "S-PIX-21", area: "pix", severity: "medium" },
  { id: "S-PIX-22", area: "pix", severity: "medium" },
  { id: "S-PIX-23", area: "pix", severity: "medium" },
  { id: "S-PIX-24", area: "pix", severity: "high" },
  { id: "S-PIX-25", area: "pix", severity: "medium" },
  { id: "S-PIX-26", area: "pix", severity: "medium" },
  { id: "S-PIX-27", area: "pix", severity: "high" },
  { id: "S-PIX-28", area: "pix", severity: "medium" },
  { id: "S-PIX-29", area: "pix", severity: "high" },
  { id: "S-PIX-30", area: "pix", severity: "medium" },
  { id: "S-PIX-31", area: "pix", severity: "medium" },
  { id: "S-PIX-32", area: "pix", severity: "high" },
  { id: "S-PIX-33", area: "pix", severity: "high" },
  { id: "S-PIX-34", area: "pix", severity: "medium" },
  { id: "S-PIX-35", area: "pix", severity: "high" },
  { id: "S-PIX-36", area: "pix", severity: "high" },
  { id: "S-PIX-37", area: "pix", severity: "high" },
  { id: "S-PIX-38", area: "pix", severity: "high" },
  { id: "S-PIX-39", area: "pix", severity: "medium" },
  { id: "S-PIX-40", area: "pix", severity: "medium" },
  { id: "S-PIX-41", area: "pix", severity: "high" },
  { id: "S-PIX-42", area: "pix", severity: "medium" },
  { id: "S-PIX-43", area: "pix", severity: "medium" },
  { id: "S-CARD-01", area: "cards", severity: "medium" },
  { id: "S-CARD-02", area: "cards", severity: "high" },
  { id: "S-CARD-03", area: "cards", severity: "high" },
  { id: "S-CARD-04", area: "cards", severity: "high" },
  { id: "S-CARD-05", area: "cards", severity: "high" },
  { id: "S-CARD-06", area: "cards", severity: "high" },
  { id: "S-CARD-07", area: "cards", severity: "critical" },
  { id: "S-CARD-08", area: "cards", severity: "high" },
  { id: "S-CARD-09", area: "cards", severity: "high" },
  { id: "S-CARD-10", area: "cards", severity: "medium" },
  { id: "S-CARD-11", area: "cards", severity: "medium" },
  { id: "S-CARD-12", area: "cards", severity: "high" },
  { id: "S-CARD-13", area: "cards", severity: "high" },
  { id: "S-LOAN-01", area: "loans", severity: "high" },
  { id: "S-LOAN-02", area: "loans", severity: "high" },
  { id: "S-LOAN-03", area: "loans", severity: "medium" },
  { id: "S-LOAN-04", area: "loans", severity: "medium" },
  { id: "S-GW-01", area: "api_gateway", severity: "medium" },
  { id: "S-GW-02", area: "api_gateway", severity: "critical" },
  { id: "S-GW-03", area: "api_gateway", severity: "high" },
  { id: "S-GW-04", area: "api_gateway", severity: "low" },
  { id: "S-GW-05", area: "api_gateway", severity: "high" },
  { id: "S-GW-06", area: "api_gateway", severity: "critical" },
  { id: "S-GW-07", area: "api_gateway", severity: "critical" },
  { id: "S-GW-08", area: "api_gateway", severity: "critical" },
  { id: "S-GW-09", area: "api_gateway", severity: "high" },
  { id: "S-GW-10", area: "api_gateway", severity: "critical" },
  { id: "S-GW-11", area: "api_gateway", severity: "medium" },
  { id: "S-GW-12", area: "api_gateway", severity: "high" },
  { id: "S-GW-13", area: "api_gateway", severity: "critical" },
  { id: "S-GW-14", area: "api_gateway", severity: "high" },
  { id: "S-GW-15", area: "api_gateway", severity: "high" },
  { id: "S-GW-16", area: "api_gateway", severity: "high" },
  { id: "S-GW-17", area: "api_gateway", severity: "critical" },
  { id: "S-GW-18", area: "api_gateway", severity: "high" },
  { id: "S-GW-19", area: "api_gateway", severity: "critical" },
  { id: "S-LED-01", area: "ledger", severity: "critical" },
  { id: "S-LED-02", area: "ledger", severity: "critical" },
  { id: "S-LED-03", area: "ledger", severity: "high" },
  { id: "S-LED-04", area: "ledger", severity: "high" },
  { id: "S-LED-05", area: "ledger", severity: "critical" },
  { id: "S-LED-06", area: "ledger", severity: "medium" },
  { id: "S-LED-07", area: "ledger", severity: "high" },
  { id: "S-LED-08", area: "ledger", severity: "high" },
  { id: "S-LED-09", area: "ledger", severity: "medium" },
  { id: "S-LED-10", area: "ledger", severity: "critical" },
  { id: "S-LED-11", area: "ledger", severity: "high" },
  { id: "S-LED-12", area: "ledger", severity: "high" },
] as const;
export const RULES: readonly Rule[] = RULE_DEFINITIONS.map((rule) => ({
  ...rule, version: rule.version ?? 1, owner: rule.owner ?? RULE_OWNERS[rule.area],
}));
export const IMPLEMENTED_RULES = ["S-AUTH-01", "S-AUTH-02", "S-AUTH-03", "S-AUTH-04", "S-AUTH-05", "S-AUTH-06", "S-AUTH-07", "S-AUTH-08", "S-AUTH-09", "S-AUTH-10", "S-AUTH-11", "S-AUTH-12", "S-AUTH-13", "S-AUTH-14", "S-AUTH-15", "S-AUTH-16", "S-ACC-01", "S-ACC-02", "S-ACC-03", "S-ACC-04",
  "S-PIX-01", "S-PIX-02", "S-PIX-03", "S-PIX-04", "S-PIX-05", "S-PIX-06", "S-PIX-07", "S-PIX-08", "S-PIX-09", "S-PIX-10", "S-PIX-11", "S-PIX-12", "S-PIX-13", "S-PIX-14", "S-PIX-15", "S-PIX-16", "S-PIX-17", "S-PIX-18", "S-PIX-19", "S-PIX-20", "S-PIX-21", "S-PIX-22", "S-PIX-23", "S-PIX-24", "S-PIX-25", "S-PIX-26", "S-PIX-27", "S-PIX-28", "S-PIX-29", "S-PIX-30", "S-PIX-31", "S-PIX-32", "S-PIX-33", "S-PIX-34", "S-PIX-35", "S-PIX-36", "S-PIX-37", "S-PIX-38", "S-PIX-39", "S-PIX-40", "S-PIX-41", "S-PIX-42", "S-PIX-43", "S-CARD-02", "S-CARD-03",
  "S-CARD-01", "S-CARD-04", "S-CARD-05", "S-CARD-06", "S-CARD-07", "S-CARD-08", "S-CARD-09", "S-CARD-10", "S-CARD-11", "S-CARD-12", "S-CARD-13", "S-LOAN-01", "S-LOAN-02", "S-LOAN-03", "S-LOAN-04", "S-GW-01", "S-GW-02", "S-GW-03", "S-GW-04", "S-GW-05", "S-GW-06", "S-GW-07", "S-GW-08", "S-GW-09", "S-GW-10", "S-GW-11", "S-GW-12", "S-GW-13", "S-GW-14", "S-GW-15", "S-GW-16", "S-GW-17", "S-GW-18", "S-GW-19", "S-LED-01", "S-LED-02", "S-LED-03", "S-LED-04", "S-LED-05", "S-LED-06", "S-LED-07", "S-LED-08", "S-LED-09", "S-LED-10", "S-LED-11", "S-LED-12"] as const;
type MonitoredProducer = "auth" | "cards" | "pix" | "spi" | "dict" | "ledger";
const PRODUCER_HEALTH_RULES: Record<MonitoredProducer, string> = {
  auth: "S-AUTH-07", cards: "S-CARD-07", pix: "S-PIX-10", spi: "S-PIX-11",
  dict: "S-PIX-12", ledger: "S-LED-05",
};
const PRODUCER_HEALTH_SUMMARIES: Record<MonitoredProducer, string> = {
  auth: "Fonte de autenticação sem heartbeat", cards: "Fonte de cartões sem heartbeat",
  pix: "Fonte de Pix sem heartbeat", spi: "Fonte de SPI sem heartbeat",
  dict: "Fonte de DICT sem heartbeat", ledger: "Fonte de ledger sem heartbeat",
};
interface Signal { ruleId: string; entity: string; observed: Record<string, number | string>; windowS: number; }
export interface SentinelAlert { alert_id: string; rule_id: string; area: Area; severity: Severity;
  entity: string; observed: Record<string, number | string>; window_s: number;
  first_seen: string; last_seen: string; count: number; evidence_ref: string; }
export interface SentinelIncident { id: string; entity_key: string; area: Area;
  severity: Severity; state: string; alert_count: number; opened_at: string; last_seen_at: string; }
export interface SentinelSummary { state: "ok" | "alerting"; checks_total: number; alerts_24h: number; }
export class SentinelEngine {
  readonly bank: Bank;
  readonly events: EventStore | undefined;
  readonly triage: SocTriage;
  private readonly behavior: BehaviorProfiles;
  private readonly sourceHealthPath: string | undefined;
  private lastLedgerRowid: number;
  private lastPixRowid: number;
  private bootstrapPixSince: string | undefined;
  private lastFullReconcileMs: number;
  private lastIntegrity: ReturnType<Bank["reconcile"]>;
  private lastHashOk = true;
  private lastTelemetryHashOk: boolean;
  private lastTelemetryVerificationMs: number;
  private ledgerAnchorMismatch = false;
  private gatewayHealthStartedMs: number | undefined;
  private riskHealthStartedMs: number | undefined;
  private readonly producerHealthStartedMs = new Map<MonitoredProducer, number>();
  constructor(bank: Bank, events?: EventStore, sourceHealthPath?: string) {
    this.bank = bank; this.events = events; this.sourceHealthPath = sourceHealthPath;
    new AuthEngine(bank); new CardsEngine(bank); new LoansEngine(bank);
    const features = new FeatureRegistry(bank);
    new ScheduledPix(bank, features);
    new ProximityPix(bank, features);
    new DataSharing(bank, features);
    new DynamicLimits(bank, features);
    new AccountService(bank);
    bank.db.exec(`CREATE TABLE IF NOT EXISTS sentinel_alerts (
      id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, entity TEXT NOT NULL,
      observed_json TEXT NOT NULL, window_s INTEGER NOT NULL,
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, count INTEGER NOT NULL,
      last_emitted TEXT NOT NULL, UNIQUE(rule_id,entity)
    );
    CREATE TABLE IF NOT EXISTS sentinel_state (
      area TEXT PRIMARY KEY, last_tick_at TEXT NOT NULL, rules_loaded_version TEXT NOT NULL,
      window_counters_summary TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_incidents (
      id TEXT PRIMARY KEY, entity_key TEXT NOT NULL, area TEXT NOT NULL, severity TEXT NOT NULL,
      state TEXT NOT NULL, alert_count INTEGER NOT NULL, opened_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_pix_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_rowid INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_redacted_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_redacted_outbox (
      event_id INTEGER PRIMARY KEY, alert_json TEXT NOT NULL, incident_id TEXT,
      incident_entity TEXT, published_at TEXT
    );
    CREATE TABLE IF NOT EXISTS sentinel_agent_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_seq INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_refusal_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_seq INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_thread_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_seq INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_agent_outbox (
      event_seq INTEGER PRIMARY KEY, alert_id TEXT NOT NULL, incident_id TEXT NOT NULL,
      observed_at TEXT NOT NULL, published_at TEXT, source_round_id TEXT
    );
    CREATE TABLE IF NOT EXISTS sentinel_agent_publication_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_seq INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_source_health_imports (
      source_alert_id INTEGER PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES sentinel_alerts(id),
      incident_id TEXT, observed_at TEXT NOT NULL, code TEXT NOT NULL,
      observed_json TEXT NOT NULL, published_at TEXT
    );
    CREATE TABLE IF NOT EXISTS sentinel_source_health_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_stream_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_spi_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_id INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sentinel_spi_event_cursor ON telemetry_events(id)
      WHERE source='spi' AND action IN ('pacs.008','pacs.002');
    CREATE TABLE IF NOT EXISTS sentinel_stream_identity (
      customer_id TEXT PRIMARY KEY, bound_event_id INTEGER NOT NULL,
      bound_twin_ts TEXT NOT NULL, change_event_id INTEGER, change_twin_ts TEXT
    );
    CREATE TABLE IF NOT EXISTS sentinel_stream_outbox (
      event_id INTEGER NOT NULL, rule_id TEXT NOT NULL,
      alert_id TEXT NOT NULL REFERENCES sentinel_alerts(id),
      incident_id TEXT, observed_json TEXT, twin_ts TEXT, published_at TEXT,
      PRIMARY KEY(event_id,rule_id)
    );
    CREATE TABLE IF NOT EXISTS sentinel_quota_outbox (
      history_id INTEGER PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES sentinel_alerts(id),
      observed_at TEXT NOT NULL, published_at TEXT
    );
    CREATE TABLE IF NOT EXISTS sentinel_quota_publication_cursor (
      id INTEGER PRIMARY KEY CHECK(id=1), last_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sentinel_med_review_outbox (
      case_id TEXT PRIMARY KEY REFERENCES med_cases(id),
      alert_id TEXT NOT NULL REFERENCES sentinel_alerts(id),
      observed_at TEXT NOT NULL, published_at TEXT
    );
    CREATE TABLE IF NOT EXISTS sentinel_med_initiation_outbox (
      case_id TEXT PRIMARY KEY REFERENCES med_cases(id),
      alert_id TEXT NOT NULL REFERENCES sentinel_alerts(id),
      observed_at TEXT NOT NULL, published_at TEXT
    );
    CREATE TABLE IF NOT EXISTS sentinel_med_psp_late_outbox (
      case_id TEXT NOT NULL REFERENCES med_cases(id), ispb TEXT NOT NULL,
      alert_id TEXT NOT NULL REFERENCES sentinel_alerts(id),
      observed_at TEXT NOT NULL, published_at TEXT,
      PRIMARY KEY(case_id,ispb)
    );
    CREATE INDEX IF NOT EXISTS sentinel_risk_heartbeat
      ON telemetry_events(id DESC,ts) WHERE source='risk' AND category='health' AND action='heartbeat';
    CREATE INDEX IF NOT EXISTS sentinel_producer_heartbeat
      ON telemetry_events(source,id DESC,ts) WHERE category='health' AND action='heartbeat';
    CREATE INDEX IF NOT EXISTS sentinel_pix_actor_device_time
      ON pix_transfers(actor,initiating_device_id,initiated_at);
    CREATE TABLE IF NOT EXISTS sentinel_incident_transfer_evidence (
      incident_id TEXT NOT NULL REFERENCES sentinel_incidents(id),
      transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
      evidence_ref TEXT NOT NULL, linked_at TEXT NOT NULL,
      PRIMARY KEY(incident_id,transfer_id,evidence_ref)
    );
    CREATE TABLE IF NOT EXISTS sentinel_cross_book_pending_items (
      kind TEXT NOT NULL, command_id TEXT NOT NULL,
      first_seen_real_ms INTEGER NOT NULL, PRIMARY KEY(kind,command_id)
    );
    CREATE TABLE IF NOT EXISTS sentinel_automatic_pix_pending (
      charge_id TEXT PRIMARY KEY, scheduled_at TEXT NOT NULL,
      first_seen_real_ms INTEGER NOT NULL
    );`);
    bank.transaction(() => {
      const outboxColumns = bank.db.prepare("PRAGMA table_info(sentinel_agent_outbox)")
        .all() as { name: string }[];
      if (!outboxColumns.some((column) => column.name === "source_round_id"))
        bank.db.exec("ALTER TABLE sentinel_agent_outbox ADD COLUMN source_round_id TEXT");
      const streamColumns = bank.db.prepare("PRAGMA table_info(sentinel_stream_outbox)")
        .all() as { name: string }[];
      if (!streamColumns.some((column) => column.name === "observed_json"))
        bank.db.exec("ALTER TABLE sentinel_stream_outbox ADD COLUMN observed_json TEXT");
      if (!streamColumns.some((column) => column.name === "twin_ts"))
        bank.db.exec("ALTER TABLE sentinel_stream_outbox ADD COLUMN twin_ts TEXT");
      bank.db.exec(`UPDATE sentinel_stream_outbox SET
        observed_json=COALESCE(observed_json,(SELECT observed_json FROM sentinel_alerts
          WHERE id=sentinel_stream_outbox.alert_id)),
        twin_ts=COALESCE(twin_ts,(SELECT last_seen FROM sentinel_alerts
          WHERE id=sentinel_stream_outbox.alert_id))
        WHERE observed_json IS NULL OR twin_ts IS NULL`);
      if (!streamColumns.some((column) => column.name === "rule_id")) {
        bank.db.exec(`CREATE TABLE sentinel_stream_outbox_v2 (
          event_id INTEGER NOT NULL, rule_id TEXT NOT NULL,
          alert_id TEXT NOT NULL REFERENCES sentinel_alerts(id),
          incident_id TEXT, observed_json TEXT, twin_ts TEXT, published_at TEXT,
          PRIMARY KEY(event_id,rule_id)
        );
        INSERT INTO sentinel_stream_outbox_v2
          SELECT event_id,'S-PIX-14',alert_id,incident_id,observed_json,twin_ts,published_at
          FROM sentinel_stream_outbox;
        DROP TABLE sentinel_stream_outbox;
        ALTER TABLE sentinel_stream_outbox_v2 RENAME TO sentinel_stream_outbox;`);
      }
    });
    this.behavior = new BehaviorProfiles(bank.db);
    this.triage = new SocTriage(bank.db, bank.realNow, RULES, events);
    bank.db.exec(`INSERT OR IGNORE INTO sentinel_stream_cursor
      SELECT 1,COALESCE(MAX(id),0) FROM telemetry_events`);
    if (bank.isSeparatedEcosystem) bank.db.exec(`INSERT OR IGNORE INTO sentinel_spi_cursor
      SELECT 1,last_id FROM sentinel_stream_cursor WHERE id=1`);
    const pixCursor = bank.db.prepare("SELECT last_rowid FROM sentinel_pix_cursor WHERE id=1")
      .get() as { last_rowid: number } | undefined;
    this.lastPixRowid = pixCursor?.last_rowid ?? (bank.db.prepare("SELECT COALESCE(MAX(rowid),0) n FROM pix_transfers")
      .get() as { n: number }).n;
    if (!pixCursor) this.bootstrapPixSince = new Date(bank.now().getTime() - 600_000).toISOString();
    this.lastLedgerRowid = (bank.db.prepare("SELECT COALESCE(MAX(rowid),0) n FROM ledger_entries")
      .get() as { n: number }).n;
    this.lastIntegrity = bank.reconcile();
    this.lastHashOk = bank.verifyLedgerChain();
    this.lastFullReconcileMs = bank.realNow().getTime();
    this.lastTelemetryHashOk = bank.telemetry.verifyChain();
    this.lastTelemetryVerificationMs = this.lastFullReconcileMs;
  }
  // Opt in only when the gateway heartbeat producer is running. Wall time is
  // independent of simulation speed; an external monitor is needed for process death.
  monitorGatewayHealth(): void { this.gatewayHealthStartedMs = this.bank.realNow().getTime(); }
  monitorRiskHealth(): void { this.riskHealthStartedMs = this.bank.realNow().getTime(); }
  monitorProducerHealth(source: MonitoredProducer): void {
    this.producerHealthStartedMs.set(source, this.bank.realNow().getTime());
  }
  private incrementalIntegrity(): ReturnType<Bank["reconcile"]> {
    const nowMs = this.bank.realNow().getTime();
    if (nowMs - this.lastFullReconcileMs >= 600_000 || nowMs < this.lastFullReconcileMs) {
      this.lastIntegrity = this.bank.reconcile();
      this.lastHashOk = this.bank.verifyLedgerChain();
      this.lastFullReconcileMs = nowMs;
      this.lastLedgerRowid = (this.bank.db.prepare("SELECT COALESCE(MAX(rowid),0) n FROM ledger_entries")
        .get() as { n: number }).n;
      return this.lastIntegrity;
    }
    const rows = this.bank.db.prepare(`SELECT rowid,tx_id,account_id FROM ledger_entries
      WHERE rowid>? ORDER BY rowid`).all(this.lastLedgerRowid) as
      { rowid: number; tx_id: string; account_id: string }[];
    if (!rows.length) return this.refreshSmallIntegrity();
    this.lastLedgerRowid = rows.at(-1)!.rowid;
    const transactions = new Set(rows.map((row) => row.tx_id));
    const accounts = new Set(rows.map((row) => row.account_id));
    let unbalancedTx = 0;
    let accountDrift = 0;
    for (const txId of transactions) {
      const total = this.bank.db.prepare("SELECT COALESCE(SUM(amount),0) n FROM ledger_entries WHERE tx_id=?")
        .get(txId) as { n: number };
      if (total.n !== 0) unbalancedTx++;
    }
    for (const accountId of accounts) {
      const amounts = this.bank.db.prepare(`SELECT a.balance_cached cached,COALESCE(SUM(l.amount),0) total
        FROM accounts a LEFT JOIN ledger_entries l ON l.account_id=a.id WHERE a.id=?`)
        .get(accountId) as { cached: number; total: number } | undefined;
      if (!amounts || amounts.cached !== amounts.total) accountDrift++;
    }
    if (unbalancedTx || accountDrift) this.lastIntegrity = {
      ...this.lastIntegrity, ok: false, unbalancedTx, accountDrift };
    return this.refreshSmallIntegrity();
  }
  private refreshSmallIntegrity(): ReturnType<Bank["reconcile"]> {
    const belowFloor = (this.bank.db.prepare(`SELECT COUNT(*) n FROM accounts WHERE kind<>'system'
      AND balance_cached < -overdraft_limit`).get() as { n: number }).n;
    const roundingDrift = (this.bank.db.prepare(`SELECT ABS(balance_cached) n FROM accounts
      WHERE kind='system' AND system_role='rounding'`).get() as { n: number } | undefined)?.n ?? 0;
    const medDrift = (this.bank.db.prepare(`SELECT COUNT(*) n FROM med_cases m
      JOIN pix_transfers p ON p.id=m.transfer_id LEFT JOIN
      (SELECT case_id,SUM(amount) total,COUNT(*) refunds FROM med_refunds GROUP BY case_id) r ON r.case_id=m.id
      LEFT JOIN (SELECT transfer_id,SUM(amount) total FROM pix_returns GROUP BY transfer_id) o
        ON o.transfer_id=p.id
      WHERE m.refunded_cents<>COALESCE(r.total,0) OR
      COALESCE(r.total,0)>COALESCE(m.claim_amount_cents,p.amount) OR
      COALESCE(m.claim_amount_cents,p.amount)+COALESCE(o.total,0)<>p.amount OR
      COALESCE(r.refunds,0)>1 OR
      (m.status='resolved' AND m.refunded_cents+m.unrecovered_cents<>
        COALESCE(m.claim_amount_cents,p.amount))`)
      .get() as { n: number }).n;
    this.lastIntegrity = { ...this.lastIntegrity, belowFloor, roundingDrift, medDrift,
      ok: this.lastIntegrity.unbalancedTx === 0 && this.lastIntegrity.accountDrift === 0 &&
        belowFloor === 0 && medDrift === 0 && roundingDrift < 500 };
    return this.lastIntegrity;
  }
  private incidentEntity(entity: string): string {
    if (entity.startsWith("cus_")) return entity;
    const account = this.bank.db.prepare("SELECT customer_id FROM accounts WHERE id=?")
      .get(entity) as { customer_id: string | null } | undefined;
    if (account?.customer_id) return account.customer_id;
    const card = this.bank.db.prepare("SELECT customer_id FROM cards WHERE id=?")
      .get(entity) as { customer_id: string } | undefined;
    if (card) return card.customer_id;
    const loan = this.bank.db.prepare("SELECT customer_id FROM loans WHERE id=?")
      .get(entity) as { customer_id: string } | undefined;
    if (loan) return loan.customer_id;
    const cardAuth = this.bank.db.prepare(`SELECT c.customer_id FROM card_authorizations a
      JOIN cards c ON c.id=a.card_id WHERE a.id=?`).get(entity) as { customer_id: string } | undefined;
    if (cardAuth) return cardAuth.customer_id;
    const med = this.bank.db.prepare("SELECT customer_id FROM med_cases WHERE id=?")
      .get(entity) as { customer_id: string } | undefined;
    return med?.customer_id ?? entity;
  }
  private openIncident(alert: SentinelAlert, publish = true): string | undefined {
    if (alert.severity === "low" || ["S-PIX-08", "S-PIX-09"].includes(alert.rule_id)) return;
    const entityKey = this.incidentEntity(alert.entity);
    const cutoff = new Date(Date.parse(alert.last_seen) - 10 * 60_000).toISOString();
    const prior = this.bank.db.prepare(`SELECT id,severity,alert_count FROM sentinel_incidents
      WHERE entity_key=? AND state<>'resolved' AND last_seen_at>=? ORDER BY last_seen_at DESC LIMIT 1`)
      .get(entityKey, cutoff) as { id: string; severity: Severity; alert_count: number } | undefined;
    const rank = { low: 0, medium: 1, high: 2, critical: 3 } as const;
    if (prior) {
      const severity = rank[alert.severity] > rank[prior.severity] ? alert.severity : prior.severity;
      this.bank.db.prepare("UPDATE sentinel_incidents SET severity=?,alert_count=alert_count+1,last_seen_at=? WHERE id=?")
        .run(severity, alert.last_seen, prior.id);
      this.linkIncidentTransfer(prior.id, alert);
      return;
    }
    const id = newId("incident", this.bank.now().getTime());
    this.bank.db.prepare("INSERT INTO sentinel_incidents VALUES (?,?,?,?,?,?,?,?)")
      .run(id, entityKey, alert.area, alert.severity, "open", 1, alert.last_seen, alert.last_seen);
    this.linkIncidentTransfer(id, alert);
    if (publish) this.events?.append({ round_id: null, ts: new Date().toISOString(), twin_ts: this.bank.now().toISOString(),
      type: "incident.opened", actor: { id: "sentinel-cluster", role: "sentinel" }, area: alert.area,
      incident_id: id, public_summary_pt: `Incidente em ${alert.area}`,
      public: { incident_id: id, severity: alert.severity, area: alert.area, alert_count: 1, source: "sentinel" },
      private: { entity_key: entityKey, alert_id: alert.alert_id } });
    return id;
  }
  private linkIncidentTransfer(incidentId: string, alert: SentinelAlert): void {
    const transferId = alert.rule_id === "S-PIX-03" &&
      typeof alert.observed.transfer_id === "string" ? alert.observed.transfer_id :
      alert.rule_id === "S-LED-12" &&
      (alert.observed.kind === "pix" || alert.observed.kind === "inbound") &&
      alert.observed.command_id === alert.entity ? alert.entity : undefined;
    if (!transferId) return;
    const transfer = this.bank.db.prepare("SELECT id FROM pix_transfers WHERE id=?")
      .get(transferId);
    if (!transfer) return;
    this.bank.db.prepare(`INSERT OR IGNORE INTO sentinel_incident_transfer_evidence
      VALUES (?,?,?,?)`).run(incidentId, transferId, alert.evidence_ref, alert.last_seen);
  }
  reportLedgerAnchorMismatch(): void { this.ledgerAnchorMismatch = true; }
  private missingHourlyLedgerProof(): Signal | undefined {
    if (!this.events || !this.bank.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='runtime_clock'`).get() ||
      !this.events.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
        AND name='hourly_ledger_proof_state'`).get()) return;
    const clock = this.bank.db.prepare(`SELECT real_start_ms,twin_start_ms,speed
      FROM runtime_clock WHERE id=1`).get() as
      { real_start_ms: number; twin_start_ms: number; speed: number } | undefined;
    const state = this.events.db.prepare(`SELECT first_hour FROM hourly_ledger_proof_state
      WHERE id=1`).get() as { first_hour: string } | undefined;
    if (!clock || !state) return;
    const hourMs = 3_600_000;
    const graceMs = 5 * 60_000;
    const twinMs = clock.twin_start_ms +
      (this.bank.realNow().getTime() - clock.real_start_ms) * clock.speed;
    let next = Date.parse(state.first_hour);
    if (!Number.isFinite(twinMs) || !Number.isFinite(next) ||
      next % hourMs !== 0 || twinMs < next) return;
    for (const row of this.events.db.prepare(`SELECT public_json FROM events
      WHERE type='ledger.hourly_proof' ORDER BY seq`).iterate() as
      Iterable<{ public_json: string }>) {
      let recorded: unknown;
      try { recorded = JSON.parse(row.public_json); }
      catch { break; }
      const hour = recorded && typeof recorded === "object" &&
        "hour_start" in recorded ? Date.parse(String(recorded.hour_start)) : NaN;
      if (hour === next) next += hourMs;
      else if (!Number.isFinite(hour) || hour > next) break;
    }
    const due = next + hourMs + graceMs;
    if (twinMs < due) return;
    return { ruleId: "S-LED-11", entity: "ledger_hourly_proof",
      observed: { missing_hour_start: new Date(next).toISOString(),
        due_at: new Date(due).toISOString(),
        overdue_seconds: Math.floor((twinMs - due) / 1_000) }, windowS: 0 };
  }
  private inconsistentPixRiskHolds(): Signal[] {
    // A promoted policy changes the replay basis; defer until a versioned replay exists.
    if (this.bank.db.prepare(`SELECT 1 FROM risk_rule_rollout_events
      WHERE area='pix' LIMIT 1`).get()) return [];
    const rules = loadRules("pix");
    const rows = this.bank.db.prepare(`SELECT h.id,d.score,d.features_json,d.reason_codes_json
      FROM risk_pix_holds h JOIN risk_decisions d ON d.id=h.risk_decision_id
      WHERE h.status='pending' AND h.expires_at>? AND d.area='pix'
        AND d.outcome='hold' ORDER BY h.created_at DESC LIMIT 100`)
      .all(this.bank.now().toISOString()) as
      { id: string; score: number; features_json: string; reason_codes_json: string }[];
    const signals: Signal[] = [];
    for (const row of rows) {
      try {
        const features = JSON.parse(row.features_json) as unknown;
        const reasons = JSON.parse(row.reason_codes_json) as unknown;
        if (!features || typeof features !== "object" || Array.isArray(features) ||
          !Object.values(features).every((value) => typeof value === "number" &&
            Number.isFinite(value))) continue;
        const expected = evaluateRiskRules(rules, features as Record<string, number>);
        if (expected.outcome !== "approve" || !Array.isArray(reasons) ||
          JSON.stringify(reasons) !== JSON.stringify(expected.reasonCodes) ||
          row.score < rules.thresholds.hold) continue;
        signals.push({ ruleId: "S-PIX-41", entity: row.id,
          observed: { hold_id: row.id, recorded_score: row.score,
            policy_score: expected.score, policy_outcome: expected.outcome }, windowS: 0 });
      } catch { /* Invalid risk evidence is ineligible for automatic repair. */ }
    }
    return signals;
  }
  private delayedAutomaticPix(): Signal[] {
    const { db } = this.bank;
    if (!db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='pix_automatic_charges'`).get()) return [];
    const now = this.bank.now().toISOString();
    const observedAt = this.bank.realNow().getTime();
    return this.bank.transaction(() => {
      db.prepare(`DELETE FROM sentinel_automatic_pix_pending AS watch
        WHERE NOT EXISTS (SELECT 1 FROM pix_automatic_charges c
          WHERE c.id=watch.charge_id AND c.status='pending'
            AND COALESCE(c.next_attempt_at,c.due_at)=watch.scheduled_at
            AND watch.scheduled_at<=?)`).run(now);
      db.prepare(`INSERT OR IGNORE INTO sentinel_automatic_pix_pending
        (charge_id,scheduled_at,first_seen_real_ms)
        SELECT id,COALESCE(next_attempt_at,due_at),? FROM pix_automatic_charges
        WHERE status='pending' AND COALESCE(next_attempt_at,due_at)<=?`)
        .run(observedAt, now);
      const due = db.prepare(`SELECT charge_id,scheduled_at,first_seen_real_ms
        FROM sentinel_automatic_pix_pending WHERE first_seen_real_ms<?
        ORDER BY first_seen_real_ms,charge_id`).all(observedAt - 30_000) as
        { charge_id: string; scheduled_at: string; first_seen_real_ms: number }[];
      return due.map((row) => ({
        ruleId: "S-PIX-43", entity: row.charge_id, windowS: 30, observed: {
          kind: "automatic_payment_queue", charge_id: row.charge_id,
          scheduled_at: row.scheduled_at,
          age_ms: observedAt - row.first_seen_real_ms,
        },
      }));
    });
  }
  private candidates(sources?: SeparatedSentinelSources): Signal[] {
    const db = this.bank.db;
    const now = this.bank.now();
    const since = (ms: number): string => new Date(now.getTime() - ms).toISOString();
    const found: Signal[] = [];
    const add = (ruleId: string, entity: string, observed: Record<string, number | string>, windowS = 0): void => {
      found.push({ ruleId, entity, observed, windowS });
    };
    const missingHourlyProof = this.missingHourlyLedgerProof();
    if (missingHourlyProof) found.push(missingHourlyProof);
    found.push(...this.inconsistentPixRiskHolds());
    if (this.events) for (const row of db.prepare(`SELECT id,trace_id,action,outcome,
      counterparty FROM telemetry_events WHERE source='agent' AND twin_ts>=?
      ORDER BY id DESC LIMIT 100`).all(since(600_000)) as
      { id: number; trace_id: string; action: string; outcome: string;
        counterparty: string | null }[]) {
      const source = this.events.db.prepare(`SELECT type,actor_id,public_json
        FROM events WHERE id=?`).get(row.trace_id) as
        { type: string; actor_id: string; public_json: string } | undefined;
      const publicData = source ? JSON.parse(source.public_json) as
        { ok?: boolean; outcome?: string } : undefined;
      const failed = source?.type === "integrity.violation" ||
        publicData?.ok === false ||
        (source?.type === "agent.finished" && publicData?.outcome !== "ok");
      if (!source || source.type !== row.action || source.actor_id !== row.counterparty ||
        row.outcome !== (failed ? "failure" : "success"))
        add("S-GW-17", `agent_event:${row.id}`, { telemetry_id: row.id,
          mirror_mismatch: 1 }, 600);
    }
    for (const row of db.prepare(`SELECT id,rule_id,category,outcome
      FROM telemetry_events WHERE source='siem' AND action='alert'
        AND twin_ts>=? ORDER BY id DESC LIMIT 100`).all(since(600_000)) as
      { id: number; rule_id: string | null; category: string; outcome: string }[]) {
      const rule = RULES.find((item) => item.id === row.rule_id);
      if (!rule || row.category !== rule.area || row.outcome !== "failure" ||
        !db.prepare(`SELECT 1 FROM sentinel_alerts WHERE rule_id=? LIMIT 1`)
          .get(row.rule_id))
        add("S-GW-18", `siem_event:${row.id}`, { telemetry_id: row.id,
          alert_mismatch: 1 }, 600);
    }
    for (const row of db.prepare(`SELECT t.id FROM telemetry_events t
      WHERE t.source='risk' AND t.action='decision' AND t.twin_ts>=?
        AND NOT EXISTS (SELECT 1 FROM risk_decisions d
          WHERE d.trace_id=t.trace_id AND d.area=t.category
            AND d.customer_id=t.user_id AND d.account_id=t.account_id
            AND d.entity_id=t.counterparty AND d.amount_cents=t.amount_cents
            AND d.score=t.risk_score AND d.reason_codes_json=t.reason_codes_json
            AND ((d.outcome='approve' AND t.outcome='success') OR
              (d.outcome<>'approve' AND t.outcome='failure')))
      LIMIT 100`).all(since(600_000)) as { id: number }[])
      add("S-GW-15", `risk_event:${row.id}`, { telemetry_id: row.id,
        decision_mismatch: 1 }, 600);
    for (const row of db.prepare(`SELECT t.id FROM telemetry_events t
      WHERE t.source='risk' AND t.action='rule_match' AND t.twin_ts>=?
        AND NOT EXISTS (SELECT 1 FROM risk_decisions d
          WHERE d.trace_id=t.trace_id AND d.area=t.category
            AND d.customer_id=t.user_id AND d.account_id=t.account_id
            AND d.entity_id=t.counterparty AND d.amount_cents=t.amount_cents
            AND d.score=t.risk_score AND d.outcome<>'approve'
            AND t.rule_id IS NOT NULL AND json_valid(t.reason_codes_json)
            AND json_array_length(t.reason_codes_json)=1
            AND EXISTS (SELECT 1 FROM json_each(d.reason_codes_json)
              WHERE value=json_extract(t.reason_codes_json,'$[0]')))
      LIMIT 100`).all(since(600_000)) as { id: number }[])
      add("S-GW-16", `risk_match:${row.id}`, { telemetry_id: row.id,
        rule_match_mismatch: 1 }, 600);
    for (const row of db.prepare(`SELECT peer_ip ip,COUNT(*) count FROM access_log
      WHERE kind='login_failed' AND ts>=? GROUP BY peer_ip HAVING count>20`).all(since(300_000)) as { ip: string; count: number }[])
      add("S-AUTH-01", row.ip, { failures: row.count }, 300);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM access_log
      WHERE kind='login_challenge' AND ts>=? AND customer_id IS NOT NULL
      GROUP BY customer_id HAVING count>=6`).all(since(300_000)) as
      { customer_id: string; count: number }[])
      add("S-AUTH-09", row.customer_id, { challenges: row.count }, 300);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM access_log
      WHERE kind='password_changed' AND ts>=? AND customer_id IS NOT NULL
      GROUP BY customer_id HAVING count>=3`).all(since(3_600_000)) as
      { customer_id: string; count: number }[])
      add("S-AUTH-10", row.customer_id, { password_changes: row.count }, 3_600);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM access_log
      WHERE kind='step_up' AND ts>=? AND customer_id IS NOT NULL
      GROUP BY customer_id HAVING count>=8`).all(since(300_000)) as
      { customer_id: string; count: number }[])
      add("S-AUTH-11", row.customer_id, { step_ups: row.count }, 300);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM access_log
      WHERE kind='pix_device_registered' AND ts>=? AND customer_id IS NOT NULL
      GROUP BY customer_id HAVING count>=4`).all(since(86_400_000)) as
      { customer_id: string; count: number }[])
      add("S-AUTH-12", row.customer_id, { registrations: row.count }, 86_400);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM customer_contact_changes
      WHERE changed_at>=? GROUP BY customer_id HAVING count>=3`)
      .all(since(86_400_000)) as { customer_id: string; count: number }[])
      add("S-AUTH-13", row.customer_id, { contact_changes: row.count }, 86_400);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM otp_attempts
      WHERE correct=0 AND ts>=? GROUP BY customer_id HAVING count>8`).all(since(600_000)) as { customer_id: string; count: number }[])
      add("S-AUTH-02", row.customer_id, { failures: row.count }, 600);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM access_log WHERE
      kind IN ('access_revoked_device','refresh_revoked_device') AND ts>=? GROUP BY customer_id`)
      .all(since(600_000)) as { customer_id: string; count: number }[])
      add("S-AUTH-03", row.customer_id, { uses: row.count }, 600);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM access_log WHERE
      kind='refresh_reuse_detected' AND ts>=? GROUP BY customer_id`)
      .all(since(86_400_000)) as { customer_id: string; count: number }[])
      add("S-AUTH-05", row.customer_id, { reused_tokens: row.count }, 86_400);
    for (const row of db.prepare(`SELECT l.customer_id,COUNT(DISTINCT p.id) transfers FROM access_log l
      JOIN auth_devices d ON d.id=substr(l.route,14) AND d.customer_id=l.customer_id
      JOIN pix_transfers p ON p.actor=l.customer_id AND p.initiating_device_id=d.id
        AND p.status IN ('settled','returned_partial','returned_full') AND p.initiated_at>=l.ts
      WHERE l.kind='step_up' AND l.ts>=?
        AND (julianday(d.first_seen_at) IS NULL OR julianday(d.bound_at) IS NULL
          OR max(julianday(d.first_seen_at),julianday(d.bound_at))>=julianday(?))
      AND (julianday(p.initiated_at)-julianday(l.ts))*1440<10
      GROUP BY l.customer_id`).all(since(600_000), since(600_000)) as
      { customer_id: string; transfers: number }[])
      add("S-AUTH-04", row.customer_id, { transfers: row.transfers }, 600);
    for (const row of db.prepare(`SELECT c.customer_id,COUNT(DISTINCT p.id) transfers
      FROM customer_contact_changes c
      JOIN auth_devices d ON d.id=c.device_id AND d.customer_id=c.customer_id
      JOIN pix_transfers p ON p.actor=c.customer_id AND p.initiating_device_id=d.id
        AND p.status IN ('settled','returned_partial','returned_full') AND p.initiated_at>=c.changed_at
      WHERE c.phone_replaced=1 AND c.changed_at>=?
        AND (julianday(d.first_seen_at) IS NULL OR julianday(d.bound_at) IS NULL
          OR max(julianday(d.first_seen_at),julianday(d.bound_at))>=julianday(?))
        AND (julianday(p.initiated_at)-julianday(c.changed_at))*1440 BETWEEN 0 AND 10
        AND NOT EXISTS (SELECT 1 FROM accounts destination
          WHERE destination.id=p.to_account AND destination.customer_id=c.customer_id)
        AND NOT EXISTS (SELECT 1 FROM pix_transfers prior
          JOIN accounts prior_source ON prior_source.id=prior.from_account
          WHERE prior_source.customer_id=c.customer_id AND prior.to_account=p.to_account
            AND prior.status IN ('settled','returned_partial','returned_full')
            AND prior.rowid<p.rowid
            AND prior.settled_at<=c.changed_at)
      GROUP BY c.customer_id`).all(since(600_000), since(86_400_000)) as
      { customer_id: string; transfers: number }[])
      add("S-AUTH-06", row.customer_id, { transfers: row.transfers }, 600);
    for (const row of db.prepare(`SELECT customer_id,COUNT(DISTINCT account_id) count FROM access_log
      WHERE kind='statement_foreign' AND status=200 AND ts>=? GROUP BY customer_id HAVING count>=3`)
      .all(since(300_000)) as { customer_id: string; count: number }[])
      add("S-ACC-01", row.customer_id, { foreign_accounts: row.count }, 300);
    for (const row of db.prepare(`SELECT failed.id,failed.customer_id,failed.account_id
      FROM access_log failed WHERE failed.kind='statement_own'
        AND failed.status=503 AND failed.customer_id IS NOT NULL
        AND failed.account_id IS NOT NULL AND failed.ts>=?
        AND failed.rowid=(SELECT MAX(latest.rowid) FROM access_log latest
          WHERE latest.kind='statement_own' AND latest.status=503
            AND latest.customer_id=failed.customer_id)
        AND NOT EXISTS (SELECT 1 FROM access_log recovered
          WHERE recovered.kind='statement_own' AND recovered.status=200
            AND recovered.customer_id=failed.customer_id
            AND recovered.account_id=failed.account_id
            AND recovered.rowid>failed.rowid)
      ORDER BY failed.rowid LIMIT 100`).all(since(300_000)) as
      { id: string; customer_id: string; account_id: string }[])
      add("S-ACC-04", row.customer_id,
        { failed_log_id: row.id, account_id: row.account_id }, 300);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM access_log
      WHERE kind='statement_own' AND status=200 AND ts>=? AND customer_id IS NOT NULL
      GROUP BY customer_id HAVING count>=40`)
      .all(since(300_000)) as { customer_id: string; count: number }[])
      add("S-GW-14", row.customer_id, { statement_reads: row.count }, 300);
    for (const row of db.prepare(`SELECT c.id customer_id,MAX(p.amount) amount FROM pix_transfers p
      JOIN accounts a ON a.id=p.from_account JOIN customers c ON c.id=a.customer_id
      WHERE c.kyc_tier=1 AND c.kyc_status='submitted' AND p.amount>100000 AND p.settled_at>=?
      GROUP BY c.id`).all(since(600_000)) as { customer_id: string; amount: number }[])
      add("S-ACC-02", row.customer_id, { amount_cents: row.amount }, 600);
    for (const row of db.prepare(`SELECT customer_id,extra_cents FROM dynamic_limits
      WHERE verified=0 AND extra_cents>0`)
      .all() as { customer_id: string; extra_cents: number }[])
      add("S-ACC-03", row.customer_id, { unverified_extra_cents: row.extra_cents });
    for (const row of db.prepare(`SELECT id,balance_cached,overdraft_limit FROM accounts WHERE kind<>'system'
      AND balance_cached < -overdraft_limit`).all() as { id: string; balance_cached: number; overdraft_limit: number }[]) {
      add("S-PIX-01", row.id, { balance_cents: row.balance_cached, floor_cents: -row.overdraft_limit });
      add("S-LED-01", row.id, { balance_cents: row.balance_cached, floor_cents: -row.overdraft_limit });
    }
    for (const row of db.prepare(`SELECT outp.from_account account_id,COUNT(DISTINCT inp.from_account) senders,
      SUM(DISTINCT outp.amount) outflow_cents,MAX(inp.amount) largest_inbound_cents
      FROM pix_transfers outp JOIN pix_transfers inp ON inp.to_account=outp.from_account
      JOIN accounts a ON a.id=outp.from_account WHERE outp.settled_at>=? AND inp.settled_at>=?
      AND a.opened_at>=? GROUP BY outp.from_account HAVING senders>=5`)
      .all(since(900_000), since(900_000), since(7 * 86_400_000)) as
      { account_id: string; senders: number; outflow_cents: number; largest_inbound_cents: number }[]) {
      const inbound = db.prepare(`SELECT COALESCE(SUM(amount),0) total FROM pix_transfers WHERE to_account=? AND settled_at>=?`)
        .get(row.account_id, since(900_000)) as { total: number };
      const outbound = db.prepare(`SELECT COALESCE(SUM(amount),0) total FROM pix_transfers WHERE from_account=? AND settled_at>=?`)
        .get(row.account_id, since(900_000)) as { total: number };
      if (outbound.total * 100 >= inbound.total * 80)
        add("S-PIX-02", row.account_id, { senders: row.senders, inbound_cents: inbound.total, outbound_cents: outbound.total }, 900);
    }
    for (const row of db.prepare(`SELECT p.id,p.from_account,p.amount,p.night_mode,
      e.job_id FROM pix_transfers p LEFT JOIN scheduled_pix_executions e ON e.transfer_id=p.id
      WHERE p.settled_at>=? AND (p.amount>100000 OR e.job_id IS NOT NULL
        OR p.rowid>? OR (p.settled_at>=? AND ?=1))`)
      .all(since(86_400_000), this.lastPixRowid, this.bootstrapPixSince ?? "", Number(Boolean(this.bootstrapPixSince))) as
      { id: string; from_account: string; amount: number;
        night_mode: number; job_id: string | null }[]) {
      const evidence = pixPolicyEvidence(this.bank, row.id);
      if (evidence?.nightExceeded || evidence?.dailyExceeded)
        add("S-PIX-03", row.from_account, { transfer_id: row.id,
          amount_cents: row.amount, recorded_night_mode: row.night_mode,
          ...(row.job_id ? { scheduled_id: row.job_id } : {}) }, 86_400);
    }
    for (const row of db.prepare(`SELECT m.id,COUNT(r.id) refunds,COALESCE(SUM(r.amount),0) refunded,p.amount
      FROM med_cases m JOIN pix_transfers p ON p.id=m.transfer_id
      LEFT JOIN med_refunds r ON r.case_id=m.id GROUP BY m.id HAVING refunds>1 OR refunded>p.amount`)
      .all() as { id: string; refunds: number; refunded: number; amount: number }[])
      add("S-PIX-04", row.id, { refunds: row.refunds, refunded_cents: row.refunded, transfer_cents: row.amount });
    for (const row of db.prepare(`SELECT session_hash,COUNT(*) count FROM pix_lookup_attempts WHERE ts>=?
      GROUP BY session_hash HAVING count>30`).all(since(60_000)) as { session_hash: string; count: number }[])
      add("S-PIX-05", row.session_hash, { lookups: row.count }, 60);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='dict' AND action='key_deregister' AND outcome='success'
        AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-18", row.user_id, { keys_deregistered: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='dict' AND action='claim_complete' AND outcome='success'
        AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-29", row.user_id, { claims_completed: row.count }, 86_400);
    for (const row of db.prepare(`SELECT session_id,COUNT(DISTINCT counterparty) count
      FROM telemetry_events WHERE source='dict' AND action='resolve_key'
        AND outcome='success' AND twin_ts>=? AND session_id IS NOT NULL
        AND counterparty IS NOT NULL
      GROUP BY session_id HAVING count>=10`).all(since(60_000)) as
      { session_id: string; count: number }[])
      add("S-PIX-30", row.session_id, { distinct_recipients: row.count }, 60);
    for (const row of db.prepare(`SELECT actor,COUNT(*) count FROM access_log
      WHERE kind='pix_key_fraud_flag' AND status=200 AND ts>=?
      GROUP BY actor HAVING count>=4`).all(since(600_000)) as
      { actor: string; count: number }[])
      add("S-PIX-19", row.actor, { fraud_marker_changes: row.count }, 600);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='mandate_granted'
        AND outcome='success' AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-20", row.user_id, { mandates_granted: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='offer_created'
        AND outcome='success' AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=5`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-21", row.user_id, { offers_created: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='mandate_revoked'
        AND outcome='success' AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-22", row.user_id, { mandates_revoked: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='offer_revoked'
        AND outcome='success' AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=5`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-23", row.user_id, { offers_revoked: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,counterparty,COUNT(*) count,
      SUM(amount_cents) amount_cents FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='charge_submitted'
        AND outcome='success' AND twin_ts>=? AND user_id IS NOT NULL
        AND counterparty IS NOT NULL
      GROUP BY user_id,counterparty HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; counterparty: string; count: number; amount_cents: number }[])
      add("S-PIX-24", row.user_id, { merchant_account: row.counterparty,
        charges_submitted: row.count, amount_cents: row.amount_cents }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='charge_retry_scheduled'
        AND outcome='failure' AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-25", row.user_id, { retries_scheduled: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='charge_failed'
        AND outcome='failure' AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-26", row.user_id, { charges_failed: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,counterparty,COUNT(*) count,
      SUM(amount_cents) amount_cents FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='charge_settled'
        AND outcome='success' AND twin_ts>=? AND user_id IS NOT NULL
        AND counterparty IS NOT NULL
      GROUP BY user_id,counterparty HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; counterparty: string; count: number; amount_cents: number }[])
      add("S-PIX-27", row.user_id, { merchant_account: row.counterparty,
        charges_settled: row.count, amount_cents: row.amount_cents }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='charge_cancelled'
        AND outcome='success' AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-28", row.user_id, { charges_cancelled: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='charge_post_due_retry'
        AND outcome='success' AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-31", row.user_id, { post_due_retries: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic'
        AND action='charge_reauthorization_required' AND outcome='failure'
        AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-32", row.user_id, { reauthorizations_required: row.count }, 86_400);
    for (const row of db.prepare(`SELECT user_id,COUNT(*) count FROM telemetry_events
      WHERE source='pix' AND category='automatic' AND action='charge_reauthorized'
        AND outcome='success' AND twin_ts>=? AND user_id IS NOT NULL
      GROUP BY user_id HAVING count>=3`).all(since(86_400_000)) as
      { user_id: string; count: number }[])
      add("S-PIX-33", row.user_id, { charges_reauthorized: row.count }, 86_400);
    for (const row of db.prepare(`SELECT account_id,COUNT(*) count,
      SUM(amount_cents) amount_cents FROM telemetry_events
      WHERE source='pix' AND action='return' AND outcome='success'
        AND twin_ts>=? AND account_id IS NOT NULL
      GROUP BY account_id HAVING count>=3`).all(since(86_400_000)) as
      { account_id: string; count: number; amount_cents: number }[])
      add("S-PIX-34", row.account_id, { returns: row.count,
        amount_cents: row.amount_cents }, 86_400);
    for (const row of db.prepare(`SELECT account_id,COUNT(*) count,
      SUM(amount_cents) amount_cents FROM telemetry_events
      WHERE source='pix' AND action='med_resolve' AND outcome='success'
        AND twin_ts>=? AND account_id IS NOT NULL
      GROUP BY account_id HAVING count>=3`).all(since(86_400_000)) as
      { account_id: string; count: number; amount_cents: number }[])
      add("S-PIX-35", row.account_id, { med_resolutions: row.count,
        claimed_cents: row.amount_cents }, 86_400);
    for (const row of db.prepare(`SELECT account_id,COUNT(*) count
      FROM telemetry_events WHERE source='pix' AND category='cautelar'
        AND action='release' AND outcome='success' AND twin_ts>=?
        AND account_id IS NOT NULL GROUP BY account_id HAVING count>=3`)
      .all(since(86_400_000)) as { account_id: string; count: number }[])
      add("S-PIX-38", row.account_id, { cautelar_releases: row.count }, 86_400);
    for (const row of db.prepare(`SELECT account_id,COUNT(*) count FROM access_log
      WHERE kind='mule_hold' AND status=409 AND ts>=? AND account_id IS NOT NULL
      GROUP BY account_id`).all(since(3_600_000)) as
      { account_id: string; count: number }[])
      add("S-PIX-36", row.account_id, { blocked_sweeps: row.count }, 3_600);
    for (const row of db.prepare(`SELECT token_id,COUNT(*) uses FROM proximity_uses
      GROUP BY token_id HAVING uses>1`).all() as { token_id: string; uses: number }[])
      add("S-PIX-06", row.token_id, { uses: row.uses });
    const activeCautelar = this.bank.isSeparatedEcosystem ?
      sources!.activeCautelar : db.prepare(`SELECT account_id,COUNT(*) holds,
        SUM(amount_cents) blocked_cents FROM psp_cautelar_holds
        WHERE status='active' AND expires_at>? GROUP BY account_id`)
        .all(now.toISOString()) as { account_id: string; holds: number; blocked_cents: number }[];
    for (const row of activeCautelar)
      add("S-PIX-07", row.account_id, { holds: row.holds,
        blocked_cents: row.blocked_cents }, 72 * 3_600);
    for (const row of db.prepare(`SELECT h.id hold_id,h.from_account,
      h.amount_cents blocked_cents,d.score risk_score
      FROM risk_pix_holds h JOIN risk_decisions d ON d.id=h.risk_decision_id
      WHERE h.status='pending' AND h.expires_at>?`)
      .all(now.toISOString()) as { from_account: string; hold_id: string;
        blocked_cents: number; risk_score: number }[])
      add("S-PIX-08", row.hold_id, { account_id: row.from_account,
        blocked_cents: row.blocked_cents, risk_score: row.risk_score }, 24 * 3_600);
    for (const row of db.prepare(`SELECT reviewer,COUNT(*) count,
      SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approvals
      FROM risk_pix_holds WHERE resolved_at>=? AND reviewer IS NOT NULL
      GROUP BY reviewer HAVING count>=5`)
      .all(since(600_000)) as { reviewer: string; count: number; approvals: number }[])
      add("S-PIX-17", row.reviewer, { decisions: row.count,
        approvals: row.approvals }, 600);
    for (const row of db.prepare(`SELECT reviewer,COUNT(*) count
      FROM risk_pix_review_acknowledgements WHERE acknowledged_at>=?
      GROUP BY reviewer HAVING count>=5`)
      .all(since(600_000)) as { reviewer: string; count: number }[])
      add("S-PIX-37", row.reviewer, { acknowledgements: row.count }, 600);
    for (const row of db.prepare(`SELECT id,expires_at FROM risk_pix_holds
      WHERE status='pending' AND expires_at>? AND expires_at<=?`)
      .all(now.toISOString(), new Date(now.getTime() + 3_600_000).toISOString()) as
      { id: string; expires_at: string }[])
      add("S-PIX-09", row.id, { deadline_at: row.expires_at,
        remaining_seconds: Math.max(0, Math.ceil((Date.parse(row.expires_at) - now.getTime()) / 1000)) },
      3_600);
    for (const row of db.prepare(`SELECT parent_id,SUM(limit_cents) allocated FROM cards
      WHERE parent_id IS NOT NULL AND status='active' GROUP BY parent_id`).all() as
      { parent_id: string; allocated: number }[]) {
      const parent = db.prepare("SELECT limit_cents FROM cards WHERE id=?").get(row.parent_id) as { limit_cents: number };
      if (row.allocated > parent.limit_cents) add("S-CARD-02", row.parent_id,
        { allocated_cents: row.allocated, parent_limit_cents: parent.limit_cents });
    }
    for (const row of db.prepare(`SELECT route card_id,COUNT(*) attempts FROM access_log
      WHERE kind='card_authorize_attempt' AND ts>=? GROUP BY route HAVING attempts>10`)
      .all(since(60_000)) as { card_id: string; attempts: number }[])
      add("S-CARD-01", row.card_id, { attempts: row.attempts }, 60);
    if (db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='card_issuer_state'`).get()) {
      const unavailable = db.prepare(`SELECT COUNT(r.id) declines FROM card_issuer_state s
        JOIN card_network_rejections r ON r.response_code='91'
          AND r.created_at>=s.changed_at
        WHERE s.id=1 AND s.available=0`).get() as { declines: number };
      if (unavailable.declines > 0)
        add("S-CARD-13", "card_issuer", { issuer_unavailable: 1,
          declined_authorizations: unavailable.declines }, 60);
    }
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count FROM access_log
      WHERE kind='card_updated' AND status=200 AND ts>=? AND customer_id IS NOT NULL
      GROUP BY customer_id HAVING count>=5`)
      .all(since(3_600_000)) as { customer_id: string; count: number }[])
      add("S-CARD-08", row.customer_id, { card_updates: row.count }, 3_600);
    for (const row of db.prepare(`SELECT card_token,counterparty,COUNT(*) count
      FROM telemetry_events response WHERE response.source='network'
        AND response.action='mti_0110' AND response.outcome='failure'
        AND response.twin_ts>=? AND response.card_token IS NOT NULL
        AND response.counterparty IS NOT NULL
        AND EXISTS (SELECT 1 FROM telemetry_events request
          WHERE request.trace_id=response.trace_id AND request.source='network'
            AND request.action='mti_0100' AND request.card_token=response.card_token)
        AND EXISTS (SELECT 1 FROM telemetry_events authorization
          WHERE authorization.trace_id=response.trace_id AND authorization.source='cards'
            AND authorization.action='authorize' AND authorization.outcome='failure'
            AND authorization.card_token=response.card_token)
      GROUP BY card_token,counterparty HAVING count>=5`).all(since(60_000)) as
      { card_token: string; counterparty: string; count: number }[])
      add("S-CARD-09", row.card_token, { merchant: row.counterparty,
        network_declines: row.count }, 60);
    for (const [action, ruleId, threshold, windowMs, observedKey] of [
      ["mti_0220", "S-CARD-10", 3, 60_000, "captures"],
      ["mti_0400", "S-CARD-11", 3, 86_400_000, "reversals"],
    ] as const) {
      for (const row of db.prepare(`SELECT card_token,counterparty,COUNT(*) count
        FROM telemetry_events WHERE source='network' AND action=?
          AND outcome='success' AND twin_ts>=? AND card_token IS NOT NULL
          AND counterparty IS NOT NULL
        GROUP BY card_token,counterparty HAVING count>=?`)
        .all(action, since(windowMs), threshold) as
        { card_token: string; counterparty: string; count: number }[])
        add(ruleId, row.card_token, { merchant: row.counterparty,
          [observedKey]: row.count }, windowMs / 1000);
    }
    if (db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='card_network_messages'`).get()) {
      for (const row of db.prepare(`SELECT a.card_id,a.merchant_id,
      COUNT(DISTINCT CASE WHEN json_valid(m.payload_json)
        THEN json_extract(m.payload_json,'$.dispute_id') END) count
      FROM card_network_messages m JOIN card_network_authorizations a
        ON a.id=m.authorization_id
      WHERE m.mti='1440' AND m.created_at>=?
      GROUP BY a.card_id,a.merchant_id HAVING count>=3`)
        .all(since(86_400_000)) as
        { card_id: string; merchant_id: string; count: number }[])
        add("S-CARD-12", row.card_id, { merchant: row.merchant_id,
          disputes: row.count }, 86_400);
    }
    for (const row of db.prepare(`SELECT card_id,COUNT(*) count FROM card_changes
      WHERE field='limit_cents' AND approved_request_id IS NULL GROUP BY card_id`).all() as
      { card_id: string; count: number }[])
      add("S-CARD-03", row.card_id, { unapproved_changes: row.count });
    for (const row of db.prepare(`SELECT a.id,COUNT(r.id) refunds,COALESCE(SUM(r.amount_cents),0) refunded,
      MAX(CASE WHEN r.target_card_id<>a.card_id THEN 1 ELSE 0 END) mismatch,a.amount_cents
      FROM card_authorizations a LEFT JOIN card_refunds r ON r.authorization_id=a.id
      GROUP BY a.id HAVING refunded>a.amount_cents OR mismatch=1`).all() as
      { id: string; refunds: number; refunded: number; mismatch: number; amount_cents: number }[])
      add("S-CARD-04", row.id, { refunded_cents: row.refunded, authorized_cents: row.amount_cents, mismatch: row.mismatch });
    for (const row of db.prepare("SELECT card_id,capture_count FROM temporary_cards WHERE capture_count>1")
      .all() as { card_id: string; capture_count: number }[])
      add("S-CARD-05", row.card_id, { captures: row.capture_count });
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) decisions,
      COUNT(DISTINCT entity_id) merchants,MAX(score) max_score FROM risk_decisions
      WHERE area='cards' AND created_at>=? AND
        (reason_codes_json LIKE ? OR reason_codes_json LIKE ?)
      GROUP BY customer_id`).all(since(600_000), '%"CARD_TESTING_VELOCITY"%',
        '%"CARD_BIN_MERCHANT_TESTING"%') as
      { customer_id: string; decisions: number; merchants: number; max_score: number }[])
      add("S-CARD-06", row.customer_id, { decisions: row.decisions,
        merchants: row.merchants, risk_score: row.max_score }, 600);
    for (const row of db.prepare(`SELECT l.id,l.principal_cents,o.max_amount_cents FROM loans l
      JOIN loan_offers o ON o.id=l.offer_id WHERE l.principal_cents>o.max_amount_cents`).all() as
      { id: string; principal_cents: number; max_amount_cents: number }[])
      add("S-LOAN-01", row.id, { principal_cents: row.principal_cents, offer_cents: row.max_amount_cents });
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) active_loans FROM loans
      WHERE status='active' GROUP BY customer_id HAVING active_loans>1`).all() as
      { customer_id: string; active_loans: number }[])
      add("S-LOAN-02", row.customer_id, { active_loans: row.active_loans });
    for (const row of db.prepare(`SELECT l.customer_id,COUNT(DISTINCT p.id) transfers FROM loans l
      JOIN auth_devices d ON d.id=l.initiating_device_id AND d.customer_id=l.customer_id
        AND d.first_seen_at<=l.started_at AND d.bound_at<=l.started_at
        AND MAX(d.first_seen_at,d.bound_at)>=?
      JOIN pix_transfers p ON p.from_account=l.account_id AND p.actor=l.customer_id
        AND p.initiating_device_id=l.initiating_device_id AND p.initiated_at>=l.started_at
      WHERE l.started_at>=? AND (julianday(p.initiated_at)-julianday(l.started_at))*1440<10
      GROUP BY l.customer_id`).all(since(86_400_000), since(86_400_000)) as
      { customer_id: string; transfers: number }[])
      add("S-LOAN-03", row.customer_id, { transfers_after_loan: row.transfers }, 600);
    for (const row of db.prepare(`WITH affected AS (
      SELECT DISTINCT customer_id FROM access_log
      WHERE kind='loan_offer_own' AND status=503 AND ts>=? AND customer_id IS NOT NULL
    ) SELECT failed.id,failed.customer_id
      FROM affected JOIN access_log failed ON failed.rowid=(
        SELECT MIN(first_failure.rowid) FROM access_log first_failure
        WHERE first_failure.kind='loan_offer_own' AND first_failure.status=503
          AND first_failure.customer_id=affected.customer_id
          AND first_failure.rowid>COALESCE((SELECT MAX(recovered.rowid)
            FROM access_log recovered WHERE recovered.kind='loan_offer_own'
              AND recovered.status=200 AND recovered.customer_id=affected.customer_id),0))
      ORDER BY failed.rowid LIMIT 100`).all(since(300_000)) as
      { id: string; customer_id: string }[])
      add("S-LOAN-04", row.customer_id,
        { failed_log_id: row.id }, 300);
    for (const row of db.prepare(`SELECT failed.id,failed.customer_id
      FROM access_log failed WHERE failed.kind='pix_automatic_mandates_own'
        AND failed.status=503 AND failed.customer_id IS NOT NULL
        AND failed.ts>=? AND failed.rowid=(SELECT MAX(latest.rowid)
          FROM access_log latest WHERE latest.kind='pix_automatic_mandates_own'
            AND latest.status=503 AND latest.customer_id=failed.customer_id)
        AND NOT EXISTS (SELECT 1 FROM access_log recovered
          WHERE recovered.kind='pix_automatic_mandates_own' AND recovered.status=200
            AND recovered.customer_id=failed.customer_id
            AND recovered.rowid>failed.rowid)
      ORDER BY failed.rowid LIMIT 100`).all(since(300_000)) as
      { id: string; customer_id: string }[])
      add("S-PIX-42", row.customer_id,
        { failed_log_id: row.id, service_unavailable: 1 }, 300);
    for (const row of db.prepare(`SELECT failed.id,failed.customer_id
      FROM access_log failed WHERE failed.kind='kyc_status_own'
        AND failed.status=503 AND failed.customer_id IS NOT NULL
        AND failed.ts>=? AND failed.rowid=(SELECT MAX(latest.rowid)
          FROM access_log latest WHERE latest.kind='kyc_status_own'
            AND latest.status=503 AND latest.customer_id=failed.customer_id)
        AND NOT EXISTS (SELECT 1 FROM access_log recovered
          WHERE recovered.kind='kyc_status_own' AND recovered.status=200
            AND recovered.customer_id=failed.customer_id
            AND recovered.rowid>failed.rowid)
      ORDER BY failed.rowid LIMIT 100`).all(since(300_000)) as
      { id: string; customer_id: string }[])
      add("S-AUTH-14", row.customer_id,
        { failed_log_id: row.id, service_unavailable: 1 }, 300);
    for (const row of db.prepare(`SELECT failed.id,failed.customer_id
      FROM access_log failed WHERE failed.kind='kyc_submission_own'
        AND failed.status=503 AND failed.customer_id IS NOT NULL
        AND failed.ts>=? AND failed.rowid=(SELECT MAX(latest.rowid)
          FROM access_log latest WHERE latest.kind='kyc_submission_own'
            AND latest.status=503 AND latest.customer_id=failed.customer_id)
        AND NOT EXISTS (SELECT 1 FROM access_log recovered
          WHERE recovered.kind='kyc_submission_own' AND recovered.status=200
            AND recovered.customer_id=failed.customer_id
            AND recovered.rowid>failed.rowid)
      ORDER BY failed.rowid LIMIT 100`).all(since(300_000)) as
      { id: string; customer_id: string }[])
      add("S-AUTH-15", row.customer_id,
        { failed_log_id: row.id, service_unavailable: 1 }, 300);
    for (const row of db.prepare(`SELECT failed.id,failed.customer_id
      FROM access_log failed WHERE failed.kind='kyc_review'
        AND failed.status=503 AND failed.customer_id IS NOT NULL
        AND failed.ts>=? AND failed.rowid=(SELECT MAX(latest.rowid)
          FROM access_log latest WHERE latest.kind='kyc_review'
            AND latest.status=503 AND latest.customer_id=failed.customer_id
            AND latest.route=failed.route)
        AND NOT EXISTS (SELECT 1 FROM access_log recovered
          WHERE recovered.kind='kyc_review' AND recovered.status=200
            AND recovered.customer_id=failed.customer_id AND recovered.route=failed.route
            AND recovered.rowid>failed.rowid)
      ORDER BY failed.rowid LIMIT 100`).all(since(300_000)) as
      { id: string; customer_id: string }[])
      add("S-AUTH-16", row.customer_id,
        { failed_log_id: row.id, service_unavailable: 1 }, 300);
    for (const row of db.prepare(`SELECT peer_ip,COUNT(*) count FROM access_log WHERE
      kind IN ('gateway_request','rate_limited') AND ts>=? GROUP BY peer_ip HAVING count>300`)
      .all(since(60_000)) as { peer_ip: string; count: number }[])
      add("S-GW-01", row.peer_ip, { requests: row.count }, 60);
    for (const row of db.prepare(`SELECT route,COUNT(*) count FROM access_log WHERE
      route LIKE '/api/v0/%' AND status>=200 AND status<300 AND ts>=? GROUP BY route`)
      .all(since(600_000)) as { route: string; count: number }[])
      add("S-GW-02", row.route, { unauthenticated_successes: row.count }, 600);
    for (const row of db.prepare(`SELECT c.customer_id,COUNT(*) reads FROM data_share_reads r
      JOIN data_consents c ON c.id=r.consent_id WHERE r.was_revoked=1
      GROUP BY c.customer_id`).all() as { customer_id: string; reads: number }[])
      add("S-GW-03", row.customer_id, { reads_after_revocation: row.reads });
    for (const row of db.prepare(`SELECT peer_ip,COUNT(*) total,SUM(CASE WHEN status>=400 AND status<500 THEN 1 ELSE 0 END) errors
      FROM access_log WHERE kind IN ('gateway_request','rate_limited') AND ts>=?
      GROUP BY peer_ip HAVING total>=100`).all(since(60_000)) as
      { peer_ip: string; total: number; errors: number }[])
      if (row.errors / row.total > 0.6) add("S-GW-04", row.peer_ip,
        { requests: row.total, errors: row.errors }, 60);
    const integrity = this.incrementalIntegrity();
    for (const row of db.prepare(`SELECT t.id,t.counterparty FROM telemetry_events t
      WHERE t.source='ledger' AND t.action='post' AND t.outcome='success'
        AND t.twin_ts>=? AND t.counterparty IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM ledger_entries e
          WHERE e.tx_id=t.counterparty GROUP BY e.tx_id
          HAVING COUNT(*)>=2 AND SUM(e.amount)=0
            AND SUM(CASE WHEN e.amount>0 THEN e.amount ELSE 0 END)=t.amount_cents)
      LIMIT 100`).all(since(600_000)) as
      { id: number; counterparty: string }[])
      add("S-LED-10", `ledger_event:${row.id}`, { telemetry_id: row.id,
        posting_mismatch: 1, transaction_id: row.counterparty }, 600);
    for (const row of db.prepare(`SELECT maker_id,COUNT(*) count FROM manual_posting_requests
      WHERE created_at>=? GROUP BY maker_id HAVING count>=10`)
      .all(since(600_000)) as { maker_id: string; count: number }[])
      add("S-LED-06", row.maker_id, { posting_requests: row.count }, 600);
    for (const row of db.prepare(`SELECT checker_id,COUNT(*) count,
      SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approvals,
      SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) rejections
      FROM manual_posting_requests WHERE resolved_at>=? AND checker_id IS NOT NULL
      GROUP BY checker_id HAVING count>=10`)
      .all(since(600_000)) as { checker_id: string; count: number;
        approvals: number; rejections: number }[])
      add("S-LED-07", row.checker_id, { resolutions: row.count,
        approvals: row.approvals, rejections: row.rejections }, 600);
    for (const row of db.prepare(`SELECT account_id,COUNT(*) count FROM account_status_changes
      WHERE changed_at>=? GROUP BY account_id HAVING count>=4`)
      .all(since(86_400_000)) as { account_id: string; count: number }[])
      add("S-LED-08", row.account_id, { status_changes: row.count }, 86_400);
    for (const row of db.prepare(`SELECT customer_id,COUNT(*) count,
      SUM(amount_cents) amount_cents FROM closed_account_credits
      WHERE status='paid' AND paid_at>=?
      GROUP BY customer_id HAVING count>=3`).all(since(86_400_000)) as
      { customer_id: string; count: number; amount_cents: number }[])
      add("S-LED-09", row.customer_id, { payouts: row.count,
        amount_cents: row.amount_cents }, 86_400);
    if (this.ledgerAnchorMismatch)
      add("S-LED-02", "ledger_anchor", { anchor_valid: 0 });
    if (integrity.unbalancedTx || integrity.accountDrift || integrity.medDrift || !this.lastHashOk)
      add("S-LED-02", "ledger", { unbalanced_tx: integrity.unbalancedTx,
        account_drift: integrity.accountDrift, med_drift: integrity.medDrift,
        hash_chain_valid: this.lastHashOk ? 1 : 0 });
    if (this.bank.isSeparatedEcosystem) {
      const crossBook = sources!.crossBook;
      const pending = crossBook.pending_pix + crossBook.pending_inbound +
        crossBook.pending_med + crossBook.pending_returns +
        crossBook.pending_cautelar_returns;
      const realNowMs = this.bank.realNow().getTime();
      const pendingItems = db.prepare(`SELECT 'pix' kind,p.id command_id,
          o.queued_at_real FROM pix_transfers p LEFT JOIN pix_spi_outbox o
          ON o.transfer_id=p.id WHERE p.status='in_processing'
        UNION ALL SELECT 'inbound',transfer_id,NULL FROM pix_psp_inbound_outbox
          WHERE acknowledged_at IS NULL
        UNION ALL SELECT 'return',id,NULL FROM pix_psp_return_outbox
          WHERE acknowledged_at IS NULL AND rejected_at IS NULL
        UNION ALL SELECT 'cautelar',id,NULL FROM pix_psp_cautelar_return_outbox
          WHERE acknowledged_at IS NULL AND rejected_at IS NULL
        UNION ALL SELECT 'med_open',case_id,NULL FROM med_psp_open_outbox
          WHERE acknowledged_at IS NULL
        UNION ALL SELECT 'med_analysis',case_id,NULL FROM med_dict_analysis_outbox
          WHERE acknowledged_at IS NULL
        UNION ALL SELECT 'med_release',case_id,NULL FROM med_psp_release_outbox
          WHERE acknowledged_at IS NULL
        UNION ALL SELECT 'med_settlement',case_id,NULL FROM med_psp_settlement_outbox
          WHERE acknowledged_at IS NULL`).all() as
        { kind: string; command_id: string; queued_at_real: string | null }[];
      const active = new Set(pendingItems.map((item) => `${item.kind}\0${item.command_id}`));
      for (const watched of db.prepare(`SELECT kind,command_id FROM
        sentinel_cross_book_pending_items`).all() as
        { kind: string; command_id: string }[])
        if (!active.has(`${watched.kind}\0${watched.command_id}`))
          db.prepare(`DELETE FROM sentinel_cross_book_pending_items
            WHERE kind=? AND command_id=?`).run(watched.kind, watched.command_id);
      const watch = db.prepare(`INSERT OR IGNORE INTO sentinel_cross_book_pending_items
        (kind,command_id,first_seen_real_ms) VALUES (?,?,?)`);
      const firstSeen = db.prepare(`SELECT first_seen_real_ms FROM
        sentinel_cross_book_pending_items WHERE kind=? AND command_id=?`);
      let stalePending = false;
      for (const item of pendingItems) {
        watch.run(item.kind, item.command_id, realNowMs);
        const observedAt = (firstSeen.get(item.kind, item.command_id) as
          { first_seen_real_ms: number }).first_seen_real_ms;
        const queuedAt = item.queued_at_real ? Date.parse(item.queued_at_real) : NaN;
        const ageMs = realNowMs - (Number.isFinite(queuedAt) ? queuedAt : observedAt);
        if (ageMs > 30_000) {
          stalePending = true;
          add("S-LED-12", item.command_id,
            { kind: item.kind, command_id: item.command_id, age_ms: ageMs }, 60);
        }
      }
      const structuralDrift = crossBook.bank_schema_drift +
        crossBook.ecosystem_schema_drift + crossBook.ledger_drift +
        crossBook.psp_account_drift + crossBook.root_overflow +
        crossBook.med_hold_drift;
      if ((!pending && !crossBook.ok) || structuralDrift > 0 ||
        stalePending)
        add("S-LED-02", "cross_book", { bank_pi_cents: crossBook.bank_pi_cents ?? "unknown",
          spi_pi_cents: crossBook.spi_pi_cents ?? "unknown", pending,
          structural_drift: structuralDrift,
          transfer_drift: crossBook.transfer_drift,
          spi_message_drift: crossBook.spi_message_drift,
          command_drift: crossBook.command_drift });
    } else {
      const spi = this.bank.reconcileSpi();
      if (!spi.ok) add("S-LED-02", "spi", { ledger_pi_cents: spi.ledger_pi_cents,
        spi_pi_cents: spi.spi_pi_cents });
      const psp = this.bank.reconcilePsp();
      if (!psp.ok) add("S-LED-02", "psp", { account_drift: psp.account_drift,
        root_overflow: psp.root_overflow, hold_overflow: psp.hold_overflow });
    }
    const cards = this.bank.reconcileCardSettlement();
    if (!cards.ok) add("S-LED-02", "card_settlement", {
      settlement_mismatches: cards.mismatches });
    const closedCredits = this.bank.closedCreditReconciliation();
    if (!closedCredits.ok) add("S-LED-02", "closed_account_credits", {
      pending_cents: closedCredits.pending_cents, suspense_cents: closedCredits.suspense_cents,
      mismatches: closedCredits.mismatches });
    for (const row of db.prepare(`SELECT id,balance_cached FROM accounts WHERE kind='system' AND system_role IN
      ('fees','loan_funding','cashback_pool') AND balance_cached<0`).all() as
      { id: string; balance_cached: number }[])
      add("S-LED-02", row.id, { balance_cents: row.balance_cached });
    if (integrity.roundingDrift >= 500) add("S-LED-03", this.bank.systemAccountId("rounding"),
      { drift_cents: integrity.roundingDrift });
    for (const row of db.prepare(`SELECT c.customer_id,COUNT(*) cases FROM cashback_records c
      JOIN card_authorizations a ON a.id=c.authorization_id LEFT JOIN
      (SELECT authorization_id,COALESCE(SUM(amount_cents),0) refunded FROM card_refunds GROUP BY authorization_id) r
      ON r.authorization_id=a.id WHERE c.credited_cents-c.clawed_back_cents >
      (a.amount_cents-COALESCE(r.refunded,0))*c.rate_bps/10000.0 + 1
      GROUP BY c.customer_id`).all() as { customer_id: string; cases: number }[])
      add("S-LED-04", row.customer_id, { overpaid_purchases: row.cases });
    const realNowMs = this.bank.realNow().getTime();
    if (realNowMs - this.lastTelemetryVerificationMs >= 60_000 ||
      realNowMs < this.lastTelemetryVerificationMs) {
      this.lastTelemetryHashOk = this.bank.telemetry.verifyChain();
      this.lastTelemetryVerificationMs = realNowMs;
    }
    if (!this.lastTelemetryHashOk)
      add("S-GW-06", "telemetry", { hash_chain_valid: 0 });
    if (this.gatewayHealthStartedMs !== undefined) {
      if (realNowMs < this.gatewayHealthStartedMs) this.gatewayHealthStartedMs = realNowMs;
      const heartbeat = db.prepare(`SELECT ts FROM telemetry_events WHERE source='gateway'
        AND category='health' AND action='heartbeat' ORDER BY id DESC LIMIT 1`).get() as
        { ts: string } | undefined;
      const lastMs = heartbeat ? Date.parse(heartbeat.ts) : 0;
      const baseline = Math.max(this.gatewayHealthStartedMs, Number.isFinite(lastMs) && lastMs <= realNowMs ? lastMs : 0);
      if (realNowMs - baseline > 30_000)
        add("S-GW-07", "gateway", { heartbeat_age_ms: realNowMs - baseline });
    }
    if (this.riskHealthStartedMs !== undefined) {
      if (realNowMs < this.riskHealthStartedMs) this.riskHealthStartedMs = realNowMs;
      const heartbeat = db.prepare(`SELECT ts FROM telemetry_events INDEXED BY sentinel_risk_heartbeat WHERE source='risk'
        AND category='health' AND action='heartbeat' ORDER BY id DESC LIMIT 1`).get() as
        { ts: string } | undefined;
      const lastMs = heartbeat ? Date.parse(heartbeat.ts) : 0;
      const baseline = Math.max(this.riskHealthStartedMs,
        Number.isFinite(lastMs) && lastMs <= realNowMs ? lastMs : 0);
      if (realNowMs - baseline > 30_000)
        add("S-GW-10", "risk", { heartbeat_age_ms: realNowMs - baseline });
    }
    for (const source of Object.keys(PRODUCER_HEALTH_RULES) as MonitoredProducer[]) {
      const started = this.producerHealthStartedMs.get(source);
      if (started === undefined) continue;
      if (realNowMs < started) this.producerHealthStartedMs.set(source, realNowMs);
      const heartbeat = db.prepare(`SELECT ts FROM telemetry_events INDEXED BY sentinel_producer_heartbeat
        WHERE source=? AND category='health' AND action='heartbeat' ORDER BY id DESC LIMIT 1`)
        .get(source) as { ts: string } | undefined;
      const lastMs = heartbeat ? Date.parse(heartbeat.ts) : 0;
      const baseline = Math.max(this.producerHealthStartedMs.get(source)!,
        Number.isFinite(lastMs) && lastMs <= realNowMs ? lastMs : 0);
      if (realNowMs - baseline > 30_000)
        add(PRODUCER_HEALTH_RULES[source], source, { heartbeat_age_ms: realNowMs - baseline });
    }
    return found;
  }
  // The event store and bank are separate databases. The local transaction commits
  // cursor, alert, incident and outbox together; idempotent publication is retried.
  private scanAgentEvents(ruleId: "S-GW-08" | "S-GW-09" | "S-GW-12", publish: boolean): SentinelAlert[] {
    if (!this.events || this.bank.db.isTransaction) return [];
    const events = this.events;
    const refusal = ruleId === "S-GW-09";
    const threadDied = ruleId === "S-GW-12";
    const cursorTable = refusal ? "sentinel_refusal_cursor" :
      threadDied ? "sentinel_thread_cursor" : "sentinel_agent_cursor";
    const severity = refusal || threadDied ? "high" : "critical";
    const matches = (id: "S-GW-08" | "S-GW-09" | "S-GW-12",
      event: ReturnType<EventStore["get"]>): boolean =>
      !!event && (id === "S-GW-09" ? event.type === "agent.finished" && event.public.outcome === "refused" :
        id === "S-GW-12" ? event.type === "agent.finished" && event.public.outcome === "failed" &&
          events.getPrivate(event.seq)?.reason === "codex_thread_stream_ended" :
          event.type === "integrity.violation");
    const entityFor = (id: "S-GW-08" | "S-GW-09" | "S-GW-12", seq: number): string =>
      `agent_${id === "S-GW-08" ? "integrity" : id === "S-GW-09" ? "refusal" : "thread"}:${seq}`;
    const selectViolations = (): ReturnType<EventStore["list"]> => {
      const cursor = this.bank.db.prepare(`SELECT last_seq FROM ${cursorTable} WHERE id=1`)
        .get() as { last_seq: number } | undefined;
      try {
        return events.list({ after: cursor?.last_seq ?? 0,
          types: [refusal || threadDied ? "agent.finished" : "integrity.violation"], limit: 100 });
      } catch {
        return [];
      }
    };
    const hasViolations = selectViolations().length > 0;
    const alerts = hasViolations ? this.bank.transaction(() => {
      const violations = selectViolations();
      const created: SentinelAlert[] = [];
      for (const event of violations) {
        if (!matches(ruleId, event)) continue;
        const now = this.bank.now().toISOString();
        const alertId = newId("alert", this.bank.now().getTime());
        const incidentId = newId("incident", this.bank.now().getTime());
        const entity = entityFor(ruleId, event.seq);
        const observed = { event_seq: event.seq };
        this.bank.db.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)")
          .run(alertId, ruleId, entity, JSON.stringify(observed), 0, now, now, 1, now);
        this.bank.db.prepare("INSERT INTO sentinel_incidents VALUES (?,?,?,?,?,?,?,?)")
          .run(incidentId, entity, "api_gateway", severity, "open", 1, now, now);
        this.bank.telemetry.emit({ source: "siem", category: "api_gateway", action: "alert",
          outcome: "failure", severity: refusal || threadDied ? "warn" : "error", ruleId,
          message: refusal ? "Agent refusal detected" : threadDied ?
            "Codex thread ended without a terminal event" : "Agent integrity violation detected" });
        this.bank.db.prepare(`INSERT INTO sentinel_agent_outbox
          (event_seq,alert_id,incident_id,observed_at,published_at,source_round_id)
          VALUES (?,?,?,?,NULL,?)`).run(event.seq, alertId, incidentId, now, event.round_id);
        created.push({ alert_id: alertId, rule_id: ruleId, area: "api_gateway",
          severity, entity, observed, window_s: 0, first_seen: now,
          last_seen: now, count: 1, evidence_ref: `sentinel_alerts:${alertId}` });
      }
      if (violations.length) this.bank.db.prepare(`INSERT INTO ${cursorTable} VALUES (1,?)
        ON CONFLICT(id) DO UPDATE SET last_seq=excluded.last_seq`).run(violations.at(-1)!.seq);
      return created;
    }) : [];
    if (!publish) return alerts;
    type PendingAgentAlert = { event_seq: number; alert_id: string; incident_id: string;
      observed_at: string; source_round_id: string | null;
      rule_id: "S-GW-08" | "S-GW-09" | "S-GW-12" };
    const cursor = this.bank.db.prepare(`SELECT last_seq FROM sentinel_agent_publication_cursor
      WHERE id=1`).get() as { last_seq: number } | undefined;
    const readPending = (after: number): PendingAgentAlert[] =>
      this.bank.db.prepare(`SELECT o.event_seq,o.alert_id,o.incident_id,o.observed_at,
        o.source_round_id,a.rule_id
        FROM sentinel_agent_outbox o JOIN sentinel_alerts a ON a.id=o.alert_id
        WHERE o.published_at IS NULL AND o.event_seq>? ORDER BY o.event_seq LIMIT 100`)
        .all(after) as PendingAgentAlert[];
    const pending = readPending(cursor?.last_seq ?? 0);
    if (!pending.length && cursor) pending.push(...readPending(0));
    for (const row of pending) {
      try {
        const isRefusal = row.rule_id === "S-GW-09";
        const isThread = row.rule_id === "S-GW-12";
        const rowSeverity = isRefusal || isThread ? "high" : "critical";
        const entity = entityFor(row.rule_id, row.event_seq);
        const source = events.get(row.event_seq);
        if (!matches(row.rule_id, source) ||
          row.source_round_id !== null && row.source_round_id !== source!.round_id)
          throw new Error("SENTINEL_AGENT_SOURCE_MISSING");
        const sourceRoundId = source!.round_id;
        events.append({ round_id: sourceRoundId, ts: this.bank.realNow().toISOString(), twin_ts: row.observed_at,
          type: "sentinel.alert", actor: { id: "sentinel-api_gateway", role: "sentinel" },
          area: "api_gateway", public_summary_pt: isRefusal ? "Recusa de agente detectada" :
            isThread ? "Thread Codex encerrada sem resultado" : "Violação de integridade de agente detectada",
          public: { alert_id: row.alert_id, rule_id: row.rule_id, severity: rowSeverity,
            area: "api_gateway", pattern_label: row.rule_id },
          private: { entity, observed: { event_seq: row.event_seq },
            evidence_ref: `sentinel_alerts:${row.alert_id}` } }, `agent-integrity:alert:${row.event_seq}`);
        events.append({ round_id: sourceRoundId, ts: this.bank.realNow().toISOString(), twin_ts: row.observed_at,
          type: "incident.opened", actor: { id: "sentinel-cluster", role: "sentinel" },
          area: "api_gateway", incident_id: row.incident_id,
          public_summary_pt: isRefusal ? "Incidente de recusa de agente" :
            isThread ? "Incidente de thread Codex encerrada" : "Incidente de integridade de agente",
          public: { incident_id: row.incident_id, severity: rowSeverity, area: "api_gateway",
            alert_count: 1, source: "sentinel" },
          private: { entity_key: entity, alert_id: row.alert_id } }, `agent-integrity:incident:${row.event_seq}`);
        this.bank.db.prepare("UPDATE sentinel_agent_outbox SET published_at=? WHERE event_seq=?")
          .run(this.bank.realNow().toISOString(), row.event_seq);
      } catch {
        // Retry this row later without delaying unrelated platform alerts.
        continue;
      }
    }
    if (pending.length) this.bank.db.prepare(`INSERT INTO sentinel_agent_publication_cursor VALUES (1,?)
      ON CONFLICT(id) DO UPDATE SET last_seq=excluded.last_seq`).run(pending.at(-1)!.event_seq);
    return alerts;
  }
  private scanRedactedTelemetry(): SentinelAlert[] {
    const readCursor = (): number => (this.bank.db.prepare(
      "SELECT last_id FROM sentinel_redacted_cursor WHERE id=1").get() as
      { last_id: number } | undefined)?.last_id ?? 0;
    const readBatch = (after: number) => this.bank.db.prepare(`SELECT id,trace_id,source
      FROM telemetry_events WHERE redacted=1 AND id>? ORDER BY id LIMIT 100`)
      .all(after) as { id: number; trace_id: string; source: string }[];
    const hasBatch = readBatch(readCursor()).length > 0;
    const alerts = hasBatch ? this.bank.transaction(() => {
      this.bank.db.exec("SAVEPOINT sentinel_redacted_batch");
      try {
        const rows = readBatch(readCursor());
        const created: SentinelAlert[] = [];
        for (const row of rows) {
          const now = this.bank.now().toISOString();
          const prior = this.bank.db.prepare(`SELECT id,first_seen,last_emitted,count FROM sentinel_alerts
            WHERE rule_id='S-GW-05' AND entity=?`).get(row.trace_id) as
            { id: string; first_seen: string; last_emitted: string; count: number } | undefined;
          const alertId = prior?.id ?? newId("alert", this.bank.now().getTime());
          const count = (prior?.count ?? 0) + 1;
          const emit = !prior || this.bank.now().getTime() - Date.parse(prior.last_emitted) >= 60_000;
          const observed = { event_id: row.id, source: row.source };
          this.bank.db.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(rule_id,entity) DO UPDATE SET observed_json=excluded.observed_json,
            last_seen=excluded.last_seen,count=excluded.count,last_emitted=excluded.last_emitted`)
            .run(alertId, "S-GW-05", row.trace_id, JSON.stringify(observed), 0,
              prior?.first_seen ?? now, now, count, emit ? now : prior!.last_emitted);
          if (!emit) continue;
          const alert: SentinelAlert = { alert_id: alertId, rule_id: "S-GW-05", area: "api_gateway",
            severity: "high", entity: row.trace_id, observed, window_s: 0,
            first_seen: prior?.first_seen ?? now, last_seen: now, count,
            evidence_ref: `sentinel_alerts:${alertId}` };
          this.bank.telemetry.emit({ source: "siem", category: "api_gateway", action: "alert",
            outcome: "failure", severity: "warn", ruleId: "S-GW-05",
            message: "Sentinel S-GW-05 detected a pattern" });
          const incidentId = this.openIncident(alert, false);
          this.bank.db.prepare(`INSERT INTO sentinel_redacted_outbox
            (event_id,alert_json,incident_id,incident_entity,published_at) VALUES (?,?,?,?,NULL)`)
            .run(row.id, JSON.stringify(alert), incidentId ?? null, this.incidentEntity(alert.entity));
          created.push(alert);
        }
        if (rows.length) this.bank.db.prepare(`INSERT INTO sentinel_redacted_cursor VALUES (1,?)
          ON CONFLICT(id) DO UPDATE SET last_id=excluded.last_id`).run(rows.at(-1)!.id);
        this.bank.db.exec("RELEASE sentinel_redacted_batch");
        return created;
      } catch (error) {
        this.bank.db.exec("ROLLBACK TO sentinel_redacted_batch");
        this.bank.db.exec("RELEASE sentinel_redacted_batch");
        throw error;
      }
    }) : [];
    if (!this.events || this.bank.db.isTransaction) return alerts;
    const pending = this.bank.db.prepare(`SELECT event_id,alert_json,incident_id,incident_entity FROM sentinel_redacted_outbox
      WHERE published_at IS NULL ORDER BY event_id LIMIT 100`).all() as
      { event_id: number; alert_json: string; incident_id: string | null; incident_entity: string | null }[];
    for (const row of pending) {
      try {
        const alert = JSON.parse(row.alert_json) as SentinelAlert;
        this.events.append({ round_id: null, ts: this.bank.realNow().toISOString(), twin_ts: alert.last_seen,
          type: "sentinel.alert", actor: { id: "sentinel-api_gateway", role: "sentinel" }, area: "api_gateway",
          public_summary_pt: "S-GW-05: padrão detectado", public: { alert_id: alert.alert_id,
            rule_id: "S-GW-05", severity: "high", area: "api_gateway", pattern_label: "S-GW-05" },
          private: { entity: alert.entity, observed: alert.observed, evidence_ref: alert.evidence_ref } },
          `redacted:alert:${row.event_id}`);
        if (row.incident_id) this.events.append({ round_id: null,
          ts: this.bank.realNow().toISOString(), twin_ts: alert.last_seen, type: "incident.opened",
          actor: { id: "sentinel-cluster", role: "sentinel" }, area: "api_gateway",
          incident_id: row.incident_id, public_summary_pt: "Incidente em api_gateway",
          public: { incident_id: row.incident_id, severity: "high", area: "api_gateway", alert_count: 1,
            source: "sentinel" }, private: { entity_key: row.incident_entity, alert_id: alert.alert_id } },
          `redacted:incident:${row.event_id}`);
        this.bank.db.prepare("UPDATE sentinel_redacted_outbox SET published_at=? WHERE event_id=?")
          .run(this.bank.realNow().toISOString(), row.event_id);
      } catch { break; }
    }
    return alerts;
  }
  private scanMedReviewOverdue(): SentinelAlert[] {
    const now = this.bank.now().toISOString();
    const hasOverdue = this.bank.db.prepare(`SELECT 1 FROM med_cases m
      WHERE m.status='open' AND m.resolve_after<?
        AND NOT EXISTS (SELECT 1 FROM med_decisions d WHERE d.case_id=m.id)
      LIMIT 1`).get(now);
    const alerts = hasOverdue ? this.bank.transaction(() => {
      const overdue = this.bank.db.prepare(`SELECT m.id,m.resolve_after FROM med_cases m
        WHERE m.status='open' AND m.resolve_after<?
          AND NOT EXISTS (SELECT 1 FROM med_decisions d WHERE d.case_id=m.id)`)
        .all(now) as { id: string; resolve_after: string }[];
      const created: SentinelAlert[] = [];
      for (const row of overdue) {
        const prior = this.bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-PIX-13' AND entity=?`).get(row.id) as
          { id: string } | undefined;
        if (prior) {
          this.bank.db.prepare(`UPDATE sentinel_alerts SET last_seen=? WHERE id=?`)
            .run(now, prior.id);
          continue;
        }
        const alertId = newId("alert", this.bank.now().getTime());
        const observed = { review_deadline: row.resolve_after };
        this.bank.db.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)`)
          .run(alertId, "S-PIX-13", row.id, JSON.stringify(observed), 0, now, now, 1, now);
        this.bank.db.prepare(`INSERT INTO sentinel_med_review_outbox
          (case_id,alert_id,observed_at,published_at) VALUES (?,?,?,NULL)`)
          .run(row.id, alertId, now);
        this.bank.telemetry.emit({ source: "siem", category: "pix", action: "alert",
          outcome: "failure", severity: "warn", ruleId: "S-PIX-13",
          message: "MED review deadline exceeded" });
        created.push({ alert_id: alertId, rule_id: "S-PIX-13", area: "pix",
          severity: "low", entity: row.id, observed, window_s: 0,
          first_seen: now, last_seen: now, count: 1,
          evidence_ref: `sentinel_alerts:${alertId}` });
      }
      return created;
    }) : [];
    if (!this.events || this.bank.db.isTransaction) return alerts;
    const pending = this.bank.db.prepare(`SELECT case_id,alert_id,observed_at
      FROM sentinel_med_review_outbox WHERE published_at IS NULL
      ORDER BY observed_at,case_id`).all() as
      { case_id: string; alert_id: string; observed_at: string }[];
    for (const row of pending) {
      try {
        this.events.append({ round_id: null, ts: this.bank.realNow().toISOString(),
          twin_ts: row.observed_at, type: "sentinel.alert",
          actor: { id: "sentinel-pix", role: "sentinel" }, area: "pix",
          public_summary_pt: "Prazo de análise MED excedido",
          public: { alert_id: row.alert_id, rule_id: "S-PIX-13", severity: "low",
            area: "pix", pattern_label: "S-PIX-13" },
          private: { entity: row.case_id, evidence_ref: `sentinel_alerts:${row.alert_id}` } },
        `med-review-overdue:${row.case_id}`);
        this.bank.db.prepare(`UPDATE sentinel_med_review_outbox SET published_at=?
          WHERE case_id=?`).run(this.bank.realNow().toISOString(), row.case_id);
      } catch {
        // Keep the row pending; the event store deduplicates a retry after restart.
        continue;
      }
    }
    return alerts;
  }
  private scanMedInitiationOverdue(): SentinelAlert[] {
    if (this.bank.db.isTransaction) return [];
    const breached = this.bank.medInitiationSla().filter((row) =>
      row.state === "overdue" || row.state === "late");
    const alerts = breached.length ? this.bank.transaction(() => {
      const created: SentinelAlert[] = [];
      const now = this.bank.now().toISOString();
      for (const row of breached) {
        if (row.deadline_at === null)
          throw new Error("INTEGRITY_MED_INITIATION_DEADLINE");
        const prior = this.bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-PIX-39' AND entity=?`).get(row.case_id) as
          { id: string } | undefined;
        if (prior) {
          this.bank.db.prepare(`UPDATE sentinel_alerts SET last_seen=? WHERE id=?`)
            .run(now, prior.id);
          continue;
        }
        const alertId = newId("alert", this.bank.now().getTime());
        const observed = { initiation_deadline: row.deadline_at,
          initiation_state: row.state };
        this.bank.db.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)`)
          .run(alertId, "S-PIX-39", row.case_id, JSON.stringify(observed), 0,
            now, now, 1, now);
        this.bank.db.prepare(`INSERT INTO sentinel_med_initiation_outbox
          (case_id,alert_id,observed_at,published_at) VALUES (?,?,?,NULL)`)
          .run(row.case_id, alertId, now);
        this.bank.telemetry.emit({ source: "siem", category: "pix", action: "alert",
          outcome: "failure", severity: "warn", ruleId: "S-PIX-39",
          message: "MED payer initiation deadline exceeded" });
        created.push({ alert_id: alertId, rule_id: "S-PIX-39", area: "pix",
          severity: "medium", entity: row.case_id, observed, window_s: 0,
          first_seen: now, last_seen: now, count: 1,
          evidence_ref: `sentinel_alerts:${alertId}` });
      }
      return created;
    }) : [];
    if (!this.events) return alerts;
    const pending = this.bank.db.prepare(`SELECT case_id,alert_id,observed_at
      FROM sentinel_med_initiation_outbox WHERE published_at IS NULL
      ORDER BY observed_at,case_id`).all() as
      { case_id: string; alert_id: string; observed_at: string }[];
    for (const row of pending) {
      try {
        this.events.append({ round_id: null, ts: this.bank.realNow().toISOString(),
          twin_ts: row.observed_at, type: "sentinel.alert",
          actor: { id: "sentinel-pix", role: "sentinel" }, area: "pix",
          public_summary_pt: "Prazo de início da devolução MED excedido",
          public: { alert_id: row.alert_id, rule_id: "S-PIX-39", severity: "medium",
            area: "pix", pattern_label: "S-PIX-39" },
          private: { entity: row.case_id, evidence_ref: `sentinel_alerts:${row.alert_id}` } },
        `med-initiation-overdue:${row.case_id}`);
        this.bank.db.prepare(`UPDATE sentinel_med_initiation_outbox SET published_at=?
          WHERE case_id=?`).run(this.bank.realNow().toISOString(), row.case_id);
      } catch {
        continue;
      }
    }
    return alerts;
  }
  private scanMedPspRefundLate(): SentinelAlert[] {
    if (this.bank.db.isTransaction) return [];
    const late = this.bank.db.prepare(`SELECT case_id,ispb,deadline_at,processed_at
      FROM med_psp_refund_steps WHERE processed_at>deadline_at
      ORDER BY processed_at,case_id,ispb`).all() as
      { case_id: string; ispb: string; deadline_at: string;
        processed_at: string }[];
    const alerts = late.length ? this.bank.transaction(() => {
      const created: SentinelAlert[] = [];
      const now = this.bank.now().toISOString();
      for (const row of late) {
        const entity = `${row.case_id}:${row.ispb}`;
        if (this.bank.db.prepare(`SELECT 1 FROM sentinel_med_psp_late_outbox
          WHERE case_id=? AND ispb=?`).get(row.case_id, row.ispb)) continue;
        const alertId = newId("alert", this.bank.now().getTime());
        const observed = { deadline_at: row.deadline_at,
          processed_at: row.processed_at,
          delay_seconds: Math.ceil((Date.parse(row.processed_at) -
            Date.parse(row.deadline_at)) / 1000) };
        this.bank.db.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)`)
          .run(alertId, "S-PIX-40", entity, JSON.stringify(observed), 0,
            now, now, 1, now);
        this.bank.db.prepare(`INSERT INTO sentinel_med_psp_late_outbox
          (case_id,ispb,alert_id,observed_at,published_at)
          VALUES (?,?,?,?,NULL)`).run(row.case_id, row.ispb, alertId, now);
        this.bank.telemetry.emit({ source: "siem", category: "pix", action: "alert",
          outcome: "failure", severity: "warn", ruleId: "S-PIX-40",
          message: "MED receiving participant refund deadline exceeded" });
        created.push({ alert_id: alertId, rule_id: "S-PIX-40", area: "pix",
          severity: "medium", entity, observed, window_s: 0,
          first_seen: now, last_seen: now, count: 1,
          evidence_ref: `sentinel_alerts:${alertId}` });
      }
      return created;
    }) : [];
    if (!this.events) return alerts;
    const pending = this.bank.db.prepare(`SELECT case_id,ispb,alert_id,observed_at
      FROM sentinel_med_psp_late_outbox WHERE published_at IS NULL
      ORDER BY observed_at,case_id,ispb`).all() as
      { case_id: string; ispb: string; alert_id: string; observed_at: string }[];
    for (const row of pending) {
      try {
        this.events.append({ round_id: null, ts: this.bank.realNow().toISOString(),
          twin_ts: row.observed_at, type: "sentinel.alert",
          actor: { id: "sentinel-pix", role: "sentinel" }, area: "pix",
          public_summary_pt: "Prazo de devolução MED do PSP excedido",
          public: { alert_id: row.alert_id, rule_id: "S-PIX-40",
            severity: "medium", area: "pix", pattern_label: "S-PIX-40" },
          private: { entity: `${row.case_id}:${row.ispb}`,
            evidence_ref: `sentinel_alerts:${row.alert_id}` } },
        `med-psp-refund-late:${row.case_id}:${row.ispb}`);
        this.bank.db.prepare(`UPDATE sentinel_med_psp_late_outbox
          SET published_at=? WHERE case_id=? AND ispb=?`)
          .run(this.bank.realNow().toISOString(), row.case_id, row.ispb);
      } catch { /* Retry the durable publication on the next scan. */ }
    }
    return alerts;
  }
  private scanQuotaPauses(): SentinelAlert[] {
    if (!this.events || this.bank.db.isTransaction) return [];
    const events = this.events;
    const historyExists = events.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='codex_quota_history'`).get();
    if (!historyExists) return [];
    const last = this.bank.db.prepare("SELECT COALESCE(MAX(history_id),0) value FROM sentinel_quota_outbox")
      .get() as { value: number };
    const rows = events.db.prepare(`SELECT id,detected_at FROM codex_quota_history
      WHERE id>? ORDER BY id LIMIT 100`).all(last.value) as
      { id: number; detected_at: string }[];
    const created = rows.length ? this.bank.transaction(() => {
      const alerts: SentinelAlert[] = [];
      for (const row of rows) {
        if (this.bank.db.prepare("SELECT 1 FROM sentinel_quota_outbox WHERE history_id=?")
          .get(row.id)) continue;
        const alertId = newId("alert", this.bank.now().getTime());
        const observedAt = this.bank.now().toISOString();
        const entity = `codex_quota:${row.id}`;
        const observed = { detected_at: row.detected_at };
        this.bank.db.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)")
          .run(alertId, "S-GW-11", entity, JSON.stringify(observed), 0,
            observedAt, observedAt, 1, observedAt);
        this.bank.telemetry.emit({ source: "siem", category: "api_gateway",
          action: "alert", outcome: "failure", severity: "warn", ruleId: "S-GW-11",
          message: "Codex usage quota paused" });
        this.bank.db.prepare(`INSERT INTO sentinel_quota_outbox
          (history_id,alert_id,observed_at,published_at)
          VALUES (?,?,?,NULL)`)
          .run(row.id, alertId, observedAt);
        alerts.push({ alert_id: alertId, rule_id: "S-GW-11", area: "api_gateway",
          severity: "medium", entity, observed, window_s: 0,
          first_seen: observedAt, last_seen: observedAt, count: 1,
          evidence_ref: `sentinel_alerts:${alertId}` });
      }
      return alerts;
    }) : [];
    const cursor = this.bank.db.prepare(`SELECT last_id FROM sentinel_quota_publication_cursor
      WHERE id=1`).get() as { last_id: number } | undefined;
    const readPending = (after: number): { history_id: number; alert_id: string;
      observed_at: string }[] => this.bank.db.prepare(`SELECT history_id,alert_id,observed_at
      FROM sentinel_quota_outbox WHERE published_at IS NULL AND history_id>?
      ORDER BY history_id LIMIT 100`).all(after) as
      { history_id: number; alert_id: string; observed_at: string }[];
    const pending = readPending(cursor?.last_id ?? 0);
    if (!pending.length && cursor) pending.push(...readPending(0));
    for (const row of pending) {
      try {
        events.append({ round_id: null, ts: this.bank.realNow().toISOString(),
          twin_ts: row.observed_at, type: "sentinel.alert",
          actor: { id: "sentinel-api_gateway", role: "sentinel" },
          area: "api_gateway", public_summary_pt: "Pausa por cota do Codex detectada",
          public: { alert_id: row.alert_id, rule_id: "S-GW-11", severity: "medium",
            area: "api_gateway", pattern_label: "S-GW-11" },
          private: { entity: `codex_quota:${row.history_id}`,
            evidence_ref: `sentinel_alerts:${row.alert_id}` } },
        `quota-alert:${row.history_id}`);
        this.bank.db.prepare(`UPDATE sentinel_quota_outbox SET published_at=?
          WHERE history_id=?`).run(this.bank.realNow().toISOString(), row.history_id);
      } catch {
        // A later scan retries the same event without publishing another alert.
        continue;
      }
    }
    if (pending.length) this.bank.db.prepare(`INSERT INTO sentinel_quota_publication_cursor VALUES (1,?)
      ON CONFLICT(id) DO UPDATE SET last_id=excluded.last_id`).run(pending.at(-1)!.history_id);
    return created;
  }
  private scanExternalSourceHealth(): SentinelAlert[] {
    if (!this.sourceHealthPath) return [];
    const created: SentinelAlert[] = [];
    if (existsSync(this.sourceHealthPath)) {
      const source = new DatabaseSync(this.sourceHealthPath, { readOnly: true, timeout: 1000 });
      try {
        if (source.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='source_health_alerts'`).get()) {
            const cursor = (this.bank.db.prepare(`SELECT last_id FROM sentinel_source_health_cursor WHERE id=1`)
              .get() as { last_id: number } | undefined)?.last_id ?? 0;
            const rows = source.prepare(`SELECT id,code,source,observed_at,details_json
              FROM source_health_alerts WHERE id>? ORDER BY id LIMIT 100`).all(cursor) as
              { id: number; code: string; source: string; observed_at: string; details_json: string }[];
            const allowed = new Set(["stream_silence", "volume_drop", "sequence_gap",
              "seal_broken", "read_failure", "process_exit", "producer_silence",
              "shadow_divergence", "canary_touch"]);
            for (const row of rows) {
              if (!((row.source === "telemetry" && ["stream_silence", "volume_drop",
                      "sequence_gap", "seal_broken", "read_failure"].includes(row.code)) ||
                    (row.source === "bank" && row.code === "process_exit") ||
                    (row.code === "shadow_divergence" && row.source === "risk") ||
                    (row.code === "canary_touch" && row.source === "canary") ||
                    (row.code === "producer_silence" && ["gateway", "auth", "risk",
                      "cards", "pix", "spi", "dict", "ledger"].includes(row.source))) ||
                  !allowed.has(row.code) ||
                  !Number.isFinite(Date.parse(row.observed_at))) {
                this.bank.db.prepare(`INSERT INTO sentinel_source_health_cursor VALUES (1,?)
                  ON CONFLICT(id) DO UPDATE SET last_id=excluded.last_id`).run(row.id);
                continue;
              }
              let details: unknown;
              try { details = JSON.parse(row.details_json); }
              catch { details = { code: "DETAILS_INVALID" }; }
              const safeDetails: Record<string, unknown> =
                details && typeof details === "object" && !Array.isArray(details) ?
                  details as Record<string, unknown> : { code: "DETAILS_INVALID" };
              const observed: Record<string, string | number> = { code: row.code, source: row.source };
              for (const [key, value] of Object.entries(safeDetails)) {
                if (/^[a-z_]{1,32}$/.test(key) &&
                    ((typeof value === "number" && Number.isSafeInteger(value)) ||
                      (typeof value === "string" && /^[A-Z_]{1,32}$/.test(value))))
                  observed[key] = value;
              }
              const alert = this.bank.transaction(() => {
                const ruleId = row.code === "canary_touch" ? "S-GW-19" : "S-GW-13";
                const entity = row.code === "canary_touch" ?
                  `canary-touch:${row.id}` : `source-health:${row.code}:${row.source}`;
                const prior = this.bank.db.prepare(`SELECT id,first_seen,count FROM sentinel_alerts
                  WHERE rule_id=? AND entity=?`).get(ruleId, entity) as
                  { id: string; first_seen: string; count: number } | undefined;
                const id = prior?.id ?? newId("alert", Date.parse(row.observed_at));
                this.bank.db.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)
                  ON CONFLICT(rule_id,entity) DO UPDATE SET observed_json=excluded.observed_json,
                  last_seen=excluded.last_seen,count=excluded.count,last_emitted=excluded.last_emitted`)
                  .run(id, ruleId, entity, JSON.stringify(observed), 0,
                    prior?.first_seen ?? row.observed_at, row.observed_at,
                    (prior?.count ?? 0) + 1, row.observed_at);
                const item: SentinelAlert = { alert_id: id, rule_id: ruleId,
                  area: "api_gateway", severity: "critical", entity, observed, window_s: 0,
                  first_seen: prior?.first_seen ?? row.observed_at, last_seen: row.observed_at,
                  count: (prior?.count ?? 0) + 1, evidence_ref: `sentinel_alerts:${id}` };
                const incidentId = this.openIncident(item, false);
                this.bank.db.prepare(`INSERT INTO sentinel_source_health_imports
                  VALUES (?,?,?,?,?,?,NULL)`).run(row.id, id, incidentId ?? null,
                    row.observed_at, row.code, JSON.stringify(observed));
                this.bank.db.prepare(`INSERT INTO sentinel_source_health_cursor VALUES (1,?)
                  ON CONFLICT(id) DO UPDATE SET last_id=excluded.last_id`).run(row.id);
                return item;
              });
              created.push(alert);
            }
        }
      } finally { source.close(); }
    }
    const pending = this.bank.db.prepare(`SELECT source_alert_id,alert_id,incident_id,
      observed_at,code,observed_json FROM sentinel_source_health_imports
      WHERE published_at IS NULL ORDER BY source_alert_id LIMIT 100`).all() as
      { source_alert_id: number; alert_id: string; incident_id: string | null;
        observed_at: string; code: string; observed_json: string }[];
    for (const row of pending) {
      if (!this.events) break;
      this.events.append({ round_id: null, ts: this.bank.realNow().toISOString(),
        twin_ts: this.bank.now().toISOString(), type: "sentinel.alert",
        actor: { id: "sentinel-source-health", role: "sentinel" }, area: "api_gateway",
        ...(row.incident_id ? { incident_id: row.incident_id } : {}),
        public_summary_pt: row.code === "process_exit" ? "Processo do banco parou" :
          row.code === "canary_touch" ? "Canário de segurança acionado" :
          "Falha na fonte de telemetria",
        public: { alert_id: row.alert_id,
          rule_id: row.code === "canary_touch" ? "S-GW-19" : "S-GW-13",
          severity: "critical",
          area: "api_gateway", pattern_label: row.code },
        private: { observed: JSON.parse(row.observed_json),
          evidence_ref: `sentinel_alerts:${row.alert_id}` } },
      `source-health:${row.source_alert_id}`);
      if (row.incident_id) this.events.append({ round_id: null,
        ts: this.bank.realNow().toISOString(), twin_ts: this.bank.now().toISOString(),
        type: "incident.opened", actor: { id: "sentinel-cluster", role: "sentinel" },
        area: "api_gateway", incident_id: row.incident_id,
        public_summary_pt: row.code === "process_exit" ? "Incidente: processo do banco parou" :
          row.code === "canary_touch" ? "Incidente: canário de segurança acionado" :
          "Incidente na fonte de telemetria",
        public: { incident_id: row.incident_id, severity: "critical",
          area: "api_gateway", alert_count: 1, source: "sentinel" },
        private: { alert_id: row.alert_id } },
      `source-health:incident:${row.source_alert_id}`);
      this.bank.db.prepare(`UPDATE sentinel_source_health_imports SET published_at=?
        WHERE source_alert_id=?`).run(this.bank.realNow().toISOString(), row.source_alert_id);
    }
    return created;
  }

  private recordStreamAlert(ruleId: "S-AUTH-08" | "S-PIX-14" | "S-PIX-15" | "S-PIX-16",
    customerId: string,
    eventId: number, twinTs: string, observed: Record<string, number | string>,
    windowS: number): SentinelAlert {
    const rule = RULES.find((candidate) => candidate.id === ruleId)!;
    const prior = this.bank.db.prepare(`SELECT id,first_seen,count FROM sentinel_alerts
      WHERE rule_id=? AND entity=?`).get(ruleId, customerId) as
      { id: string; first_seen: string; count: number } | undefined;
    const id = prior?.id ?? newId("alert", Date.parse(twinTs));
    this.bank.db.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)
      ON CONFLICT(rule_id,entity) DO UPDATE SET observed_json=excluded.observed_json,
      last_seen=excluded.last_seen,count=excluded.count,last_emitted=excluded.last_emitted`)
      .run(id, ruleId, customerId, JSON.stringify(observed), windowS,
        prior?.first_seen ?? twinTs, twinTs, (prior?.count ?? 0) + 1, twinTs);
    const alert: SentinelAlert = { alert_id: id, rule_id: ruleId, area: rule.area,
      severity: rule.severity, entity: customerId, observed, window_s: windowS,
      first_seen: prior?.first_seen ?? twinTs, last_seen: twinTs,
      count: (prior?.count ?? 0) + 1, evidence_ref: `sentinel_alerts:${id}` };
    const incidentId = this.openIncident(alert, false);
    this.bank.db.prepare(`INSERT INTO sentinel_stream_outbox
      (event_id,rule_id,alert_id,incident_id,observed_json,twin_ts,published_at)
      VALUES (?,?,?,?,?,?,NULL)`)
      .run(eventId, ruleId, id, incidentId ?? null, JSON.stringify(observed), twinTs);
    this.bank.telemetry.emit({ source: "siem", category: rule.area, action: "alert",
      outcome: "failure", severity: "warn", ruleId,
      message: `Sentinel ${ruleId} detected a pattern` });
    return alert;
  }

  private spiMismatch(row: { id: number; twin_ts: string; action: string;
    outcome: string; amount_cents: number | null; e2e_id: string | null;
    trace_id: string }, message: Record<string, unknown> | undefined):
    SentinelAlert | undefined {
    const expectedOutcome = row.action === "pacs.008" ? "success" :
      message?.status === "ACSC" ? "success" :
      message?.status === "RJCT" ? "failure" : null;
    if (message && message.type === row.action &&
      message.end_to_end_id === row.e2e_id &&
      message.amount_cents === row.amount_cents && row.outcome === expectedOutcome)
      return undefined;
    return this.recordStreamAlert("S-PIX-16",
      row.e2e_id ?? `telemetry:${row.id}`, row.id, row.twin_ts,
      { rule_version: 1, source_event_id: row.id, action: row.action,
        e2e_id: row.e2e_id ?? "missing", trace_id: row.trace_id,
        mismatch: !message ? "missing_message" : "message_or_outcome" }, 0);
  }

  pendingSpiEvidenceIds(): string[] {
    if (!this.bank.isSeparatedEcosystem) return [];
    const cursor = (this.bank.db.prepare("SELECT last_id FROM sentinel_spi_cursor WHERE id=1")
      .get() as { last_id: number }).last_id;
    const rows = this.bank.db.prepare(`SELECT e2e_id FROM telemetry_events
      WHERE id>? AND source='spi' AND action IN ('pacs.008','pacs.002')
      ORDER BY id LIMIT 500`).all(cursor) as { e2e_id: string | null }[];
    return [...new Set(rows.filter((row) => row.e2e_id)
      .map((row) => row.e2e_id!))];
  }

  scanSpiEvidence(evidence: ReadonlyMap<string, readonly SpiMessage[]>): SentinelAlert[] {
    if (!this.bank.isSeparatedEcosystem)
      throw new Error("SEPARATED_SPI_EVIDENCE_ONLY");
    const cursor = (this.bank.db.prepare("SELECT last_id FROM sentinel_spi_cursor WHERE id=1")
      .get() as { last_id: number }).last_id;
    const selectRows = this.bank.db.prepare(`SELECT id,twin_ts,source,action,outcome,
      amount_cents,e2e_id,trace_id FROM telemetry_events
      WHERE id>? AND source='spi' AND action IN ('pacs.008','pacs.002')
      ORDER BY id LIMIT 500`);
    const rows = selectRows.all(cursor) as { id: number; twin_ts: string;
      source: string; action: string; outcome: string; amount_cents: number | null;
      e2e_id: string | null; trace_id: string }[];
    const missing = (row: typeof rows[number]) => row.source === "spi" &&
      ["pacs.008", "pacs.002"].includes(row.action) && row.e2e_id &&
      !evidence.has(row.e2e_id);
    if (rows.some(missing)) throw new Error("SPI_EVIDENCE_REQUIRED");
    const alerts: SentinelAlert[] = [];
    if (rows.length) this.bank.transaction(() => {
      const lockedCursor = (this.bank.db.prepare("SELECT last_id FROM sentinel_spi_cursor WHERE id=1")
        .get() as { last_id: number }).last_id;
      const lockedRows = lockedCursor === cursor ? rows : selectRows.all(lockedCursor) as typeof rows;
      if (!lockedRows.length) return;
      if (lockedRows.some(missing)) throw new Error("SPI_EVIDENCE_REQUIRED");
      for (const row of lockedRows) {
        if (row.source !== "spi" || !["pacs.008", "pacs.002"].includes(row.action))
          continue;
        const match = row.e2e_id ? evidence.get(row.e2e_id)?.find((message) =>
          message.type === row.action) : undefined;
        const mismatch = this.spiMismatch(row, match ? { ...match } : undefined);
        if (mismatch) alerts.push(mismatch);
      }
      this.bank.db.prepare("UPDATE sentinel_spi_cursor SET last_id=? WHERE id=1")
        .run(lockedRows.at(-1)!.id);
    });
    return alerts;
  }

  scanStream(): SentinelAlert[] {
    const cursor = (this.bank.db.prepare("SELECT last_id FROM sentinel_stream_cursor WHERE id=1")
      .get() as { last_id: number }).last_id;
    const selectRows = this.bank.db.prepare(`SELECT id,twin_ts,source,action,outcome,user_id,
      device_id,geo,counterparty,amount_cents,e2e_id,trace_id
      FROM telemetry_events WHERE id>? ORDER BY id LIMIT 500`);
    const rows = selectRows.all(cursor) as { id: number; twin_ts: string; source: string; action: string;
        outcome: string; user_id: string | null; device_id: string | null;
        geo: string | null; counterparty: string | null;
        amount_cents: number | null; e2e_id: string | null; trace_id: string }[];
    const alerts: SentinelAlert[] = [];
    if (rows.length) this.bank.transaction(() => {
      const lockedCursor = (this.bank.db.prepare("SELECT last_id FROM sentinel_stream_cursor WHERE id=1")
        .get() as { last_id: number }).last_id;
      const lockedRows = lockedCursor === cursor ? rows : selectRows.all(lockedCursor) as typeof rows;
      if (!lockedRows.length) return;
      const stateFor = this.bank.db.prepare(`SELECT bound_event_id,bound_twin_ts,
        change_event_id,change_twin_ts FROM sentinel_stream_identity WHERE customer_id=?`);
      const spiMessageFor = this.bank.isSeparatedEcosystem ? undefined :
        this.bank.db.prepare(`SELECT payload_json FROM spi_messages
          WHERE end_to_end_id=? AND message_type=? ORDER BY id LIMIT 1`);
      const windowMs = 10 * 60_000;
      for (const row of lockedRows) {
        if (row.source === "spi" && ["pacs.008", "pacs.002"].includes(row.action)) {
          if (this.bank.isSeparatedEcosystem) continue;
          let message: Record<string, unknown> | undefined;
          const stored = row.e2e_id ? spiMessageFor?.get(row.e2e_id, row.action) as
            { payload_json: string } | undefined : undefined;
          try {
            const parsed = stored ? JSON.parse(stored.payload_json) as unknown : undefined;
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
              message = parsed as Record<string, unknown>;
          } catch { /* Malformed SPI evidence is a detection mismatch. */ }
          const mismatch = this.spiMismatch(row, message);
          if (mismatch) alerts.push(mismatch);
          continue;
        }
        const customerId = row.user_id;
        const eventMs = Date.parse(row.twin_ts);
        if (!customerId || !/^cus_[A-Za-z0-9_-]{1,96}$/.test(customerId) ||
          !Number.isFinite(eventMs) || row.outcome !== "success") continue;
        if (row.source === "auth" && ["access_revoked_device",
          "refresh_revoked_device"].includes(row.action)) {
          alerts.push(this.recordStreamAlert("S-AUTH-08", customerId, row.id,
            row.twin_ts, { rule_version: 1, source_event_id: row.id, action: row.action,
              trace_id: row.trace_id,
              ...(row.device_id ? { device_id: row.device_id } : {}) }, 0));
          continue;
        }
        if (row.source === "pix" && row.action === "settle") {
          const behavior = this.behavior.observe(row);
          if (behavior) alerts.push(this.recordStreamAlert("S-PIX-15", behavior.customerId,
            row.id, row.twin_ts, behavior.observed, 0));
        }
        if (row.source === "auth" && row.action === "device_key_bound") {
          this.bank.db.prepare(`INSERT INTO sentinel_stream_identity
            VALUES (?,?,?,NULL,NULL) ON CONFLICT(customer_id) DO UPDATE SET
            bound_event_id=excluded.bound_event_id,bound_twin_ts=excluded.bound_twin_ts,
            change_event_id=NULL,change_twin_ts=NULL`)
            .run(customerId, row.id, row.twin_ts);
          continue;
        }
        if (row.source !== "pix" || !["daily_limit_changed",
          "night_setting_requested", "settle"].includes(row.action)) continue;
        const state = stateFor.get(customerId) as { bound_event_id: number;
          bound_twin_ts: string; change_event_id: number | null;
          change_twin_ts: string | null } | undefined;
        if (!state) continue;
        const elapsed = eventMs - Date.parse(state.bound_twin_ts);
        if (elapsed < 0 || elapsed > windowMs) {
          if (elapsed > windowMs) this.bank.db.prepare(`DELETE FROM sentinel_stream_identity
            WHERE customer_id=?`).run(customerId);
          continue;
        }
        if (row.action !== "settle") {
          this.bank.db.prepare(`UPDATE sentinel_stream_identity SET
            change_event_id=?,change_twin_ts=? WHERE customer_id=?`)
            .run(row.id, row.twin_ts, customerId);
          continue;
        }
        if (state.change_event_id === null || !state.change_twin_ts ||
          eventMs < Date.parse(state.change_twin_ts) ||
          typeof row.amount_cents !== "number" ||
          !Number.isSafeInteger(row.amount_cents) || row.amount_cents < 100_000) continue;
        const observed = { amount_cents: row.amount_cents,
          bound_event_id: state.bound_event_id, change_event_id: state.change_event_id,
          settlement_event_id: row.id, trace_id: row.trace_id };
        const alert = this.recordStreamAlert("S-PIX-14", customerId,
          row.id, row.twin_ts, observed, 600);
        this.bank.db.prepare("DELETE FROM sentinel_stream_identity WHERE customer_id=?")
          .run(customerId);
        alerts.push(alert);
      }
      this.bank.db.prepare("UPDATE sentinel_stream_cursor SET last_id=? WHERE id=1")
        .run(lockedRows.at(-1)!.id);
    });
    if (this.bank.db.isTransaction) return alerts;
    const pending = this.bank.db.prepare(`SELECT o.event_id,o.rule_id,o.alert_id,o.incident_id,
      a.entity,o.observed_json,o.twin_ts
      FROM sentinel_stream_outbox o JOIN sentinel_alerts a ON a.id=o.alert_id
      WHERE o.published_at IS NULL ORDER BY o.event_id,o.rule_id LIMIT 100`).all() as
      { event_id: number; rule_id: "S-AUTH-08" | "S-PIX-14" | "S-PIX-15" | "S-PIX-16";
        alert_id: string; incident_id: string | null;
        entity: string; observed_json: string | null; twin_ts: string | null }[];
    for (const row of pending) {
      if (!this.events) break;
      try {
        if (!row.observed_json || !row.twin_ts) throw new Error("SENTINEL_STREAM_EVIDENCE_MISSING");
        const rule = RULES.find((candidate) => candidate.id === row.rule_id);
        if (!rule) throw new Error("SENTINEL_STREAM_RULE_MISSING");
        const behavioral = row.rule_id === "S-PIX-15";
        const revokedDevice = row.rule_id === "S-AUTH-08";
        const spiMismatch = row.rule_id === "S-PIX-16";
        const eventKey = row.rule_id !== "S-PIX-14" ?
          `sentinel-stream:${row.rule_id}:${row.event_id}` :
          `sentinel-stream:${row.event_id}`;
        const incidentKey = row.rule_id !== "S-PIX-14" ?
          `sentinel-stream:incident:${row.rule_id}:${row.event_id}` :
          `sentinel-stream:incident:${row.event_id}`;
        this.events.append({ round_id: null, ts: this.bank.realNow().toISOString(),
          twin_ts: row.twin_ts, type: "sentinel.alert",
          actor: { id: "sentinel-stream", role: "sentinel" }, area: rule.area,
          ...(row.incident_id ? { incident_id: row.incident_id } : {}),
          public_summary_pt: revokedDevice ? "Acesso aceito por aparelho revogado" :
            behavioral ? "Desvio comportamental em Pix" :
            spiMismatch ? "Telemetria SPI divergente da mensagem persistida" :
            "Sequência de dispositivo, limite e Pix alto",
          public: { alert_id: row.alert_id, rule_id: row.rule_id,
            severity: rule.severity,
            area: rule.area, pattern_label: row.rule_id },
          private: { entity: row.entity, observed: JSON.parse(row.observed_json),
            evidence_ref: `sentinel_alerts:${row.alert_id}` } },
        eventKey);
        if (row.incident_id) this.events.append({ round_id: null,
          ts: this.bank.realNow().toISOString(), twin_ts: row.twin_ts,
          type: "incident.opened", actor: { id: "sentinel-stream", role: "sentinel" },
          area: rule.area, incident_id: row.incident_id,
          public_summary_pt: revokedDevice ? "Incidente de aparelho revogado" :
            behavioral ? "Incidente de desvio comportamental em Pix" :
            spiMismatch ? "Incidente de divergência nas mensagens SPI" :
            "Incidente na sequência de Pix",
          public: { incident_id: row.incident_id,
            severity: rule.severity, area: rule.area,
            alert_count: 1, source: "sentinel" },
          private: { alert_id: row.alert_id } },
        incidentKey);
        this.bank.db.prepare(`UPDATE sentinel_stream_outbox SET published_at=?
          WHERE event_id=? AND rule_id=?`)
          .run(this.bank.realNow().toISOString(), row.event_id, row.rule_id);
      } catch { /* Keep the durable outbox row for the next stream poll. */ }
    }
    return alerts;
  }

  scan(sources?: SeparatedSentinelSources): SentinelAlert[] {
    if (this.bank.isSeparatedEcosystem && !sources)
      throw new Error("SEPARATED_SENTINEL_SOURCES_REQUIRED");
    const now = this.bank.now().toISOString();
    const newestPixRowid = (this.bank.db.prepare("SELECT COALESCE(MAX(rowid),0) n FROM pix_transfers")
      .get() as { n: number }).n;
    const alerts: SentinelAlert[] = [
      ...this.scanExternalSourceHealth(),
      ...this.scanAgentEvents("S-GW-08", false), ...this.scanAgentEvents("S-GW-09", false),
      ...this.scanAgentEvents("S-GW-12", true),
      ...this.scanRedactedTelemetry(), ...this.scanMedReviewOverdue(),
      ...this.scanMedInitiationOverdue(),
      ...this.scanMedPspRefundLate(),
      ...this.scanQuotaPauses(),
    ];
    for (const signal of [...this.candidates(sources), ...this.delayedAutomaticPix()]) {
      const rule = RULES.find((item) => item.id === signal.ruleId)!;
      const producer = (Object.keys(PRODUCER_HEALTH_RULES) as MonitoredProducer[])
        .find((source) => PRODUCER_HEALTH_RULES[source] === rule.id);
      const clock = rule.id === "S-GW-07" || rule.id === "S-GW-10" ||
        rule.id === "S-LED-11" || rule.id === "S-LED-12" || rule.id === "S-PIX-43" || producer ?
        this.bank.realNow() : this.bank.now();
      const now = clock.toISOString();
      const prior = this.bank.db.prepare(`SELECT id,first_seen,last_emitted,count,
        json_extract(observed_json,'$.kind') AS observed_kind FROM sentinel_alerts
        WHERE rule_id=? AND entity=?`).get(rule.id, signal.entity) as
        { id: string; first_seen: string; last_emitted: string; count: number;
          observed_kind: string | null } | undefined;
      const id = prior?.id ?? newId("alert", this.bank.now().getTime());
      const count = (prior?.count ?? 0) + 1;
      const stageChanged = rule.id === "S-LED-12" && prior &&
        prior.observed_kind !== signal.observed.kind;
      const emit = !prior || stageChanged || clock.getTime() - Date.parse(prior.last_emitted) >= 60_000;
      this.bank.db.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(rule_id,entity) DO UPDATE SET observed_json=excluded.observed_json,
        last_seen=excluded.last_seen,count=excluded.count,last_emitted=excluded.last_emitted`)
        .run(id, rule.id, signal.entity, JSON.stringify(signal.observed), signal.windowS,
          prior?.first_seen ?? now, now, count, emit ? now : prior!.last_emitted);
      if (!emit) {
        if (rule.id === "S-PIX-03" && typeof signal.observed.transfer_id === "string") {
          const entityKey = this.incidentEntity(signal.entity);
          const cutoff = new Date(this.bank.now().getTime() - 10 * 60_000).toISOString();
          const active = this.bank.db.prepare(`SELECT id FROM sentinel_incidents
            WHERE entity_key=? AND state<>'resolved' AND last_seen_at>=?
            ORDER BY last_seen_at DESC LIMIT 1`).get(entityKey, cutoff) as
            { id: string } | undefined;
          if (active) this.bank.db.prepare(`INSERT OR IGNORE INTO sentinel_incident_transfer_evidence
            VALUES (?,?,?,?)`).run(active.id, signal.observed.transfer_id,
              `sentinel_alerts:${id}`, now);
        }
        continue;
      }
      const alert: SentinelAlert = { alert_id: id, rule_id: rule.id, area: rule.area, severity: rule.severity,
        entity: signal.entity, observed: signal.observed, window_s: signal.windowS,
        first_seen: prior?.first_seen ?? now, last_seen: now, count,
        evidence_ref: `sentinel_alerts:${id}` };
      alerts.push(alert);
      this.bank.telemetry.emit({ source: "siem", category: rule.area, action: "alert",
        outcome: "failure", severity: rule.severity === "critical" ? "error" : "warn",
        ruleId: rule.id,
        ...(!["S-PIX-08", "S-PIX-09"].includes(rule.id) ? { counterparty: signal.entity } : {}),
        message: rule.id === "S-GW-10" ? "Risk telemetry heartbeat missing" :
          producer ? `${producer} telemetry heartbeat missing` :
            `Sentinel ${rule.id} detected a pattern` });
      this.events?.append({ round_id: null, ts: new Date().toISOString(), twin_ts: this.bank.now().toISOString(),
        type: "sentinel.alert", actor: { id: `sentinel-${rule.area}`, role: "sentinel" }, area: rule.area,
        public_summary_pt: rule.id === "S-GW-10" ? "Fonte de risco sem heartbeat" :
          (producer ? PRODUCER_HEALTH_SUMMARIES[producer] :
            `${rule.id}: padrão detectado`), public: { alert_id: id, rule_id: rule.id,
          severity: rule.severity, area: rule.area, pattern_label: rule.id },
        private: { entity: signal.entity, observed: signal.observed, evidence_ref: alert.evidence_ref } });
      this.openIncident(alert);
    }
    for (const area of AREAS) {
      const prior = this.bank.db.prepare("SELECT window_counters_summary FROM sentinel_state WHERE area=?")
        .get(area) as { window_counters_summary: string } | undefined;
      const checks = Number((JSON.parse(prior?.window_counters_summary ?? "{}") as { checks_total?: number }).checks_total ?? 0) +
        RULES.filter((rule) => rule.area === area &&
          !["S-AUTH-08", "S-PIX-14", "S-PIX-15"].includes(rule.id)).length;
      this.bank.db.prepare(`INSERT INTO sentinel_state VALUES (?,?,?,?) ON CONFLICT(area) DO UPDATE SET
        last_tick_at=excluded.last_tick_at,window_counters_summary=excluded.window_counters_summary`)
        .run(area, now, "v1", JSON.stringify({ checks_total: checks }));
    }
    this.bank.db.prepare(`INSERT INTO sentinel_pix_cursor VALUES (1,?)
      ON CONFLICT(id) DO UPDATE SET last_rowid=excluded.last_rowid`).run(newestPixRowid);
    this.lastPixRowid = newestPixRowid;
    this.bootstrapPixSince = undefined;
    this.triage.escalateDue();
    return alerts;
  }
  recentAlerts(limit = 20): SentinelAlert[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("SENTINEL_ALERT_LIMIT_INVALID");
    const since = new Date(this.bank.now().getTime() - 86_400_000).toISOString();
    const rows = this.bank.db.prepare(`SELECT id,rule_id,entity,observed_json,window_s,
      first_seen,last_seen,count FROM sentinel_alerts WHERE last_seen>=?
      AND rule_id IN (SELECT value FROM json_each(?))
      ORDER BY last_seen DESC,id DESC LIMIT ?`)
      .all(since, JSON.stringify(RULES.map((rule) => rule.id)), limit) as
      { id: string; rule_id: string; entity: string; observed_json: string;
        window_s: number; first_seen: string; last_seen: string; count: number }[];
    return rows.flatMap((row) => {
      const rule = RULES.find((item) => item.id === row.rule_id);
      if (!rule) return [];
      return [{ alert_id: row.id, rule_id: row.rule_id, area: rule.area,
        severity: rule.severity, entity: row.entity,
        observed: JSON.parse(row.observed_json) as Record<string, number | string>,
        window_s: row.window_s, first_seen: row.first_seen, last_seen: row.last_seen,
        count: row.count, evidence_ref: `sentinel_alerts:${row.id}` }];
    });
  }
  recentIncidents(limit = 20): SentinelIncident[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("SENTINEL_INCIDENT_LIMIT_INVALID");
    const since = new Date(this.bank.now().getTime() - 86_400_000).toISOString();
    return this.bank.db.prepare(`SELECT id,entity_key,area,severity,state,alert_count,opened_at,last_seen_at
      FROM sentinel_incidents WHERE state<>'resolved' OR last_seen_at>=?
      ORDER BY CASE WHEN state='resolved' THEN 1 ELSE 0 END,last_seen_at DESC,id DESC LIMIT ?`)
      .all(since, limit) as unknown as SentinelIncident[];
  }
  telemetry(): Record<Area, SentinelSummary> {
    const now = this.bank.now();
    const since = new Date(now.getTime() - 86_400_000).toISOString();
    const recent = new Date(now.getTime() - 120_000).toISOString();
    return Object.fromEntries(AREAS.map((area) => {
      const row = this.bank.db.prepare("SELECT window_counters_summary FROM sentinel_state WHERE area=?")
        .get(area) as { window_counters_summary: string } | undefined;
      const counts = this.bank.db.prepare(`SELECT COUNT(*) alerts_24h,
        COALESCE(MAX(last_seen),'') last_seen FROM sentinel_alerts WHERE rule_id IN
        (SELECT value FROM json_each(?)) AND last_seen>=?`)
        .get(JSON.stringify(RULES.filter((rule) => rule.area === area).map((rule) => rule.id)), since) as
        { alerts_24h: number; last_seen: string };
      const checks = Number((JSON.parse(row?.window_counters_summary ?? "{}") as { checks_total?: number }).checks_total ?? 0);
      return [area, { state: counts.last_seen >= recent ? "alerting" : "ok",
        checks_total: checks, alerts_24h: counts.alerts_24h }];
    })) as Record<Area, SentinelSummary>;
  }
}
