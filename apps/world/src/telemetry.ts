import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { installTelemetryIntegrity, verifyTelemetryChain } from "./telemetry-integrity.ts";

export type TelemetrySource = "gateway" | "auth" | "pix" | "spi" | "dict" | "cards" |
  "network" | "ledger" | "risk" | "siem" | "agent";
export interface TelemetryEvent {
  id: number;
  ts: string;
  twin_ts: string;
  trace_id: string;
  span_id: string;
  source: TelemetrySource;
  category: string;
  action: string;
  outcome: "success" | "failure" | "unknown";
  severity: "info" | "warn" | "error";
  user_id: string | null;
  account_id: string | null;
  source_ip: string | null;
  device_id: string | null;
  session_id: string | null;
  user_agent: string | null;
  geo: string | null;
  amount_cents: number | null;
  counterparty: string | null;
  e2e_id: string | null;
  card_token: string | null;
  rule_id: string | null;
  risk_score: number | null;
  reason_codes_json: string | null;
  message: string;
  redacted: number;
}

interface TraceContext {
  traceId: string;
  userId?: string;
  deviceId?: string;
  sessionId?: string;
  sourceIp?: string;
  userAgent?: string;
  geo?: string;
}
const traceContext = new AsyncLocalStorage<TraceContext>();
function redact(value: string): string {
  if (/\b(?:password|senha|otp|cvv|pan)\s*[:=]/i.test(value)) return "[redacted]";
  return value.replace(/(?<![\w])(?:\d[ -]?){12,18}\d(?![\w])/g, "[redacted]")
    .replace(/(?<![\w])\d{3}\.?(?:\d{3})\.?(?:\d{3})-?\d{2}(?![\w])/g, "[redacted]");
}
export function withTrace<T>(traceId: string, work: () => T,
  context: Omit<TraceContext, "traceId"> = {}): T {
  const parent = traceContext.getStore();
  return traceContext.run({ ...(parent?.traceId === traceId ? parent : {}),
    traceId, ...context }, work);
}
export function currentTrace(): string | undefined { return traceContext.getStore()?.traceId; }
export function setTraceIdentity(identity: { userId: string; deviceId: string;
  sessionId: string; geo?: string }): void {
  const context = traceContext.getStore();
  if (context) Object.assign(context, identity);
}

export class TelemetryStore {
  private readonly db: DatabaseSync;
  private readonly now: () => Date;
  private readonly realNow: () => Date;
  constructor(db: DatabaseSync, now: () => Date, realNow: () => Date) {
    this.db = db;
    this.now = now;
    this.realNow = realNow;
    db.exec(`CREATE TABLE IF NOT EXISTS telemetry_events (
      id INTEGER PRIMARY KEY, ts TEXT NOT NULL, twin_ts TEXT NOT NULL,
      trace_id TEXT NOT NULL, span_id TEXT NOT NULL, source TEXT NOT NULL,
      category TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL,
      severity TEXT NOT NULL, user_id TEXT, account_id TEXT, source_ip TEXT,
      device_id TEXT, session_id TEXT, user_agent TEXT, geo TEXT,
      amount_cents INTEGER, counterparty TEXT, e2e_id TEXT, message TEXT NOT NULL,
      redacted INTEGER NOT NULL DEFAULT 0, risk_score INTEGER, reason_codes_json TEXT,
      card_token TEXT, rule_id TEXT
    );
    CREATE INDEX IF NOT EXISTS telemetry_trace ON telemetry_events(trace_id,id);
    CREATE INDEX IF NOT EXISTS telemetry_source_time ON telemetry_events(source,ts);`);
    const columns = db.prepare("PRAGMA table_info(telemetry_events)").all() as { name: string }[];
    if (!columns.some((column) => column.name === "redacted"))
      db.exec("ALTER TABLE telemetry_events ADD COLUMN redacted INTEGER NOT NULL DEFAULT 0");
    if (!columns.some((column) => column.name === "e2e_id"))
      db.exec("ALTER TABLE telemetry_events ADD COLUMN e2e_id TEXT");
    if (!columns.some((column) => column.name === "risk_score"))
      db.exec("ALTER TABLE telemetry_events ADD COLUMN risk_score INTEGER");
    if (!columns.some((column) => column.name === "reason_codes_json"))
      db.exec("ALTER TABLE telemetry_events ADD COLUMN reason_codes_json TEXT");
    for (const column of ["device_id", "session_id", "user_agent", "geo",
      "card_token", "rule_id"]) {
      if (!columns.some((existing) => existing.name === column))
        db.exec(`ALTER TABLE telemetry_events ADD COLUMN ${column} TEXT`);
    }
    db.exec("CREATE INDEX IF NOT EXISTS telemetry_redacted ON telemetry_events(redacted,id)");
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_session_activity
      ON telemetry_events(session_id,user_id,device_id,id) WHERE session_id IS NOT NULL`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_device_activity
      ON telemetry_events(device_id,twin_ts,id) WHERE device_id IS NOT NULL`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_key_deregister_window
      ON telemetry_events(twin_ts,user_id)
      WHERE source='dict' AND action='key_deregister' AND outcome='success'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_claim_complete_window
      ON telemetry_events(twin_ts,user_id)
      WHERE source='dict' AND action='claim_complete' AND outcome='success'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_dict_resolve_window
      ON telemetry_events(twin_ts,session_id,counterparty)
      WHERE source='dict' AND action='resolve_key' AND outcome='success'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_card_network_declines
      ON telemetry_events(twin_ts,card_token,counterparty)
      WHERE source='network' AND action='mti_0110' AND outcome='failure'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_card_network_actions
      ON telemetry_events(action,twin_ts,card_token,counterparty)
      WHERE source='network' AND outcome='success'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_pix_returns_window
      ON telemetry_events(twin_ts,account_id)
      WHERE source='pix' AND action='return' AND outcome='success'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_med_resolve_window
      ON telemetry_events(twin_ts,account_id)
      WHERE source='pix' AND action='med_resolve' AND outcome='success'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_cautelar_release_window
      ON telemetry_events(twin_ts,account_id)
      WHERE source='pix' AND category='cautelar' AND action='release'
        AND outcome='success'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_automatic_authorizations
      ON telemetry_events(action,twin_ts,user_id)
      WHERE source='pix' AND category='automatic' AND outcome='success'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_automatic_failures
      ON telemetry_events(action,twin_ts,user_id)
      WHERE source='pix' AND category='automatic' AND outcome='failure'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_risk_decisions_window
      ON telemetry_events(twin_ts,trace_id)
      WHERE source='risk' AND action='decision'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_risk_matches_window
      ON telemetry_events(twin_ts,trace_id)
      WHERE source='risk' AND action='rule_match'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_ledger_posts_window
      ON telemetry_events(twin_ts,counterparty)
      WHERE source='ledger' AND action='post' AND outcome='success'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_agent_mirror_window
      ON telemetry_events(twin_ts,id)
      WHERE source='agent'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_siem_alert_window
      ON telemetry_events(twin_ts,id)
      WHERE source='siem' AND action='alert'`);
    db.exec(`CREATE INDEX IF NOT EXISTS telemetry_health_window ON telemetry_events(ts)
      WHERE category='health' AND action='heartbeat'`);
    installTelemetryIntegrity(db);
  }
  emit(input: { source: TelemetrySource; category: string; action: string;
    outcome: TelemetryEvent["outcome"]; severity?: TelemetryEvent["severity"];
    userId?: string; accountId?: string; sourceIp?: string; amountCents?: number;
    deviceId?: string; sessionId?: string; userAgent?: string; geo?: string;
    counterparty?: string; e2eId?: string; cardToken?: string; ruleId?: string;
    riskScore?: number;
    reasonCodes?: string[]; message: string }): string {
    if (input.amountCents !== undefined && !Number.isSafeInteger(input.amountCents))
      throw new Error("TELEMETRY_AMOUNT_INVALID");
    if (input.e2eId !== undefined && !/^E\d{8}\d{12}[A-Z0-9]{11}$/.test(input.e2eId))
      throw new Error("TELEMETRY_E2E_INVALID");
    if (input.cardToken !== undefined && !/^card_[A-Za-z0-9_-]{1,95}$/.test(input.cardToken))
      throw new Error("TELEMETRY_CARD_TOKEN_INVALID");
    if (input.ruleId !== undefined && !/^[A-Z0-9_-]{1,64}$/.test(input.ruleId))
      throw new Error("TELEMETRY_RULE_INVALID");
    if (input.riskScore !== undefined && (!Number.isSafeInteger(input.riskScore) ||
      input.riskScore < 0 || input.riskScore > 1000)) throw new Error("TELEMETRY_RISK_INVALID");
    if (input.reasonCodes && (input.reasonCodes.length > 20 ||
      input.reasonCodes.some((code) => !/^[A-Z0-9_-]{1,64}$/.test(code))))
      throw new Error("TELEMETRY_REASONS_INVALID");
    const category = redact(input.category);
    const action = redact(input.action);
    const message = redact(input.message);
    const context = traceContext.getStore();
    const rawUserId = input.userId ?? context?.userId;
    const rawSourceIp = input.sourceIp ?? context?.sourceIp;
    const rawDeviceId = input.deviceId ?? context?.deviceId;
    const rawSessionId = input.sessionId ?? context?.sessionId;
    const rawUserAgent = input.userAgent ?? context?.userAgent;
    const rawGeo = input.geo ?? context?.geo;
    const userId = rawUserId ? redact(rawUserId) : null;
    const accountId = input.accountId ? redact(input.accountId) : null;
    const sourceIp = rawSourceIp ? redact(rawSourceIp) : null;
    const deviceId = rawDeviceId ? redact(rawDeviceId) : null;
    const sessionId = rawSessionId ? redact(rawSessionId) : null;
    const userAgent = rawUserAgent ? redact(rawUserAgent.slice(0, 256)) : null;
    const geo = rawGeo ? redact(rawGeo.slice(0, 100)) : null;
    const counterparty = input.counterparty ? redact(input.counterparty) : null;
    const wasRedacted = category !== input.category || action !== input.action ||
      message !== input.message || userId !== (rawUserId ?? null) ||
      accountId !== (input.accountId ?? null) || sourceIp !== (rawSourceIp ?? null) ||
      deviceId !== (rawDeviceId ?? null) || sessionId !== (rawSessionId ?? null) ||
      userAgent !== (rawUserAgent ? rawUserAgent.slice(0, 256) : null) ||
      geo !== (rawGeo ? rawGeo.slice(0, 100) : null) ||
      counterparty !== (input.counterparty ?? null);
    const traceId = context?.traceId ?? randomUUID();
    this.db.prepare(`INSERT INTO telemetry_events (ts,twin_ts,trace_id,span_id,source,category,
      action,outcome,severity,user_id,account_id,source_ip,device_id,session_id,user_agent,geo,
      amount_cents,counterparty,e2e_id,message,redacted,risk_score,reason_codes_json,
      card_token,rule_id)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(this.realNow().toISOString(),
      this.now().toISOString(), traceId, randomUUID(), input.source, category,
      action, input.outcome, wasRedacted ? "warn" : input.severity ?? "info", userId,
      accountId, sourceIp, deviceId, sessionId, userAgent, geo,
      input.amountCents ?? null, counterparty, input.e2eId ?? null, message,
      Number(wasRedacted), input.riskScore ?? null,
      input.reasonCodes ? JSON.stringify(input.reasonCodes) : null,
      input.cardToken ?? null, input.ruleId ?? null);
    return traceId;
  }
  trace(traceId: string): TelemetryEvent[] {
    if (!/^[a-zA-Z0-9_-]{1,100}$/.test(traceId)) return [];
    return this.db.prepare("SELECT * FROM telemetry_events WHERE trace_id=? ORDER BY id LIMIT 500")
      .all(traceId) as unknown as TelemetryEvent[];
  }
  list(after = 0, limit = 200): TelemetryEvent[] {
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 500)
      throw new Error("TELEMETRY_PAGE_INVALID");
    return this.db.prepare("SELECT * FROM telemetry_events WHERE id>? ORDER BY id LIMIT ?")
      .all(after, limit) as unknown as TelemetryEvent[];
  }
  latest(limit = 1000): TelemetryEvent[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
      throw new Error("TELEMETRY_PAGE_INVALID");
    return (this.db.prepare("SELECT * FROM telemetry_events ORDER BY id DESC LIMIT ?")
      .all(limit) as unknown as TelemetryEvent[]).reverse();
  }
  isTransactionOpen(): boolean { return this.db.isTransaction; }
  verifyChain(): boolean { return verifyTelemetryChain(this.db); }
}

export class TelemetryStream {
  private readonly store: TelemetryStore;
  private readonly ring: TelemetryEvent[];
  private readonly listeners = new Set<(event: TelemetryEvent) => void>();
  private cursor: number;
  private readonly timer: NodeJS.Timeout;
  constructor(store: TelemetryStore, pollMs = 1000) {
    this.store = store;
    this.ring = store.latest();
    this.cursor = this.ring.at(-1)?.id ?? 0;
    this.timer = setInterval(() => this.poll(), pollMs);
    this.timer.unref();
  }
  private poll(): void {
    if (this.store.isTransactionOpen()) return;
    while (true) {
      const batch = this.store.list(this.cursor, 500);
      for (const event of batch) {
        this.cursor = event.id;
        this.ring.push(event);
        if (this.ring.length > 1000) this.ring.shift();
        for (const listener of this.listeners) {
          try { listener(event); } catch { this.listeners.delete(listener); }
        }
      }
      if (batch.length < 500) break;
    }
  }
  recent(): TelemetryEvent[] { return [...this.ring]; }
  subscribe(listener: (event: TelemetryEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  close(): void { clearInterval(this.timer); this.listeners.clear(); }
}
