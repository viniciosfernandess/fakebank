import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { verifyTelemetryChain, verifyTelemetryTail } from
  "../apps/world/src/telemetry-integrity.ts";
import { RiskShadowWatchdog } from "./risk-shadow-watchdog.mjs";

const MAX_SILENCE_MS = 15_000;
const VOLUME_WINDOW_MS = 20_000;
const SEAL_CHECK_MS = 30_000;
const PRODUCER_SILENCE_MS = 30_000;
const PRODUCERS = ["gateway", "auth", "risk", "cards", "pix", "spi", "dict", "ledger"];

function canonicalCanaryPixKey(value) {
  if (typeof value !== "string") return null;
  if (/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@.]{2,}$/.test(value))
    return value.toLowerCase();
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value))
    return value.toLowerCase();
  return null;
}

export class SourceHealthWatchdog {
  constructor(dataDir, now = () => Date.now()) {
    this.bankPath = join(dataDir, "bank.sqlite");
    this.now = now;
    this.outbox = new DatabaseSync(join(dataDir, "source-health.sqlite"), { timeout: 1000 });
    this.outbox.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS source_health_alerts (
        id INTEGER PRIMARY KEY, code TEXT NOT NULL, source TEXT NOT NULL,
        observed_at TEXT NOT NULL, details_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS source_health_conditions (
        code TEXT NOT NULL, source TEXT NOT NULL, active INTEGER NOT NULL,
        PRIMARY KEY(code,source)
      );
      CREATE TABLE IF NOT EXISTS canary_accounts (
        account_id TEXT PRIMARY KEY, active_after_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_cards (
        card_id TEXT PRIMARY KEY, active_after_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_credentials (
        customer_id TEXT PRIMARY KEY, active_after_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_cursor (
        id INTEGER PRIMARY KEY CHECK(id=1), last_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_pix_keys (
        key_hash TEXT PRIMARY KEY, active_after_rowid INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_key_cursor (
        id INTEGER PRIMARY KEY CHECK(id=1), last_rowid INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_triggered_traces (
        kind TEXT NOT NULL, trace_id TEXT NOT NULL,
        PRIMARY KEY(kind,trace_id)
      );`);
    this.riskShadow = new RiskShadowWatchdog(this.outbox, (code, details) =>
      this.report(code, "risk", details));
    this.lastId = undefined;
    this.firstSeenAt = undefined;
    this.lastSealCheckAt = 0;
    this.fullSealOk = true;
    this.lastProducerHeartbeat = new Map();
    this.producerBaselineLoaded = false;
  }

  report(code, source, details = {}) {
    const prior = this.outbox.prepare(`SELECT active FROM source_health_conditions
      WHERE code=? AND source=?`).get(code, source);
    if (prior?.active) return;
    const observedAt = new Date(this.now()).toISOString();
    this.outbox.exec("BEGIN IMMEDIATE");
    try {
      this.outbox.prepare(`INSERT INTO source_health_alerts(code,source,observed_at,details_json)
        VALUES (?,?,?,?)`).run(code, source, observedAt, JSON.stringify(details));
      this.outbox.prepare(`INSERT INTO source_health_conditions VALUES (?,?,1)
        ON CONFLICT(code,source) DO UPDATE SET active=1`).run(code, source);
      this.outbox.exec("COMMIT");
    } catch (error) { this.outbox.exec("ROLLBACK"); throw error; }
    console.error(`source health alert: ${code} (${source})`);
  }

  resolve(code, source) {
    this.outbox.prepare(`UPDATE source_health_conditions SET active=0
      WHERE code=? AND source=?`).run(code, source);
  }

  registerCanaryAccount(accountId) {
    if (typeof accountId !== "string" || !/^acc_[A-Za-z0-9_-]{1,95}$/.test(accountId))
      throw new Error("CANARY_ACCOUNT_INVALID");
    const bank = new DatabaseSync(this.bankPath, { readOnly: true, timeout: 1000 });
    try {
      const account = bank.prepare(`SELECT kind FROM accounts WHERE id=?`).get(accountId);
      if (!account || account.kind === "system") throw new Error("CANARY_ACCOUNT_INVALID");
      const afterId = bank.prepare(`SELECT COALESCE(MAX(id),0) id FROM telemetry_events`).get().id;
      this.outbox.exec("BEGIN IMMEDIATE");
      try {
        this.outbox.prepare(`INSERT INTO canary_accounts VALUES (?,?)`).run(accountId, afterId);
        this.outbox.prepare(`INSERT OR IGNORE INTO canary_cursor VALUES (1,?)`).run(afterId);
        this.outbox.exec("COMMIT");
      } catch (error) { this.outbox.exec("ROLLBACK"); throw error; }
    } finally { bank.close(); }
  }

  registerCanaryCard(cardId) {
    if (typeof cardId !== "string" || !/^card_[A-Za-z0-9_-]{1,95}$/.test(cardId))
      throw new Error("CANARY_CARD_INVALID");
    const bank = new DatabaseSync(this.bankPath, { readOnly: true, timeout: 1000 });
    try {
      if (!bank.prepare(`SELECT 1 FROM cards WHERE id=?`).get(cardId))
        throw new Error("CANARY_CARD_INVALID");
      const afterId = bank.prepare(`SELECT COALESCE(MAX(id),0) id FROM telemetry_events`).get().id;
      this.outbox.exec("BEGIN IMMEDIATE");
      try {
        this.outbox.prepare(`INSERT INTO canary_cards VALUES (?,?)`).run(cardId, afterId);
        this.outbox.prepare(`INSERT OR IGNORE INTO canary_cursor VALUES (1,?)`).run(afterId);
        this.outbox.exec("COMMIT");
      } catch (error) { this.outbox.exec("ROLLBACK"); throw error; }
    } finally { bank.close(); }
  }

  registerCanaryCredential(customerId) {
    if (typeof customerId !== "string" || !/^cus_[A-Za-z0-9_-]{1,95}$/.test(customerId))
      throw new Error("CANARY_CREDENTIAL_INVALID");
    const bank = new DatabaseSync(this.bankPath, { readOnly: true, timeout: 1000 });
    try {
      if (!bank.prepare(`SELECT 1 FROM customers WHERE id=?`).get(customerId))
        throw new Error("CANARY_CREDENTIAL_INVALID");
      const afterId = bank.prepare(`SELECT COALESCE(MAX(id),0) id FROM telemetry_events`).get().id;
      this.outbox.exec("BEGIN IMMEDIATE");
      try {
        this.outbox.prepare(`INSERT INTO canary_credentials VALUES (?,?)`).run(customerId, afterId);
        this.outbox.prepare(`INSERT OR IGNORE INTO canary_cursor VALUES (1,?)`).run(afterId);
        this.outbox.exec("COMMIT");
      } catch (error) { this.outbox.exec("ROLLBACK"); throw error; }
    } finally { bank.close(); }
  }

  registerCanaryPixKey(key) {
    const normalized = canonicalCanaryPixKey(key);
    if (!normalized)
      throw new Error("CANARY_PIX_KEY_INVALID");
    const bank = new DatabaseSync(this.bankPath, { readOnly: true, timeout: 1000 });
    try {
      const afterRowid = bank.prepare(`SELECT COALESCE(MAX(rowid),0) id
        FROM pix_lookup_attempts`).get().id;
      const hash = createHash("sha256").update(normalized).digest("hex");
      this.outbox.exec("BEGIN IMMEDIATE");
      try {
        this.outbox.prepare(`INSERT INTO canary_pix_keys VALUES (?,?)`).run(hash, afterRowid);
        this.outbox.prepare(`INSERT OR IGNORE INTO canary_key_cursor VALUES (1,?)`)
          .run(afterRowid);
        this.outbox.exec("COMMIT");
      } catch (error) { this.outbox.exec("ROLLBACK"); throw error; }
    } finally { bank.close(); }
  }

  scanCanaryPixKeys(bank) {
    const targets = this.outbox.prepare(`SELECT key_hash,active_after_rowid
      FROM canary_pix_keys`).all();
    if (!targets.length) return;
    const cursor = this.outbox.prepare(`SELECT last_rowid FROM canary_key_cursor WHERE id=1`)
      .get()?.last_rowid ?? 0;
    const rows = bank.prepare(`SELECT rowid id,key_hash FROM pix_lookup_attempts
      WHERE rowid>? ORDER BY rowid LIMIT 1000`).all(cursor);
    if (!rows.length) return;
    const registered = new Map(targets.map((target) =>
      [target.key_hash, target.active_after_rowid]));
    this.outbox.exec("BEGIN IMMEDIATE");
    try {
      for (const row of rows) {
        if (row.id <= (registered.get(row.key_hash) ?? Number.MAX_SAFE_INTEGER)) continue;
        this.outbox.prepare(`INSERT INTO source_health_alerts
          (code,source,observed_at,details_json) VALUES ('canary_touch','canary',?,?)`)
          .run(new Date(this.now()).toISOString(),
            JSON.stringify({ lookup_rowid: row.id, kind: "PIX_KEY" }));
      }
      this.outbox.prepare(`INSERT INTO canary_key_cursor VALUES (1,?)
        ON CONFLICT(id) DO UPDATE SET last_rowid=excluded.last_rowid`).run(rows.at(-1).id);
      this.outbox.exec("COMMIT");
    } catch (error) { this.outbox.exec("ROLLBACK"); throw error; }
  }

  scanCanaryAccounts(bank) {
    const targets = this.outbox.prepare(`SELECT account_id,active_after_id
      FROM canary_accounts`).all();
    const cards = this.outbox.prepare(`SELECT card_id,active_after_id
      FROM canary_cards`).all();
    const credentials = this.outbox.prepare(`SELECT customer_id,active_after_id
      FROM canary_credentials`).all();
    if (!targets.length && !cards.length && !credentials.length) return;
    const cursor = this.outbox.prepare(`SELECT last_id FROM canary_cursor WHERE id=1`).get()?.last_id ?? 0;
    const rows = bank.prepare(`SELECT id,trace_id,source,category,action,outcome,user_id,account_id,
      counterparty,card_token
      FROM telemetry_events WHERE id>? ORDER BY id LIMIT 1000`).all(cursor);
    if (!rows.length) return;
    const registered = new Map(targets.map((target) => [target.account_id, target.active_after_id]));
    const registeredCards = new Map(cards.map((card) => [card.card_id, card.active_after_id]));
    const registeredCredentials = new Map(credentials.map((credential) =>
      [credential.customer_id, credential.active_after_id]));
    this.outbox.exec("BEGIN IMMEDIATE");
    try {
      for (const row of rows) {
        const touched = [row.account_id];
        if (row.source === "pix" && row.action === "settle" ||
          row.source === "risk" && row.category === "pix" &&
            row.action === "decision" ||
          row.source === "dict" && row.action === "resolve_key")
          touched.push(row.counterparty);
        const accountTouch = row.category !== "health" && touched.some((id) =>
          row.id > (registered.get(id) ?? Number.MAX_SAFE_INTEGER));
        const cardTouch = row.category !== "health" &&
          row.id > (registeredCards.get(row.card_token) ?? Number.MAX_SAFE_INTEGER);
        const credentialTouch = row.source === "auth" && row.category !== "health" &&
          row.id > (registeredCredentials.get(row.user_id) ?? Number.MAX_SAFE_INTEGER);
        if (!accountTouch && !cardTouch && !credentialTouch) continue;
        const kind = credentialTouch ? "CREDENTIAL" : cardTouch ? "CARD" : "ACCOUNT";
        if (row.trace_id && !this.outbox.prepare(`INSERT OR IGNORE INTO canary_triggered_traces
          VALUES (?,?)`).run(kind, row.trace_id).changes) continue;
        this.outbox.prepare(`INSERT INTO source_health_alerts
          (code,source,observed_at,details_json) VALUES ('canary_touch','canary',?,?)`)
          .run(new Date(this.now()).toISOString(), JSON.stringify({ telemetry_id: row.id,
            kind }));
      }
      this.outbox.prepare(`INSERT INTO canary_cursor VALUES (1,?)
        ON CONFLICT(id) DO UPDATE SET last_id=excluded.last_id`).run(rows.at(-1).id);
      this.outbox.exec("COMMIT");
    } catch (error) { this.outbox.exec("ROLLBACK"); throw error; }
  }

  tick() {
    const now = this.now();
    if (!existsSync(this.bankPath)) {
      if (this.firstSeenAt !== undefined)
        this.report("read_failure", "telemetry", { code: "BANK_FILE_MISSING" });
      return;
    }
    this.firstSeenAt ??= now;
    let bank;
    try {
      bank = new DatabaseSync(this.bankPath, { readOnly: true, timeout: 1000 });
      bank.exec("BEGIN");
      const table = bank.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='telemetry_events'`).get();
      if (!table) {
        if (now - this.firstSeenAt >= MAX_SILENCE_MS)
          this.report("read_failure", "telemetry", { code: "TELEMETRY_TABLE_MISSING" });
        return;
      }
      const newest = bank.prepare(`SELECT id,ts FROM telemetry_events ORDER BY id DESC LIMIT 1`).get();
      this.scanCanaryPixKeys(bank);
      if (!newest) {
        if (now - this.firstSeenAt >= MAX_SILENCE_MS)
          this.report("stream_silence", "telemetry", { last_id: 0 });
        return;
      }
      const latestMs = Date.parse(newest.ts);
      if (now - this.firstSeenAt >= MAX_SILENCE_MS &&
          (!Number.isFinite(latestMs) || now - latestMs > MAX_SILENCE_MS))
        this.report("stream_silence", "telemetry", { last_id: newest.id });
      else {
        this.resolve("stream_silence", "telemetry");
        this.resolve("process_exit", "bank");
      }

      if (Number.isFinite(latestMs) && now - latestMs <= MAX_SILENCE_MS) {
        if (!this.producerBaselineLoaded) {
          const knownHeartbeats = bank.prepare(`SELECT source,MAX(ts) ts
            FROM telemetry_events WHERE category='health' AND action='heartbeat'
            GROUP BY source`).all();
          for (const row of knownHeartbeats)
            if (PRODUCERS.includes(row.source))
              this.lastProducerHeartbeat.set(row.source, row.ts);
          this.producerBaselineLoaded = true;
        }
        const recentHeartbeats = bank.prepare(`SELECT source,MAX(ts) ts
          FROM telemetry_events INDEXED BY telemetry_health_window
          WHERE category='health' AND action='heartbeat' AND ts>=?
          GROUP BY source`).all(new Date(now - PRODUCER_SILENCE_MS).toISOString());
        for (const row of recentHeartbeats)
          if (PRODUCERS.includes(row.source))
            this.lastProducerHeartbeat.set(row.source, row.ts);
        for (const source of PRODUCERS) {
          const heartbeatAt = this.lastProducerHeartbeat.get(source);
          if (!heartbeatAt) continue;
          const lastAt = Date.parse(heartbeatAt);
          if (!Number.isFinite(lastAt) || now - lastAt > PRODUCER_SILENCE_MS)
            this.report("producer_silence", source, { last_heartbeat_at: heartbeatAt });
          else this.resolve("producer_silence", source);
        }
      }

      if (this.lastId !== undefined && newest.id !== this.lastId) {
        const count = bank.prepare(`SELECT COUNT(*) n FROM telemetry_events WHERE id>? AND id<=?`)
          .get(this.lastId, newest.id).n;
        if (newest.id < this.lastId || count !== newest.id - this.lastId)
          this.report("sequence_gap", "telemetry", { previous_id: this.lastId,
            last_id: newest.id, rows_seen: count });
        else this.resolve("sequence_gap", "telemetry");
      }
      this.lastId = newest.id;

      const recent = bank.prepare(`SELECT COUNT(*) n FROM telemetry_events
        WHERE category='health' AND action='heartbeat' AND ts>=?`)
        .get(new Date(now - VOLUME_WINDOW_MS).toISOString()).n;
      const previous = bank.prepare(`SELECT COUNT(*) n FROM telemetry_events
        WHERE category='health' AND action='heartbeat' AND ts>=? AND ts<?`)
        .get(new Date(now - 2 * VOLUME_WINDOW_MS).toISOString(),
          new Date(now - VOLUME_WINDOW_MS).toISOString()).n;
      if (previous >= 8 && recent <= 2 && recent * 4 < previous)
        this.report("volume_drop", "telemetry", { previous, recent });
      else this.resolve("volume_drop", "telemetry");

      const tailOk = verifyTelemetryTail(bank);
      if (now - this.lastSealCheckAt >= SEAL_CHECK_MS) {
        this.lastSealCheckAt = now;
        this.fullSealOk = verifyTelemetryChain(bank);
      }
      if (!tailOk || !this.fullSealOk)
        this.report("seal_broken", "telemetry", { last_id: newest.id });
      else this.resolve("seal_broken", "telemetry");
      this.riskShadow.scan(bank);
      this.scanCanaryAccounts(bank);
      this.resolve("read_failure", "telemetry");
    } catch (error) {
      if (now - this.firstSeenAt >= MAX_SILENCE_MS)
        this.report("read_failure", "telemetry", { code: String(error?.code || "READ_ERROR") });
    } finally {
      if (bank?.isTransaction) bank.exec("ROLLBACK");
      bank?.close();
    }
  }

  close() { this.outbox.close(); }
}
