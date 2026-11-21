import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Bank } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { EventStore } from "../packages/event-store/src/index.ts";
import { HourlyLedgerProofStore } from "../apps/orchestrator/src/hourly-ledger-proof.ts";

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-hourly-sentinel-"));
  let realMs = Date.parse("2026-11-18T12:30:00.000Z");
  let twinMs = realMs;
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date(twinMs),
    () => new Date(realMs));
  const events = new EventStore(join(dir, "events.sqlite"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  bank.db.exec(`CREATE TABLE runtime_clock (
    id INTEGER PRIMARY KEY CHECK(id=1), real_start_ms INTEGER NOT NULL,
    twin_start_ms INTEGER NOT NULL, speed REAL NOT NULL)`);
  bank.db.prepare("INSERT INTO runtime_clock VALUES (1,?,?,?)")
    .run(realMs, realMs, 1);
  const proofs = new HourlyLedgerProofStore(bank, events);
  const sentinels = new SentinelEngine(bank, events);
  return { bank, events, proofs, sentinels,
    advance(iso) { realMs = Date.parse(iso); twinMs = realMs; },
    advanceTwin(iso) { twinMs = Date.parse(iso); },
    close() { events.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("hourly proof detector stays quiet when a completed hour is published", () => {
  const env = fixture();
  try {
    assert.equal(env.sentinels.scan().some((alert) => alert.rule_id === "S-LED-11"), false);
    env.advance("2026-11-18T13:01:00.000Z");
    assert.equal(env.proofs.publishCompleted(), 1);
    env.advance("2026-11-18T13:05:00.000Z");
    assert.equal(env.sentinels.scan().some((alert) => alert.rule_id === "S-LED-11"), false);
    assert.equal(env.bank.db.prepare("SELECT COUNT(*) n FROM sentinel_alerts WHERE rule_id='S-LED-11'")
      .get().n, 0);
  } finally { env.close(); }
});

test("hourly proof detector waits until the persisted Twin deadline plus grace", () => {
  const env = fixture();
  try {
    env.advance("2026-11-18T13:04:59.000Z");
    assert.equal(env.sentinels.scan().some((alert) => alert.rule_id === "S-LED-11"), false);
    env.advance("2026-11-18T13:05:00.000Z");
    const alert = env.sentinels.scan().find((item) => item.rule_id === "S-LED-11");
    assert.ok(alert);
    assert.equal(alert.severity, "high");
    const observed = env.bank.db.prepare("SELECT observed_json FROM sentinel_alerts WHERE id=?")
      .get(alert.alert_id);
    assert.deepEqual(JSON.parse(observed.observed_json), {
      missing_hour_start: "2026-11-18T12:00:00.000Z",
      due_at: "2026-11-18T13:05:00.000Z", overdue_seconds: 0 });
    assert.ok(env.sentinels.recentIncidents().some((item) => item.area === "ledger"));
    assert.equal(env.proofs.publishCompleted(), 1);
    assert.equal(env.sentinels.scan().some((item) => item.rule_id === "S-LED-11"), false);
  } finally { env.close(); }
});

test("missing proof timing uses persisted accelerated Twin clock", () => {
  const env = fixture();
  try {
    const anchor = Date.parse("2026-11-18T12:30:00.000Z");
    env.bank.db.prepare("UPDATE runtime_clock SET speed=12 WHERE id=1").run();
    env.advance("2026-11-18T12:32:54.000Z");
    assert.equal(env.sentinels.scan().some((alert) => alert.rule_id === "S-LED-11"), false);
    env.advance("2026-11-18T12:32:55.000Z");
    assert.equal(anchor + 175_000 * 12,
      Date.parse("2026-11-18T13:05:00.000Z"));
    assert.ok(env.sentinels.scan().some((alert) => alert.rule_id === "S-LED-11"));
  } finally { env.close(); }
});

test("accelerated proof gap does not open repeated incidents within one real minute", () => {
  const env = fixture();
  try {
    env.bank.db.prepare("UPDATE runtime_clock SET speed=60 WHERE id=1").run();
    env.advance("2026-11-18T12:30:35.000Z");
    assert.ok(env.sentinels.scan().some((alert) => alert.rule_id === "S-LED-11"));
    env.advance("2026-11-18T12:30:50.000Z");
    env.advanceTwin("2026-11-18T12:45:50.000Z");
    assert.equal(env.sentinels.scan().some((alert) => alert.rule_id === "S-LED-11"), false);
    assert.equal(env.sentinels.recentIncidents().filter((item) =>
      item.area === "ledger").length, 1);
  } finally { env.close(); }
});
