import { test } from "node:test";
import assert from "node:assert/strict";
import { backup, DatabaseSync } from "node:sqlite";
import { chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { EventStore } from "../packages/event-store/src/index.ts";
import { LedgerAnchorStore } from "../apps/orchestrator/src/ledger-anchors.ts";
import { snapshotRound, verifySnapshot } from "../apps/orchestrator/src/snapshot.ts";
import { verifySnapshotRestore } from "../scripts/verify-snapshot-restore.mjs";

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-anchor-"));
  const bankPath = join(dir, "bank.sqlite");
  const eventsPath = join(dir, "events.sqlite");
  const bank = new Bank(bankPath);
  const events = new EventStore(eventsPath);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  return { dir, bank, events, bankPath, eventsPath,
    anchors: new LedgerAnchorStore(bank, events, join(dir, "ledger-anchors")) };
}

test("ledger anchor detects file changes, event changes and valid bank rollback", async () => {
  const state = setup();
  const { dir, bank, events, anchors, bankPath, eventsPath } = state;
  const baseline = anchors.verify();
  assert.equal(baseline.provenance, "baseline");
  const oldBankPath = join(dir, "old-bank.sqlite");
  try {
    await backup(bank.db, oldBankPath);
    bank.fund("acc_01M73YF000C4A1RJ5SMQ8CXNWH", 100);
    const checkpoint = anchors.checkpoint(true);
    assert.equal(checkpoint.sequence, 2);
    assert.ok(checkpoint.entry_rowid > baseline.entry_rowid);
    assert.equal(new LedgerAnchorStore(bank, events, anchors.directory).verify().anchor_hash,
      checkpoint.anchor_hash);
    const file = join(anchors.directory, "000000002.json");
    const original = readFileSync(file);
    chmodSync(file, 0o644);
    writeFileSync(file, original.toString().replace("checkpoint", "other-value"));
    assert.throws(() => anchors.verify(), /INTEGRITY_LEDGER_ANCHOR_FILE_MISMATCH/);
    const sentinels = new SentinelEngine(bank, events);
    sentinels.reportLedgerAnchorMismatch();
    assert.ok(sentinels.scan().some((alert) => alert.rule_id === "S-LED-02" &&
      alert.area === "ledger" && alert.entity === "ledger_anchor"));
    writeFileSync(file, original);
    chmodSync(file, 0o444);
    const changed = new DatabaseSync(eventsPath);
    try {
      changed.exec("DROP TRIGGER ledger_anchors_no_update");
      changed.prepare("UPDATE ledger_anchors SET entry_hash=? WHERE sequence=2")
        .run("f".repeat(64));
    } finally { changed.close(); }
    assert.throws(() => anchors.verify(), /INTEGRITY_LEDGER_ANCHOR_CHAIN/);
    const repaired = new DatabaseSync(eventsPath);
    try { repaired.prepare("UPDATE ledger_anchors SET entry_hash=? WHERE sequence=2")
      .run(checkpoint.entry_hash); }
    finally { repaired.close(); }
    assert.equal(anchors.verify().anchor_hash, checkpoint.anchor_hash);
  } finally { events.close(); bank.close(); }
  try {
    copyFileSync(oldBankPath, bankPath);
    const rolledBack = new Bank(bankPath);
    const anchorEvents = new EventStore(eventsPath);
    try {
      assert.equal(rolledBack.verifyLedgerChain(), true);
      assert.throws(() => new LedgerAnchorStore(rolledBack, anchorEvents, anchors.directory),
        /INTEGRITY_LEDGER_ANCHOR_HISTORY/);
    } finally { anchorEvents.close(); rolledBack.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("snapshot includes a checked external anchor and restore verifies it", async () => {
  const { dir, bank, events, anchors } = setup();
  try {
    const base = { round_id: "r01", ts: "2026-11-11T12:00:00.000Z",
      actor: { id: "harness", role: "system" } };
    events.append({ ...base, type: "round.started", public_summary_pt: "Start",
      public: { round_no: 1, budget_usd: 0.7, feature_ids_live: [], open_weaknesses_count: 17 } });
    events.append({ ...base, type: "round.ended", public_summary_pt: "End",
      public: { status: "completed", score: { red_points: 0, blue_points: 0,
        attacks_succeeded: 0, attacks_total: 0, mttd_s: null, mttr_s: null,
        honest_wrongly_blocked: 0, loss_cents: 0, restored_cents: 0 },
      summary_pt: "Done", duration_s: 1 } });
    bank.fund("acc_01M73YF000C4A1RJ5SMQ8CXNWH", 100);
    const checkpointAt = anchors.checkpointAt.bind(anchors);
    anchors.checkpointAt = (tip) => {
      bank.fund("acc_01M73YF000C4A1RJ5SMQ8CXNWH", 50);
      assert.equal(anchors.checkpoint(true).sequence, 1);
      return checkpointAt(tip);
    };
    const result = await snapshotRound({ bank, events, ledgerAnchors: anchors,
      root: join(dir, "snapshots"), roundId: "r01" });
    assert.equal(result.manifest.ledgerAnchor.provenance, "checkpoint");
    assert.equal(verifySnapshotRestore(result.path).ledgerAnchorHash,
      result.manifest.ledgerAnchor.anchorHash);
    const file = join(result.path, "ledger-anchors", "000000002.json");
    chmodSync(file, 0o644);
    writeFileSync(file, readFileSync(file, "utf8").replace("checkpoint", "altered"));
    assert.throws(() => verifySnapshot(result.path), /INTEGRITY_LEDGER_ANCHOR_FILE_MISMATCH/);
  } finally { events.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("startup checks every ledger entry even when the anchored tip is unchanged", () => {
  const { dir, bank, events, anchors } = setup();
  try {
    const tip = anchors.verify();
    bank.db.exec("DROP TRIGGER ledger_entries_no_update");
    bank.db.prepare("UPDATE ledger_entries SET kind='changed' WHERE rowid=(SELECT MIN(rowid) FROM ledger_entries)").run();
    assert.equal(anchors.verify().anchor_hash, tip.anchor_hash);
    assert.equal(bank.verifyLedgerChain(), false);
    assert.throws(() => new LedgerAnchorStore(bank, events, anchors.directory),
      /INTEGRITY_LEDGER_CHAIN_INVALID/);
  } finally { events.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
