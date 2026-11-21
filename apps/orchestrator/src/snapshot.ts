import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { DatabaseSync, backup } from "node:sqlite";
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parsePixLimits, type Bank } from "../../world/src/bank.ts";
import { verifyEventIntegrity, type EventStore } from "../../../packages/event-store/src/index.ts";
import { verifyLedgerChain } from "../../world/src/ledger-integrity.ts";
import { verifyTelemetryChain } from "../../world/src/telemetry-integrity.ts";
import type { SimulatorDeviceKeys } from "../../world/src/simulator-device-keys.ts";
import { ledgerTip, verifyLedgerAnchors, type LedgerAnchorStore } from "./ledger-anchors.ts";
import { verifyPeriodCloseAnchors, type PeriodCloseAnchorStore } from "./period-close-anchors.ts";
import { canaryExcludedCustomers } from "./canary-exclusions.ts";

export interface SnapshotManifest { roundId: string; createdAt: string; latestSeq: number;
  files: { events: string; bank: string; ecosystem?: string; simulator?: string;
    sourceHealth?: string };
  sha256: { events: string; bank: string; ecosystem?: string; simulator?: string;
    sourceHealth?: string };
  pixLimits?: { file: "pix-limits.json"; version: number; sha256: string };
  ledgerAnchor?: { directory: "ledger-anchors"; count: number; anchorHash: string;
    entryRowid: number; provenance: "baseline" | "checkpoint" };
  periodCloseAnchor?: { committed: number }; }
function check(path: string): void {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const result = db.prepare("PRAGMA integrity_check").get() as { integrity_check: string };
    if (result.integrity_check !== "ok") throw new Error("SNAPSHOT_INTEGRITY_FAILED");
  } finally { db.close(); }
}
function digest(path: string): string {
  const hash = createHash("sha256");
  const file = openSync(path, "r");
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const read = readSync(file, chunk, 0, chunk.length, null);
      if (!read) break;
      hash.update(chunk.subarray(0, read));
    }
    return hash.digest("hex");
  } finally { closeSync(file); }
}

export async function snapshotRound(input: { bank: Bank; events: EventStore; root: string;
  roundId: string; now?: () => Date; simulatorKeys?: SimulatorDeviceKeys;
  ecosystemSnapshot?: (destination: string) => Promise<void>;
  sourceHealthPath?: string;
  ledgerAnchors?: LedgerAnchorStore; periodCloseAnchors?: PeriodCloseAnchorStore }):
  Promise<{ path: string; manifest: SnapshotManifest }> {
  if (input.bank.isSeparatedEcosystem !== Boolean(input.ecosystemSnapshot))
    throw new Error("SNAPSHOT_ECOSYSTEM_OWNER_REQUIRED");
  if (!/^r\d{2}$/.test(input.roundId)) throw new Error("SNAPSHOT_INVALID_ROUND");
  const round = input.events.rounds().find((item) => item.round_id === input.roundId);
  if (!round || round.status === "started" || round.last_seq === null)
    throw new Error("SNAPSHOT_ROUND_NOT_CLOSED");
  if (!input.bank.verifyLedgerChain()) throw new Error("SNAPSHOT_LEDGER_CHAIN_INVALID");
  mkdirSync(input.root, { recursive: true });
  const stage = join(input.root, `.tmp-${input.roundId}-${randomUUID()}`);
  const destination = join(input.root, input.roundId);
  mkdirSync(stage, { mode: 0o700 });
  try {
    const eventsPath = join(stage, "events.sqlite");
    const bankPath = join(stage, "bank.sqlite");
    const sourceHealthPath = input.sourceHealthPath && existsSync(input.sourceHealthPath) ?
      join(stage, "source-health.sqlite") : undefined;
    const capture = async () => {
      input.periodCloseAnchors?.verify();
      if (input.sourceHealthPath) canaryExcludedCustomers(input.bank,
        input.sourceHealthPath, true);
      else if (input.bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
        AND name='runtime_external_registry_required'`).get())
        throw new Error("SNAPSHOT_CANARY_REGISTRY_MISSING");
      const registryLock = sourceHealthPath ? new DatabaseSync(input.sourceHealthPath!,
        { timeout: 5_000 }) : undefined;
      try {
        registryLock?.exec("BEGIN IMMEDIATE");
        if (sourceHealthPath) {
          const registry = new DatabaseSync(input.sourceHealthPath!, { readOnly: true });
          try { await backup(registry, sourceHealthPath); }
          finally { registry.close(); }
          chmodSync(sourceHealthPath, 0o600);
          check(sourceHealthPath);
        }
        await backup(input.bank.db, bankPath);
      } finally {
        if (registryLock?.isTransaction) registryLock.exec("ROLLBACK");
        registryLock?.close();
      }
      chmodSync(bankPath, 0o600);
      if (input.ecosystemSnapshot) {
        await input.ecosystemSnapshot(join(stage, "ecosystem.sqlite"));
        check(join(stage, "ecosystem.sqlite"));
      }
      const copiedBank = new DatabaseSync(bankPath, { readOnly: true });
      let snapshotTip: ReturnType<typeof ledgerTip>;
      try { snapshotTip = ledgerTip(copiedBank); }
      finally { copiedBank.close(); }
      if (input.ledgerAnchors) input.ledgerAnchors.checkpointAt(snapshotTip);
      await backup(input.events.db, eventsPath);
      chmodSync(eventsPath, 0o600);
      check(eventsPath); check(bankPath);
      const copiedEvents = new DatabaseSync(eventsPath, { readOnly: true });
      let anchor: ReturnType<typeof verifyLedgerAnchors> = null;
      let periodCloseCount: number | null = null;
      try {
        const latestSeq = (copiedEvents.prepare("SELECT COALESCE(MAX(seq),0) n FROM events").get() as
          { n: number }).n;
        if (input.ledgerAnchors) {
          const count = (copiedEvents.prepare("SELECT COUNT(*) n FROM ledger_anchors").get() as
            { n: number }).n;
          input.ledgerAnchors.copyFiles(join(stage, "ledger-anchors"), count);
          const anchoredBank = new DatabaseSync(bankPath, { readOnly: true });
          try { anchor = verifyLedgerAnchors(anchoredBank, copiedEvents,
            join(stage, "ledger-anchors")); }
          finally { anchoredBank.close(); }
          if (!anchor || anchor.entry_rowid !== snapshotTip.entry_rowid ||
            anchor.entry_hash !== snapshotTip.entry_hash)
            throw new Error("SNAPSHOT_LEDGER_ANCHOR_MISMATCH");
        }
        if (input.periodCloseAnchors) {
          const anchoredBank = new DatabaseSync(bankPath, { readOnly: true });
          try {
            periodCloseCount = verifyPeriodCloseAnchors(anchoredBank, copiedEvents,
              () => new Date(), "strict");
          } finally { anchoredBank.close(); }
        }
        return { latestSeq, anchor, periodCloseCount };
      } finally { copiedEvents.close(); }
    };
    const { latestSeq, anchor, periodCloseCount } = input.ledgerAnchors ?
      await input.ledgerAnchors.withSnapshotCopy(capture) : await capture();
    const simulatorPath = input.simulatorKeys ? join(stage, "simulator-device-keys.sqlite") : undefined;
    if (simulatorPath) {
      await backup(input.simulatorKeys!.db, simulatorPath);
      chmodSync(simulatorPath, 0o600);
      check(simulatorPath);
    }
    const pixLimits = input.bank.pixLimitsSnapshot();
    const limitsPath = join(stage, "pix-limits.json");
    writeFileSync(limitsPath, pixLimits.bytes);
    const manifest: SnapshotManifest = { roundId: input.roundId,
      createdAt: (input.now?.() ?? new Date()).toISOString(), latestSeq,
      pixLimits: { file: "pix-limits.json", version: pixLimits.version, sha256: digest(limitsPath) },
      ...(anchor ? { ledgerAnchor: { directory: "ledger-anchors" as const,
        count: anchor.sequence, anchorHash: anchor.anchor_hash,
        entryRowid: anchor.entry_rowid, provenance: anchor.provenance } } : {}),
      ...(periodCloseCount !== null ? { periodCloseAnchor: { committed: periodCloseCount } } : {}),
      files: { events: "events.sqlite", bank: "bank.sqlite",
        ...(input.ecosystemSnapshot ? { ecosystem: "ecosystem.sqlite" } : {}),
        ...(simulatorPath ? { simulator: "simulator-device-keys.sqlite" } : {}),
        ...(sourceHealthPath ? { sourceHealth: "source-health.sqlite" } : {}) },
      sha256: { events: digest(eventsPath), bank: digest(bankPath),
        ...(input.ecosystemSnapshot ? { ecosystem: digest(join(stage, "ecosystem.sqlite")) } : {}),
        ...(simulatorPath ? { simulator: digest(simulatorPath) } : {}),
        ...(sourceHealthPath ? { sourceHealth: digest(sourceHealthPath) } : {}) } };
    writeFileSync(join(stage, "manifest.json"), JSON.stringify(manifest, null, 2));
    verifySnapshot(stage);
    try { renameSync(stage, destination); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST" &&
        (error as NodeJS.ErrnoException).code !== "ENOTEMPTY") throw error;
      const existing = verifySnapshot(destination);
      if (existing.roundId !== input.roundId || existing.latestSeq !== manifest.latestSeq ||
        !existing.pixLimits || existing.pixLimits.sha256 !== manifest.pixLimits?.sha256 ||
        existing.sha256.ecosystem !== manifest.sha256.ecosystem ||
        existing.sha256.sourceHealth !== manifest.sha256.sourceHealth ||
        existing.ledgerAnchor?.anchorHash !== manifest.ledgerAnchor?.anchorHash ||
        existing.periodCloseAnchor?.committed !== manifest.periodCloseAnchor?.committed)
        throw new Error("SNAPSHOT_CONFLICT");
      rmSync(stage, { recursive: true, force: true });
      return { path: destination, manifest: existing };
    }
    return { path: destination, manifest };
  } catch (error) {
    rmSync(stage, { recursive: true, force: true });
    throw error;
  }
}

export function verifySnapshot(path: string): SnapshotManifest {
  const manifest = JSON.parse(readFileSync(join(path, "manifest.json"), "utf8")) as SnapshotManifest;
  if (!/^r\d{2}$/.test(manifest.roundId) || !Number.isSafeInteger(manifest.latestSeq))
    throw new Error("SNAPSHOT_MANIFEST_INVALID");
  if (Boolean(manifest.files.simulator) !== Boolean(manifest.sha256.simulator) ||
    (manifest.files.simulator !== undefined && manifest.files.simulator !== "simulator-device-keys.sqlite"))
    throw new Error("SNAPSHOT_MANIFEST_INVALID");
  if (Boolean(manifest.files.ecosystem) !== Boolean(manifest.sha256.ecosystem) ||
    (manifest.files.ecosystem !== undefined &&
      manifest.files.ecosystem !== "ecosystem.sqlite"))
    throw new Error("SNAPSHOT_MANIFEST_INVALID");
  if (Boolean(manifest.files.sourceHealth) !== Boolean(manifest.sha256.sourceHealth) ||
    (manifest.files.sourceHealth !== undefined &&
      manifest.files.sourceHealth !== "source-health.sqlite") ||
    (!manifest.files.sourceHealth && existsSync(join(path, "source-health.sqlite"))))
    throw new Error("SNAPSHOT_MANIFEST_INVALID");
  if (manifest.ledgerAnchor) {
    const anchor = manifest.ledgerAnchor;
    if (anchor.directory !== "ledger-anchors" || !Number.isSafeInteger(anchor.count) ||
      anchor.count < 1 || !Number.isSafeInteger(anchor.entryRowid) || anchor.entryRowid < 0 ||
      !/^[a-f0-9]{64}$/.test(anchor.anchorHash) ||
      !["baseline", "checkpoint"].includes(anchor.provenance))
      throw new Error("SNAPSHOT_MANIFEST_INVALID");
  } else if (existsSync(join(path, "ledger-anchors"))) {
    throw new Error("SNAPSHOT_LEDGER_ANCHOR_UNDECLARED");
  }
  if (manifest.periodCloseAnchor !== undefined &&
    (!manifest.periodCloseAnchor ||
      Object.keys(manifest.periodCloseAnchor).length !== 1 ||
      !Number.isSafeInteger(manifest.periodCloseAnchor.committed) ||
      manifest.periodCloseAnchor.committed < 0))
    throw new Error("SNAPSHOT_MANIFEST_INVALID");
  if (manifest.pixLimits !== undefined) {
    const policy = manifest.pixLimits;
    if (!policy || typeof policy !== "object" || Object.keys(policy).length !== 3 ||
      policy.file !== "pix-limits.json" || policy.version !== 1 ||
      typeof policy.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(policy.sha256))
      throw new Error("SNAPSHOT_MANIFEST_INVALID");
    const limitsPath = join(path, policy.file);
    if (statSync(limitsPath).size > 16_384) throw new Error("PIX_LIMITS_INVALID");
    const bytes = readFileSync(limitsPath);
    if (createHash("sha256").update(bytes).digest("hex") !== policy.sha256)
      throw new Error("SNAPSHOT_HASH_MISMATCH");
    if (parsePixLimits(bytes).version !== policy.version) throw new Error("SNAPSHOT_MANIFEST_INVALID");
  } else if (existsSync(join(path, "pix-limits.json"))) {
    throw new Error("SNAPSHOT_MANIFEST_INVALID");
  }
  for (const name of ["events", "bank",
    ...(manifest.files.ecosystem ? ["ecosystem"] as const : []),
    ...(manifest.files.simulator ? ["simulator"] as const : []),
    ...(manifest.files.sourceHealth ? ["sourceHealth"] as const : [])] as const) {
    if (name !== "simulator" && name !== "sourceHealth" &&
      manifest.files[name] !== `${name}.sqlite`)
      throw new Error("SNAPSHOT_MANIFEST_INVALID");
    const filename = manifest.files[name];
    if (!filename) throw new Error("SNAPSHOT_MANIFEST_INVALID");
    const file = join(path, filename);
    if (digest(file) !== manifest.sha256[name]) throw new Error("SNAPSHOT_HASH_MISMATCH");
    check(file);
  }
  const db = new DatabaseSync(join(path, manifest.files.events), { readOnly: true });
  try {
    const sequence = db.prepare("SELECT COUNT(*) count, COALESCE(MIN(seq),0) first, COALESCE(MAX(seq),0) last FROM events")
      .get() as { count: number; first: number; last: number };
    if (sequence.first !== 1 || sequence.count !== sequence.last || sequence.last !== manifest.latestSeq)
      throw new Error("SNAPSHOT_SEQUENCE_MISMATCH");
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_integrity'").get())
      throw new Error("SNAPSHOT_EVENT_SEAL_MISSING");
    if (!verifyEventIntegrity(db).ok) throw new Error("SNAPSHOT_EVENT_CHAIN_INVALID");
    const round = db.prepare("SELECT status, last_seq FROM rounds WHERE round_id=?")
      .get(manifest.roundId) as { status: string; last_seq: number | null } | undefined;
    if (!round || round.status === "started" || round.last_seq === null || round.last_seq > sequence.last)
      throw new Error("SNAPSHOT_ROUND_MISMATCH");
  } finally { db.close(); }
  const bank = new DatabaseSync(join(path, manifest.files.bank), { readOnly: true });
  try {
    const separated = !bank.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='spi_participants'`).get();
    if (separated !== Boolean(manifest.files.ecosystem))
      throw new Error("SNAPSHOT_ECOSYSTEM_MISSING");
    for (const [table, error] of [["ledger_seals", "SNAPSHOT_LEDGER_SEAL_MISSING"],
      ["telemetry_seals", "SNAPSHOT_TELEMETRY_SEAL_MISSING"]] as const)
      if (!bank.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table))
        throw new Error(error);
    if (!verifyLedgerChain(bank)) throw new Error("SNAPSHOT_LEDGER_CHAIN_INVALID");
    if (!verifyTelemetryChain(bank)) throw new Error("SNAPSHOT_TELEMETRY_CHAIN_INVALID");
    if (manifest.files.sourceHealth) canaryExcludedCustomers({ db: bank },
      join(path, manifest.files.sourceHealth), true);
    else if (bank.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='runtime_external_registry_required'`).get())
      throw new Error("SNAPSHOT_CANARY_REGISTRY_MISSING");
  } finally { bank.close(); }
  if (manifest.files.ecosystem) {
    try {
      execFileSync(process.execPath, [fileURLToPath(new URL(
        "../../../scripts/verify-split-snapshot.mjs", import.meta.url)),
      join(path, manifest.files.bank), join(path, manifest.files.ecosystem)],
      { stdio: "pipe", timeout: 120_000 });
    } catch { throw new Error("SNAPSHOT_CROSS_BOOK_DRIFT"); }
  }
  const anchorEvents = new DatabaseSync(join(path, manifest.files.events), { readOnly: true });
  const anchorBank = new DatabaseSync(join(path, manifest.files.bank), { readOnly: true });
  try {
    const anchorRows = anchorEvents.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='ledger_anchors'`).get() ?
      (anchorEvents.prepare("SELECT COUNT(*) n FROM ledger_anchors").get() as { n: number }).n : 0;
    if (!manifest.ledgerAnchor) {
      if (anchorRows) throw new Error("SNAPSHOT_LEDGER_ANCHOR_UNDECLARED");
    } else {
      const anchor = verifyLedgerAnchors(anchorBank, anchorEvents,
        join(path, manifest.ledgerAnchor.directory));
      const tip = ledgerTip(anchorBank);
      if (!anchor || anchor.sequence !== manifest.ledgerAnchor.count ||
        anchor.anchor_hash !== manifest.ledgerAnchor.anchorHash ||
        anchor.entry_rowid !== manifest.ledgerAnchor.entryRowid ||
        anchor.provenance !== manifest.ledgerAnchor.provenance ||
        anchor.entry_rowid !== tip.entry_rowid || anchor.entry_hash !== tip.entry_hash)
        throw new Error("SNAPSHOT_LEDGER_ANCHOR_MISMATCH");
    }
    const closeState = anchorEvents.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='period_close_anchor_state'`).get();
    const closeRegistry = anchorBank.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='period_close_anchor_registry'`).get() &&
      anchorBank.prepare("SELECT 1 FROM period_close_anchor_registry WHERE id=1").get();
    if (closeState || closeRegistry || manifest.periodCloseAnchor) {
      if (!closeState || !closeRegistry)
        throw new Error("SNAPSHOT_PERIOD_CLOSE_ANCHOR_MISSING");
      const committed = verifyPeriodCloseAnchors(anchorBank, anchorEvents,
        () => new Date(), "strict");
      if (manifest.periodCloseAnchor && committed !== manifest.periodCloseAnchor.committed)
        throw new Error("SNAPSHOT_PERIOD_CLOSE_ANCHOR_MISMATCH");
    }
  } finally { anchorEvents.close(); anchorBank.close(); }
  return manifest;
}
