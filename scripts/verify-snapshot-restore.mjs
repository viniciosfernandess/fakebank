import { cpSync, copyFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { Bank } from "../apps/world/src/bank.ts";
import { EventStore } from "../packages/event-store/src/index.ts";
import { verifySnapshot } from "../apps/orchestrator/src/snapshot.ts";
import { canaryExcludedCustomers } from "../apps/orchestrator/src/canary-exclusions.ts";
import { verifySplitSnapshots } from "./verify-split-snapshot.mjs";

function verifySimulatorKeys(bank, path) {
  const storedKeys = new Map();
  if (path) {
    const keys = new DatabaseSync(path, { readOnly: true });
    try {
      let records;
      try { records = keys.prepare("SELECT customer_id,public_key,private_key FROM device_keys").all(); }
      catch { throw new Error("RESTORE_SIMULATOR_KEY_MISMATCH"); }
      for (const stored of records) {
        try {
          const privateKey = createPrivateKey({ key: Buffer.from(stored.private_key, "base64url"),
            format: "der", type: "pkcs8" });
          const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" })
            .toString("base64url");
          if (publicKey !== stored.public_key) throw new Error("Key pair mismatch");
        } catch { throw new Error("RESTORE_SIMULATOR_KEY_MISMATCH"); }
        storedKeys.set(stored.customer_id, stored.public_key);
      }
    } finally { keys.close(); }
  }
  const devicesTable = bank.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='auth_devices'").get();
  if (!devicesTable) return 0;
  const columns = bank.db.prepare("PRAGMA table_info(auth_devices)").all().map((column) => column.name);
  if (!columns.includes("public_key") || !columns.includes("fingerprint")) return 0;
  const devices = bank.db.prepare(`SELECT customer_id,public_key FROM auth_devices
    WHERE fingerprint='sim-device-' || customer_id AND public_key IS NOT NULL`).all();
  if (!devices.length) return 0;
  if (!path) throw new Error("RESTORE_SIMULATOR_KEYS_MISSING");
  for (const device of devices)
    if (storedKeys.get(device.customer_id) !== device.public_key)
      throw new Error("RESTORE_SIMULATOR_KEY_MISMATCH");
  return devices.length;
}

export function verifySnapshotRestore(source) {
  const manifest = verifySnapshot(source);
  const disposable = mkdtempSync(join(tmpdir(), "banco-vivo-restore-"));
  let events;
  let bank;
  try {
    for (const file of ["manifest.json", manifest.files.events, manifest.files.bank,
      ...(manifest.files.ecosystem ? [manifest.files.ecosystem] : []),
      ...(manifest.files.simulator ? [manifest.files.simulator] : []),
      ...(manifest.files.sourceHealth ? [manifest.files.sourceHealth] : []),
      ...(manifest.pixLimits ? [manifest.pixLimits.file] : [])])
      copyFileSync(join(source, file), join(disposable, file));
    if (manifest.ledgerAnchor) cpSync(join(source, manifest.ledgerAnchor.directory),
      join(disposable, manifest.ledgerAnchor.directory), { recursive: true });
    verifySnapshot(disposable);
    events = new EventStore(join(disposable, manifest.files.events));
    bank = new Bank(join(disposable, manifest.files.bank), undefined, undefined, {
      ...(manifest.pixLimits ? { pixLimitsBytes: readFileSync(join(disposable, manifest.pixLimits.file)) } : {}),
      ...(manifest.files.ecosystem ? { ecosystemMode: "separated" } : {}) });
    let after = 0;
    for (;;) {
      const batch = events.list({ after, limit: 500 });
      if (!batch.length) break;
      for (const event of batch) {
        if (event.seq !== after + 1) throw new Error("RESTORE_EVENT_GAP");
        after = event.seq;
      }
    }
    if (after !== manifest.latestSeq) throw new Error("RESTORE_EVENT_COUNT_MISMATCH");
    const round = events.rounds().find((item) => item.round_id === manifest.roundId);
    if (!round || round.status === "started" || round.last_seq === null)
      throw new Error("RESTORE_ROUND_MISSING");
    if (!bank.verifyLedgerChain()) throw new Error("RESTORE_LEDGER_CHAIN_INVALID");
    if (manifest.files.sourceHealth) canaryExcludedCustomers(bank,
      join(disposable, manifest.files.sourceHealth));
    const simulatorDevicesVerified = verifySimulatorKeys(bank,
      manifest.files.simulator ? join(disposable, manifest.files.simulator) : undefined);
    const effectiveLimits = bank.pixLimitsSnapshot();
    const effectiveLimitsHash = createHash("sha256").update(effectiveLimits.bytes).digest("hex");
    if (manifest.pixLimits && (effectiveLimitsHash !== manifest.pixLimits.sha256 ||
      effectiveLimits.version !== manifest.pixLimits.version))
      throw new Error("RESTORE_PIX_LIMITS_MISMATCH");
    const crossBook = manifest.files.ecosystem ? verifySplitSnapshots(
      join(disposable, manifest.files.bank), join(disposable, manifest.files.ecosystem)) : null;
    if (crossBook && !crossBook.ok) throw new Error("RESTORE_CROSS_BOOK_DRIFT");
    const bankIntegrity = bank.reconcile();
    if (!bankIntegrity.ok) throw new Error("RESTORE_BANK_RECONCILIATION_FAILED");
    return { roundId: manifest.roundId, latestSeq: after, rounds: events.rounds().length,
      bank: bankIntegrity, simulatorDevicesVerified,
      ...(crossBook ? { crossBook } : {}),
      pixLimitsProvenance: manifest.pixLimits ? "captured" : "unknown",
      canaryRegistryProvenance: manifest.files.sourceHealth ? "captured" : "unknown",
      ledgerAnchorProvenance: manifest.ledgerAnchor?.provenance ?? "unknown",
      ledgerAnchorHash: manifest.ledgerAnchor?.anchorHash ?? null,
      pixLimitsSha256: manifest.pixLimits ? effectiveLimitsHash : null };
  } finally {
    bank?.close();
    events?.close();
    rmSync(disposable, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const source = process.argv[2];
  if (!source || process.argv.length !== 3)
    throw new Error("Usage: npm run verify:restore -- <snapshot-directory>");
  process.stdout.write(`${JSON.stringify(verifySnapshotRestore(resolve(source)), null, 2)}\n`);
}
