import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const markerValue = "banco-vivo-fault-lab-v1\n";
const activeStates = new Set(["arming", "injecting", "observed", "cleanup_failed"]);

/** Archives authoritative local evidence and replaces only a stopped disposable lab. */
export function resetFaultLab(input = {}) {
  const source = realpathSync(resolve(input.sourceRoot ?? projectRoot));
  const selected = resolve(input.dataDir ?? process.env.FAULT_LAB_DATA_DIR ??
    join(source, "data/fault-lab"));
  if (!existsSync(selected) || lstatSync(selected).isSymbolicLink() ||
    !lstatSync(selected).isDirectory() ||
    !selected.endsWith("/fault-lab") && !process.env.FAULT_LAB_DATA_DIR &&
      input.dataDir === undefined)
    throw new Error("FAULT_LAB_RESET_PATH_INVALID");
  const data = realpathSync(selected);
  if (data === source || data === dirname(source) || data === "/" ||
    readFileSync(join(data, "fault-lab.marker"), "utf8") !== markerValue)
    throw new Error("FAULT_LAB_RESET_MARKER_INVALID");
  const checkout = join(data, "code-checkout");
  if (!existsSync(checkout) || lstatSync(checkout).isSymbolicLink() ||
    readFileSync(join(checkout, ".lab-code-source"), "utf8") !== source + "\n" ||
    realpathSync(checkout) !== checkout)
    throw new Error("FAULT_LAB_RESET_CHECKOUT_INVALID");
  const lock = join(data, "lab-process.json");
  if (existsSync(lock)) {
    let pid;
    try { pid = JSON.parse(readFileSync(lock, "utf8")).pid; }
    catch { throw new Error("FAULT_LAB_RESET_LOCK_INVALID"); }
    if (!Number.isSafeInteger(pid) || pid <= 0)
      throw new Error("FAULT_LAB_RESET_LOCK_INVALID");
    try { process.kill(pid, 0); throw new Error("FAULT_LAB_RESET_RUNNING"); }
    catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  }
  const dbPath = join(data, "fault-lab.sqlite");
  let runs = [];
  if (existsSync(dbPath)) {
    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      runs = db.prepare(`SELECT id,status,selected_json,started_at,stopped_at
        FROM fault_lab_runs ORDER BY started_at,id`).all().map((row) => ({
        id: row.id, status: row.status, selected_ids: JSON.parse(row.selected_json),
        started_at: row.started_at, stopped_at: row.stopped_at }));
    } finally { db.close(); }
  }
  if (runs.some((run) => activeStates.has(run.status)))
    throw new Error("FAULT_LAB_RESET_ACTIVE_RUN");
  const head = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: checkout, encoding: "utf8" }).trim();
  const files = readdirSync(data).filter((name) =>
    name === "fault-lab.marker" || /^[a-z0-9-]+\.sqlite(?:-(?:wal|shm))?$/.test(name));
  const manifest = { schema: "banco-vivo-fault-lab-reset-v1",
    reset_at: new Date().toISOString(), source, previous_code_head: head,
    runs, files: files.map((name) => ({ name,
      sha256: createHash("sha256").update(readFileSync(join(data, name))).digest("hex") })) };
  const archiveDir = join(dirname(data), "fault-lab-archives");
  if (existsSync(archiveDir) && lstatSync(archiveDir).isSymbolicLink())
    throw new Error("FAULT_LAB_RESET_ARCHIVE_PATH_INVALID");
  mkdirSync(archiveDir, { recursive: true, mode: 0o700 });
  chmodSync(archiveDir, 0o700);
  const id = `${manifest.reset_at.replaceAll(/[^0-9]/g, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
  const archive = join(archiveDir, `fault-lab-${id}.tar.gz`);
  const staging = mkdtempSync(join(tmpdir(), "bv-lab-reset-"));
  try {
    writeFileSync(join(staging, "reset-manifest.json"),
      JSON.stringify(manifest, null, 2) + "\n", { mode: 0o600 });
    execFileSync("git", ["bundle", "create", join(staging, "code.bundle"), "--all"],
      { cwd: checkout, maxBuffer: 4 * 1024 * 1024 });
    const pending = join(archiveDir, `.fault-lab-${id}.pending`);
    try {
      execFileSync("tar", ["-czf", pending, "-C", data, ...files,
        "-C", staging, "reset-manifest.json", "code.bundle"],
      { maxBuffer: 4 * 1024 * 1024 });
      chmodSync(pending, 0o600);
      execFileSync("tar", ["-tzf", pending], { maxBuffer: 4 * 1024 * 1024 });
      renameSync(pending, archive);
    } finally { rmSync(pending, { force: true }); }
  } finally { rmSync(staging, { recursive: true, force: true }); }
  const archiveSha256 = createHash("sha256").update(readFileSync(archive)).digest("hex");
  rmSync(data, { recursive: true, force: false });
  mkdirSync(data, { recursive: true, mode: 0o700 });
  writeFileSync(join(data, "fault-lab.marker"), markerValue,
    { mode: 0o600, flag: "wx" });
  const receipt = { schema: "banco-vivo-fault-lab-reset-receipt-v1",
    reset_at: manifest.reset_at, previous_code_head: head,
    archived_runs: runs.length, archive, archive_sha256: archiveSha256 };
  writeFileSync(join(data, "last-reset.json"), JSON.stringify(receipt, null, 2) + "\n",
    { mode: 0o600, flag: "wx" });
  return receipt;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== "--confirm")
    throw new Error("FAULT_LAB_RESET_CONFIRM_REQUIRED: run pnpm reset:lab --confirm");
  console.log(JSON.stringify(resetFaultLab()));
}
