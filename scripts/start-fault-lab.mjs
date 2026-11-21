import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync,
  statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { prepareLabCodeCheckout } from
  "../apps/orchestrator/src/lab-code-checkout.ts";

const source = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const data = resolve(process.env.FAULT_LAB_DATA_DIR || join(source, "data/fault-lab"));
mkdirSync(data, { recursive: true });
const marker = join(data, "fault-lab.marker");
if (!existsSync(marker)) {
  if (["bank.sqlite", "ecosystem.sqlite", "events.sqlite"].some((name) =>
    existsSync(join(data, name)))) throw new Error("FAULT_LAB_DATA_DIR_NOT_DISPOSABLE");
  writeFileSync(marker, "banco-vivo-fault-lab-v1\n",
    { encoding: "utf8", flag: "wx", mode: 0o600 });
} else if (readFileSync(marker, "utf8") !== "banco-vivo-fault-lab-v1\n") {
  throw new Error("FAULT_LAB_MARKER_INVALID");
}
const processLock = join(data, "lab-process.json");
if (existsSync(processLock)) {
  let pid;
  try { pid = JSON.parse(readFileSync(processLock, "utf8")).pid; }
  catch { throw new Error("FAULT_LAB_PROCESS_LOCK_INVALID"); }
  if (!Number.isSafeInteger(pid) || pid <= 0)
    throw new Error("FAULT_LAB_PROCESS_LOCK_INVALID");
  try { process.kill(pid, 0); throw new Error("FAULT_LAB_ALREADY_RUNNING"); }
  catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  rmSync(processLock);
}
writeFileSync(processLock, JSON.stringify({ pid: process.pid,
  started_at: new Date().toISOString() }) + "\n", { flag: "wx", mode: 0o600 });
process.once("exit", () => {
  try {
    if (JSON.parse(readFileSync(processLock, "utf8")).pid === process.pid)
      rmSync(processLock);
  } catch { /* Leave a changed lock untouched. */ }
});
const checkout = prepareLabCodeCheckout(source, data);
const dist = join(source, "apps/web/dist");
if (!statSync(dist).isDirectory()) throw new Error("FAULT_LAB_WEB_BUILD_MISSING");
cpSync(dist, join(checkout, "apps/web/dist"), { recursive: true, force: true });
const child = spawn(process.execPath, ["--disable-warning=ExperimentalWarning",
  "--experimental-strip-types", "scripts/runtime-supervisor.mjs"], {
  cwd: checkout, stdio: "inherit",
  env: { ...process.env, FAULT_LAB_MODE: "1", FAULT_LAB_DATA_DIR: data,
    FAULT_LAB_CODE_SOURCE_REPO: source },
});
let stopping = false;
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => {
  if (stopping) return;
  stopping = true;
  child.kill(signal);
});
child.once("exit", (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0);
});
