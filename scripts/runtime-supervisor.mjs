import { spawn, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const labMode = process.env.FAULT_LAB_MODE === "1";
const dataDir = resolve(labMode ?
  (process.env.FAULT_LAB_DATA_DIR || resolve(root, "data/fault-lab")) :
  (process.env.DATA_DIR || resolve(root, "data")));
mkdirSync(dataDir, { recursive: true });
const watchdogFile = resolve(root, "scripts/source-health-watchdog.mjs");
const watchdogClass = existsSync(watchdogFile) ?
  (await import(pathToFileURL(watchdogFile).href)).SourceHealthWatchdog : undefined;
let watchdog;
function ensureWatchdog() {
  if (watchdog || !watchdogClass) return;
  if (labMode) {
    const marker = join(dataDir, "fault-lab.marker");
    if (!existsSync(marker) ||
      readFileSync(marker, "utf8") !== "banco-vivo-fault-lab-v1\n") return;
  }
  watchdog = new watchdogClass(dataDir);
}
if (!labMode) ensureWatchdog();
const watchdogTimer = watchdogClass ? setInterval(() => {
  try { ensureWatchdog(); watchdog?.tick(); }
  catch (error) { console.error("source health watchdog failure", error); }
}, 2_000) : undefined;
const gitHead = () => execFileSync("git", ["rev-parse", "HEAD"], {
  cwd: root, encoding: "utf8", maxBuffer: 1024 * 1024,
}).trim();

let child;
let stopping = false;
let patchRestarts = 0;
let labRestarts = 0;
let restartTimer;
function finish(code) {
  if (watchdogTimer) clearInterval(watchdogTimer);
  watchdog?.close();
  process.exitCode = code ?? 1;
}
function launch() {
  const head = gitHead();
  child = spawn(process.execPath, ["--env-file-if-exists=.env", "--disable-warning=ExperimentalWarning",
    "--experimental-strip-types", "apps/server/src/main.ts"], {
    cwd: root, stdio: "inherit", env: { ...process.env, DATA_DIR: dataDir,
      BANCO_VIVO_RUNTIME_HEAD: head },
  });
  child.once("exit", (code, signal) => {
    if (!stopping) {
      try {
        ensureWatchdog();
        if (code !== 75) {
          watchdog?.report("process_exit", "bank", {
            exit_code: code ?? -1, signal: signal ?? "NONE" });
        }
      } catch (error) { console.error("source health exit alert failure", error); }
      if (code === 75 && patchRestarts++ < 20) { launch(); return; }
      if (labMode && labRestarts < 3) {
        labRestarts++;
        restartTimer = setTimeout(() => { restartTimer = undefined; launch(); },
          1_000 * labRestarts);
        return;
      }
    }
    finish(code);
  });
}
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => {
  if (stopping) return;
  stopping = true;
  if (restartTimer) { clearTimeout(restartTimer); finish(0); }
  else child?.kill(signal);
});
launch();
