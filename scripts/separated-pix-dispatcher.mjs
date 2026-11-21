import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Bank } from "../apps/world/src/bank.ts";
import { EcosystemClient } from "../apps/ecosystem/src/client.ts";
import { SeparatedPixCoordinator } from "../apps/world/src/separated-pix-coordinator.ts";

import { PixOutcomeController } from "../apps/world/src/pix-outcome-controller.ts";

import { loadPixOutcomePolicy } from "../apps/world/src/pix-outcome-policy-file.ts";

const dataDir = resolve(process.env.DATA_DIR ?? "data");
const bankPath = join(dataDir, "bank.sqlite");
const ecosystemPath = join(dataDir, "ecosystem.sqlite");
if (!existsSync(bankPath) || !existsSync(ecosystemPath))
  throw new Error("SEPARATED_PIX_FILES_MISSING");

const clockDb = new DatabaseSync(bankPath, { readOnly: true });
let anchor;
try {
  if (clockDb.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='runtime_clock'`).get())
    anchor = clockDb.prepare(`SELECT real_start_ms,twin_start_ms,speed
      FROM runtime_clock WHERE id=1`).get();
} finally { clockDb.close(); }
if (anchor && (!Number.isSafeInteger(anchor.real_start_ms) ||
  !Number.isSafeInteger(anchor.twin_start_ms) ||
  !Number.isFinite(anchor.speed) || anchor.speed <= 0 || anchor.speed > 64))
  throw new Error("SEPARATED_PIX_CLOCK_INVALID");
const realNow = () => new Date();
const twinNow = () => anchor ? new Date(anchor.twin_start_ms +
  (Date.now() - anchor.real_start_ms) * anchor.speed) : realNow();

const outcomePolicy = process.env.PIX_OUTCOME_ENGINE === "1" ?
  loadPixOutcomePolicy(process.env.PIX_OUTCOME_POLICY_FILE) : undefined;
const bank = new Bank(bankPath, twinNow, realNow, { ecosystemMode: "separated" });
let ecosystem;
try { ecosystem = await EcosystemClient.start(ecosystemPath); }
catch (error) { bank.close(); throw error; }
const coordinator = new SeparatedPixCoordinator(bank, ecosystem);
const outcome = outcomePolicy ?
  new PixOutcomeController(coordinator, bank.db, realNow, outcomePolicy,
    (decision) => console.log(JSON.stringify({ event: "pix.outcome.adjustment", ...decision }))) : undefined;
let timer;
let running = false;
let stopping = false;
let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  try { await ecosystem.close(); }
  finally { bank.close(); }
}
function stop() {
  if (stopping) return;
  stopping = true;
  clearInterval(timer);
  if (!running) void close().catch((error) => {
    console.error("Separated Pix shutdown failed", error);
    process.exitCode = 1;
  });
}
async function tick() {
  if (stopping || running) return;
  running = true;
  try { await (outcome ? outcome.dispatch() : coordinator.dispatch()); }
  catch (error) {
    console.error("Separated Pix dispatch failed", error);
    process.exitCode = 1;
    stop();
  } finally {
    running = false;
    if (stopping) try { await close(); }
    catch (error) {
      console.error("Separated Pix shutdown failed", error);
      process.exitCode = 1;
    }
  }
}
for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, stop);
console.log("SEPARATED_PIX_DISPATCHER_READY");
timer = setInterval(() => { void tick(); }, 50);
void tick();
