import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { Bank } from "../apps/world/src/bank.ts";
import { EcosystemClient } from "../apps/ecosystem/src/client.ts";
import { SeparatedPixCoordinator } from "../apps/world/src/separated-pix-coordinator.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { exportSplitSnapshots } from "../scripts/export-ecosystem-snapshot.mjs";
import { verifySplitSnapshots } from "../scripts/verify-split-snapshot.mjs";

const script = resolve("scripts/separated-pix-dispatcher.mjs");

test("separated dispatcher drains a durable Pix and resumes without duplicate credit", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-split-dispatcher-"));
  const sourcePath = join(dir, "combined.sqlite");
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  const original = new Bank(sourcePath);
  let bank;
  let ecosystem;
  let child;
  let stderr = "";
  let stdout = "";
  const launch = () => {
    const childProcess = spawn(process.execPath, ["--disable-warning=ExperimentalWarning",
      "--experimental-strip-types", script], {
      cwd: resolve("."), env: { ...process.env, DATA_DIR: dir },
      stdio: ["ignore", "pipe", "pipe"],
    });
    stdout = "";
    childProcess.stdout.setEncoding("utf8");
    childProcess.stdout.on("data", (chunk) => { stdout += chunk; });
    childProcess.stderr.setEncoding("utf8");
    childProcess.stderr.on("data", (chunk) => { stderr += chunk; });
    return childProcess;
  };
  const waitReady = async () => {
    const deadline = Date.now() + 5_000;
    while (!stdout.includes("SEPARATED_PIX_DISPATCHER_READY")) {
      if (Date.now() > deadline || child.exitCode !== null)
        assert.fail(`dispatcher did not start: ${stderr}`);
      await delay(10);
    }
  };
  const stop = async () => {
    if (!child) return;
    const running = child;
    child = undefined;
    if (running.exitCode === null) {
      const exited = once(running, "exit");
      running.kill("SIGTERM");
      const [code] = await exited;
      assert.equal(code, 0, stderr);
    } else assert.equal(running.exitCode, 0, stderr);
  };
  try {
    seedBank(original, { customers: 2, accounts: 2, historyTransactions: 0 });
    original.close();
    exportSplitSnapshots(sourcePath, bankPath, ecosystemPath);
    bank = new Bank(bankPath, undefined, undefined, { ecosystemMode: "separated" });
    ecosystem = await EcosystemClient.start(ecosystemPath);
    const queued = await new SeparatedPixCoordinator(bank, ecosystem).enqueue({
      from: seedAccountId(1), to: "psp_ipe_ana", amount: 500,
      idempotencyKey: "dispatcher-restart", actor: seedCustomerId(1),
    });
    assert.equal(queued.status, "in_processing");
    await ecosystem.close(); ecosystem = undefined;
    bank.close(); bank = undefined;
    child = launch();
    await waitReady();
    const reader = new DatabaseSync(bankPath, { readOnly: true });
    try {
      const deadline = Date.now() + 8_000;
      for (;;) {
        const row = reader.prepare(`SELECT p.status,o.acknowledged_at
          FROM pix_transfers p LEFT JOIN pix_psp_inbound_outbox o
          ON o.transfer_id=p.id WHERE p.id=?`).get(queued.id);
        if (row?.status === "settled" && row.acknowledged_at) break;
        if (Date.now() > deadline || child.exitCode !== null)
          assert.fail(`dispatcher did not settle: ${JSON.stringify(row)} ${stderr}`);
        await delay(25);
      }
    } finally { reader.close(); }
    await stop();
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
    const before = new DatabaseSync(ecosystemPath, { readOnly: true });
    const funds = before.prepare(`SELECT balance_cents FROM psp_accounts
      WHERE id='psp_ipe_ana'`).get().balance_cents;
    before.close();
    bank = new Bank(bankPath, undefined, undefined, { ecosystemMode: "separated" });
    const med = bank.requestExternalMed(seedCustomerId(1), queued.id);
    assert.equal(med.status, "opening");
    bank.close(); bank = undefined;
    child = launch();
    await waitReady();
    const medReader = new DatabaseSync(bankPath, { readOnly: true });
    try {
      const deadline = Date.now() + 8_000;
      while (medReader.prepare("SELECT status FROM med_cases WHERE id=?")
        .get(med.id).status !== "open") {
        if (Date.now() > deadline || child.exitCode !== null)
          assert.fail(`dispatcher did not open MED: ${stderr}`);
        await delay(25);
      }
    } finally { medReader.close(); }
    await stop();
    const after = new DatabaseSync(ecosystemPath, { readOnly: true });
    try {
      assert.equal(after.prepare(`SELECT balance_cents FROM psp_accounts
        WHERE id='psp_ipe_ana'`).get().balance_cents, funds);
      assert.equal(after.prepare(`SELECT COUNT(*) n FROM psp_med_holds
        WHERE case_id=?`).get(med.id).n, 1);
    } finally { after.close(); }
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
  } finally {
    if (child && child.exitCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      await exited.catch(() => {});
    }
    await ecosystem?.close();
    try { bank?.close(); } catch { /* Already closed. */ }
    try { original.close(); } catch { /* Already closed. */ }
    rmSync(dir, { recursive: true, force: true });
  }
});
