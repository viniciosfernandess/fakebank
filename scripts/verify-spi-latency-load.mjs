import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { Bank } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId } from "../apps/world/src/id.ts";

const root = mkdtempSync(join(tmpdir(), "banco-vivo-spi-latency-"));
const bank = new Bank(join(root, "bank.sqlite"),
  () => new Date("2026-11-13T12:00:00Z"));
try {
  seedBank(bank, { customers: 1_000, accounts: 1_000, historyTransactions: 0 });
  for (let index = 0; index < 1_000; index++) {
    const payment = bank.enqueueExternalPix({
      from: seedAccountId(index + 1), to: `psp_sim_${index % 250}`,
      amount: 100, idempotencyKey: `latency-load-${index}`, actor: "latency-gate",
    });
    assert.equal(payment.status, "in_processing");
    if (index % 20 === 19) {
      bank.dispatchPendingPix(1_000);
      await delay(10);
    }
  }
  const deadline = Date.now() + 10_000;
  while (bank.pixLatencyMetrics().count < 1_000 && Date.now() < deadline) {
    bank.dispatchPendingPix(1_000);
    await delay(25);
  }
  const latency = bank.pixLatencyMetrics();
  const integrity = bank.reconcile();
  const spiIntegrity = bank.reconcileSpi();
  const pspIntegrity = bank.reconcilePsp();
  assert.equal(latency.count, 1_000, "Queued Pix did not receive 1,000 SPI responses");
  assert.ok(latency.p50_ms <= 200, `Observed p50 exceeded 200 ms: ${latency.p50_ms}`);
  assert.ok(latency.p99_ms <= 2_000, `Observed p99 exceeded 2,000 ms: ${latency.p99_ms}`);
  assert.equal(integrity.ok, true, JSON.stringify(integrity));
  assert.equal(spiIntegrity.ok, true, JSON.stringify(spiIntegrity));
  assert.equal(pspIntegrity.ok, true, JSON.stringify(pspIntegrity));
  process.stdout.write(JSON.stringify({ latency, integrity, spiIntegrity, pspIntegrity }) + "\n");
} finally {
  bank.close();
  rmSync(root, { recursive: true, force: true });
}
