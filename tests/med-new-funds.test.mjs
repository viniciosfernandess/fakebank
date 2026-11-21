import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Bank } from "../apps/world/src/bank.ts";
import { EcosystemClient } from "../apps/ecosystem/src/client.ts";
import { SeparatedPixCoordinator } from "../apps/world/src/separated-pix-coordinator.ts";
import { exportSplitSnapshots } from "../scripts/export-ecosystem-snapshot.mjs";
import { verifySplitSnapshots } from "../scripts/verify-split-snapshot.mjs";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { reviewMedForTest } from "./med-review-helper.mjs";
import { moneyFlowMedStateFromPspHops } from
  "../apps/orchestrator/src/money-flow-disclosure.ts";

test("new PSP credit during MED analysis is held and released after rejection", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-new-credit-release-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-18T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const original = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000, idempotencyKey: "med-new-original",
      actor: customer });
    bank.psp.cashOut(original.id, "psp_ipe_ana", 1_000, "med-new-spent");
    const med = bank.requestMed(customer, original.id);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM med_hops WHERE case_id=?")
      .get(med.id).n, 0);
    const later = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 500, idempotencyKey: "med-new-later",
      actor: customer });
    assert.equal(bank.psp.rootBalance("psp_ipe_ana", later.id), 500);
    assert.equal(bank.psp.availableRoot("psp_ipe_ana", later.id), 0);
    assert.throws(() => bank.psp.cashOut(later.id, "psp_ipe_ana", 1,
      "med-new-blocked"), /PSP_FUNDS_UNAVAILABLE/);
    assert.equal(bank.db.prepare(`SELECT blocked_cents FROM med_hops
      WHERE case_id=? AND root_transfer_id=?`).get(med.id, later.id).blocked_cents, 500);
    reviewMedForTest(bank, med.id, original.id, "rejected");
    assert.equal(bank.psp.availableRoot("psp_ipe_ana", later.id), 500);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("approved MED refunds a later root only up to its claimed amount", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-new-credit-refund-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-18T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const original = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000, idempotencyKey: "med-new-refund-original",
      actor: customer });
    bank.psp.cashOut(original.id, "psp_ipe_ana", 1_000, "med-new-refund-spent");
    const med = bank.requestMed(customer, original.id);
    const later = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 500, idempotencyKey: "med-new-refund-later",
      actor: customer });
    reviewMedForTest(bank, med.id, original.id);
    assert.equal(bank.resolveMed(med.id).refunded_cents, 500);
    assert.equal(bank.psp.rootBalance("psp_ipe_ana", later.id), 0);
    assert.equal(bank.db.prepare(`SELECT refunded_cents FROM med_hops
      WHERE case_id=? AND root_transfer_id=?`).get(med.id, later.id).refunded_cents, 500);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("MED reserve and PSP fan-in review do not reject an honest incoming credit", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-new-credit-fanin-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-18T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 6, accounts: 6, historyTransactions: 0 });
    const original = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-fanin-original", actor: seedCustomerId(1) });
    bank.psp.cashOut(original.id, "psp_ipe_ana", 1_000,
      "med-fanin-original-spent");
    const med = bank.requestMed(seedCustomerId(1), original.id);
    for (let index = 2; index <= 5; index++) {
      const from = seedAccountId(index);
      const later = bank.transferPix({ from, to: "psp_ipe_ana", amount: 100,
        idempotencyKey: `med-fanin-${index}`,
        actor: bank.account(from).customer_id });
      assert.equal(later.status, "settled");
      assert.equal(bank.psp.availableRoot("psp_ipe_ana", later.id), 0);
    }
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM med_hops WHERE case_id=?`)
      .get(med.id).n, 4);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("MED caps new-credit holds at the unblocked part of the claim", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-new-credit-cap-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-18T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const original = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-cap-original", actor: customer });
    bank.psp.cashOut(original.id, "psp_ipe_ana", 500, "med-cap-spent");
    const med = bank.requestMed(customer, original.id);
    const later = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-cap-later", actor: customer });
    assert.equal(bank.db.prepare(`SELECT blocked_cents FROM med_hops
      WHERE case_id=? AND root_transfer_id=?`).get(med.id, later.id).blocked_cents, 500);
    assert.equal(bank.psp.availableRoot("psp_ipe_ana", later.id), 500);
    reviewMedForTest(bank, med.id, original.id);
    assert.equal(bank.resolveMed(med.id).refunded_cents, 1_000);
    assert.equal(bank.psp.availableRoot("psp_ipe_ana", later.id), 500);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("releasing an earlier MED reassigns available funds to a later open case", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-overlap-release-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-18T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const original = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-overlap-first", actor: customer });
    bank.psp.cashOut(original.id, "psp_ipe_ana", 1_000, "med-overlap-spent");
    const first = bank.requestMed(customer, original.id);
    const later = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 500,
      idempotencyKey: "med-overlap-second", actor: customer });
    const second = bank.requestMed(customer, later.id);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM med_hops WHERE case_id=?`)
      .get(second.id).n, 0);
    reviewMedForTest(bank, first.id, original.id, "rejected");
    assert.equal(bank.db.prepare(`SELECT blocked_cents FROM med_hops
      WHERE case_id=? AND root_transfer_id=?`).get(second.id, later.id).blocked_cents, 500);
    assert.equal(bank.psp.availableRoot("psp_ipe_ana", later.id), 0);
    reviewMedForTest(bank, second.id, later.id);
    assert.equal(bank.resolveMed(second.id).refunded_cents, 500);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("separated MED mirrors a later credit hold and releases it after rejection", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-new-credit-split-"));
  const source = join(dir, "combined.sqlite");
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  let nowMs = Date.parse("2026-11-18T12:00:00.000Z");
  const now = () => new Date(nowMs);
  let realMs = Date.now();
  const realNow = () => new Date(realMs);
  const originalBank = new Bank(source, now, realNow);
  let bank;
  let ecosystem;
  try {
    seedBank(originalBank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const original = originalBank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-split-original", actor: customer });
    originalBank.psp.cashOut(original.id, "psp_ipe_ana", 1_000,
      "med-split-original-spent");
    originalBank.close();
    exportSplitSnapshots(source, bankPath, ecosystemPath);
    bank = new Bank(bankPath, now, realNow, { ecosystemMode: "separated" });
    ecosystem = await EcosystemClient.start(ecosystemPath);
    const coordinator = new SeparatedPixCoordinator(bank, ecosystem);
    const med = coordinator.requestMed(customer, original.id);
    assert.equal(bank.medOpeningSla().cases.find((row) => row.case_id === med.id)?.state,
      "pending");
    nowMs += 31 * 60_000;
    assert.equal(bank.medOpeningSla().cases.find((row) => row.case_id === med.id)?.state,
      "overdue");
    assert.equal(bank.medOpeningSla().target_met, false);
    assert.equal(await coordinator.dispatchMedOpenings(), 1);
    assert.deepEqual({ p95: bank.medOpeningSla().p95_seconds,
      met: bank.medOpeningSla().target_met,
      state: bank.medOpeningSla().cases.find((row) => row.case_id === med.id)?.state },
      { p95: 1_860, met: false, state: "late" });
    const later = await coordinator.enqueue({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 500, idempotencyKey: "med-split-later",
      actor: customer });
    realMs += 3_000;
    assert.equal((await coordinator.dispatch()).pspCredited, 1);
    const projection = await ecosystem.medCaseProjection(med.id, original.id);
    const newHold = projection.hops.find((hop) => hop.root_transfer_id === later.id);
    assert.equal(newHold?.blocked_cents, 500);
    assert.equal(bank.db.prepare(`SELECT blocked_cents FROM med_hops
      WHERE id=?`).get(newHold.id).blocked_cents, 500);
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
    reviewMedForTest(bank, med.id, original.id, "rejected");
    assert.equal(await coordinator.dispatchMedReleases(), 1);
    assert.ok((await ecosystem.medCaseProjection(med.id, original.id)).hops
      .every((hop) => hop.released_at !== null));
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
    const moved = await ecosystem.transferPspFunds({ rootTransferId: later.id,
      fromAccount: "psp_ipe_ana", toAccount: "psp_aroeira_bruno",
      amountCents: 500, idempotencyKey: "med-split-released-spend",
      processedAt: now().toISOString() });
    assert.equal(moved.status, "settled");
  } finally {
    await ecosystem?.close();
    bank?.close();
    try { originalBank.close(); } catch { /* Already closed after export. */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("separated MED refunds a later root with balanced bank and PSP books", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-new-credit-refund-split-"));
  const source = join(dir, "combined.sqlite");
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  const now = () => new Date("2026-11-18T12:00:00.000Z");
  let realMs = Date.now();
  const realNow = () => new Date(realMs);
  const originalBank = new Bank(source, now, realNow);
  let bank;
  let ecosystem;
  try {
    seedBank(originalBank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const original = originalBank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-split-refund-original", actor: customer });
    originalBank.psp.cashOut(original.id, "psp_ipe_ana", 700,
      "med-split-refund-original-spent");
    originalBank.close();
    exportSplitSnapshots(source, bankPath, ecosystemPath);
    bank = new Bank(bankPath, now, realNow, { ecosystemMode: "separated" });
    ecosystem = await EcosystemClient.start(ecosystemPath);
    const coordinator = new SeparatedPixCoordinator(bank, ecosystem);
    const med = coordinator.requestMed(customer, original.id);
    assert.equal(await coordinator.dispatchMedOpenings(), 1);
    const later = await coordinator.enqueue({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 500,
      idempotencyKey: "med-split-refund-later", actor: customer });
    realMs += 3_000;
    assert.equal((await coordinator.dispatch()).pspCredited, 1);
    const pending = await ecosystem.medCaseProjection(med.id, original.id);
    assert.equal(pending.hops.length, 2);
    assert.equal(moneyFlowMedStateFromPspHops(bank, original.id,
      pending.hops)?.recovery, "pending");
    reviewMedForTest(bank, med.id, original.id);
    assert.equal(bank.resolveMed(med.id).status, "analysis_pending_dict");
    assert.equal(await coordinator.dispatchMedAnalyses(), 1);
    const postAnalysis = await coordinator.enqueue({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 200,
      idempotencyKey: "med-split-after-analysis", actor: customer });
    realMs += 3_000;
    assert.equal((await coordinator.dispatch()).pspCredited, 1);
    assert.equal((await ecosystem.medCaseProjection(med.id, original.id)).hops
      .some((item) => item.root_transfer_id === postAnalysis.id), false);
    assert.equal(bank.resolveMed(med.id).status, "settlement_pending_psp");
    assert.equal(await coordinator.dispatchMedSettlements(), 1);
    assert.equal(bank.db.prepare("SELECT refunded_cents FROM med_cases WHERE id=?")
      .get(med.id).refunded_cents, 800);
    const hop = (await ecosystem.medCaseProjection(med.id, original.id)).hops
      .find((item) => item.root_transfer_id === later.id);
    assert.equal(hop?.refunded_cents, 500);
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
    assert.equal(bank.reconcile().ok, true);
  } finally {
    await ecosystem?.close();
    bank?.close();
    try { originalBank.close(); } catch { /* Already closed after export. */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("new MED hold from a PSP transfer mirrors after bank and worker restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-new-credit-restart-"));
  const source = join(dir, "combined.sqlite");
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  const now = () => new Date("2026-11-18T12:00:00.000Z");
  const originalBank = new Bank(source, now);
  let bank;
  let ecosystem;
  try {
    seedBank(originalBank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const original = originalBank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-restart-original", actor: customer });
    originalBank.psp.cashOut(original.id, "psp_ipe_ana", 1_000,
      "med-restart-spent");
    const independent = originalBank.transferPix({ from: seedAccountId(1),
      to: "psp_aroeira_bruno", amount: 500,
      idempotencyKey: "med-restart-independent", actor: customer });
    originalBank.close();
    exportSplitSnapshots(source, bankPath, ecosystemPath);
    bank = new Bank(bankPath, now, undefined, { ecosystemMode: "separated" });
    ecosystem = await EcosystemClient.start(ecosystemPath);
    let coordinator = new SeparatedPixCoordinator(bank, ecosystem);
    const med = coordinator.requestMed(customer, original.id);
    assert.equal(await coordinator.dispatchMedOpenings(), 1);
    assert.equal((await ecosystem.transferPspFunds({
      rootTransferId: independent.id, fromAccount: "psp_aroeira_bruno",
      toAccount: "psp_ipe_ana", amountCents: 500,
      idempotencyKey: "med-restart-later-transfer",
      processedAt: now().toISOString() })).status, "settled");
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).med_hold_drift, 1);
    await ecosystem.close(); ecosystem = undefined;
    bank.close(); bank = undefined;
    bank = new Bank(bankPath, now, undefined, { ecosystemMode: "separated" });
    ecosystem = await EcosystemClient.start(ecosystemPath);
    coordinator = new SeparatedPixCoordinator(bank, ecosystem);
    assert.equal(await coordinator.syncMedHoldAdditions(), 1);
    assert.equal(await coordinator.syncMedHoldAdditions(), 0);
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
    await assert.rejects(() => ecosystem.cashOutPspFunds({
      rootTransferId: independent.id, accountId: "psp_ipe_ana",
      amountCents: 1, idempotencyKey: "med-restart-denied-spend",
      processedAt: now().toISOString() }), /PSP_FUNDS_UNAVAILABLE/);
    reviewMedForTest(bank, med.id, original.id, "rejected");
    assert.equal(await coordinator.dispatchMedReleases(), 1);
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
  } finally {
    await ecosystem?.close();
    bank?.close();
    try { originalBank.close(); } catch { /* Already closed after export. */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("separated overlapping MED cases reassign a released root without double holding", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-overlap-split-"));
  const source = join(dir, "combined.sqlite");
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  const now = () => new Date("2026-11-18T12:00:00.000Z");
  let realMs = Date.now();
  const realNow = () => new Date(realMs);
  const originalBank = new Bank(source, now, realNow);
  let bank;
  let ecosystem;
  try {
    seedBank(originalBank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const original = originalBank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-overlap-split-first", actor: customer });
    originalBank.psp.cashOut(original.id, "psp_ipe_ana", 1_000,
      "med-overlap-split-spent");
    originalBank.close();
    exportSplitSnapshots(source, bankPath, ecosystemPath);
    bank = new Bank(bankPath, now, realNow, { ecosystemMode: "separated" });
    ecosystem = await EcosystemClient.start(ecosystemPath);
    const coordinator = new SeparatedPixCoordinator(bank, ecosystem);
    const first = coordinator.requestMed(customer, original.id);
    assert.equal(await coordinator.dispatchMedOpenings(), 1);
    const later = await coordinator.enqueue({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 500,
      idempotencyKey: "med-overlap-split-second", actor: customer });
    realMs += 3_000;
    assert.equal((await coordinator.dispatch()).pspCredited, 1);
    const second = coordinator.requestMed(customer, later.id);
    assert.equal(await coordinator.dispatchMedOpenings(), 1);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM med_hops WHERE case_id=?")
      .get(second.id).n, 0);
    reviewMedForTest(bank, first.id, original.id, "rejected");
    assert.equal(await coordinator.dispatchMedReleases(), 1);
    assert.equal(bank.db.prepare(`SELECT blocked_cents FROM med_hops
      WHERE case_id=? AND root_transfer_id=?`).get(second.id, later.id).blocked_cents, 500);
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
    await assert.rejects(() => ecosystem.cashOutPspFunds({
      rootTransferId: later.id, accountId: "psp_ipe_ana", amountCents: 1,
      idempotencyKey: "med-overlap-split-denied",
      processedAt: now().toISOString() }), /PSP_FUNDS_UNAVAILABLE/);
    reviewMedForTest(bank, second.id, later.id, "rejected");
    assert.equal(await coordinator.dispatchMedReleases(), 1);
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
  } finally {
    await ecosystem?.close();
    bank?.close();
    try { originalBank.close(); } catch { /* Already closed after export. */ }
    rmSync(dir, { recursive: true, force: true });
  }
});
