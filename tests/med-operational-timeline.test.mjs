import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Bank } from "../apps/world/src/bank.ts";
import { EcosystemClient } from "../apps/ecosystem/src/client.ts";
import { SeparatedPixCoordinator } from "../apps/world/src/separated-pix-coordinator.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { exportSplitSnapshots } from "../scripts/export-ecosystem-snapshot.mjs";
import { verifySplitSnapshots } from "../scripts/verify-split-snapshot.mjs";
import { reviewMedForTest } from "./med-review-helper.mjs";

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

test("separated MED follows opening, analysis, initiation and two PSP deadlines", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-timeline-"));
  const source = join(dir, "combined.sqlite");
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  let clock = Date.parse("2026-11-18T12:00:00.000Z");
  const now = () => new Date(clock);
  const original = new Bank(source, now);
  let bank;
  let ecosystem;
  try {
    seedBank(original, { customers: 2, accounts: 2, historyTransactions: 0 });
    const payment = original.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000, idempotencyKey: "med-full-timeline",
      actor: seedCustomerId(1) });
    original.psp.transfer(payment.id, "psp_ipe_ana", "psp_aroeira_bruno", 400,
      "med-full-timeline-hop");
    original.close();
    exportSplitSnapshots(source, bankPath, ecosystemPath);
    bank = new Bank(bankPath, now, undefined, { ecosystemMode: "separated" });
    ecosystem = await EcosystemClient.start(ecosystemPath);
    const coordinator = new SeparatedPixCoordinator(bank, ecosystem);
    const requestedAt = now().toISOString();
    const med = coordinator.requestMed(seedCustomerId(1), payment.id);
    assert.equal(bank.medOpeningSla().cases.find((row) => row.case_id === med.id)?.state,
      "pending");
    assert.equal(bank.db.prepare("SELECT resolve_after FROM med_cases WHERE id=?")
      .get(med.id).resolve_after,
    new Date(Date.parse(requestedAt) + 7 * DAY_MS).toISOString());
    clock += 20 * 60_000;
    assert.equal(await coordinator.dispatchMedOpenings(), 1);
    const opening = bank.medOpeningSla();
    assert.equal(opening.cases.find((row) => row.case_id === med.id)?.state,
      "on_time");
    assert.equal(opening.cases.find((row) => row.case_id === med.id)?.elapsed_seconds,
      20 * 60);
    assert.equal(opening.target_met, true);
    reviewMedForTest(bank, med.id, payment.id);
    assert.equal(bank.resolveMed(med.id).status, "analysis_pending_dict");
    assert.equal(bank.medInitiationSla().find((row) => row.case_id === med.id)?.state,
      "awaiting_analysis");
    assert.equal(await coordinator.dispatchMedAnalyses(), 1);
    const awaitingInitiation = bank.medInitiationSla()
      .find((row) => row.case_id === med.id);
    assert.equal(awaitingInitiation.state, "pending");
    assert.equal(awaitingInitiation.deadline_at,
      new Date(Date.parse(awaitingInitiation.analysed_at) + 72 * HOUR_MS).toISOString());
    clock += 71 * HOUR_MS;
    assert.equal(bank.resolveMed(med.id).status, "settlement_pending_psp");
    assert.equal(bank.medInitiationSla().find((row) => row.case_id === med.id)?.state,
      "on_time");
    const command = bank.pendingExternalMedSettlements()[0];
    const process = () => ecosystem.settleMedCase({ caseId: med.id,
      rootTransferId: payment.id, endToEndId: payment.end_to_end_id,
      claimAmountCents: command.claim_amount_cents,
      settledAt: command.created_at, processedAt: now().toISOString() });
    assert.ok((await process()).every((hop) => hop.released_at === null));
    clock += 5 * HOUR_MS + 59 * 60_000;
    const first = await process();
    assert.equal(first.filter((hop) => hop.released_at !== null).length, 1);
    clock += 5 * HOUR_MS + 59 * 60_000;
    const finished = await process();
    assert.ok(finished.every((hop) => hop.released_at !== null));
    const steps = await ecosystem.medRefundTimeline(med.id, payment.id);
    assert.deepEqual(steps.map((step) => step.sequence), [1, 2]);
    assert.ok(steps.every((step) => step.case_id === med.id &&
      Date.parse(step.deadline_at) - Date.parse(step.requested_at) === 6 * HOUR_MS &&
      Date.parse(step.processed_at) >= Date.parse(step.requested_at) &&
      Date.parse(step.processed_at) <= Date.parse(step.deadline_at)));
    assert.ok(Date.parse(steps[1].requested_at) >= Date.parse(steps[0].processed_at));
    bank.applyExternalMedSettlement(med.id, finished, steps);
    assert.equal(bank.db.prepare("SELECT status,refunded_cents FROM med_cases WHERE id=?")
      .get(med.id).status, "resolved");
    assert.equal(bank.db.prepare("SELECT refunded_cents FROM med_cases WHERE id=?")
      .get(med.id).refunded_cents, 1_000);
    assert.equal(bank.reconcile().ok, true);
    const crossBook = verifySplitSnapshots(bankPath, ecosystemPath);
    assert.equal(crossBook.ok, true, JSON.stringify(crossBook));
  } finally {
    await ecosystem?.close();
    try { bank?.close(); } catch { /* Closed during a failed setup. */ }
    try { original.close(); } catch { /* Closed before export. */ }
    rmSync(dir, { recursive: true, force: true });
  }
});
