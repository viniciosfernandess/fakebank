import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { EcosystemClient } from "../apps/ecosystem/src/client.ts";
import { Bank } from "../apps/world/src/bank.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { SeparatedPixCoordinator } from "../apps/world/src/separated-pix-coordinator.ts";
import { moneyFlowMedStateFromPspHops } from "../apps/orchestrator/src/money-flow-disclosure.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { exportSplitSnapshots } from "../scripts/export-ecosystem-snapshot.mjs";
import { verifySplitSnapshots } from "../scripts/verify-split-snapshot.mjs";
import { reviewMedForTest } from "./med-review-helper.mjs";

test("DICT sends one MED refund request per PSP and records a six-hour breach", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-refund-sequence-"));
  const source = join(dir, "combined.sqlite");
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  let clock = "2026-11-13T12:00:00.000Z";
  const now = () => new Date(clock);
  const original = new Bank(source, now);
  let bank;
  let ecosystem;
  try {
    seedBank(original, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const payment = original.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000, idempotencyKey: "med-two-psps",
      actor: customer });
    original.psp.transfer(payment.id, "psp_ipe_ana", "psp_aroeira_bruno", 400,
      "med-two-psps-hop");
    original.close();
    exportSplitSnapshots(source, bankPath, ecosystemPath);
    bank = new Bank(bankPath, now, undefined, { ecosystemMode: "separated" });
    ecosystem = await EcosystemClient.start(ecosystemPath);
    const coordinator = new SeparatedPixCoordinator(bank, ecosystem);
    const med = coordinator.requestMed(customer, payment.id);
    assert.equal(await coordinator.dispatchMedOpenings(), 1);
    reviewMedForTest(bank, med.id, payment.id);
    assert.equal(bank.resolveMed(med.id).status, "analysis_pending_dict");
    assert.equal(await coordinator.dispatchMedAnalyses(), 1);
    assert.equal(bank.resolveMed(med.id).status, "settlement_pending_psp");
    const openingProjection = await ecosystem.moneyFlowProjection(payment.id, med.id);
    const openingMed = moneyFlowMedStateFromPspHops(bank, payment.id,
      openingProjection.hops);
    assert.equal(openingMed?.status, "open");
    assert.equal(openingMed?.recovery, "pending");
    const command = bank.pendingExternalMedSettlements()[0];
    const process = () => ecosystem.settleMedCase({ caseId: med.id,
      rootTransferId: payment.id, endToEndId: payment.end_to_end_id,
      claimAmountCents: command.claim_amount_cents,
      settledAt: command.created_at, processedAt: now().toISOString() });
    assert.ok((await process()).every((hop) => hop.released_at === null));
    const first = await process();
    assert.equal(first.filter((hop) => hop.released_at !== null).length, 1);
    const duringMed = moneyFlowMedStateFromPspHops(bank, payment.id, first);
    assert.equal(duringMed?.status, "open");
    assert.equal(duringMed?.recovery, "pending");
    assert.ok(duringMed?.institutions.every((institution) => institution.state === "held"));
    assert.throws(() => moneyFlowMedStateFromPspHops(bank, payment.id,
      first.map((hop) => hop.released_at === null ? hop :
        { ...hop, refunded_cents: hop.blocked_cents + 1 })),
    /MONEY_FLOW_MED_PROJECTION_DRIFT/);
    const pending = await ecosystem.medRefundTimeline(med.id, payment.id);
    assert.deepEqual(pending.map((step) => step.sequence), [1, 2]);
    assert.equal(pending[1].processed_at, null);
    clock = new Date(Date.parse(pending[1].deadline_at) + 1).toISOString();
    const finished = await process();
    assert.ok(finished.every((hop) => hop.released_at !== null));
    const timeline = await ecosystem.medRefundTimeline(med.id, payment.id);
    assert.ok(Date.parse(timeline[1].processed_at) >
      Date.parse(timeline[1].deadline_at));
    assert.ok(Date.parse(timeline[1].requested_at) >=
      Date.parse(timeline[0].processed_at));
    assert.throws(() => bank.applyExternalMedSettlement(med.id, finished, []),
      /INTEGRITY_MED_REFUND_TIMELINE/);
    assert.equal(bank.db.prepare(`SELECT requires_timeline FROM med_psp_settlement_outbox
      WHERE case_id=?`).get(med.id).requires_timeline, 1);
    assert.throws(() => bank.db.prepare(`UPDATE med_psp_settlement_outbox
      SET requires_timeline=0 WHERE case_id=?`).run(med.id),
    /MED_PSP_SETTLEMENT_COMMAND_IMMUTABLE/);
    bank.applyExternalMedSettlement(med.id, finished, timeline);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM med_psp_refund_steps
      WHERE case_id=? AND processed_at>deadline_at`).get(med.id).n, 1);
    const sentinels = new SentinelEngine(bank);
    const sources = { crossBook: verifySplitSnapshots(bankPath, ecosystemPath),
      activeCautelar: [] };
    const late = sentinels.scan(sources).filter((alert) =>
      alert.rule_id === "S-PIX-40");
    assert.equal(late.length, 1);
    assert.equal(late[0].observed.delay_seconds, 1);
    assert.equal(sentinels.scan(sources).filter((alert) =>
      alert.rule_id === "S-PIX-40").length, 0);
    assert.equal(bank.db.prepare("SELECT refunded_cents FROM med_cases WHERE id=?")
      .get(med.id).refunded_cents, 1_000);
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).ok, true);
    assert.equal(bank.reconcile().ok, true);
    await ecosystem.close(); ecosystem = undefined;
    const tampered = new DatabaseSync(ecosystemPath);
    try {
      tampered.exec("DROP TRIGGER dict_med_refund_result_immutable");
      tampered.prepare(`UPDATE dict_med_refund_requests
        SET refunded_cents=refunded_cents+1 WHERE case_id=? AND sequence=2`)
        .run(med.id);
    } finally { tampered.close(); }
    assert.equal(verifySplitSnapshots(bankPath, ecosystemPath).med_command_drift, 1);
  } finally {
    await ecosystem?.close();
    try { bank?.close(); } catch { /* Already closed. */ }
    try { original.close(); } catch { /* Already closed. */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("preexisting MED settlement commands keep an explicit legacy timeline exemption", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-timeline-migration-"));
  const path = join(dir, "bank.sqlite");
  const old = new DatabaseSync(path);
  try {
    old.exec(`CREATE TABLE med_psp_settlement_outbox (
      case_id TEXT PRIMARY KEY,transfer_id TEXT NOT NULL,end_to_end_id TEXT NOT NULL,
      claim_amount_cents INTEGER NOT NULL,created_at TEXT NOT NULL,
      acknowledged_at TEXT)`);
    old.prepare(`INSERT INTO med_psp_settlement_outbox VALUES (?,?,?,?,?,NULL)`)
      .run("legacy-case", "legacy-transfer", "E-legacy", 100,
        "2026-11-13T12:00:00.000Z");
  } finally { old.close(); }
  let bank;
  try {
    bank = new Bank(path, () => new Date("2026-11-13T13:00:00.000Z"));
    assert.equal(bank.db.prepare(`SELECT requires_timeline
      FROM med_psp_settlement_outbox WHERE case_id='legacy-case'`).get().requires_timeline, 0);
    assert.throws(() => bank.db.prepare(`UPDATE med_psp_settlement_outbox
      SET requires_timeline=1 WHERE case_id='legacy-case'`).run(),
    /MED_PSP_SETTLEMENT_COMMAND_IMMUTABLE/);
  } finally { bank?.close(); rmSync(dir, { recursive: true, force: true }); }
});
