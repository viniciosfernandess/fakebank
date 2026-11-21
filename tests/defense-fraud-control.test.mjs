import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { newId, seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { pixEndToEndId } from "../apps/world/src/pix-id.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { EventStore } from "../packages/event-store/src/index.ts";
import { DefenseCoordinator } from
  "../apps/orchestrator/src/defense-coordinator.ts";
import { CampaignRuntime } from "../apps/orchestrator/src/campaign-runtime.ts";
import { OperatorAuth } from "../apps/world/src/operator-auth.ts";
import { MedOperatorReview } from "../apps/server/src/med-operator-review.ts";
import { ensureSeparatedData } from "../apps/server/src/separated-bootstrap.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { AccountLifecycle } from "../apps/world/src/account-lifecycle.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { Gateway } from "../apps/world/src/gateway.ts";
import { CustomerSimulator } from "../apps/world/src/simulator.ts";
import { bindDeviceKey, signedOperationHeaders } from
  "./device-proof-helper.mjs";
import { listIncidentNotices, recordSuspiciousPixNotice } from
  "../apps/world/src/incident-notices.ts";

async function setup(runtime, transferKey = "fraud-out") {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-fraud-control-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () =>
    new Date("2026-11-19T12:00:00.000Z"));
  const events = new EventStore(join(dir, "events.sqlite"));
  try {
    seedBank(bank, { customers: 8, accounts: 8, historyTransactions: 0 });
    const sentinels = new SentinelEngine(bank, events);
    const accountId = newId("acc", bank.now().getTime());
    bank.addAccount({ id: accountId, customer_id: seedCustomerId(8),
      kind: "checking", system_role: null, overdraft_limit: 0,
      status: "active" });
    for (let index = 1; index <= 6; index++)
      bank.transferPix({ from: seedAccountId(index), to: accountId,
        amount: 1_000, idempotencyKey: `fraud-in-${index}`, actor: "test" });
    // Import a fictional historical settlement into this disposable
    // database so the remediation test starts with balanced legacy records.
    // The current transfer policy remains enabled throughout the test.
    assert.equal(bank.isWeaknessOpen("W17"), false);
    const recipient = seedAccountId(7);
    assert.throws(() => bank.transferPix({ from: accountId, to: recipient,
      amount: 4_800, idempotencyKey: "current-policy-check", actor: "test" }),
    { code: "BIZ_MULE_HOLD" });
    const id = newId("pix", bank.now().getTime());
    const at = bank.now().toISOString();
    const transfer = { id };
    bank.transaction(() => {
      const actor = "synthetic_history";
      const ledgerId = bank.post([
        { accountId, amount: -4_800, kind: "pix", actor, refType: "pix", refId: id },
        { accountId: recipient, amount: 4_800, kind: "pix", actor, refType: "pix", refId: id },
      ]);
      bank.db.prepare(`INSERT INTO pix_transfers (id,idempotency_key,from_account,
        to_account,amount,status,initiated_at,settled_at,ledger_tx_id,night_mode,
        actor,end_to_end_id) VALUES (?,?,?,?,4800,'settled',?,?,?,0,?,?)`).run(
        id, transferKey, accountId, recipient, at, at, ledgerId, actor,
        pixEndToEndId(id, bank.now()));
      const history = bank.db.prepare(`INSERT INTO pix_status_history
        (transfer_id,status,changed_at) VALUES (?,?,?)`);
      history.run(id, "created", at);
      history.run(id, "settled", at);
    });
    assert.equal(bank.reconcile().ok, true);
    const alert = sentinels.scan().find((item) =>
      item.rule_id === "S-PIX-02" && item.entity === accountId);
    assert.ok(alert);
    const defense = new DefenseCoordinator({ bank, sentinels, events,
      dataDir: dir, ...(runtime ? { runtime } : {}) });
    await defense.scanOnce();
    const incident = bank.db.prepare(`SELECT * FROM sentinel_incidents
      WHERE entity_key=? AND area='pix'`).get(seedCustomerId(8));
    const row = events.db.prepare(`SELECT * FROM defense_cases
      WHERE incident_id=?`).get(incident.id);
    return { bank, events, defense, incident, row, alert: {
      id: alert.alert_id, rule_id: alert.rule_id,
      entity: alert.entity, observed: alert.observed },
    accountId, transfer, close: async () => {
      await defense.close(); events.close(); bank.close();
      rmSync(dir, { recursive: true, force: true }); } };
  } catch (error) {
    events.close(); bank.close(); rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}

test("fraud impact agent receives the exact payment but cannot claim verified loss", async () => {
  let assessed = false;
  let assessorCalls = 0;
  let architectCalls = 0;
  let alertRef;
  const runtime = { async run(spec) {
    const incidentId = spec.snapshot.incidentId;
    const version = spec.snapshot.caseVersion;
    if (spec.role === "investigator") {
      const facts = await spec.tools.find((tool) => tool.name === "alerts.get")
        .execute({ cluster_id: incidentId }, new AbortController().signal);
      const fraudAlert = facts.alerts.find((item) => item.rule_id === "S-PIX-02");
      assert.ok(fraudAlert);
      alertRef = `sentinel_alerts:${fraudAlert.id}`;
      assert.ok(spec.dossier.alertRefs.includes(alertRef));
      const transferRef = spec.dossier.alertRefs.find((ref) =>
        ref.startsWith("pix_transfers:"));
      assert.ok(transferRef);
      const body = { incident_id: incidentId, case_version: version,
        profile: "fraud", disposition: "confirmed",
        facts: [{ statement: "A recent account swept recent Pix inflows",
          evidence_refs: [alertRef, transferRef] }],
        hypotheses: [], affected_entities: [],
        unknowns: ["Customer authorization is unverified"],
        recommended_action: "assess_customer_impact",
        recommendation_reason: "Check the exact transfer and customer state" };
      assert.equal(spec.validateDossier({ ...body, facts: [{ ...body.facts[0],
        evidence_refs: ["pix_transfers:unrelated-transfer"] }] }), false);
      assert.equal(spec.validateDossier(body), true);
      return { status: "ok", data: body, tokens: 1 };
    }
    if (spec.role === "damage_assessor") {
      assessorCalls++;
      const snapshot = await spec.tools[0].execute({ incident_id: incidentId },
        new AbortController().signal);
      assert.equal(snapshot.fraudTransfers.length, 1);
      assert.equal(snapshot.fraudTransfersTruncated, false);
      const transfer = snapshot.fraudTransfers[0];
      const body = { incident_id: incidentId, case_version: version,
        findings: [{ kind: "money_candidate", entity_ref: transfer.id,
          evidence_refs: [alertRef, `pix_transfers:${transfer.id}`],
          amount_cents: transfer.amount,
          assessment: "Suspicious settled transfer; customer loss is unverified" }],
        unverified_categories: ["customer_authorization", "financial_loss"],
        customer_repair_required: "unknown" };
      assert.equal(spec.validateDossier({ ...body, findings: [] }), false);
      if (assessorCalls === 1) {
        assert.equal(spec.dossier.priorValidationFailure, null);
        return { status: "failed", reason: "invalid_dossier", tokens: 1 };
      }
      assert.equal(spec.dossier.priorValidationFailure.impact_validation_reason,
        "missing_scoped_fraud_transfer_candidate");
      assert.equal(spec.validateDossier(body), true);
      assessed = true;
      return { status: "ok", data: body, tokens: 1 };
    }
    assert.equal(spec.role, "architect");
    const body = { incident_id: incidentId, case_version: version,
      disposition: "code_candidate", cause_hypothesis: "Risk hold was bypassed",
      evidence_refs: [alertRef], proposed_change: "Restore the mule hold policy",
      acceptance_invariants: ["The sweep is held"],
      do_not_break: ["Established merchant transfer"],
      rollback_plan: "Restore the previous local code head", unknowns: [] };
    architectCalls++;
    if (architectCalls === 1) {
      assert.equal(spec.dossier.priorValidationFailure, null);
      assert.equal(spec.validateDossier({ ...body,
        disposition: "insufficient_evidence" }), false);
      return { status: "failed", reason: "invalid_dossier", tokens: 1 };
    }
    assert.equal(spec.dossier.priorValidationFailure.plan_validation_reason,
      "trusted_code_requires_candidate");
    assert.equal(spec.validateDossier(body), true);
    return { status: "ok", data: body, tokens: 1 };
  } };
  const item = await setup(runtime);
  try {
    await item.defense.scanOnce();
    const failure = item.events.caseFile.history(item.incident.id).find((entry) =>
      entry.kind === "defense.planning_failure");
    assert.equal(failure.payload.plan_validation_reason,
      "trusted_code_requires_candidate");
    assert.equal(failure.payload.impact_validation_reason,
      "missing_scoped_fraud_transfer_candidate");
    await item.defense.scanOnce();
    assert.equal(assessed, true, JSON.stringify(item.events.caseFile.history(
      item.incident.id).filter((entry) => entry.kind === "defense.planning_failure")
      .map((entry) => entry.payload)));
    assert.equal(architectCalls, 2);
    assert.equal(assessorCalls, 2);
    const impact = item.events.caseFile.history(item.incident.id).find((entry) =>
      entry.kind === "dossier.defense_impact");
    assert.equal(impact.payload.findings[0].entity_ref, item.transfer.id);
    assert.equal(impact.payload.customer_repair_required, "unknown");
  } finally { await item.close(); }
});

test("post-promotion fraud control records only the scoped payment and leaves harm open", async () => {
  const item = await setup();
  try {
    item.defense.finishMergedFraudCode(item.incident, item.row,
      [item.alert], "approved-head", "ci-run");
    const receipt = item.events.caseFile.history(item.incident.id).find((entry) =>
      entry.kind === "defense.fraud_control_verified");
    assert.equal(receipt.payload.transfer_id, item.transfer.id);
    assert.equal(receipt.payload.customer_impact, "unverified");
    const state = item.events.db.prepare(`SELECT state,last_error FROM defense_cases
      WHERE incident_id=?`).get(item.incident.id);
    assert.equal(state.state, "needs_attention");
    assert.equal(state.last_error, "fraud_customer_impact_unverified");
    assert.equal(item.defense.cases()[0].attentionReason, "impact_unverified");
    const owner = item.bank.db.prepare(`SELECT customer_id FROM accounts
      WHERE id=?`).get(item.accountId).customer_id;
    const notices = listIncidentNotices(item.bank.db, owner).items;
    assert.equal(notices.length, 1);
    assert.equal(notices[0].kind, "suspicious_pix_review");
    assert.match(notices[0].message_pt, /R\$\s*48,00/);
    assert.equal(listIncidentNotices(item.bank.db, seedCustomerId(7)).items.length, 0);
    assert.ok(item.events.caseFile.history(item.incident.id).some((entry) =>
      entry.kind === "defense.customer_notice" &&
      entry.payload.transfer_id === item.transfer.id &&
      entry.payload.notice_id === notices[0].id));
    const exact = { incidentId: item.incident.id, customerId: owner,
      alertId: item.alert.id, transferId: item.transfer.id };
    assert.equal(recordSuspiciousPixNotice(item.bank, exact).id, notices[0].id);
    item.defense.finishMergedFraudCode(item.incident, item.row,
      [item.alert], "approved-head", "ci-run");
    assert.equal(listIncidentNotices(item.bank.db, owner).items.length, 1);
    assert.equal(item.events.caseFile.history(item.incident.id).filter((entry) =>
      entry.kind === "defense.customer_notice").length, 1);
    assert.throws(() => recordSuspiciousPixNotice(item.bank, {
      ...exact, customerId: seedCustomerId(7) }),
    (error) => error instanceof BankError &&
      error.code === "DEF_INCIDENT_NOTICE_EVIDENCE");
    const unrelatedIncident = newId("incident",
      Date.parse("2026-11-19T13:00:00.000Z"));
    item.bank.db.prepare(`INSERT INTO sentinel_incidents
      (id,entity_key,area,severity,state,alert_count,opened_at,last_seen_at)
      VALUES (?,?,'pix','high','open',1,?,?)`).run(unrelatedIncident,
        owner, "2026-11-19T13:00:00.000Z", "2026-11-19T13:00:00.000Z");
    assert.throws(() => recordSuspiciousPixNotice(item.bank, {
      ...exact, incidentId: unrelatedIncident }),
    (error) => error instanceof BankError &&
      error.code === "DEF_INCIDENT_NOTICE_EVIDENCE");
    assert.throws(() => item.bank.db.prepare(`UPDATE fraud_incident_notices
      SET message_pt='changed' WHERE customer_id=? AND id=?`).run(owner,
        notices[0].id), /INCIDENT_NOTICE_IMMUTABLE/);
    assert.equal(item.bank.db.prepare(`SELECT status FROM pix_transfers
      WHERE id=?`).get(item.transfer.id).status, "settled");
    assert.equal(item.bank.reconcile().ok, true);
  } finally { await item.close(); }
});

test("synthetic customer contests only a notified lab Pix through signed gateway MED", async () => {
  const item = await setup(undefined,
    "lab:00000000-0000-4000-8000-000000000001:missed_hold");
  const auth = new AuthEngine(item.bank);
  const api = createTwinApi(item.bank, auth);
  const sim = new CustomerSimulator(item.bank, auth,
    new Gateway(item.bank, api), item.events);
  try {
    assert.equal(await sim.contestNotifiedLabPix(), 0);
    assert.equal(item.bank.db.prepare("SELECT COUNT(*) n FROM med_cases").get().n, 0);
    item.defense.finishMergedFraudCode(item.incident, item.row,
      [item.alert], "approved-head", "ci-run");
    assert.equal(await sim.contestNotifiedLabPix(), 1);
    const med = item.bank.db.prepare(`SELECT id,customer_id,transfer_id,status,
      refunded_cents FROM med_cases WHERE transfer_id=?`).get(item.transfer.id);
    assert.equal(med.customer_id, seedCustomerId(8));
    assert.equal(med.transfer_id, item.transfer.id);
    assert.equal(med.status, "open");
    assert.equal(med.refunded_cents, 0);
    assert.equal(await sim.contestNotifiedLabPix(), 0);
    assert.equal(item.bank.db.prepare("SELECT COUNT(*) n FROM med_cases").get().n, 1);
    await item.defense.scanOnce();
    assert.equal(item.defense.cases()[0].state, "needs_attention");
    assert.equal(item.bank.reconcile().ok, true);
  } finally { sim.close(); await api.close(); await item.close(); }
});

test("a later approved full MED refund repairs only the linked fraud customer", async () => {
  const item = await setup();
  let customerApp;
  try {
    item.defense.finishMergedFraudCode(item.incident, item.row,
      [item.alert], "approved-head", "ci-run");
    const owner = seedCustomerId(8);
    const auth = new AuthEngine(item.bank);
    auth.setPassword(owner, "temporary-customer-password");
    customerApp = createTwinApi(item.bank, auth);
    const challenge = auth.beginLogin(item.bank.customer(owner).cpf,
      "temporary-customer-password", "127.0.0.1", "med-repair-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, owner), "127.0.0.1");
    auth.stepUp(session.access_token, "temporary-customer-password");
    const headers = { authorization: `Bearer ${session.access_token}` };
    const key = await bindDeviceKey(customerApp, headers);
    const body = { transfer_id: item.transfer.id };
    const signed = await signedOperationHeaders(customerApp, headers, key,
      "/pix/med", body);
    const opened = await customerApp.inject({ method: "POST", url: "/pix/med",
      headers: signed, payload: body });
    assert.equal(opened.statusCode, 200, opened.body);
    const med = opened.json();
    await item.defense.scanOnce();
    assert.equal(item.defense.cases()[0].state, "needs_attention",
      "a customer claim alone does not prove a loss or completed repair");
    assert.equal(item.events.caseFile.history(item.incident.id).filter((entry) =>
      entry.kind === "defense.customer_dispute_observed").length, 1);
    const operators = new OperatorAuth(item.bank);
    operators.bootstrap("med_admin", "temporary-admin-password");
    operators.add("med_admin", "med_maker", "maker", "temporary-maker-password");
    operators.add("med_admin", "med_checker", "reviewer", "temporary-review-password");
    const review = new MedOperatorReview(item.bank);
    const proposed = review.propose(med.id, "approved",
      `sentinel_alerts:${item.alert.id}`, "med_maker", "fraud_indicators",
      "The exact customer Pix has a verified suspicious sweep signal.");
    review.confirm(proposed.id, "med_checker");
    const settled = review.settle(med.id);
    assert.equal(settled.status, "refunded");
    assert.equal(settled.refunded_cents, 4_800);
    const customerResult = await customerApp.inject({ method: "GET",
      url: `/pix/med/${med.id}`, headers });
    assert.equal(customerResult.statusCode, 200);
    assert.equal(customerResult.json().status, "refunded");
    assert.equal(customerResult.json().refunded_cents, 4_800);
    await item.defense.scanOnce();
    assert.equal(item.defense.cases()[0].state, "customer_repaired");
    assert.equal(item.events.db.prepare(`SELECT last_error FROM defense_cases
      WHERE incident_id=?`).get(item.incident.id).last_error, null);
    const history = item.events.caseFile.history(item.incident.id);
    const receipt = history.find((entry) =>
      entry.kind === "defense.customer_repair_verified");
    assert.equal(receipt.payload.customer_id, owner);
    assert.equal(receipt.payload.transfer_id, item.transfer.id);
    assert.equal(receipt.payload.med_case_id, med.id);
    assert.equal(receipt.payload.amount_cents, 4_800);
    assert.equal(receipt.payload.refund_ids.length, 1);
    await item.defense.scanOnce();
    assert.equal(item.events.caseFile.history(item.incident.id).filter((entry) =>
      entry.kind === "defense.customer_repair_verified").length, 1);
    assert.equal(item.bank.reconcile().ok, true);
  } finally { await customerApp?.close(); await item.close(); }
});

async function verifyScopedMedCompensation(remaining, closedSource = false) {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-compensation-"));
  const now = new Date("2026-11-19T12:00:00.000Z");
  const events = new EventStore(join(dir, "events.sqlite"));
  let runtime;
  let defense;
  try {
    const seed = { customers: 3, accounts: 3, historyTransactions: 0, openWeaknesses: false };
    ensureSeparatedData(dir, seed);
    runtime = await CampaignRuntime.openSeparated({ dataDir: dir, events, onDemand: true,
      faultLab: true, realNow: () => now, seed });
    const { bank, sentinels, auth } = runtime;
    const owner = seedCustomerId(1);
    const accountId = closedSource ? newId("acc", bank.now().getTime()) : seedAccountId(1);
    if (closedSource) {
      bank.addAccount({ id: accountId, customer_id: owner, kind: "checking",
        system_role: null, overdraft_limit: 0, status: "active" });
      bank.fund(accountId, 4_800);
    }
    const recipient = seedAccountId(2);
    const recipientHistory = await runtime.recipientFraudHistory(recipient, bank.now());
    const transfer = bank.transferInternalPixWithHistory({
      from: accountId, to: recipient, amount: 4_800,
      idempotencyKey: "lab:00000000-0000-4000-8000-000000000003:missed_hold", actor: owner,
    }, recipientHistory);
    assert.equal(transfer.status, "settled");
    if (closedSource) new AccountLifecycle(bank).transition(accountId, "closed", owner);
    const incidentId = "incident_med_compensation_fixture";
    const alert = { id: "med_compensation_alert", rule_id: "S-PIX-02", entity: accountId,
      observed: { inbound_cents: 6_000, outbound_cents: 4_800 } };
    const at = bank.now().toISOString();
    bank.db.prepare("INSERT INTO sentinel_incidents VALUES (?,?,'pix','high','open',1,?,?)")
      .run(incidentId, owner, at, at);
    bank.db.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,900,?,?,1,?)")
      .run(alert.id, alert.rule_id, alert.entity, JSON.stringify(alert.observed), at, at, at);
    defense = new DefenseCoordinator({ bank, sentinels, events, dataDir: dir });
    await defense.scanOnce();
    const incident = bank.db.prepare("SELECT * FROM sentinel_incidents WHERE id=?").get(incidentId);
    const row = events.db.prepare("SELECT * FROM defense_cases WHERE incident_id=?").get(incidentId);
    defense.finishMergedFraudCode(incident, row, [alert], "approved-head", "ci-run");
    assert.equal(defense.cases()[0].state, "needs_attention");
    await runtime.cycle();
    const med = bank.db.prepare(`SELECT id,customer_id,status FROM med_cases
      WHERE transfer_id=?`).get(transfer.id);
    assert.equal(med?.status, "open");
    assert.equal(med.customer_id, owner);

    const spent = bank.account(recipient).balance_cached - remaining;
    assert.ok(spent > 0);
    bank.post([
      { accountId: recipient, amount: -spent, kind: "recipient_spend",
        actor: "test_recipient", refType: "test", refId: "partial-med" },
      { accountId: seedAccountId(3), amount: spent, kind: "recipient_spend",
        actor: "test_recipient", refType: "test", refId: "partial-med" },
    ]);
    const before = bank.account(accountId).balance_cached;
    const lossId = bank.systemAccountId("bank_loss");
    const lossBefore = bank.account(lossId).balance_cached;
    const gap = 4_800 - remaining;
    const password = "temporary-compensation-password";
    const peerIp = "127.0.0.1";
    auth.setPassword(owner, password);
    const challenge = auth.beginLogin(bank.customer(owner).cpf, password, peerIp, "partial-med-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, owner), peerIp);
    const headers = { authorization: `Bearer ${session.access_token}` };
    assert.equal(bank.compensateIncidentMed(med.id, incidentId), undefined);
    await defense.scanOnce();
    assert.equal(bank.account(accountId).balance_cached, before);

    const operators = new OperatorAuth(bank);
    operators.bootstrap("partial_admin", "temporary-admin-password");
    operators.add("partial_admin", "partial_maker", "maker",
      "temporary-maker-password");
    operators.add("partial_admin", "partial_checker", "reviewer",
      "temporary-review-password");
    const review = new MedOperatorReview(bank);
    const proposal = review.propose(med.id, "approved",
      `sentinel_alerts:${alert.id}`, "partial_maker", "fraud_indicators",
      "The exact customer Pix has a verified suspicious sweep signal.");
    review.confirm(proposal.id, "partial_checker");
    const settled = review.settle(med.id);
    assert.equal(settled.status, "resolved");
    assert.equal(settled.refunded_cents, remaining);
    assert.equal(bank.compensateIncidentMed(med.id, "unrelated_incident"), undefined);
    assert.equal(bank.account(accountId).balance_cached, before + (closedSource ? 0 : remaining));
    // A durable payment may exist before the coordinator records its case receipt.
    const priorPayment = remaining > 0 && !closedSource ?
      bank.compensateIncidentMed(med.id, incidentId) : undefined;
    if (remaining > 0 && !closedSource) assert.equal(priorPayment?.amount, gap);
    if (remaining === 0)
      bank.db.prepare("UPDATE sentinel_incidents SET state='resolved' WHERE id=?").run(incidentId);
    await defense.close();
    defense = new DefenseCoordinator({ bank, sentinels, events, dataDir: dir });
    await defense.scanOnce();
    await defense.scanOnce();
    assert.equal(defense.cases()[0].state, "customer_repaired");
    assert.equal(bank.account(accountId).balance_cached, before + (closedSource ? 0 : 4_800));
    if (closedSource) {
      const credits = bank.closedAccountCredits(owner).items
        .filter((credit) => credit.source_account === accountId);
      assert.deepEqual(credits.map((credit) => credit.amount_cents).sort(), [2_000, 2_800]);
      const destination = seedAccountId(1);
      const previous = bank.account(destination).balance_cached;
      for (const credit of credits)
        bank.claimClosedAccountCredit(owner, credit.id, destination);
      assert.equal(bank.account(destination).balance_cached, previous + 4_800);
    }
    assert.equal(bank.account(lossId).balance_cached, lossBefore - gap);
    const response = await runtime.gateway.call({ method: "GET", path: `/api/v1/pix/med/${med.id}`,
      headers, peerIp });
    assert.equal(response.status, 200);
    assert.equal(response.body.refunded_cents, remaining);
    assert.equal(response.body.bank_compensated_cents, gap);
    const history = events.caseFile.history(incidentId);
    const outcomes = history.filter((entry) =>
      entry.kind === "defense.customer_dispute_outcome");
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].payload.outcome, remaining ? "partial_refund" : "no_funds_recovered");
    assert.equal(outcomes[0].payload.refunded_cents, remaining);
    assert.equal(outcomes[0].payload.unrecovered_cents, gap);
    const receipts = history.filter((entry) => entry.kind === "defense.customer_repair_verified");
    assert.equal(receipts.length, 1);
    const paid = { txId: receipts[0].payload.bank_compensation_tx_id, amount: gap };
    if (priorPayment) assert.deepEqual(paid, priorPayment);
    const reopened = new Bank(join(dir, "bank.sqlite"), () => now, undefined,
      { ecosystemMode: "separated" });
    try { assert.deepEqual(reopened.compensateIncidentMed(med.id, incidentId), paid); }
    finally { reopened.close(); }
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.closedCreditReconciliation().ok, true);
    assert.equal((await runtime.crossBookNow())?.report.ok, true);
  } finally {
    await defense?.close(); await runtime?.close(); events.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a scheduled partial MED claim is made whole once after scoped dual approval",
  () => verifyScopedMedCompensation(2_000));

test("the bank compensates an approved scheduled MED claim when recovery is zero",
  () => verifyScopedMedCompensation(0));

test("a scheduled MED claim for a closed account remains payable to its owner",
  () => verifyScopedMedCompensation(2_000, true));

test("a rejected MED records the disposition without resolving the underlying fraud impact", async () => {
  const item = await setup();
  try {
    item.defense.finishMergedFraudCode(item.incident, item.row,
      [item.alert], "approved-head", "ci-run");
    const med = item.bank.requestMed(seedCustomerId(8), item.transfer.id);
    const operators = new OperatorAuth(item.bank);
    operators.bootstrap("reject_admin", "temporary-admin-password");
    operators.add("reject_admin", "reject_maker", "maker", "temporary-maker-password");
    operators.add("reject_admin", "reject_checker", "reviewer", "temporary-review-password");
    const review = new MedOperatorReview(item.bank);
    const proposal = review.propose(med.id, "rejected",
      `sentinel_alerts:${item.alert.id}`, "reject_maker", "insufficient_evidence",
      "The reviewed dispute did not establish a customer loss.");
    assert.equal(review.confirm(proposal.id, "reject_checker").status, "rejected");
    await item.defense.scanOnce();
    await item.defense.scanOnce();
    const history = item.events.caseFile.history(item.incident.id);
    const outcomes = history.filter((entry) =>
      entry.kind === "defense.customer_dispute_outcome");
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0].payload.outcome, "claim_rejected");
    assert.equal(outcomes[0].payload.refunded_cents, 0);
    assert.equal(outcomes[0].payload.unrecovered_cents, null);
    assert.equal(history.some((entry) => entry.kind === "defense.customer_repair_verified"), false);
    assert.equal(item.defense.cases()[0].state, "needs_attention");
    assert.equal(item.bank.reconcile().ok, true);
  } finally { await item.close(); }
});

test("a full MED refund citing another alert does not close this defense case", async () => {
  const item = await setup();
  try {
    item.defense.finishMergedFraudCode(item.incident, item.row,
      [item.alert], "approved-head", "ci-run");
    const med = item.bank.requestMed(seedCustomerId(8), item.transfer.id);
    const operators = new OperatorAuth(item.bank);
    operators.bootstrap("wrong_admin", "temporary-admin-password");
    operators.add("wrong_admin", "wrong_maker", "maker",
      "temporary-maker-password");
    operators.add("wrong_admin", "wrong_checker", "reviewer",
      "temporary-review-password");
    const review = new MedOperatorReview(item.bank);
    const proposal = review.propose(med.id, "approved",
      "sentinel_alerts:unrelated", "wrong_maker", "fraud_indicators",
      "The manually supplied reference is unrelated to this case.");
    review.confirm(proposal.id, "wrong_checker");
    assert.equal(review.settle(med.id).status, "refunded");
    await item.defense.scanOnce();
    assert.equal(item.defense.cases()[0].state, "needs_attention");
    assert.equal(item.events.caseFile.history(item.incident.id).filter((entry) =>
      entry.kind === "defense.customer_repair_verified").length, 0);
    assert.equal(item.bank.reconcile().ok, true);
  } finally { await item.close(); }
});
