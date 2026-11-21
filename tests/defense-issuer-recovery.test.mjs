import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { CardNetwork } from "../apps/world/src/ecosystem/card-network.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { listIncidentNotices, recordIssuerRecoveryNotice } from
  "../apps/world/src/incident-notices.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { BlueInvestigation } from "../apps/orchestrator/src/blue-investigation.ts";
import { DefenseCoordinator } from "../apps/orchestrator/src/defense-coordinator.ts";
import { ROLE_TOOLS } from "../apps/orchestrator/src/agent-loop.ts";
import { EventStore } from "../packages/event-store/src/index.ts";

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "bv-issuer-recovery-"));
  let now = new Date("2026-11-18T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now, () => now);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const cards = new CardsEngine(bank);
  const network = new CardNetwork(bank, cards);
  const card = cards.issueDebit(seedCustomerId(1), seedAccountId(1), 10_000);
  const events = new EventStore(join(dir, "events.sqlite"));
  const sentinels = new SentinelEngine(bank, events);
  const authorize = () => network.authorize({ cardId: card.id,
    merchantId: "shop_ipe", amountCents: 500, entryMode: "chip",
    cvv: cards.vault.currentCvv(card.id) });
  const advance = (seconds) => { now = new Date(now.getTime() + seconds * 1000); };
  const prior = authorize();
  assert.equal(prior.response_code, "00");
  advance(1);
  network.setIssuerAvailability(false, "external_test");
  advance(1);
  const rejected = authorize();
  assert.equal(rejected.response_code, "91");
  advance(1);
  assert.ok(sentinels.scan().some((item) => item.rule_id === "S-CARD-13"));
  const incident = sentinels.recentIncidents().find((item) =>
    item.area === "cards" && item.entity_key === "card_issuer");
  assert.ok(incident);
  return { dir, bank, events, sentinels, network, incident, rejected,
    authorize, advance, close() { events.close(); bank.close();
      rmSync(dir, { recursive: true, force: true }); } };
}

test("issuer proof requires restoration and a later real accepted authorization", () => {
  const env = fixture();
  try {
    const status = () => new BlueInvestigation(env.bank, env.incident.id).issuerStatus();
    assert.equal(status()?.phase, "outage_confirmed");
    assert.equal(status()?.rejectionsByCode.find((item) => item.code === "91")?.count, 1);
    assert.equal(status()?.availabilityHistory.at(-1)?.available, false);
    env.advance(1);
    env.network.setIssuerAvailability(true, "external_test");
    assert.equal(status()?.phase, "restored_awaiting_authorization");
    assert.equal(status()?.authorizationId, null);
    env.advance(1);
    const accepted = env.authorize();
    assert.equal(accepted.response_code, "00");
    assert.equal(status()?.phase, "recovered");
    assert.equal(status()?.authorizationId, accepted.id);
    assert.equal(status()?.acceptedAfterRestoreCount, 1);
    assert.equal(status()?.availabilityHistory.at(-1)?.available, true);
    assert.ok(status()?.evidenceRefs.includes(`card_network_authorizations:${accepted.id}`));
  } finally { env.close(); }
});

test("an old or unlinked alert cannot establish issuer recovery", () => {
  const env = fixture();
  try {
    const status = () => new BlueInvestigation(env.bank, env.incident.id).issuerStatus();
    env.advance(1);
    env.network.setIssuerAvailability(true, "external_test");
    assert.equal(status()?.phase, "restored_awaiting_authorization",
      "the authorization before the outage is insufficient");
    env.bank.db.prepare("UPDATE sentinel_incidents SET opened_at=? WHERE id=?")
      .run("2026-11-18T12:01:00.000Z", env.incident.id);
    assert.equal(status(), null, "an alert before this incident is not linked");
  } finally { env.close(); }
});

test("a bare authorization row without its network response is not recovery proof", () => {
  const env = fixture();
  try {
    env.advance(1);
    env.network.setIssuerAvailability(true, "external_test");
    env.advance(1);
    const accepted = env.authorize();
    assert.equal(accepted.response_code, "00");
    env.bank.db.prepare(`DELETE FROM card_network_messages
      WHERE authorization_id=? AND mti='0110'`).run(accepted.id);
    assert.equal(new BlueInvestigation(env.bank, env.incident.id)
      .issuerStatus()?.phase, "restored_awaiting_authorization");
  } finally { env.close(); }
});

test("coordinator monitors an external outage without claiming customer repair", async () => {
  const env = fixture();
  try {
    const roles = [];
    const runtime = { async run(spec) {
      assert.ok(spec.tools.every((item) => ROLE_TOOLS[spec.role].has(item.name)),
        `All ${spec.role} tools must be permitted by the live runtime`);
      roles.push(spec.role);
      const core = { incident_id: env.incident.id,
        case_version: spec.snapshot.caseVersion };
      const alertRef = `sentinel_alerts:${new BlueInvestigation(env.bank,
        env.incident.id).issuerStatus().alertId}`;
      const rejectionRef = `card_network_rejections:${env.rejected.id}`;
      if (spec.role === "investigator") {
        await spec.tools.find((item) => item.name === "alerts.get").execute({
          cluster_id: env.incident.id }, new AbortController().signal);
        const issuer = await spec.tools.find((item) =>
          item.name === "cards.issuer_status").execute({ incident_id: env.incident.id },
            new AbortController().signal);
        assert.equal(issuer.phase, "outage_confirmed");
        const body = { ...core, profile: "operations", disposition: "confirmed",
          facts: [{ statement: "External issuer declined a network authorization",
            evidence_refs: [alertRef, rejectionRef] }], hypotheses: [],
          affected_entities: [], unknowns: ["Individual customer impact"],
          recommended_action: "observe",
          recommendation_reason: "Wait for a new accepted authorization" };
        assert.equal(spec.validateDossier(body), true);
        return { status: "ok", data: body, tokens: 1 };
      }
      if (spec.role === "damage_assessor") {
        const impact = await spec.tools[0].execute({ incident_id: env.incident.id },
          new AbortController().signal);
        assert.ok(impact.issuerAttempts.some((attempt) =>
          attempt.rejection_id === env.rejected.id &&
          attempt.customer_id === seedCustomerId(1)));
        assert.equal(impact.issuerUnlinkedAttempts, 0);
        assert.equal(spec.validateDossier({ ...core, findings: [],
          unverified_categories: [], customer_repair_required: "unknown" }), false,
        "a linked declined customer cannot disappear from impact assessment");
        return { status: "ok", data: { ...core, findings: [{
          kind: "service_unavailable", entity_ref: seedCustomerId(1),
          evidence_refs: [rejectionRef], amount_cents: null,
          assessment: "The customer's card authorization was declined during the outage",
        }], unverified_categories: ["Whether the purchase was retried"],
          customer_repair_required: "yes" }, tokens: 1 };
      }
      if (spec.role === "architect") return { status: "ok", data: {
        ...core, disposition: "external_recovery",
        cause_hypothesis: "External issuer unavailable", evidence_refs: [alertRef, rejectionRef],
        proposed_change: "Monitor restoration and an accepted authorization",
        acceptance_invariants: ["No bank money movement"],
        do_not_break: ["Existing authorizations"], rollback_plan: "No bank change",
        unknowns: ["Individual customer harm"] }, tokens: 1 };
      assert.equal(spec.role, "reviewer");
      assert.equal(spec.dossier.candidate.phase, "outage_confirmed");
      return { status: "ok", data: { ...core, verdict: "approve",
        evidence_refs: [alertRef, rejectionRef],
        findings: ["Monitor aggregate recovery only"], correction_risk: "low",
        customer_impact_checked: true }, tokens: 1 };
    } };
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir, runtime });
    await coordinator.scanOnce(); await coordinator.scanOnce(); await coordinator.scanOnce();
    assert.deepEqual(roles, ["investigator", "damage_assessor", "architect", "reviewer"]);
    assert.equal(env.events.caseFile.history(env.incident.id).find((entry) =>
      entry.kind === "dossier.defense_impact")?.payload.findings[0].entity_ref,
    seedCustomerId(1));
    assert.equal(coordinator.cases()[0].state, "monitoring_external");
    assert.equal(env.events.caseFile.history(env.incident.id).some((entry) =>
      entry.kind === "defense.external_recovery_verified"), false);
    await coordinator.close();
    const resumed = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir });
    env.advance(1); env.network.setIssuerAvailability(true, "external_test");
    await resumed.scanOnce();
    assert.equal(resumed.cases()[0].state, "monitoring_external");
    env.advance(1);
    const accepted = env.authorize();
    assert.equal(accepted.response_code, "00");
    await resumed.scanOnce();
    assert.equal(resumed.cases()[0].state, "external_recovered");
    const receipt = env.events.caseFile.history(env.incident.id).find((entry) =>
      entry.kind === "defense.external_recovery_verified");
    assert.equal(receipt.payload.case_version, 1);
    assert.equal(receipt.payload.revision, 0);
    assert.equal(receipt.payload.customer_repair, "not_proven");
    assert.equal(receipt.payload.bank_correction_applied, false);
    assert.ok(receipt.payload.evidence_refs.includes(
      `card_network_authorizations:${accepted.id}`));
    assert.equal(receipt.payload.notified_customer_count, 1);
    const notices = listIncidentNotices(env.bank.db, seedCustomerId(1));
    assert.equal(notices.items.length, 1);
    assert.match(notices.items[0].message_pt, /serviço voltou/i);
    assert.equal(listIncidentNotices(env.bank.db, seedCustomerId(2)).items.length, 0);
    assert.equal(env.events.caseFile.history(env.incident.id).filter((entry) =>
      entry.kind === "defense.customer_notice").length, 1);
    assert.equal(recordIssuerRecoveryNotice(env.bank, {
      incidentId: env.incident.id, customerId: seedCustomerId(1),
      outageHistoryId: receipt.payload.outage_history_id,
      rejectionId: env.rejected.id,
      restoredHistoryId: receipt.payload.restored_history_id,
      authorizationId: accepted.id,
    }).id, notices.items[0].id);
    assert.equal(listIncidentNotices(env.bank.db, seedCustomerId(1)).items.length, 1);
    assert.throws(() => recordIssuerRecoveryNotice(env.bank, {
      incidentId: env.incident.id, customerId: seedCustomerId(2),
      outageHistoryId: receipt.payload.outage_history_id,
      rejectionId: env.rejected.id,
      restoredHistoryId: receipt.payload.restored_history_id,
      authorizationId: accepted.id,
    }), /DEF_INCIDENT_NOTICE_EVIDENCE/);
    assert.throws(() => recordIssuerRecoveryNotice(env.bank, {
      incidentId: env.incident.id, customerId: seedCustomerId(1),
      outageHistoryId: receipt.payload.outage_history_id,
      rejectionId: env.rejected.id,
      restoredHistoryId: receipt.payload.restored_history_id,
      authorizationId: "unlinked_authorization",
    }), /DEF_INCIDENT_NOTICE_EVIDENCE/);
    assert.throws(() => env.bank.db.prepare(`UPDATE incident_customer_notices
      SET message_pt='changed' WHERE customer_id=?`).run(seedCustomerId(1)),
    /INCIDENT_NOTICE_IMMUTABLE/);
    const auth = new AuthEngine(env.bank);
    const app = createTwinApi(env.bank, auth);
    try {
      const access = async (customerId) => {
        auth.setPassword(customerId, "local-notice-password-123");
        const login = await app.inject({ method: "POST", url: "/auth/login",
          payload: { cpf: env.bank.customer(customerId).cpf,
            password: "local-notice-password-123", device_id: `notice-${customerId}` } });
        const challengeId = login.json().challenge_id;
        const otp = await app.inject({ method: "POST", url: "/auth/otp",
          payload: { challenge_id: challengeId,
            otp: auth.simulatedOtp(challengeId, customerId) } });
        return { authorization: `Bearer ${otp.json().access_token}` };
      };
      assert.equal((await app.inject({ method: "GET",
        url: "/incidents/notices" })).statusCode, 403);
      const owner = await app.inject({ method: "GET", url: "/incidents/notices",
        headers: await access(seedCustomerId(1)) });
      assert.equal(owner.statusCode, 200);
      assert.equal(owner.json().items.length, 1);
      const other = await app.inject({ method: "GET", url: "/incidents/notices",
        headers: await access(seedCustomerId(2)) });
      assert.equal(other.statusCode, 200);
      assert.equal(other.json().items.length, 0);
      assert.equal((await app.inject({ method: "GET",
        url: `/incidents/notices?before=${notices.items[0].id}`,
        headers: await access(seedCustomerId(2)) })).statusCode, 404);
    } finally { await app.close(); }
    await resumed.close();
  } finally { env.close(); }
});
