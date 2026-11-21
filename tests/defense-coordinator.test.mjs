import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { Bank } from "../apps/world/src/bank.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { EventStore } from "../packages/event-store/src/index.ts";
import { DefenseCoordinator } from "../apps/orchestrator/src/defense-coordinator.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { FeatureRegistry } from "../apps/world/src/features.ts";
import { DynamicLimits } from "../apps/world/src/dynamic-limits.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { Gateway } from "../apps/world/src/gateway.ts";
import { CustomerSimulator } from "../apps/world/src/simulator.ts";
import { FaultLab } from "../apps/orchestrator/src/fault-lab.ts";
import { FaultLabEvaluator } from "../apps/orchestrator/src/fault-lab-evaluator.ts";
import { createFaultLabAdapters } from "../apps/orchestrator/src/fault-lab-adapters.ts";
import { exportSplitSnapshots } from "../scripts/export-ecosystem-snapshot.mjs";
import { EcosystemClient } from "../apps/ecosystem/src/client.ts";
import { CrossBookVerifierClient } from "../apps/ecosystem/src/verifier-client.ts";
import { SeparatedPixCoordinator } from
  "../apps/world/src/separated-pix-coordinator.ts";

function environment() {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-defense-"));
  const now = () => new Date("2026-11-18T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), now, now);
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const events = new EventStore(join(dir, "events.sqlite"));
  const sentinels = new SentinelEngine(bank, events);
  return { dir, bank, events, sentinels, close() {
    events.close(); bank.close(); rmSync(dir, { recursive: true, force: true });
  } };
}

test("statement outage agents require the exact denied customer and account", async () => {
  const env = environment();
  try {
    const customerId = env.bank.db.prepare(`SELECT id FROM customers ORDER BY id LIMIT 1`)
      .get().id;
    const accountId = env.bank.db.prepare(`SELECT id FROM accounts
      WHERE customer_id=? ORDER BY id LIMIT 1`).get(customerId).id;
    const failedId = "statement_denied_case";
    env.bank.db.prepare(`INSERT INTO access_log
      (id,ts,actor,kind,customer_id,account_id,route,status)
      VALUES (?,?,?,?,?,?,?,?)`).run(failedId, env.bank.now().toISOString(),
        customerId, "statement_own", customerId, accountId,
        `/accounts/${accountId}/statement`, 503);
    const alert = env.sentinels.scan().find((item) => item.rule_id === "S-ACC-04");
    assert.ok(alert);
    const incident = env.sentinels.recentIncidents().find((item) =>
      item.area === "accounts" && item.entity_key === customerId);
    assert.ok(incident);
    const alertRef = `sentinel_alerts:${alert.alert_id}`;
    const failedRef = `access_log:${failedId}`;
    const roles = [];
    const runtime = { async run(spec) {
      roles.push(spec.role);
      const common = { incident_id: incident.id,
        case_version: spec.snapshot.caseVersion };
      if (spec.role === "investigator") {
        assert.match(spec.goalPt, /own-statement request/);
        assert.deepEqual(spec.dossier.statementFailures, [{ alertRef,
          failedLogRef: failedRef, customerId, accountId }]);
        const evidence = await spec.tools[0].execute({ cluster_id: incident.id },
          new AbortController().signal);
        assert.ok(evidence.alerts.some((item) => item.id === alert.alert_id));
        const body = { ...common,
          profile: "operations", disposition: "confirmed",
          facts: [{ statement: "Own statement returned 503",
            evidence_refs: [alertRef, failedRef] }], hypotheses: [],
          affected_entities: [customerId], unknowns: [],
          recommended_action: "assess_customer_impact",
          recommendation_reason: "Customer cannot read the statement" };
        assert.equal(spec.validateDossier({ ...body,
          facts: [{ ...body.facts[0],
            evidence_refs: ["access_log:unrelated"] }] }), false);
        assert.equal(spec.validationFeedback(), "no_scoped_fact");
        assert.equal(spec.validateDossier({ ...body,
          facts: [{ ...body.facts[0], evidence_refs: [alertRef, "access_log:unrelated"] }] }), false);
        assert.equal(spec.validationFeedback(), "unscoped_fact_reference");
        assert.equal(spec.validateDossier(body), true);
        assert.equal(spec.validationFeedback(), undefined);
        return { status: "ok", tokens: 1, data: body };
      }
      if (spec.role === "damage_assessor") {
        assert.match(spec.goalPt, /statementDenials/);
        const snapshot = await spec.tools[0].execute({ incident_id: incident.id },
          new AbortController().signal);
        assert.deepEqual(snapshot.statementDenials, [{ alertId: alert.alert_id,
          failedLogId: failedId, customerId, accountId }]);
        const body = { ...common, findings: [{ kind: "service_unavailable",
          entity_ref: customerId, evidence_refs: [alertRef, failedRef],
          amount_cents: null, assessment: "Statement request failed" }],
          unverified_categories: [], customer_repair_required: "yes" };
        assert.equal(spec.validateDossier({ ...body, findings: [] }), false);
        assert.equal(spec.validateDossier(body), true);
        return { status: "ok", tokens: 1, data: body };
      }
      if (spec.role === "architect") {
        assert.match(spec.goalPt, /later 200 for the same customer and account/);
        const body = { ...common, disposition: "source_recovery",
          cause_hypothesis: "Statement service is unavailable",
          evidence_refs: [alertRef, failedRef],
          proposed_change: "Monitor restoration of the exact statement route",
          acceptance_invariants: ["Same customer and account read succeeds"],
          do_not_break: ["Customer isolation"],
          rollback_plan: "Keep the case open if the route still fails", unknowns: [] };
        assert.equal(spec.validateDossier({ ...body,
          evidence_refs: [alertRef] }), false);
        assert.equal(spec.validateDossier(body), true);
        return { status: "ok", tokens: 1, data: body };
      }
      assert.equal(spec.role, "reviewer");
      assert.match(spec.goalPt, /same customer on the same account/);
      const body = { ...common, verdict: "approve",
        evidence_refs: [alertRef, failedRef],
        findings: ["Require a later same-owner statement read"],
        correction_risk: "low", customer_impact_checked: true };
      assert.equal(spec.validateDossier({ ...body,
        evidence_refs: [alertRef] }), false);
      assert.equal(spec.validateDossier(body), true);
      return { status: "ok", tokens: 1, data: body };
    } };
    const coordinator = new DefenseCoordinator({ bank: env.bank,
      sentinels: env.sentinels, events: env.events, dataDir: env.dir, runtime });
    for (let index = 0; index < 6; index++) await coordinator.scanOnce();
    assert.deepEqual(new Set(roles), new Set([
      "investigator", "damage_assessor", "architect", "reviewer"]));
    assert.equal(coordinator.cases()[0].state, "monitoring_external");
    env.bank.db.prepare(`INSERT INTO access_log
      (id,ts,actor,kind,customer_id,account_id,route,status)
      VALUES (?,?,?,?,?,?,?,?)`).run("statement_recovered_case",
        env.bank.now().toISOString(), customerId, "statement_own",
        customerId, accountId, `/accounts/${accountId}/statement`, 200);
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].state, "external_recovered");
    assert.ok(env.events.caseFile.history(incident.id).some((entry) =>
      entry.kind === "defense.source_recovery_verified" &&
      entry.payload.evidence_refs.includes(failedRef)));
    await coordinator.close();
  } finally { env.close(); }
});

function realLedgerIncident(env) {
  env.bank.spi.fund("12345678", 1);
  assert.ok(env.sentinels.scan().some((alert) => alert.rule_id === "S-LED-02"));
  const incident = env.sentinels.recentIncidents().find((item) => item.area === "ledger");
  assert.ok(incident);
  return incident;
}

test("a real Sentinel incident becomes a durable case without an attack round or model", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir });
    await coordinator.scanOnce();
    assert.deepEqual(coordinator.cases().map((item) =>
      [item.incidentId, item.profile, item.state]), [[incident.id, "integrity", "awaiting_runtime"]]);
    assert.equal(env.events.caseFile.history(incident.id).filter((entry) =>
      entry.kind === "defense.observed").length, 1);
    await coordinator.scanOnce();
    assert.equal(env.events.caseFile.history(incident.id).filter((entry) =>
      entry.kind === "defense.observed").length, 1);
    await coordinator.close();
    const restarted = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir });
    await restarted.scanOnce();
    assert.equal(restarted.cases()[0].caseVersion, 1);
    await restarted.close();
  } finally { env.close(); }
});

test("interrupted defense handoffs reopen at their durable retry stage", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    let coordinator = new DefenseCoordinator({ bank: env.bank,
      sentinels: env.sentinels, events: env.events, dataDir: env.dir });
    await coordinator.scanOnce();
    await coordinator.close();
    for (const [interrupted, expected] of [
      ["investigating", "retry_pending"],
      ["planning", "investigated"],
      ["reviewing", "planned"],
    ]) {
      env.events.db.prepare("UPDATE defense_cases SET state=? WHERE incident_id=?")
        .run(interrupted, incident.id);
      coordinator = new DefenseCoordinator({ bank: env.bank,
        sentinels: env.sentinels, events: env.events, dataDir: env.dir });
      assert.equal(coordinator.cases()[0].state, expected);
      assert.equal(env.events.caseFile.history(incident.id).filter((entry) =>
        entry.kind === "defense.observed").length, 1);
      await coordinator.close();
    }
  } finally { env.close(); }
});

test("a promoted code case retries a failed restart request without repeating the merge", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const initial = new DefenseCoordinator({ bank: env.bank,
      sentinels: env.sentinels, events: env.events, dataDir: env.dir });
    await initial.scanOnce();
    const caseRow = initial.cases()[0];
    await initial.close();
    const head = "a".repeat(40);
    const ciRun = "ci_restart_test";
    env.events.caseFile.record({ incidentId: incident.id, roundId: null,
      kind: "defense.code_merged", actorId: "test",
      entryKey: "defense:code_merged:restart_test",
      createdAt: "2026-11-18T12:00:00.000Z",
      payload: { case_version: caseRow.caseVersion, head_sha: head,
        ci_run_id: ciRun, status: "restart_pending" } });
    env.events.db.prepare(`UPDATE defense_cases SET state='code_merged'
      WHERE incident_id=?`).run(incident.id);
    let requests = 0;
    const coordinatorInput = { bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir,
      runtime: { async run() { assert.fail("no agent should start"); } },
      repoRoot: env.dir, loadedCodeHead: "previous-head", onCodePromotion() {
        requests++;
        if (requests === 1) throw new Error("restart callback unavailable");
      } };
    const coordinator = new DefenseCoordinator(coordinatorInput);
    env.events.db.prepare(`INSERT INTO patch_ci_runs VALUES
      (?,?,?,?,?,'merged',NULL,NULL,?,?)`).run(ciRun, "task_restart_test",
      "b".repeat(40), head, "c".repeat(64),
      "2026-11-18T12:00:00.000Z", "{}");
    await coordinator.scanOnce();
    assert.equal(requests, 1);
    assert.equal(coordinator.cases()[0].state, "code_merged");
    assert.match(env.events.db.prepare(`SELECT last_error FROM defense_cases
      WHERE incident_id=?`).get(incident.id).last_error,
    /^code_restart_request_failed:/);
    assert.equal(env.events.caseFile.history(incident.id).filter((entry) =>
      entry.kind === "defense.code_restart_requested").length, 0);
    await coordinator.close();
    const restarted = new DefenseCoordinator(coordinatorInput);
    await restarted.scanOnce();
    assert.equal(requests, 2);
    assert.equal(restarted.cases()[0].state, "code_merged");
    assert.equal(env.events.db.prepare(`SELECT last_error FROM defense_cases
      WHERE incident_id=?`).get(incident.id).last_error, null);
    await restarted.scanOnce();
    assert.equal(requests, 2);
    assert.equal(env.events.caseFile.history(incident.id).filter((entry) =>
      entry.kind === "defense.code_restart_requested").length, 1);
    await restarted.close();
  } finally { env.close(); }
});

test("repeated live Sentinel scans keep one case version despite rolling counters", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir });
    await coordinator.scanOnce();
    const first = coordinator.cases()[0];
    const alert = env.bank.db.prepare(`SELECT id,observed_json FROM sentinel_alerts
      WHERE entity=? LIMIT 1`).get(incident.entity_key);
    assert.ok(alert);
    for (let index = 1; index <= 3; index++) {
      env.sentinels.scan();
      env.bank.db.prepare(`UPDATE sentinel_alerts SET count=count+1,last_seen=?,
        observed_json=? WHERE id=?`).run(`2026-11-18T12:00:0${index}.000Z`,
          JSON.stringify({ ...JSON.parse(alert.observed_json), age_ms: index * 1000,
            overdue_seconds: index * 10, declined_authorizations: index }), alert.id);
      env.bank.db.prepare(`UPDATE sentinel_incidents SET alert_count=alert_count+1,
        last_seen_at=? WHERE id=?`).run(`2026-11-18T12:00:0${index}.000Z`, incident.id);
      await coordinator.scanOnce();
      assert.equal(coordinator.cases()[0].caseVersion, first.caseVersion);
    }
    assert.equal(env.events.caseFile.history(incident.id).filter((entry) =>
      entry.kind === "defense.observed").length, 1);
    env.bank.db.prepare(`UPDATE sentinel_alerts SET observed_json=
      json_set(observed_json,'$.missing_hour_start','2026-11-18T11:00:00.000Z') WHERE id=?`)
      .run(alert.id);
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].caseVersion, first.caseVersion + 1);
    await coordinator.close();
  } finally { env.close(); }
});

test("a new alert or severity change creates a new case version", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir });
    await coordinator.scanOnce();
    const start = coordinator.cases()[0].caseVersion;
    env.bank.db.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?,?,?,?)`)
      .run("new-ledger-alert", "S-LED-03", incident.entity_key, '{"new_issue":1}',
        60, "2026-11-18T12:00:00.000Z", "2026-11-18T12:00:00.000Z", 1,
        "2026-11-18T12:00:00.000Z");
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].caseVersion, start + 1);
    env.bank.db.prepare("UPDATE sentinel_incidents SET severity='high' WHERE id=?")
      .run(incident.id);
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].caseVersion, start + 2);
    env.bank.db.prepare(`UPDATE sentinel_alerts SET observed_json=? WHERE id=?`)
      .run('{"new_issue":2}', "new-ledger-alert");
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].caseVersion, start + 3);
    assert.equal(env.events.caseFile.history(incident.id).filter((entry) =>
      entry.kind === "defense.observed").length, 4);
    await coordinator.close();
  } finally { env.close(); }
});

test("more than thirty alerts do not change case version when recency order changes", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const insert = env.bank.db.prepare(`INSERT INTO sentinel_alerts VALUES
      (?,?,?,?,?,?,?,?,?)`);
    for (let index = 0; index < 35; index++)
      insert.run(`extra-${index}`, `S-EXTRA-${index}`, incident.entity_key,
        '{"signal":"stable"}', 60, "2026-11-18T12:00:00.000Z",
        new Date(Date.parse("2026-11-18T12:00:00.000Z") + index * 1000)
          .toISOString(), 1, "2026-11-18T12:00:00.000Z");
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir });
    await coordinator.scanOnce();
    const first = coordinator.cases()[0].caseVersion;
    const observed = env.events.caseFile.history(incident.id).find((entry) =>
      entry.kind === "defense.observed");
    assert.equal(observed.payload.alerts_truncated, true);
    assert.ok(observed.payload.alert_count_total > 30);
    assert.equal(observed.payload.alert_refs.length, 30);
    env.bank.db.prepare("UPDATE sentinel_alerts SET last_seen=? WHERE id=?")
      .run("2026-11-18T12:02:00.000Z", "extra-0");
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].caseVersion, first);
    insert.run("extra-new", "S-EXTRA-NEW", incident.entity_key,
      '{"signal":"new"}', 60, "2026-11-18T12:02:01.000Z",
      "2026-11-18T12:02:01.000Z", 1, "2026-11-18T12:02:01.000Z");
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].caseVersion, first + 1);
    await coordinator.close();
  } finally { env.close(); }
});

test("a closed incident is not silently treated as a completed defense case", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir });
    await coordinator.scanOnce();
    env.bank.db.prepare("UPDATE sentinel_incidents SET state='resolved' WHERE id=?")
      .run(incident.id);
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].state, "needs_attention");
    await coordinator.close();
  } finally { env.close(); }
});

test("isolated investigator receives scoped evidence and cannot authorize an effect", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    let seen = false;
    const runtime = { async run(spec) {
      seen = true;
      assert.equal(spec.role, "investigator");
      assert.ok(spec.system[0].includes("read-only"));
      assert.ok(spec.tools.every((tool) => tool.kind === "investigate"));
      assert.deepEqual(new Set(spec.tools.map((tool) => tool.name)),
        new Set(["alerts.get", "logs.query", "ledger.trace", "ledger.query", "entity.profile"]));
      await assert.rejects(spec.tools.find((tool) => tool.name === "entity.profile")
        .execute({ id: "unrelated-customer" }, new AbortController().signal),
      /DEF_ENTITY_SCOPE/);
      await assert.rejects(spec.tools.find((tool) => tool.name === "ledger.trace")
        .execute({ account_id: "unrelated-account", depth: 1 },
          new AbortController().signal), /DEF_ENTITY_SCOPE/);
      const alerts = await spec.tools[0].execute({ cluster_id: incident.id }, new AbortController().signal);
      assert.ok(alerts.alerts.length > 0);
      const body = { incident_id: incident.id, case_version: spec.snapshot.caseVersion,
        profile: "integrity", disposition: "confirmed",
        facts: [{ statement: "Bank and settlement records disagree",
          evidence_refs: [`sentinel_alerts:${alerts.alerts[0].id}`] }],
        hypotheses: [], affected_entities: [], unknowns: [],
        recommended_action: "investigate_more",
        recommendation_reason: "Reconcile the authoritative books before any write" };
      assert.equal(await spec.validateDossier(body), true);
      return { status: "ok", data: body, tokens: 10 };
    } };
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir, runtime });
    await coordinator.scanOnce();
    assert.equal(seen, true);
    assert.equal(coordinator.cases()[0].state, "investigated");
    const history = env.events.caseFile.history(incident.id);
    assert.ok(history.some((entry) => entry.kind === "defense.handoff" &&
      entry.payload.input_sha256.length === 64));
    assert.ok(history.some((entry) => entry.kind === "dossier.defense_investigation"));
    assert.equal(env.bank.db.prepare("SELECT state FROM sentinel_incidents WHERE id=?")
      .get(incident.id).state, "open");
    await coordinator.close();
  } finally { env.close(); }
});

test("an unsupported model assertion is rejected and never becomes a verified dossier", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const runtime = { async run(spec) {
      await spec.tools[0].execute({ cluster_id: incident.id }, new AbortController().signal);
      return { status: "ok", tokens: 1, data: {
        incident_id: incident.id, case_version: spec.snapshot.caseVersion,
        profile: "integrity", disposition: "confirmed",
        facts: [{ statement: "Unsupported assertion",
          evidence_refs: ["sentinel_alerts:unrelated"] }],
        hypotheses: [], affected_entities: [], unknowns: [],
        recommended_action: "bounded_containment",
        recommendation_reason: "Unsupported" } };
    } };
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir, runtime });
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].state, "retry_pending");
    assert.equal(env.events.caseFile.history(incident.id).some((entry) =>
      entry.kind === "dossier.defense_investigation"), false);
    await coordinator.close();
  } finally { env.close(); }
});

test("verified investigation feeds scoped architect and impact handoffs", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const roles = [];
    const runtime = { async run(spec) {
      roles.push(spec.role);
      const alertRef = spec.dossier.alertRefs.find((item) => item.startsWith("sentinel_alerts:"));
      if (spec.role === "investigator") {
        const alerts = await spec.tools[0].execute({ cluster_id: incident.id },
          new AbortController().signal);
        assert.ok(alerts.alerts.length);
        const body = { incident_id: incident.id, case_version: spec.snapshot.caseVersion,
          profile: "integrity", disposition: "confirmed",
          facts: [{ statement: "Settlement mismatch exists", evidence_refs: [alertRef] }],
          hypotheses: [], affected_entities: [], unknowns: [],
          recommended_action: "assess_customer_impact",
          recommendation_reason: "Assess linked ledger evidence" };
        assert.equal(spec.validateDossier(body), true);
        return { status: "ok", data: body, tokens: 1 };
      }
      if (spec.role === "damage_assessor") {
        assert.deepEqual(spec.tools.map((tool) => tool.name), ["ledger.scan_damage"]);
        const evidence = await spec.tools[0].execute({ incident_id: incident.id },
          new AbortController().signal);
        assert.equal(evidence.incidentId, incident.id);
        const body = { incident_id: incident.id, case_version: spec.snapshot.caseVersion,
          findings: [{ kind: "unknown", entity_ref: incident.entity_key,
            evidence_refs: [alertRef], amount_cents: null,
            assessment: "Customer impact is not established" }],
          unverified_categories: ["customer loss"], customer_repair_required: "unknown" };
        assert.equal(spec.validateDossier(body), true);
        return { status: "ok", data: body, tokens: 1 };
      }
      if (spec.role === "reviewer") return { status: "ok", tokens: 1, data: {
        incident_id: incident.id, case_version: spec.snapshot.caseVersion,
        verdict: "approve", evidence_refs: [alertRef],
        findings: ["No bounded correction is established"],
        correction_risk: "low", customer_impact_checked: true } };
      assert.equal(spec.role, "architect");
      assert.deepEqual(spec.tools, []);
      assert.equal(spec.dossier.investigation.facts[0].evidence_refs[0], alertRef);
      const body = { incident_id: incident.id, case_version: spec.snapshot.caseVersion,
        disposition: "insufficient_evidence", cause_hypothesis: "Source mismatch",
        evidence_refs: [alertRef], proposed_change: "Inspect source reconciliation",
        acceptance_invariants: ["No double posting"],
        do_not_break: ["Valid transfers"], rollback_plan: "No change made", unknowns: [] };
      assert.equal(spec.validateDossier(body), true);
      return { status: "ok", data: body, tokens: 1 };
    } };
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir, runtime });
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].state, "planned");
    assert.deepEqual(new Set(roles), new Set(["investigator", "architect", "damage_assessor"]));
    const history = env.events.caseFile.history(incident.id);
    assert.ok(history.some((entry) => entry.kind === "dossier.defense_plan"));
    assert.ok(history.some((entry) => entry.kind === "dossier.defense_impact"));
    assert.equal(history.find((entry) => entry.kind === "defense.planning_handoff")
      .payload.input_sha256.length, 64);
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].state, "needs_attention");
    assert.equal(env.events.db.prepare(`SELECT last_error FROM defense_cases
      WHERE incident_id=?`).get(incident.id).last_error,
    "no_bounded_deterministic_action");
    assert.equal(env.events.caseFile.history(incident.id).find((entry) =>
      entry.kind === "defense.mitigation_decision").payload.applied, false);
    await coordinator.close();
  } finally { env.close(); }
});

test("impact agent cannot assert an unlinked financial loss", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const runtime = { async run(spec) {
      const alertRef = spec.dossier.alertRefs.find((item) => item.startsWith("sentinel_alerts:"));
      if (spec.role === "investigator") {
        await spec.tools[0].execute({ cluster_id: incident.id },
          new AbortController().signal);
        return { status: "ok", tokens: 1, data: {
          incident_id: incident.id, case_version: spec.snapshot.caseVersion,
          profile: "integrity", disposition: "confirmed",
          facts: [{ statement: "Mismatch", evidence_refs: [alertRef] }],
          hypotheses: [], affected_entities: [], unknowns: [],
          recommended_action: "assess_customer_impact", recommendation_reason: "Assess" } };
      }
      if (spec.role === "damage_assessor") {
        await spec.tools[0].execute({ incident_id: incident.id },
          new AbortController().signal);
        const body = { incident_id: incident.id, case_version: spec.snapshot.caseVersion,
          findings: [{ kind: "money_candidate", entity_ref: "unlinked-transfer",
            evidence_refs: [alertRef], amount_cents: 999,
            assessment: "Claimed loss" }], unverified_categories: [],
          customer_repair_required: "yes" };
        assert.equal(spec.validateDossier(body), false);
        return { status: "ok", data: body, tokens: 1 };
      }
      return { status: "ok", tokens: 1, data: {
        incident_id: incident.id, case_version: spec.snapshot.caseVersion,
        disposition: "insufficient_evidence", cause_hypothesis: "Mismatch",
        evidence_refs: [alertRef], proposed_change: "Inspect",
        acceptance_invariants: ["Balance"], do_not_break: ["Transfers"],
        rollback_plan: "No change", unknowns: [] } };
    } };
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir, runtime });
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].state, "investigated");
    const history = env.events.caseFile.history(incident.id);
    assert.equal(history.some((entry) => entry.kind === "dossier.defense_impact"), false);
    assert.equal(history.some((entry) => entry.kind === "dossier.defense_plan"), true);
    await coordinator.close();
  } finally { env.close(); }
});

test("approved code plan without a registered trusted proof is explicitly deferred", async () => {
  const env = environment();
  try {
    const incident = realLedgerIncident(env);
    const roles = [];
    const runtime = { async run(spec) {
      roles.push(spec.role);
      const alertRef = spec.dossier.alertRefs.find((item) =>
        item.startsWith("sentinel_alerts:"));
      const core = { incident_id: incident.id,
        case_version: spec.snapshot.caseVersion };
      if (spec.role === "investigator") {
        await spec.tools[0].execute({ cluster_id: incident.id },
          new AbortController().signal);
        return { status: "ok", tokens: 1, data: { ...core, profile: "integrity",
          disposition: "confirmed", facts: [{ statement: "Ledger mismatch",
            evidence_refs: [alertRef] }], hypotheses: [], affected_entities: [],
          unknowns: [], recommended_action: "investigate_more",
          recommendation_reason: "Check code and external evidence" } };
      }
      if (spec.role === "damage_assessor") {
        await spec.tools[0].execute({ incident_id: incident.id },
          new AbortController().signal);
        return { status: "ok", tokens: 1, data: { ...core, findings: [],
          unverified_categories: ["customer loss"],
          customer_repair_required: "unknown" } };
      }
      if (spec.role === "architect") return { status: "ok", tokens: 1, data: {
        ...core, disposition: "code_candidate",
        cause_hypothesis: "Possible reconciliation defect", evidence_refs: [alertRef],
        proposed_change: "Inspect reconciliation logic",
        acceptance_invariants: ["Balanced ledger"],
        do_not_break: ["Valid transfers"], rollback_plan: "Revert candidate",
        unknowns: ["Exact defect is unproven"] } };
      assert.fail(`preliminary ${spec.role} reviewer must not block the code builder`);
    } };
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir, runtime });
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    assert.deepEqual(roles, ["investigator", "damage_assessor", "architect"]);
    assert.equal(coordinator.cases()[0].state, "needs_attention");
    const receipt = env.events.caseFile.history(incident.id).find((entry) =>
      entry.kind === "defense.code_dispatch");
    assert.equal(receipt.payload.reason, "trusted_code_proof_missing");
    assert.equal(receipt.payload.status, "deferred");
    assert.equal(env.events.caseFile.history(incident.id).some((entry) =>
      entry.kind === "defense.mitigation_decision"), false);
    await coordinator.scanOnce();
    assert.equal(env.events.caseFile.history(incident.id).filter((entry) =>
      entry.kind === "defense.code_dispatch").length, 1);
    await coordinator.close();
  } finally { env.close(); }
});

test("review rejection revises the plan before a temporary feature pause", async () => {
  const env = environment();
  try {
    const features = new FeatureRegistry(env.bank);
    new DynamicLimits(env.bank, features);
    features.setEnabled("limite_dinamico", true, "test-operator");
    const customerId = env.bank.db.prepare("SELECT id FROM customers ORDER BY id LIMIT 1").get().id;
    env.bank.db.prepare("INSERT INTO dynamic_limits VALUES (?,?,?,?,?)")
      .run(customerId, 100_000, 3, 0, env.bank.now().toISOString());
    env.bank.db.prepare("INSERT INTO dynamic_limit_changes VALUES (?,?,?,?,?,?,?)")
      .run("limit_test", customerId, 0, 100_000, 3, 0, env.bank.now().toISOString());
    assert.ok(env.sentinels.scan().some((alert) => alert.rule_id === "S-ACC-03"));
    const incident = env.sentinels.recentIncidents().find((item) => item.area === "accounts");
    assert.ok(incident);
    let reviews = 0;
    let plans = 0;
    const runtime = { async run(spec) {
      const alertRef = spec.dossier.alertRefs.find((item) => item.startsWith("sentinel_alerts:"));
      if (spec.role === "investigator") {
        await spec.tools[0].execute({ cluster_id: incident.id },
          new AbortController().signal);
        return { status: "ok", tokens: 1, data: {
          incident_id: incident.id, case_version: spec.snapshot.caseVersion,
          profile: "operations", disposition: "confirmed",
          facts: [{ statement: "Unverified limit increase", evidence_refs: [alertRef] }],
          hypotheses: [], affected_entities: [customerId], unknowns: [],
          recommended_action: "bounded_containment",
          recommendation_reason: "Prevent more unverified increases" } };
      }
      if (spec.role === "damage_assessor") {
        await spec.tools[0].execute({ incident_id: incident.id },
          new AbortController().signal);
        return { status: "ok", tokens: 1, data: {
          incident_id: incident.id, case_version: spec.snapshot.caseVersion,
          findings: [], unverified_categories: ["customer limit impact"],
          customer_repair_required: "unknown" } };
      }
      if (spec.role === "architect") {
        assert.equal(spec.dossier.revision, plans++);
        if (spec.dossier.revision === 1)
          assert.equal(spec.dossier.priorRejection.verdict, "reject");
        return { status: "ok", tokens: 1, data: {
        incident_id: incident.id, case_version: spec.snapshot.caseVersion,
        disposition: "operational_action", cause_hypothesis: "Unverified source raised a limit",
        evidence_refs: [alertRef], proposed_change: "Pause dynamic limit feature briefly",
        acceptance_invariants: ["Verified sources unaffected"],
        do_not_break: ["Existing balances"], rollback_plan: "Allow pause to expire",
        unknowns: ["Impact on prior customers"] } };
      }
      assert.equal(spec.role, "reviewer");
      assert.equal(spec.dossier.candidate.target, "limite_dinamico");
      assert.deepEqual(spec.tools, []);
      reviews++;
      return { status: "ok", tokens: 1, data: {
        incident_id: incident.id, case_version: spec.snapshot.caseVersion,
        verdict: reviews === 1 ? "reject" : "approve", evidence_refs: [alertRef],
        findings: [reviews === 1 ? "Revise collateral analysis" : "Temporary pause is bounded"],
        correction_risk: "low",
        customer_impact_checked: true } };
    } };
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir, runtime });
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    assert.equal(coordinator.cases().find((item) => item.incidentId === incident.id).state,
      "investigated");
    assert.equal(features.isEnabled("limite_dinamico"), true);
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    assert.equal(reviews, 2);
    assert.equal(plans, 2);
    assert.equal(coordinator.cases().find((item) => item.incidentId === incident.id).state,
      "mitigated");
    assert.equal(features.isEnabled("limite_dinamico"), false);
    const receipt = env.events.caseFile.history(incident.id).find((entry) =>
      entry.kind === "defense.mitigation_decision");
    assert.equal(receipt.payload.applied, true);
    assert.equal(receipt.payload.repair_status, "pending_evidence");
    assert.equal(env.bank.db.prepare("SELECT state FROM sentinel_incidents WHERE id=?")
      .get(incident.id).state, "open");
    await coordinator.scanOnce();
    assert.equal(env.bank.db.prepare("SELECT COUNT(*) n FROM blue_containments WHERE incident_id=?")
      .get(incident.id).n, 1);
    env.bank.db.prepare("UPDATE blue_containments SET expires_at=? WHERE incident_id=?")
      .run("2026-11-18T11:59:59.000Z", incident.id);
    await coordinator.scanOnce();
    assert.equal(coordinator.cases().find((item) => item.incidentId === incident.id).state,
      "needs_attention");
    await coordinator.close();
  } finally { env.close(); }
});

async function falsePixHoldFixture() {
  const env = environment();
  const auth = new AuthEngine(env.bank);
  const api = createTwinApi(env.bank, auth);
  const simulator = new CustomerSimulator(env.bank, auth, new Gateway(env.bank, api));
  const adapters = createFaultLabAdapters({ bank: env.bank });
  const lab = new FaultLab({ dbPath: join(env.dir, "lab-private.sqlite"),
    adapters: { risk_false_hold: adapters.risk_false_hold } });
  const started = await lab.start(["risk_false_hold"]);
  assert.equal((await simulator.localFaultProbe("risk_hold", started.id)).status, 400);
  await lab.stop(started.id);
  const riskAlert = env.sentinels.scan().find((item) => item.rule_id === "S-PIX-41");
  assert.ok(riskAlert);
  const hold = env.bank.riskPixHold(riskAlert.entity);
  assert.ok(hold);
  const incident = env.sentinels.recentIncidents().find((item) =>
    item.entity_key === hold.id);
  assert.ok(incident);
  return { ...env, api, simulator, lab, hold, incident,
    async shutdown() { await lab.shutdown(); simulator.close(); await api.close(); env.close(); } };
}

function falsePixRuntime(incident, hold, onReview = () => {}) {
  return { async run(spec) {
    const alertRefs = spec.dossier.alertRefs.filter((item) => item.startsWith("sentinel_alerts:"));
    const [ref] = alertRefs;
    const core = { incident_id: incident.id, case_version: spec.snapshot.caseVersion };
    if (spec.role === "investigator") {
      await spec.tools[0].execute({ cluster_id: incident.id },
        new AbortController().signal);
      return { status: "ok", tokens: 1, data: { ...core, profile: "fraud",
        disposition: "confirmed", facts: [{ statement: "Risk score disagrees with policy replay",
          evidence_refs: [ref] }], hypotheses: [], affected_entities: [hold.id],
        unknowns: [], recommended_action: "assess_customer_impact",
        recommendation_reason: "A pending payment may have been wrongly retained" } };
    }
    if (spec.role === "damage_assessor") {
      await spec.tools[0].execute({ incident_id: incident.id },
        new AbortController().signal);
      return { status: "ok", tokens: 1, data: { ...core,
        findings: [{ kind: "wrongful_hold", entity_ref: hold.id,
          evidence_refs: alertRefs, amount_cents: hold.amount_cents,
          assessment: "Funds are reserved without a policy hold reason" }],
        unverified_categories: [], customer_repair_required: "yes" } };
    }
    if (spec.role === "architect") return { status: "ok", tokens: 1, data: {
      ...core, disposition: "operational_action",
      cause_hypothesis: "Recorded hold diverges from policy decision",
      evidence_refs: alertRefs, proposed_change: "Release verified false hold",
      acceptance_invariants: ["Ledger remains balanced"],
      do_not_break: ["Other pending holds"], rollback_plan: "Stop and escalate if settlement fails",
      unknowns: [] } };
    assert.equal(spec.role, "reviewer");
    onReview(spec.dossier.candidate);
    return { status: "ok", tokens: 1, data: { ...core,
      verdict: "approve", evidence_refs: alertRefs,
      findings: ["Signed request and policy replay checked"],
      correction_risk: "low", customer_impact_checked: true } };
  } };
}

test("verified false Pix hold is released and settles exactly once after review", async () => {
  const env = await falsePixHoldFixture();
  try {
    let candidate;
    const runtime = falsePixRuntime(env.incident, env.hold, (value) => { candidate = value; });
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir, runtime });
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    assert.equal(candidate.kind, "release_false_pix_hold");
    assert.equal(candidate.holdId, env.hold.id);
    assert.equal(coordinator.cases().find((item) => item.incidentId === env.incident.id)
      .state, "customer_repaired");
    const resolved = env.bank.riskPixHold(env.hold.id);
    assert.equal(resolved.status, "approved");
    const transfer = env.bank.db.prepare("SELECT status,ledger_tx_id FROM pix_transfers WHERE id=?")
      .get(resolved.transfer_id);
    assert.equal(transfer.status, "settled");
    assert.equal(env.bank.reconcile().ok, true);
    const receipt = env.events.caseFile.history(env.incident.id).find((entry) =>
      entry.kind === "defense.mitigation_decision" && entry.payload.applied === true);
    assert.equal(receipt.payload.transfer_id, resolved.transfer_id);
    assert.equal(receipt.payload.ledger_tx_id, transfer.ledger_tx_id);
    await coordinator.scanOnce();
    assert.equal(env.bank.db.prepare("SELECT COUNT(*) n FROM pix_transfers WHERE id=?")
      .get(resolved.transfer_id).n, 1);
    await coordinator.close();
  } finally { await env.shutdown(); }
});

test("a lost Pix repair receipt is recovered without a second transfer", async () => {
  const env = await falsePixHoldFixture();
  let coordinator;
  try {
    const record = env.events.caseFile.record.bind(env.events.caseFile);
    let failReceipt = true;
    env.events.caseFile.record = (input) => {
      if (input.kind === "defense.mitigation_decision" && failReceipt) {
        failReceipt = false;
        throw new Error("SIMULATED_RECEIPT_FAILURE");
      }
      return record(input);
    };
    coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir,
      runtime: falsePixRuntime(env.incident, env.hold) });
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    const first = env.bank.riskPixHold(env.hold.id);
    assert.equal(first.status, "approved");
    assert.ok(first.transfer_id);
    assert.equal(coordinator.cases()[0].state, "reviewed");
    assert.equal(env.events.caseFile.history(env.incident.id).some((entry) =>
      entry.kind === "defense.mitigation_decision"), false);
    env.events.caseFile.record = record;
    await coordinator.close();
    coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir,
      runtime: falsePixRuntime(env.incident, env.hold) });
    await coordinator.scanOnce();
    assert.equal(coordinator.cases()[0].state, "customer_repaired");
    assert.equal(env.bank.riskPixHold(env.hold.id).transfer_id, first.transfer_id);
    assert.equal(env.bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers
      WHERE id=?`).get(first.transfer_id).n, 1);
    assert.equal(env.events.caseFile.history(env.incident.id).filter((entry) =>
      entry.kind === "defense.mitigation_decision" && entry.payload.applied).length, 1);
    assert.equal(env.bank.reconcile().ok, true);
  } finally { await coordinator?.close(); await env.shutdown(); }
});

test("run-owned false Pix hold reaches a watched end-to-end verdict", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-risk-watch-"));
  let realMs = Date.now();
  const now = () => new Date(realMs);
  const bank = new Bank(join(dir, "bank.sqlite"), now, now);
  let events;
  let api;
  let simulator;
  let lab;
  let coordinator;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    events = new EventStore(join(dir, "events.sqlite"));
    const sentinels = new SentinelEngine(bank, events);
    const auth = new AuthEngine(bank);
    api = createTwinApi(bank, auth);
    simulator = new CustomerSimulator(bank, auth, new Gateway(bank, api));
    const adapters = createFaultLabAdapters({ bank });
    lab = new FaultLab({ dbPath: join(dir, "lab-private.sqlite"), now,
      adapters: { risk_false_hold: adapters.risk_false_hold } });
    const run = await lab.start(["risk_false_hold"]);
    assert.equal((await simulator.localFaultProbe("risk_hold", run.id)).status, 400);
    await lab.tick();
    assert.equal(lab.run(run.id).results[0].state, "observed");
    const alert = sentinels.scan().find((item) => item.rule_id === "S-PIX-41");
    assert.ok(alert);
    const hold = bank.riskPixHold(alert.entity);
    const incident = sentinels.recentIncidents().find((item) =>
      item.entity_key === hold.id);
    assert.ok(incident);
    const runtime = falsePixRuntime(incident, hold);
    let reviews = 0;
    coordinator = new DefenseCoordinator({ bank, sentinels, events, dataDir: dir,
      runtime: { async run(spec) {
        const result = await runtime.run(spec);
        if (spec.role !== "reviewer" || ++reviews !== 1) return result;
        const unchecked = { ...result.data, customer_impact_checked: false };
        assert.equal(spec.validateDossier(unchecked), false);
        return { ...result, data: unchecked };
      } } });
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    assert.equal(bank.riskPixHold(hold.id).status, "pending");
    assert.equal(coordinator.cases()[0].state, "planned");
    await coordinator.scanOnce();
    assert.equal(reviews, 2);
    assert.equal(coordinator.cases()[0].state, "customer_repaired");
    const evaluator = new FaultLabEvaluator({ lab, bank, events,
      reconcile: () => bank.reconcile(), now });
    assert.equal(evaluator.evaluate(run.id).verdict, "pending");
    realMs += 120_001;
    await lab.tick();
    assert.equal(lab.run(run.id).status, "expired");
    assert.equal(evaluator.evaluate(run.id).fixtures[0].watch.state, "pending");
    const stoppedMs = realMs;
    for (const seconds of [5, 19]) {
      const at = new Date(stoppedMs + seconds * 1_000).toISOString();
      events.append({ round_id: null, ts: at, twin_ts: at, type: "sim.tick",
        actor: { id: "customer-simulator", role: "sim" }, area: "accounts",
        public_summary_pt: "Normal customer traffic continued",
        public: { minute: at, ops: 2, approvals_pct: 100,
          honest_blocked: 0, false_block_rate: 0, by_area: { pix: 1 } } });
    }
    realMs = stoppedMs + 20_000;
    const result = evaluator.evaluate(run.id);
    assert.equal(result.verdict, "passed", JSON.stringify(result));
    assert.deepEqual(result.fixtures[0].watch.evidence_refs.length, 2);
  } finally {
    await coordinator?.close();
    await lab?.shutdown();
    simulator?.close();
    await api?.close();
    events?.close();
    bank.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("false Pix hold remains pending when signed customer evidence is missing", async () => {
  const env = await falsePixHoldFixture();
  try {
    env.bank.db.prepare("UPDATE auth_device_challenges SET used_at=NULL WHERE device_id=?")
      .run(env.hold.device_id);
    let candidate;
    const runtime = falsePixRuntime(env.incident, env.hold, (value) => { candidate = value; });
    const coordinator = new DefenseCoordinator({ bank: env.bank, sentinels: env.sentinels,
      events: env.events, dataDir: env.dir, runtime });
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    await coordinator.scanOnce();
    assert.equal(candidate, null);
    assert.equal(env.bank.riskPixHold(env.hold.id).status, "pending");
    assert.equal(coordinator.cases().find((item) => item.incidentId === env.incident.id)
      .state, "needs_attention");
    const decision = env.events.caseFile.history(env.incident.id).find((entry) =>
      entry.kind === "defense.mitigation_decision");
    assert.equal(decision.payload.applied, false);
    await coordinator.close();
  } finally { await env.shutdown(); }
});

test("separated ecosystem repairs a signed internal false hold without external settlement", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-split-repair-"));
  const now = new Date("2026-11-18T15:00:00.000Z");
  const combined = join(dir, "combined.sqlite");
  const bankPath = join(dir, "bank.sqlite");
  const ecosystemPath = join(dir, "ecosystem.sqlite");
  const source = new Bank(combined, () => now, () => now);
  seedBank(source, { customers: 2, accounts: 2, historyTransactions: 0 });
  const external = source.db.prepare("SELECT id,pix_key FROM psp_accounts ORDER BY id LIMIT 1")
    .get();
  source.close();
  exportSplitSnapshots(combined, bankPath, ecosystemPath);
  const bank = new Bank(bankPath, () => now, () => now,
    { ecosystemMode: "separated" });
  const events = new EventStore(join(dir, "events.sqlite"));
  let ecosystem;
  let verifier;
  let api;
  let simulator;
  let lab;
  let defense;
  try {
    ecosystem = await EcosystemClient.start(ecosystemPath);
    verifier = await CrossBookVerifierClient.start(bankPath, ecosystemPath);
    const pix = new SeparatedPixCoordinator(bank, ecosystem);
    const auth = new AuthEngine(bank);
    api = createTwinApi(bank, auth, { pspNotices: ecosystem, pixCoordinator: pix });
    simulator = new CustomerSimulator(bank, auth, new Gateway(bank, api),
      undefined, undefined, undefined, 1, {
        externalRecipients: [{ id: external.id, pixKey: external.pix_key }],
        dispatchPendingPix: () => pix.dispatch(),
        spiStatus: () => ecosystem.spiAvailability(),
      });
    const adapters = createFaultLabAdapters({ bank, separatedEcosystem: true });
    lab = new FaultLab({ dbPath: join(dir, "lab-private.sqlite"),
      adapters: { risk_false_hold: adapters.risk_false_hold } });
    const started = await lab.start(["risk_false_hold"]);
    assert.equal((await simulator.localFaultProbe("risk_hold", started.id)).status, 400);
    await lab.stop(started.id);
    const sentinels = new SentinelEngine(bank, events);
    const alerts = sentinels.scan({ crossBook: await verifier.verify(),
      activeCautelar: await ecosystem.activeCautelarSummary(bank.now()) });
    const alert = alerts.find((item) => item.rule_id === "S-PIX-41");
    assert.ok(alert);
    const hold = bank.riskPixHold(alert.entity);
    assert.ok(bank.db.prepare("SELECT 1 FROM accounts WHERE id=?")
      .get(hold.to_account));
    const incident = sentinels.recentIncidents().find((item) =>
      item.entity_key === hold.id);
    assert.ok(incident);
    let reviewed;
    defense = new DefenseCoordinator({ bank, sentinels, events, dataDir: dir,
      runtime: falsePixRuntime(incident, hold, (candidate) => { reviewed = candidate; }),
      recipientFraudHistory: (id, at) => ecosystem.accountFraudHistory(id, at) });
    await defense.scanOnce();
    await defense.scanOnce();
    await defense.scanOnce();
    assert.equal(reviewed.kind, "release_false_pix_hold");
    assert.equal(defense.cases().find((item) => item.incidentId === incident.id).state,
      "customer_repaired");
    const resolved = bank.riskPixHold(hold.id);
    assert.equal(resolved.status, "approved");
    assert.equal(bank.db.prepare("SELECT status FROM pix_transfers WHERE id=?")
      .get(resolved.transfer_id).status, "settled");
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_spi_outbox").get().n, 0);
    assert.equal((await verifier.verify()).ok, true);
    await defense.close();
    const externalRun = randomUUID();
    bank.risk.setLocalFalseHoldProbeKey(`sim:${externalRun}:0`);
    try {
      const externalProbe = await simulator.operation(simulator.customers[0],
        simulator.customers[1], 0.78, 0, externalRun);
      assert.equal(externalProbe.result.status, 400);
    } finally { bank.risk.setLocalFalseHoldProbeKey(null); }
    const externalHold = bank.db.prepare(`SELECT * FROM risk_pix_holds
      WHERE to_account=? AND status='pending' ORDER BY created_at DESC LIMIT 1`)
      .get(external.id);
    assert.ok(externalHold);
    const nextAlerts = sentinels.scan({ crossBook: await verifier.verify(),
      activeCautelar: await ecosystem.activeCautelarSummary(bank.now()) });
    assert.ok(nextAlerts.some((item) => item.rule_id === "S-PIX-41" &&
      item.entity === externalHold.id));
    const externalIncident = sentinels.recentIncidents().find((item) =>
      item.entity_key === externalHold.id);
    assert.ok(externalIncident);
    let externalCandidate;
    defense = new DefenseCoordinator({ bank, sentinels, events, dataDir: dir,
      runtime: falsePixRuntime(externalIncident, externalHold,
        (candidate) => { externalCandidate = candidate; }),
      recipientFraudHistory: (id, at) => ecosystem.accountFraudHistory(id, at) });
    await defense.scanOnce();
    await defense.scanOnce();
    await defense.scanOnce();
    assert.equal(externalCandidate, null);
    assert.equal(bank.riskPixHold(externalHold.id).status, "pending");
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_spi_outbox").get().n, 0);
  } finally {
    await defense?.close();
    await lab?.shutdown();
    simulator?.close();
    await api?.close();
    await verifier?.close();
    await ecosystem?.close();
    events.close(); bank.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
