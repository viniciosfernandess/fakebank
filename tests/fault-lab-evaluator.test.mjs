import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { FaultLabEvaluator } from "../apps/orchestrator/src/fault-lab-evaluator.ts";

const begin = "2026-11-18T10:00:00.000Z";
const end = "2026-11-18T10:02:00.000Z";
function setup(results, status = "expired") {
  const bank = new DatabaseSync(":memory:");
  const events = new DatabaseSync(":memory:");
  bank.exec(`CREATE TABLE sentinel_alerts (id TEXT PRIMARY KEY,rule_id TEXT,
    entity TEXT,first_seen TEXT,last_seen TEXT,observed_json TEXT);
    CREATE TABLE risk_pix_holds (id TEXT PRIMARY KEY,idempotency_key TEXT,
    status TEXT,transfer_id TEXT,balance_hold_id TEXT,reviewer TEXT);
    CREATE TABLE balance_holds (id TEXT PRIMARY KEY,released_at TEXT);
    CREATE TABLE pix_transfers (id TEXT PRIMARY KEY,status TEXT,ledger_tx_id TEXT,
      idempotency_key TEXT);
    CREATE TABLE ledger_entries (tx_id TEXT,amount INTEGER);
    CREATE TABLE pix_spi_outbox (transfer_id TEXT PRIMARY KEY,response_status TEXT);
    CREATE TABLE pix_psp_inbound_outbox (transfer_id TEXT PRIMARY KEY,
      acknowledged_at TEXT);
    CREATE TABLE card_network_rejections (id TEXT PRIMARY KEY,response_code TEXT,
      created_at TEXT,card_id TEXT,merchant_id TEXT,amount_cents INTEGER);
    CREATE TABLE card_issuer_history (id INTEGER PRIMARY KEY,available INTEGER,
      changed_by TEXT,changed_at TEXT);
    CREATE TABLE card_network_authorizations (id TEXT PRIMARY KEY,
      response_code TEXT,created_at TEXT,card_id TEXT,merchant_id TEXT,
      amount_cents INTEGER);
    CREATE TABLE card_network_messages (authorization_id TEXT,mti TEXT,
      payload_json TEXT);
    CREATE TABLE incident_customer_notices (customer_id TEXT,id INTEGER,
      incident_id TEXT,rejection_id TEXT,kind TEXT,created_at TEXT);
    CREATE TABLE telemetry_events (id INTEGER PRIMARY KEY,source TEXT,category TEXT,
      action TEXT,ts TEXT,outcome TEXT);`);
  events.exec(`CREATE TABLE defense_cases (incident_id TEXT PRIMARY KEY);
    CREATE TABLE incident_case_entries (id INTEGER PRIMARY KEY,incident_id TEXT,
      kind TEXT,payload_json TEXT,created_at TEXT DEFAULT '2026-11-18T10:01:00.000Z');
    CREATE TABLE events (seq INTEGER PRIMARY KEY,type TEXT,public_json TEXT,
      ts TEXT DEFAULT '2026-11-18T10:00:00.000Z',
      twin_ts TEXT DEFAULT '2026-11-18T10:00:00.000Z');
    CREATE TABLE event_private (seq INTEGER PRIMARY KEY,private_json TEXT);`);
  const run = { id: "run-1", status, selected_ids: results.map((row) => row.fixture_id),
    started_at: begin, stopped_at: ["stopped", "expired", "failed"].includes(status) ? end : null,
    expires_at: end, timeline: [], results };
  const evaluator = new FaultLabEvaluator({ lab: { run: () => run },
    bank: { db: bank }, events: { db: events }, reconcile: () => ({ ok: true }),
    now: () => new Date("2026-11-18T10:02:20.000Z") });
  return { bank, events, run, evaluator,
    close: () => { bank.close(); events.close(); } };
}
const observed = (fixture_id, ref) => ({ fixture_id, state: "observed",
  evidence_refs: [ref] });
function emit(events, seq, alertId, ruleId, entity, observedData, ts = begin) {
  events.prepare(`INSERT INTO events (seq,type,public_json,ts,twin_ts)
    VALUES (?,'sentinel.alert',?,?,?)`).run(seq,
      JSON.stringify({ alert_id: alertId, rule_id: ruleId }), ts, ts);
  events.prepare("INSERT INTO event_private VALUES (?,?)").run(seq,
    JSON.stringify({ entity, observed: observedData }));
}

test("identity notice is evidenced only with the exact impact dossier", () => {
  const item = setup([observed("revoked_device_access",
    "sentinel_alerts:identity-alert")]);
  try {
    const bank = item.bank, events = item.events;
    for (const column of ["user_id", "device_id", "trace_id", "session_id", "message", "twin_ts", "counterparty"])
      bank.exec(`ALTER TABLE telemetry_events ADD COLUMN ${column} TEXT`);
    bank.exec("ALTER TABLE telemetry_events ADD COLUMN amount_cents INTEGER");
    bank.exec(`CREATE TABLE lab_revoked_device_receipts (run_id TEXT,
      customer_id TEXT,device_id TEXT,telemetry_event_id INTEGER);
      CREATE TABLE auth_devices (id TEXT,customer_id TEXT,revoked_at TEXT);
      CREATE TABLE auth_sessions (id TEXT,customer_id TEXT,device_id TEXT,revoked_at TEXT);
      CREATE TABLE identity_incident_notices (id INTEGER,incident_id TEXT,
        customer_id TEXT,alert_id TEXT,source_event_id INTEGER,device_id TEXT);`);
    events.exec(`CREATE TABLE patch_ci_runs (id TEXT,candidate_sha TEXT,state TEXT)`);
    const customer = "cus_identity", device = "dev_identity";
    const head = "a".repeat(40), digest = "b".repeat(64);
    const observedData = { source_event_id: 1, device_id: device,
      action: "access_revoked_device" };
    bank.prepare(`INSERT INTO lab_revoked_device_receipts VALUES (?,?,?,?)`)
      .run("run-1", customer, device, 1);
    bank.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)`)
      .run("identity-alert", "S-AUTH-08", customer, begin, begin,
        JSON.stringify(observedData));
    bank.prepare(`INSERT INTO telemetry_events
      (id,source,category,action,ts,outcome,user_id,device_id)
      VALUES (1,'auth','audit','access_revoked_device',?,'success',?,?)`)
      .run(begin, customer, device);
    bank.prepare(`INSERT INTO auth_devices VALUES (?,?,?)`)
      .run(device, customer, begin);
    emit(events, 1, "identity-alert", "S-AUTH-08", customer,
      observedData);
    events.prepare(`INSERT INTO defense_cases VALUES (?)`).run("identity-case");
    events.prepare(`INSERT INTO patch_ci_runs VALUES (?,?,'merged')`)
      .run("ci-identity", head);
    const entry = (id, kind, payload) => events.prepare(`INSERT INTO
      incident_case_entries (id,incident_id,kind,payload_json)
      VALUES (?,'identity-case',?,?)`).run(id, kind,
        JSON.stringify(payload));
    entry(1, "defense.observed", { case_version: 1,
      alert_refs: ["sentinel_alerts:identity-alert"] });
    entry(2, "dossier.defense_investigation", { case_version: 1 });
    entry(3, "dossier.defense_impact", { case_version: 1,
      customer_repair_required: "yes", findings: [{ kind: "access",
        entity_ref: customer, amount_cents: null,
        evidence_refs: ["sentinel_alerts:identity-alert", "telemetry_events:1"] }] });
    entry(4, "defense.code_review_approved", { case_version: 1,
      head_sha: head, ci_run_id: "ci-identity" });
    entry(5, "defense.code_bank_gate", { case_version: 1,
      head_sha: head, ci_run_id: "ci-identity", tests: 1132,
      output_sha256: digest });
    entry(6, "defense.code_merged", { case_version: 1,
      head_sha: head, ci_run_id: "ci-identity" });
    entry(7, "defense.identity_containment_verified", { case_version: 1,
      head_sha: head, ci_run_id: "ci-identity", bank_reconciled: true,
      live_sessions_after: 0, customer_impact: "unverified", through_event_id: 2,
      contained_at_real: begin,
      devices: [{ alert_id: "identity-alert", customer_id: customer,
        device_id: device, source_event_id: 1 }] });
    bank.prepare(`INSERT INTO identity_incident_notices VALUES (?,?,?,?,?,?)`)
      .run(1, "identity-case", customer, "identity-alert", 1, device);
    entry(8, "defense.customer_notice", { case_version: 1,
      kind: "revoked_device_access", customer_id: customer,
      device_id: device, source_event_id: 1, notice_id: 1,
      customer_impact: "unverified" });
    const repair = () => item.evaluator.evaluate("run-1").fixtures[0].customer_repair;
    assert.equal(repair().reason, "customer_notified_impact_unverified");
    assert.equal(repair().state, "inconclusive");
    assert.ok(repair().evidence_refs.includes("incident_case_entries:3"));
    bank.prepare(`INSERT INTO auth_sessions VALUES ('session-fixture',?,?,?)`).run(customer, device, begin);
    bank.prepare(`UPDATE telemetry_events SET trace_id='scope-trace',session_id='session-fixture',
      twin_ts=? WHERE id=1`).run(begin);
    bank.prepare(`INSERT INTO telemetry_events (id,source,category,action,ts,outcome,
      user_id,device_id,trace_id,session_id,message,twin_ts)
      VALUES (2,'gateway','request','request',?,'success',?,?,
      'scope-trace','session-fixture','Gateway GET /api/v1/customers/me completed fields=email',?)`)
      .run(begin, customer, device, begin);
    const scope = { case_version: 1, customer_id: customer, device_id: device,
      source_event_id: 1, through_event_id: 2, complete: true,
      observed: [{ access_event_id: 1, response_event_id: 2,
        route_template: "/api/v1/customers/me", response_fields: ["email"] }],
      financial: { verified_postings: [], unresolved_posting_ids: [],
        truncated: false, no_observed_posting: true } };
    entry(9, "defense.identity_scope_measured", scope);
    assert.equal(repair().reason, "customer_notified_observed_scope_verified");
    assert.equal(repair().state, "inconclusive");
    assert.ok(repair().evidence_refs.includes("incident_case_entries:9"));
    const reconciliation = () => item.evaluator.evaluate("run-1").fixtures[0].reconciliation;
    assert.equal(reconciliation().reason, "no_identity_posting_in_observed_window");
    bank.prepare(`UPDATE telemetry_events SET session_id='unmatched-session' WHERE id=2`).run();
    assert.equal(repair().reason, "customer_notified_impact_unverified");
    assert.equal(reconciliation().reason, "financial_impact_unassessed");
    for (const column of ["amount INTEGER", "from_account TEXT", "to_account TEXT", "end_to_end_id TEXT",
      "initiating_device_id TEXT", "settled_at TEXT", "spi_command_version INTEGER"])
      bank.exec(`ALTER TABLE pix_transfers ADD COLUMN ${column}`);
    for (const column of ["end_to_end_id TEXT", "amount_cents INTEGER", "trace_id TEXT",
      "queued_at_real TEXT", "created_at TEXT"])
      bank.exec(`ALTER TABLE pix_spi_outbox ADD COLUMN ${column}`);
    for (const column of ["end_to_end_id TEXT", "amount_cents INTEGER", "from_account TEXT",
      "to_account TEXT", "settled_at TEXT", "trace_id TEXT", "created_at TEXT"])
      bank.exec(`ALTER TABLE pix_psp_inbound_outbox ADD COLUMN ${column}`);
    bank.exec("CREATE TABLE accounts (id TEXT,customer_id TEXT)");
    bank.prepare("INSERT INTO accounts VALUES ('owner-account',?)").run(customer);
    bank.prepare(`INSERT INTO pix_transfers
      (id,from_account,to_account,amount,status,end_to_end_id,initiating_device_id,spi_command_version)
      VALUES ('payment','owner-account','remote-account',219,'in_processing','e2e-fixture',?,2)`).run(device);
    bank.prepare(`INSERT INTO pix_spi_outbox
      (transfer_id,end_to_end_id,amount_cents,trace_id,queued_at_real,created_at)
      VALUES ('payment','e2e-fixture',219,'scope-trace',?,?)`).run(begin, begin);
    events.prepare("UPDATE incident_case_entries SET payload_json=? WHERE id=9")
      .run(JSON.stringify({ ...scope, pix_scope_checked: true, contained_at_real: begin }));
    assert.equal(reconciliation().reason, "identity_pix_followup_evidence_pending");
    entry(10, "defense.identity_pix_followup", { case_version: 1, source_event_id: 1,
      through_event_id: 2, contained_at_real: begin, truncated: false,
      commands: [{ transfer_id: "payment", access_event_id: 1, state: "pending_spi" }] });
    assert.equal(reconciliation().reason, "identity_pix_followup_impact_unverified");
    assert.equal(reconciliation().state, "inconclusive");
    assert.ok(reconciliation().evidence_refs.includes("incident_case_entries:10"));
    events.prepare(`DELETE FROM incident_case_entries WHERE id=3`).run();
    assert.equal(repair().reason, "access_impact_and_notice_unverified");
  } finally { item.close(); }
});

test("missed fraud hold needs the run-owned payment and matching Sentinel emission", () => {
  const item = setup([observed("risk_missed_hold",
    "sentinel_alerts:risk-miss-alert")]);
  try {
    const bank = item.bank;
    for (const [column, kind] of [["amount", "INTEGER"],
      ["from_account", "TEXT"], ["to_account", "TEXT"],
      ["settled_at", "TEXT"]])
      bank.exec(`ALTER TABLE pix_transfers ADD COLUMN ${column} ${kind}`);
    bank.exec(`CREATE TABLE lab_risk_miss_receipts (run_id TEXT,
      account_id TEXT,transfer_id TEXT,recipient_account_id TEXT)`);
    bank.prepare(`INSERT INTO lab_risk_miss_receipts VALUES (?,?,?,?)`)
      .run("run-1", "account-mule", "transfer-out", "account-recipient");
    bank.prepare(`INSERT INTO pix_transfers
      (id,status,amount,from_account,to_account,settled_at)
      VALUES (?,'settled',4800,?,?,?)`).run("transfer-out",
        "account-mule", "account-recipient", begin);
    bank.prepare(`INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)`)
      .run("risk-miss-alert", "S-PIX-02", "account-mule", begin, begin,
        JSON.stringify({ senders: 6, inbound_cents: 6_000,
          outbound_cents: 4_800 }));
    let result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.symptom.state, "verified");
    assert.equal(result.detection.state, "inconclusive");
    emit(item.events, 1, "risk-miss-alert", "S-PIX-02", "account-mule",
      { senders: 6, inbound_cents: 6_000, outbound_cents: 4_800 });
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.detection.state, "verified");
    assert.equal(result.customer_repair.state, "inconclusive");
    assert.equal(result.verdict, "inconclusive");
    bank.prepare(`UPDATE pix_transfers SET ledger_tx_id=? WHERE id=?`)
      .run("ledger-out", "transfer-out");
    bank.prepare(`INSERT INTO ledger_entries VALUES (?,?)`).run("ledger-out", -4_800);
    bank.prepare(`INSERT INTO ledger_entries VALUES (?,?)`).run("ledger-out", 4_800);
    item.events.exec(`CREATE TABLE patch_ci_runs
      (id TEXT,candidate_sha TEXT,state TEXT)`);
    item.events.prepare(`INSERT INTO patch_ci_runs VALUES (? ,?,'merged')`)
      .run("ci-risk", "a".repeat(40));
    item.events.prepare(`INSERT INTO defense_cases VALUES (?)`).run("fraud-case");
    const entry = (id, kind, payload) => item.events.prepare(`INSERT INTO
      incident_case_entries (id,incident_id,kind,payload_json)
      VALUES (?,'fraud-case',?,?)`).run(id, kind, JSON.stringify(payload));
    entry(1, "defense.observed", { case_version: 1,
      alert_refs: ["sentinel_alerts:risk-miss-alert"] });
    entry(2, "dossier.defense_investigation", { case_version: 1 });
    entry(3, "dossier.defense_impact", { case_version: 1,
      findings: [{ kind: "money_candidate", entity_ref: "transfer-out",
        amount_cents: 4_800, evidence_refs: [
          "sentinel_alerts:risk-miss-alert", "pix_transfers:transfer-out"] }] });
    entry(4, "dossier.defense_plan", { case_version: 1,
      disposition: "code_candidate" });
    entry(5, "defense.code_review_approved", {
      head_sha: "a".repeat(40), ci_run_id: "ci-risk" });
    entry(6, "defense.code_bank_gate", { case_version: 1,
      head_sha: "a".repeat(40), ci_run_id: "ci-risk", tests: 1136,
      output_sha256: "b".repeat(64) });
    entry(7, "defense.code_merged", { case_version: 1,
      head_sha: "a".repeat(40), ci_run_id: "ci-risk" });
    entry(8, "defense.fraud_control_verified", { case_version: 1,
      head_sha: "a".repeat(40), ci_run_id: "ci-risk",
      alert_id: "risk-miss-alert", account_id: "account-mule",
      transfer_id: "transfer-out", recipient_account_id: "account-recipient",
      ledger_tx_id: "ledger-out", customer_impact: "unverified",
      bank_reconciled: true });
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.response.state, "verified");
    assert.equal(result.continuity.state, "verified");
    assert.equal(result.reconciliation.state, "verified");
    assert.equal(result.customer_repair.reason,
      "suspicious_payment_impact_unverified");
    bank.exec(`CREATE TABLE accounts (id TEXT,customer_id TEXT,system_role TEXT);
      CREATE TABLE fraud_incident_notices (id INTEGER,customer_id TEXT,
        incident_id TEXT,alert_id TEXT,transfer_id TEXT,kind TEXT);`);
    bank.prepare("INSERT INTO accounts (id,customer_id) VALUES (?,?)")
      .run("account-mule", "cus-owner");
    const notice = bank.prepare(`INSERT INTO fraud_incident_notices
      VALUES (?,?,?,?,?,'suspicious_pix_review')`);
    notice.run(1, "cus-other", "fraud-case", "risk-miss-alert", "transfer-out");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "suspicious_payment_impact_unverified");
    notice.run(2, "cus-owner", "fraud-case", "risk-miss-alert", "transfer-out");
    entry(9, "defense.customer_notice", { case_version: 1,
      kind: "suspicious_pix_review", customer_id: "cus-owner",
      alert_id: "risk-miss-alert", transfer_id: "transfer-out", notice_id: 2,
      customer_impact: "unverified" });
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.customer_repair.reason,
      "suspicious_payment_customer_notified_impact_unverified");
    assert.equal(result.customer_repair.state, "inconclusive");
    for (const [column, kind] of [["account_id", "TEXT"], ["kind", "TEXT"],
      ["ref_type", "TEXT"], ["ref_id", "TEXT"]])
      bank.exec(`ALTER TABLE ledger_entries ADD COLUMN ${column} ${kind}`);
    bank.exec(`CREATE TABLE med_cases (id TEXT,transfer_id TEXT,customer_id TEXT,
      status TEXT,claim_amount_cents INTEGER,refunded_cents INTEGER,
      unrecovered_cents INTEGER);
      CREATE TABLE med_decisions (case_id TEXT,decision TEXT,maker_id TEXT,
        checker_id TEXT,evidence_ref TEXT);
      CREATE TABLE med_refunds (id TEXT,case_id TEXT,amount INTEGER,
        ledger_tx_id TEXT);`);
    bank.prepare(`INSERT INTO med_cases VALUES
      ('med-1','transfer-out','cus-owner','open',4800,0,0)`).run();
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "customer_dispute_recorded_repair_unverified");
    entry(10, "defense.customer_repair_verified", { case_version: 1,
      customer_id: "cus-owner", transfer_id: "transfer-out",
      med_case_id: "med-1", amount_cents: 4_800, refund_ids: ["refund-1"],
      notice_id: 2, bank_reconciled: true });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "customer_dispute_recorded_repair_unverified",
      "a receipt cannot substitute for a completed MED decision and credit");
    const outcome = { case_version: 1, customer_id: "cus-owner",
      transfer_id: "transfer-out", med_case_id: "med-1",
      evidence_refs: ["sentinel_alerts:risk-miss-alert", "med_cases:med-1"] };
    entry(11, "defense.customer_dispute_outcome", { ...outcome,
      outcome: "claim_rejected", refunded_cents: 0, unrecovered_cents: null });
    bank.prepare(`INSERT INTO med_decisions VALUES
      ('med-1','rejected','maker-1','checker-1','sentinel_alerts:risk-miss-alert')`).run();
    bank.prepare("UPDATE med_cases SET status='rejected' WHERE id='med-1'").run();
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.customer_repair.reason, "med_claim_rejected_impact_unresolved");
    assert.equal(result.customer_repair.state, "inconclusive");
    bank.prepare("UPDATE med_decisions SET decision='approved' WHERE case_id='med-1'").run();
    bank.prepare(`UPDATE med_cases SET status='resolved',unrecovered_cents=4800
      WHERE id='med-1'`).run();
    entry(12, "defense.customer_dispute_outcome", { ...outcome,
      outcome: "no_funds_recovered", refunded_cents: 0, unrecovered_cents: 4_800 });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "med_no_funds_recovered");
    bank.prepare(`UPDATE med_cases SET refunded_cents=2000,unrecovered_cents=2800
      WHERE id='med-1'`).run();
    entry(13, "defense.customer_dispute_outcome", { ...outcome,
      outcome: "partial_refund", refunded_cents: 2_000, unrecovered_cents: 2_800,
      evidence_refs: [...outcome.evidence_refs, "med_refunds:refund-1"] });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "customer_dispute_recorded_repair_unverified",
      "partial repair also needs independently verified funds");
    bank.prepare(`INSERT INTO med_refunds VALUES
      ('refund-1','med-1',2000,'med-ledger')`).run();
    bank.prepare(`INSERT INTO ledger_entries
      (tx_id,amount,account_id,kind,ref_type,ref_id)
      VALUES ('med-ledger',2000,'account-mule','med_refund','pix','transfer-out')`).run();
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.customer_repair.reason, "med_partial_refund_remaining");
    assert.equal(result.customer_repair.state, "inconclusive");
    entry(14, "defense.customer_repair_verified", { ...outcome, amount_cents: 4_800,
      refund_ids: ["refund-1"], notice_id: 2, bank_reconciled: true,
      bank_compensation_cents: 2_800, bank_compensation_tx_id: "med-compensation" });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "med_partial_refund_remaining", "a compensation receipt needs independent ledger legs");
    bank.exec(`INSERT INTO accounts VALUES ('bank-loss',NULL,'bank_loss');
      INSERT INTO ledger_entries (tx_id,amount,account_id,kind,ref_type,ref_id)
        VALUES ('med-compensation',-2800,'bank-loss','med_incident_loss','med_case','med-1'),
          ('med-compensation',2800,'account-mule','med_incident_compensation','med_case','med-1');`);
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.customer_repair.reason, "approved_med_compensation_verified");
    assert.equal(result.customer_repair.state, "verified");
    assert.ok(result.reconciliation.evidence_refs.includes("ledger_entries:med-compensation"));
    item.events.prepare("DELETE FROM incident_case_entries WHERE id=14").run();
    bank.prepare("DELETE FROM ledger_entries WHERE tx_id='med-compensation'").run();
    bank.prepare(`UPDATE med_cases SET status='refunded',refunded_cents=4800,unrecovered_cents=0
      WHERE id='med-1'`).run();
    bank.prepare("UPDATE med_refunds SET amount=4800 WHERE id='refund-1'").run();
    bank.prepare("UPDATE ledger_entries SET amount=4800 WHERE tx_id='med-ledger'").run();
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.customer_repair.state, "verified");
    assert.equal(result.customer_repair.reason, "approved_med_refund_verified");
    assert.equal(result.reconciliation.reason, "payment_and_med_refund_balanced");
    bank.prepare(`UPDATE med_decisions SET evidence_ref='sentinel_alerts:other-alert'
      WHERE case_id='med-1'`).run();
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.state,
      "inconclusive", "a different alert cannot approve this incident repair");
    bank.prepare(`UPDATE med_decisions SET evidence_ref='sentinel_alerts:risk-miss-alert'
      WHERE case_id='med-1'`).run();
    bank.prepare(`UPDATE med_cases SET customer_id='cus-other'
      WHERE id='med-1'`).run();
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "suspicious_payment_customer_notified_impact_unverified",
      "another customer's MED cannot repair this owner");
    bank.prepare(`UPDATE med_cases SET customer_id='cus-owner'
      WHERE id='med-1'`).run();
    item.events.prepare(`DELETE FROM incident_case_entries WHERE id=3`).run();
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "suspicious_payment_impact_not_assessed");
    bank.prepare(`UPDATE lab_risk_miss_receipts SET transfer_id=?
      WHERE run_id='run-1'`).run("another-transfer");
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.symptom.state, "inconclusive");
    assert.equal(result.detection.state, "inconclusive");
  } finally { item.close(); }
});

test("an injector observation and an unrelated alert never pass the run", () => {
  const item = setup([observed("pix_dispatch_paused", "pix_spi_outbox:transfer-1")]);
  try {
    item.bank.prepare("INSERT INTO pix_spi_outbox VALUES (?,NULL)")
      .run("transfer-1");
    item.bank.prepare("INSERT INTO pix_transfers VALUES (?,?,?,?)")
      .run("transfer-1", "in_processing", null, "sim:another-run:0");
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("alert-1", "S-LED-02", "cross_book", begin, end, "{}");
    const result = item.evaluator.evaluate("run-1");
    assert.equal(result.verdict, "inconclusive");
    assert.equal(result.fixtures[0].symptom.state, "inconclusive");
    assert.equal(result.fixtures[0].detection.state, "inconclusive");
    assert.equal(result.fixtures[0].case.state, "inconclusive");
  } finally { item.close(); }
});

test("two fixtures only receive their own alert and case evidence", () => {
  const item = setup([observed("auth_event_silence", "sentinel_alerts:auth-alert"),
    observed("card_issuer_offline", "card_network_rejections:card-decline")]);
  try {
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("auth-alert", "S-AUTH-07", "auth", begin, begin, "{}");
    emit(item.events, 1, "auth-alert", "S-AUTH-07", "auth", {});
    item.events.prepare("INSERT INTO defense_cases VALUES (?)").run("auth-case");
    item.events.prepare(`INSERT INTO incident_case_entries
      (id,incident_id,kind,payload_json) VALUES (?,?,?,?)`)
      .run(1, "auth-case", "defense.observed",
        JSON.stringify({ alert_refs: ["sentinel_alerts:auth-alert"] }));
    const result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].detection.state, "verified");
    assert.equal(result.fixtures[0].case.state, "verified");
    assert.equal(result.fixtures[1].detection.state, "inconclusive");
    assert.equal(result.fixtures[1].case.state, "inconclusive");
    assert.equal(result.verdict, "inconclusive");
    item.events.prepare(`UPDATE incident_case_entries SET created_at=? WHERE id=1`)
      .run("2026-11-18T09:00:00.000Z");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].case.state,
      "inconclusive", "an old case for a reused alert ID is not this run's case");
  } finally { item.close(); }
});

test("a reused global alert needs an immutable emission inside the run", () => {
  const item = setup([observed("auth_event_silence",
    "sentinel_alerts:reused-alert")]);
  try {
    const before = "2026-11-18T09:00:00.000Z";
    const after = "2026-11-18T10:30:00.000Z";
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("reused-alert", "S-AUTH-07", "auth", before, begin, "{}");
    emit(item.events, 1, "reused-alert", "S-AUTH-07", "auth", {}, before);
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "inconclusive", "last_seen inside the run is insufficient");
    emit(item.events, 2, "reused-alert", "S-AUTH-07", "auth", {}, begin);
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "verified");
    item.bank.prepare(`UPDATE sentinel_alerts SET last_seen=?,observed_json=?
      WHERE id='reused-alert'`).run(after, JSON.stringify({ unrelated: 1 }));
    emit(item.events, 3, "reused-alert", "S-AUTH-07", "auth", {}, after);
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "verified", "later scans cannot erase the run's immutable emission");
  } finally { item.close(); }
});

test("simultaneous Pix and PSP faults require distinct transfer and stage alerts", () => {
  const item = setup([observed("pix_dispatch_paused", "pix_spi_outbox:pix-1"),
    observed("psp_receipt_delayed", "pix_psp_inbound_outbox:psp-1")]);
  try {
    item.bank.prepare("INSERT INTO pix_transfers VALUES (?,?,?,?)")
      .run("pix-1", "in_processing", null,
        "sim:run-1:pix_dispatch_paused:0");
    item.bank.prepare("INSERT INTO pix_transfers VALUES (?,?,?,?)")
      .run("psp-1", "settled", null,
        "sim:run-1:psp_receipt_delayed:0");
    item.bank.prepare("INSERT INTO pix_spi_outbox VALUES (?,NULL)").run("pix-1");
    item.bank.prepare("INSERT INTO pix_psp_inbound_outbox VALUES (?,NULL)")
      .run("psp-1");
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("pix-alert", "S-LED-12", "pix-1", begin, begin,
        JSON.stringify({ kind: "pix", command_id: "pix-1" }));
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("psp-alert", "S-LED-12", "psp-1", begin, begin,
        JSON.stringify({ kind: "pix", command_id: "psp-1" }));
    emit(item.events, 1, "pix-alert", "S-LED-12", "pix-1",
      { kind: "pix", command_id: "pix-1" });
    emit(item.events, 2, "psp-alert", "S-LED-12", "psp-1",
      { kind: "pix", command_id: "psp-1" });
    item.events.prepare("INSERT INTO defense_cases VALUES (?)").run("pix-case");
    item.events.prepare(`INSERT INTO incident_case_entries
      (id,incident_id,kind,payload_json) VALUES (?,?,?,?)`)
      .run(10, "pix-case", "defense.observed",
        JSON.stringify({ alert_refs: ["sentinel_alerts:pix-alert"] }));
    const result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].symptom.state, "verified");
    assert.equal(result.fixtures[0].detection.state, "verified");
    assert.equal(result.fixtures[0].case.state, "verified");
    assert.equal(result.fixtures[1].symptom.state, "verified");
    assert.equal(result.fixtures[1].detection.state, "inconclusive",
      "a Pix-stage alert cannot satisfy the PSP-stage fixture");
    assert.equal(result.fixtures[1].case.state, "inconclusive");
    emit(item.events, 3, "psp-alert", "S-LED-12", "psp-1",
      { kind: "inbound", command_id: "psp-1" });
    const corrected = item.evaluator.evaluate("run-1");
    assert.equal(corrected.fixtures[1].detection.state, "verified");
    assert.equal(corrected.fixtures[1].case.state, "inconclusive",
      "a separate alert without a defense case cannot borrow the Pix case");
    item.bank.prepare(`UPDATE sentinel_alerts SET observed_json=?,last_seen=?
      WHERE id='psp-alert'`).run(JSON.stringify({ kind: "pix", command_id: "psp-1" }),
        "2026-11-18T10:30:00.000Z");
    emit(item.events, 4, "psp-alert", "S-LED-12", "psp-1",
      { kind: "pix", command_id: "psp-1" }, "2026-11-18T10:30:00.000Z");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[1].detection.state,
      "verified", "later kind changes cannot erase an in-run inbound emission");
  } finally { item.close(); }
});

test("PSP reconciliation requires fresh external and balanced bank books", () => {
  const item = setup([observed("psp_receipt_delayed",
    "pix_psp_inbound_outbox:psp-1")]);
  try {
    item.bank.prepare("INSERT INTO pix_transfers VALUES (?,?,?,?)")
      .run("psp-1", "settled", "tx-1", "sim:run-1:psp_receipt_delayed:0");
    item.bank.prepare("INSERT INTO pix_spi_outbox VALUES (?,?)")
      .run("psp-1", "ACSC");
    item.bank.prepare("INSERT INTO pix_psp_inbound_outbox VALUES (?,?)")
      .run("psp-1", end);
    item.bank.prepare("INSERT INTO ledger_entries VALUES (?,?)").run("tx-1", -100);
    item.bank.prepare("INSERT INTO ledger_entries VALUES (?,?)").run("tx-1", 100);
    const stageFor = (observation) => item.evaluator.evaluate("run-1", observation)
      .fixtures[0].reconciliation;
    assert.equal(stageFor(null).reason, "cross_book_reconciliation_not_proven");
    assert.equal(stageFor({ checked_at: begin, report: { ok: true } }).state,
      "inconclusive", "a pre-recovery verification cannot prove both books");
    assert.equal(stageFor({ checked_at: "2026-11-18T10:02:19.000Z",
      report: { ok: false } }).state, "inconclusive");
    const report = { ok: true };
    const checkedAt = "2026-11-18T10:02:19.000Z";
    const observation = { checked_at: checkedAt, report, proof_ref: "events:7" };
    assert.equal(stageFor(observation).state, "inconclusive",
      "a current verifier result without a durable receipt is insufficient");
    const reportHash = createHash("sha256").update(JSON.stringify(report))
      .digest("hex");
    item.events.prepare(`INSERT INTO events (seq,type,public_json,ts,twin_ts)
      VALUES (7,'ecosystem.cross_book_check',?,?,?)`).run(
      JSON.stringify({ ok: true, report_sha256: reportHash }), checkedAt, checkedAt);
    item.events.prepare("INSERT INTO event_private VALUES (?,?)")
      .run(7, JSON.stringify({ report }));
    const checked = stageFor(observation);
    assert.equal(checked.state, "verified");
    assert.ok(checked.evidence_refs.includes("ledger_entries:tx-1"));
    assert.ok(checked.evidence_refs.includes("pix_psp_inbound_outbox:psp-1"));
    assert.ok(checked.evidence_refs.includes("events:7"));
    item.events.prepare("UPDATE event_private SET private_json=? WHERE seq=7")
      .run(JSON.stringify({ report: { ok: false } }));
    assert.equal(stageFor(observation).state, "inconclusive",
      "a receipt for another report cannot prove the current result");
    item.events.prepare("UPDATE event_private SET private_json=? WHERE seq=7")
      .run(JSON.stringify({ report }));
    item.bank.prepare("DELETE FROM ledger_entries WHERE amount=100").run();
    assert.equal(stageFor(observation).state, "inconclusive",
    "an external green report cannot hide an unbalanced local posting");
  } finally { item.close(); }
});

test("queue response requires a reviewed receipt for the exact transfer and cross-book proof", () => {
  const item = setup([observed("pix_dispatch_paused", "pix_spi_outbox:pix-1")]);
  try {
    item.bank.prepare("INSERT INTO pix_transfers VALUES (?,?,?,?)")
      .run("pix-1", "settled", "tx-1", "sim:run-1:pix_dispatch_paused:0");
    item.bank.prepare("INSERT INTO pix_spi_outbox VALUES (?,?)")
      .run("pix-1", "ACSC");
    item.bank.prepare("INSERT INTO pix_psp_inbound_outbox VALUES (?,?)")
      .run("pix-1", end);
    item.bank.prepare("INSERT INTO ledger_entries VALUES (?,?)").run("tx-1", -100);
    item.bank.prepare("INSERT INTO ledger_entries VALUES (?,?)").run("tx-1", 100);
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("pix-alert", "S-LED-12", "pix-1", begin, begin,
        JSON.stringify({ kind: "pix", command_id: "pix-1" }));
    emit(item.events, 1, "pix-alert", "S-LED-12", "pix-1",
      { kind: "pix", command_id: "pix-1" });
    item.events.prepare("INSERT INTO defense_cases VALUES (?)").run("pix-case");
    const add = (id, kind, payload) => item.events.prepare(`INSERT INTO
      incident_case_entries (id,incident_id,kind,payload_json)
      VALUES (?,'pix-case',?,?)`).run(id, kind, JSON.stringify(payload));
    add(1, "defense.observed", { case_version: 1,
      alert_refs: ["sentinel_alerts:pix-alert"] });
    add(2, "dossier.defense_investigation", { case_version: 1 });
    add(3, "dossier.defense_plan", { case_version: 1, revision: 0,
      disposition: "external_recovery" });
    add(4, "dossier.defense_review", { case_version: 1, revision: 0,
      verdict: "approve" });
    const checkedAt = "2026-11-18T10:02:19.000Z";
    const report = { ok: true };
    const reportHash = createHash("sha256").update(JSON.stringify(report))
      .digest("hex");
    item.events.prepare(`INSERT INTO events (seq,type,public_json,ts,twin_ts)
      VALUES (7,'ecosystem.cross_book_check',?,?,?)`).run(
      JSON.stringify({ ok: true, report_sha256: reportHash }), checkedAt, checkedAt);
    item.events.prepare("INSERT INTO event_private VALUES (?,?)")
      .run(7, JSON.stringify({ report }));
    const crossBook = { checked_at: checkedAt, report, proof_ref: "events:7" };
    const response = () => item.evaluator.evaluate("run-1", crossBook)
      .fixtures[0].response;
    assert.equal(response().state, "inconclusive",
      "settlement and a reviewed plan alone do not prove the defense response");
    const receipt = { case_version: 1, revision: 0, phase: "recovered",
      evidence_refs: ["sentinel_alerts:pix-alert", "pix_transfers:pix-1"],
      items: [{ transfer_id: "pix-1", ledger_tx_id: "tx-1",
        response_status: "ACSC", recipient_acknowledged: true }],
      bank_reconciled: true, bank_correction_applied: false,
      customer_repair: "payment_completed" };
    add(5, "defense.queue_recovery_verified", receipt);
    assert.equal(response().state, "verified");
    for (const [seq, ts] of [[8, end], [9, "2026-11-18T10:02:10.000Z"]])
      item.events.prepare(`INSERT INTO events (seq,type,public_json,ts,twin_ts)
        VALUES (?,'sim.tick',?,?,?)`).run(seq,
          JSON.stringify({ ops: 8, honest_blocked: 0, by_area: { pix: 2 } }), ts, ts);
    assert.equal(item.evaluator.evaluate("run-1", crossBook).verdict, "passed",
      "a ten-second simulator cadence must survive verification query latency");
    item.events.prepare("UPDATE incident_case_entries SET payload_json=? WHERE id=5")
      .run(JSON.stringify({ ...receipt, items: [{ ...receipt.items[0],
        transfer_id: "other-transfer" }] }));
    assert.equal(response().state, "inconclusive",
      "a receipt for another transfer cannot verify this run");
    item.events.prepare("UPDATE incident_case_entries SET payload_json=? WHERE id=5")
      .run(JSON.stringify(receipt));
    item.events.prepare("UPDATE event_private SET private_json=? WHERE seq=7")
      .run(JSON.stringify({ report: { ok: false } }));
    assert.equal(response().state, "inconclusive",
      "a positive defense receipt cannot replace a valid external book proof");
  } finally { item.close(); }
});

test("SPI outage only accepts its own Pix-stage transfer alert", () => {
  const item = setup([observed("spi_unavailable", "pix_spi_outbox:spi-1")]);
  try {
    item.bank.prepare("INSERT INTO pix_transfers VALUES (?,?,?,?)")
      .run("spi-1", "in_processing", null, "sim:run-1:spi_unavailable:0");
    item.bank.prepare("INSERT INTO pix_spi_outbox VALUES (?,NULL)").run("spi-1");
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("spi-alert", "S-LED-12", "spi-1", begin, begin,
        JSON.stringify({ kind: "pix", command_id: "some-other-transfer" }));
    emit(item.events, 1, "spi-alert", "S-LED-12", "spi-1",
      { kind: "pix", command_id: "some-other-transfer" });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "inconclusive");
    emit(item.events, 2, "spi-alert", "S-LED-12", "spi-1",
      { kind: "pix", command_id: "spi-1" });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "verified");
  } finally { item.close(); }
});

test("hourly proof recovery requires the proof for the missing hour", () => {
  const item = setup([observed("hourly_proof_paused",
    "sentinel_alerts:proof-alert")]);
  try {
    const hour = "2026-11-18T09:00:00.000Z";
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("proof-alert", "S-LED-11", "ledger_hourly_proof", begin, begin,
        JSON.stringify({ missing_hour_start: hour }));
    emit(item.events, 1, "proof-alert", "S-LED-11",
      "ledger_hourly_proof", { missing_hour_start: hour });
    item.events.prepare("INSERT INTO events (seq,type,public_json) VALUES (?,?,?)")
      .run(2, "ledger.hourly_proof",
        JSON.stringify({ hour_start: "2026-11-18T08:00:00.000Z" }));
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].continuity.state,
      "inconclusive");
    item.events.prepare("INSERT INTO events (seq,type,public_json) VALUES (?,?,?)")
      .run(3, "ledger.hourly_proof", JSON.stringify({ hour_start: hour }));
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].continuity.state,
      "verified");
  } finally { item.close(); }
});

test("stopping a fault and reviewing a code candidate do not complete defense", () => {
  const item = setup([observed("auth_event_silence",
    "sentinel_alerts:auth-alert")]);
  try {
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("auth-alert", "S-AUTH-07", "auth", begin, begin, "{}");
    emit(item.events, 1, "auth-alert", "S-AUTH-07", "auth", {});
    item.bank.prepare("INSERT INTO telemetry_events VALUES (?,?,?,?,?,'success')")
      .run(1, "auth", "health", "heartbeat", "2026-11-18T10:02:02.000Z");
    item.events.prepare("INSERT INTO defense_cases VALUES (?)").run("auth-case");
    const add = (id, kind, payload) => item.events.prepare(`INSERT INTO
      incident_case_entries (id,incident_id,kind,payload_json)
      VALUES (?,'auth-case',?,?)`).run(id, kind, JSON.stringify(payload));
    add(1, "defense.observed", { case_version: 1,
      alert_refs: ["sentinel_alerts:auth-alert"] });
    let result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].continuity.state, "verified");
    assert.equal(result.fixtures[0].case.state, "verified");
    assert.equal(result.fixtures[0].response.state, "inconclusive");
    assert.equal(result.verdict, "inconclusive");
    add(2, "dossier.defense_investigation", { case_version: 1 });
    add(3, "dossier.defense_plan", { case_version: 1, revision: 0,
      disposition: "code_candidate" });
    add(4, "dossier.defense_review", { case_version: 1, revision: 0,
      verdict: "approve" });
    add(5, "defense.code_dispatch", { case_version: 1, revision: 0,
      status: "ready_for_internal_pr" });
    result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].response.reason,
      "reviewed_code_candidate_not_applied");
    assert.equal(result.verdict, "inconclusive");
  } finally { item.close(); }
});

test("gateway silence needs its own alert, later heartbeat and reviewed recovery receipt", () => {
  const item = setup([observed("gateway_heartbeat_silence",
    "sentinel_alerts:gateway-alert")]);
  try {
    const bank = item.bank, events = item.events;
    bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("gateway-alert", "S-AUTH-07", "auth", begin, begin, "{}");
    emit(events, 1, "gateway-alert", "S-AUTH-07", "auth", {});
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "inconclusive");
    bank.prepare("UPDATE sentinel_alerts SET rule_id=?,entity=? WHERE id=?")
      .run("S-GW-07", "gateway", "gateway-alert");
    emit(events, 2, "gateway-alert", "S-GW-07", "gateway", {});
    let result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.detection.state, "verified");
    assert.equal(result.continuity.state, "inconclusive");
    const heartbeat = bank.prepare("INSERT INTO telemetry_events VALUES (?,?,?,?,?,?)");
    heartbeat.run(1, "auth", "health", "heartbeat", "2026-11-18T10:02:02.000Z", "success");
    heartbeat.run(2, "gateway", "health", "heartbeat", "2026-11-18T10:02:02.000Z", "failure");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].continuity.state,
      "inconclusive");
    heartbeat.run(3, "gateway", "health", "heartbeat", "2026-11-18T10:02:03.000Z", "success");
    heartbeat.run(4, "gateway", "health", "heartbeat", "2026-11-18T10:02:06.000Z", "success");
    events.prepare("INSERT INTO defense_cases VALUES (?)").run("gateway-case");
    const add = (id, kind, payload) => events.prepare(`INSERT INTO
      incident_case_entries (id,incident_id,kind,payload_json)
      VALUES (?,'gateway-case',?,?)`).run(id, kind, JSON.stringify(payload));
    add(1, "defense.observed", { case_version: 1,
      alert_refs: ["sentinel_alerts:gateway-alert"] });
    add(2, "dossier.defense_investigation", { case_version: 1 });
    add(3, "dossier.defense_plan", { case_version: 1, revision: 0,
      disposition: "source_recovery" });
    add(4, "dossier.defense_review", { case_version: 1, revision: 0,
      verdict: "approve" });
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.continuity.state, "verified");
    assert.equal(result.response.state, "inconclusive");
    const receipt = { case_version: 1,
      revision: 0, source: "gateway", alert_id: "gateway-alert",
      ledger_healthy: true, bank_correction_applied: false,
      customer_repair: "no_linked_loss" };
    const recordReceipt = (evidenceId) => events.prepare(`INSERT OR REPLACE INTO
      incident_case_entries (id,incident_id,kind,payload_json,created_at)
      VALUES (5,'gateway-case','defense.source_recovery_verified',?,
        '2026-11-18T10:02:05.000Z')`).run(JSON.stringify({
          ...receipt, evidence_refs: ["sentinel_alerts:gateway-alert", `telemetry_events:${evidenceId}`],
        }));
    for (const incorrect of [1, 2, 4]) {
      recordReceipt(incorrect);
      assert.equal(item.evaluator.evaluate("run-1").fixtures[0].response.state,
        "inconclusive");
    }
    recordReceipt(3);
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.response.state, "verified");
    assert.equal(result.response.reason, "reviewed_source_recovery");
    assert.equal(result.verdict, "pending",
      "source recovery alone does not prove healthy post-recovery traffic");
  } finally { item.close(); }
});

test("statement recovery belongs to the denied customer and exact account", () => {
  const item = setup([observed("statement_unavailable",
    "sentinel_alerts:statement-alert")]);
  try {
    const bank = item.bank, events = item.events;
    bank.exec(`CREATE TABLE access_log (id TEXT PRIMARY KEY,ts TEXT,
      kind TEXT,status INTEGER,customer_id TEXT,account_id TEXT);
      CREATE TABLE lab_statement_outage_receipts (run_id TEXT,
        customer_id TEXT,account_id TEXT,failed_log_id TEXT,
        recovered_log_id TEXT);`);
    bank.prepare(`INSERT INTO lab_statement_outage_receipts VALUES
      ('run-1','customer-1','account-1','failed-1',NULL)`).run();
    bank.prepare("INSERT INTO access_log VALUES (?,?,?,?,?,?)")
      .run("failed-1", begin, "statement_own", 503,
        "customer-1", "account-1");
    const observedData = { failed_log_id: "failed-1", account_id: "account-1" };
    bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("statement-alert", "S-ACC-04", "customer-1", begin, begin,
        JSON.stringify(observedData));
    emit(events, 1, "statement-alert", "S-ACC-04", "customer-1",
      observedData);
    let result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.symptom.state, "verified");
    assert.equal(result.detection.state, "verified");
    assert.equal(result.customer_repair.state, "inconclusive");
    bank.prepare("INSERT INTO access_log VALUES (?,?,?,?,?,?)")
      .run("other-1", end, "statement_own", 200,
        "customer-2", "account-1");
    bank.prepare(`UPDATE lab_statement_outage_receipts
      SET recovered_log_id='other-1'`).run();
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].continuity.state,
      "inconclusive");
    bank.prepare("INSERT INTO access_log VALUES (?,?,?,?,?,?)")
      .run("recovered-1", end, "statement_own", 200,
        "customer-1", "account-1");
    bank.prepare(`UPDATE lab_statement_outage_receipts
      SET recovered_log_id='recovered-1'`).run();
    events.prepare("INSERT INTO defense_cases VALUES (?)").run("statement-case");
    const add = (id, kind, payload) => events.prepare(`INSERT INTO
      incident_case_entries (id,incident_id,kind,payload_json)
      VALUES (?,'statement-case',?,?)`).run(id, kind, JSON.stringify(payload));
    add(1, "defense.observed", { case_version: 1,
      alert_refs: ["sentinel_alerts:statement-alert"] });
    add(2, "dossier.defense_investigation", { case_version: 1 });
    add(3, "dossier.defense_plan", { case_version: 1, revision: 0,
      disposition: "source_recovery" });
    add(4, "dossier.defense_review", { case_version: 1, revision: 0,
      verdict: "approve" });
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.continuity.state, "verified");
    assert.equal(result.customer_repair.state, "verified");
    assert.equal(result.response.state, "inconclusive");
    add(5, "defense.source_recovery_verified", { case_version: 1,
      revision: 0, source: "accounts_statement", alert_id: "statement-alert",
      ledger_healthy: true, bank_correction_applied: false,
      customer_repair: "statement_retry_succeeded",
      evidence_refs: ["sentinel_alerts:statement-alert",
        "access_log:recovered-1"] });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].response.state,
      "inconclusive", "the reviewed receipt must cite the original denial");
    events.prepare(`UPDATE incident_case_entries SET payload_json=? WHERE id=5`)
      .run(JSON.stringify({ case_version: 1, revision: 0,
        source: "accounts_statement", alert_id: "statement-alert",
        ledger_healthy: true, bank_correction_applied: false,
        customer_repair: "statement_retry_succeeded",
        evidence_refs: ["sentinel_alerts:statement-alert",
          "access_log:failed-1", "access_log:recovered-1"] }));
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.response.state, "verified");
    assert.equal(result.verdict, "pending",
      "the honest-traffic watch still needs its own proof");
  } finally { item.close(); }
});

test("loan offer recovery requires the denied customer and exact reviewed receipt", () => {
  const item = setup([observed("loan_offer_unavailable",
    "sentinel_alerts:loan-alert")]);
  try {
    const bank = item.bank, events = item.events;
    bank.exec(`CREATE TABLE access_log (id TEXT PRIMARY KEY,ts TEXT,
      kind TEXT,status INTEGER,customer_id TEXT);
      CREATE TABLE lab_loan_offer_outage_receipts (run_id TEXT,
        customer_id TEXT,failed_log_id TEXT,recovered_log_id TEXT);`);
    bank.prepare("INSERT INTO lab_loan_offer_outage_receipts VALUES (?,?,?,NULL)")
      .run("run-1", "customer-1", "failed-1");
    bank.prepare("INSERT INTO access_log VALUES (?,?,?,?,?)")
      .run("failed-1", begin, "loan_offer_own", 503, "customer-1");
    const observedData = { failed_log_id: "failed-1" };
    bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("loan-alert", "S-LOAN-04", "customer-1", begin, begin,
        JSON.stringify(observedData));
    emit(events, 1, "loan-alert", "S-LOAN-04", "customer-1", observedData);
    let result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.symptom.state, "verified");
    assert.equal(result.detection.state, "verified");
    assert.equal(result.customer_repair.state, "inconclusive");
    bank.prepare("INSERT INTO access_log VALUES (?,?,?,?,?)")
      .run("other-1", end, "loan_offer_own", 200, "customer-2");
    bank.prepare("UPDATE lab_loan_offer_outage_receipts SET recovered_log_id='other-1'").run();
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].continuity.state,
      "inconclusive");
    bank.prepare("INSERT INTO access_log VALUES (?,?,?,?,?)")
      .run("recovered-1", end, "loan_offer_own", 200, "customer-1");
    bank.prepare("UPDATE lab_loan_offer_outage_receipts SET recovered_log_id='recovered-1'").run();
    events.prepare("INSERT INTO defense_cases VALUES (?)").run("loan-case");
    const add = (id, kind, payload) => events.prepare(`INSERT INTO
      incident_case_entries (id,incident_id,kind,payload_json)
      VALUES (?,'loan-case',?,?)`).run(id, kind, JSON.stringify(payload));
    add(1, "defense.observed", { case_version: 1,
      alert_refs: ["sentinel_alerts:loan-alert"] });
    add(2, "dossier.defense_investigation", { case_version: 1 });
    add(3, "dossier.defense_plan", { case_version: 1, revision: 0,
      disposition: "source_recovery" });
    add(4, "dossier.defense_review", { case_version: 1, revision: 0,
      verdict: "approve" });
    result = item.evaluator.evaluate("run-1").fixtures[0];
    assert.equal(result.continuity.state, "verified");
    assert.equal(result.customer_repair.state, "verified");
    add(5, "defense.source_recovery_verified", { case_version: 1,
      revision: 0, source: "loans_offer", alert_id: "loan-alert",
      ledger_healthy: true, bank_correction_applied: false,
      customer_repair: "loan_offer_retry_succeeded",
      evidence_refs: ["sentinel_alerts:loan-alert", "access_log:recovered-1"] });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].response.state,
      "inconclusive");
    events.prepare("UPDATE incident_case_entries SET payload_json=? WHERE id=5")
      .run(JSON.stringify({ case_version: 1, revision: 0,
        source: "loans_offer", alert_id: "loan-alert",
        ledger_healthy: true, bank_correction_applied: false,
        customer_repair: "loan_offer_retry_succeeded",
        evidence_refs: ["sentinel_alerts:loan-alert",
          "access_log:failed-1", "access_log:recovered-1"] }));
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].response.state,
      "verified");
  } finally { item.close(); }
});

test("insufficient evidence never verifies a response, even after queue recovery", () => {
  const item = setup([observed("spi_unavailable", "pix_spi_outbox:spi-1")]);
  try {
    item.bank.prepare("INSERT INTO pix_transfers VALUES (?,?,?,?)")
      .run("spi-1", "settled", null, "sim:run-1:spi_unavailable:0");
    item.bank.prepare("INSERT INTO pix_spi_outbox VALUES (?,?)")
      .run("spi-1", "ACSC");
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("spi-alert", "S-LED-12", "spi-1", begin, begin,
        JSON.stringify({ kind: "pix", command_id: "spi-1" }));
    emit(item.events, 1, "spi-alert", "S-LED-12", "spi-1",
      { kind: "pix", command_id: "spi-1" });
    item.events.prepare("INSERT INTO defense_cases VALUES (?)").run("spi-case");
    const add = (id, kind, payload) => item.events.prepare(`INSERT INTO
      incident_case_entries (id,incident_id,kind,payload_json)
      VALUES (?,'spi-case',?,?)`).run(id, kind, JSON.stringify(payload));
    add(1, "defense.observed", { case_version: 1,
      alert_refs: ["sentinel_alerts:spi-alert"] });
    add(2, "dossier.defense_investigation", { case_version: 1 });
    add(3, "dossier.defense_plan", { case_version: 1, revision: 0,
      disposition: "insufficient_evidence" });
    add(4, "dossier.defense_review", { case_version: 1, revision: 0,
      verdict: "approve" });
    let result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].response.state, "inconclusive");
    assert.equal(result.fixtures[0].response.reason,
      "reviewed_plan_has_no_verified_correction");
    assert.equal(result.fixtures[0].reconciliation.state, "inconclusive");
    item.bank.prepare("UPDATE pix_transfers SET idempotency_key=? WHERE id='spi-1'")
      .run("sim:another-run:0");
    result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].response.state, "inconclusive");
  } finally { item.close(); }
});

test("card issuer recovery requires a same-case and same-revision receipt", () => {
  const item = setup([observed("card_issuer_offline",
    "card_network_rejections:decline-1")]);
  try {
    item.bank.prepare("INSERT INTO card_issuer_history VALUES (?,?,?,?)")
      .run(1, 0, "fault_lab_run_1", begin);
    item.bank.prepare("INSERT INTO card_issuer_history VALUES (?,?,?,?)")
      .run(2, 1, "fault_lab_run_1", "2026-11-18T10:01:00.000Z");
    item.bank.prepare("INSERT INTO card_network_rejections VALUES (?,?,?,?,?,?)")
      .run("decline-1", "91", begin, "card-1", "shop_ipe", 500);
    item.bank.prepare("INSERT INTO card_network_authorizations VALUES (?,?,?,?,?,?)")
      .run("auth-1", "00", "2026-11-18T10:01:30.000Z",
        "card-1", "market_aroeira", 100);
    item.bank.prepare("INSERT INTO card_network_messages VALUES (?,?,?)")
      .run("auth-1", "0110", JSON.stringify({ response_code: "00" }));
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("issuer-alert", "S-CARD-13", "card_issuer", begin, begin,
        JSON.stringify({ issuer_unavailable: 1, declined_authorizations: 1 }));
    emit(item.events, 1, "issuer-alert", "S-CARD-13", "card_issuer",
      { issuer_unavailable: 1, declined_authorizations: 1 });
    item.events.prepare("INSERT INTO defense_cases VALUES (?)").run("card-case");
    item.events.prepare("INSERT INTO defense_cases VALUES (?)").run("other-case");
    const add = (id, incident, kind, payload) => item.events.prepare(`INSERT INTO
      incident_case_entries (id,incident_id,kind,payload_json)
      VALUES (?,?,?,?)`).run(id, incident, kind, JSON.stringify(payload));
    add(1, "card-case", "defense.observed", { case_version: 2,
      alert_refs: ["sentinel_alerts:issuer-alert"] });
    add(2, "card-case", "dossier.defense_investigation", { case_version: 2 });
    add(3, "card-case", "dossier.defense_plan", { case_version: 2,
      revision: 1, disposition: "external_recovery" });
    add(4, "card-case", "dossier.defense_review", { case_version: 2,
      revision: 1, verdict: "approve" });
    const refs = ["sentinel_alerts:issuer-alert",
      "card_issuer_history:1", "card_network_rejections:decline-1",
      "card_issuer_history:2", "card_network_authorizations:auth-1"];
    const receipt = (case_version, revision) => ({ case_version, revision,
      phase: "recovered", evidence_refs: refs, issuer_available: true,
      alert_id: "issuer-alert", rejection_id: "decline-1",
      outage_history_id: 1, restored_history_id: 2,
      authorization_id: "auth-1",
      customer_repair: "not_proven", individual_nonfinancial_harm: "unknown",
      bank_correction_applied: false });
    let result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].continuity.state, "verified");
    assert.equal(result.fixtures[0].response.state, "inconclusive");
    assert.equal(result.fixtures[0].customer_repair.state, "inconclusive");
    assert.equal(result.fixtures[0].customer_repair.reason,
      "individual_nonfinancial_harm_unknown");
    add(5, "other-case", "defense.external_recovery_verified", receipt(2, 1));
    add(6, "card-case", "defense.external_recovery_verified", receipt(3, 1));
    add(7, "card-case", "defense.external_recovery_verified", receipt(2, 0));
    result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].response.state, "inconclusive");
    add(8, "card-case", "defense.external_recovery_verified",
      { ...receipt(2, 1), rejection_id: "other-decline" });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].response.state,
      "inconclusive", "a receipt naming another rejection is not this run's recovery");
    item.bank.prepare("INSERT INTO card_network_rejections VALUES (?,?,?,?,?,?)")
      .run("decline-2", "91", "2026-11-18T10:00:30.000Z",
        "card-2", "shop_ipe", 500);
    add(9, "card-case", "defense.external_recovery_verified", {
      ...receipt(2, 1), rejection_id: "decline-2",
      evidence_refs: refs.map((ref) => ref ===
        "card_network_rejections:decline-1" ?
        "card_network_rejections:decline-2" : ref) });
    result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].response.state, "verified");
    assert.ok(result.fixtures[0].symptom.evidence_refs.includes(
      "card_network_rejections:decline-1"),
    "the run-owned decline remains separately proven");
    assert.equal(result.fixtures[0].customer_repair.state, "inconclusive");
    assert.equal(result.verdict, "inconclusive",
      "service recovery does not prove individual customer repair");
    add(10, "card-case", "dossier.defense_impact", { case_version: 2,
      findings: [{ kind: "service_unavailable", entity_ref: "customer-1",
        evidence_refs: ["card_network_rejections:other-decline"] }] });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "individual_nonfinancial_harm_unknown");
    add(11, "card-case", "dossier.defense_impact", { case_version: 2,
      findings: [{ kind: "service_unavailable", entity_ref: "customer-1",
        evidence_refs: ["card_network_rejections:decline-1"] }] });
    result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].customer_repair.reason,
      "known_service_harm_not_repaired");
    assert.deepEqual(result.fixtures[0].customer_repair.evidence_refs,
      ["incident_case_entries:11"]);
    add(12, "card-case", "defense.customer_notice", { case_version: 2,
      customer_id: "customer-1", notice_id: 1, rejection_id: "decline-1" });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.reason,
      "known_service_harm_not_repaired", "a case receipt alone is not delivery proof");
    item.bank.prepare("INSERT INTO incident_customer_notices VALUES (?,?,?,?,?,?)")
      .run("customer-1", 1, "card-case", "decline-1",
        "card_issuer_recovered", "2026-11-18T10:01:35.000Z");
    result = item.evaluator.evaluate("run-1");
    assert.equal(result.fixtures[0].customer_repair.reason,
      "customer_notified_retry_unproven");
    assert.equal(result.fixtures[0].customer_repair.state, "inconclusive");
    item.bank.prepare("INSERT INTO card_network_authorizations VALUES (?,?,?,?,?,?)")
      .run("auth-retry", "00", "2026-11-18T10:01:40.000Z",
        "card-1", "shop_ipe", 500);
    item.bank.prepare("INSERT INTO card_network_messages VALUES (?,?,?)")
      .run("auth-retry", "0110", JSON.stringify({ response_code: "00" }));
    item.events.prepare(`INSERT INTO events (seq,type,public_json,ts,twin_ts)
      VALUES (13,'sim.card_retry',?,?,?)`).run(
      JSON.stringify({ outcome: "authorized" }),
      "2026-11-18T10:01:40.000Z", "2026-11-18T10:01:40.000Z");
    item.events.prepare("INSERT INTO event_private VALUES (?,?)")
      .run(13, JSON.stringify({ customer_id: "customer-1",
        rejection_id: "decline-1", authorization_id: "auth-retry" }));
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.state,
      "verified");
    item.events.prepare("UPDATE event_private SET private_json=? WHERE seq=13")
      .run(JSON.stringify({ customer_id: "other-customer",
        rejection_id: "decline-1", authorization_id: "auth-retry" }));
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].customer_repair.state,
      "inconclusive", "another customer's retry cannot repair this customer");
  } finally { item.close(); }
});

test("card detection requires an emission after this run's decline", () => {
  const item = setup([observed("card_issuer_offline",
    "card_network_rejections:decline-1")]);
  try {
    const declineAt = "2026-11-18T10:00:30.000Z";
    item.bank.prepare("INSERT INTO card_issuer_history VALUES (?,?,?,?)")
      .run(1, 0, "fault_lab_run_1", begin);
    item.bank.prepare("INSERT INTO card_network_rejections VALUES (?,?,?,?,?,?)")
      .run("decline-1", "91", declineAt, "card-1", "shop_ipe", 500);
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("issuer-alert", "S-CARD-13", "card_issuer", begin, end, "{}");
    const signal = { issuer_unavailable: 1, declined_authorizations: 1 };
    emit(item.events, 1, "issuer-alert", "S-CARD-13", "card_issuer",
      signal, "2026-11-18T10:00:05.000Z");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "inconclusive", "an earlier decline signal cannot prove this decline");
    emit(item.events, 2, "issuer-alert", "S-CARD-13", "card_issuer",
      signal, "2026-11-18T10:00:35.000Z");
    assert.deepEqual(item.evaluator.evaluate("run-1").fixtures[0].detection.evidence_refs,
      ["events:2"]);
  } finally { item.close(); }
});

test("a risk hold passes only with its exact Sentinel case and applied repair receipt", () => {
  const item = setup([observed("risk_false_hold", "risk_pix_holds:hold-1")]);
  try {
    item.bank.prepare("INSERT INTO risk_pix_holds VALUES (?,?,?,?,?,?)")
      .run("hold-1", "sim:run-1:0", "approved", "transfer-1", "balance-1",
        "defense-coordinator");
    item.bank.prepare("INSERT INTO balance_holds VALUES (?,?)")
      .run("balance-1", end);
    item.bank.prepare("INSERT INTO pix_transfers VALUES (?,?,?,?)")
      .run("transfer-1", "settled", "tx-1", "sim:run-1:0");
    item.bank.prepare("INSERT INTO ledger_entries VALUES (?,?)").run("tx-1", -100);
    item.bank.prepare("INSERT INTO ledger_entries VALUES (?,?)").run("tx-1", 100);
    item.bank.prepare("INSERT INTO sentinel_alerts VALUES (?,?,?,?,?,?)")
      .run("risk-alert", "S-PIX-41", "hold-1", begin, begin, "{}");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "inconclusive", "a mutable alert row does not prove an in-run emission");
    emit(item.events, 1, "risk-alert", "S-PIX-41", "hold-1",
      { hold_id: "another-hold", policy_outcome: "approve",
        recorded_score: 90, policy_score: 10 });
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "inconclusive", "another hold's emission cannot satisfy this fixture");
    emit(item.events, 2, "risk-alert", "S-PIX-41", "hold-1",
      { hold_id: "hold-1", policy_outcome: "approve",
        recorded_score: 90, policy_score: 10 });
    item.events.prepare("INSERT INTO defense_cases VALUES (?)").run("risk-case");
    item.events.prepare(`INSERT INTO incident_case_entries
      (id,incident_id,kind,payload_json) VALUES (?,?,?,?)`)
      .run(1, "risk-case", "defense.observed",
        JSON.stringify({ case_version: 1,
          alert_refs: ["sentinel_alerts:risk-alert"] }));
    assert.equal(item.evaluator.evaluate("run-1").verdict, "inconclusive");
    item.events.prepare(`INSERT INTO incident_case_entries
      (id,incident_id,kind,payload_json) VALUES (?,?,?,?)`)
      .run(2, "risk-case", "dossier.defense_investigation",
        JSON.stringify({ case_version: 1 }));
    item.events.prepare(`INSERT INTO incident_case_entries
      (id,incident_id,kind,payload_json) VALUES (?,?,?,?)`)
      .run(3, "risk-case", "dossier.defense_plan", JSON.stringify({
        case_version: 1, revision: 0, disposition: "operational_action" }));
    item.events.prepare(`INSERT INTO incident_case_entries
      (id,incident_id,kind,payload_json) VALUES (?,?,?,?)`)
      .run(4, "risk-case", "dossier.defense_review", JSON.stringify({
        case_version: 1, revision: 0, verdict: "approve" }));
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].response.state,
      "inconclusive", "review approval alone does not apply the repair");
    item.events.prepare(`INSERT INTO incident_case_entries
      (id,incident_id,kind,payload_json) VALUES (?,?,?,?)`)
      .run(5, "risk-case", "defense.mitigation_decision", JSON.stringify({
        case_version: 1, revision: 0,
        applied: true, action: "release_false_pix_hold", hold_id: "hold-1",
        transfer_id: "transfer-1", ledger_tx_id: "tx-1",
        repair_status: "verified_transfer" }));
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].watch.state,
      "pending", "repair without later healthy traffic is not a full pass");
    for (const [seq, ts] of [[3, "2026-11-18T10:02:05.000Z"],
      [4, "2026-11-18T10:02:19.000Z"]]) {
      item.events.prepare(`INSERT INTO events (seq,type,public_json,ts,twin_ts)
        VALUES (?,'sim.tick',?,?,?)`).run(seq, JSON.stringify({ ops: 2,
          honest_blocked: 0, by_area: { pix: 1 } }), ts, ts);
    }
    const result = item.evaluator.evaluate("run-1");
    assert.equal(result.verdict, "passed");
    assert.deepEqual(result.fixtures[0].detection.evidence_refs,
      ["sentinel_alerts:risk-alert", "events:2"]);
    assert.equal(result.fixtures[0].response.state, "verified");
    assert.equal(result.fixtures[0].customer_repair.state, "verified");
    assert.equal(result.fixtures[0].reconciliation.state, "verified");
    assert.equal(result.fixtures[0].watch.state, "verified");
    const receiptTime = item.events.prepare(`UPDATE incident_case_entries SET created_at=?
      WHERE id=5 AND kind='defense.mitigation_decision'`);
    receiptTime.run("2026-11-18T10:02:12.000Z");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].watch.reason,
      "watch_window_open", "traffic before the verified repair cannot finish the watch");
    receiptTime.run("2026-11-18T10:01:00.000Z");
    item.events.prepare(`INSERT INTO events (seq,type,public_json,ts,twin_ts)
      VALUES (5,'sentinel.alert',?,?,NULL)`).run(JSON.stringify({
      alert_id: "risk-alert", rule_id: "S-PIX-41",
      pattern_label: "TRIAGE_SLA_EXCEEDED" }),
    "2026-11-18T10:02:15.000Z");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].watch.state,
      "verified", "a triage reminder is not a new Sentinel observation");
    item.events.prepare("DELETE FROM events WHERE seq=5").run();
    emit(item.events, 5, "risk-alert", "S-PIX-41", "hold-1",
      { hold_id: "hold-1", policy_outcome: "approve",
        recorded_score: 90, policy_score: 10 }, "2026-11-18T10:02:15.000Z");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].watch.reason,
      "watch_recurrence_observed");
    item.events.prepare("DELETE FROM events WHERE seq=5").run();
    item.events.prepare("DELETE FROM event_private WHERE seq=5").run();
    item.events.prepare(`INSERT INTO events (seq,type,public_json,ts,twin_ts)
      VALUES (6,'sim.tick',?,?,?)`).run(JSON.stringify({ ops: 1,
        honest_blocked: 1, by_area: { pix: 1 } }),
      "2026-11-18T10:02:16.000Z", "2026-11-18T10:02:16.000Z");
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].watch.reason,
      "watch_honest_traffic_unhealthy");
    item.events.prepare("DELETE FROM events WHERE seq=6").run();
    for (const status of ["stopped", "failed", "cleanup_failed"]) {
      item.run.status = status;
      assert.equal(item.evaluator.evaluate("run-1").verdict, "inconclusive",
        `${status} cannot pass even when all evidence stages are complete`);
    }
    item.run.status = "expired";
    item.bank.prepare(`UPDATE sentinel_alerts SET first_seen=?,last_seen=?
      WHERE id='risk-alert'`).run("2026-11-18T09:00:00.000Z", begin);
    assert.equal(item.evaluator.evaluate("run-1").fixtures[0].detection.state,
      "inconclusive", "a preexisting hold alert cannot be attributed by last_seen");
  } finally { item.close(); }
});
