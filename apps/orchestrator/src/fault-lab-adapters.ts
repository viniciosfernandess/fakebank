import { randomBytes, randomInt } from "node:crypto";
import type { CampaignRuntime } from "./campaign-runtime.ts";
import { availabilityFaultAdapter, type FaultAdapter, type FaultId,
  type FaultObservation } from "./fault-lab.ts";
import { evaluateRiskRules, loadRules } from "../../world/src/risk/engine.ts";
import { brtHour, syntheticCpf } from "../../world/src/bank.ts";
import { newId, seedAccountId, seedCustomerId } from "../../world/src/id.ts";
import { pixEndToEndId } from "../../world/src/pix-id.ts";
import { encodeResponseFieldEvidence } from "../../world/src/response-field-evidence.ts";
import { withTrace } from "../../world/src/telemetry.ts";

const actor = (runId: string): string =>
  `fault_lab_${runId.replaceAll("-", "_")}`;
const missing = (): FaultObservation => ({ observed: false, evidence_refs: [] });
const found = (reference: string): FaultObservation =>
  ({ observed: true, evidence_refs: [reference] });

/**
 * The adapters change only allowlisted local simulation seams. They never emit
 * a fault-lab alert into ordinary bank telemetry or tell a defense agent the
 * fixture ID. A symptom is observed from a bank/Sentinel record, not from a
 * successful adapter start.
 */
export function createFaultLabAdapters(runtime: CampaignRuntime):
  Partial<Record<FaultId, FaultAdapter>> {
  const bank = runtime.bank;
  const medCompletionDelay = (stage: "settlement" | "release"): FaultAdapter => {
    const outbox = stage === "settlement" ? "med_psp_settlement_outbox" : "med_psp_release_outbox";
    const decision = stage === "settlement" ? "approved" : "rejected";
    return {
      start() { /* The original authenticated decision must create the command. */ },
      stop() { /* The dispatch hook releases ownership on stop or expiry. */ },
      observe({ runId }) {
        const row = bank.db.prepare(`SELECT o.case_id FROM ${outbox} o
          JOIN med_cases m ON m.id=o.case_id AND m.transfer_id=o.transfer_id
          JOIN med_decisions d ON d.case_id=m.id AND d.decision=?
          JOIN pix_transfers p ON p.id=o.transfer_id
          WHERE p.idempotency_key=? AND o.acknowledged_at IS NULL
            AND d.maker_id<>d.checker_id AND m.refunded_cents=0
            AND EXISTS (SELECT 1 FROM med_hops h
              WHERE h.case_id=m.id AND h.released_at IS NULL AND h.blocked_cents>0)`)
          .get(decision, `sim:${runId}:med_${stage}_delayed:0`) as { case_id: string } | undefined;
        return row ? found(`${outbox}:${row.case_id}`) : missing();
      },
    };
  };
  const eligibleAutomaticCharge = () => {
    const now = bank.now();
    const speed = runtime.clock.speed;
    if (brtHour(now) >= 8 || brtHour(new Date(now.getTime() + 150_000 * speed)) >= 8)
      return undefined;
    const hasReceipts = bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE
      type='table' AND name='lab_automatic_pix_delay'`).get();
    return bank.db.prepare(`SELECT c.id FROM pix_automatic_charges c
      JOIN pix_automatic_mandates m ON m.id=c.mandate_id
      WHERE c.status='pending' AND c.next_attempt_at IS NULL AND m.status='active'
        AND c.due_at>=? AND c.due_at<=?
        ${hasReceipts ? "AND NOT EXISTS (SELECT 1 FROM lab_automatic_pix_delay d WHERE d.charge_id=c.id)" : ""}
      ORDER BY c.due_at,c.id LIMIT 1`)
      .get(now.toISOString(), new Date(now.getTime() + 20_000 * speed).toISOString()) as
      { id: string } | undefined;
  };
  // Keep cleanup for already persisted attempts during an upgrade.
  const retiredProbe = (id: "W02" | "W17"): FaultAdapter => {
    const stop: FaultAdapter["stop"] = ({ runId }) => {
      bank.transaction(() => {
        if (id === "W02" && bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_revoked_device_receipts'`).get()) {
          bank.db.prepare(`UPDATE auth_sessions SET revoked_at=?
            WHERE device_id IN (SELECT device_id FROM lab_revoked_device_receipts
              WHERE run_id=?) AND revoked_at IS NULL`)
            .run(bank.now().toISOString(), runId);
        }
        const state = bank.db.prepare(`SELECT open,changed_by FROM weakness_state
          WHERE id=?`).get(id) as { open: number; changed_by: string } | undefined;
        if (state?.open && state.changed_by === actor(runId))
          bank.setWeaknessOpen(id, false, actor(runId));
      });
    };
    const unavailable = () => { throw new Error("FAULT_LAB_FIXTURE_UNAVAILABLE"); };
    return {
      available: () => false,
      start: unavailable,
      resume(scope) {
        stop(scope);
        unavailable();
      },
      stop,
      observe: missing,
    };
  };
  const newReplayCustomer = (name: string) => {
    const id = newId("cus", bank.now().getTime());
    const cpf = syntheticCpf(randomInt(50_000_000, 100_000_000));
    bank.addCustomer({ id, cpf, name, persona: "student", kyc_tier: 1,
      kyc_status: "approved", risk_score: 5, is_attacker_owned: false, status: "active" });
    return { id, cpf };
  };
  const legacyFraud = retiredProbe("W17");
  const fraudReplayFor = (runId: string) => bank.db.prepare(`SELECT 1 FROM sqlite_master
    WHERE type='table' AND name='lab_pix_history_replays'`).get() ?
    bank.db.prepare(`SELECT r.account_id,r.transfer_id
      FROM lab_pix_history_replays p JOIN lab_risk_miss_receipts r
        ON r.run_id=p.run_id AND r.account_id=p.account_id
      WHERE p.run_id=?`).get(runId) as { account_id: string; transfer_id: string } |
        undefined : undefined;
  const legacyIdentity = retiredProbe("W02");
  const replayFor = (runId: string) => bank.db.prepare(`SELECT 1 FROM sqlite_master
    WHERE type='table' AND name='lab_identity_replays'`).get() ?
    bank.db.prepare(`SELECT r.customer_id,r.device_id,r.telemetry_event_id
      FROM lab_identity_replays p JOIN lab_revoked_device_receipts r
        ON r.run_id=p.run_id AND r.telemetry_event_id=p.telemetry_event_id
      WHERE p.run_id=?`).get(runId) as { customer_id: string; device_id: string;
        telemetry_event_id: number } | undefined : undefined;
  return {
    automatic_pix_execution_delayed: {
      available: () => Boolean(eligibleAutomaticCharge()),
      start({ runId }) {
        bank.db.exec(`CREATE TABLE IF NOT EXISTS lab_automatic_pix_delay (
          run_id TEXT PRIMARY KEY, charge_id TEXT NOT NULL UNIQUE)`);
        if (bank.db.prepare("SELECT 1 FROM lab_automatic_pix_delay WHERE run_id=?").get(runId))
          return;
        const charge = eligibleAutomaticCharge();
        if (!charge) throw new Error("FAULT_LAB_AUTOMATIC_CHARGE_UNAVAILABLE");
        bank.db.prepare("INSERT INTO lab_automatic_pix_delay VALUES (?,?)").run(runId, charge.id);
      },
      stop() { /* Execution resumes when this run becomes inactive. */ },
      observe({ runId }) {
        const row = bank.db.prepare(`SELECT c.id FROM lab_automatic_pix_delay d
          JOIN pix_automatic_charges c ON c.id=d.charge_id
          WHERE d.run_id=? AND c.status='pending' AND c.due_at<=?`)
          .get(runId, bank.now().toISOString()) as { id: string } | undefined;
        return row ? found(`pix_automatic_charges:${row.id}`) : missing();
      },
    },
    risk_missed_hold: {
      available: () => runtime.faultLab && !bank.isWeaknessOpen("W17"),
      start({ runId }) {
        if (!runtime.faultLab || bank.isWeaknessOpen("W17"))
          throw new Error("FAULT_LAB_PIX_HISTORY_UNAVAILABLE");
        bank.transaction(() => {
          if (fraudReplayFor(runId)) return;
          bank.db.exec(`CREATE TABLE IF NOT EXISTS lab_risk_miss_receipts (
            run_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
            account_id TEXT NOT NULL, transfer_id TEXT NOT NULL,
            recipient_account_id TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS lab_pix_history_replays (
            run_id TEXT PRIMARY KEY, account_id TEXT NOT NULL UNIQUE
          );`);
          if (bank.db.prepare("SELECT 1 FROM lab_risk_miss_receipts WHERE run_id=?")
            .get(runId)) throw new Error("FAULT_LAB_PIX_LEGACY_RECEIPT");
          const at = bank.now();
          const timestamp = at.toISOString();
          const postingActor = "synthetic_pix_history";
          const newAccount = (owner: string) => {
            const id = newId("acc", at.getTime());
            bank.addAccount({ id, customer_id: owner, kind: "checking",
              system_role: null, overdraft_limit: 0, status: "active" });
            return id;
          };
          const recordHistoricalPayment = (from: string, to: string,
            amount: number, key: string) => {
            const id = newId("pix", at.getTime());
            const ledger = bank.post([
              { accountId: from, amount: -amount, kind: "pix", actor: postingActor,
                refType: "pix", refId: id },
              { accountId: to, amount, kind: "pix", actor: postingActor,
                refType: "pix", refId: id },
            ]);
            bank.db.prepare(`INSERT INTO pix_transfers (id,idempotency_key,from_account,
              to_account,amount,status,initiated_at,settled_at,ledger_tx_id,
              night_mode,actor,end_to_end_id)
              VALUES (?,?,?,?,?,'settled',?,?,?,0,?,?)`).run(id, key, from, to,
                amount, timestamp, timestamp, ledger, postingActor, pixEndToEndId(id, at));
            const history = bank.db.prepare(`INSERT INTO pix_status_history
              (transfer_id,status,changed_at) VALUES (?,?,?)`);
            history.run(id, "created", timestamp);
            history.run(id, "settled", timestamp);
            return id;
          };
          // Import a closed set of fictional historical postings. All accounts
          // belong to this run and the live payment policy stays enabled.
          const customer = newReplayCustomer("Synthetic Pix Payer");
          const account = newAccount(customer.id);
          const recipient = newAccount(newReplayCustomer("Synthetic Pix Recipient").id);
          for (let index = 0; index < 6; index += 1) {
            const sender = newAccount(newReplayCustomer("Synthetic Pix Sender").id);
            bank.fund(sender, 1_000);
            recordHistoricalPayment(sender, account, 1_000, `lab:${runId}:history:${index}`);
          }
          const payment = recordHistoricalPayment(account, recipient, 4_800,
            `lab:${runId}:missed_hold`);
          bank.db.prepare("INSERT INTO lab_risk_miss_receipts VALUES (?,?,?,?,?)")
            .run(runId, customer.id, account, payment, recipient);
          bank.db.prepare("INSERT INTO lab_pix_history_replays VALUES (?,?)")
            .run(runId, account);
        });
      },
      resume(scope) {
        if (!fraudReplayFor(scope.runId)) return legacyFraud.resume?.(scope);
      },
      stop: legacyFraud.stop,
      observe({ runId, startedAt }) {
        const replay = fraudReplayFor(runId);
        if (!replay) return missing();
        const alert = bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-PIX-02' AND entity=? AND first_seen>=?
          ORDER BY first_seen LIMIT 1`).get(replay.account_id, startedAt) as
          { id: string } | undefined;
        if (!alert) return missing();
        return { observed: true, evidence_refs: [`sentinel_alerts:${alert.id}`,
          `pix_transfers:${replay.transfer_id}`] };
      },
    },
    revoked_device_access: {
      available: () => runtime.faultLab && !bank.isWeaknessOpen("W02"),
      start({ runId, startedAt }) {
        if (!runtime.faultLab || bank.isWeaknessOpen("W02"))
          throw new Error("FAULT_LAB_IDENTITY_REPLAY_UNAVAILABLE");
        bank.transaction(() => {
          if (replayFor(runId)) return;
          bank.db.exec(`CREATE TABLE IF NOT EXISTS lab_revoked_device_receipts (
            run_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
            device_id TEXT NOT NULL, telemetry_event_id INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS lab_identity_replays (
            run_id TEXT PRIMARY KEY, telemetry_event_id INTEGER NOT NULL UNIQUE
          );`);
          if (bank.db.prepare(`SELECT 1 FROM lab_revoked_device_receipts
            WHERE run_id=?`).get(runId))
            throw new Error("FAULT_LAB_IDENTITY_LEGACY_RECEIPT");
          // A dedicated synthetic customer starts without an account or funds.
          const { id: customerId, cpf } = newReplayCustomer("Synthetic Identity Replay");
          const fingerprint = `identity-replay-${runId}`;
          const secret = randomBytes(32).toString("base64url");
          const auth = runtime.auth;
          auth.setPassword(customerId, secret);
          const challenge = auth.beginLogin(cpf, secret, "127.0.0.1", fingerprint);
          const session = auth.verifyOtp(challenge.challenge_id,
            auth.simulatedOtp(challenge.challenge_id, customerId), "127.0.0.1");
          const identity = auth.traceIdentityForAccess(session.access_token);
          auth.revokeDevice(customerId, fingerprint);
          if (!identity || identity.userId !== customerId ||
            auth.customerForAccess(session.access_token) !== undefined)
            throw new Error("FAULT_LAB_IDENTITY_REVOCATION_UNVERIFIED");
          const route = "/api/v1/accounts";
          const fields = encodeResponseFieldEvidence("GET", route, 200, []);
          if (fields !== "none") throw new Error("FAULT_LAB_IDENTITY_RESPONSE_UNSUPPORTED");
          const trace = withTrace(`identity-replay-${runId}`, () => {
            const replay = bank.telemetry.emit({ source: "auth", category: "audit",
              action: "access_revoked_device", outcome: "success",
              message: "Synthetic historical identity replay" });
            bank.telemetry.emit({ source: "gateway", category: "request",
              action: "request", outcome: "success",
              message: `Gateway GET ${route} completed fields=${fields}` });
            return replay;
          }, { userId: customerId, deviceId: identity.deviceId, sessionId: identity.sessionId });
          const event = bank.telemetry.trace(trace).find((entry) =>
            entry.user_id === customerId && entry.device_id === identity.deviceId &&
            entry.action === "access_revoked_device" && entry.ts >= startedAt);
          if (!event) throw new Error("FAULT_LAB_IDENTITY_REPLAY_EVIDENCE_MISSING");
          bank.db.prepare("INSERT INTO lab_revoked_device_receipts VALUES (?,?,?,?)")
            .run(runId, customerId, identity.deviceId, event.id);
          bank.db.prepare("INSERT INTO lab_identity_replays VALUES (?,?)")
            .run(runId, event.id);
        });
      },
      resume(scope) {
        if (!replayFor(scope.runId)) return legacyIdentity.resume?.(scope);
      },
      stop: legacyIdentity.stop,
      observe({ runId }) {
        const replay = replayFor(runId);
        if (!replay) return missing();
        const alert = bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-AUTH-08' AND entity=?
            AND json_extract(observed_json,'$.source_event_id')=?
            AND json_extract(observed_json,'$.device_id')=?`).get(
              replay.customer_id, replay.telemetry_event_id, replay.device_id) as
          { id: string } | undefined;
        return alert ? found(`sentinel_alerts:${alert.id}`) : missing();
      },
    },
    risk_false_hold: {
      start() { /* The signed simulator probe arms one risk decision. */ },
      stop() { /* The probe clears its scoped risk hook in finally. */ },
      observe({ runId }) {
        const row = bank.db.prepare(`SELECT h.id,d.features_json,d.outcome,
            d.score,l.label
          FROM risk_pix_holds h
          JOIN risk_decisions d ON d.id=h.risk_decision_id
          JOIN sim_risk_labels l ON l.decision_id=d.id
          WHERE h.idempotency_key=? AND h.status='pending'
            AND l.label='honest' AND l.source='customer_simulator_v1'
          LIMIT 1`).get(`sim:${runId}:0`) as { id: string; features_json: string;
          outcome: string; score: number; label: string } | undefined;
        if (!row || row.outcome !== "hold") return missing();
        const baseline = evaluateRiskRules(loadRules("pix"),
          JSON.parse(row.features_json) as Record<string, number>);
        return baseline.outcome === "approve" && baseline.score < row.score ?
          found(`risk_pix_holds:${row.id}`) : missing();
      },
    },
    ...(runtime.faultLab && runtime.clock.speed >= 40 ? {
      hourly_proof_paused: {
        start() { /* CampaignRuntime's proof publisher reads FaultLab.active(). */ },
        stop() { /* The next campaign cycle resumes proof publication. */ },
        observe({ startedAt }: { startedAt: string }) {
          if (runtime.clock.speed < 40) return missing();
          const row = bank.db.prepare(`SELECT id FROM sentinel_alerts
            WHERE rule_id='S-LED-11' AND entity='ledger_hourly_proof'
              AND first_seen>=? ORDER BY first_seen LIMIT 1`).get(startedAt) as
            { id: string } | undefined;
          return row ? found(`sentinel_alerts:${row.id}`) : missing();
        },
      } satisfies FaultAdapter,
    } : {}),
    auth_event_silence: {
      start() { /* CampaignRuntime's heartbeat hook reads FaultLab.active(). */ },
      stop() { /* Heartbeats resume when the run becomes inactive. */ },
      observe({ startedAt }) {
        const row = bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-AUTH-07' AND entity='auth'
          AND last_seen>=? LIMIT 1`).get(startedAt) as
          { id: string } | undefined;
        return row ? found(`sentinel_alerts:${row.id}`) : missing();
      },
    },
    gateway_heartbeat_silence: {
      start() { /* The gateway heartbeat producer reads FaultLab.active(). */ },
      stop() { /* The next heartbeat resumes when the run becomes inactive. */ },
      observe({ startedAt }) {
        const row = bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-GW-07' AND entity='gateway'
            AND last_seen>=? ORDER BY last_seen DESC LIMIT 1`).get(startedAt) as
          { id: string } | undefined;
        return row ? found(`sentinel_alerts:${row.id}`) : missing();
      },
    },
    statement_unavailable: {
      available() {
        return Boolean(bank.db.prepare(`SELECT 1 FROM accounts WHERE id=?
          AND customer_id=? AND status='active'`).get(
            seedAccountId(8), seedCustomerId(8)));
      },
      resume({ runId }) {
        const receipt = bank.db.prepare(`SELECT customer_id,account_id
          FROM lab_statement_outage_receipts WHERE run_id=?`).get(runId) as
          { customer_id: string; account_id: string } | undefined;
        if (receipt) runtime.armLabStatementOutage(runId,
          receipt.customer_id, receipt.account_id);
      },
      async start({ runId }) {
        bank.db.exec(`CREATE TABLE IF NOT EXISTS lab_statement_outage_receipts (
          run_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
          account_id TEXT NOT NULL, failed_log_id TEXT NOT NULL,
          recovered_log_id TEXT
        )`);
        if (bank.db.prepare(`SELECT 1 FROM lab_statement_outage_receipts
          WHERE run_id=?`).get(runId)) return;
        const customerId = seedCustomerId(8);
        const accountId = seedAccountId(8);
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        runtime.armLabStatementOutage(runId, customerId, accountId);
        const result = await runtime.simulator.probeOwnStatement(customerId,
          accountId);
        if (result.status !== 503)
          throw new Error("FAULT_LAB_STATEMENT_OUTAGE_NOT_OBSERVED");
        const failed = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='statement_own' AND status=503
            AND customer_id=? AND account_id=?
          ORDER BY rowid LIMIT 1`).get(before.n,
            customerId, accountId) as { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='statement_own'
            AND user_id=? AND account_id=? AND outcome='failure' LIMIT 1`)
          .get(result.requestId, customerId, accountId);
        if (!failed || !trace) throw new Error("FAULT_LAB_STATEMENT_LOG_MISSING");
        bank.db.prepare(`INSERT INTO lab_statement_outage_receipts
          (run_id,customer_id,account_id,failed_log_id) VALUES (?,?,?,?)`)
          .run(runId, customerId, accountId, failed.id);
      },
      async stop({ runId }) {
        runtime.stopLabStatementOutage(runId);
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_statement_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          account_id,recovered_log_id FROM lab_statement_outage_receipts
          WHERE run_id=?`).get(runId) as { customer_id: string;
            account_id: string; recovered_log_id: string | null } | undefined :
          undefined;
        if (!receipt || receipt.recovered_log_id) return;
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        const result = await runtime.simulator.probeOwnStatement(
          receipt.customer_id, receipt.account_id);
        if (result.status !== 200)
          throw new Error("FAULT_LAB_STATEMENT_RECOVERY_NOT_OBSERVED");
        const recovered = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='statement_own' AND status=200
            AND customer_id=? AND account_id=?
          ORDER BY rowid LIMIT 1`).get(before.n,
            receipt.customer_id, receipt.account_id) as
            { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='statement_own'
            AND user_id=? AND account_id=? AND outcome='success' LIMIT 1`)
          .get(result.requestId, receipt.customer_id, receipt.account_id);
        if (!recovered || !trace)
          throw new Error("FAULT_LAB_STATEMENT_RECOVERY_LOG_MISSING");
        bank.db.prepare(`UPDATE lab_statement_outage_receipts
          SET recovered_log_id=? WHERE run_id=? AND recovered_log_id IS NULL`)
          .run(recovered.id, runId);
      },
      observe({ runId }) {
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_statement_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          account_id,failed_log_id FROM lab_statement_outage_receipts
          WHERE run_id=?`).get(runId) as { customer_id: string;
            account_id: string; failed_log_id: string } | undefined : undefined;
        if (!receipt) return missing();
        const alert = bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-ACC-04' AND entity=?
            AND json_extract(observed_json,'$.failed_log_id')=?
            AND json_extract(observed_json,'$.account_id')=?
          LIMIT 1`).get(receipt.customer_id,
            receipt.failed_log_id, receipt.account_id) as
            { id: string } | undefined;
        return alert ? { observed: true, evidence_refs: [
          `sentinel_alerts:${alert.id}`,
          `access_log:${receipt.failed_log_id}`] } : missing();
      },
    },
    loan_offer_unavailable: {
      available() {
        return Boolean(bank.db.prepare(`SELECT 1 FROM customers WHERE id=?
          AND status='active'`).get(seedCustomerId(8)));
      },
      resume({ runId }) {
        const receipt = bank.db.prepare(`SELECT customer_id
          FROM lab_loan_offer_outage_receipts WHERE run_id=?`).get(runId) as
          { customer_id: string } | undefined;
        if (receipt) runtime.armLabLoanOfferOutage(runId, receipt.customer_id);
      },
      async start({ runId }) {
        bank.db.exec(`CREATE TABLE IF NOT EXISTS lab_loan_offer_outage_receipts (
          run_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
          failed_log_id TEXT NOT NULL, recovered_log_id TEXT
        )`);
        if (bank.db.prepare(`SELECT 1 FROM lab_loan_offer_outage_receipts
          WHERE run_id=?`).get(runId)) return;
        const customerId = seedCustomerId(8);
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        runtime.armLabLoanOfferOutage(runId, customerId);
        const result = await runtime.simulator.probeOwnLoanOffer(customerId);
        if (result.status !== 503)
          throw new Error("FAULT_LAB_LOAN_OFFER_OUTAGE_NOT_OBSERVED");
        const failed = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='loan_offer_own' AND status=503
            AND customer_id=? ORDER BY rowid LIMIT 1`).get(before.n,
              customerId) as { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='loan_offer_own'
            AND user_id=? AND outcome='failure' LIMIT 1`)
          .get(result.requestId, customerId);
        if (!failed || !trace)
          throw new Error("FAULT_LAB_LOAN_OFFER_LOG_MISSING");
        bank.db.prepare(`INSERT INTO lab_loan_offer_outage_receipts
          (run_id,customer_id,failed_log_id) VALUES (?,?,?)`)
          .run(runId, customerId, failed.id);
      },
      async stop({ runId }) {
        runtime.stopLabLoanOfferOutage(runId);
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_loan_offer_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          recovered_log_id FROM lab_loan_offer_outage_receipts WHERE run_id=?`)
          .get(runId) as { customer_id: string;
            recovered_log_id: string | null } | undefined : undefined;
        if (!receipt || receipt.recovered_log_id) return;
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        const result = await runtime.simulator.probeOwnLoanOffer(receipt.customer_id);
        if (result.status !== 200)
          throw new Error("FAULT_LAB_LOAN_OFFER_RECOVERY_NOT_OBSERVED");
        const recovered = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='loan_offer_own' AND status=200
            AND customer_id=? ORDER BY rowid LIMIT 1`).get(before.n,
              receipt.customer_id) as { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='loan_offer_own'
            AND user_id=? AND outcome='success' LIMIT 1`)
          .get(result.requestId, receipt.customer_id);
        if (!recovered || !trace)
          throw new Error("FAULT_LAB_LOAN_OFFER_RECOVERY_LOG_MISSING");
        bank.db.prepare(`UPDATE lab_loan_offer_outage_receipts
          SET recovered_log_id=? WHERE run_id=? AND recovered_log_id IS NULL`)
          .run(recovered.id, runId);
      },
      observe({ runId }) {
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_loan_offer_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          failed_log_id FROM lab_loan_offer_outage_receipts WHERE run_id=?`)
          .get(runId) as { customer_id: string;
            failed_log_id: string } | undefined : undefined;
        if (!receipt) return missing();
        const alert = bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-LOAN-04' AND entity=?
            AND json_extract(observed_json,'$.failed_log_id')=? LIMIT 1`)
          .get(receipt.customer_id, receipt.failed_log_id) as
          { id: string } | undefined;
        return alert ? { observed: true, evidence_refs: [
          `sentinel_alerts:${alert.id}`,
          `access_log:${receipt.failed_log_id}`] } : missing();
      },
    },
    pix_automatic_mandates_unavailable: {
      available() {
        return Boolean(bank.db.prepare(`SELECT 1 FROM customers WHERE id=?
          AND status='active'`).get(seedCustomerId(9)));
      },
      resume({ runId }) {
        const receipt = bank.db.prepare(`SELECT customer_id
          FROM lab_pix_automatic_mandates_outage_receipts WHERE run_id=?`).get(runId) as
          { customer_id: string } | undefined;
        if (receipt) runtime.armLabPixAutomaticMandatesOutage(runId, receipt.customer_id);
      },
      async start({ runId }) {
        bank.db.exec(`CREATE TABLE IF NOT EXISTS lab_pix_automatic_mandates_outage_receipts (
          run_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
          failed_log_id TEXT NOT NULL, recovered_log_id TEXT
        )`);
        if (bank.db.prepare(`SELECT 1 FROM lab_pix_automatic_mandates_outage_receipts
          WHERE run_id=?`).get(runId)) return;
        const customerId = seedCustomerId(9);
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        runtime.armLabPixAutomaticMandatesOutage(runId, customerId);
        const result = await runtime.simulator.probeOwnPixAutomaticMandates(customerId);
        if (result.status !== 503)
          throw new Error("FAULT_LAB_PIX_AUTOMATIC_MANDATES_OUTAGE_NOT_OBSERVED");
        const failed = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='pix_automatic_mandates_own' AND status=503
            AND customer_id=? ORDER BY rowid LIMIT 1`).get(before.n,
              customerId) as { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='pix_automatic_mandates_own'
            AND user_id=? AND outcome='failure' LIMIT 1`)
          .get(result.requestId, customerId);
        if (!failed || !trace)
          throw new Error("FAULT_LAB_PIX_AUTOMATIC_MANDATES_LOG_MISSING");
        bank.db.prepare(`INSERT INTO lab_pix_automatic_mandates_outage_receipts
          (run_id,customer_id,failed_log_id) VALUES (?,?,?)`)
          .run(runId, customerId, failed.id);
      },
      async stop({ runId }) {
        runtime.stopLabPixAutomaticMandatesOutage(runId);
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_pix_automatic_mandates_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          recovered_log_id FROM lab_pix_automatic_mandates_outage_receipts WHERE run_id=?`)
          .get(runId) as { customer_id: string;
            recovered_log_id: string | null } | undefined : undefined;
        if (!receipt || receipt.recovered_log_id) return;
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        const result = await runtime.simulator.probeOwnPixAutomaticMandates(receipt.customer_id);
        if (result.status !== 200)
          throw new Error("FAULT_LAB_PIX_AUTOMATIC_MANDATES_RECOVERY_NOT_OBSERVED");
        const recovered = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='pix_automatic_mandates_own' AND status=200
            AND customer_id=? ORDER BY rowid LIMIT 1`).get(before.n,
              receipt.customer_id) as { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='pix_automatic_mandates_own'
            AND user_id=? AND outcome='success' LIMIT 1`)
          .get(result.requestId, receipt.customer_id);
        if (!recovered || !trace)
          throw new Error("FAULT_LAB_PIX_AUTOMATIC_MANDATES_RECOVERY_LOG_MISSING");
        bank.db.prepare(`UPDATE lab_pix_automatic_mandates_outage_receipts
          SET recovered_log_id=? WHERE run_id=? AND recovered_log_id IS NULL`)
          .run(recovered.id, runId);
      },
      observe({ runId }) {
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_pix_automatic_mandates_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          failed_log_id FROM lab_pix_automatic_mandates_outage_receipts WHERE run_id=?`)
          .get(runId) as { customer_id: string;
            failed_log_id: string } | undefined : undefined;
        if (!receipt) return missing();
        const alert = bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-PIX-42' AND entity=?
            AND json_extract(observed_json,'$.failed_log_id')=? LIMIT 1`)
          .get(receipt.customer_id, receipt.failed_log_id) as
          { id: string } | undefined;
        return alert ? { observed: true, evidence_refs: [
          `sentinel_alerts:${alert.id}`,
          `access_log:${receipt.failed_log_id}`] } : missing();
      },
    },
    kyc_status_unavailable: {
      available() {
        return Boolean(bank.db.prepare(`SELECT 1 FROM customers WHERE id=?
          AND status='active'`).get(seedCustomerId(10)));
      },
      resume({ runId }) {
        const receipt = bank.db.prepare(`SELECT customer_id
          FROM lab_kyc_status_outage_receipts WHERE run_id=?`).get(runId) as
          { customer_id: string } | undefined;
        if (receipt) runtime.armLabKycStatusOutage(runId, receipt.customer_id);
      },
      async start({ runId }) {
        bank.db.exec(`CREATE TABLE IF NOT EXISTS lab_kyc_status_outage_receipts (
          run_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
          failed_log_id TEXT NOT NULL, recovered_log_id TEXT
        )`);
        if (bank.db.prepare(`SELECT 1 FROM lab_kyc_status_outage_receipts
          WHERE run_id=?`).get(runId)) return;
        const customerId = seedCustomerId(10);
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        runtime.armLabKycStatusOutage(runId, customerId);
        const result = await runtime.simulator.probeOwnKycStatus(customerId);
        if (result.status !== 503)
          throw new Error("FAULT_LAB_KYC_STATUS_OUTAGE_NOT_OBSERVED");
        const failed = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='kyc_status_own' AND status=503
            AND customer_id=? ORDER BY rowid LIMIT 1`).get(before.n,
              customerId) as { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='kyc_status_own'
            AND user_id=? AND outcome='failure' LIMIT 1`)
          .get(result.requestId, customerId);
        if (!failed || !trace)
          throw new Error("FAULT_LAB_KYC_STATUS_LOG_MISSING");
        bank.db.prepare(`INSERT INTO lab_kyc_status_outage_receipts
          (run_id,customer_id,failed_log_id) VALUES (?,?,?)`)
          .run(runId, customerId, failed.id);
      },
      async stop({ runId }) {
        runtime.stopLabKycStatusOutage(runId);
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_kyc_status_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          recovered_log_id FROM lab_kyc_status_outage_receipts WHERE run_id=?`)
          .get(runId) as { customer_id: string;
            recovered_log_id: string | null } | undefined : undefined;
        if (!receipt || receipt.recovered_log_id) return;
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        const result = await runtime.simulator.probeOwnKycStatus(receipt.customer_id);
        if (result.status !== 200)
          throw new Error("FAULT_LAB_KYC_STATUS_RECOVERY_NOT_OBSERVED");
        const recovered = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='kyc_status_own' AND status=200
            AND customer_id=? ORDER BY rowid LIMIT 1`).get(before.n,
              receipt.customer_id) as { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='kyc_status_own'
            AND user_id=? AND outcome='success' LIMIT 1`)
          .get(result.requestId, receipt.customer_id);
        if (!recovered || !trace)
          throw new Error("FAULT_LAB_KYC_STATUS_RECOVERY_LOG_MISSING");
        bank.db.prepare(`UPDATE lab_kyc_status_outage_receipts
          SET recovered_log_id=? WHERE run_id=? AND recovered_log_id IS NULL`)
          .run(recovered.id, runId);
      },
      observe({ runId }) {
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_kyc_status_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          failed_log_id FROM lab_kyc_status_outage_receipts WHERE run_id=?`)
          .get(runId) as { customer_id: string;
            failed_log_id: string } | undefined : undefined;
        if (!receipt) return missing();
        const alert = bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-AUTH-14' AND entity=?
            AND json_extract(observed_json,'$.failed_log_id')=? LIMIT 1`)
          .get(receipt.customer_id, receipt.failed_log_id) as
          { id: string } | undefined;
        return alert ? { observed: true, evidence_refs: [
          `sentinel_alerts:${alert.id}`,
          `access_log:${receipt.failed_log_id}`] } : missing();
      },
    },
    kyc_submission_unavailable: {
      available() {
        return Boolean(bank.db.prepare(`SELECT 1 FROM customers WHERE id=?
          AND status='active' AND kyc_tier<3 AND NOT EXISTS (
            SELECT 1 FROM kyc_requests WHERE customer_id=customers.id AND status='submitted')
          AND NOT EXISTS (SELECT 1 FROM onboarding_applications WHERE customer_id=customers.id AND status<>'approved')`).get(seedCustomerId(11)));
      },
      resume({ runId }) {
        const receipt = bank.db.prepare(`SELECT customer_id
          FROM lab_kyc_submission_outage_receipts WHERE run_id=?`).get(runId) as
          { customer_id: string } | undefined;
        if (receipt) runtime.armLabKycSubmissionOutage(runId, receipt.customer_id);
      },
      async start({ runId }) {
        bank.db.exec(`CREATE TABLE IF NOT EXISTS lab_kyc_submission_outage_receipts (
          run_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL,
          failed_log_id TEXT NOT NULL, recovered_log_id TEXT, submitted_history_id INTEGER
        )`);
        if (bank.db.prepare(`SELECT 1 FROM lab_kyc_submission_outage_receipts
          WHERE run_id=?`).get(runId)) return;
        const customerId = seedCustomerId(11);
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        runtime.armLabKycSubmissionOutage(runId, customerId);
        const result = await runtime.simulator.probeOwnKycSubmission(customerId);
        if (result.status !== 503)
          throw new Error("FAULT_LAB_KYC_SUBMISSION_OUTAGE_NOT_OBSERVED");
        const failed = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='kyc_submission_own' AND status=503
            AND customer_id=? ORDER BY rowid LIMIT 1`).get(before.n,
              customerId) as { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='kyc_submission_own'
            AND user_id=? AND outcome='failure' LIMIT 1`)
          .get(result.requestId, customerId);
        if (!failed || !trace)
          throw new Error("FAULT_LAB_KYC_SUBMISSION_LOG_MISSING");
        bank.db.prepare(`INSERT INTO lab_kyc_submission_outage_receipts
          (run_id,customer_id,failed_log_id) VALUES (?,?,?)`)
          .run(runId, customerId, failed.id);
      },
      async stop({ runId }) {
        runtime.stopLabKycSubmissionOutage(runId);
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_kyc_submission_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          recovered_log_id FROM lab_kyc_submission_outage_receipts WHERE run_id=?`)
          .get(runId) as { customer_id: string;
            recovered_log_id: string | null } | undefined : undefined;
        if (!receipt || receipt.recovered_log_id) return;
        const before = bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
          FROM access_log`).get() as { n: number };
        const result = await runtime.simulator.probeOwnKycSubmission(receipt.customer_id);
        if (result.status !== 200)
          throw new Error("FAULT_LAB_KYC_SUBMISSION_RECOVERY_NOT_OBSERVED");
        const recovered = bank.db.prepare(`SELECT id FROM access_log
          WHERE rowid>? AND kind='kyc_submission_own' AND status=200
            AND customer_id=? ORDER BY rowid LIMIT 1`).get(before.n,
              receipt.customer_id) as { id: string } | undefined;
        const trace = bank.db.prepare(`SELECT 1 FROM telemetry_events
          WHERE trace_id=? AND source='gateway' AND action='kyc_submission_own'
            AND user_id=? AND outcome='success' LIMIT 1`)
          .get(result.requestId, receipt.customer_id);
        const submission = bank.db.prepare(`SELECT h.id FROM kyc_history h
          JOIN kyc_requests r ON r.customer_id=h.customer_id AND r.submitted_at=h.twin_at
          JOIN customers c ON c.id=h.customer_id AND c.kyc_tier=h.previous_tier
          JOIN access_log denial ON denial.id=(SELECT failed_log_id
            FROM lab_kyc_submission_outage_receipts WHERE run_id=?)
          WHERE h.customer_id=? AND h.event='submitted' AND h.requested_tier=3
            AND r.status='submitted' AND r.requested_tier=3 AND h.twin_at>=denial.ts
          ORDER BY h.id DESC LIMIT 1`).get(runId, receipt.customer_id) as
          { id: number } | undefined;
        if (!recovered || !trace || !submission)
          throw new Error("FAULT_LAB_KYC_SUBMISSION_RECOVERY_LOG_MISSING");
        bank.db.prepare(`UPDATE lab_kyc_submission_outage_receipts
          SET recovered_log_id=?,submitted_history_id=? WHERE run_id=? AND recovered_log_id IS NULL`)
          .run(recovered.id, submission.id, runId);
      },
      observe({ runId }) {
        const exists = bank.db.prepare(`SELECT 1 FROM sqlite_master
          WHERE type='table' AND name='lab_kyc_submission_outage_receipts'`).get();
        const receipt = exists ? bank.db.prepare(`SELECT customer_id,
          failed_log_id FROM lab_kyc_submission_outage_receipts WHERE run_id=?`)
          .get(runId) as { customer_id: string;
            failed_log_id: string } | undefined : undefined;
        if (!receipt) return missing();
        const alert = bank.db.prepare(`SELECT id FROM sentinel_alerts
          WHERE rule_id='S-AUTH-15' AND entity=?
            AND json_extract(observed_json,'$.failed_log_id')=? LIMIT 1`)
          .get(receipt.customer_id, receipt.failed_log_id) as
          { id: string } | undefined;
        return alert ? { observed: true, evidence_refs: [
          `sentinel_alerts:${alert.id}`,
          `access_log:${receipt.failed_log_id}`] } : missing();
      },
    },
    kyc_review_interrupted: {
      available() {
        return Boolean(bank.db.prepare(`SELECT 1 FROM customers WHERE id=?
          AND status='active' AND kyc_tier<3 AND NOT EXISTS (
            SELECT 1 FROM kyc_requests WHERE customer_id=customers.id AND status='submitted')
          AND NOT EXISTS (SELECT 1 FROM onboarding_applications
            WHERE customer_id=customers.id AND status<>'approved')`).get(seedCustomerId(12)));
      },
      async start({ runId, startedAt, expiresAt }) {
        const customerId = seedCustomerId(12);
        bank.db.exec(`CREATE TABLE IF NOT EXISTS lab_kyc_review_interruptions (
          run_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, submitted_at TEXT,
          expires_at TEXT NOT NULL, released_at TEXT
        )`);
        bank.db.prepare(`INSERT OR IGNORE INTO lab_kyc_review_interruptions
          (run_id,customer_id,expires_at) VALUES (?,?,?)`).run(runId, customerId, expiresAt);
        const existing = bank.db.prepare(`SELECT submitted_at FROM lab_kyc_review_interruptions
          WHERE run_id=?`).get(runId) as { submitted_at: string | null };
        if (existing.submitted_at) return;
        const result = await runtime.simulator.probeOwnKycSubmission(customerId);
        const request = bank.db.prepare(`SELECT r.submitted_at FROM kyc_requests r
          JOIN kyc_history h ON h.customer_id=r.customer_id AND h.twin_at=r.submitted_at
          WHERE r.customer_id=? AND r.status='submitted' AND r.requested_tier=3
            AND h.event='submitted' AND h.requested_tier=3 AND h.recorded_at>=?`)
          .get(customerId, startedAt) as { submitted_at: string } | undefined;
        if (result.status !== 200 || !request) throw new Error("FAULT_LAB_KYC_REVIEW_REQUEST_MISSING");
        bank.db.prepare(`UPDATE lab_kyc_review_interruptions SET submitted_at=?
          WHERE run_id=? AND submitted_at IS NULL`).run(request.submitted_at, runId);
      },
      stop({ runId }) {
        if (!bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
          AND name='lab_kyc_review_interruptions'`).get()) return;
        bank.db.prepare(`UPDATE lab_kyc_review_interruptions SET released_at=?
          WHERE run_id=? AND released_at IS NULL`).run(bank.realNow().toISOString(), runId);
      },
      observe({ runId }) {
        const row = bank.db.prepare(`SELECT a.id alert_id
          FROM lab_kyc_review_interruptions b JOIN access_log l
            ON l.customer_id=b.customer_id AND l.route=b.submitted_at
          JOIN sentinel_alerts a ON a.entity=b.customer_id
            AND json_extract(a.observed_json,'$.failed_log_id')=l.id
          WHERE b.run_id=? AND l.kind='kyc_review' AND l.status=503
            AND a.rule_id='S-AUTH-16'`).get(runId) as
          { alert_id: string } | undefined;
        return row ? found(`sentinel_alerts:${row.alert_id}`) : missing();
      },
    },
    fee_rounding_drift: {
      available: () => false,
      start() { throw new Error("FAULT_NOT_AVAILABLE"); },
      stop() {},
      observe: () => missing(),
    },
    pix_dispatch_paused: {
      start() { /* CampaignRuntime's dispatch hook reads FaultLab.active(). */ },
      stop() { /* Dispatch resumes when the run becomes inactive. */ },
      observe({ runId }) {
        const row = bank.db.prepare(`SELECT o.transfer_id FROM pix_spi_outbox o
          JOIN pix_transfers t ON t.id=o.transfer_id
          WHERE t.idempotency_key=? AND o.response_status IS NULL
          LIMIT 1`).get(`sim:${runId}:pix_dispatch_paused:0`) as
          { transfer_id: string } | undefined;
        return row ? found(`pix_spi_outbox:${row.transfer_id}`) : missing();
      },
    },
    ...(runtime.separatedEcosystem ? { psp_receipt_delayed: {
      start() { /* The coordinator's PSP credit hook reads FaultLab.active(). */ },
      stop() { /* PSP credit dispatch resumes when the run becomes inactive. */ },
      observe({ runId }: { runId: string }) {
        const row = bank.db.prepare(`SELECT p.transfer_id FROM pix_psp_inbound_outbox p
          JOIN pix_spi_outbox s ON s.transfer_id=p.transfer_id
          JOIN pix_transfers t ON t.id=p.transfer_id
          WHERE t.idempotency_key=? AND p.acknowledged_at IS NULL
            AND s.response_status='ACSC' LIMIT 1`)
          .get(`sim:${runId}:psp_receipt_delayed:0`) as
          { transfer_id: string } | undefined;
        return row ? found(`pix_psp_inbound_outbox:${row.transfer_id}`) : missing();
      },
    } satisfies FaultAdapter } : {}),
    ...(runtime.separatedEcosystem ? { med_opening_delayed: {
      start() { /* The dispatch hook pauses this run's opening command. */ },
      stop() { /* The same command can dispatch after expiry. */ },
      observe({ runId }) {
        const row = bank.db.prepare(`SELECT o.case_id FROM med_psp_open_outbox o
          JOIN med_cases m ON m.id=o.case_id AND m.transfer_id=o.transfer_id
          JOIN pix_transfers p ON p.id=o.transfer_id
          WHERE p.idempotency_key=? AND o.acknowledged_at IS NULL
            AND m.status='opening'`).get(`sim:${runId}:med_opening_delayed:0`) as
          { case_id: string } | undefined;
        return row ? found(`med_psp_open_outbox:${row.case_id}`) : missing();
      },
    } satisfies FaultAdapter } : {}),
    ...(runtime.separatedEcosystem ? { med_analysis_delayed: {
      start() { /* Wait for a real maker and checker decision on the probe case. */ },
      stop() { /* The run-owned DICT command is eligible again after expiry. */ },
      observe({ runId }) {
        const row = bank.db.prepare(`SELECT o.case_id FROM med_dict_analysis_outbox o
          JOIN med_cases m ON m.id=o.case_id AND m.transfer_id=o.transfer_id
          JOIN med_decisions d ON d.case_id=m.id AND d.decision='approved'
          JOIN pix_transfers p ON p.id=o.transfer_id
          WHERE p.idempotency_key=? AND o.acknowledged_at IS NULL
            AND d.maker_id<>d.checker_id AND m.refunded_cents=0`)
          .get(`sim:${runId}:med_analysis_delayed:0`) as { case_id: string } | undefined;
        return row ? found(`med_dict_analysis_outbox:${row.case_id}`) : missing();
      },
    } satisfies FaultAdapter } : {}),
    ...(runtime.separatedEcosystem ? {
      med_settlement_delayed: medCompletionDelay("settlement"),
      med_release_delayed: medCompletionDelay("release"),
    } : {}),
    card_issuer_offline: availabilityFaultAdapter({
      available: () => runtime.cardNetwork.issuerAvailability().available,
      ownsFailure: (runId) =>
        runtime.cardNetwork.issuerAvailability().changed_by === actor(runId),
      setAvailable: (available, runId) => {
        runtime.cardNetwork.setIssuerAvailability(available, actor(runId));
      },
      symptom: (_startedAt, runId) => {
        const row = bank.db.prepare(`SELECT r.id FROM card_network_rejections r
          JOIN card_issuer_history h ON h.available=0
          WHERE h.changed_by=?
            AND r.response_code='91' AND r.created_at>=h.changed_at
            AND NOT EXISTS (SELECT 1 FROM card_issuer_history later
              WHERE later.id>h.id AND later.changed_at<=r.created_at)
          ORDER BY r.created_at LIMIT 1`).get(actor(runId)) as
          { id: string } | undefined;
        return row ? found(`card_network_rejections:${row.id}`) : missing();
      },
    }),
    ...(runtime.separatedEcosystem ? { spi_unavailable: availabilityFaultAdapter({
      available: async () => (await runtime.labSpiAvailability()).available,
      ownsFailure: async (runId) =>
        (await runtime.labSpiAvailability()).changed_by === actor(runId),
      setAvailable: async (available, runId) => {
        await runtime.labSetSpiAvailability(available, actor(runId));
      },
      symptom: (_startedAt, runId) => {
        const row = bank.db.prepare(`SELECT o.transfer_id FROM pix_spi_outbox o
          JOIN pix_transfers t ON t.id=o.transfer_id
          WHERE t.idempotency_key=? AND o.response_status IS NULL LIMIT 1`)
          .get(`sim:${runId}:spi_unavailable:0`) as
          { transfer_id: string } | undefined;
        return row ? found(`pix_spi_outbox:${row.transfer_id}`) : missing();
      },
    }) } : {}),
  };
}
