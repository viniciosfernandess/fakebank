import { execFileSync } from "node:child_process";
import { AREA, type Area } from "../../../packages/contracts/src/index.ts";
import type { Bank } from "../../world/src/bank.ts";
import type { AuthEngine } from "../../world/src/auth.ts";
import type { Gateway } from "../../world/src/gateway.ts";
import type { CustomerSimulator } from "../../world/src/simulator.ts";
import type { TwinClock } from "../../world/src/clock.ts";
import type { SentinelEngine } from "../../world/src/sentinels.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { BudgetLedger } from "./budget.ts";
import { BlueChain } from "./blue-chain.ts";
import { FeatureChain } from "./feature-chain.ts";
import { PatchPipeline } from "./patch-pipeline.ts";
import type { AgentTransport } from "./agent-loop.ts";
import type { AgentRuntime } from "./runtime/agent-runtime.ts";
import type { StoredFeature, StoredSlot } from "./schedule-store.ts";
import { TRUSTED_PROOFS, type TrustedProof } from "./trusted-proofs.ts";
import { RecoveryChain } from "./recovery-chain.ts";
import { DeploymentWatch } from "./deployment-watch.ts";
import { BlueContainment } from "./blue-containment.ts";
import { HardeningChain, type HardeningRunResult } from "./hardening-chain.ts";
import { PostmortemChain } from "./postmortem-chain.ts";
import { publishMoneyFlowDisclosures, publishMoneyFlowMedSnapshots,
  publishSeparatedMoneyFlowMedSnapshots, recordMoneyFlowDisclosure,
  recordSeparatedMoneyFlowDisclosure } from
  "./money-flow-disclosure.ts";
import type { EcosystemClient } from "../../ecosystem/src/client.ts";

interface ControllerDependencies {
  bank: Bank; auth: AuthEngine; gateway: Gateway; clock: TwinClock;
  sentinels: SentinelEngine; events: EventStore; budget?: BudgetLedger;
  transport?: AgentTransport; runtime?: AgentRuntime; repoRoot: string; bankPath: string;
  simulator?: CustomerSimulator; realNow?: () => Date;
  scanSentinels?: () => Promise<void>;
  separatedMed?: { project: (transferId: string, caseId?: string) =>
    ReturnType<EcosystemClient["moneyFlowProjection"]>;
    dispatchOpenings: () => Promise<number> };
  paymentMessages?: (endToEndId: string) =>
    ReturnType<EcosystemClient["paymentMessages"]>;
  blue?: Pick<BlueChain, "run">;
  feature?: Pick<FeatureChain, "run">; recovery?: Pick<RecoveryChain, "run">;
  hardening?: Pick<HardeningChain, "run" | "verify">;
  postmortem?: Pick<PostmortemChain, "run">;
}
interface RoundScanSummary { missions: number; attempts: number; verifiedBreaches: number;
  memoryAdded: number; failures: string[]; }
interface IncidentProof { incidentId: string; area: Area; ruleId: string;
  proof: TrustedProof | undefined; scenarioId?: string; }
export interface CampaignRoundResult { status: "completed" | "partial" | "restart" | "watching";
  red: RoundScanSummary; incidents: number; merged: number; reasons: string[]; }
interface PendingDeployment { incidentId: string; taskId: string; runId: string;
  headSha: string; ruleId: string; regressionId: string;
  weaknessId?: TrustedProof["weaknessId"]; scenarioId?: string;
  phase?: "fix" | "hardening"; hardeningRuleId?: string; }
interface RoundProgress { startSeq: number; red: RoundScanSummary; incidents: IncidentProof[];
  nextIncident: number; merged: number; attemptsByIncident: Record<string, number>; reasons: string[];
  processedMissionIds: string[]; redDone: boolean;
  pending?: PendingDeployment; rollbackPending?: boolean;
  finished?: "completed" | "partial"; }

export class CampaignController {
  readonly bank: Bank;
  readonly sentinels: SentinelEngine;
  readonly events: EventStore;
  readonly blue: Pick<BlueChain, "run">;
  readonly feature: Pick<FeatureChain, "run">;
  readonly recovery: Pick<RecoveryChain, "run">;
  readonly hardening: Pick<HardeningChain, "run" | "verify">;
  readonly postmortem: Pick<PostmortemChain, "run">;
  readonly pipeline: PatchPipeline;
  readonly repoRoot: string;
  readonly bankPath: string;
  readonly deploymentWatch: DeploymentWatch | undefined;
  readonly scanSentinels: (() => Promise<void>) | undefined;
  readonly separatedMed: ControllerDependencies["separatedMed"];
  constructor(input: ControllerDependencies) {
    this.bank = input.bank; this.sentinels = input.sentinels; this.events = input.events;
    this.scanSentinels = input.scanSentinels;
    this.separatedMed = input.separatedMed;
    this.repoRoot = input.repoRoot; this.bankPath = input.bankPath;
    this.pipeline = new PatchPipeline(input.events.db, input.repoRoot);
    this.deploymentWatch = input.simulator ? new DeploymentWatch(input.bank, input.gateway,
      input.simulator, input.events, input.realNow) : undefined;
    this.events.db.exec(`CREATE TABLE IF NOT EXISTS campaign_round_progress (
      round_id TEXT PRIMARY KEY, data_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attack_incident_links (
      attack_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
      disclosed INTEGER NOT NULL DEFAULT 0 CHECK(disclosed IN (0,1))
    );
    CREATE TABLE IF NOT EXISTS campaign_recovery_followups (
      incident_id TEXT PRIMARY KEY, first_round_id TEXT NOT NULL,
      reason TEXT NOT NULL, updated_at TEXT NOT NULL
    );`);
    this.bank.db.exec(`CREATE TABLE IF NOT EXISTS presentation_money_flow_disclosures (
      id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES sentinel_incidents(id),
      transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
      edges_json TEXT NOT NULL, disclosed_at TEXT NOT NULL,
      UNIQUE(incident_id,transfer_id)
    );
    CREATE TABLE IF NOT EXISTS sentinel_incident_transfer_evidence (
      incident_id TEXT NOT NULL REFERENCES sentinel_incidents(id),
      transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
      evidence_ref TEXT NOT NULL, linked_at TEXT NOT NULL,
      PRIMARY KEY(incident_id,transfer_id,evidence_ref)
    )`);
    this.blue = input.blue ?? new BlueChain({ bank: input.bank, events: input.events,
      ...(input.budget ? { budget: input.budget } : {}),
      ...(input.transport ? { transport: input.transport } : {}),
      ...(input.runtime ? { runtime: input.runtime } : {}),
      pipeline: this.pipeline, repoRoot: input.repoRoot,
      ...(input.paymentMessages ? { paymentMessages: input.paymentMessages } : {}) });
    this.feature = input.feature ?? new FeatureChain({ events: input.events,
      ...(input.budget ? { budget: input.budget } : {}),
      ...(input.transport ? { transport: input.transport } : {}),
      ...(input.runtime ? { runtime: input.runtime } : {}),
      repoRoot: input.repoRoot });
    this.recovery = input.recovery ?? new RecoveryChain({ bank: input.bank,
      events: input.events, ...(input.budget ? { budget: input.budget } : {}),
      ...(input.transport ? { transport: input.transport } : {}),
      ...(input.runtime ? { runtime: input.runtime } : {}),
      ...(input.separatedMed ? { separatedMed: input.separatedMed } : {}) });
    this.hardening = input.hardening ?? new HardeningChain(input.bank, input.events,
      input.budget, input.transport, input.runtime);
    this.postmortem = input.postmortem ?? new PostmortemChain(input.events, input.budget,
      input.transport, input.runtime);
  }
  private readProgress(roundId: string): RoundProgress | undefined {
    const row = this.events.db.prepare("SELECT data_json FROM campaign_round_progress WHERE round_id=?")
      .get(roundId) as { data_json: string } | undefined;
    if (!row) return undefined;
    const progress = JSON.parse(row.data_json) as RoundProgress & { engineerAttempts?: number };
    if (!progress.attemptsByIncident) progress.attemptsByIncident = {};
    delete progress.engineerAttempts;
    for (const incident of progress.incidents) {
      const started = this.events.caseFile.history(incident.incidentId)
        .filter((entry) => entry.round_id === roundId && entry.kind === "attempt.started")
        .length;
      if (started) progress.attemptsByIncident[incident.incidentId] = Math.max(
        progress.attemptsByIncident[incident.incidentId] ?? 0, started);
      if (!AREA.safeParse(incident.area).success) {
        const stored = this.bank.db.prepare("SELECT area FROM sentinel_incidents WHERE id=?")
          .get(incident.incidentId) as { area: string } | undefined;
        if (!stored || !AREA.safeParse(stored.area).success) throw new Error("PROGRESS_INCIDENT_AREA_INVALID");
        incident.area = stored.area as Area;
      }
      incident.ruleId ||= incident.proof?.sentinelRuleId ?? "audit";
    }
    if (progress.pending && (!progress.pending.ruleId || !progress.pending.regressionId)) {
      const proof = TRUSTED_PROOFS.find((item) => item.weaknessId === progress.pending?.weaknessId);
      progress.pending.ruleId ||= proof?.sentinelRuleId ?? "audit";
      progress.pending.regressionId ||= progress.pending.scenarioId ?? proof?.regressionId ?? "";
      if (!progress.pending.regressionId) throw new Error("PROGRESS_REGRESSION_ID_MISSING");
    }
    return progress;
  }
  private saveProgress(roundId: string, progress: RoundProgress): void {
    this.events.db.prepare(`INSERT INTO campaign_round_progress VALUES (?,?)
      ON CONFLICT(round_id) DO UPDATE SET data_json=excluded.data_json`)
      .run(roundId, JSON.stringify(progress));
  }
  private async publishPostmortem(roundId: string, incidentId: string): Promise<void> {
    const incident = this.bank.db.prepare("SELECT area FROM sentinel_incidents WHERE id=?")
      .get(incidentId) as { area: Area } | undefined;
    if (!incident) throw new Error("POSTMORTEM_INCIDENT_MISSING");
    try {
      await this.postmortem.run({ incidentId, roundId, area: incident.area,
        twinNow: this.bank.now() });
    } catch (error) {
      this.events.caseFile.record({ incidentId, roundId,
        kind: "postmortem.agent_failure", actorId: "postmortem",
        createdAt: new Date().toISOString(), payload: {
          reason: error instanceof Error ? error.message : "postmortem_failed" } });
    }
  }
  private deploymentEvent(slot: StoredSlot, pending: PendingDeployment,
    type: "deploy.succeeded" | "deploy.rolled_back" | "regression.result",
    publicPayload: Record<string, unknown>): void {
    this.events.append({ round_id: slot.roundId, ts: new Date().toISOString(),
      twin_ts: this.bank.now().toISOString(), type,
      actor: { id: "campaign-deployer", role: "system" }, task_id: pending.taskId,
      incident_id: pending.incidentId, public_summary_pt: type.replaceAll(".", " "),
      public: publicPayload }, `deploy:${pending.runId}:${type}`);
  }
  private reopenRolledBackTask(pending: PendingDeployment): void {
    const exists = this.bank.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='blue_tasks'`).get();
    if (!exists) return;
    const current = this.bank.db.prepare("SELECT state FROM blue_tasks WHERE id=? AND incident_id=?")
      .get(pending.taskId, pending.incidentId) as { state: string } | undefined;
    if (!current) throw new Error("ROLLBACK_TASK_MISSING");
    if (current.state !== "open" && current.state !== "merged")
      throw new Error("ROLLBACK_TASK_STATE_INVALID");
    if (pending.phase === "hardening") {
      this.bank.db.prepare("UPDATE blue_tasks SET state='rolled_back' WHERE id=? AND incident_id=?")
        .run(pending.taskId, pending.incidentId);
      this.bank.db.prepare("UPDATE sentinel_incidents SET state='needs_human' WHERE id=?")
        .run(pending.incidentId);
      this.events.append({ round_id: null, ts: new Date().toISOString(),
        twin_ts: this.bank.now().toISOString(), type: "incident.updated",
        actor: { id: "campaign-controller", role: "system" }, area: "pix",
        incident_id: pending.incidentId,
        public_summary_pt: "Regra pós-incidente revertida; revisão humana necessária",
        public: { incident_id: pending.incidentId, state: "needs_human" },
        private: { reason: "hardening_rule_rolled_back", task_id: pending.taskId } });
      return;
    }
    if (current.state === "merged") this.bank.db.prepare(
      "UPDATE blue_tasks SET state='open' WHERE id=? AND incident_id=?")
      .run(pending.taskId, pending.incidentId);
    const containment = new BlueContainment(this.bank, this.events);
    const state = containment.hasActive(pending.incidentId) ?
      "awaiting_next_window" : "needs_human";
    this.bank.db.prepare("UPDATE sentinel_incidents SET state=? WHERE id=?")
      .run(state, pending.incidentId);
    if (state === "awaiting_next_window") containment.renewAwaiting(pending.incidentId);
    const incident = this.bank.db.prepare("SELECT area FROM sentinel_incidents WHERE id=?")
      .get(pending.incidentId) as { area: Area };
    this.events.append({ round_id: null, ts: new Date().toISOString(),
      twin_ts: this.bank.now().toISOString(), type: "incident.updated",
      actor: { id: "campaign-controller", role: "system" }, area: incident.area,
      incident_id: pending.incidentId,
      public_summary_pt: state === "awaiting_next_window" ?
        "Correção revertida; contenção mantida" : "Correção revertida; análise humana necessária",
      public: { incident_id: pending.incidentId, state },
      private: { reason: "deploy_rolled_back" } });
  }
  private async beginHardening(slot: StoredSlot, progress: RoundProgress,
    base: Pick<PendingDeployment, "incidentId" | "ruleId" | "regressionId" |
      "weaknessId" | "scenarioId">): Promise<"skip" | "restart" | "failed"> {
    if (!base.scenarioId || !this.bank.db.prepare(`SELECT 1
      FROM sentinel_incident_transfer_evidence
      WHERE incident_id=? AND evidence_ref LIKE 'red_sandbox_calls:%' LIMIT 1`)
      .get(base.incidentId)) return "skip";
    let result: HardeningRunResult;
    try {
      result = await this.hardening.run({ roundId: slot.roundId,
        incidentId: base.incidentId, repoRoot: this.repoRoot,
        pipeline: this.pipeline, deadlineAt: Date.parse(slot.endsAt) });
    } catch (error) {
      result = { status: "needs_human", reason: error instanceof Error ? error.message :
        "hardening_error" };
    }
    if (result.status === "merged") {
      progress.merged++;
      progress.pending = { incidentId: base.incidentId, taskId: result.taskId,
        runId: result.runId, headSha: result.headSha,
        ruleId: base.ruleId, regressionId: base.regressionId,
        ...(base.weaknessId ? { weaknessId: base.weaknessId } : {}),
        scenarioId: base.scenarioId, phase: "hardening",
        hardeningRuleId: result.ruleId };
      return "restart";
    }
    progress.reasons.push(`hardening:${base.incidentId}:${result.reason}`);
    this.bank.db.prepare("UPDATE sentinel_incidents SET state='needs_human' WHERE id=?")
      .run(base.incidentId);
    this.events.append({ round_id: slot.roundId, ts: new Date().toISOString(),
      twin_ts: this.bank.now().toISOString(), type: "incident.updated",
      actor: { id: "campaign-controller", role: "system" }, area: "pix",
      incident_id: base.incidentId,
      public_summary_pt: "Regra pós-incidente requer revisão humana",
      public: { incident_id: base.incidentId, state: "needs_human" },
      private: { reason: result.reason } });
    return "failed";
  }
  private async verifyDeployment(slot: StoredSlot, progress: RoundProgress): Promise<
    "ok" | "restart" | "failed" | "watching"> {
    const pending = progress.pending!;
    const runningHead = process.env.BANCO_VIVO_RUNTIME_HEAD;
    const repositoryHead = execFileSync("git", ["rev-parse", "HEAD"],
      { cwd: this.repoRoot, encoding: "utf8" }).trim();
    if (runningHead !== pending.headSha || repositoryHead !== pending.headSha) {
      progress.reasons.push(`deploy_version_mismatch:${pending.incidentId}`);
      return "failed";
    }
    const watchState = this.deploymentWatch?.state(pending.runId);
    if (watchState?.state === "failed" || watchState?.state === "rolled_back") return "failed";
    if (watchState?.state === "watching") return "watching";
    const merge = this.events.db.prepare("SELECT merged_at FROM patch_ci_runs WHERE id=?")
      .get(pending.runId) as { merged_at: string } | undefined;
    const duration = merge?.merged_at ? Math.max(0, Math.round((Date.now() -
      Date.parse(merge.merged_at)) / 1000)) : 0;
    this.deploymentEvent(slot, pending, "deploy.succeeded", { task_id: pending.taskId,
      mode: "restart", version: pending.headSha.slice(0, 12), duration_s: duration });
    let passed = watchState?.state === "passed";
    if (!watchState) {
      try { passed = pending.phase === "hardening" ? Boolean(pending.hardeningRuleId &&
        this.hardening.verify(pending.incidentId, pending.hardeningRuleId)) :
        false; }
      catch { passed = false; }
      if (passed) {
        if (this.separatedMed)
          await recordSeparatedMoneyFlowDisclosure(this.bank, pending.incidentId,
            [], this.separatedMed.project);
        else recordMoneyFlowDisclosure(this.bank, pending.incidentId,
          []);
        this.events.db.prepare("UPDATE attack_incident_links SET disclosed=1 WHERE incident_id=?")
          .run(pending.incidentId);
        publishMoneyFlowDisclosures(this.bank, this.events, slot.roundId, pending.incidentId);
        if (this.separatedMed)
          await publishSeparatedMoneyFlowMedSnapshots(this.bank, this.events,
            slot.roundId, pending.incidentId, this.separatedMed.project);
        else publishMoneyFlowMedSnapshots(this.bank, this.events,
          slot.roundId, pending.incidentId);
      }
      this.deploymentEvent(slot, pending, "regression.result", { run_id: pending.runId,
        suite: "regression", kind: "proof", pass: passed ? 1 : 0, fail: passed ? 0 : 1,
        total: 1, added_test_id: pending.regressionId });
      if (passed && this.deploymentWatch) {
        this.deploymentWatch.begin({ runId: pending.runId, roundId: slot.roundId,
          incidentId: pending.incidentId, taskId: pending.taskId, ruleId: pending.ruleId });
        return "watching";
      }
    }
    if (passed) {
      if (pending.phase === "hardening") {
        await this.publishPostmortem(slot.roundId, pending.incidentId);
        this.bank.db.prepare("UPDATE sentinel_incidents SET state='resolved' WHERE id=?")
          .run(pending.incidentId);
        this.events.append({ round_id: slot.roundId, ts: new Date().toISOString(),
          twin_ts: this.bank.now().toISOString(), type: "incident.updated",
          actor: { id: "campaign-controller", role: "system" }, area: "pix",
          incident_id: pending.incidentId,
          public_summary_pt: "Correção e detecção antecipada verificadas",
          public: { incident_id: pending.incidentId, state: "resolved" } },
        `incident:${pending.incidentId}:resolved`);
        delete progress.pending; progress.nextIncident++; return "ok";
      }
      const recovery = await this.recovery.run({ roundId: slot.roundId,
        incidentId: pending.incidentId, deadlineAt: Date.parse(slot.endsAt) });
      if (recovery.status === "partial") {
        progress.reasons.push(`recovery:${pending.incidentId}:${recovery.reason ?? "unknown"}`);
        this.events.db.prepare(`INSERT INTO campaign_recovery_followups VALUES (?,?,?,?)
          ON CONFLICT(incident_id) DO UPDATE SET reason=excluded.reason,
          updated_at=excluded.updated_at`)
          .run(pending.incidentId, slot.roundId, recovery.reason ?? "unknown",
            new Date().toISOString());
      }
      else {
        this.events.db.prepare("DELETE FROM campaign_recovery_followups WHERE incident_id=?")
          .run(pending.incidentId);
        const hardened = await this.beginHardening(slot, progress, pending);
        if (hardened === "restart") return "restart";
        if (hardened === "failed") {
          delete progress.pending; progress.nextIncident++; return "ok";
        }
        await this.publishPostmortem(slot.roundId, pending.incidentId);
        this.bank.db.prepare("UPDATE sentinel_incidents SET state='resolved' WHERE id=?")
          .run(pending.incidentId);
        this.events.append({ round_id: slot.roundId, ts: new Date().toISOString(),
          twin_ts: this.bank.now().toISOString(), type: "incident.updated",
          actor: { id: "campaign-controller", role: "system" },
          incident_id: pending.incidentId, public_summary_pt: "Incidente resolvido",
          public: { incident_id: pending.incidentId, state: "resolved" } },
        `incident:${pending.incidentId}:resolved`);
      }
      delete progress.pending; progress.nextIncident++; return "ok";
    }
    try {
      const reverted = this.pipeline.rollback(pending.runId, "post_deploy_proof_failed");
      this.reopenRolledBackTask(pending);
      this.deploymentEvent(slot, pending, "deploy.rolled_back", { task_id: pending.taskId,
        reason_code: "honest_probe", version_back_to: reverted.slice(0, 12) });
      progress.rollbackPending = true;
      progress.reasons.push(`post_deploy_proof_failed:${pending.incidentId}`);
      return "restart";
    } catch {
      progress.reasons.push(`rollback_failed:${pending.incidentId}`);
      return "failed";
    }
  }
  async observeDeployment(): Promise<boolean> {
    if (!this.deploymentWatch) return false;
    for (const failed of await this.deploymentWatch.observe()) {
      const progressRow = this.events.db.prepare(`SELECT round_id,data_json FROM campaign_round_progress
        WHERE json_extract(data_json,'$.pending.runId')=?`).get(failed.runId) as
        { round_id: string; data_json: string } | undefined;
      if (!progressRow) throw new Error("DEPLOYMENT_WATCH_PROGRESS_MISSING");
      const progress = JSON.parse(progressRow.data_json) as RoundProgress;
      const pending = progress.pending;
      if (!pending) throw new Error("DEPLOYMENT_WATCH_PENDING_MISSING");
      const reverted = this.pipeline.state(failed.runId) === "rolled_back" ?
        execFileSync("git", ["rev-parse", "HEAD"], { cwd: this.repoRoot,
          encoding: "utf8" }).trim() :
        this.pipeline.rollback(failed.runId, `watch_${failed.reason}`,
          this.deploymentWatch.startedAt(failed.runId));
      this.reopenRolledBackTask(pending);
      const slot = { roundId: progressRow.round_id } as StoredSlot;
      const reasonCode = failed.reason === "health" ? "health" :
        failed.reason === "http_5xx" ? "errors" : failed.reason === "latency" ? "latency" :
        failed.reason === "false_block" ? "false_block" : failed.reason === "ledger_drift" ?
          "drift" : failed.reason === "unrelated_critical" ? "alert" : "honest_probe";
      this.deploymentEvent(slot, pending, "deploy.rolled_back", { task_id: pending.taskId,
        reason_code: reasonCode, version_back_to: reverted.slice(0, 12) });
      progress.rollbackPending = true;
      progress.reasons.push(`deployment_watch:${pending.incidentId}:${failed.reason}`);
      this.saveProgress(progressRow.round_id, progress);
      this.deploymentWatch.markRolledBack(failed.runId);
      return true;
    }
    return false;
  }
  private incidentProof(event: ReturnType<EventStore["list"]>[number]): IncidentProof {
    const alertId = this.events.getPrivate(event.seq)?.alert_id;
    const rule = typeof alertId === "string" ? this.bank.db.prepare(
      "SELECT rule_id FROM sentinel_alerts WHERE id=?").get(alertId) as
      { rule_id: string } | undefined : undefined;
    const incidentId = String(event.public.incident_id);
    return { incidentId, area: event.area as Area, ruleId: rule?.rule_id ?? "audit",
      proof: TRUSTED_PROOFS.find((item) => item.sentinelRuleId === rule?.rule_id &&
        item.area === event.area) };
  }
  private openIncidents(): IncidentProof[] {
    const open = this.bank.db.prepare(`SELECT id FROM sentinel_incidents
      WHERE state IN ('open','contained','patching','awaiting_next_window') ORDER BY opened_at,id`)
      .all() as { id: string }[];
    return open.flatMap(({ id }) => {
      const row = this.events.db.prepare(`SELECT seq FROM events WHERE type='incident.opened'
        AND incident_id=? ORDER BY seq DESC LIMIT 1`).get(id) as { seq: number } | undefined;
      const event = row ? this.events.get(row.seq) : undefined;
      return event && event.area ? [this.incidentProof(event)] : [];
    });
  }
  private deferDeadlineIncident(roundId: string, incident: IncidentProof): void {
    const row = this.bank.db.prepare("SELECT state FROM sentinel_incidents WHERE id=?")
      .get(incident.incidentId) as { state: string } | undefined;
    if (!row || row.state === "resolved" || row.state === "needs_human") return;
    const containment = new BlueContainment(this.bank, this.events);
    const pendingMed = Boolean(this.events.db.prepare(`SELECT 1 FROM campaign_recovery_followups
      WHERE incident_id=? AND reason='med_review_pending'`).get(incident.incidentId));
    const activeContainment = containment.hasActive(incident.incidentId);
    const state = pendingMed || activeContainment ?
      "awaiting_next_window" : "needs_human";
    if (row.state === state) {
      if (activeContainment && state === "awaiting_next_window")
        containment.renewAwaiting(incident.incidentId);
      return;
    }
    this.bank.db.prepare("UPDATE sentinel_incidents SET state=? WHERE id=?")
      .run(state, incident.incidentId);
    if (activeContainment && state === "awaiting_next_window")
      containment.renewAwaiting(incident.incidentId);
    this.events.append({ round_id: roundId, ts: new Date().toISOString(),
      twin_ts: this.bank.now().toISOString(), type: "incident.updated",
      actor: { id: "campaign-controller", role: "system" }, area: incident.area,
      incident_id: incident.incidentId,
      public_summary_pt: pendingMed ? "Acompanhamento do MED continua na próxima janela" :
        state === "awaiting_next_window" ?
          "Incidente continua na próxima janela" : "Incidente requer análise humana",
      public: { incident_id: incident.incidentId, state },
      private: { reason: pendingMed ? "med_pending_deadline" : "round_deadline" } },
    `deadline:${roundId}:${incident.incidentId}:${state}`);
  }
  deferExpiredRound(roundId: string, endsAt: string): void {
    const progress = this.readProgress(roundId);
    const openedAt = this.events.db.prepare(`SELECT ts FROM events WHERE type='incident.opened'
      AND incident_id=? ORDER BY seq LIMIT 1`);
    const eligible = (incident: IncidentProof): boolean => {
      const opened = openedAt.get(incident.incidentId) as { ts: string } | undefined;
      return Boolean(opened && opened.ts <= endsAt);
    };
    let pending: IncidentProof[];
    if (progress) {
      const listed = new Set(progress.incidents.map((incident) => incident.incidentId));
      const medFollowups = progress.incidents.slice(0, progress.nextIncident)
        .filter((incident) => eligible(incident) && Boolean(this.events.db.prepare(`SELECT 1
          FROM campaign_recovery_followups WHERE incident_id=? AND reason='med_review_pending'`)
          .get(incident.incidentId)));
      pending = [...progress.incidents.slice(progress.nextIncident).filter(eligible),
        ...medFollowups,
        ...this.incidentsAfter(progress.startSeq, endsAt)
          .filter((incident) => !listed.has(incident.incidentId))];
    } else {
      pending = this.openIncidents().filter(eligible);
    }
    for (const incident of new Map(pending.map((item) => [item.incidentId, item])).values())
      this.deferDeadlineIncident(roundId, incident);
  }
  private blueAttemptCap(): number {
    const value = Number(process.env.BLUE_MAX_ATTEMPTS_PER_ROUND ?? 4);
    if (!Number.isInteger(value) || value < 1 || value > 12)
      throw new Error("BLUE_MAX_ATTEMPTS_PER_ROUND_INVALID");
    return value;
  }
  private incidentsAfter(seq: number, beforeTs?: string): IncidentProof[] {
    const incidents: IncidentProof[] = [];
    let cursor = seq;
    for (;;) {
      const page = this.events.list({ after: cursor, types: ["incident.opened"], limit: 500 });
      for (const event of page) if (event.area && (!beforeTs || event.ts <= beforeTs))
        incidents.push(this.incidentProof(event));
      if (page.length < 500) break;
      cursor = page.at(-1)!.seq;
    }
    return incidents;
  }
  private async advanceRed(slot: StoredSlot, progress: RoundProgress): Promise<void> {
    const startSeq = this.events.latestSeq();
    progress.redDone = true;
    if (this.scanSentinels) await this.scanSentinels();
    else this.sentinels.scan();
    progress.incidents.push(...this.incidentsAfter(startSeq));
    this.saveProgress(slot.roundId, progress);
  }
  async runRound(slot: StoredSlot): Promise<CampaignRoundResult> {
    let progress = this.readProgress(slot.roundId);
    if (!progress) {
      const startSeq = this.events.latestSeq();
      progress = { startSeq, red: { missions: 0, attempts: 0, verifiedBreaches: 0,
        memoryAdded: 0, failures: [] }, incidents: this.openIncidents(), nextIncident: 0, merged: 0,
        attemptsByIncident: {}, reasons: [], processedMissionIds: [], redDone: false };
      this.saveProgress(slot.roundId, progress);
    }
    const result = (status: CampaignRoundResult["status"]): CampaignRoundResult => ({
      status, red: progress.red, incidents: progress.incidents.length,
      merged: progress.merged, reasons: progress.reasons });
    if (progress.finished) return result(progress.finished);
    if (progress.rollbackPending) {
      progress.finished = "partial"; this.saveProgress(slot.roundId, progress);
      return result("partial");
    }
    if (progress.pending) {
      const state = await this.verifyDeployment(slot, progress);
      this.saveProgress(slot.roundId, progress);
      if (state === "restart") return result("restart");
      if (state === "watching") return result("watching");
      if (state === "failed") {
        progress.finished = "partial"; this.saveProgress(slot.roundId, progress);
        return result("partial");
      }
    }
    for (;;) {
      if (progress.nextIncident >= progress.incidents.length) {
        if (Date.now() >= Date.parse(slot.endsAt)) {
          this.deferExpiredRound(slot.roundId, slot.endsAt);
          break;
        }
        const blockingReason = progress.reasons.some((reason) =>
          !/^recovery:[^:]+:(med_review_pending|external_damage_unverified)$/.test(reason));
        if (progress.redDone || blockingReason) break;
        await this.advanceRed(slot, progress);
        continue;
      }
      const incident = progress.incidents[progress.nextIncident]!;
      if (Date.now() >= Date.parse(slot.endsAt)) {
        this.deferExpiredRound(slot.roundId, slot.endsAt);
        progress.reasons.push("round_deadline"); break;
      }
      const currentState = this.bank.db.prepare("SELECT state FROM sentinel_incidents WHERE id=?")
        .get(incident.incidentId) as { state: string } | undefined;
      if (!currentState || !["open", "awaiting_next_window"].includes(currentState.state)) {
        if (currentState?.state !== "resolved")
          progress.reasons.push(`incident_state:${incident.incidentId}:${currentState?.state ?? "missing"}`);
        progress.nextIncident++;
        this.saveProgress(slot.roundId, progress);
        continue;
      }
      if (this.events.db.prepare("SELECT 1 FROM campaign_recovery_followups WHERE incident_id=?")
        .get(incident.incidentId)) {
        const recovery = await this.recovery.run({ roundId: slot.roundId,
          incidentId: incident.incidentId, deadlineAt: Date.parse(slot.endsAt) });
        if (recovery.status === "partial") {
          progress.reasons.push(`recovery:${incident.incidentId}:${recovery.reason ?? "unknown"}`);
          this.events.db.prepare(`UPDATE campaign_recovery_followups SET reason=?,updated_at=?
            WHERE incident_id=?`).run(recovery.reason ?? "unknown", new Date().toISOString(),
              incident.incidentId);
        } else {
          this.events.db.prepare("DELETE FROM campaign_recovery_followups WHERE incident_id=?")
            .run(incident.incidentId);
          const hardened = await this.beginHardening(slot, progress, {
            incidentId: incident.incidentId, ruleId: incident.ruleId,
            regressionId: incident.scenarioId ?? incident.proof?.regressionId ?? "",
            ...(incident.scenarioId ? { scenarioId: incident.scenarioId } : {}),
            ...(incident.proof ? { weaknessId: incident.proof.weaknessId } : {}) });
          if (hardened === "restart") {
            this.saveProgress(slot.roundId, progress);
            return result("restart");
          }
          if (hardened === "failed") {
            progress.nextIncident++;
            this.saveProgress(slot.roundId, progress);
            continue;
          }
          await this.publishPostmortem(slot.roundId, incident.incidentId);
          this.bank.db.prepare("UPDATE sentinel_incidents SET state='resolved' WHERE id=?")
            .run(incident.incidentId);
          this.events.append({ round_id: slot.roundId, ts: new Date().toISOString(),
            twin_ts: this.bank.now().toISOString(), type: "incident.updated",
            actor: { id: "campaign-controller", role: "system" },
            incident_id: incident.incidentId, public_summary_pt: "Incidente resolvido",
            public: { incident_id: incident.incidentId, state: "resolved" } },
          `incident:${incident.incidentId}:resolved`);
        }
        progress.nextIncident++;
        this.saveProgress(slot.roundId, progress);
        continue;
      }
      if (!incident.proof && !incident.scenarioId) {
        progress.reasons.push(`no_reproduction:${incident.incidentId}`);
        progress.nextIncident++;
        this.saveProgress(slot.roundId, progress);
        continue;
      }
      const incidentAttempts = progress.attemptsByIncident[incident.incidentId] ?? 0;
      if (incidentAttempts >= this.blueAttemptCap()) {
        const containment = new BlueContainment(this.bank, this.events);
        const state = containment.hasActive(incident.incidentId) ?
          "awaiting_next_window" : "needs_human";
        this.bank.db.prepare("UPDATE sentinel_incidents SET state=? WHERE id=?")
          .run(state, incident.incidentId);
        if (state === "awaiting_next_window") containment.renewAwaiting(incident.incidentId);
        this.events.append({ round_id: slot.roundId, ts: new Date().toISOString(),
          twin_ts: this.bank.now().toISOString(), type: "incident.updated",
          actor: { id: "campaign-controller", role: "system" }, area: incident.area,
          incident_id: incident.incidentId,
          public_summary_pt: state === "awaiting_next_window" ?
            "Correção continua na próxima janela" : "Incidente requer contenção humana",
          public: { incident_id: incident.incidentId, state } });
        progress.reasons.push(`engineer_attempt_cap:${incident.incidentId}`);
        progress.nextIncident++;
        this.saveProgress(slot.roundId, progress);
        continue;
      }
      progress.reasons.push(`manual_validation_required:${incident.incidentId}`);
      progress.nextIncident++;
      this.saveProgress(slot.roundId, progress);
      continue;
    }
    if (progress.red.verifiedBreaches > progress.incidents.length)
      progress.reasons.push("post_round_audit_required");
    if (Date.now() >= Date.parse(slot.endsAt) && !progress.reasons.includes("round_deadline"))
      progress.reasons.push("round_deadline");
    progress.finished = progress.reasons.length ? "partial" : "completed";
    this.saveProgress(slot.roundId, progress);
    const outcome = result(progress.finished);
    return outcome;
  }
  runFeature(slot: StoredFeature): ReturnType<FeatureChain["run"]> {
    return this.feature.run(slot);
  }
}
