import { randomUUID } from "node:crypto";
import { AREA, type Area } from "../../../packages/contracts/src/index.ts";
import { fixDesignBody, incidentDossierBody, incidentMapBody, patchDossierBody,
  reviewVerdictBody, rootCauseReportBody } from "../../../packages/contracts/src/dossiers.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { Bank } from "../../world/src/bank.ts";
import type { AgentTransport } from "./agent-loop.ts";
import { agentExecutor, type AgentRuntime } from "./runtime/agent-runtime.ts";
import { stageAgentId, unfinishedStageAgentId } from "./runtime/stage-agent-id.ts";
import { BudgetLedger } from "./budget.ts";
import { createInvestigatorTools } from "./blue-tools.ts";
import { PatchPipeline } from "./patch-pipeline.ts";
import { createArchitectTools, createEngineerTools, createReviewerTools, type PatchToolContext } from "./patch-tools.ts";
import { IncidentCaseFile } from "../../../packages/event-store/src/incident-case-file.ts";
import { isEditablePath } from "../../world/src/patch-guard.ts";
import { BlueContainment } from "./blue-containment.ts";
import { createForensicTools, createRootCauseTools } from "./blue-forensics.ts";
import type { EcosystemClient } from "../../ecosystem/src/client.ts";

export interface BlueChainResult { status: "no_task" | "awaiting_next_window" | "needs_human" | "merged" | "failed";
  taskId?: string; ciRunId?: string; headSha?: string; attempts: number; reason?: string; }
export class BlueChain {
  readonly bank: Bank;
  readonly events: EventStore;
  readonly budget: BudgetLedger | undefined;
  readonly transport: AgentTransport | undefined;
  readonly runtime: AgentRuntime | undefined;
  readonly pipeline: PatchPipeline;
  readonly caseFile: IncidentCaseFile;
  readonly repoRoot: string;
  readonly paymentMessages: ((endToEndId: string) =>
    ReturnType<EcosystemClient["paymentMessages"]>) | undefined;
  constructor(input: { bank: Bank; events: EventStore; budget?: BudgetLedger;
    transport?: AgentTransport; pipeline: PatchPipeline; repoRoot: string;
    runtime?: AgentRuntime; paymentMessages?: (endToEndId: string) =>
      ReturnType<EcosystemClient["paymentMessages"]> }) {
    this.bank = input.bank; this.events = input.events; this.budget = input.budget;
    this.transport = input.transport; this.pipeline = input.pipeline; this.repoRoot = input.repoRoot;
    this.runtime = input.runtime;
    this.paymentMessages = input.paymentMessages;
    this.caseFile = this.events.caseFile;
  }
  private remember(roundId: string, incidentId: string, kind: string, actorId: string,
    payload: Record<string, unknown>, attemptNo?: number, entryKey?: string): void {
    this.caseFile.record({ incidentId, roundId, kind, actorId, payload,
      ...(attemptNo ? { attemptNo } : {}), ...(entryKey ? { entryKey } : {}),
      createdAt: this.bank.realNow().toISOString() });
  }
  private emit(roundId: string, type: "context.handoff" | "review.rejected" | "review.approved" |
    "patch.merged", actorId: string, area: Area, incidentId: string, taskId: string | undefined,
    publicPayload: Record<string, unknown>, privatePayload?: Record<string, unknown>): void {
    this.events.append({ round_id: roundId, ts: new Date().toISOString(), twin_ts: this.bank.now().toISOString(),
      type, actor: { id: actorId, role: "system" }, area, incident_id: incidentId,
      ...(taskId ? { task_id: taskId } : {}), public_summary_pt: type.replaceAll(".", " "),
      public: publicPayload, ...(privatePayload ? { private: privatePayload } : {}) });
  }
  private defer(roundId: string, incidentId: string, area: Area, taskId: string | undefined,
    attempts: number, reason: string, forceHuman = false): BlueChainResult {
    const containment = new BlueContainment(this.bank, this.events);
    const state = !forceHuman && containment.hasActive(incidentId) ?
      "awaiting_next_window" : "needs_human";
    this.bank.db.prepare("UPDATE sentinel_incidents SET state=? WHERE id=?")
      .run(state, incidentId);
    if (state === "awaiting_next_window") containment.renewAwaiting(incidentId);
    this.events.append({ round_id: roundId, ts: new Date().toISOString(),
      twin_ts: this.bank.now().toISOString(), type: "incident.updated",
      actor: { id: "harness", role: "system" }, area, incident_id: incidentId,
      ...(taskId ? { task_id: taskId } : {}),
      public_summary_pt: state === "awaiting_next_window" ?
        "Correção continua na próxima janela" : "Incidente requer contenção humana",
      public: { incident_id: incidentId, state }, private: { reason } });
    return { status: state, ...(taskId ? { taskId } : {}), attempts,
      reason: state === "needs_human" && !forceHuman ? "containment_missing" : reason };
  }
  async run(input: { roundId: string; incidentId: string; regressionIds: string[];
    redFirstTestSource: string; reproductionSymptoms: string[];
    patchArea?: Area;
    maxAttempts?: number; deadlineAt?: number }): Promise<BlueChainResult> {
    const incident = this.bank.db.prepare("SELECT area,severity,state,opened_at FROM sentinel_incidents WHERE id=?")
      .get(input.incidentId) as { area: string; severity: string; state: string;
        opened_at: string } | undefined;
    if (!incident || !["open", "awaiting_next_window"].includes(incident.state) ||
      !AREA.safeParse(incident.area).success)
      throw new Error("BLUE_CHAIN_INCIDENT_INVALID");
    const area = incident.area as Area;
    this.caseFile.open(input.incidentId, area, incident.opened_at);
    const loop = agentExecutor(this.events, this.budget, this.runtime, this.transport);
    const taskTableExists = this.bank.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='blue_tasks'`).get();
    let existingTask = taskTableExists ? this.bank.db.prepare(`SELECT id,title,kind,priority,
      acceptance_json,do_not_break_json,regression_json FROM blue_tasks
      WHERE incident_id=? AND state='open' LIMIT 1`).get(input.incidentId) : undefined;
    if (!existingTask && taskTableExists) {
      const mergedTask = this.bank.db.prepare(`SELECT id FROM blue_tasks
        WHERE incident_id=? AND state='merged' ORDER BY opened_at DESC LIMIT 1`)
        .get(input.incidentId) as { id: string } | undefined;
      const ciTableExists = this.events.db.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='patch_ci_runs'`).get();
      const rolledBack = mergedTask && ciTableExists && this.events.db.prepare(`SELECT 1 FROM patch_ci_runs
        WHERE task_id=? AND state='rolled_back' LIMIT 1`).get(mergedTask.id);
      if (mergedTask && rolledBack) {
        this.bank.db.prepare("UPDATE blue_tasks SET state='open' WHERE id=?")
          .run(mergedTask.id);
        existingTask = mergedTask;
      }
    }
    const previousInvestigation = incident.state === "awaiting_next_window" || existingTask ?
      this.caseFile.history(input.incidentId).filter((entry) =>
        entry.kind === "dossier.investigation").at(-1) : undefined;
    const resuming = incident.state === "awaiting_next_window" ||
      Boolean(existingTask && previousInvestigation);
    if (resuming) {
      const containment = new BlueContainment(this.bank, this.events);
      if (!containment.hasActive(input.incidentId))
        return this.defer(input.roundId, input.incidentId, area,
          (existingTask as { id: string } | undefined)?.id, 0,
          "resumed_containment_missing", true);
      containment.renewAwaiting(input.incidentId);
    }
    if (incident.state === "open" && existingTask && previousInvestigation) {
      this.bank.db.prepare("UPDATE sentinel_incidents SET state='awaiting_next_window' WHERE id=?")
        .run(input.incidentId);
      this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
        twin_ts: this.bank.now().toISOString(), type: "incident.updated",
        actor: { id: "harness", role: "system" }, area, incident_id: input.incidentId,
        public_summary_pt: "Contenção preservada após retomada da tarefa",
        public: { incident_id: input.incidentId, state: "awaiting_next_window" } });
    }
    const investigatorId = previousInvestigation?.actor_id ?? (this.runtime ?
      stageAgentId(this.events, input.roundId, "investigator", input.incidentId) :
      `investigator_${randomUUID()}`);
    const investigation = previousInvestigation ?
      { status: "ok" as const, data: incidentDossierBody.parse(previousInvestigation.payload) } :
      await loop.run({ runId: input.roundId, agentId: investigatorId,
      ...(input.deadlineAt ? { deadlineAt: input.deadlineAt } : {}),
      role: "investigator", goalPt: `Investigar sinais na área ${area}`,
      snapshot: { roundId: input.roundId, incidentId: input.incidentId, area },
      dossier: { incidentId: input.incidentId, regressionIds: input.regressionIds,
        ...(existingTask ? { openTask: existingTask } : {}) },
      dossierSchema: incidentDossierBody,
      validateDossier: (body) => body.incident_id === input.incidentId && body.area === area,
      tools: createInvestigatorTools({ bank: this.bank, events: this.events,
        incidentId: input.incidentId, agentId: investigatorId }) });
    if (investigation.status !== "ok" || !investigation.data) {
      this.remember(input.roundId, input.incidentId, "agent.failure", investigatorId,
        { role: "investigator", status: investigation.status });
      return this.defer(input.roundId, input.incidentId, area, undefined, 0,
        `investigator:${investigation.status}`);
    }
    if (!previousInvestigation) this.remember(input.roundId, input.incidentId,
      "dossier.investigation", investigatorId, investigation.data, undefined, investigatorId);
    if (investigation.data.disposition === "needs_human")
      return this.defer(input.roundId, input.incidentId, area, undefined, 0,
        "investigator:needs_human", true);
    if (investigation.data.disposition !== "incident" || !investigation.data.task)
      return { status: "no_task", attempts: 0 };
    const task = this.bank.db.prepare(`SELECT id,title,kind,priority,acceptance_json,
      do_not_break_json,regression_json FROM blue_tasks
      WHERE incident_id=? AND state='open' ORDER BY opened_at DESC LIMIT 1`).get(input.incidentId) as
      { id: string; title: string; kind: string; priority: number; acceptance_json: string;
        do_not_break_json: string; regression_json: string } | undefined;
    if (!task || task.title !== investigation.data.task.title ||
      task.kind !== investigation.data.task.kind ||
      task.priority !== investigation.data.task.priority ||
      JSON.stringify(investigation.data.task.acceptance_invariants) !== task.acceptance_json ||
      JSON.stringify(investigation.data.task.do_not_break) !== task.do_not_break_json ||
      JSON.stringify(input.regressionIds) !== task.regression_json)
      return this.defer(input.roundId, input.incidentId, area, task?.id, 0,
        "investigator_task_mismatch", true);
    if (!this.caseFile.history(input.incidentId).some((entry) =>
      entry.kind === "task.verified" && entry.payload.task_id === task.id))
      this.remember(input.roundId, input.incidentId, "task.verified", investigatorId,
        { task_id: task.id, title: task.title, kind: task.kind, priority: task.priority,
          regression_ids: input.regressionIds }, undefined, `task:${investigatorId}`);
    const context: PatchToolContext = { repoRoot: this.repoRoot, taskId: task.id,
      scope: { area: input.patchArea ?? area }, pipeline: this.pipeline, regressionIds: input.regressionIds,
      redFirstTestSource: input.redFirstTestSource, reproductionSymptoms: input.reproductionSymptoms };
    const savedMap = this.caseFile.history(input.incidentId).filter((entry) =>
      entry.kind === "dossier.incident_map" && entry.payload.task_id === task.id).at(-1);
    const mapperId = savedMap?.actor_id ?? (this.runtime ?
      stageAgentId(this.events, input.roundId, "forensic_mapper", task.id) :
      `forensic_mapper_${randomUUID()}`);
    const mapContext = { incidentId: input.incidentId, taskId: task.id, area,
      summary: investigation.data.summary.slice(0, 1200),
      timeline: investigation.data.timeline.slice(0, 8).map((item) => ({
        ts: item.ts.slice(0, 40), event_ref: item.event_ref.slice(0, 128),
        note: item.note.slice(0, 300) })),
      affectedEntities: investigation.data.affected_entities.slice(0, 16).map((item) => ({
        kind: item.kind.slice(0, 40), id: item.id.slice(0, 128) })),
      containmentActions: investigation.data.containment_actions.slice(0, 4).map((item) => ({
        tool: item.tool.slice(0, 80), call_id: item.call_id.slice(0, 128),
        expires_at: item.expires_at.slice(0, 40) })) };
    if (!savedMap) this.emit(input.roundId, "context.handoff", investigatorId, area,
      input.incidentId, task.id, { from: investigatorId, to: mapperId,
        dossier_kind: "IncidentMapRequest", summary_pt: "Mapeamento forense",
        context_sha256: IncidentCaseFile.digest(mapContext),
        inherited: ["investigation", "verified_task"] }, mapContext);
    let alertsRead = false;
    const mapped = savedMap ? { status: "ok" as const,
      data: incidentMapBody.parse(savedMap.payload) } : await loop.run({
      runId: input.roundId, agentId: mapperId, role: "forensic_mapper",
      ...(input.deadlineAt ? { deadlineAt: input.deadlineAt } : {}),
      goalPt: `Mapear evidências do incidente ${input.incidentId}`,
      snapshot: { roundId: input.roundId, incidentId: input.incidentId, area },
      dossier: mapContext, dossierSchema: incidentMapBody,
      validateDossier: (body) => alertsRead && body.incident_id === input.incidentId &&
        body.task_id === task.id && body.area === area &&
        (body.timeline.length > 0 || body.observed_stages.length > 0) &&
        body.evidence_refs.some((ref) => ref === `sentinel_incidents:${input.incidentId}` ||
          (ref.startsWith("sentinel_alerts:") && Boolean(this.bank.db.prepare(`SELECT 1 FROM sentinel_alerts a
            JOIN sentinel_incidents i ON i.id=? WHERE a.id=? AND a.entity=i.entity_key LIMIT 1`)
            .get(input.incidentId, ref.slice("sentinel_alerts:".length))))),
      tools: createForensicTools({ bank: this.bank, incidentId: input.incidentId,
        context: () => mapContext, onAlertsRead: () => { alertsRead = true; },
        ...(this.paymentMessages ? { paymentMessages: this.paymentMessages } : {}) }) });
    if (mapped.status !== "ok" || !mapped.data) {
      this.remember(input.roundId, input.incidentId, "agent.failure", mapperId,
        { role: "forensic_mapper", task_id: task.id, status: mapped.status });
      return this.defer(input.roundId, input.incidentId, area, task.id, 0,
        `forensic_mapper:${mapped.status}`);
    }
    if (!savedMap) this.remember(input.roundId, input.incidentId, "dossier.incident_map",
      mapperId, mapped.data, undefined, mapperId);
    const savedRootCause = this.caseFile.history(input.incidentId).filter((entry) =>
      entry.kind === "dossier.root_cause" && entry.payload.task_id === task.id).at(-1);
    const analystId = savedRootCause?.actor_id ?? (this.runtime ?
      stageAgentId(this.events, input.roundId, "root_cause_analyst", task.id) :
      `root_cause_analyst_${randomUUID()}`);
    const readScenarios = new Set<string>();
    const rootContext = { incidentId: input.incidentId, taskId: task.id, area,
      incidentMap: { timeline: mapped.data.timeline.slice(0, 12),
        entities: mapped.data.entities.slice(0, 12),
        indicators: mapped.data.indicators.slice(0, 12),
        observed_stages: mapped.data.observed_stages.slice(0, 8),
        scope: mapped.data.scope, evidence_refs: mapped.data.evidence_refs.slice(0, 20) },
      task: investigation.data.task,
      regressionIds: input.regressionIds,
      bankSideSymptoms: input.reproductionSymptoms.slice(0, 6) };
    if (!savedRootCause) this.emit(input.roundId, "context.handoff", mapperId, area,
      input.incidentId, task.id, { from: mapperId, to: analystId,
        dossier_kind: "RootCauseRequest", summary_pt: "Análise da causa raiz",
        context_sha256: IncidentCaseFile.digest(rootContext),
        inherited: ["incident_map", "verified_task", "regression_symptoms"] }, rootContext);
    const rootCause = savedRootCause ? { status: "ok" as const,
      data: rootCauseReportBody.parse(savedRootCause.payload) } : await loop.run({
      runId: input.roundId, agentId: analystId, role: "root_cause_analyst",
      ...(input.deadlineAt ? { deadlineAt: input.deadlineAt } : {}),
      goalPt: `Verificar causa raiz de ${task.title}`,
      snapshot: { roundId: input.roundId, incidentId: input.incidentId, area },
      dossier: rootContext, dossierSchema: rootCauseReportBody,
      validateDossier: (body) => body.incident_id === input.incidentId &&
        body.task_id === task.id && body.area === area &&
        (body.decision === "needs_human" || (body.flow_point !== null &&
          input.regressionIds.some((id) => readScenarios.has(id) &&
            body.evidence_refs.includes(`regression:${id}`)) &&
          body.evidence_refs.some((ref) => mapped.data!.evidence_refs.includes(ref)) &&
          isEditablePath(body.flow_point.path, context.scope) &&
          investigation.data!.task!.acceptance_invariants.every((item) =>
            body.violated_invariants.includes(item)) &&
          investigation.data!.task!.do_not_break.every((item) => body.do_not_break.includes(item)) &&
          input.regressionIds.every((id) => body.regression_ids.includes(id)))),
      tools: createRootCauseTools({ bank: this.bank, incidentId: input.incidentId,
        context: () => rootContext, patch: context,
        symptoms: input.reproductionSymptoms,
        onScenarioRead: (id) => readScenarios.add(id) }) });
    if (rootCause.status !== "ok" || !rootCause.data) {
      this.remember(input.roundId, input.incidentId, "agent.failure", analystId,
        { role: "root_cause_analyst", task_id: task.id, status: rootCause.status });
      return this.defer(input.roundId, input.incidentId, area, task.id, 0,
        `root_cause_analyst:${rootCause.status}`);
    }
    if (!savedRootCause) this.remember(input.roundId, input.incidentId, "dossier.root_cause",
      analystId, rootCause.data, undefined, analystId);
    if (rootCause.data.decision === "needs_human")
      return this.defer(input.roundId, input.incidentId, area, task.id, 0,
        "root_cause_analyst:needs_human", true);
    let priorRejections: string[] = [];
    const maxAttempts = Math.max(0, Math.min(12, input.maxAttempts ?? 4));
    const attemptHistory = this.caseFile.history(input.incidentId);
    const latestAttempt = attemptHistory
      .filter((entry) => entry.payload.task_id === task.id &&
        entry.attempt_no !== null)
      .reduce((max, entry) => Math.max(max, entry.attempt_no!), 0);
    if (this.runtime && latestAttempt > 0) {
      const interruptedRole = (["engineer", "reviewer"] as const).find((role) =>
        unfinishedStageAgentId(this.events, input.roundId, role,
          `${task.id}:${latestAttempt}`));
      if (interruptedRole)
        return this.defer(input.roundId, input.incidentId, area, task.id, 0,
          `interrupted_${interruptedRole}_requires_reconciliation`, true);
    }
    const interruptedArchitect = this.runtime && latestAttempt > 0 &&
      unfinishedStageAgentId(this.events, input.roundId, "architect",
        `${task.id}:${latestAttempt}`) &&
      !attemptHistory.some((entry) => entry.kind === "dossier.fix_design" &&
        entry.payload.task_id === task.id && entry.attempt_no === latestAttempt);
    const attemptBase = interruptedArchitect ? latestAttempt - 1 : latestAttempt;
    for (let attempt = attemptBase + 1; attempt <= attemptBase + maxAttempts; attempt++) {
      const used = attempt - attemptBase;
      if (resuming && !new BlueContainment(this.bank, this.events).hasActive(input.incidentId))
        return this.defer(input.roundId, input.incidentId, area, task.id,
          used - 1, "resumed_containment_expired", true);
      if ((this.bank.db.prepare("SELECT state FROM sentinel_incidents WHERE id=?")
        .get(input.incidentId) as { state: string }).state === "needs_human")
        return { status: "needs_human", taskId: task.id, attempts: used - 1,
          reason: "containment_lost" };
      if (input.deadlineAt && Date.now() >= input.deadlineAt)
        return this.defer(input.roundId, input.incidentId, area, task.id,
          used - 1, "round_deadline");
      this.remember(input.roundId, input.incidentId, "attempt.started", "harness",
        { task_id: task.id, attempt_no: attempt }, attempt,
        `attempt:${task.id}:${attempt}`);
      const architectId = this.runtime ? stageAgentId(this.events, input.roundId,
        "architect", `${task.id}:${attempt}`) : `architect_${randomUUID()}`;
      const architectContext = this.caseFile.architectContext(input.incidentId, task.id, attempt);
      this.emit(input.roundId, "context.handoff", analystId, area, input.incidentId, task.id,
        { from: analystId, to: architectId, dossier_kind: "ArchitectTask",
          summary_pt: "Desenho da correção", context_sha256: architectContext.sha256,
          inherited: architectContext.inherited }, architectContext.payload);
      const caseHistory = this.caseFile.history(input.incidentId);
      const previousDesigns = caseHistory.filter((entry) =>
        entry.kind === "dossier.fix_design" && entry.payload.task_id === task.id);
      const reviewReasons = caseHistory.filter((entry) =>
        entry.kind === "dossier.review" && entry.payload.task_id === task.id &&
        entry.payload.verdict === "reject").map((entry) =>
        JSON.stringify(entry.payload.reasons_for_rejection));
      const repeatedReason = reviewReasons.length >= 2 &&
        reviewReasons.at(-1) === reviewReasons.at(-2);
      const architect = await loop.run({ runId: input.roundId, agentId: architectId,
        role: "architect", goalPt: `Desenhar correção para ${task.title}`,
        ...(input.deadlineAt ? { deadlineAt: input.deadlineAt } : {}),
        snapshot: { roundId: input.roundId, area, attempt }, dossier: architectContext.payload,
        dossierSchema: fixDesignBody,
        validateDossier: (body) => body.task_id === task.id && body.attempt_no === attempt &&
          (body.decision === "needs_human" ||
            (body.allowed_paths.length > 0 && body.test_plan.length > 0 &&
              body.allowed_paths.every((path) => isEditablePath(path, context.scope)) &&
              investigation.data!.task!.acceptance_invariants.every((item) =>
                body.acceptance_invariants.includes(item)) &&
              investigation.data!.task!.do_not_break.every((item) =>
                body.do_not_break.includes(item)) &&
              input.regressionIds.every((id) => body.test_plan.some((item) => item.includes(id))) &&
              (!repeatedReason || previousDesigns.at(-1)?.payload.approach !== body.approach))),
        tools: createArchitectTools(context, () => architectContext.payload) });
      if (architect.status !== "ok" || !architect.data) {
        this.remember(input.roundId, input.incidentId, "agent.failure", architectId,
          { role: "architect", task_id: task.id, status: architect.status }, attempt);
        priorRejections.push(`Architect attempt ${attempt}: ${architect.status}`);
        continue;
      }
      this.remember(input.roundId, input.incidentId, "dossier.fix_design", architectId,
        architect.data, attempt, architectId);
      if (architect.data.decision === "needs_human") {
        this.bank.db.prepare("UPDATE sentinel_incidents SET state='needs_human' WHERE id=?")
          .run(input.incidentId);
        this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
          twin_ts: this.bank.now().toISOString(), type: "incident.updated",
          actor: { id: "harness", role: "system" }, area, incident_id: input.incidentId,
          public_summary_pt: "Incidente encaminhado para análise humana",
          public: { incident_id: input.incidentId, state: "needs_human" } });
        return { status: "needs_human", taskId: task.id, attempts: used,
          reason: architect.data.reason };
      }
      const engineerId = this.runtime ? stageAgentId(this.events, input.roundId,
        "engineer", `${task.id}:${attempt}`) : `engineer_${randomUUID()}`;
      const engineerContext = this.caseFile.builderContext(input.incidentId, task.id, attempt);
      const engineerDossier = engineerContext.payload;
      this.emit(input.roundId, "context.handoff", architectId, area, input.incidentId, task.id,
        { from: architectId, to: engineerId, dossier_kind: "PatchTask", summary_pt: "Tarefa de correção",
          context_sha256: engineerContext.sha256, inherited: engineerContext.inherited },
        engineerDossier);
      const engineerTools = createEngineerTools({ ...context,
        allowedPaths: architect.data.allowed_paths }).map((tool) => tool.name === "repo.apply_patch" ?
        { ...tool, execute: async (payload: unknown, signal: AbortSignal): Promise<unknown> => {
          const diff = (payload as { diff?: unknown })?.diff;
          if (typeof diff === "string") this.remember(input.roundId, input.incidentId,
            "patch.diff", engineerId, { task_id: task.id, sha256: IncidentCaseFile.digest(diff),
              diff: diff.slice(0, 128_000), truncated: diff.length > 128_000 }, attempt);
          try {
            const result = await tool.execute(payload, signal);
            if (result && typeof result === "object" &&
              (result as { ready?: unknown }).ready === false)
              this.remember(input.roundId, input.incidentId, "ci.failure", engineerId,
                { task_id: task.id, ...result }, attempt);
            return result;
          } catch (error) {
            this.remember(input.roundId, input.incidentId, "ci.failure", engineerId,
              { task_id: task.id, red_first: "error", typecheck: false, world_tests: false,
                failure_output: String(error).slice(-1000) }, attempt);
            throw error;
          }
        } } : tool);
      const engineer = await loop.run({ runId: input.roundId, agentId: engineerId, role: "engineer",
        ...(input.deadlineAt ? { deadlineAt: input.deadlineAt } : {}),
        goalPt: `Corrigir ${task.title}`, snapshot: { roundId: input.roundId, area, attempt },
        dossier: engineerDossier,
        dossierSchema: patchDossierBody,
        validateDossier: (body) => body.task_id === task.id && body.attempt_no === attempt &&
          body.targeted_test_runs.some((run) => {
            if (run.result !== "pass") return false;
            try { const details = this.pipeline.details(run.run_id);
              return details.taskId === task.id && details.headSha === body.head_sha &&
                details.result.readyForReview; }
            catch { return false; }
          }),
        tools: engineerTools });
      if (engineer.status !== "ok" || !engineer.data) {
        this.remember(input.roundId, input.incidentId, "agent.failure", engineerId,
          { role: "engineer", task_id: task.id, status: engineer.status }, attempt);
        priorRejections.push(`Engineer attempt ${attempt}: ${engineer.status}`); continue;
      }
      this.remember(input.roundId, input.incidentId, "dossier.candidate", engineerId,
        engineer.data, attempt, engineerId);
      const ciRun = engineer.data.targeted_test_runs.find((run) => {
        try { return this.pipeline.details(run.run_id).headSha === engineer.data?.head_sha; }
        catch { return false; }
      });
      if (!ciRun) {
        this.remember(input.roundId, input.incidentId, "agent.failure", engineerId,
          { role: "engineer", task_id: task.id, status: "ci_run_missing" }, attempt);
        priorRejections.push("CI run not found for exact candidate"); continue;
      }
      this.remember(input.roundId, input.incidentId, "ci.result", engineerId,
        { task_id: task.id, run_id: ciRun.run_id,
          result: this.pipeline.details(ciRun.run_id).result },
        attempt, ciRun.run_id);
      const reviewerId = this.runtime ? stageAgentId(this.events, input.roundId,
        "reviewer", `${task.id}:${attempt}`) : `reviewer_${randomUUID()}`;
      const reviewerContext = this.caseFile.reviewerContext(input.incidentId, task.id, attempt);
      const reviewerDossier = reviewerContext.payload;
      this.emit(input.roundId, "context.handoff", engineerId, area, input.incidentId, task.id,
        { from: engineerId, to: reviewerId, dossier_kind: "ReviewRequest", summary_pt: "Patch em revisão",
          context_sha256: reviewerContext.sha256, inherited: reviewerContext.inherited },
        reviewerDossier);
      const reviewer = await loop.run({ runId: input.roundId, agentId: reviewerId, role: "reviewer",
        ...(input.deadlineAt ? { deadlineAt: input.deadlineAt } : {}),
        goalPt: "Revisar correção e testes no commit exato", snapshot: { roundId: input.roundId, area, attempt },
        dossier: reviewerDossier, dossierSchema: reviewVerdictBody,
        validateDossier: (body) => body.task_id === task.id && body.attempt_no === attempt &&
          body.head_sha === engineer.data?.head_sha &&
          (body.verdict === "reject" || (
            body.runs.regression_run_id === ciRun.run_id &&
            body.runs.honest_run_id === ciRun.run_id &&
            body.runs.scope_check_run_id === ciRun.run_id &&
            body.runs.regression.passed === body.runs.regression.total &&
            body.runs.honest.passed === body.runs.honest.total &&
            body.runs.honest.false_positive_rate === 0 &&
            !body.findings.some((finding) => finding.severity === "blocker") &&
            this.pipeline.state(ciRun.run_id) === "approved")),
        tools: createReviewerTools({ ...context, reviewerId }) });
      if (reviewer.status !== "ok" || !reviewer.data) {
        this.remember(input.roundId, input.incidentId, "agent.failure", reviewerId,
          { role: "reviewer", task_id: task.id, status: reviewer.status }, attempt);
        priorRejections.push(`Reviewer attempt ${attempt}: ${reviewer.status}`); continue;
      }
      this.remember(input.roundId, input.incidentId, "dossier.review", reviewerId,
        reviewer.data, attempt, reviewerId);
      if (reviewer.data.verdict === "reject") {
        const reasons = reviewer.data.reasons_for_rejection.length ?
          reviewer.data.reasons_for_rejection : ["Reviewer rejected candidate"];
        priorRejections.push(reasons.join("; "));
        this.remember(input.roundId, input.incidentId, "dossier.rejection_report", reviewerId,
          { task_id: task.id, findings: reviewer.data.findings,
            reasons_for_rejection: reasons, required_changes: reviewer.data.required_changes,
            head_sha: reviewer.data.head_sha }, attempt, `rejection:${reviewerId}`);
        this.emit(input.roundId, "review.rejected", reviewerId, area, input.incidentId, task.id,
          { task_id: task.id, attempt, reason_pt: reasons[0], failing_suites: [] });
        continue;
      }
      const runId = ciRun.run_id;
      if (resuming && !new BlueContainment(this.bank, this.events).hasActive(input.incidentId))
        return this.defer(input.roundId, input.incidentId, area, task.id,
          used, "resumed_containment_expired", true);
      if ((this.bank.db.prepare("SELECT state FROM sentinel_incidents WHERE id=?")
        .get(input.incidentId) as { state: string }).state === "needs_human")
        return { status: "needs_human", taskId: task.id, attempts: used,
          reason: "containment_lost" };
      if (input.deadlineAt && Date.now() >= input.deadlineAt)
        return this.defer(input.roundId, input.incidentId, area, task.id,
          used, "round_deadline");
      this.emit(input.roundId, "review.approved", reviewerId, area, input.incidentId, task.id,
        { task_id: task.id, attempt, ci_run_id: runId,
          checks: { typecheck: "pass", red_first: "pass", honest: "pass" } });
      const headSha = this.pipeline.merge(runId);
      const patchKind = this.pipeline.details(runId).result.inspection.kind === "rule" ? "rule" : "code";
      this.emit(input.roundId, "patch.merged", "harness", area, input.incidentId, task.id,
        { task_id: task.id, commit_short: headSha.slice(0, 7), kind: patchKind });
      this.caseFile.syncEvents(input.incidentId);
      this.remember(input.roundId, input.incidentId, "merge.verified", "harness",
        { task_id: task.id, ci_run_id: runId, head_sha: headSha }, attempt, `merge:${runId}`);
      this.bank.db.prepare("UPDATE blue_tasks SET state='merged' WHERE id=?").run(task.id);
      return { status: "merged", taskId: task.id, ciRunId: runId, headSha, attempts: used };
    }
    return this.defer(input.roundId, input.incidentId, area, task.id, maxAttempts,
      priorRejections.at(-1) ?? "attempt_cap");
  }
}
