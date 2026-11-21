import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { hardeningProposalBody, hardeningReviewBody } from "../../../packages/contracts/src/dossiers.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { Bank } from "../../world/src/bank.ts";
import { evaluateRiskRules, loadRules } from "../../world/src/risk/engine.ts";
import type { AgentTransport } from "./agent-loop.ts";
import { BudgetLedger } from "./budget.ts";
import { agentExecutor, type AgentRuntime } from "./runtime/agent-runtime.ts";
import { stageAgentId } from "./runtime/stage-agent-id.ts";
import { collectPixHardeningEvidence } from "./hardening-evidence.ts";
import type { RiskSample } from "./hardening-evidence.ts";
import { PatchCiFailure, type PatchPipeline } from "./patch-pipeline.ts";

type Proposal = ReturnType<typeof hardeningProposalBody.parse>;
export type HardeningPlan = { status: "proven"; proposal: Proposal;
  attackDecisionIds: string[]; honestSampleCount: number;
  attackSamples: RiskSample[]; honestSamples: RiskSample[] } |
  { status: "needs_human"; reason: string };
export type HardeningRunResult = { status: "merged"; taskId: string; runId: string;
  headSha: string; ruleId: string } | { status: "needs_human"; reason: string };

export function hardeningRuleContext(rules: ReturnType<typeof loadRules>["rules"]) {
  return rules.map((rule) => ({ id: rule.id, feature: rule.feature,
    operator: rule.operator, value: rule.value, points: rule.points, reason: rule.reason,
    mode: rule.mode ?? "active",
    ...(rule.all ? { all: rule.all.map((condition) => ({ ...condition })) } : {}),
    ...(rule.any ? { any: rule.any.map((condition) => ({ ...condition })) } : {}) }));
}

function candidateDiff(path: string, rule: NonNullable<Proposal["rule"]>): string {
  const lines = JSON.stringify({ version: 1, rules: [{ ...rule, mode: "shadow" }] }, null, 2).split("\n");
  return [`diff --git a/${path} b/${path}`, "new file mode 100644",
    `--- /dev/null`, `+++ b/${path}`, `@@ -0,0 +1,${lines.length} @@`,
    ...lines.map((line) => `+${line}`), ""].join("\n");
}

function proofSource(plan: Extract<HardeningPlan, { status: "proven" }>): string {
  const current = loadRules("pix");
  const rank = { approve: 0, step_up: 1, hold: 2, decline: 3 } as const;
  const attack = plan.attackSamples.slice(0, 10).map((item) => ({ features: item.features,
    baseline: rank[evaluateRiskRules(current, item.features).outcome] }));
  const honest = plan.honestSamples.slice(0, 20).map((item) => item.features);
  const ruleId = plan.proposal.rule!.id;
  return `import { test } from "node:test";
import assert from "node:assert/strict";
import { loadRules, evaluateRiskRules } from "../apps/world/src/risk/engine.ts";
test("captured risk decisions receive an earlier intervention without honest false blocks", () => {
  const loaded = loadRules("pix");
  const candidate = loaded.rules.find((rule) => rule.id === ${JSON.stringify(ruleId)});
  assert.equal(candidate?.mode, "shadow");
  const rules = { ...loaded, rules: loaded.rules.map((rule) =>
    rule.id === ${JSON.stringify(ruleId)} ? { ...rule, mode: "active" } : rule) };
  const ranks = { approve: 0, step_up: 1, hold: 2, decline: 3 };
  for (const item of ${JSON.stringify(attack)})
    assert.ok(ranks[evaluateRiskRules(rules, item.features).outcome] > item.baseline);
  for (const features of ${JSON.stringify(honest)})
    assert.equal(evaluateRiskRules(rules, features).outcome, "approve");
});
`;
}

export class HardeningChain {
  private readonly bank: Bank;
  private readonly events: EventStore;
  private readonly budget: BudgetLedger | undefined;
  private readonly transport: AgentTransport | undefined;
  private readonly runtime: AgentRuntime | undefined;
  constructor(bank: Bank, events: EventStore, budget?: BudgetLedger,
    transport?: AgentTransport, runtime?: AgentRuntime) {
    this.bank = bank; this.events = events; this.budget = budget;
    this.transport = transport; this.runtime = runtime;
  }

  async plan(input: { roundId: string; incidentId: string; deadlineAt?: number }): Promise<HardeningPlan> {
    const incident = this.bank.db.prepare("SELECT area,opened_at FROM sentinel_incidents WHERE id=?")
      .get(input.incidentId) as { area: string; opened_at: string } | undefined;
    if (incident?.area !== "pix") return { status: "needs_human", reason: "unsupported_area" };
    this.events.caseFile.open(input.incidentId, "pix", incident.opened_at);
    const evidence = collectPixHardeningEvidence(this.bank, input.incidentId);
    if (evidence.attackTruncated || evidence.affectedHonestTruncated)
      return { status: "needs_human", reason: "risk_evidence_truncated" };
    if (evidence.ambiguousTransferIds.length)
      return { status: "needs_human", reason: "risk_decision_ambiguous" };
    if (!evidence.attack.length || !evidence.honest.length)
      return { status: "needs_human", reason: "risk_evidence_missing" };
    const priorRejections = this.events.caseFile.history(input.incidentId)
      .filter((entry) => entry.kind === "hardening.rejection")
      .map((entry) => entry.payload).slice(-4);
    const current = loadRules("pix");
    const loop = agentExecutor(this.events, this.budget, this.runtime, this.transport);
    const agentId = this.runtime ? stageAgentId(this.events, input.roundId,
      "hardening", `${input.incidentId}:${priorRejections.length}`) :
      `hardening_${randomUUID()}`;
    const result = await loop.run({ runId: input.roundId, agentId, role: "hardening",
      goalPt: "Propor uma regra de risco defensiva para o incidente Pix verificado",
      ...(input.deadlineAt ? { deadlineAt: input.deadlineAt } : {}),
      snapshot: { incidentId: input.incidentId, area: "pix" },
      dossier: { incidentId: input.incidentId,
        currentRules: hardeningRuleContext(current.rules),
        thresholds: current.thresholds,
        attack: evidence.attack.map((item) => ({ decisionId: item.decisionId,
          outcome: item.outcome, features: item.features })),
        honest: evidence.honest.slice(0, 20).map((item) => ({ decisionId: item.decisionId,
          features: item.features })), priorRejections },
      dossierSchema: hardeningProposalBody, tools: [] });
    if (result.status !== "ok" || !result.data)
      return { status: "needs_human", reason: `agent_${result.status}` };
    const proposal = result.data;
    this.events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
      kind: "dossier.hardening", actorId: agentId,
      createdAt: this.bank.realNow().toISOString(), payload: proposal });
    if (proposal.incident_id !== input.incidentId || proposal.decision !== "propose" ||
      !proposal.rule) return { status: "needs_human", reason: "proposal_declined" };
    const cited = new Set(proposal.evidence_decision_ids);
    if (cited.size !== evidence.attack.length || evidence.attack.some((item) =>
      !cited.has(item.decisionId)))
      return { status: "needs_human", reason: "evidence_mismatch" };
    if (current.rules.some((rule) => rule.id === proposal.rule!.id) ||
      !evidence.attack.every((item) => proposal.rule!.feature in item.features) ||
      !evidence.honest.every((item) => proposal.rule!.feature in item.features))
      return { status: "needs_human", reason: "rule_feature_invalid" };
    if (priorRejections.some((item) => {
      const prior = item.prior_rule as Partial<NonNullable<Proposal["rule"]>> | undefined;
      return prior?.feature === proposal.rule!.feature &&
        prior?.operator === proposal.rule!.operator && prior?.value === proposal.rule!.value &&
        prior?.points === proposal.rule!.points;
    }))
      return { status: "needs_human", reason: "hardening_proposal_repeated" };
    const candidate = { ...current, rules: [...current.rules, proposal.rule] };
    const rank = { approve: 0, step_up: 1, hold: 2, decline: 3 } as const;
    const improved = evidence.attack.every((item) => {
      const before = evaluateRiskRules(current, item.features).outcome;
      const after = evaluateRiskRules(candidate, item.features).outcome;
      return rank[after] > rank[before];
    });
    const honestSafe = evidence.honest.every((item) =>
      evaluateRiskRules(candidate, item.features).outcome === "approve");
    if (!improved || !honestSafe)
      return { status: "needs_human", reason: !improved ? "no_earlier_intervention" :
        "honest_false_block" };
    this.events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
      kind: "hardening.proof", actorId: "hardening-verifier",
      createdAt: this.bank.realNow().toISOString(), payload: {
        rule_id: proposal.rule.id,
        attack_decision_ids: evidence.attack.map((item) => item.decisionId),
        honest_sample_count: evidence.honest.length,
        all_attack_decisions_improved: true, honest_false_blocks: 0,
        attack_samples: evidence.attack.map((item) => ({ decision_id: item.decisionId,
          outcome: item.outcome, features: item.features })),
        honest_samples: evidence.honest.map((item) => ({ decision_id: item.decisionId,
          features: item.features })) } });
    return { status: "proven", proposal,
      attackDecisionIds: evidence.attack.map((item) => item.decisionId),
      honestSampleCount: evidence.honest.length,
      attackSamples: evidence.attack, honestSamples: evidence.honest };
  }

  verify(incidentId: string, ruleId: string, ruleDirectory?: string): boolean {
    const proof = this.events.caseFile.history(incidentId).filter((entry) =>
      entry.kind === "hardening.proof" && entry.payload.rule_id === ruleId).at(-1);
    if (!proof) return false;
    const attack = proof.payload.attack_samples;
    const honest = proof.payload.honest_samples;
    if (!Array.isArray(attack) || !attack.length || !Array.isArray(honest) || !honest.length)
      return false;
    const loaded = loadRules("pix", ruleDirectory);
    if (!loaded.rules.some((rule) => rule.id === ruleId && rule.mode === "shadow")) return false;
    const config = { ...loaded, rules: loaded.rules.map((rule) =>
      rule.id === ruleId ? { ...rule, mode: "active" as const } : rule) };
    const rank: Record<string, number> = { approve: 0, step_up: 1, hold: 2, decline: 3 };
    return attack.every((value) => {
      const item = value as { outcome: string; features: Record<string, number> };
      return (rank[evaluateRiskRules(config, item.features).outcome] ?? 0) >
        (rank[item.outcome] ?? 0);
    }) && honest.every((value) => {
      const item = value as { features: Record<string, number> };
      return evaluateRiskRules(config, item.features).outcome === "approve";
    });
  }

  async run(input: { roundId: string; incidentId: string; repoRoot: string;
    pipeline: Pick<PatchPipeline, "evaluate" | "approve" | "merge">;
    deadlineAt?: number }): Promise<HardeningRunResult> {
    const priorRejections = this.events.caseFile.history(input.incidentId)
      .filter((entry) => entry.kind === "hardening.rejection");
    const attemptNo = priorRejections.length + 1;
    if (attemptNo > 4)
      return { status: "needs_human", reason: "hardening_attempt_cap" };
    const planned = await this.plan(input);
    if (planned.status !== "proven") return planned;
    const rule = planned.proposal.rule!;
    const suffix = createHash("sha256").update(input.incidentId).digest("hex").slice(0, 12);
    const path = `rules/pix/hardening-${suffix}.json`;
    if (existsSync(join(input.repoRoot, path)))
      return { status: "needs_human", reason: "hardening_rule_exists" };
    const source = proofSource(planned);
    if (Buffer.byteLength(source) > 16_384)
      return { status: "needs_human", reason: "hardening_proof_too_large" };
    const diff = candidateDiff(path, rule);
    const taskId = `task_hardening_${suffix}`;
    this.bank.db.exec(`CREATE TABLE IF NOT EXISTS blue_tasks (
      id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, actor_id TEXT NOT NULL,
      title TEXT NOT NULL, kind TEXT NOT NULL, priority INTEGER NOT NULL,
      acceptance_json TEXT NOT NULL, do_not_break_json TEXT NOT NULL,
      regression_json TEXT NOT NULL, state TEXT NOT NULL, opened_at TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS blue_tasks_one_open ON blue_tasks(incident_id)
      WHERE state='open';`);
    const existing = this.bank.db.prepare("SELECT state FROM blue_tasks WHERE id=?")
      .get(taskId) as { state: string } | undefined;
    if (existing?.state === "merged")
      return { status: "needs_human", reason: "hardening_already_merged" };
    if (!existing) {
      this.bank.db.prepare("INSERT INTO blue_tasks VALUES (?,?,?,?,?,?,?,?,?,'open',?)")
        .run(taskId, input.incidentId, "hardening", "Add earlier inline risk detection",
          "patch_rule", 2, JSON.stringify(["Captured risk decisions intervene earlier"]),
          JSON.stringify(["Honest approvals remain unaffected"]),
          JSON.stringify(planned.attackDecisionIds), this.bank.now().toISOString());
      this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
        twin_ts: this.bank.now().toISOString(), type: "task.opened",
        actor: { id: "hardening", role: "hardening" }, area: "pix",
        incident_id: input.incidentId, task_id: taskId,
        public_summary_pt: "Tarefa de detecção antecipada aberta",
        public: { task_id: taskId, incident_id: input.incidentId,
          title_pt: "Nova regra de detecção Pix", area: "pix", severity: "medium" } });
    }
    let evaluated: Awaited<ReturnType<PatchPipeline["evaluate"]>>;
    try {
      evaluated = await input.pipeline.evaluate({ taskId, diff,
        scope: { area: "pix", maxFiles: 1, maxChangedLines: 80 },
        redFirstTestSource: source });
    } catch (error) {
      const reason = error instanceof PatchCiFailure ? "hardening_ci_failed" :
        error instanceof Error ? error.message : "hardening_ci_error";
      this.events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
        kind: "hardening.ci_failure", actorId: "patch-ci",
        createdAt: this.bank.realNow().toISOString(), payload: { task_id: taskId, reason } });
      return { status: "needs_human", reason };
    }
    const { runId, result: ci } = evaluated;
    this.events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
      kind: "hardening.ci", actorId: "patch-ci",
      createdAt: this.bank.realNow().toISOString(), payload: {
        task_id: taskId, run_id: runId, head_sha: ci.headSha,
        red_first: ci.redFirst, typecheck: ci.typecheck.ok,
        world_tests: ci.worldTests?.ok ?? false } });
    const reviewerId = `hardening_reviewer_${randomUUID()}`;
    const loop = agentExecutor(this.events, this.budget, this.runtime, this.transport);
    const reviewed = await loop.run({ runId: input.roundId, agentId: reviewerId,
      role: "reviewer", goalPt: "Revisar a regra defensiva e a prova exata do CI",
      ...(input.deadlineAt ? { deadlineAt: input.deadlineAt } : {}),
      system: ["You are an independent defensive code reviewer. Review the exact candidate and CI evidence.",
        "Approve only if the captured decisions improve, honest decisions remain approved, and the diff changes only the intended rule. Reject uncertainty. Return a HardeningReview dossier."],
      snapshot: { incidentId: input.incidentId, taskId, runId, headSha: ci.headSha },
      dossier: { proposal: planned.proposal, diff, ci: { redFirst: ci.redFirst,
        typecheck: ci.typecheck.ok, worldTests: ci.worldTests?.ok ?? false },
        attackDecisionIds: planned.attackDecisionIds,
        honestSampleCount: planned.honestSampleCount },
      dossierSchema: hardeningReviewBody, tools: [] });
    if (reviewed.status !== "ok" || !reviewed.data)
      return { status: "needs_human", reason: `reviewer_${reviewed.status}` };
    const review = reviewed.data;
    this.events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
      kind: "dossier.hardening_review", actorId: reviewerId,
      createdAt: this.bank.realNow().toISOString(), payload: review });
    if (review.incident_id !== input.incidentId || review.task_id !== taskId ||
      review.run_id !== runId || review.head_sha !== ci.headSha ||
      review.evidence_checked.length !== planned.attackDecisionIds.length ||
      planned.attackDecisionIds.some((id) => !review.evidence_checked.includes(id)) ||
      !review.honest_impact_checked || review.verdict !== "approve") {
      const reason = review.verdict === "reject" ? "reviewer_rejected" :
        "review_evidence_mismatch";
      this.events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
        kind: "hardening.rejection", actorId: reviewerId,
        entryKey: `hardening:rejection:${input.incidentId}:${attemptNo}`,
        createdAt: this.bank.realNow().toISOString(), payload: {
          task_id: taskId, attempt_no: attemptNo, reason,
          prior_rule: rule, reviewer_rationale: review.rationale } });
      this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
        twin_ts: this.bank.now().toISOString(), type: "review.rejected",
        actor: { id: reviewerId, role: "reviewer" }, area: "pix",
        incident_id: input.incidentId, task_id: taskId,
        public_summary_pt: "Regra de hardening reprovada",
        public: { task_id: taskId, attempt: attemptNo,
          reason_pt: "Prova ou revisão insuficiente", failing_suites: [] } },
      `hardening:review-rejected:${input.incidentId}:${attemptNo}`);
      return attemptNo < 4 ? this.run(input) :
        { status: "needs_human", reason: "hardening_attempt_cap" };
    }
    input.pipeline.approve({ runId, taskId, headSha: ci.headSha!, reviewerId });
    this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
      twin_ts: this.bank.now().toISOString(), type: "review.approved",
      actor: { id: reviewerId, role: "reviewer" }, area: "pix",
      incident_id: input.incidentId, task_id: taskId,
      public_summary_pt: "Regra de hardening aprovada",
      public: { task_id: taskId, attempt: attemptNo, ci_run_id: runId,
        checks: { captured: "pass", honest: "pass", scope: "pass" } } });
    const headSha = input.pipeline.merge(runId);
    this.bank.db.prepare("UPDATE blue_tasks SET state='merged' WHERE id=?").run(taskId);
    this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
      twin_ts: this.bank.now().toISOString(), type: "patch.merged",
      actor: { id: reviewerId, role: "reviewer" }, area: "pix",
      incident_id: input.incidentId, task_id: taskId,
      public_summary_pt: "Nova regra de detecção mesclada",
      public: { task_id: taskId, commit_short: headSha.slice(0, 12), kind: "rule",
        phase: "hardening" },
      private: { run_id: runId, rule_id: rule.id, path } });
    return { status: "merged", taskId, runId, headSha, ruleId: rule.id };
  }
}
