import { Codex, type CodexOptions } from "@openai/codex-sdk";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, rmSync, rmdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { EventStore } from "../../../../packages/event-store/src/index.ts";
import { sanitizeDossier, systemForRole } from "../../../../packages/prompts/src/index.ts";
import { ROLE_TOOLS, type AgentResult, type AgentSpec } from "../agent-loop.ts";
import type { AgentRuntime } from "./agent-runtime.ts";
import { UsageLedger } from "./usage-ledger.ts";
import { AgentQueue, type AgentPriority } from "./agent-queue.ts";
import { RoleToolBroker } from "../mcp/role-broker.ts";
import { CodexQuotaGate } from "./quota-gate.ts";

type CodexClient = Pick<Codex, "startThread" | "resumeThread">;
const forbidden = new Set(["command_execution", "file_change", "web_search"]);
const toolRoles = new Set(["investigator", "forensic_mapper", "root_cause_analyst",
  "architect", "engineer", "damage_assessor", "restorer", "reviewer"]);
const resumableRoles = new Set([...toolRoles, "hardening", "postmortem", "product", "narrator"]);
const cliEnvironmentKeys = ["PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL", "TERM",
  "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
  "https_proxy", "http_proxy", "no_proxy"] as const;
const roleLimits: Record<AgentSpec<unknown>["role"], { wallMs: number; toolCalls: number }> = {
  investigator: { wallMs: 90_000, toolCalls: 20 },
  forensic_mapper: { wallMs: 90_000, toolCalls: 12 },
  root_cause_analyst: { wallMs: 150_000, toolCalls: 12 },
  architect: { wallMs: 180_000, toolCalls: 15 },
  engineer: { wallMs: 600_000, toolCalls: 20 },
  reviewer: { wallMs: 300_000, toolCalls: 10 },
  damage_assessor: { wallMs: 60_000, toolCalls: 15 },
  restorer: { wallMs: 90_000, toolCalls: 20 },
  hardening: { wallMs: 90_000, toolCalls: 0 },
  postmortem: { wallMs: 60_000, toolCalls: 0 },
  product: { wallMs: 45_000, toolCalls: 2 },
  narrator: { wallMs: 75_000, toolCalls: 0 },
};

function modelFor(role: string): string | undefined {
  if (role === "reviewer" && process.env.CODEX_MODEL_REVIEWER)
    return process.env.CODEX_MODEL_REVIEWER;
  const strong = new Set(["root_cause_analyst", "architect", "engineer", "reviewer", "hardening"]);
  return process.env[strong.has(role) ? "CODEX_MODEL_STRONG" : "CODEX_MODEL_FAST"] || undefined;
}
function effortFor(role: string) {
  const value = process.env[`CODEX_REASONING_${role.toUpperCase()}`];
  if (!value) return role === "reviewer" ? "high" : role === "engineer" ? "medium" : undefined;
  if (!["minimal", "low", "medium", "high", "xhigh", "max", "ultra", "persistent"].includes(value))
    throw new Error("CODEX_REASONING_INVALID");
  return value as "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | "ultra" | "persistent";
}
function priorityFor(role: string): AgentPriority {
  if (["investigator", "forensic_mapper", "root_cause_analyst", "architect",
    "engineer", "reviewer", "hardening", "product"].includes(role)) return 1;
  if (["damage_assessor", "restorer", "postmortem", "narrator"].includes(role)) return 2;
  return 4;
}

export class CodexRuntime implements AgentRuntime {
  private readonly client: CodexClient;
  private readonly events: EventStore;
  private readonly agentsDir: string;
  readonly usage: UsageLedger;
  readonly quota: CodexQuotaGate;
  readonly queue: AgentQueue;
  private readonly broker: RoleToolBroker;
  private readonly manifestsDir: string;
  private readonly codexOptions: CodexOptions;
  private readonly activeAgents = new Set<string>();
  constructor(input: { events: EventStore; dataDir: string; client?: CodexClient;
    codexHome?: string; codexBin?: string; queue?: AgentQueue;
    usageCaps?: ConstructorParameters<typeof UsageLedger>[1] }) {
    this.events = input.events;
    this.usage = new UsageLedger(input.events, input.usageCaps);
    this.quota = new CodexQuotaGate(input.events);
    this.queue = input.queue ?? new AgentQueue();
    this.broker = new RoleToolBroker(resolve(input.dataDir), input.events);
    this.agentsDir = resolve(input.dataDir, "agents");
    this.manifestsDir = resolve(input.dataDir, "mcp-manifests");
    mkdirSync(this.agentsDir, { recursive: true });
    mkdirSync(this.manifestsDir, { recursive: true });
    const home = resolve(input.codexHome || process.env.CODEX_HOME || join(homedir(), ".codex"));
    const environment = Object.fromEntries(cliEnvironmentKeys.flatMap((key) =>
      process.env[key] === undefined ? [] : [[key, process.env[key]!]]));
    environment.CODEX_HOME = home;
    environment.CODEX_BIN = input.codexBin || process.env.CODEX_BIN || "codex";
    this.codexOptions = { codexPathOverride: fileURLToPath(
      new URL("../../../../scripts/codex-isolated-cli.sh", import.meta.url)),
      env: environment, config: { features: { shell_tool: false }, web_search: "disabled",
        approval_policy: "never", project_root_markers: [] } };
    this.client = input.client ?? new Codex(this.codexOptions);
  }
  async close(): Promise<void> { await this.broker.close(); }
  private emit<T>(spec: AgentSpec<T>, type: "agent.spawned" | "agent.finished" | "integrity.violation",
    summary: string, payload: Record<string, unknown>, privatePayload?: Record<string, unknown>): void {
    this.events.append({ round_id: spec.runId, ts: new Date().toISOString(), type,
      actor: { id: spec.agentId, role: spec.role }, public_summary_pt: summary, public: payload,
      ...(privatePayload ? { private: privatePayload } : {}) });
  }
  async run<T>(spec: AgentSpec<T>): Promise<AgentResult<T>> {
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(spec.agentId)) throw new Error("AGENT_ID_INVALID");
    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(spec.runId)) throw new Error("RUN_ID_INVALID");
    if (spec.tools.length && (!toolRoles.has(spec.role) ||
      spec.tools.some((tool) => !ROLE_TOOLS[spec.role].has(tool.name)) ||
      new Set(spec.tools.map((tool) => tool.name)).size !== spec.tools.length))
      throw new Error("AGENT_TOOL_SCOPE");
    if (spec.role === "reviewer" && modelFor("reviewer") === modelFor("engineer") &&
      effortFor("reviewer") === effortFor("engineer"))
      throw new Error("REVIEWER_NOT_INDEPENDENT");
    const system = spec.system ?? systemForRole(spec.role);
    const prompt = `${system[0]}\n${system[1]}\n\nGoal: ${spec.goalPt}\n\nSnapshot:\n` +
      `${JSON.stringify(sanitizeDossier(spec.snapshot))}\n\nDossier:\n` +
      `${JSON.stringify(sanitizeDossier(spec.dossier))}`;
    const promptHash = createHash("sha256").update(JSON.stringify({ role: spec.role,
      prompt, tools: spec.tools.map((tool) => tool.name) })).digest("hex");
    const existing = this.usage.session(spec.runId, spec.agentId);
    if (existing && (existing.role !== spec.role || existing.promptHash !== promptHash))
      return { status: "failed", reason: "agent_session_conflict", tokens: 0 };
    if (existing && existing.status !== null) {
      if (existing.status === "ok" && spec.tools.length === 0 &&
        resumableRoles.has(spec.role)) {
        const cached = spec.dossierSchema.safeParse(this.usage.completedResult(
          spec.runId, spec.agentId, promptHash));
        if (cached.success && await spec.validateDossier?.(cached.data) !== false)
          return { status: "ok", data: cached.data, tokens: 0 };
      }
      return { status: "failed", reason: "agent_session_conflict", tokens: 0 };
    }
    const roleLimit = roleLimits[spec.role];
    const deadline = Math.min(spec.deadlineAt ?? Infinity, Date.now() + roleLimit.wallMs);
    if (Date.now() >= deadline) return { status: "timeout", reason: "run_deadline", tokens: 0 };
    if (this.quota.resumeAt()) return { status: "budget", reason: "codex_quota_pause", tokens: 0 };
    const activeKey = `${spec.runId}:${spec.agentId}`;
    if (this.activeAgents.has(activeKey))
      return { status: "failed", reason: "agent_already_running", tokens: 0 };
    if (existing && !resumableRoles.has(spec.role))
      return { status: "failed", reason: "thread_resume_unavailable", tokens: 0 };
    if (existing && this.broker.hasUncertainCall(spec.runId, spec.agentId))
      return { status: "failed", reason: "uncertain_tool_call", tokens: 0 };
    if (existing && this.broker.hasNonReadCall(spec.runId, spec.agentId))
      return { status: "failed", reason: "non_idempotent_tool_call", tokens: 0 };
    if (existing && !existing.threadId &&
      this.usage.hasRecordedTurn(spec.runId, spec.agentId))
      return { status: "failed", reason: "thread_resume_unavailable", tokens: 0 };
    if (existing && !this.usage.canContinue(spec.runId, spec.role))
      return { status: "budget", reason: "usage_cap", tokens: 0 };
    const runDir = join(this.agentsDir, spec.runId);
    mkdirSync(runDir, { recursive: true });
    const workdir = join(runDir, spec.agentId);
    if (existing) {
      if (!existsSync(workdir))
        return { status: "failed", reason: "thread_workdir_missing", tokens: 0 };
    } else {
      if (existsSync(workdir))
        return { status: "failed", reason: "thread_workdir_orphaned", tokens: 0 };
      mkdirSync(workdir, { recursive: false });
      if (!this.usage.tryStart(spec.runId, spec.agentId, spec.role, promptHash)) {
        rmdirSync(workdir);
        return { status: "budget", reason: "usage_cap", tokens: 0 };
      }
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error("wall_clock")), deadline - Date.now());
    const finalSchema = z.strictObject({ body: spec.dossierSchema,
      public_summary_pt: z.string().max(160), confidence: z.number().min(0).max(1),
      escalation: z.string().max(500).nullable() });
    let tokens = 0;
    let result: AgentResult<T> = { status: "failed", reason: "no_response", tokens: 0 };
    let release: (() => void) | undefined;
    let token: string | undefined;
    let manifest: string | undefined;
    this.activeAgents.add(activeKey);
    try {
      const model = modelFor(spec.role);
      const effort = effortFor(spec.role);
      release = await this.queue.acquire(priorityFor(spec.role), controller.signal);
      let client = this.client;
      if (spec.tools.length) {
        await this.broker.start();
        token = this.broker.register({ ...spec,
          maxToolCalls: Math.min(spec.maxToolCalls ?? roleLimit.toolCalls,
            roleLimit.toolCalls) }, controller.signal);
        manifest = join(this.manifestsDir, `${spec.runId}-${spec.agentId}.json`);
        writeFileSync(manifest, JSON.stringify({ tools: spec.tools.map((tool) => ({
          name: tool.name, description: tool.description,
          inputSchema: z.toJSONSchema(tool.schema),
        })) }), { mode: 0o600, flag: existing ? "w" : "wx" });
        client = new Codex({ ...this.codexOptions, config: {
          ...this.codexOptions.config,
          mcp_servers: { banco_vivo_role: { command: process.execPath,
            args: ["--experimental-strip-types", fileURLToPath(new URL("../mcp/role-server.ts", import.meta.url)),
              "--socket", this.broker.socketPath, "--agent", spec.agentId,
              "--token", token, "--manifest", manifest], required: true,
            default_tools_approval_mode: "approve" } },
        } });
      }
      const threadOptions = { workingDirectory: workdir, skipGitRepoCheck: true,
        sandboxMode: "read-only", approvalPolicy: "never", networkAccessEnabled: false,
        webSearchMode: "disabled", ...(model ? { model } : {}),
        ...(effort ? { modelReasoningEffort: effort } : {}) } as const;
      const thread = existing?.threadId ?
        client.resumeThread(existing.threadId, threadOptions) :
        client.startThread(threadOptions);
      if (!existing) this.emit(spec, "agent.spawned", "Agente iniciado", {
        agent_id: spec.agentId, role: spec.role, goal_pt: spec.goalPt });
      let retryPrompt = "Your final response did not match the required schema or verified evidence. Correct it now.";
      for (let attempt = 0; attempt < 2; attempt++) {
        let finalResponse = "";
        let violation = false;
        let failure: string | undefined;
        let terminal = false;
        const startedAt = Date.now();
        const turn = await thread.runStreamed(attempt === 0 ? existing?.threadId ?
          `${prompt}\n\nContinue this assignment in the same thread. Recheck current state before any action.` : prompt :
          retryPrompt,
          { outputSchema: z.toJSONSchema(finalSchema), signal: controller.signal });
        for await (const event of turn.events) {
          if (event.type === "thread.started")
            this.usage.bindThread(spec.runId, spec.agentId, event.thread_id);
          const toolName = event.type.startsWith("item.") && "item" in event &&
            event.item.type === "mcp_tool_call" ? event.item.tool : "";
          if ((event.type === "item.started" || event.type === "item.updated" ||
            event.type === "item.completed") && (forbidden.has(event.item.type) ||
            event.item.type === "mcp_tool_call" &&
              (event.item.server !== "banco_vivo_role" ||
                !spec.tools.some((tool) => tool.name === toolName)))) {
            violation = true;
            controller.abort(new Error("integrity_violation"));
            this.emit(spec, "integrity.violation", "Ferramenta proibida", {
              kind: "forbidden_codex_item", reason_pt: `Codex tentou ${event.item.type}` });
            break;
          }
          if (event.type === "item.completed" && event.item.type === "agent_message")
            finalResponse = event.item.text;
          if (event.type === "turn.completed") {
            terminal = true;
            this.usage.recordTurn(spec.runId, spec.agentId, event.usage, Date.now() - startedAt);
            tokens += event.usage.input_tokens + event.usage.output_tokens;
          }
          if (event.type === "turn.failed" || event.type === "error") {
            terminal = true;
            failure = event.type === "error" ? event.message : event.error.message;
          }
        }
        if (violation) { result = { status: "failed", reason: "integrity_violation", tokens }; break; }
        if (controller.signal.aborted) { result = { status: "timeout", reason: "wall_clock", tokens }; break; }
        if (!terminal) {
          result = { status: "failed", reason: "codex_thread_stream_ended", tokens }; break;
        }
        if (failure) {
          const paused = this.quota.noteFailure(failure);
          result = { status: paused ? "budget" : "failed",
            reason: paused ? "codex_quota_pause" : failure, tokens }; break;
        }
        let parsed: ReturnType<typeof finalSchema.safeParse>;
        try { parsed = finalSchema.safeParse(JSON.parse(finalResponse)); }
        catch { parsed = finalSchema.safeParse(null); }
        if (parsed.success && await spec.validateDossier?.(parsed.data.body) !== false) {
          result = { status: "ok", data: parsed.data.body, tokens }; break;
        }
        const feedback = parsed.success ? spec.validationFeedback?.() :
          parsed.error.issues.slice(0, 5).map((issue) =>
            `${issue.path.join(".") || "root"}: ${issue.message}`).join("; ");
        if (feedback)
          retryPrompt = `Your final response failed validation (${feedback.slice(0, 300)}). Correct that exact error, keep the original evidence scope, and return the required schema.`;
        result = { status: "failed", reason: "invalid_dossier", tokens };
        if (attempt === 1 && parsed.success)
          this.emit(spec, "integrity.violation", "Alegação sem prova verificada", {
            kind: "claim_unverified", reason_pt: "Dossiê sem prova confirmada" });
        if (!this.usage.canContinue(spec.runId, spec.role)) {
          result = { status: "budget", reason: "usage_cap", tokens }; break;
        }
      }
    } catch (error) {
      const paused = this.quota.noteFailure(error instanceof Error ? error.message : "");
      result = { status: controller.signal.aborted && controller.signal.reason?.message !== "integrity_violation"
        ? "timeout" : paused ? "budget" : "failed",
      reason: paused ? "codex_quota_pause" : error instanceof Error ? error.message : "runtime_error", tokens };
    } finally {
      clearTimeout(timer);
      if (token) this.broker.revoke(token);
      if (manifest) rmSync(manifest, { force: true });
      release?.();
      this.activeAgents.delete(activeKey);
      this.usage.finish(spec.runId, spec.agentId, result.status,
        spec.tools.length === 0 && resumableRoles.has(spec.role) ? result.data : undefined);
      this.emit(spec, "agent.finished", "Agente concluído", { agent_id: spec.agentId,
        outcome: result.status === "budget" ? "fallback" : result.status, tokens },
      result.reason ? { reason: result.reason.slice(0, 500) } : undefined);
    }
    return result;
  }
}
