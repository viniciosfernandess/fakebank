import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Role } from "../../../packages/contracts/src/index.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import { BudgetLedger, type BudgetModel, type BudgetPriority, type ModelUsage } from "./budget.ts";
import { sanitizeDossier, systemForRole } from "../../../packages/prompts/src/index.ts";

type AgentRole = Exclude<Role, "sentinel" | "historian" | "scout" | "intruder" | "exploiter">;
type ToolKind = "recon" | "action" | "investigate" | "contain" | "restore" | "ci" | "code";
type Effort = "low" | "medium";
interface TextBlockParam { type: "text"; text: string;
  cache_control?: { type: "ephemeral"; ttl?: "1h" }; }
interface ToolUseBlock { type: "tool_use"; id: string; name: string; input: unknown; }
interface ToolResultBlock { type: "tool_result"; tool_use_id: string;
  content: string; is_error: boolean; }
type MessageContent = TextBlockParam | ToolUseBlock | ToolResultBlock;
interface MessageParam { role: "user" | "assistant"; content: string | MessageContent[]; }
interface Tool { name: string; description: string; input_schema: Record<string, unknown>; }
interface Response { id: string; content: MessageContent[]; stop_reason: string | null;
  usage: ModelUsage; }
interface Request { model: BudgetModel; max_tokens: number; stream: false;
  service_tier: "standard_only"; thinking: { type: "adaptive" };
  output_config: { effort: Effort }; cache_control: { type: "ephemeral" };
  system: TextBlockParam[]; tools: Tool[]; messages: MessageParam[]; }

export interface AgentTransport {
  send(request: Request, options: { signal: AbortSignal; timeoutMs: number }): Promise<Response>;
}

export const ROLE_TOOLS: Record<AgentRole, ReadonlySet<string>> = {
  investigator: new Set(["alerts.get", "cards.issuer_status", "logs.query", "ledger.trace", "ledger.query", "entity.profile",
    "kb.query", "sim.honest_impact", "contain.freeze_account", "contain.block_route", "contain.disable_flag",
    "contain.revoke_session", "contain.revoke_key", "task.open"]),
  forensic_mapper: new Set(["alerts.get", "logs.query", "trace.get", "ledger.trace",
    "spi.messages", "sessions.list", "case.history"]),
  root_cause_analyst: new Set(["alerts.get", "logs.query", "trace.get", "ledger.trace",
    "scenario.get", "repo.read", "repo.search", "case.history"]),
  architect: new Set(["repo.read", "repo.search", "case.history"]),
  engineer: new Set(["repo.read", "repo.search", "repo.apply_patch", "tests.reproduce", "tests.run_targeted"]),
  reviewer: new Set(["repo.read", "repo.search", "tests.run_targeted", "repo.diff", "diff.scope_check",
    "tests.run_regression", "tests.run_honest", "review.submit"]),
  damage_assessor: new Set(["logs.query", "ledger.trace", "ledger.query", "ledger.scan_damage",
    "med.status", "accounts.balance_check", "sessions.list_suspicious", "keys.list_suspicious",
    "containment.list_active"]),
  restorer: new Set(["ledger.trace", "ledger.reverse", "account.restore_balance", "contain.lift",
    "account.unfreeze", "session.revoke", "key.revoke", "scheduler.cancel_job",
    "med.status", "med.request", "bank.compensate_expired"]),
  hardening: new Set(),
  postmortem: new Set(),
  product: new Set(),
  narrator: new Set(),
};
const LIMITS: Record<AgentRole, { turns: number; tools: number; wallMs: number; p90Nusd: number }> = {
  investigator: { turns: 8, tools: 20, wallMs: 90_000, p90Nusd: 4_500_000 },
  forensic_mapper: { turns: 6, tools: 12, wallMs: 90_000, p90Nusd: 4_500_000 },
  root_cause_analyst: { turns: 6, tools: 12, wallMs: 150_000, p90Nusd: 73_000_000 },
  architect: { turns: 8, tools: 15, wallMs: 180_000, p90Nusd: 73_000_000 },
  engineer: { turns: 8, tools: 20, wallMs: 240_000, p90Nusd: 139_000_000 },
  reviewer: { turns: 6, tools: 10, wallMs: 300_000, p90Nusd: 73_000_000 },
  damage_assessor: { turns: 6, tools: 15, wallMs: 60_000, p90Nusd: 3_600_000 },
  restorer: { turns: 6, tools: 20, wallMs: 90_000, p90Nusd: 3_600_000 },
  hardening: { turns: 4, tools: 0, wallMs: 90_000, p90Nusd: 73_000_000 },
  postmortem: { turns: 3, tools: 0, wallMs: 60_000, p90Nusd: 3_600_000 },
  product: { turns: 3, tools: 2, wallMs: 45_000, p90Nusd: 20_000_000 },
  narrator: { turns: 2, tools: 0, wallMs: 25_000, p90Nusd: 3_000_000 },
};
const PRIORITY: Record<AgentRole, BudgetPriority> = {
  investigator: 1, forensic_mapper: 1, root_cause_analyst: 1,
  architect: 1, engineer: 1, reviewer: 1,
  damage_assessor: 2, restorer: 2, hardening: 1, postmortem: 2, product: 1, narrator: 2,
};
export interface AgentTool {
  name: string;
  description: string;
  kind: ToolKind;
  schema: z.ZodType;
  execute: (input: unknown, signal: AbortSignal) => Promise<unknown>;
  timeoutMs?: (input: unknown) => number;
  wallExtensionMs?: (input: unknown) => number;
}
export interface AgentSpec<T> {
  runId: string;
  agentId: string;
  role: AgentRole;
  goalPt: string;
  system?: [string, string];
  snapshot: unknown;
  dossier: unknown;
  dossierSchema: z.ZodType<T>;
  validateDossier?: (body: T) => boolean | Promise<boolean>;
  validationFeedback?: () => string | undefined;
  tools: AgentTool[];
  maxTurns?: number;
  maxTokens?: number;
  maxToolCalls?: number;
  deadlineAt?: number;
}
export interface AgentResult<T> {
  status: "ok" | "budget" | "refused" | "timeout" | "failed";
  data?: T;
  reason?: string;
  tokens: number;
}
export interface AgentLoopOptions {
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  now?: () => Date;
  toolTimeoutMs?: number;
  onDiagnostic?: (entry: { kind: string; agentId: string; detail: string }) => void;
}
function defaultSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { signal.removeEventListener("abort", onAbort); resolve(); }, ms);
    const onAbort = () => { clearTimeout(timer); reject(signal.reason ?? new Error("aborted")); };
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
}
async function executeWithTimeout(tool: AgentTool, input: unknown, parent: AbortSignal, ms: number): Promise<unknown> {
  if (parent.aborted) throw parent.reason ?? new Error("aborted");
  const controller = new AbortController();
  const onParentAbort = () => controller.abort(parent.reason);
  parent.addEventListener("abort", onParentAbort, { once: true });
  if (parent.aborted) onParentAbort();
  const timer = setTimeout(() => controller.abort(new Error("tool_timeout")), ms);
  const aborted = new Promise<never>((_, reject) => controller.signal.addEventListener("abort",
    () => reject(controller.signal.reason), { once: true }));
  try { return await Promise.race([tool.execute(input, controller.signal), aborted]); }
  finally { clearTimeout(timer); parent.removeEventListener("abort", onParentAbort); }
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  return JSON.stringify(value) ?? "null";
}
function toolDefinition(tool: AgentTool): Tool {
  return { name: tool.name, description: tool.description,
    input_schema: z.toJSONSchema(tool.schema) as Record<string, unknown> };
}
function inputUpperBound(request: Request): number {
  return Buffer.byteLength(JSON.stringify(request), "utf8") + 4096;
}
function errorStatus(error: unknown): number | undefined {
  const status = (error as { status?: unknown })?.status;
  return typeof status === "number" ? status : undefined;
}
function outcome(status: AgentResult<unknown>["status"]): "ok" | "fallback" | "refused" | "timeout" | "failed" {
  return status === "budget" ? "fallback" : status;
}

export class AgentLoop {
  readonly events: EventStore;
  readonly budget: BudgetLedger;
  readonly transport: AgentTransport;
  readonly options: AgentLoopOptions;
  constructor(events: EventStore, budget: BudgetLedger, transport: AgentTransport, options: AgentLoopOptions = {}) {
    this.events = events; this.budget = budget; this.transport = transport; this.options = options;
  }
  private emit(runId: string, agentId: string, role: Role | "system", type: string,
    summaryPt: string, publicPayload: Record<string, unknown>): void {
    this.events.append({ round_id: runId, ts: (this.options.now?.() ?? new Date()).toISOString(),
      type: type as "agent.spawned", actor: { id: agentId, role }, public_summary_pt: summaryPt,
      public: publicPayload });
  }
  private emitCost(runId: string): void {
    const summary = this.budget.summary(runId);
    const totalNusd = (this.events.db.prepare("SELECT COALESCE(SUM(cost_nusd),0) n FROM budget_calls")
      .get() as { n: number }).n;
    this.emit(runId, "budget", "system", "cost.updated", "Custo atualizado", {
      round_cost_usd: summary.spentNusd / 1e9, total_cost_usd: totalNusd / 1e9,
      budget_left_usd: Math.max(0, summary.capNusd - summary.spentNusd) / 1e9,
      capped: summary.committedNusd >= summary.capNusd });
  }
  async run<T>(spec: AgentSpec<T>): Promise<AgentResult<T>> {
    const limits = LIMITS[spec.role];
    if (!limits || spec.tools.some((tool) => !ROLE_TOOLS[spec.role].has(tool.name)) ||
      new Set(spec.tools.map((tool) => tool.name)).size !== spec.tools.length)
      throw new Error("AGENT_TOOL_SCOPE");
    const model: BudgetModel = spec.role === "engineer" || spec.role === "reviewer"
      ? "claude-sonnet-5-5" : "claude-haiku-5-5";
    const maxTurns = Math.min(spec.maxTurns ?? limits.turns, limits.turns);
    const maxToolCalls = Math.min(spec.maxToolCalls ?? limits.tools, limits.tools);
    const maxTokens = Math.min(spec.maxTokens ?? 4096, 8192);
    if (maxTurns <= 0 || maxToolCalls < 0 || maxTokens <= 0) throw new Error("AGENT_INVALID_LIMITS");
    const hardDeadline = spec.deadlineAt ?? Number.POSITIVE_INFINITY;
    if (Date.now() >= hardDeadline)
      return { status: "timeout", reason: "run_deadline", tokens: 0 };
    const reservation = this.budget.reserve(spec.runId, spec.role, PRIORITY[spec.role],
      Math.ceil(limits.p90Nusd * 1.25));
    if (!reservation) {
      this.emit(spec.runId, spec.agentId, "system", "agent.spawn_denied", "Agente não iniciado: orçamento", {
        role: spec.role, reason: "budget" });
      return { status: "budget", reason: "spawn_denied", tokens: 0 };
    }
    const controller = new AbortController();
    let wallDeadline = Math.min(Date.now() + limits.wallMs, hardDeadline);
    let wall = setTimeout(() => controller.abort(new Error("wall_clock")),
      Math.max(0, wallDeadline - Date.now()));
    const extendWall = (ms: number): void => {
      if (!Number.isSafeInteger(ms) || ms < 0 || ms > 150_000) throw new Error("AGENT_INVALID_WALL_EXTENSION");
      wallDeadline = Math.min(wallDeadline + ms, hardDeadline);
      clearTimeout(wall);
      wall = setTimeout(() => controller.abort(new Error("wall_clock")), Math.max(0, wallDeadline - Date.now()));
    };
    const tools = [...spec.tools].sort((a, b) => a.name.localeCompare(b.name));
    const finalSchema = z.strictObject({ body: spec.dossierSchema, public_summary_pt: z.string().max(160),
      confidence: z.number().min(0).max(1), escalation: z.unknown().nullable() });
    const requestTools = [...tools.map(toolDefinition), { name: "submit_dossier",
      description: "Submit the final structured dossier and end this agent.",
      input_schema: z.toJSONSchema(finalSchema) as Record<string, unknown> }];
    const ttl = model === "claude-sonnet-5-5" ? { type: "ephemeral" as const, ttl: "1h" as const }
      : { type: "ephemeral" as const };
    const promptSystem = spec.system ?? systemForRole(spec.role);
    const system: TextBlockParam[] = [
      { type: "text", text: promptSystem[0] },
      { type: "text", text: promptSystem[1], cache_control: ttl },
    ];
    const messages: MessageParam[] = [{ role: "user", content: [
      { type: "text", text: canonical(sanitizeDossier(spec.snapshot)), cache_control: ttl },
      { type: "text", text: canonical(sanitizeDossier(spec.dossier)) },
    ] }];
    let tokens = 0;
    let toolCalls = 0;
    let nudged = false;
    let uncertainClaim = false;
    let result: AgentResult<T> = { status: "failed", reason: "unknown", tokens: 0 };
    this.emit(spec.runId, spec.agentId, spec.role, "agent.spawned", "Agente iniciado", {
      agent_id: spec.agentId, role: spec.role, goal_pt: spec.goalPt });
    try {
      turnLoop: for (let turn = 1; turn <= maxTurns; turn++) {
        if (controller.signal.aborted || Date.now() >= hardDeadline) {
          result = { status: "timeout", reason: "run_deadline", tokens }; break;
        }
        const request: Request = { model, max_tokens: maxTokens, stream: false, service_tier: "standard_only",
          thinking: { type: "adaptive" }, output_config: { effort: (model === "claude-sonnet-5-5" ? "medium" : "low") as Effort },
          cache_control: { type: "ephemeral" }, system, tools: requestTools, messages };
        let response: Response | undefined;
        for (let attempt = 0; attempt < 4; attempt++) {
          const callId = `call_${randomUUID()}`;
          if (this.budget.claim(reservation, callId, model, inputUpperBound(request), maxTokens) === null) {
            this.emitCost(spec.runId);
            result = { status: "budget", reason: "call_denied", tokens };
            break turnLoop;
          }
          try {
            response = await this.transport.send(request, { signal: controller.signal,
              timeoutMs: model === "claude-sonnet-5-5" ? 150_000 : 90_000 });
          } catch (error) {
            const status = errorStatus(error);
            if (status !== undefined) this.budget.cancelUnbilledClaim(callId);
            else uncertainClaim = true;
            if (controller.signal.aborted) {
              result = { status: "timeout", reason: "wall_clock", tokens };
              break turnLoop;
            }
            if ((status === undefined || [429, 500, 502, 503, 504, 529].includes(status)) && attempt < 3) {
              this.options.onDiagnostic?.({ kind: "api.retry", agentId: spec.agentId, detail: String(status ?? "network") });
              await (this.options.sleep ?? defaultSleep)(1000 * 2 ** attempt, controller.signal);
              continue;
            }
            result = { status: "failed", reason: `api_${status ?? "network"}`, tokens };
            break turnLoop;
          }
          const settled = this.budget.settle(callId, response.usage);
          tokens += response.usage.input_tokens + response.usage.output_tokens +
            (response.usage.cache_read_input_tokens ?? 0) + (response.usage.cache_creation_input_tokens ?? 0);
          this.emitCost(spec.runId);
          if (settled.estimateExceeded) {
            result = { status: "budget", reason: "estimate_exceeded", tokens };
            break turnLoop;
          }
          break;
        }
        if (!response) continue;
        if (response.stop_reason === "refusal") {
          result = { status: "refused", reason: "model_refusal", tokens }; break;
        }
        const uses = response.content.filter((block): block is ToolUseBlock => block.type === "tool_use");
        if (response.stop_reason === "tool_use" && uses.length) {
          const submit = uses.find((block) => block.name === "submit_dossier");
          if (submit && uses.length === 1) {
            const parsed = finalSchema.safeParse(submit.input);
            if (parsed.success && await spec.validateDossier?.(parsed.data.body) === false) {
              this.emit(spec.runId, spec.agentId, "system", "integrity.violation",
                "Alegação sem prova verificada", { kind: "claim_unverified", reason_pt: "Efeito não confirmado pelo banco" });
            } else if (parsed.success) {
              this.emit(spec.runId, spec.agentId, spec.role, "tool.called", "Dossiê entregue", {
                tool: "submit_dossier", ok: true, kind: "action" });
              result = { status: "ok", data: parsed.data.body, tokens }; break;
            }
          }
          messages.push({ role: "assistant", content: response.content as MessageParam["content"] });
          const results: { type: "tool_result"; tool_use_id: string; content: string; is_error: boolean }[] = [];
          for (const use of uses) {
            if (controller.signal.aborted || Date.now() >= hardDeadline) {
              result = { status: "timeout", reason: "run_deadline", tokens };
              break;
            }
            toolCalls++;
            const tool = tools.find((item) => item.name === use.name);
            let ok = false;
            let content = "Tool unavailable";
            if (toolCalls > maxToolCalls) content = "Tool call limit reached";
            else if (use.name === "submit_dossier") content = "Invalid or non-final dossier";
            else if (tool) {
              const input = tool.schema.safeParse(use.input);
              if (!input.success) content = "Invalid tool input";
              else {
                try {
                  if (tool.wallExtensionMs) extendWall(tool.wallExtensionMs(input.data));
                  const value = await executeWithTimeout(tool, input.data, controller.signal,
                    tool.timeoutMs?.(input.data) ?? this.options.toolTimeoutMs ?? 10_000);
                  content = JSON.stringify(value) ?? "null"; ok = true;
                } catch { content = "Tool failed"; }
              }
            }
            this.emit(spec.runId, spec.agentId, spec.role, "tool.called", `${use.name}: ${ok ? "ok" : "erro"}`, {
              tool: use.name, ok, kind: tool?.kind ?? "action" });
            results.push({ type: "tool_result", tool_use_id: use.id,
              content: content.length > 8000 ? `${content.slice(0, 8000)}…` : content, is_error: !ok });
          }
          if (result.status === "timeout") break turnLoop;
          messages.push({ role: "user", content: results });
          continue;
        }
        if ((response.stop_reason === "end_turn" || response.stop_reason === "max_tokens") && !nudged) {
          messages.push({ role: "assistant", content: response.content as MessageParam["content"] });
          messages.push({ role: "user", content: "Submit your final dossier with submit_dossier now." });
          nudged = true; continue;
        }
        result = { status: "failed", reason: `stop_${response.stop_reason ?? "unknown"}`, tokens };
        break;
      }
      if (result.reason === "unknown") result = { status: "failed", reason: "turn_cap", tokens };
      if (uncertainClaim && result.status === "ok")
        result = { status: "failed", reason: "unsettled_request", tokens };
      return result;
    } catch (error) {
      result = { status: controller.signal.aborted ? "timeout" : "failed",
        reason: error instanceof Error ? error.message : "unknown_error", tokens };
      return result;
    } finally {
      clearTimeout(wall);
      if (!uncertainClaim) {
        try { this.budget.release(reservation); }
        catch { uncertainClaim = true; }
      }
      this.emit(spec.runId, spec.agentId, spec.role, "agent.finished", "Agente concluído", {
        agent_id: spec.agentId, outcome: outcome(result.status), tokens });
    }
  }
}
