import { randomUUID } from "node:crypto";
import type { Usage } from "@openai/codex-sdk";
import type { EventStore } from "../../../../packages/event-store/src/index.ts";
import { ROLES } from "../../../../packages/contracts/src/index.ts";

export interface UsageSummary {
  agents: number;
  turns: number;
  inputTokens: number;
  outputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  reasoningOutputTokens: number;
  wallMs: number;
}
interface UsageCaps { maxAgents?: number; maxTurns?: number; maxTokens?: number }

function limit(value: string | undefined, fallback: number): number {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error("CODEX_USAGE_LIMIT_INVALID");
  return parsed;
}
function count(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("CODEX_USAGE_INVALID");
  return value;
}

export class UsageLedger {
  private readonly events: EventStore;
  private readonly maxAgents: number;
  private readonly maxTurns: number;
  private readonly maxTokens: number;
  private readonly roleCaps: Record<string, Required<UsageCaps>>;
  constructor(events: EventStore, options: UsageCaps & { roleCaps?: Record<string, UsageCaps> } = {}) {
    this.events = events;
    this.maxAgents = count(options.maxAgents ?? limit(process.env.CODEX_ROUND_MAX_AGENTS, 64));
    this.maxTurns = count(options.maxTurns ?? limit(process.env.CODEX_ROUND_MAX_TURNS, 128));
    this.maxTokens = count(options.maxTokens ?? limit(process.env.CODEX_ROUND_MAX_TOKENS, 2_000_000));
    this.roleCaps = Object.fromEntries(ROLES.map((role) => {
      const configured = options.roleCaps?.[role];
      const name = role.toUpperCase();
      return [role, {
        maxAgents: count(configured?.maxAgents ?? limit(process.env[`CODEX_${name}_MAX_AGENTS`], 64)),
        maxTurns: count(configured?.maxTurns ?? limit(process.env[`CODEX_${name}_MAX_TURNS`], 128)),
        maxTokens: count(configured?.maxTokens ?? limit(process.env[`CODEX_${name}_MAX_TOKENS`], 2_000_000)),
      }];
    }));
    events.db.exec(`CREATE TABLE IF NOT EXISTS codex_usage_agents (
      agent_id TEXT NOT NULL, run_id TEXT NOT NULL, role TEXT NOT NULL,
      started_at TEXT NOT NULL, finished_at TEXT, status TEXT, thread_id TEXT,
      prompt_hash TEXT, result_json TEXT,
      PRIMARY KEY(run_id,agent_id)
    );
    CREATE INDEX IF NOT EXISTS codex_usage_agents_run ON codex_usage_agents(run_id);
    CREATE TABLE IF NOT EXISTS codex_usage_turns (
      id TEXT PRIMARY KEY, run_id TEXT NOT NULL, agent_id TEXT NOT NULL,
      input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL,
      cached_input_tokens INTEGER NOT NULL, cache_write_input_tokens INTEGER NOT NULL,
      reasoning_output_tokens INTEGER NOT NULL, wall_ms INTEGER NOT NULL,
      recorded_at TEXT NOT NULL,
      FOREIGN KEY(run_id,agent_id) REFERENCES codex_usage_agents(run_id,agent_id)
    );
    CREATE INDEX IF NOT EXISTS codex_usage_turns_run ON codex_usage_turns(run_id);`);
    const agentColumns = events.db.prepare("PRAGMA table_info(codex_usage_agents)")
      .all() as { name: string }[];
    if (!agentColumns.some((column) => column.name === "thread_id"))
      events.db.exec("ALTER TABLE codex_usage_agents ADD COLUMN thread_id TEXT");
    if (!agentColumns.some((column) => column.name === "prompt_hash"))
      events.db.exec("ALTER TABLE codex_usage_agents ADD COLUMN prompt_hash TEXT");
    if (!agentColumns.some((column) => column.name === "result_json"))
      events.db.exec("ALTER TABLE codex_usage_agents ADD COLUMN result_json TEXT");
  }
  session(runId: string, agentId: string): { role: string; threadId: string | null;
    status: string | null; promptHash: string | null } | undefined {
    const row = this.events.db.prepare(`SELECT role,thread_id,status,prompt_hash FROM codex_usage_agents
      WHERE run_id=? AND agent_id=?`).get(runId, agentId) as
      { role: string; thread_id: string | null; status: string | null;
        prompt_hash: string | null } | undefined;
    return row ? { role: row.role, threadId: row.thread_id, status: row.status,
      promptHash: row.prompt_hash } : undefined;
  }
  completedResult(runId: string, agentId: string, promptHash: string): unknown {
    const row = this.events.db.prepare(`SELECT result_json FROM codex_usage_agents
      WHERE run_id=? AND agent_id=? AND status='ok' AND prompt_hash=?`)
      .get(runId, agentId, promptHash) as { result_json: string | null } | undefined;
    if (!row?.result_json) return undefined;
    try { return JSON.parse(row.result_json); } catch { return undefined; }
  }
  hasRecordedTurn(runId: string, agentId: string): boolean {
    return Boolean(this.events.db.prepare(`SELECT 1 FROM codex_usage_turns
      WHERE run_id=? AND agent_id=? LIMIT 1`).get(runId, agentId));
  }
  bindThread(runId: string, agentId: string, threadId: string): void {
    if (!/^[A-Za-z0-9_-]{1,100}$/.test(threadId)) throw new Error("CODEX_THREAD_ID_INVALID");
    const result = this.events.db.prepare(`UPDATE codex_usage_agents SET thread_id=?
      WHERE run_id=? AND agent_id=? AND status IS NULL
        AND (thread_id IS NULL OR thread_id=?)`)
      .run(threadId, runId, agentId, threadId);
    if (result.changes !== 1) throw new Error("CODEX_THREAD_BIND_CONFLICT");
  }
  summary(runId: string): UsageSummary {
    const agents = this.events.db.prepare("SELECT COUNT(*) n FROM codex_usage_agents WHERE run_id=?")
      .get(runId) as { n: number };
    const turns = this.events.db.prepare(`SELECT COUNT(*) turns,
      COALESCE(SUM(input_tokens),0) input_tokens, COALESCE(SUM(output_tokens),0) output_tokens,
      COALESCE(SUM(cached_input_tokens),0) cached_input_tokens,
      COALESCE(SUM(cache_write_input_tokens),0) cache_write_input_tokens,
      COALESCE(SUM(reasoning_output_tokens),0) reasoning_output_tokens,
      COALESCE(SUM(wall_ms),0) wall_ms FROM codex_usage_turns WHERE run_id=?`)
      .get(runId) as { turns: number; input_tokens: number; output_tokens: number;
        cached_input_tokens: number; cache_write_input_tokens: number;
        reasoning_output_tokens: number; wall_ms: number };
    return { agents: agents.n, turns: turns.turns, inputTokens: turns.input_tokens,
      outputTokens: turns.output_tokens, cachedInputTokens: turns.cached_input_tokens,
      cacheWriteInputTokens: turns.cache_write_input_tokens,
      reasoningOutputTokens: turns.reasoning_output_tokens, wallMs: turns.wall_ms };
  }
  private roleSummary(runId: string, role: string): { agents: number; turns: number; tokens: number } {
    const row = this.events.db.prepare(`SELECT COUNT(DISTINCT a.agent_id) agents,
      COUNT(t.id) turns, COALESCE(SUM(t.input_tokens+t.output_tokens),0) tokens
      FROM codex_usage_agents a LEFT JOIN codex_usage_turns t
      ON t.run_id=a.run_id AND t.agent_id=a.agent_id
      WHERE a.run_id=? AND a.role=?`).get(runId, role) as
      { agents: number; turns: number; tokens: number };
    return row;
  }
  tryStart(runId: string, agentId: string, role: string, promptHash?: string): boolean {
    this.events.db.exec("BEGIN IMMEDIATE");
    try {
      const summary = this.summary(runId);
      const roleSummary = this.roleSummary(runId, role);
      const caps = this.roleCaps[role];
      if (!caps) throw new Error("CODEX_ROLE_INVALID");
      if (summary.agents >= this.maxAgents || summary.turns >= this.maxTurns ||
        summary.inputTokens + summary.outputTokens >= this.maxTokens ||
        roleSummary.agents >= caps.maxAgents || roleSummary.turns >= caps.maxTurns ||
        roleSummary.tokens >= caps.maxTokens) {
        this.events.db.exec("COMMIT");
        return false;
      }
      this.events.db.prepare(`INSERT INTO codex_usage_agents
        (agent_id,run_id,role,started_at,prompt_hash) VALUES (?,?,?,?,?)`)
        .run(agentId, runId, role, new Date().toISOString(), promptHash ?? null);
      this.events.db.exec("COMMIT");
      return true;
    } catch (error) { this.events.db.exec("ROLLBACK"); throw error; }
  }
  recordTurn(runId: string, agentId: string, usage: Usage, wallMs: number): UsageSummary {
    const values = [usage.input_tokens, usage.output_tokens, usage.cached_input_tokens,
      usage.cache_write_input_tokens, usage.reasoning_output_tokens, wallMs].map(count);
    this.events.db.prepare(`INSERT INTO codex_usage_turns VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(randomUUID(), runId, agentId, ...values, new Date().toISOString());
    const summary = this.summary(runId);
    this.events.append({ round_id: runId, ts: new Date().toISOString(), type: "usage.updated",
      actor: { id: agentId, role: "system" }, public_summary_pt: "Uso do Codex atualizado",
      public: { agents: summary.agents, turns: summary.turns,
        input_tokens: summary.inputTokens, output_tokens: summary.outputTokens,
        cached_input_tokens: summary.cachedInputTokens, wall_ms: summary.wallMs } });
    return summary;
  }
  canContinue(runId: string, role?: string): boolean {
    const summary = this.summary(runId);
    if (summary.turns >= this.maxTurns ||
      summary.inputTokens + summary.outputTokens >= this.maxTokens) return false;
    if (!role) return true;
    const caps = this.roleCaps[role];
    if (!caps) throw new Error("CODEX_ROLE_INVALID");
    const byRole = this.roleSummary(runId, role);
    return byRole.turns < caps.maxTurns && byRole.tokens < caps.maxTokens;
  }
  finish(runId: string, agentId: string, status: string, result?: unknown): void {
    this.events.db.prepare(`UPDATE codex_usage_agents
      SET finished_at=?,status=?,result_json=? WHERE run_id=?
      AND agent_id=? AND finished_at IS NULL`).run(new Date().toISOString(), status,
        status === "ok" && result !== undefined ? JSON.stringify(result) : null, runId, agentId);
  }
}
