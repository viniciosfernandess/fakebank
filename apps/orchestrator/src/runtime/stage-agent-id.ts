import { createHash, randomUUID } from "node:crypto";
import type { Role } from "../../../../packages/contracts/src/index.ts";
import type { EventStore } from "../../../../packages/event-store/src/index.ts";

function latestStageAgent(events: EventStore, runId: string, role: Role,
  stageKey: string): { agent_id: string; status: string | null } | undefined {
  const digest = createHash("sha256").update(stageKey).digest("hex").slice(0, 24);
  const prefix = `${role}_${digest}_`;
  const hasUsage = events.db.prepare(`SELECT 1 FROM sqlite_master
    WHERE type='table' AND name='codex_usage_agents'`).get();
  if (!hasUsage) return undefined;
  return events.db.prepare(`SELECT agent_id,status FROM codex_usage_agents
    WHERE run_id=? AND role=? AND substr(agent_id,1,?)=?
    ORDER BY rowid DESC LIMIT 1`)
    .get(runId, role, prefix.length, prefix) as
    { agent_id: string; status: string | null } | undefined;
}

export function unfinishedStageAgentId(events: EventStore, runId: string, role: Role,
  stageKey: string): string | undefined {
  const previous = latestStageAgent(events, runId, role, stageKey);
  return previous?.status === null ? previous.agent_id : undefined;
}

export function stageAgentId(events: EventStore, runId: string, role: Role,
  stageKey: string): string {
  const previous = latestStageAgent(events, runId, role, stageKey);
  if (previous && (previous.status === null || previous.status === "ok"))
    return previous.agent_id;
  const digest = createHash("sha256").update(stageKey).digest("hex").slice(0, 24);
  const prefix = `${role}_${digest}_`;
  return `${prefix}${randomUUID()}`;
}
