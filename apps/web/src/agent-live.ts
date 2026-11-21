import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";

export interface AgentActivity {
  key: string;
  agentId: string;
  role: string;
  startedAt: string;
  lastAt: string;
  outcome: string | null;
  tokens: number | null;
  currentTool: string | null;
  events: ArenaEvent[];
}

export function agentActivity(events: readonly ArenaEvent[]): AgentActivity[] {
  const byKey = new Map<string, AgentActivity>();
  for (const event of events) {
    if (event.type === "agent.spawned") {
      const agentId = event.public.agent_id;
      const role = event.public.role;
      if (typeof agentId !== "string" || typeof role !== "string") continue;
      const key = `${event.round_id ?? "none"}:${agentId}`;
      if (!byKey.has(key)) byKey.set(key, {
        key, agentId, role,
        startedAt: event.ts, lastAt: event.ts, outcome: null, tokens: null,
        currentTool: null, events: [event],
      });
      continue;
    }
    if (event.type !== "tool.called" && event.type !== "agent.finished" &&
      event.type !== "context.handoff") continue;
    const ids = event.type === "context.handoff" ?
      [event.public.from, event.public.to].filter((id): id is string =>
        typeof id === "string") : [event.actor.id];
    for (const id of new Set(ids)) {
      const row = byKey.get(`${event.round_id ?? "none"}:${id}`);
      if (!row) continue;
      row.events.push(event);
      row.lastAt = event.ts;
      if (event.type === "tool.called")
        row.currentTool = typeof event.public.label_pt === "string" ?
          event.public.label_pt : typeof event.public.tool === "string" ?
            event.public.tool : null;
      if (event.type === "agent.finished" && id === event.actor.id) {
        row.outcome = typeof event.public.outcome === "string" ?
          event.public.outcome : "unknown";
        row.tokens = typeof event.public.tokens === "number" ? event.public.tokens : null;
        row.currentTool = null;
      }
    }
  }
  return [...byKey.values()].sort((left, right) =>
    Date.parse(right.startedAt) - Date.parse(left.startedAt));
}
