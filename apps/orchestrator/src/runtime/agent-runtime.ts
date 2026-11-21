import { AgentLoop, type AgentResult, type AgentSpec,
  type AgentTransport } from "../agent-loop.ts";
import type { EventStore } from "../../../../packages/event-store/src/index.ts";
import type { BudgetLedger } from "../budget.ts";

export interface AgentRuntime {
  run<T>(spec: AgentSpec<T>): Promise<AgentResult<T>>;
  close?(): Promise<void>;
}

export function agentExecutor(events: EventStore, budget: BudgetLedger | undefined,
  runtime?: AgentRuntime, transport?: AgentTransport): AgentRuntime {
  if (runtime) return runtime;
  if (transport) {
    if (!budget) throw new Error("LEGACY_BUDGET_UNAVAILABLE");
    return new AgentLoop(events, budget, transport);
  }
  throw new Error("AGENT_RUNTIME_UNAVAILABLE");
}
