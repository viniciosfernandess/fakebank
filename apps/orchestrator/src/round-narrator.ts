import { randomUUID } from "node:crypto";
import { z } from "zod";
import { narrationBody } from "../../../packages/contracts/src/dossiers.ts";
import { isSafePublicText } from "../../../packages/contracts/src/public-safety.ts";
import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { AgentTransport } from "./agent-loop.ts";
import { agentExecutor, type AgentRuntime } from "./runtime/agent-runtime.ts";
import { stageAgentId } from "./runtime/stage-agent-id.ts";
import type { BudgetLedger } from "./budget.ts";

export type RoundNarration = typeof narrationBody._output;

function safeNarration(body: RoundNarration, refs: ReadonlySet<string>): boolean {
  const sentences = body.summary_pt.split(/[.!?]+/).filter((item) => item.trim());
  if (body.headline_pt.length > 90 || sentences.length < 3 || sentences.length > 5 ||
      body.chapters.length < 2 || body.chapters.length > 4 ||
      ![body.headline_pt, body.summary_pt, body.takeaway_for_banks_pt]
        .every((item) => isSafePublicText(item))) return false;
  return body.chapters.every((chapter) => chapter.body_pt.split(/\s+/).length <= 60 &&
    isSafePublicText(chapter.title_pt) && isSafePublicText(chapter.body_pt) &&
    chapter.event_refs.length > 0 && chapter.event_refs.every((ref) => refs.has(ref)));
}

export class RoundNarrator {
  readonly events: EventStore;
  readonly budget: BudgetLedger | undefined;
  readonly transport: AgentTransport | undefined;
  readonly runtime: AgentRuntime | undefined;
  constructor(events: EventStore, budget?: BudgetLedger, transport?: AgentTransport,
    runtime?: AgentRuntime) {
    this.events = events; this.budget = budget; this.transport = transport; this.runtime = runtime;
  }

  async run(roundId: string, score: Record<string, number | null>,
    sourceEvents: readonly ArenaEvent[]): Promise<RoundNarration | undefined> {
    const publicEvents = sourceEvents.filter((event) => ["round.started", "score.updated",
      "invariant.checked", "attack.succeeded", "attack.failed",
      "incident.opened", "containment.applied", "review.rejected", "review.approved",
      "deploy.succeeded", "deploy.rolled_back", "damage.restored", "regression.result",
      "memory.updated", "area.quarantined", "usage.updated"]
      .includes(event.type)).slice(-30).map((event) => ({
        ref: `evt_${event.seq}`, type: event.type, area: event.area ?? null,
        summary_pt: isSafePublicText(event.public_summary_pt) ? event.public_summary_pt : "Evento reservado",
        metrics: Object.fromEntries(Object.entries(event.public).filter(([key, value]) =>
          ["loss_cents", "restored_cents", "customers_made_whole", "pass", "fail",
            "entries_added", "agents", "turns", "input_tokens", "output_tokens",
            "cached_input_tokens", "wall_ms", "collateral_honest"].includes(key) &&
          typeof value === "number" && Number.isFinite(value))),
      }));
    const refs = new Set(publicEvents.map((event) => event.ref));
    if (refs.size < 2) return undefined;
    const eventRef = z.enum([...refs] as [string, ...string[]]);
    const dossierSchema = narrationBody.extend({
      headline_pt: z.string().min(1).max(90),
      summary_pt: z.string().min(1).max(280),
      chapters: z.array(z.strictObject({
        title_pt: z.string().min(1).max(280),
        body_pt: z.string().min(1).max(280),
        event_refs: z.array(eventRef).min(1),
      })).min(2).max(4),
      takeaway_for_banks_pt: z.string().min(1).max(280),
    });
    const loop = agentExecutor(this.events, this.budget, this.runtime, this.transport);
    const agentId = this.runtime ? stageAgentId(this.events, roundId, "narrator", "round_narration") :
      `narrator_${randomUUID()}`;
    const result = await loop.run({ runId: roundId, agentId,
      role: "narrator", goalPt: "Resumir a rodada com fatos públicos verificados",
      snapshot: { roundId, score, events: publicEvents },
      dossier: { instruction: "Use only the supplied facts and event refs. Omit unsupported details. If no verified attack or response exists, say so and cover the start, invariant check, and score in separate chapters." },
      dossierSchema, validateDossier: (body) => safeNarration(body, refs),
      tools: [], maxTurns: 2, maxTokens: 900 });
    return result.status === "ok" ? result.data : undefined;
  }
}
