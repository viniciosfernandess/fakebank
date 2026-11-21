import { randomUUID } from "node:crypto";
import { postmortemBody } from "../../../packages/contracts/src/dossiers.ts";
import { isSafePublicText } from "../../../packages/contracts/src/public-safety.ts";
import type { Area } from "../../../packages/contracts/src/index.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { AgentTransport } from "./agent-loop.ts";
import type { BudgetLedger } from "./budget.ts";
import { agentExecutor, type AgentRuntime } from "./runtime/agent-runtime.ts";
import { stageAgentId } from "./runtime/stage-agent-id.ts";
import { publishPostmortem } from "./postmortem.ts";

type Narrative = ReturnType<typeof postmortemBody.parse>;

export class PostmortemChain {
  private readonly events: EventStore;
  private readonly budget: BudgetLedger | undefined;
  private readonly transport: AgentTransport | undefined;
  private readonly runtime: AgentRuntime | undefined;
  constructor(events: EventStore, budget?: BudgetLedger,
    transport?: AgentTransport, runtime?: AgentRuntime) {
    this.events = events; this.budget = budget; this.transport = transport;
    this.runtime = runtime;
  }

  async run(input: { incidentId: string; roundId: string; area: Area;
    twinNow: Date; deadlineAt?: number }): Promise<"narrated" | "fallback"> {
    publishPostmortem(this.events, input);
    const history = this.events.caseFile.history(input.incidentId);
    const report = history.find((entry) => entry.kind === "postmortem.report")?.payload;
    if (!report) throw new Error("POSTMORTEM_REPORT_MISSING");
    const existing = history.find((entry) => entry.kind === "dossier.postmortem")?.payload;
    let narrative: Narrative | undefined = existing ? postmortemBody.parse(existing) : undefined;
    if (!narrative) {
      const agentId = this.runtime ? stageAgentId(this.events, input.roundId,
        "postmortem", input.incidentId) : `postmortem_${randomUUID()}`;
      const loop = agentExecutor(this.events, this.budget, this.runtime, this.transport);
      const result = await loop.run({ runId: input.roundId, agentId, role: "postmortem",
        goalPt: "Redigir síntese sem culpados do incidente encerrado",
        ...(input.deadlineAt ? { deadlineAt: input.deadlineAt } : {}),
        snapshot: { incidentId: input.incidentId, area: input.area },
        dossier: { incidentId: input.incidentId, area: input.area,
          rootCauseClass: report.root_cause_class,
          timelineStages: Array.isArray(report.timeline) ? report.timeline.slice(0, 30)
            .map((item) => (item as { kind: string }).kind) : [],
          metrics: report.metrics, finance: report.finance,
          permanentActions: Array.isArray(report.permanent_actions) ?
            report.permanent_actions.length : 0 },
        dossierSchema: postmortemBody, tools: [],
        validateDossier: (body) => body.incident_id === input.incidentId &&
          isSafePublicText(body.summary_pt) && isSafePublicText(body.learning_pt) });
      if (result.status !== "ok" || !result.data) {
        this.events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
          kind: "postmortem.agent_failure", actorId: agentId,
          createdAt: new Date().toISOString(), payload: { status: result.status } });
        return "fallback";
      }
      narrative = result.data;
      this.events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
        kind: "dossier.postmortem", actorId: agentId,
        entryKey: `postmortem:dossier:${input.incidentId}`,
        createdAt: new Date().toISOString(), payload: narrative });
    }
    this.events.append({ round_id: input.roundId, ts: new Date().toISOString(),
      twin_ts: input.twinNow.toISOString(), type: "postmortem.narrated",
      actor: { id: "postmortem", role: "postmortem" }, area: input.area,
      incident_id: input.incidentId, public_summary_pt: narrative.summary_pt,
      public: { incident_id: input.incidentId, summary_pt: narrative.summary_pt,
        learning_pt: narrative.learning_pt, residual_risk: narrative.residual_risk } },
    `postmortem:narrated:${input.incidentId}`);
    return "narrated";
  }
}
