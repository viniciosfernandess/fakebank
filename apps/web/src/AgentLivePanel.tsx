import { useMemo, useState } from "react";
import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";
import { agentActivity } from "./agent-live.ts";

function elapsedSeconds(startedAt: string, endMs: number): string {
  const seconds = Math.max(0, Math.floor((endMs - Date.parse(startedAt)) / 1000));
  return seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`;
}

export function AgentLivePanel({ events, nowMs, presentation, onSelect }: {
  events: readonly ArenaEvent[]; nowMs: number; presentation: boolean;
  onSelect: (event: ArenaEvent) => void;
}) {
  const rows = useMemo(() => agentActivity(events).slice(0, 8), [events]);
  const [expanded, setExpanded] = useState<string | null>(null);
  return <section className="agent-live-panel" aria-label="Threads de agentes">
    <div className="subheading">THREADS DE AGENTES <span>{rows.length} RECENTES</span></div>
    {rows.length === 0 ? <p>Nenhuma thread iniciada nesta visão.</p> :
      <ol>{rows.map((row) => <li key={row.key}>
        <button className="agent-live-row" aria-expanded={expanded === row.key}
          onClick={() => setExpanded(expanded === row.key ? null : row.key)}>
          <strong>{row.role.replaceAll("_", " ")}</strong>
          <span>{row.outcome ?? "ativo"}</span>
          <span>{presentation ? "—" : row.currentTool ? `Última: ${row.currentTool}` : "—"}</span>
          <span>{row.tokens === null ? "—" : `${row.tokens} tokens`}</span>
          <time>{elapsedSeconds(row.startedAt, row.outcome ?
            Date.parse(row.lastAt) : nowMs)}</time>
        </button>
        {expanded === row.key && <div className="agent-live-detail">
          <small>Thread {presentation ? "reservada" : row.agentId}</small>
          {row.events.slice(-12).map((event) => <button key={event.seq}
            onClick={() => onSelect(event)}>
            <time>{new Date(event.ts).toLocaleTimeString("pt-BR", {
              hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time>
            <span>{presentation ? "Evento de agente" : event.type === "context.handoff" ?
              `Handoff: ${String(event.public.summary_pt ?? event.public_summary_pt)}` :
              event.type === "tool.called" ?
                String(event.public.label_pt ?? event.public.tool) :
                event.public_summary_pt}</span>
          </button>)}</div>}
      </li>)}</ol>}
  </section>;
}
