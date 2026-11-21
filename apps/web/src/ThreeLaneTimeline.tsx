import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";
import { presentationEventSummary } from "./presentation-mode.ts";
import { threeLaneTimeline, type TimelineLane } from "./three-lane-timeline.ts";

const laneNames: Record<TimelineLane, string> = {
  attack: "Ataque", detection: "Detecção", correction: "Correção",
};

function timeOf(event: ArenaEvent): string {
  const value = event.twin_ts ?? event.ts;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleTimeString("pt-BR", {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    timeZone: "America/Sao_Paulo",
  }) : "—";
}

export function ThreeLaneTimeline({ events, selectedIncident, presentation,
  attackEnabled, onSelect }: {
    events: ArenaEvent[]; selectedIncident?: string | null;
    presentation: boolean; attackEnabled: boolean;
    onSelect: (event: ArenaEvent) => void;
  }) {
  const lanes = threeLaneTimeline(events, selectedIncident);
  return <section className="three-lane-timeline" aria-label="Raias sincronizadas da rodada">
    <header><div><small>REPLAY SINCRONIZADO</small><h2>O que aconteceu, quem percebeu e o que mudou</h2></div>
      <span>{selectedIncident ? "Incidente selecionado" : "Eventos até o cursor atual"}</span></header>
    <div className="three-lane-grid">{(["attack", "detection", "correction"] as const)
      .map((lane) => <section key={lane} aria-label={`Raia de ${laneNames[lane].toLowerCase()}`}
        className={`three-lane-column ${lane}`}>
        <h3>{laneNames[lane]} <span>{lanes[lane].length}</span></h3>
        {lanes[lane].length ? <ol>{lanes[lane].map(({ event, incidentId }) =>
          <li key={event.seq}>
            <button onClick={() => onSelect(event)}>
              <time>{timeOf(event)}</time>
              <strong>{presentation ? presentationEventSummary(event) :
                event.public_summary_pt}</strong>
              {incidentId && <small>{presentation ? "Vinculado ao incidente" :
                `Incidente …${incidentId.slice(-8)}`}</small>}
              {event.type === "review.rejected" && <em>↩ Revisão devolvida</em>}
            </button>
          </li>)}</ol> : <p>{lane === "attack" && !attackEnabled ?
          "Simulação ofensiva desativada nesta execução." : selectedIncident ?
            "Sem evento vinculado a este incidente." : "Aguardando eventos."}</p>}
      </section>)}</div>
  </section>;
}
