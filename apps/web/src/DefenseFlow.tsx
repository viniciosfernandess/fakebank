import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";
import { useEffect, useRef } from "react";
import { defenseFlow, defenseIncidents, type DefenseIncident } from "./defense-flow.ts";

const areaNames: Record<string, string> = {
  auth: "AUTENTICAÇÃO", accounts: "CONTAS", pix: "PIX", cards: "CARTÕES",
  loans: "CRÉDITO", api_gateway: "ENTRADA", ledger: "LIVRO-RAZÃO",
};

export function DefenseFlow({ events, presentation, selectedId, onIncidentSelect, onSelect }: {
  events: ArenaEvent[];
  presentation: boolean;
  selectedId: string | null;
  onIncidentSelect: (incident: DefenseIncident) => void;
  onSelect: (event: ArenaEvent) => void;
}) {
  const incidents = defenseIncidents(events);
  const currentId = selectedId && incidents.some(({ id }) => id === selectedId) ?
    selectedId : incidents.at(-1)?.id;
  const steps = defenseFlow(events, currentId);
  const roundRejections = events.filter((event) => event.type === "review.rejected").length;
  const listRef = useRef<HTMLOListElement>(null);
  const lastSeq = steps.at(-1)?.event.seq;
  useEffect(() => { if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight; }, [currentId, lastSeq]);
  return <section className="defense-flow" aria-label="Fluxo da defesa">
    <div className="subheading">FLUXO DA DEFESA <span>{roundRejections ?
      `↩ ${roundRejections} ${roundRejections === 1 ? "DEVOLUÇÃO" : "DEVOLUÇÕES"} NA RODADA` :
      steps.length ? "MARCOS CONFIRMADOS" : "AGUARDANDO"}</span></div>
    {incidents.length > 1 && <div className="flow-incidents" role="group" aria-label="Selecionar incidente">
      {incidents.map((incident, index) => <button key={incident.id} aria-pressed={incident.id === currentId}
        onClick={() => onIncidentSelect(incident)}>
        {String(index + 1).padStart(2, "0")} {incident.area ? areaNames[incident.area] : "INCIDENTE"}
      </button>)}
    </div>}
    {steps.length ? <ol ref={listRef}>{steps.map((step, index) => <li key={step.event.seq}>
      <button onClick={() => {
        const incident = incidents.find(({ id }) => id === currentId);
        if (incident) onIncidentSelect(incident);
        onSelect(step.event);
      }} aria-current={index === steps.length - 1 ? "step" : undefined}>
        <span className="flow-index">{String(index + 1).padStart(2, "0")}</span>
        <span className="flow-copy"><strong>{step.label}</strong><small>{presentation ? step.presentationSummary : step.event.public_summary_pt}</small></span>
        {step.retry !== null && <em>TENTATIVA {step.retry}</em>}
      </button>
    </li>)}</ol> : <p>Aguardando o primeiro incidente.</p>}
  </section>;
}
