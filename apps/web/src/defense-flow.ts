import type { Area, ArenaEvent } from "../../../packages/contracts/src/index.ts";

export interface DefenseStep {
  event: ArenaEvent;
  label: string;
  presentationSummary: string;
  retry: number | null;
}

export interface DefenseIncident {
  id: string;
  area?: Area;
  firstSeq: number;
}

const labels: Partial<Record<ArenaEvent["type"], [string, string]>> = {
  "incident.opened": ["INCIDENTE", "Incidente registrado"],
  "containment.applied": ["CONTENÇÃO", "Contenção aplicada"],
  "task.opened": ["ARQUITETO", "Correção solicitada"],
  "patch.proposed": ["BUILDER", "Candidato entregue para revisão"],
  "review.rejected": ["REPROVAÇÃO ↩", "Candidato devolvido ao arquiteto"],
  "review.approved": ["REVISOR", "Candidato aprovado"],
  "patch.merged": ["MERGE", "Correção integrada"],
  "deploy.succeeded": ["IMPLANTAÇÃO", "Versão ativada"],
  "damage.assessed": ["DANO", "Dano avaliado"],
  "damage.restored": ["RESTAURO", "Recuperação registrada"],
  "postmortem.published": ["POSTMORTEM", "Lições publicadas"],
};

function taskIncidents(events: ArenaEvent[]): Map<string, string> {
  const incidentByTask = new Map<string, string>();
  for (const event of events) {
    if (event.type === "task.opened" && typeof event.public.task_id === "string" &&
      typeof event.public.incident_id === "string") {
      incidentByTask.set(event.public.task_id, event.public.incident_id);
    }
  }
  return incidentByTask;
}

function linkedIncident(event: ArenaEvent, incidentByTask: Map<string, string>): string | undefined {
  const taskId = event.task_id ?? event.public.task_id;
  const id = event.incident_id ?? event.public.incident_id ??
    (typeof taskId === "string" ? incidentByTask.get(taskId) : undefined);
  return typeof id === "string" ? id : undefined;
}

export function defenseIncidents(events: ArenaEvent[]): DefenseIncident[] {
  const incidentByTask = taskIncidents(events);
  const incidents = new Map<string, DefenseIncident>();
  for (const event of events) {
    if (!labels[event.type] && event.type !== "incident.updated") continue;
    const id = linkedIncident(event, incidentByTask);
    if (!id) continue;
    const existing = incidents.get(id);
    if (existing && !existing.area && event.area) existing.area = event.area;
    else if (!existing) incidents.set(id, { id, ...(event.area ? { area: event.area } : {}), firstSeq: event.seq });
  }
  return [...incidents.values()];
}

export function defenseFlow(events: ArenaEvent[], incidentId = defenseIncidents(events).at(-1)?.id): DefenseStep[] {
  if (!incidentId) return [];
  const incidentByTask = taskIncidents(events);
  return events.flatMap((event) => {
    const match = labels[event.type];
    if (!match) return [];
    if (linkedIncident(event, incidentByTask) !== incidentId) return [];
    const label = event.type === "patch.merged" && event.public.phase === "hardening" ?
      "NOVA REGRA" : match[0];
    const retry = event.type === "review.rejected" &&
      Number.isInteger(event.public.attempt) && Number(event.public.attempt) >= 1 ?
      Number(event.public.attempt) + 1 : null;
    return [{ event, label, presentationSummary: match[1], retry }];
  });
}
