import type { ArenaEvent, EventType } from "../../../packages/contracts/src/index.ts";

export type TimelineLane = "attack" | "detection" | "correction";
export interface TimelineEntry {
  event: ArenaEvent;
  incidentId: string | null;
}

const laneByType: Partial<Record<EventType, TimelineLane>> = {
  "attack.attempted": "attack", "attack.succeeded": "attack",
  "attack.failed": "attack", "impact.caused": "attack",
  "sentinel.alert": "detection", "incident.opened": "detection",
  "incident.updated": "detection", "containment.applied": "detection",
  "damage.assessed": "detection",
  "task.opened": "correction", "patch.proposed": "correction",
  "review.rejected": "correction", "review.approved": "correction",
  "patch.merged": "correction", "deploy.succeeded": "correction",
  "deploy.rolled_back": "correction", "damage.restored": "correction",
  "postmortem.published": "correction",
};

function publicId(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

export function threeLaneTimeline(events: ArenaEvent[], selectedIncident?: string | null,
  limit = 8): Record<TimelineLane, TimelineEntry[]> {
  const taskIncident = new Map<string, string>();
  for (const event of events) {
    if (event.type !== "task.opened") continue;
    const task = publicId(event.public.task_id);
    const incident = publicId(event.incident_id ?? event.public.incident_id);
    if (task && incident) taskIncident.set(task, incident);
  }
  const lanes: Record<TimelineLane, TimelineEntry[]> = {
    attack: [], detection: [], correction: [],
  };
  for (const event of events) {
    const lane = laneByType[event.type];
    if (!lane) continue;
    const task = publicId(event.task_id ?? event.public.task_id);
    const incidentId = publicId(event.incident_id ?? event.public.incident_id) ??
      (task ? taskIncident.get(task) ?? null : null);
    if (selectedIncident && incidentId !== selectedIncident) continue;
    lanes[lane].push({ event, incidentId });
  }
  for (const lane of Object.keys(lanes) as TimelineLane[])
    lanes[lane] = lanes[lane].slice(-limit);
  return lanes;
}
