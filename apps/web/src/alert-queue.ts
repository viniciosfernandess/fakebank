import { AREAS, type Area, type ArenaEvent } from "../../../packages/contracts/src/index.ts";

export interface RecentAlert {
  event: ArenaEvent;
  area: Area;
  severity: "low" | "medium" | "high" | "critical";
  ruleId: string;
  ageSeconds: number;
}

const severities = ["low", "medium", "high", "critical"] as const;

export function recentAlerts(events: ArenaEvent[], nowMs: number, limit = 3): RecentAlert[] {
  const alerts: RecentAlert[] = [];
  const seen = new Set<string>();
  for (let index = events.length - 1; index >= 0 && alerts.length < limit; index--) {
    const event = events[index]!;
    if (event.type !== "sentinel.alert") continue;
    const id = event.public.alert_id;
    const area = event.area ?? event.public.area;
    const severity = event.public.severity;
    if (typeof id !== "string" || seen.has(id) || !AREAS.includes(area as Area) ||
      !severities.includes(severity as RecentAlert["severity"])) continue;
    seen.add(id);
    const timestamp = Date.parse(event.ts);
    alerts.push({ event, area: area as Area, severity: severity as RecentAlert["severity"],
      ruleId: String(event.public.rule_id),
      ageSeconds: Number.isFinite(timestamp) ? Math.max(0, Math.floor((nowMs - timestamp) / 1000)) : 0 });
  }
  return alerts;
}

export function alertAge(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
  return `${Math.floor(seconds / 3600)} h`;
}
