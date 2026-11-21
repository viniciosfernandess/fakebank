import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";

export interface ReplayChapter {
  key: string;
  label: string;
  cursor: number;
  seq: number;
}

const markers = [
  { key: "start", label: "INÍCIO", matches: (event: ArenaEvent) => event.type === "round.started" },
  { key: "signal", label: "ALARME", matches: (event: ArenaEvent) =>
    event.type === "sentinel.alert" || event.type === "incident.opened" },
  { key: "contain", label: "CONTENÇÃO", matches: (event: ArenaEvent) =>
    event.type === "containment.applied" },
  { key: "reject", label: "REPROVAÇÃO", matches: (event: ArenaEvent) =>
    event.type === "review.rejected" },
  { key: "merge", label: "CORREÇÃO", matches: (event: ArenaEvent) =>
    event.type === "patch.merged" && event.public.phase !== "hardening" },
  { key: "med", label: "MED BLOQUEADO", matches: (event: ArenaEvent) =>
    event.type === "damage.assessed" && Number(event.public.blocked_cents) > 0 },
  { key: "hardening", label: "NOVA REGRA", matches: (event: ArenaEvent) =>
    event.type === "patch.merged" && event.public.phase === "hardening" },
  { key: "close", label: "ENCERRAMENTO", matches: (event: ArenaEvent) =>
    event.type === "round.ended" },
] as const;

export function replayChapters(events: ArenaEvent[]): ReplayChapter[] {
  const chapters = markers.flatMap((marker) => {
    const index = events.findIndex(marker.matches);
    return index < 0 ? [] : [{ key: marker.key, label: marker.label,
      cursor: index + 1, seq: events[index]!.seq }];
  });
  return chapters.sort((left, right) => left.cursor - right.cursor);
}
