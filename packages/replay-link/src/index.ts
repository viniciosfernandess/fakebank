import type { ArenaEvent } from "../../contracts/src/index.ts";

const CHAPTER_TYPES = {
  start: ["round.started"], breach: ["attack.succeeded"],
  detect: ["sentinel.alert"], reject: ["review.rejected"],
  seal: ["patch.merged", "deploy.succeeded"], restore: ["damage.restored"],
  quarantine: ["area.quarantined"], score: ["round.ended"],
} as const;
type Chapter = keyof typeof CHAPTER_TYPES;
export type MomentPosition = { kind: "final" } | { kind: "time"; seconds: number } |
  { kind: "chapter"; chapter: Chapter; ordinal: number };

export function parseMomentPosition(value: string | undefined): MomentPosition | null {
  if (value === undefined) return { kind: "final" };
  if (/^\d{1,5}$/.test(value)) {
    const seconds = Number(value);
    return seconds <= 86_400 ? { kind: "time", seconds } : null;
  }
  const match = /^chapter:([a-z]+)-(\d{1,2})$/.exec(value);
  if (!match || !(match[1]! in CHAPTER_TYPES)) return null;
  const ordinal = Number(match[2]);
  return ordinal >= 1 && ordinal <= 20 ?
    { kind: "chapter", chapter: match[1] as Chapter, ordinal } : null;
}

export function resolveMomentCursor(events: readonly ArenaEvent[], position: MomentPosition): number | null {
  if (position.kind === "final") return events.length;
  if (position.kind === "time") {
    const first = events[0];
    if (!first) return 0;
    const target = Date.parse(first.ts) + position.seconds * 1_000;
    return events.filter((event) => Date.parse(event.ts) <= target).length;
  }
  const types: readonly string[] = CHAPTER_TYPES[position.chapter];
  let found = 0;
  for (const [index, event] of events.entries()) {
    if (!types.includes(event.type)) continue;
    found++;
    if (found === position.ordinal) return index + 1;
  }
  return null;
}
