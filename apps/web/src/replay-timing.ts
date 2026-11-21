export interface TimedEvent { ts: string }

export function nextReplayStep(events: readonly TimedEvent[], cursor: number, speed: 1 | 4 | 16):
  { cursor: number; delayMs: number } | null {
  if (cursor >= events.length) return null;
  const next = events[cursor]!;
  const previous = events[cursor - 1];
  const gap = previous ? Date.parse(next.ts) - Date.parse(previous.ts) : 0;
  const delayMs = Math.max(0, Math.min(Number.isFinite(gap) ? gap : 0, 5_000)) / speed;
  let end = cursor + 1;
  while (end < events.length && events[end]!.ts === next.ts) end++;
  return { cursor: end, delayMs };
}
