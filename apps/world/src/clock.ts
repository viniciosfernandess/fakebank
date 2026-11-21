import { brtHour } from "./bank.ts";

export interface ClockSnapshot { twin_ts: string; brt_date: string; brt_hour: number;
  phase: "night" | "morning" | "afternoon" | "evening"; speed: number; }
export class TwinClock {
  private readonly realStartMs: number;
  private readonly twinStartMs: number;
  private readonly realNow: () => number;
  readonly speed: number;
  constructor(twinStart: Date, realNow: () => number = () => Date.now(), speed = 12) {
    if (!Number.isFinite(twinStart.getTime()) || !Number.isFinite(speed) || speed <= 0)
      throw new Error("Invalid Twin clock configuration");
    this.realNow = realNow;
    this.realStartMs = realNow();
    this.twinStartMs = twinStart.getTime();
    this.speed = speed;
  }
  now(): Date { return new Date(this.twinStartMs + (this.realNow() - this.realStartMs) * this.speed); }
  snapshot(): ClockSnapshot {
    const now = this.now();
    const brtHourOfDay = brtHour(now);
    const parts = new Intl.DateTimeFormat("en-US", { timeZone: "America/Sao_Paulo", year: "numeric",
      month: "2-digit", day: "2-digit" }).formatToParts(now);
    const value = (name: string): string => parts.find((part) => part.type === name)?.value ?? "";
    const brtDate = `${value("year")}-${value("month")}-${value("day")}`;
    const phase = brtHourOfDay < 6 ? "night" : brtHourOfDay < 12 ? "morning"
      : brtHourOfDay < 18 ? "afternoon" : brtHourOfDay < 22 ? "evening" : "night";
    return { twin_ts: now.toISOString(), brt_date: brtDate, brt_hour: brtHourOfDay, phase, speed: this.speed };
  }
  async waitTwinMinutes(minutes: number, signal?: AbortSignal): Promise<void> {
    if (!Number.isFinite(minutes) || minutes < 0 || minutes > 30) throw new Error("Twin wait must be 0–30 minutes");
    await new Promise<void>((resolve, reject) => {
      if (signal?.aborted) { reject(signal.reason); return; }
      const timer = setTimeout(() => { signal?.removeEventListener("abort", onAbort); resolve(); }, minutes * 60_000 / this.speed);
      const onAbort = (): void => { clearTimeout(timer); reject(signal?.reason); };
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }
}
