import { z } from "zod";

const BRT = "America/Sao_Paulo";
const dateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const formatter = new Intl.DateTimeFormat("en-CA", { timeZone: BRT, year: "numeric", month: "2-digit",
  day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" });

function parts(at: Date): { date: string; hour: number; minute: number } {
  const values = Object.fromEntries(formatter.formatToParts(at).map((part) => [part.type, part.value]));
  return { date: `${values.year}-${values.month}-${values.day}`,
    hour: Number(values.hour), minute: Number(values.minute) };
}
function brtInstant(date: string, hour: number): Date {
  const [year, month, day] = date.split("-").map(Number);
  const anchor = Date.UTC(year!, month! - 1, day!, hour);
  for (let offsetMinutes = -12 * 60; offsetMinutes <= 14 * 60; offsetMinutes += 15) {
    const candidate = new Date(anchor - offsetMinutes * 60_000);
    const local = parts(candidate);
    if (local.date === date && local.hour === hour && local.minute === 0) return candidate;
  }
  throw new Error("BRT_SCHEDULE_TIME_UNAVAILABLE");
}
function dateAt(start: string, days: number): string {
  const [year, month, day] = start.split("-").map(Number);
  const value = new Date(Date.UTC(year!, month! - 1, day! + days));
  return value.toISOString().slice(0, 10);
}
export interface RoundSlot { roundNo: number; day: number; slot: "09:00" | "18:00" | "manual";
  startsAt: string; endsAt: string; roundId: string; }
export interface FeatureSlot { day: number; featureId: string; startsAt: string; }
const featureIds = ["pix_agendado_recorrente", "cartao_virtual_temporario", "emprestimo_relampago",
  "pix_aproximacao", "cashback", "compartilhar_dados", "limite_dinamico"] as const;

export function campaignSchedule(startBrtDate: string): { rounds: RoundSlot[]; features: FeatureSlot[] } {
  dateSchema.parse(startBrtDate);
  if (dateAt(startBrtDate, 0) !== startBrtDate) throw new Error("BRT_SCHEDULE_INVALID_DATE");
  const rounds: RoundSlot[] = [];
  const features: FeatureSlot[] = [];
  for (let day = 1; day <= 7; day++) {
    const date = dateAt(startBrtDate, day - 1);
    for (const [index, hour] of [9, 18].entries()) {
      const roundNo = 2 * (day - 1) + index + 1;
      const start = brtInstant(date, hour);
      rounds.push({ roundNo, day, slot: hour === 9 ? "09:00" : "18:00",
        startsAt: start.toISOString(), endsAt: new Date(start.getTime() + 40 * 60_000).toISOString(),
        roundId: `r${String(roundNo).padStart(2, "0")}` });
    }
    features.push({ day, featureId: featureIds[day - 1]!, startsAt: brtInstant(date, 12).toISOString() });
  }
  return { rounds, features };
}

export function nextRound(schedule: readonly RoundSlot[], after: Date): RoundSlot | undefined {
  return schedule.find((slot) => Date.parse(slot.startsAt) > after.getTime());
}
