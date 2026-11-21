import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";

export interface RecoveryOverview {
  impactCents: number | null;
  restoredCents: number | null;
  recoveredCents: number | null;
  absorbedCents: number | null;
}

export function recoveryOverview(events: readonly ArenaEvent[]): RecoveryOverview {
  let impactCents: number | null = null;
  let restoredCents: number | null = null;
  let recoveredCents: number | null = null;
  let absorbedCents: number | null = null;
  let breakdownComplete = true;
  for (const event of events) {
    if (event.type === "impact.caused") {
      impactCents = (impactCents ?? 0) + Number(event.public.loss_cents);
    }
    if (event.type === "damage.restored") {
      const restored = Number(event.public.restored_cents);
      restoredCents = (restoredCents ?? 0) + restored;
      if (restored > 0 && (typeof event.public.recovered_cents !== "number" ||
        typeof event.public.absorbed_cents !== "number")) breakdownComplete = false;
      if (typeof event.public.recovered_cents === "number")
        recoveredCents = (recoveredCents ?? 0) + event.public.recovered_cents;
      if (typeof event.public.absorbed_cents === "number")
        absorbedCents = (absorbedCents ?? 0) + event.public.absorbed_cents;
    }
  }
  if (!breakdownComplete) return { impactCents, restoredCents,
    recoveredCents: null, absorbedCents: null };
  return { impactCents, restoredCents, recoveredCents, absorbedCents };
}
