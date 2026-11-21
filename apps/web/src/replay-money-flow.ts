import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";
import type { MoneyFlowSnapshot } from "./MoneyFlow.tsx";

export function replayMoneyFlow(events: readonly ArenaEvent[],
  incidentId: string | null | undefined): MoneyFlowSnapshot | null {
  if (incidentId === undefined) return null;
  for (let index = events.length - 1; index >= 0; index--) {
    const event = events[index]!;
    if (event.type !== "money_flow.disclosed" || !event.incident_id ||
      event.public.incident_id !== event.incident_id ||
      incidentId !== null && event.incident_id !== incidentId) continue;
    const edges = event.public.edges as MoneyFlowSnapshot["edges"];
    if (!Array.isArray(edges) || !edges.length) continue;
    let med: MoneyFlowSnapshot["med"] = null;
    for (let later = events.length - 1; later > index; later--) {
      const update = events[later]!;
      if (update.type !== "money_flow.med_updated" ||
        update.public.disclosure_seq !== event.seq ||
        update.incident_id !== event.incident_id || update.public.masked) continue;
      med = { status: update.public.status as NonNullable<typeof med>["status"],
        recovery: update.public.recovery as NonNullable<typeof med>["recovery"],
        institutions: update.public.institutions as NonNullable<typeof med>["institutions"],
        ...(Array.isArray(update.public.accounts) ?
          { accounts: update.public.accounts as NonNullable<typeof med>["accounts"] } : {}) };
      break;
    }
    return { incidentId: event.incident_id, edges, med };
  }
  return null;
}
