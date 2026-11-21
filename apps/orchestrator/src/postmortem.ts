import type { Area, ArenaEvent } from "../../../packages/contracts/src/index.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";

const included = new Set(["incident.opened", "containment.applied", "dossier.incident_map",
  "dossier.root_cause", "dossier.fix_design", "review.rejected", "patch.merged",
  "damage.assessed", "damage.restored", "hardening.proof"]);
const cents = (value: unknown): number => typeof value === "number" &&
  Number.isSafeInteger(value) && value >= 0 ? value : 0;
const elapsed = (start: ArenaEvent | undefined, end: ArenaEvent | undefined): number | null => {
  if (!start || !end) return null;
  const seconds = (Date.parse(end.ts) - Date.parse(start.ts)) / 1000;
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
};

export function publishPostmortem(events: EventStore, input: {
  incidentId: string; roundId: string; area: Area; twinNow: Date;
}): void {
  if (events.caseFile.history(input.incidentId).some((entry) =>
    entry.kind === "postmortem.report")) return;
  const rows = events.db.prepare(`SELECT seq FROM events WHERE incident_id=? ORDER BY seq`)
    .all(input.incidentId) as { seq: number }[];
  const history = rows.map(({ seq }) => events.get(seq)!).filter(Boolean);
  const first = (type: string): ArenaEvent | undefined =>
    history.find((event) => event.type === type);
  const opened = first("incident.opened");
  const containment = first("containment.applied");
  const action = history.find((event) => event.type === "containment.applied" ||
    event.type === "task.opened");
  const recovery = history.filter((event) => event.type === "damage.restored");
  const merges = history.filter((event) => event.type === "patch.merged");
  const firstRecovery = recovery[0];
  const fix = merges.filter((event) => event.public.phase !== "hardening" &&
    (!firstRecovery || event.seq < firstRecovery.seq) &&
    !history.some((later) => later.type === "deploy.rolled_back" &&
      (later.task_id ?? later.public.task_id) === (event.task_id ?? event.public.task_id) &&
      later.seq > event.seq)).at(-1);
  const linkTable = events.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='attack_incident_links'`).get();
  const attackRow = linkTable ? events.db.prepare(`SELECT MIN(e.seq) seq FROM events e
    JOIN attack_incident_links l ON l.attack_id=json_extract(e.public_json,'$.attack_id')
    WHERE l.incident_id=? AND e.type='attack.attempted'`).get(input.incidentId) as
      { seq: number | null } : undefined;
  const attack = attackRow?.seq ? events.get(attackRow.seq) : undefined;
  let restoredCents = 0;
  let lossCents = 0;
  for (const event of history) {
    if (event.type === "damage.restored") restoredCents += cents(event.public.restored_cents);
    if (event.type === "damage.assessed") lossCents = Math.max(lossCents,
      restoredCents + cents(event.public.loss_cents));
  }
  lossCents = Math.max(lossCents, restoredCents);
  const caseHistory = events.caseFile.history(input.incidentId);
  const rootCause = caseHistory.filter((entry) => entry.kind === "dossier.root_cause")
    .at(-1)?.payload;
  const milestones = caseHistory.filter((entry) => included.has(entry.kind));
  const selectedMilestones = milestones.length > 100 ?
    [...milestones.slice(0, 10), ...milestones.slice(-90)] : milestones;
  const report = {
    incident_id: input.incidentId,
    root_cause_class: typeof rootCause?.class === "string" ? rootCause.class : null,
    root_cause_explanation: typeof rootCause?.explanation === "string" ?
      rootCause.explanation : null,
    timeline_total_steps: milestones.length,
    timeline_truncated: milestones.length > selectedMilestones.length,
    timeline: selectedMilestones
      .map((entry) => ({ kind: entry.kind, at: entry.created_at,
        event_seq: entry.source_event_seq })),
    metrics: { mttd_s: opened?.public.source === "audit" ? null : elapsed(attack, opened),
      mtta_s: elapsed(opened, action), mttc_s: elapsed(opened, containment),
      mttr_fix_s: elapsed(attack, fix),
      mttr_recovery_s: elapsed(attack, recovery.at(-1)) },
    finance: { loss_cents: lossCents,
      recovered_cents: recovery.reduce((sum, event) =>
        sum + cents(event.public.recovered_cents), 0),
      absorbed_cents: recovery.reduce((sum, event) =>
        sum + cents(event.public.absorbed_cents), 0) },
    permanent_actions: merges.filter((event) => !history.some((later) =>
      later.type === "deploy.rolled_back" &&
      (later.task_id ?? later.public.task_id) === (event.task_id ?? event.public.task_id) &&
      later.seq > event.seq)).map((event) => ({ task_id: event.task_id ??
        event.public.task_id ?? null,
      phase: event.public.phase === "hardening" ? "hardening" : "fix",
      commit_short: event.public.commit_short ?? null })),
  };
  const at = new Date().toISOString();
  events.append({ round_id: input.roundId, ts: at,
    twin_ts: input.twinNow.toISOString(), type: "postmortem.published",
    actor: { id: "postmortem", role: "system" }, area: input.area,
    incident_id: input.incidentId,
    public_summary_pt: "Postmortem do incidente publicado com linha do tempo e métricas",
    public: { incident_id: input.incidentId,
      summary_pt: "A resposta foi concluída e os controles permanentes foram registrados.",
      timeline_steps: report.timeline_total_steps,
      ...report.metrics, ...report.finance,
      permanent_actions: report.permanent_actions.length } },
  `postmortem:${input.incidentId}`);
  events.caseFile.record({ incidentId: input.incidentId, roundId: input.roundId,
    kind: "postmortem.report", actorId: "postmortem",
    entryKey: `postmortem:${input.incidentId}`, createdAt: at, payload: report });
}
