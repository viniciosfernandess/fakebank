import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";

export interface SocMetrics {
  attempts: number;
  pending: number;
  unclassified: number;
  blockedInline: number;
  detectedAfter: number;
  undetected: number;
  blockedInlinePct: number;
  detectedAfterPct: number;
  undetectedPct: number;
  unclassifiedPct: number;
  mttdSeconds: number | null;
  mttaSeconds: number | null;
  mttcSeconds: number | null;
  mttrFixSeconds: number | null;
  mttrRecoverySeconds: number | null;
  lossCents: number;
  recoveredCents: number;
  absorbedCents: number;
  bankReimbursedCents: number;
  restoredCents: number;
  honestFalseBlocks: number;
  reviewRejections: number;
  rollbacks: number;
}

type PublicEvent = Omit<ArenaEvent, "private">;
const amount = (value: unknown): number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;
const seconds = (start: PublicEvent, end: PublicEvent): number | null => {
  const delta = (Date.parse(end.ts) - Date.parse(start.ts)) / 1000;
  return Number.isFinite(delta) && delta >= 0 ? delta : null;
};
const average = (values: (number | null)[]): number | null => {
  const valid = values.filter((value): value is number => value !== null);
  return valid.length ? Math.round(valid.reduce((sum, value) => sum + value, 0) / valid.length) : null;
};

export function calculateSocMetrics(events: PublicEvent[], links: {
  attack_id: string; incident_id: string;
}[], bankReimbursedCents = 0): SocMetrics {
  const ordered = [...events].sort((left, right) => left.seq - right.seq);
  const first = (type: PublicEvent["type"], incidentId: string): PublicEvent | undefined =>
    ordered.find((event) => event.type === type && event.incident_id === incidentId);
  const firstAttempt = new Map<string, PublicEvent>();
  for (const event of ordered) if (event.type === "attack.attempted" &&
    !firstAttempt.has(String(event.public.attack_id)))
    firstAttempt.set(String(event.public.attack_id), event);
  const attempts = new Set(firstAttempt.keys());
  const failed = new Map(ordered.filter((event) => event.type === "attack.failed")
    .map((event) => [String(event.public.attack_id), event]));
  const successes = new Map(ordered.filter((event) => event.type === "attack.succeeded")
    .map((event) => [String(event.public.attack_id), event]));
  for (const attackId of failed.keys()) attempts.add(attackId);
  for (const attackId of successes.keys()) attempts.add(attackId);
  const incidentOpened = new Map(ordered.filter((event) => event.type === "incident.opened")
    .map((event) => [String(event.public.incident_id), event]));
  const byAttack = new Map<string, string>();
  for (const link of links) {
    const opened = incidentOpened.get(link.incident_id);
    const current = byAttack.get(link.attack_id);
    if (opened && (!current || !incidentOpened.has(current) ||
      opened.seq < incidentOpened.get(current)!.seq))
      byAttack.set(link.attack_id, link.incident_id);
  }
  let blockedInline = 0;
  let detectedAfter = 0;
  let undetected = 0;
  let unclassified = 0;
  const mttd: (number | null)[] = [];
  const mtta: (number | null)[] = [];
  const mttc: (number | null)[] = [];
  const mttrFix: (number | null)[] = [];
  const mttrRecovery: (number | null)[] = [];
  let pending = 0;
  for (const attackId of attempts) {
    const attack = successes.get(attackId);
    if (!attack) {
      const failure = failed.get(attackId);
      if (!failure) pending++;
      else if (failure.public.blocked_by === "rule") blockedInline++;
      else unclassified++;
      continue;
    }
    const attempted = firstAttempt.get(attackId) ?? attack;
    const started = ordered.find((event) => event.type === "agent.spawned" &&
      event.public.agent_id === attack.actor.id && event.seq <= attempted.seq) ?? attempted;
    const incidentId = byAttack.get(attackId);
    const opened = incidentId ? incidentOpened.get(incidentId) : undefined;
    if (!incidentId || !opened) {
      undetected++;
      continue;
    }
    if (opened.public.source === "audit") undetected++;
    else detectedAfter++;
    const contained = first("containment.applied", incidentId);
    const firstAction = ordered.find((event) => event.incident_id === incidentId &&
      (event.type === "containment.applied" || event.type === "task.opened"));
    const firstRecovery = ordered.find((event) => event.type === "damage.restored" &&
      event.incident_id === incidentId);
    const validMerge = ordered.filter((event) => event.type === "patch.merged" &&
      event.incident_id === incidentId &&
      event.public.phase !== "hardening" &&
      (!firstRecovery || event.seq < firstRecovery.seq) &&
      !ordered.some((later) => later.type === "deploy.rolled_back" &&
        later.incident_id === incidentId &&
        (later.task_id ?? later.public.task_id) === (event.task_id ?? event.public.task_id) &&
        later.seq > event.seq)).at(-1);
    const recovered = ordered.filter((event) => event.type === "damage.restored" &&
      event.incident_id === incidentId && amount(event.public.restored_cents) > 0).at(-1);
    const lastState = ordered.filter((event) => event.type === "incident.updated" &&
      event.incident_id === incidentId).at(-1);
    const recoveryComplete = lastState?.public.state === "resolved";
    if (opened.public.source !== "audit") mttd.push(seconds(started, opened));
    mtta.push(firstAction ? seconds(opened, firstAction) : null);
    mttc.push(contained ? seconds(opened, contained) : null);
    mttrFix.push(validMerge ? seconds(started, validMerge) : null);
    mttrRecovery.push(recoveryComplete && recovered ? seconds(started, recovered) : null);
  }
  const total = attempts.size - pending;
  const pct = (count: number) => total ? Math.round(count * 10_000 / total) / 100 : 0;
  const restoredEvents = ordered.filter((event) => event.type === "damage.restored");
  const parent = new Map<string, string>();
  const root = (key: string): string => {
    let current = key;
    while (parent.has(current)) current = parent.get(current)!;
    return current;
  };
  for (const link of links) {
    const attack = root(`attack:${link.attack_id}`);
    const incident = root(`incident:${link.incident_id}`);
    if (attack !== incident) parent.set(attack, incident);
  }
  const impactByCase = new Map<string, number>();
  for (const event of ordered.filter((item) => item.type === "impact.caused")) {
    const attackId = String(event.public.attack_id);
    const key = root(`attack:${attackId}`);
    impactByCase.set(key, (impactByCase.get(key) ?? 0) + amount(event.public.loss_cents));
  }
  const assessedByCase = new Map<string, number>();
  const restoredByCase = new Map<string, number>();
  for (const event of ordered) {
    if (event.type !== "damage.restored" && event.type !== "damage.assessed") continue;
    const key = event.incident_id ?? String(event.public.incident_id);
    if (event.type === "damage.restored") {
      restoredByCase.set(key, (restoredByCase.get(key) ?? 0) +
        amount(event.public.restored_cents));
    } else {
      assessedByCase.set(key, Math.max(assessedByCase.get(key) ?? 0,
        (restoredByCase.get(key) ?? 0) + amount(event.public.loss_cents)));
    }
  }
  const assessedByGroup = new Map<string, number>();
  const restoredByGroup = new Map<string, number>();
  for (const [incidentId, cents] of assessedByCase) {
    const key = root(`incident:${incidentId}`);
    assessedByGroup.set(key, (assessedByGroup.get(key) ?? 0) + cents);
  }
  for (const [incidentId, cents] of restoredByCase) {
    const key = root(`incident:${incidentId}`);
    restoredByGroup.set(key, (restoredByGroup.get(key) ?? 0) + cents);
  }
  const cases = new Set([...impactByCase.keys(), ...assessedByGroup.keys(),
    ...restoredByGroup.keys()]);
  const lossCents = [...cases].reduce((sum, key) => sum + Math.max(
    impactByCase.get(key) ?? 0, assessedByGroup.get(key) ?? 0,
    restoredByGroup.get(key) ?? 0), 0);
  const grossAbsorbed = restoredEvents.reduce((sum, event) => sum +
    amount(event.public.absorbed_cents), 0);
  const reimbursed = Math.min(grossAbsorbed, amount(bankReimbursedCents));
  return {
    attempts: attempts.size, pending, unclassified, blockedInline, detectedAfter, undetected,
    blockedInlinePct: pct(blockedInline), detectedAfterPct: pct(detectedAfter),
    undetectedPct: pct(undetected), unclassifiedPct: pct(unclassified),
    mttdSeconds: average(mttd),
    mttaSeconds: average(mtta), mttcSeconds: average(mttc),
    mttrFixSeconds: average(mttrFix), mttrRecoverySeconds: average(mttrRecovery),
    lossCents,
    recoveredCents: restoredEvents.reduce((sum, event) => sum +
      amount(event.public.recovered_cents), reimbursed),
    absorbedCents: grossAbsorbed - reimbursed,
    bankReimbursedCents: reimbursed,
    restoredCents: restoredEvents.reduce((sum, event) => sum +
      amount(event.public.restored_cents), 0),
    honestFalseBlocks: ordered.filter((event) => event.type === "sim.tick")
      .reduce((sum, event) => sum + amount(event.public.honest_blocked), 0),
    reviewRejections: ordered.filter((event) => event.type === "review.rejected").length,
    rollbacks: ordered.filter((event) => event.type === "deploy.rolled_back").length,
  };
}
