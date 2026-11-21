import type { Bank } from "../../world/src/bank.ts";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { ArenaEvent } from "../../../packages/contracts/src/index.ts";
import { CampaignScheduleStore } from "./schedule-store.ts";
import { redScore, blueScore } from "./scoring.ts";
import { snapshotRound, verifySnapshot } from "./snapshot.ts";
import type { LedgerAnchorStore } from "./ledger-anchors.ts";
import type { PeriodCloseAnchorStore } from "./period-close-anchors.ts";
import type { SimulatorDeviceKeys } from "../../world/src/simulator-device-keys.ts";
import type { RoundSlot } from "./schedule.ts";
import type { RoundNarration } from "./round-narrator.ts";
import type { CrossBookReport } from "../../ecosystem/src/verifier-client.ts";

interface SummaryScore { red_points: number; blue_points: number; attacks_succeeded: number;
  attacks_total: number; mttd_s: number | null; mttc_s: number | null; mttr_s: number | null;
  honest_wrongly_blocked: number; loss_cents: number; restored_cents: number; }
function scoreFromEvents(bank: Bank, events: EventStore, roundId: string,
  firstSeq: number, startedAt: string, endedAt: string): SummaryScore {
  const score: SummaryScore = { red_points: 0, blue_points: 0, attacks_succeeded: 0,
    attacks_total: 0, mttd_s: null, mttc_s: null, mttr_s: null, honest_wrongly_blocked: 0,
    loss_cents: 0, restored_cents: 0 };
  const rows: ArenaEvent[] = [];
  let after = firstSeq - 1;
  for (;;) {
    const batch = events.list({ after, limit: 500 });
    rows.push(...batch);
    if (batch.length < 500) break;
    after = batch.at(-1)!.seq;
  }
  const own = rows.filter((event) => event.round_id === roundId);
  const at = (event: ArenaEvent): number => Date.parse(event.ts);
  const attempted = own.filter((event) => event.type === "attack.attempted");
  const succeeded = own.filter((event) => event.type === "attack.succeeded");
  const failed = own.filter((event) => event.type === "attack.failed");
  const incidents = rows.filter((event) => event.type === "incident.opened");
  const linkTable = events.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='attack_incident_links'`).get();
  const links = linkTable ? events.db.prepare(`SELECT attack_id,incident_id FROM attack_incident_links`)
    .all() as { attack_id: string; incident_id: string }[] : [];
  const byAttack = new Map(links.map((link) => [link.attack_id, link.incident_id]));
  const memoryTable = bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='attack_memory'`).get();
  const effectsTable = bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='red_sandbox_effect_checks'`).get();
  const verified = succeeded.flatMap((event) => {
    const effectId = events.getPrivate(event.seq)?.effect_check_id;
    const check = effectsTable && typeof effectId === "string" ? bank.db.prepare(`SELECT
      claim_kind,amount_cents FROM red_sandbox_effect_checks WHERE id=? AND round_id=?
      AND agent_id=? AND verified=1`).get(effectId, roundId, event.actor.id) as
      { claim_kind: string; amount_cents: number } | undefined : undefined;
    return check ? [{ event, moneyCents: check.claim_kind === "money_moved" ?
      check.amount_cents : 0 }] : [];
  });
  const byVerifiedAttack = new Map<string, { event: ArenaEvent; moneyCents: number;
    creditedCents: number; reported: boolean }>();
  for (const { event, moneyCents } of verified) {
    const attackId = String(event.public.attack_id);
    const reported = events.getPrivate(event.seq)?.unreported !== true;
    const prior = byVerifiedAttack.get(attackId);
    if (prior) {
      prior.moneyCents += moneyCents;
      prior.creditedCents += moneyCents * (reported ? 1 : 0.5);
      prior.reported ||= reported;
    } else byVerifiedAttack.set(attackId, { event, moneyCents,
      creditedCents: moneyCents * (reported ? 1 : 0.5), reported });
  }
  const breaches = [...byVerifiedAttack.values()];
  const redInputs = breaches.map(({ event, creditedCents, reported }) => {
    const attackId = String(event.public.attack_id);
    const incidentId = byAttack.get(attackId);
    const detected = incidents.find((item) => item.incident_id === incidentId &&
      item.public.source !== "audit");
    const novelty = memoryTable ? bank.db.prepare(`SELECT novelty FROM attack_memory
      WHERE round_id=? AND agent_id=? ORDER BY created_at DESC LIMIT 1`)
      .get(roundId, event.actor.id) as { novelty: number } | undefined : undefined;
    return { moneyBrl: creditedCents / 100,
      novelty: reported ? novelty?.novelty ?? 0 : 0, detectedAfterSeconds: detected ?
        Math.max(0, (at(detected) - at(event)) / 1000) : null,
      reported: true };
  });
  const blueIncidents = breaches.map(({ event }) => {
    const incidentId = byAttack.get(String(event.public.attack_id));
    const detected = incidents.find((item) => item.incident_id === incidentId &&
      item.public.source !== "audit");
    const contained = rows.find((item) => item.type === "containment.applied" &&
      item.incident_id === incidentId);
    const merged = rows.find((item) => item.type === "patch.merged" &&
      item.incident_id === incidentId);
    return { detectedAfterSeconds: detected ? Math.max(0, (at(detected) - at(event)) / 1000) : null,
      containedAfterAlertSeconds: detected && contained ?
        Math.max(0, (at(contained) - at(detected)) / 1000) : null,
      mergedAfterEffectSeconds: merged ? Math.max(0, (at(merged) - at(event)) / 1000) : null };
  });
  score.attacks_total = attempted.length;
  score.attacks_succeeded = breaches.length;
  score.loss_cents = breaches.reduce((sum, item) => sum + item.moneyCents, 0);
  score.restored_cents = own.filter((event) => event.type === "damage.restored")
    .reduce((sum, event) => sum + Number(event.public.restored_cents), 0);
  const blockedCustomersTable = bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='sim_blocked_customers'`).get();
  score.honest_wrongly_blocked = blockedCustomersTable ?
    (bank.db.prepare(`SELECT COUNT(DISTINCT customer_id) n FROM sim_blocked_customers
      WHERE minute>=? AND minute<=?`).get(startedAt, endedAt) as { n: number }).n :
    rows.filter((event) => event.type === "sim.tick" && event.round_id === null &&
      event.ts >= startedAt && event.ts <= endedAt)
      .reduce((sum, event) => sum + Number(event.public.honest_blocked), 0);
  score.red_points = redScore(redInputs);
  score.blue_points = blueScore({ incidents: blueIncidents,
    restoredBrl: score.restored_cents / 100,
    openAfterDeployBrl: score.loss_cents / 100,
    blockedAttempts: failed.filter((event) => !byVerifiedAttack.has(
      String(event.public.attack_id))).length,
    totalAttempts: attempted.length,
    honestCustomersWronglyBlocked: score.honest_wrongly_blocked,
    reviewRejections: own.filter((event) => event.type === "review.rejected" ||
      event.type === "deploy.rolled_back").length,
    quarantinedAreas: new Set(own.filter((event) => event.type === "area.quarantined")
      .map((event) => event.area)).size });
  const detectedTimes = blueIncidents.map((item) => item.detectedAfterSeconds)
    .filter((value): value is number => value !== null);
  const containedTimes = blueIncidents.map((item) => item.containedAfterAlertSeconds)
    .filter((value): value is number => value !== null);
  const mergedTimes = blueIncidents.map((item) => item.mergedAfterEffectSeconds)
    .filter((value): value is number => value !== null);
  score.mttd_s = detectedTimes.length ? detectedTimes.reduce((a, b) => a + b, 0) /
    detectedTimes.length : null;
  score.mttc_s = containedTimes.length ? containedTimes.reduce((a, b) => a + b, 0) /
    containedTimes.length : null;
  score.mttr_s = mergedTimes.length ? mergedTimes.reduce((a, b) => a + b, 0) /
    mergedTimes.length : null;
  return score;
}

export function reviseClosedRoundScore(bank: Bank, events: EventStore, roundId: string): boolean {
  const indexed = events.rounds().find((round) => round.round_id === roundId);
  if (!indexed || indexed.status === "started" || !indexed.score_json) return false;
  const ended = events.db.prepare(`SELECT ts FROM events WHERE round_id=?
    AND type='round.ended' ORDER BY seq DESC LIMIT 1`).get(roundId) as
    { ts: string } | undefined;
  const started = events.get(indexed.first_seq);
  if (!ended || !started || started.type !== "round.started") return false;
  const score = scoreFromEvents(bank, events, roundId, indexed.first_seq,
    started.ts, ended.ts);
  const serialized = JSON.stringify(score);
  if (serialized === indexed.score_json) return false;
  const revision = createHash("sha256").update(serialized).digest("hex").slice(0, 16);
  events.append({ round_id: roundId, ts: new Date().toISOString(),
    twin_ts: bank.now().toISOString(), type: "score.updated",
    actor: { id: "round-scorer", role: "system" },
    public_summary_pt: "Pontuação revista após efeito tardio",
    public: { red: score.red_points, blue: score.blue_points,
      delta: score.blue_points - score.red_points, reason: "delayed_effect",
      collateral: score.honest_wrongly_blocked } },
  `round:${roundId}:score:revision:${revision}`);
  events.db.prepare("UPDATE rounds SET score_json=? WHERE round_id=?")
    .run(serialized, roundId);
  return true;
}

export class RoundJanitor {
  readonly bank: Bank;
  readonly events: EventStore;
  readonly schedule: CampaignScheduleStore;
  readonly backupRoot: string;
  readonly simulatorKeys: SimulatorDeviceKeys | undefined;
  readonly ledgerAnchors: LedgerAnchorStore | undefined;
  readonly periodCloseAnchors: PeriodCloseAnchorStore | undefined;
  readonly verifyCrossBook: (() => Promise<CrossBookReport>) | undefined;
  readonly ecosystemSnapshot: ((destination: string) => Promise<void>) | undefined;
  readonly sourceHealthPath: string | undefined;
  readonly narrate: ((roundId: string, score: Record<string, number | null>,
    sourceEvents: readonly ArenaEvent[]) => Promise<RoundNarration | undefined>) | undefined;
  readonly scheduleNext: boolean;
  readonly onExpiredRound: ((roundId: string, endsAt: string) => void) | undefined;
  constructor(input: { bank: Bank; events: EventStore; schedule: CampaignScheduleStore; backupRoot: string;
    simulatorKeys?: SimulatorDeviceKeys;
    ledgerAnchors?: LedgerAnchorStore;
    periodCloseAnchors?: PeriodCloseAnchorStore;
    verifyCrossBook?: () => Promise<CrossBookReport>;
    ecosystemSnapshot?: (destination: string) => Promise<void>;
    sourceHealthPath?: string;
    scheduleNext?: boolean;
    onExpiredRound?: (roundId: string, endsAt: string) => void;
    narrate?: (roundId: string, score: Record<string, number | null>,
      sourceEvents: readonly ArenaEvent[]) => Promise<RoundNarration | undefined> }) {
    this.bank = input.bank; this.events = input.events;
    this.schedule = input.schedule; this.backupRoot = input.backupRoot;
    this.simulatorKeys = input.simulatorKeys;
    this.ledgerAnchors = input.ledgerAnchors;
    this.periodCloseAnchors = input.periodCloseAnchors;
    this.verifyCrossBook = input.verifyCrossBook;
    this.ecosystemSnapshot = input.ecosystemSnapshot;
    this.sourceHealthPath = input.sourceHealthPath;
    this.narrate = input.narrate;
    this.scheduleNext = input.scheduleNext ?? true;
    this.onExpiredRound = input.onExpiredRound;
  }
  async close(slot: RoundSlot, input: { status: "completed" | "partial" | "aborted";
    reason?: string; summaryPt: string; now?: Date }): Promise<void> {
    const now = input.now ?? new Date();
    const indexed = this.events.rounds().find((round) => round.round_id === slot.roundId);
    if (!indexed) throw new Error("JANITOR_ROUND_NOT_STARTED");
    if (indexed.status === "started") {
      const bankIntegrity = this.bank.reconcile();
      const crossBook = await this.verifyCrossBook?.();
      const integrity = { ...bankIntegrity, ok: bankIntegrity.ok && (crossBook?.ok ?? true) };
      this.events.append({ round_id: slot.roundId, ts: now.toISOString(), twin_ts: this.bank.now().toISOString(),
        type: "invariant.checked", actor: { id: "round-janitor", role: "system" }, area: "ledger",
        public_summary_pt: integrity.ok ? "Ledger reconciliado" : "Ledger requer revisão",
        public: { ok: integrity.ok, drift_cents: this.bank.balanceDriftCents(),
          at: now.toISOString() },
        private: { ...integrity, ...(crossBook ? { cross_book: crossBook } : {}) } },
      `round:${slot.roundId}:final-reconcile`);
      const score = scoreFromEvents(this.bank, this.events, slot.roundId, indexed.first_seq,
        slot.startsAt, now.toISOString());
      const status = integrity.ok ? input.status : "partial";
      const reason = integrity.ok ? input.reason : "unresolved_damage";
      this.events.append({ round_id: slot.roundId, ts: now.toISOString(), twin_ts: this.bank.now().toISOString(),
        type: "score.updated", actor: { id: "round-scorer", role: "system" },
        public_summary_pt: "Pontuação da rodada atualizada", public: {
          red: score.red_points, blue: score.blue_points,
          delta: score.blue_points - score.red_points, reason: "round_final",
          collateral: score.honest_wrongly_blocked } }, `round:${slot.roundId}:score`);
      const fallback = score.attacks_succeeded ?
        `${score.attacks_succeeded} desvio(s) confirmado(s) em ${score.attacks_total} tentativa(s). ` +
          `R$ ${(score.restored_cents / 100).toFixed(2).replace(".", ",")} restaurados.` :
        `Nenhum desvio confirmado em ${score.attacks_total} tentativa(s).`;
      const sourceEvents: ArenaEvent[] = [];
      let after = indexed.first_seq - 1;
      for (;;) {
        const batch = this.events.list({ after, limit: 500 });
        sourceEvents.push(...batch.filter((event) => event.round_id === slot.roundId));
        if (batch.length < 500) break;
        after = batch.at(-1)!.seq;
      }
      let generated: RoundNarration | undefined;
      try { generated = await this.narrate?.(slot.roundId, { ...score }, sourceEvents); }
      catch { /* A model failure must not prevent round closure. */ }
      const narration = generated?.headline_pt ?? fallback;
      const refs = generated?.chapters.flatMap((chapter) => chapter.event_refs
        .map((ref) => Number(ref.slice(4))).filter(Number.isSafeInteger)) ?? [];
      this.events.append({ round_id: slot.roundId, ts: now.toISOString(), twin_ts: this.bank.now().toISOString(),
        type: "narration.published", actor: { id: "round-narrator", role: "narrator" },
        public_summary_pt: narration, public: { text_pt: narration,
          severity: integrity.ok && score.attacks_succeeded === 0 ? "good" : "warn", refs,
          ...(generated ? { headline_pt: generated.headline_pt,
            summary_pt: generated.summary_pt,
            takeaway_for_banks_pt: generated.takeaway_for_banks_pt,
            chapters: generated.chapters.map((chapter) => ({
              title_pt: chapter.title_pt, body_pt: chapter.body_pt,
              refs: chapter.event_refs.map((ref) => Number(ref.slice(4))) })) } : {}) },
        ...(generated ? { private: { narration: generated } } : {}) },
      `round:${slot.roundId}:narration`);
      this.events.append({ round_id: slot.roundId, ts: now.toISOString(), twin_ts: this.bank.now().toISOString(),
        type: "round.ended", actor: { id: "round-janitor", role: "system" },
        public_summary_pt: input.summaryPt, public: { status, score, summary_pt: input.summaryPt,
          duration_s: Math.max(0, Math.round((now.getTime() - Date.parse(slot.startsAt)) / 1000)),
          ...(reason ? { reason } : {}) } }, `round:${slot.roundId}:end`);
    }
    const snapshotPath = join(this.backupRoot, slot.roundId);
    if (existsSync(snapshotPath)) verifySnapshot(snapshotPath);
    else await snapshotRound({ bank: this.bank, events: this.events, root: this.backupRoot, roundId: slot.roundId,
      now: () => now, ...(this.simulatorKeys ? { simulatorKeys: this.simulatorKeys } : {}),
      ...(this.ledgerAnchors ? { ledgerAnchors: this.ledgerAnchors } : {}),
      ...(this.ecosystemSnapshot ? { ecosystemSnapshot: this.ecosystemSnapshot } : {}),
      ...(this.sourceHealthPath ? { sourceHealthPath: this.sourceHealthPath } : {}),
      ...(this.periodCloseAnchors ? { periodCloseAnchors: this.periodCloseAnchors } : {}) });
    this.schedule.close(slot.roundId, now);
    const next = this.schedule.list().find((item) => item.roundNo === slot.roundNo + 1);
    if (next && this.scheduleNext) this.events.append({ round_id: null, ts: now.toISOString(), type: "round.scheduled",
      actor: { id: "round-janitor", role: "system" }, public_summary_pt: "Próxima rodada agendada",
      public: { round_no: next.roundNo, starts_at: next.startsAt, slot: next.slot } },
    `round:${next.roundId}:scheduled`);
  }
  async closeExpired(now = new Date(), activeRoundIds: ReadonlySet<string> = new Set()): Promise<string[]> {
    const expired = this.schedule.recover(now).expired;
    const hasProgress = this.events.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='campaign_round_progress'`).get();
    const closed: string[] = [];
    for (const slot of expired) {
      if (activeRoundIds.has(slot.roundId)) continue;
      const pending = hasProgress && this.events.db.prepare(`SELECT 1 FROM campaign_round_progress
        WHERE round_id=? AND json_extract(data_json,'$.pending') IS NOT NULL`).get(slot.roundId);
      if (pending) continue;
      this.onExpiredRound?.(slot.roundId, slot.endsAt);
      await this.close(slot, { status: "partial", reason: "deadline",
        summaryPt: "Rodada encerrada pelo limite de tempo", now });
      closed.push(slot.roundId);
    }
    return closed;
  }
}
