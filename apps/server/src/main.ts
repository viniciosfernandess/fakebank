import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import type { IncomingHttpHeaders, ServerResponse } from "node:http";
import { isIP } from "node:net";
import { join, resolve, relative, extname, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { EventStore } from "../../../packages/event-store/src/index.ts";
import { EVENT_TYPES, publicView, type ArenaEvent, type EventType } from "../../../packages/contracts/src/index.ts";
import { incidentMapBody, rootCauseReportBody, fixDesignBody } from "../../../packages/contracts/src/dossiers.ts";
import { isSafePublicText, maskPublicEventText, safeFallback } from "../../../packages/contracts/src/public-safety.ts";
import { OpsControl, type OpsState } from "../../../packages/ops-control/src/index.ts";
import { decodeKeyframe } from "../../../packages/world-reducer/src/keyframes.ts";
import { parseMomentPosition, resolveMomentCursor } from "../../../packages/replay-link/src/index.ts";
import type { AgentTransport } from "../../orchestrator/src/agent-loop.ts";
import { createCampaignApp, createSeparatedCampaignApp } from "../../orchestrator/src/campaign-app.ts";
import type { SeedOptions } from "../../world/src/seed.ts";
import { CodexQuotaGate } from "../../orchestrator/src/runtime/quota-gate.ts";
import type { AgentRuntime } from "../../orchestrator/src/runtime/agent-runtime.ts";
import { CodexRuntime } from "../../orchestrator/src/runtime/codex-runtime.ts";
import { DefenseCoordinator } from "../../orchestrator/src/defense-coordinator.ts";
import { describeIdentityActivity, describeMeasuredIdentityScope } from
  "../../orchestrator/src/identity-session-activity.ts";
import { describeIdentityPixFollowup } from "../../orchestrator/src/identity-pix-followup.ts";
import { prepareLabCodeCheckout } from "../../orchestrator/src/lab-code-checkout.ts";
import { FaultLab, FaultLabError, type FaultId } from
  "../../orchestrator/src/fault-lab.ts";
import { createFaultLabAdapters } from "../../orchestrator/src/fault-lab-adapters.ts";
import { FaultLabEvaluator } from "../../orchestrator/src/fault-lab-evaluator.ts";
import { TelemetryStream, type TelemetryEvent } from "../../world/src/telemetry.ts";
import { RULES } from "../../world/src/sentinels.ts";
import { BankError } from "../../world/src/bank.ts";
import { calculateSocMetrics } from "./soc-metrics.ts";
import { OperatorSessions } from "./operator-session.ts";
import { MedOperatorReview, type MedDecision, type MedReviewBasis } from
  "./med-operator-review.ts";
import { startCustomerOtpMailbox } from "./customer-otp-mailbox.ts";
import { ensureSeparatedData } from "./separated-bootstrap.ts";
import { incidentMoneyFlow, incidentMoneyFlowSeparated,
  presentationMoneyFlow } from "./money-flow.ts";
import { moneyFlowMedState, type DisclosedMoneyEdge } from
  "../../orchestrator/src/money-flow-disclosure.ts";
import { publishMoneyFlowMedSnapshots, publishSeparatedMoneyFlowMedSnapshots } from
  "../../orchestrator/src/money-flow-disclosure.ts";
import { publicCrossBookSummary } from
  "../../orchestrator/src/cross-book-summary.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_STATIC = resolve(HERE, "../../web/dist");
const FAULT_LAB_USAGE_CAPS = { maxTokens: 8_000_000,
  roleCaps: { engineer: { maxTokens: 4_000_000 },
    reviewer: { maxTokens: 3_000_000 } } };
const MIME: Record<string, string> = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".jsonl": "application/x-ndjson; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp", ".ico": "image/x-icon" };
const intParam = (value: unknown, fallback: number, max = Number.MAX_SAFE_INTEGER): number => {
  const number = Number(value ?? fallback);
  return Number.isSafeInteger(number) && number >= 0 && number <= max ? number : fallback;
};
function sseFrame(event: Omit<ArenaEvent, "private">): string {
  return `id: ${event.seq}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
}
function localMutationAllowed(headers: IncomingHttpHeaders, protocol: string,
  publicOrigin?: string): boolean {
  const host = headers.host;
  if (!host) return false;
  const configuredHost = process.env.HOST?.trim() || "127.0.0.1";
  if (!publicOrigin && ["127.0.0.1", "localhost", "::1"].includes(configuredHost)) {
    let hostname: string;
    try { hostname = new URL(`${protocol}://${host}`).hostname; }
    catch { return false; }
    if (!["127.0.0.1", "localhost", "[::1]"].includes(hostname)) return false;
  }
  const site = headers["sec-fetch-site"];
  if (site && site !== "same-origin" && site !== "none") return false;
  if (headers.origin) {
    try { if (new URL(headers.origin).origin !==
      (publicOrigin ?? new URL(`${protocol}://${host}`).origin)) return false; }
    catch { return false; }
  }
  return true;
}
const localOperatorAllowed = (ip: string): boolean =>
  ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(ip);
function trustedProxyPeer(ip: string): boolean {
  if (isIP(ip) !== 4) return false;
  const [first, second] = ip.split(".").map(Number);
  return first === 10 || first === 127 ||
    first === 172 && second! >= 16 && second! <= 31 ||
    first === 192 && second === 168;
}
const publicTelemetrySources = new Set([
  "gateway", "auth", "pix", "spi", "dict", "cards", "network",
  "ledger", "risk", "siem", "agent",
]);
function publicTelemetry(entry: TelemetryEvent) {
  return { id: entry.id, ts: entry.ts, twin_ts: entry.twin_ts,
    trace_id: entry.trace_id, span_id: entry.span_id,
    source: publicTelemetrySources.has(entry.source) ? entry.source : "unknown",
    category: entry.category === "audit" ? "audit" : "activity", action: "event",
    outcome: entry.outcome, severity: entry.severity, message: "Evento sintético do banco",
    redacted: entry.redacted, user_id: null, account_id: null, source_ip: null,
    device_id: null, session_id: null, user_agent: null, geo: null,
    amount_cents: null, counterparty: null, e2e_id: null, card_token: null,
    rule_id: null, risk_score: null, reason_codes_json: null };
}
type CampaignServerOptions = { startBrtDate: string; repoRoot: string;
    bankOnly?: boolean;
    faultLab?: boolean;
    publicOrigin?: string;
    transport?: AgentTransport;
    runtime?: AgentRuntime; localCodex?: boolean;
    plantCanaries?: boolean;
    onDemand?: boolean;
    continuousIntervalMinutes?: number;
    campaignMode?: "bank_only" | "fault_lab" | "defensive_only" | "legacy";
    seed?: SeedOptions; realNow?: () => Date; onError?: (error: unknown) => void;
    twinSpeed?: number;
    onRestart?: () => void;
    prepared?: { events: EventStore; campaign: ReturnType<typeof createCampaignApp>;
      localAgentRuntime?: CodexRuntime } };

export function buildServer(dataDir: string, staticDir = DEFAULT_STATIC,
  campaignOptions?: CampaignServerOptions) {
  const publicOrigin = campaignOptions?.publicOrigin ?? process.env.PUBLIC_ORIGIN?.trim();
  if (publicOrigin) {
    const parsed = new URL(publicOrigin);
    if (parsed.origin !== publicOrigin || !["http:", "https:"].includes(parsed.protocol))
      throw new Error("PUBLIC_ORIGIN_INVALID");
  }
  mkdirSync(dataDir, { recursive: true });
  const events = campaignOptions?.prepared?.events ??
    new EventStore(join(dataDir, "events.sqlite"));
  const ops = new OpsControl(dataDir);
  const quota = new CodexQuotaGate(events);
  let disclosureSeq = -1;
  let disclosedAttackIds = new Set<string>();
  const platformAgentRules = ["S-GW-08", "S-GW-09", "S-GW-12"] as const;
  const agentAlertSource = (ruleId: string, seq: number): boolean => {
    const source = events.get(seq);
    if (!source) return false;
    if (ruleId === "S-GW-08") return source.type === "integrity.violation";
    if (ruleId === "S-GW-09")
      return source.type === "agent.finished" && source.public.outcome === "refused";
    return ruleId === "S-GW-12" && source.type === "agent.finished" &&
      source.public.outcome === "failed" &&
      events.getPrivate(seq)?.reason === "codex_thread_stream_ended";
  };
  const agentAlertEntity = (ruleId: string, seq: number): string =>
    `agent_${ruleId === "S-GW-08" ? "integrity" :
      ruleId === "S-GW-09" ? "refusal" : "thread"}:${seq}`;
  const disclosure = (): ReadonlySet<string> => {
    const latest = events.latestSeq();
    if (latest === disclosureSeq) return disclosedAttackIds;
    disclosureSeq = latest;
    const table = events.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='attack_incident_links'`).get();
    disclosedAttackIds = new Set(table ? (events.db.prepare(`SELECT attack_id FROM attack_incident_links
      WHERE disclosed=1`).all() as { attack_id: string }[]).map((row) => row.attack_id) : []);
    return disclosedAttackIds;
  };
  const isHidden = (event: ArenaEvent, state: OpsState): boolean => {
    if (state.level < 2 || !state.hiddenRoundIds.length) return false;
    if (event.round_id && state.hiddenRoundIds.includes(event.round_id)) return true;
    if (event.round_id === null && event.type === "sentinel.alert" &&
      platformAgentRules.includes(event.public.rule_id as typeof platformAgentRules[number])) {
      const observed = events.getPrivate(event.seq)?.observed;
      const sourceSeq = observed && typeof observed === "object" && !Array.isArray(observed)
        ? (observed as Record<string, unknown>).event_seq : undefined;
      if (!Number.isSafeInteger(sourceSeq) || (sourceSeq as number) < 1 ||
        (sourceSeq as number) >= event.seq) return true;
      if (!agentAlertSource(event.public.rule_id as string, sourceSeq as number)) return true;
      const source = events.get(sourceSeq as number)!;
      if (isHidden(source, state)) return true;
    }
    const unattributedAlert = event.type === "sentinel.alert" &&
      !platformAgentRules.includes(event.public.rule_id as typeof platformAgentRules[number]);
    const unattributedIncident = event.type === "incident.opened" &&
      event.actor.role === "sentinel";
    if (event.round_id === null && (unattributedAlert || unattributedIncident))
      return true;
    return events.rounds().some((round) => state.hiddenRoundIds.includes(round.round_id) &&
      event.seq >= round.first_seq && event.seq <= (round.last_seq ?? events.latestSeq()));
  };
  const project = (event: ArenaEvent): Omit<ArenaEvent, "private"> | undefined => {
    const state = ops.read();
    if (isHidden(event, state)) return undefined;
    const visible = publicView(event, disclosure());
    return state.level >= 2 && state.hiddenSeqs.includes(event.seq)
      ? maskPublicEventText(visible) : visible;
  };
  const page = (query: Parameters<EventStore["list"]>[0]) => {
    const batch = events.list(query);
    return { events: batch.map(project).filter((event): event is Omit<ArenaEvent, "private"> => Boolean(event)),
      latest_seq: events.latestSeq(), next_after: batch.at(-1)?.seq ?? query?.after ?? 0,
      has_more: batch.length === (query?.limit ?? 500) };
  };
  const roundPreview = (roundText: string, secondsText: string | undefined) => {
    if (!/^\d{1,2}$/.test(roundText)) return null;
    const roundNo = Number(roundText);
    const position = parseMomentPosition(secondsText);
    if (roundNo < 1 || roundNo > 14 || !position) return null;
    const round = events.rounds().find((item) => item.round_no === roundNo);
    if (!round || ops.read().level >= 2 && ops.read().hiddenRoundIds.includes(round.round_id)) return null;
    const visible: ArenaEvent[] = [];
    const end = round.last_seq ?? events.latestSeq();
    let after = round.first_seq - 1;
    for (let index = 0; index < 200; index++) {
      const batch = page({ after, before: end + 1, limit: 500 });
      visible.push(...batch.events.filter((event) => event.round_id === round.round_id ||
        event.round_id === null && event.seq >= round.first_seq && event.seq <= end));
      if (!batch.has_more || batch.next_after >= end || batch.next_after <= after) break;
      after = batch.next_after;
    }
    if (round.last_seq !== null && round.last_seq < events.latestSeq()) {
      after = round.last_seq;
      for (let index = 0; index < 200; index++) {
        const batch = page({ roundId: round.round_id, after, limit: 500 });
        visible.push(...batch.events);
        if (!batch.has_more || batch.next_after <= after) break;
        after = batch.next_after;
      }
    }
    return resolveMomentCursor(visible, position) !== null;
  };
  const app = Fastify({ logger: false, trustProxy: false, bodyLimit: 32 * 1024 });
  const eventStreams = new Set<ServerResponse>();
  const trackEventStream = (response: ServerResponse) => {
    eventStreams.add(response);
    response.once("close", () => { eventStreams.delete(response); });
  };
  app.addHook("preClose", async () => {
    for (const response of eventStreams) response.end();
  });
  if (campaignOptions?.bankOnly && !campaignOptions.faultLab)
    app.addHook("onRequest", async (request, reply) => {
      if (request.url === "/api/operator" || request.url.startsWith("/api/operator/"))
        return reply.code(404).send({ error: "DEF_NOT_FOUND" });
    });
  const labUsageCaps = campaignOptions?.faultLab ? FAULT_LAB_USAGE_CAPS : undefined;
  const localAgentRuntime = campaignOptions?.prepared?.localAgentRuntime ??
    (campaignOptions?.localCodex && !campaignOptions.prepared ?
      new CodexRuntime({ events, dataDir, usageCaps: labUsageCaps }) : undefined);
  const campaign = campaignOptions?.prepared?.campaign ?? (campaignOptions ?
    createCampaignApp({ dataDir, events, ...campaignOptions,
      ...(localAgentRuntime ? { runtime: localAgentRuntime } : {}) }) : undefined);
  const codeRepoRoot = campaignOptions?.faultLab && localAgentRuntime &&
    campaignOptions.repoRoot ? prepareLabCodeCheckout(campaignOptions.repoRoot,
      dataDir) : campaignOptions?.repoRoot;
  const defense = campaignOptions?.bankOnly && campaign ? new DefenseCoordinator({
    bank: campaign.runtime.bank, sentinels: campaign.runtime.sentinels,
    events, dataDir, ...(codeRepoRoot ? { repoRoot: codeRepoRoot } : {}),
    ...(campaignOptions.faultLab && campaignOptions.onRestart && codeRepoRoot ? {
      onCodePromotion: campaignOptions.onRestart,
      loadedCodeHead: process.env.BANCO_VIVO_RUNTIME_HEAD } : {}),
    recipientFraudHistory: (id, at) => campaign.runtime.recipientFraudHistory(id, at),
    ...(localAgentRuntime ? { runtime: localAgentRuntime } : {}),
  }) : undefined;
  const faultLab = campaignOptions?.faultLab && campaign ? new FaultLab({
    dbPath: join(dataDir, "fault-lab.sqlite"),
    adapters: createFaultLabAdapters(campaign.runtime),
  }) : undefined;
  const faultLabEvaluator = faultLab && campaign ? new FaultLabEvaluator({
    lab: faultLab, bank: campaign.runtime.bank, events,
    reconcile: () => campaign.runtime.bank.reconcile(),
  }) : undefined;
  if (faultLab) campaign!.runtime.setFaultActiveReader(
    (id, runId) => faultLab.active(id as FaultId, runId));
  if (faultLab) app.addHook("onReady", async () => {
    await faultLab.tick();
  });
  const operatorSessions = campaign ? new OperatorSessions(campaign.runtime.bank) : undefined;
  const medOperatorReview = campaign ? new MedOperatorReview(campaign.runtime.bank) : undefined;
  const publishOperatorMedState = async (caseId: string): Promise<boolean> => {
    if (!campaign) return false;
    const bank = campaign.runtime.bank;
    const transfer = bank.db.prepare("SELECT transfer_id FROM med_cases WHERE id=?")
      .get(caseId) as { transfer_id: string } | undefined;
    if (!transfer || !bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='presentation_money_flow_disclosures'`).get()) return false;
    const incidents = bank.db.prepare(`SELECT DISTINCT incident_id FROM
      presentation_money_flow_disclosures WHERE transfer_id=?`)
      .all(transfer.transfer_id) as { incident_id: string }[];
    let published = false;
    for (const incident of incidents) {
      const disclosed = events.db.prepare(`SELECT 1 FROM attack_incident_links
        WHERE incident_id=? AND disclosed=1`).get(incident.incident_id);
      if (!disclosed) continue;
      const links = events.db.prepare(`SELECT round_id,idem FROM events
        WHERE type='money_flow.disclosed' AND incident_id=?`)
        .all(incident.incident_id) as { round_id: string | null; idem: string | null }[];
      for (const link of links) {
        if (!link.round_id || link.idem !==
          `money-flow:${link.round_id}:${incident.incident_id}:${transfer.transfer_id}`) continue;
        if (campaign.runtime.separatedEcosystem)
          await publishSeparatedMoneyFlowMedSnapshots(bank, events, link.round_id,
            incident.incident_id, (rootId, medCaseId) =>
              campaign.runtime.ecosystemMoneyFlowProjection(rootId, medCaseId));
        else publishMoneyFlowMedSnapshots(bank, events, link.round_id,
          incident.incident_id);
        published = true;
      }
    }
    return published;
  };
  let activeMedReplayFlush: Promise<void> | undefined;
  const flushOperatorMedReplay = (): Promise<void> => {
    if (activeMedReplayFlush) return activeMedReplayFlush;
    const run = (async () => {
      if (!medOperatorReview) return;
      for (const caseId of medOperatorReview.pendingReplay()) {
        try {
          if (await publishOperatorMedState(caseId))
            medOperatorReview.markReplayPublished(caseId);
        } catch {
          app.log.warn("MED replay publication pending retry");
        }
      }
    })();
    activeMedReplayFlush = run;
    void run.then(() => { if (activeMedReplayFlush === run) activeMedReplayFlush = undefined; },
      () => { if (activeMedReplayFlush === run) activeMedReplayFlush = undefined; });
    return run;
  };
  const medReplayTimer = medOperatorReview ? setInterval(() => {
    void flushOperatorMedReplay().catch((error) => app.log.warn(error));
  }, 10_000) : null;
  medReplayTimer?.unref();
  let labTickPending: Promise<void> | undefined;
  const labTimer = faultLab ? setInterval(() => {
    if (labTickPending) return;
    const tick = faultLab.tick().catch((error: unknown) => app.log.warn(error))
      .finally(() => { if (labTickPending === tick) labTickPending = undefined; });
    labTickPending = tick;
  }, 1_000) : null;
  labTimer?.unref();
  const telemetryStream = campaign ? new TelemetryStream(campaign.runtime.bank.telemetry) : undefined;
  const operatorReadAllowed = (request: FastifyRequest): boolean =>
    localOperatorAllowed(request.ip) && Boolean(operatorSessions?.identity(request.headers.cookie));
  const requireOperatorRead = (request: FastifyRequest, reply: FastifyReply): boolean => {
    reply.header("cache-control", "no-store");
    if (operatorReadAllowed(request)) return true;
    reply.code(localOperatorAllowed(request.ip) ? 401 : 403)
      .send({ code: "OPERATOR_AUTH_REQUIRED" });
    return false;
  };
  let preserveFaultsOnClose = false;
  app.addHook("onClose", async () => {
    if (medReplayTimer) clearInterval(medReplayTimer);
    if (labTimer) clearInterval(labTimer);
    await activeMedReplayFlush?.catch(() => undefined);
    await labTickPending?.catch(() => undefined);
    campaign?.runtime.detachFaultActiveReader();
    if (preserveFaultsOnClose) faultLab?.close();
    else await faultLab?.shutdown();
    telemetryStream?.close();
    await defense?.close();
    await campaign?.runtime.close();
    await localAgentRuntime?.close();
    await campaignOptions?.runtime?.close?.();
    events.close();
  });
  app.get("/healthz", async () => {
    const state = ops.read();
    return { ok: true, latest_seq: state.level >= 2 && state.hiddenRoundIds.length ? 0 :
      events.latestSeq() };
  });
  app.get("/api/defense/status", async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!defense) return reply.code(404).send({ code: "DEFENSE_MODE_UNAVAILABLE" });
    if (!requireOperatorRead(request, reply)) return;
    return { status: defense.status(), cases: defense.cases() };
  });
  app.get<{ Params: { id: string } }>("/api/defense/cases/:id",
    async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!defense) return reply.code(404).send({ code: "DEFENSE_MODE_UNAVAILABLE" });
      if (!requireOperatorRead(request, reply)) return;
      const { id } = request.params;
      if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id))
        return reply.code(400).send({ code: "DEFENSE_CASE_ID_INVALID" });
      const row = events.db.prepare(`SELECT profile,state FROM defense_cases
        WHERE incident_id=?`).get(id) as
        { profile: string; state: string } | undefined;
      if (!row) return reply.code(404).send({ code: "DEFENSE_CASE_NOT_FOUND" });
      const stages: Record<string, string> = {
        "defense.observed": "Alerta do Sentinela registrado",
        "defense.handoff": "Investigador despachado",
        "dossier.defense_investigation": "Investigação entregue",
        "defense.planning_handoff": "Plano e impacto despachados",
        "dossier.defense_impact": "Impacto avaliado",
        "defense.identity_activity_observed": "Atividade da sessão registrada",
        "dossier.defense_plan": "Plano proposto",
        "defense.planning_failure": "Plano ou impacto recusado",
        "defense.review_handoff": "Revisão independente iniciada",
        "dossier.defense_review": "Revisão concluída",
        "defense.mitigation_decision": "Ação de defesa registrada",
        "defense.external_monitoring": "Recuperação externa em observação",
        "defense.customer_notice": "Aviso individual registrado",
        "defense.external_recovery_verified": "Recuperação externa comprovada",
        "defense.code_design": "Correção de código planejada",
        "defense.code_candidate": "Candidato de código passou no CI",
        "defense.code_review": "Candidato revisado",
        "defense.code_build_failure": "Implementação não passou nos testes",
        "defense.code_review_approved": "Correção aprovada",
        "defense.code_bank_gate": "Suíte completa do banco passou",
        "defense.code_merged": "Correção aplicada no laboratório",
        "defense.identity_containment_verified": "Sessões do aparelho revogado encerradas",
        "defense.identity_scope_measured": "Escopo da janela observada analisado",
        "defense.identity_pix_followup": "Acompanhamento dos Pix vinculados ao acesso",
        "defense.fraud_control_verified": "Controle antifraude restaurado",
        "defense.customer_dispute_observed": "Contestação do cliente vinculada ao Pix",
        "defense.customer_dispute_outcome": "Resultado da contestação registrado",
        "defense.customer_repair_verified": "Devolução ao cliente comprovada",
        "defense.fee_repair_verified": "Reparação contábil conciliada",
      };
      const timeline = events.caseFile.history(id)
        .filter((entry) => Object.hasOwn(stages, entry.kind) &&
          (entry.kind !== "defense.identity_pix_followup" || entry.payload.truncated === true ||
            Array.isArray(entry.payload.commands) && entry.payload.commands.length > 0))
        .slice(-100).map((entry) => {
          const payload = entry.payload;
          const applied = payload.applied === true;
          const detail = entry.kind === "dossier.defense_review" ?
            payload.verdict === "approve" ? "Plano aprovado" : "Plano reprovado" :
            entry.kind === "defense.mitigation_decision" ?
              applied && payload.repair_status === "verified_transfer" ?
                "Pix liberado, transferência e ledger verificados" :
                applied ? "Contenção temporária aplicada" : "Ação adiada" :
            entry.kind === "defense.external_monitoring" ?
              "Em observação; recuperação ainda não comprovada" :
            entry.kind === "defense.customer_notice" ?
              payload.kind === "revoked_device_access" ?
                "Cliente avisado após encerrar as sessões do aparelho revogado; impacto anterior em apuração" :
              payload.kind === "suspicious_pix_review" ?
                "Cliente avisado sobre o Pix suspeito e caminho de contestação; prejuízo ainda em apuração" :
                "Cliente afetado avisado após recuperação do emissor" :
            entry.kind === "defense.external_recovery_verified" ?
              "Emissor restaurado e autorização posterior comprovada" :
            entry.kind === "defense.code_review" ?
              payload.verdict === "approve" ? "Candidato aprovado pela revisão" :
                "Candidato rejeitado pela revisão" :
            entry.kind === "defense.code_merged" ?
              "Correção aplicada apenas na cópia local; reinício pendente" :
            entry.kind === "defense.identity_containment_verified" ?
              "Sessões ativas do aparelho revogado encerradas; efeitos anteriores ainda em apuração" :
            entry.kind === "defense.identity_activity_observed" ?
              describeIdentityActivity(payload.observations) :
            entry.kind === "defense.identity_scope_measured" ?
              describeMeasuredIdentityScope(payload) :
            entry.kind === "defense.identity_pix_followup" ?
              describeIdentityPixFollowup(payload) :
            entry.kind === "defense.fraud_control_verified" ?
              "Controle antifraude restaurado; impacto do Pix já liquidado ainda em apuração" :
            entry.kind === "defense.customer_dispute_observed" ?
              "Contestação MED recebida para o Pix e cliente deste incidente; análise em andamento" :
            entry.kind === "defense.customer_dispute_outcome" ?
              payload.outcome === "claim_rejected" ?
                "Contestação recusada pelo MED; impacto do incidente segue em apuração" :
                payload.outcome === "partial_refund" ?
                  "Devolução parcial conciliada; reparação segue pendente" :
                  "MED concluído sem recuperação de saldo; reparação segue pendente" :
            entry.kind === "defense.customer_repair_verified" ?
              payload.bank_compensation_tx_id ?
                "Decisão MED aprovada, diferença coberta pelo banco e crédito integral conciliado" :
                "Decisão MED aprovada, devolução integral e crédito conciliado para o cliente afetado" :
            entry.kind === "defense.planning_failure" ?
              "Dossiê recusado; motivo registrado para a próxima tentativa" :
            entry.kind === "defense.code_build_failure" ?
              "Patch não passou no CI; falhas registradas para nova implementação" :
            entry.kind === "defense.fee_repair_verified" ?
              "Perda do banco registrada e razão conciliado; sem cobrança excessiva ao cliente" :
              stages[entry.kind]!;
          return { at: entry.created_at, stage: entry.kind, detail,
            verified: entry.kind === "defense.observed" ||
              entry.kind === "defense.customer_notice" ||
              entry.kind === "defense.external_recovery_verified" ||
              entry.kind === "defense.code_review_approved" ||
              entry.kind === "defense.code_bank_gate" ||
              entry.kind === "defense.code_merged" ||
              entry.kind === "defense.identity_containment_verified" ||
              entry.kind === "defense.identity_scope_measured" && payload.complete === true ||
              entry.kind === "defense.fraud_control_verified" ||
              entry.kind === "defense.customer_dispute_observed" ||
              entry.kind === "defense.customer_dispute_outcome" ||
              entry.kind === "defense.customer_repair_verified" ||
              entry.kind === "defense.fee_repair_verified" ||
              entry.kind === "defense.mitigation_decision" && applied };
        });
      return { case: { incidentId: id, profile: row.profile, state: row.state },
        timeline };
    });
  const labAccess = (request: FastifyRequest, reply: FastifyReply,
    mutation: boolean): boolean => {
    reply.header("cache-control", "no-store");
    if (!faultLab) {
      reply.code(404).send({ code: "FAULT_LAB_UNAVAILABLE" });
      return false;
    }
    if (!requireOperatorRead(request, reply)) return false;
    if (mutation && !localMutationAllowed(request.headers, request.protocol)) {
      reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      return false;
    }
    return true;
  };
  const labFailure = (error: unknown, reply: FastifyReply) => {
    if (!(error instanceof FaultLabError)) throw error;
    const code = error.code;
    const status = code === "FAULT_LAB_RUN_NOT_FOUND" ? 404 :
      code.startsWith("FAULT_LAB_PREVIEW_REJECTED") ||
      code === "FAULT_LAB_RUN_NOT_ACTIVE" ? 409 : 400;
    return reply.code(status).send({ code });
  };
  const labSelection = (body: unknown): string[] => {
    if (!body || typeof body !== "object" || Array.isArray(body) ||
      !("ids" in body) || !Array.isArray(body.ids))
      throw new FaultLabError("FAULT_LAB_SELECTION_INVALID");
    return body.ids as string[];
  };
  app.get("/api/fault-lab/catalog", async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!faultLab) return reply.code(404).send({ code: "FAULT_LAB_UNAVAILABLE" });
    if (!localOperatorAllowed(request.ip))
      return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
    return { fixtures: faultLab.catalog() };
  });
  app.post("/api/fault-lab/preview", async (request, reply) => {
    if (!labAccess(request, reply, true)) return;
    try { return faultLab!.preview(labSelection(request.body)); }
    catch (error) { return labFailure(error, reply); }
  });
  app.post("/api/fault-lab/runs", async (request, reply) => {
    if (!labAccess(request, reply, true)) return;
    try {
      const run = await faultLab!.start(labSelection(request.body));
      for (const fixtureId of run.selected_ids) {
        if (fixtureId === "med_opening_delayed" || fixtureId === "med_analysis_delayed" ||
          fixtureId === "med_settlement_delayed" || fixtureId === "med_release_delayed") {
          try {
            await campaign!.runtime.probeLabMedOpening(run.id, fixtureId);
            faultLab!.recordProbe(run.id, fixtureId, "completed");
          } catch {
            faultLab!.recordProbe(run.id, fixtureId, "failed");
          }
          continue;
        }
        const operation = fixtureId === "pix_dispatch_paused" ||
          fixtureId === "spi_unavailable" ||
          fixtureId === "psp_receipt_delayed" ? "external_pix" :
          fixtureId === "risk_false_hold" ? "risk_hold" :
          fixtureId === "card_issuer_offline" ? "card_authorization" : null;
        if (!operation) continue;
        try {
          const probe = await campaign!.runtime.simulator.localFaultProbe(operation,
            run.id, operation === "external_pix" ? fixtureId as
              "pix_dispatch_paused" | "spi_unavailable" | "psp_receipt_delayed" : undefined);
          faultLab!.recordProbe(run.id, fixtureId,
            probe.status >= 200 && probe.status < 500 ? "completed" : "failed");
        } catch {
          faultLab!.recordProbe(run.id, fixtureId, "failed");
        }
      }
      await faultLab!.tick();
      return reply.code(201).send({ run: faultLab!.run(run.id) });
    } catch (error) { return labFailure(error, reply); }
  });
  app.get<{ Params: { id: string } }>("/api/fault-lab/runs/:id",
    async (request, reply) => {
      if (!labAccess(request, reply, false)) return;
      const { id } = request.params;
      if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id))
        return reply.code(400).send({ code: "FAULT_LAB_RUN_ID_INVALID" });
      const run = faultLab!.run(id);
      if (!run) return reply.code(404).send({ code: "FAULT_LAB_RUN_NOT_FOUND" });
      let crossBook = null;
      if (run.status === "expired" && run.selected_ids.some((fixture) =>
        ["pix_dispatch_paused", "spi_unavailable", "psp_receipt_delayed", "med_opening_delayed",
          "automatic_pix_execution_delayed", "med_analysis_delayed",
          "med_settlement_delayed", "med_release_delayed"]
          .includes(fixture))) {
        try { crossBook = await campaign!.runtime.crossBookNow(); }
        catch { /* A missing verifier cannot prove reconciliation. */ }
      }
      return { run, evaluation: faultLabEvaluator!.evaluate(id, crossBook) };
    });
  app.post<{ Params: { id: string } }>("/api/fault-lab/runs/:id/stop",
    async (request, reply) => {
      if (!labAccess(request, reply, true)) return;
      const { id } = request.params;
      if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id))
        return reply.code(400).send({ code: "FAULT_LAB_RUN_ID_INVALID" });
      try { return { run: await faultLab!.stop(id) }; }
      catch (error) { return labFailure(error, reply); }
    });
  app.route({ method: ["GET", "POST", "PATCH", "DELETE"], url: "/api/client/*",
    handler: async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!campaign) return reply.code(404).send({ error: "DEF_NOT_FOUND" });
      if (!localOperatorAllowed(request.ip) &&
        !(campaignOptions?.bankOnly && publicOrigin))
        return reply.code(403).send({ error: "DEF_UNAUTHORIZED" });
      if (request.method !== "GET" &&
        !localMutationAllowed(request.headers, request.protocol,
          campaignOptions?.bankOnly ? publicOrigin : undefined))
        return reply.code(403).send({ error: "DEF_UNAUTHORIZED" });
      const path = request.raw.url?.slice("/api/client".length) ?? "";
      const headers: Record<string, string> = {};
      for (const name of ["authorization", "user-agent", "x-device-challenge",
        "x-device-signature", "x-psp-challenge", "x-psp-signature"]) {
        const value = request.headers[name];
        if (typeof value === "string") headers[name] = value;
      }
      const railwayIp = request.headers["x-real-ip"];
      const sourceIp = campaignOptions?.bankOnly && publicOrigin &&
        request.headers["x-forwarded-proto"] === "https" &&
        trustedProxyPeer(request.ip) && typeof railwayIp === "string" &&
        isIP(railwayIp) === 4 ? railwayIp :
        isIP(request.ip) === 4 ? request.ip : "127.0.0.1";
      const result = await campaign.runtime.gateway.call({ method: request.method,
        path: `/api/v1${path}`, peerIp: sourceIp, headers,
        ...(request.body === undefined ? {} : { body: request.body }) });
      return reply.code(result.status).send(result.body);
    } });
  app.get<{ Params: { n: string }; Querystring: { t?: string } }>("/rodada/:n", async (request, reply) => {
    if (!roundPreview(request.params.n, request.query.t))
      return reply.code(404).send({ code: "ROUND_NOT_FOUND" });
    const path = join(staticDir, "index.html");
    if (!existsSync(path)) return reply.code(404).send({ code: "PAGE_NOT_FOUND" });
    return reply.header("cache-control", "no-store").type("text/html; charset=utf-8")
      .send(readFileSync(path));
  });
  app.get("/api/status", async () => {
    const quotaResumeAt = quota.resumeAt();
    const hasSchedule = events.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='campaign_slots'").get();
    const next = hasSchedule ? events.db.prepare(`SELECT starts_at FROM campaign_slots WHERE state='scheduled'
      AND starts_at>=? ORDER BY starts_at LIMIT 1`).get(
        (campaign?.runtime.realNow() ?? new Date()).toISOString()) as
      { starts_at: string } | undefined : undefined;
    const control = ops.read();
    const visibleRounds = events.rounds().filter((round) =>
      control.level < 2 || !control.hiddenRoundIds.includes(round.round_id));
    return { mode: control.level === 3 ? "replay_only" : control.level >= 1 || quotaResumeAt ? "paused" :
      visibleRounds.some((round) => round.status === "started") ? "live" : "idle",
      campaign_mode: campaignOptions?.campaignMode ?? (campaign ? "legacy" : "none"),
      round_mode: campaignOptions?.campaignMode === "bank_only" ||
        campaignOptions?.campaignMode === "fault_lab" ? "none" :
        campaignOptions?.continuousIntervalMinutes !== undefined ? "continuous" :
        campaignOptions?.onDemand ? "manual" : campaign ? "scheduled" : "none",
      latest_seq: control.level >= 2 && control.hiddenRoundIds.length ? 0 :
        events.latestSeq(), rounds: visibleRounds.length,
      next_round_at: campaignOptions?.continuousIntervalMinutes !== undefined ?
        campaign?.runtime.continuousNextAt()?.toISOString() ?? null :
        campaignOptions?.onDemand ? null : next?.starts_at ?? null,
      quota_resume_at: quotaResumeAt,
      visibility_version: createHash("sha256").update(JSON.stringify(control)).digest("hex").slice(0, 12) };
  });
  app.post("/api/rounds/start", async (request, reply) => {
    if (!campaign || !campaignOptions?.onDemand ||
      campaignOptions.continuousIntervalMinutes !== undefined ||
      campaignOptions.campaignMode !== "defensive_only")
      return reply.code(404).send({ code: "MANUAL_ROUNDS_UNAVAILABLE" });
    if (!localMutationAllowed(request.headers, request.protocol))
      return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
    const slot = await campaign.runtime.startOnDemandRound();
    return slot ? reply.code(202).send({ round_id: slot.roundId, round_no: slot.roundNo,
      ends_at: slot.endsAt }) : reply.code(409).send({ code: "ROUND_UNAVAILABLE" });
  });
  const hiddenSocRows = (): { alerts: string[]; incidents: string[] } => {
    const state = ops.read();
    if (!campaign || state.level < 2 || !state.hiddenRoundIds.length)
      return { alerts: [], incidents: [] };
    const db = campaign.runtime.bank.db;
    const alerts = db.prepare(`SELECT a.id,a.entity,a.rule_id,o.event_seq FROM sentinel_alerts a
      LEFT JOIN sentinel_agent_outbox o ON o.alert_id=a.id
      WHERE a.rule_id IN ('S-GW-08','S-GW-09','S-GW-12')`).all() as
      { id: string; entity: string; rule_id: string; event_seq: number | null }[];
    const incidents = db.prepare(`SELECT i.id,i.entity_key entity,a.rule_id,o.event_seq FROM sentinel_incidents i
      LEFT JOIN sentinel_agent_outbox o ON o.incident_id=i.id
      LEFT JOIN sentinel_alerts a ON a.id=o.alert_id
      WHERE i.entity_key LIKE 'agent_integrity:%' OR i.entity_key LIKE 'agent_refusal:%'
        OR i.entity_key LIKE 'agent_thread:%'`).all() as
      { id: string; entity: string; rule_id: string | null; event_seq: number | null }[];
    const unattributedAlerts = db.prepare(`SELECT id FROM sentinel_alerts
      WHERE rule_id NOT IN ('S-GW-08','S-GW-09','S-GW-12')`).all() as { id: string }[];
    const unattributedIncidents = db.prepare(`SELECT id FROM sentinel_incidents
      WHERE entity_key NOT LIKE 'agent_integrity:%'
        AND entity_key NOT LIKE 'agent_refusal:%'
        AND entity_key NOT LIKE 'agent_thread:%'`).all() as { id: string }[];
    const hidden = (row: { entity: string; rule_id: string | null; event_seq: number | null }): boolean => {
      if (!Number.isSafeInteger(row.event_seq) || !row.event_seq || row.event_seq < 1 ||
        row.entity !== agentAlertEntity(row.rule_id ?? "", row.event_seq))
        return true;
      try {
        const source = events.get(row.event_seq);
        if (!events.db.prepare("SELECT 1 FROM event_integrity WHERE seq=?").get(row.event_seq) ||
          !source || !agentAlertSource(row.rule_id ?? "", row.event_seq))
          return true;
        return isHidden(source, state);
      } catch { return true; }
    };
    return { alerts: [...alerts.filter(hidden).map((row) => row.id),
      ...unattributedAlerts.map((row) => row.id)],
      incidents: [...incidents.filter(hidden).map((row) => row.id),
        ...unattributedIncidents.map((row) => row.id)] };
  };
  app.get<{ Querystring: { limit?: string } }>("/api/soc/alerts", async (request, reply) => {
    if (!campaign) return reply.code(404).send({ code: "SOC_UNAVAILABLE" });
    const limit = intParam(request.query.limit, 20, 100) || 20;
    const bank = campaign.runtime.bank;
    const since = new Date(bank.now().getTime() - 86_400_000).toISOString();
    const excluded = JSON.stringify(hiddenSocRows().alerts);
    const total = (bank.db.prepare(`SELECT COUNT(*) n FROM sentinel_alerts
      WHERE last_seen>=? AND rule_id IN (SELECT value FROM json_each(?))
      AND id NOT IN (SELECT value FROM json_each(?))`)
      .get(since, JSON.stringify(RULES.map((rule) => rule.id)), excluded) as { n: number }).n;
    const rows = bank.db.prepare(`SELECT id,rule_id,window_s,first_seen,last_seen,count
      FROM sentinel_alerts WHERE last_seen>=? AND rule_id IN (SELECT value FROM json_each(?))
      AND id NOT IN (SELECT value FROM json_each(?)) ORDER BY last_seen DESC,id DESC LIMIT ?`)
      .all(since, JSON.stringify(RULES.map((rule) => rule.id)), excluded, limit) as
      { id: string; rule_id: string; window_s: number; first_seen: string; last_seen: string; count: number }[];
    const alerts = rows.flatMap((row) => {
      const rule = RULES.find((item) => item.id === row.rule_id);
      return rule ? [{ alert_id: row.id, rule_id: row.rule_id, area: rule.area,
        severity: rule.severity, entity: ["S-PIX-08", "S-PIX-09"].includes(row.rule_id)
          ? "Caso Pix protegido" : "Entidade protegida", observed: {}, window_s: row.window_s,
        first_seen: row.first_seen, last_seen: row.last_seen, count: row.count, evidence_ref: "" }] : [];
    });
    return { alerts, total,
      twin_now: bank.now().toISOString() };
  });
  app.get("/api/operator/soc/detection-coverage", async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!operatorReadAllowed(request)) return reply.code(403).send({ code: "OPERATOR_AUTH_REQUIRED" });
    if (ops.read().level >= 2) return reply.code(404).send({ code: "NOT_FOUND" });
    const path = fileURLToPath(new URL("../../../rules/detection/coverage.json", import.meta.url));
    const coverage: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!coverage || typeof coverage !== "object" || Array.isArray(coverage) ||
      (coverage as { version?: unknown }).version !== 1 ||
      !Array.isArray((coverage as { entries?: unknown }).entries) ||
      !Array.isArray((coverage as { dynamic?: unknown }).dynamic))
      throw new Error("DETECTION_COVERAGE_INVALID");
    return { ...coverage, rules: RULES };
  });
  app.get<{ Querystring: { limit?: string } }>("/api/operator/soc/alerts",
    async (request, reply) => {
      if (!requireOperatorRead(request, reply)) return;
      if (!campaign) return reply.code(404).send({ code: "SOC_UNAVAILABLE" });
      const limit = intParam(request.query.limit, 20, 100) || 20;
      const bank = campaign.runtime.bank;
      const since = new Date(bank.now().getTime() - 86_400_000).toISOString();
      const total = (bank.db.prepare(`SELECT COUNT(*) n FROM sentinel_alerts
        WHERE last_seen>=? AND rule_id IN (SELECT value FROM json_each(?))`)
        .get(since, JSON.stringify(RULES.map((rule) => rule.id))) as { n: number }).n;
      return { alerts: campaign.runtime.sentinels.recentAlerts(limit).map((alert) => ({
        ...alert, triage: campaign.runtime.sentinels.triage.get(alert.alert_id),
      })), total,
        twin_now: bank.now().toISOString() };
    });
  app.post<{ Params: { id: string } }>("/api/operator/soc/alerts/:id/acknowledge",
    { bodyLimit: 64 }, async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!campaign || !operatorSessions)
        return reply.code(404).send({ code: "SOC_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const identity = operatorSessions.identity(request.headers.cookie);
      if (!identity) return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      try { return campaign.runtime.sentinels.triage.acknowledge(request.params.id, identity.id); }
      catch (error) {
        if (error instanceof Error && error.message === "SOC_ALERT_NOT_FOUND")
          return reply.code(404).send({ code: error.message });
        if (error instanceof Error && ["SOC_ALERT_ALREADY_ACKNOWLEDGED",
          "SOC_TRIAGE_INPUT_INVALID"].includes(error.message))
          return reply.code(409).send({ code: error.message });
        throw error;
      }
    });
  app.get("/api/soc/risk-review-summary", async (_request, reply) => {
    if (!campaign) return reply.code(404).send({ code: "SOC_UNAVAILABLE" });
    const control = ops.read();
    if (control.level >= 2 && control.hiddenRoundIds.length)
      return { pending_total: 0, due_within_hour: 0, unacknowledged_due_within_hour: 0 };
    const bank = campaign.runtime.bank;
    const now = bank.now();
    const dueBy = new Date(now.getTime() + 3_600_000).toISOString();
    const summary = bank.db.prepare(`SELECT COUNT(*) pending_total,
      SUM(CASE WHEN h.expires_at<=? THEN 1 ELSE 0 END) due_within_hour,
      SUM(CASE WHEN h.expires_at<=? AND ack.hold_id IS NULL THEN 1 ELSE 0 END)
        unacknowledged_due_within_hour
      FROM risk_pix_holds h LEFT JOIN risk_pix_review_acknowledgements ack ON ack.hold_id=h.id
      WHERE h.status='pending' AND h.expires_at>?`)
      .get(dueBy, dueBy, now.toISOString()) as
      { pending_total: number; due_within_hour: number | null;
        unacknowledged_due_within_hour: number | null };
    return { pending_total: summary.pending_total,
      due_within_hour: summary.due_within_hour ?? 0,
      unacknowledged_due_within_hour: summary.unacknowledged_due_within_hour ?? 0 };
  });
  app.get("/api/operator/session", async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!localOperatorAllowed(request.ip))
      return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
    const identity = operatorSessions?.medIdentity(request.headers.cookie);
    return identity ? { authenticated: true, operator_id: identity.id, role: identity.role } :
      { authenticated: false };
  });
  app.post<{ Body: { id?: string; password?: string } }>("/api/operator/login",
    { bodyLimit: 2048 }, async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!operatorSessions) return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const { id, password } = request.body ?? {};
      if (typeof id !== "string" || typeof password !== "string" ||
        id.length > 80 || password.length > 256)
        return reply.code(400).send({ code: "INVALID_CREDENTIALS" });
      try {
        const session = operatorSessions.login(id, password);
        operatorSessions.logout(request.headers.cookie);
        return reply.header("set-cookie", operatorSessions.cookie(session.token,
          request.protocol === "https", faultLab ? "/api" : "/api/operator"))
          .send({ authenticated: true,
          operator_id: session.identity.id, role: session.identity.role });
      } catch (error) {
        if (error instanceof Error && ["OPERATOR_BAD_CREDENTIALS", "OPERATOR_FORBIDDEN"]
          .includes(error.message))
          return reply.code(401).send({ code: "INVALID_CREDENTIALS" });
        throw error;
      }
    });
  app.post<{ Body: { id?: string; password?: string } }>("/api/operator/med/login",
    { bodyLimit: 2048 }, async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!operatorSessions) return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const { id, password } = request.body ?? {};
      if (typeof id !== "string" || typeof password !== "string" ||
        id.length > 80 || password.length > 256)
        return reply.code(400).send({ code: "INVALID_CREDENTIALS" });
      try {
        const session = operatorSessions.loginMedMaker(id, password);
        operatorSessions.logout(request.headers.cookie);
        return reply.header("set-cookie", operatorSessions.cookie(session.token,
          request.protocol === "https")).send({ authenticated: true,
          operator_id: session.identity.id, role: session.identity.role });
      } catch (error) {
        if (error instanceof Error && ["OPERATOR_BAD_CREDENTIALS", "OPERATOR_FORBIDDEN"]
          .includes(error.message))
          return reply.code(401).send({ code: "INVALID_CREDENTIALS" });
        throw error;
      }
    });
  app.post("/api/operator/logout", async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!operatorSessions) return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
    if (!localOperatorAllowed(request.ip))
      return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
    if (!localMutationAllowed(request.headers, request.protocol))
      return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
    operatorSessions.logout(request.headers.cookie);
    return reply.header("set-cookie", operatorSessions.clearCookie(request.protocol === "https",
      faultLab ? "/api" : "/api/operator"))
      .send({ authenticated: false });
  });
  app.get<{ Querystring: { cursor?: string } }>("/api/operator/med-reviews",
    async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!medOperatorReview || !operatorSessions)
      return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
    if (!localOperatorAllowed(request.ip))
      return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
    if (!operatorSessions.medIdentity(request.headers.cookie))
      return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
    const cursor = request.query.cursor;
    if (cursor !== undefined && (typeof cursor !== "string" || cursor.length > 512))
      return reply.code(400).send({ code: "DEF_MED_REVIEW_CURSOR_INVALID" });
    await flushOperatorMedReplay();
    try { return medOperatorReview.list(cursor); }
    catch (error) {
      if (error instanceof BankError && error.code === "DEF_MED_REVIEW_CURSOR_INVALID")
        return reply.code(400).send({ code: error.code });
      throw error;
    }
  });
  app.post<{ Params: { id: string }; Body: { decision?: string; evidence_ref?: string;
    basis_code?: string; evidence_summary?: string } }>(
    "/api/operator/med-reviews/:id/proposals", { bodyLimit: 2048 },
    async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!medOperatorReview || !operatorSessions)
        return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const identity = operatorSessions.medIdentity(request.headers.cookie);
      if (!identity) return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      if (!["maker", "admin"].includes(identity.role))
        return reply.code(403).send({ code: "MAKER_REQUIRED" });
      const { decision, evidence_ref: evidenceRef, basis_code: basisCode,
        evidence_summary: evidenceSummary } = request.body ?? {};
      if (!(["approved", "rejected"] as string[]).includes(decision ?? "") ||
        typeof evidenceRef !== "string" || typeof basisCode !== "string" ||
        typeof evidenceSummary !== "string")
        return reply.code(400).send({ code: "DEF_MED_REVIEW_INVALID" });
      try {
        return medOperatorReview.propose(request.params.id,
          decision as MedDecision, evidenceRef, identity.id,
          basisCode as MedReviewBasis, evidenceSummary);
      } catch (error) {
        if (error instanceof BankError)
          return reply.code(409).send({ code: error.code });
        throw error;
      }
    });
  app.post<{ Params: { id: string } }>(
    "/api/operator/med-reviews/proposals/:id/confirm", { bodyLimit: 128 },
    async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!medOperatorReview || !operatorSessions)
        return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const identity = operatorSessions.medIdentity(request.headers.cookie);
      if (!identity) return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      if (!["reviewer", "admin"].includes(identity.role))
        return reply.code(403).send({ code: "REVIEWER_REQUIRED" });
      try {
        const result = medOperatorReview.confirm(request.params.id, identity.id);
        await flushOperatorMedReplay();
        if (result.status === "rejection_pending_psp") reply.code(202);
        return { ...result, replay_update_pending:
          medOperatorReview.isReplayPending(result.case_id) };
      }
      catch (error) {
        if (error instanceof BankError)
          return reply.code(409).send({ code: error.code });
        throw error;
      }
    });
  app.post<{ Params: { id: string } }>(
    "/api/operator/med-reviews/:id/settle", { bodyLimit: 128 },
    async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!medOperatorReview || !operatorSessions)
        return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const identity = operatorSessions.medIdentity(request.headers.cookie);
      if (!identity) return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      if (!["reviewer", "admin"].includes(identity.role))
        return reply.code(403).send({ code: "REVIEWER_REQUIRED" });
      try {
        const result = medOperatorReview.settle(request.params.id);
        await flushOperatorMedReplay();
        if (result.status === "settlement_pending_psp" ||
          result.status === "analysis_pending_dict") reply.code(202);
        return { ...result, replay_update_pending:
          medOperatorReview.isReplayPending(result.id) };
      }
      catch (error) {
        if (error instanceof BankError)
          return reply.code(error.code === "BIZ_MED_NOT_FOUND" ? 404 : 409)
            .send({ code: error.code });
        if (error instanceof Error && error.message === "SPI_UNAVAILABLE")
          return reply.code(503).send({ code: "BIZ_SPI_UNAVAILABLE" });
        throw error;
      }
    });
  app.get<{ Params: { id: string } }>("/api/operator/risk-profiles/:id",
    async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!campaign || !operatorSessions) return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!operatorSessions.identity(request.headers.cookie))
        return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      if (!/^[a-zA-Z0-9_-]{1,128}$/.test(request.params.id))
        return reply.code(400).send({ code: "INVALID_CUSTOMER" });
      const bank = campaign.runtime.bank;
      try {
        const profile = bank.risk.profile(request.params.id);
        const history = bank.db.prepare(`SELECT actor,risk_tier,verified_income_cents,
          declared_income_cents,changed_at FROM customer_risk_profile_changes
          WHERE customer_id=? ORDER BY rowid DESC LIMIT 20`).all(request.params.id);
        return { ...profile, history };
      } catch (error) {
        if (error instanceof Error && error.message === "RISK_PROFILE_NOT_FOUND")
          return reply.code(404).send({ code: "CUSTOMER_NOT_FOUND" });
        throw error;
      }
    });
  app.post<{ Params: { id: string }; Body: { risk_tier?: unknown;
    verified_income_cents?: unknown } }>("/api/operator/risk-profiles/:id",
    { bodyLimit: 512 }, async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!campaign || !operatorSessions) return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const identity = operatorSessions.identity(request.headers.cookie);
      if (!identity) return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      if (identity.role !== "admin") return reply.code(403).send({ code: "ADMIN_REQUIRED" });
      const { risk_tier, verified_income_cents } = request.body ?? {};
      if (!/^[a-zA-Z0-9_-]{1,128}$/.test(request.params.id) ||
        !["low", "medium", "high"].includes(risk_tier as string) ||
        !Number.isSafeInteger(verified_income_cents) ||
        (verified_income_cents as number) < 0)
        return reply.code(400).send({ code: "RISK_PROFILE_INVALID" });
      try {
        return campaign.runtime.bank.risk.setVerifiedProfile(request.params.id,
          risk_tier as "low" | "medium" | "high", verified_income_cents as number,
          identity.id);
      } catch (error) {
        if (error instanceof Error && error.message === "RISK_PROFILE_NOT_FOUND")
          return reply.code(404).send({ code: "CUSTOMER_NOT_FOUND" });
        throw error;
      }
    });
  app.get<{ Querystring: { cursor?: string } }>("/api/operator/risk-reviews",
    async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!campaign || !operatorSessions?.identity(request.headers.cookie))
        return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      let afterExpiry = "", afterId = "";
      if (request.query.cursor !== undefined) {
        const raw = request.query.cursor;
        if (!/^[A-Za-z0-9_-]{1,256}$/.test(raw))
          return reply.code(400).send({ code: "INVALID_CURSOR" });
        try {
          const pair: unknown = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
          if (!Array.isArray(pair) || pair.length !== 2 ||
            typeof pair[0] !== "string" || typeof pair[1] !== "string" ||
            !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(pair[0]) ||
            !/^[a-zA-Z0-9_-]{1,128}$/.test(pair[1]))
            return reply.code(400).send({ code: "INVALID_CURSOR" });
          [afterExpiry, afterId] = pair;
        } catch { return reply.code(400).send({ code: "INVALID_CURSOR" }); }
      }
      const bank = campaign.runtime.bank;
      const now = bank.now();
      const isoNow = now.toISOString();
      const total = (bank.db.prepare(`SELECT COUNT(*) n FROM risk_pix_holds
        WHERE status='pending' AND expires_at>?`).get(isoNow) as { n: number }).n;
      const rows = bank.db.prepare(`SELECT h.id,h.from_account,h.to_account,h.amount_cents,
        h.actor,h.product,h.created_at,h.expires_at,d.score,d.reason_codes_json,
        ack.reviewer acknowledged_by,ack.acknowledged_at
        FROM risk_pix_holds h JOIN risk_decisions d ON d.id=h.risk_decision_id
        LEFT JOIN risk_pix_review_acknowledgements ack ON ack.hold_id=h.id
        WHERE h.status='pending' AND h.expires_at>?
          AND (h.expires_at>? OR (h.expires_at=? AND h.id>?))
        ORDER BY h.expires_at,h.id LIMIT 21`).all(isoNow, afterExpiry, afterExpiry, afterId) as
        { id: string; from_account: string; to_account: string; amount_cents: number;
          actor: string; product: string; created_at: string; expires_at: string; score: number;
          reason_codes_json: string; acknowledged_by: string | null;
          acknowledged_at: string | null }[];
      const visible = rows.slice(0, 20);
      const last = visible.at(-1);
      return { reviews: visible.map((row) => ({
        id: row.id, from_account: row.from_account, to_account: row.to_account,
        amount_cents: row.amount_cents, actor: row.actor, product: row.product,
        created_at: row.created_at,
        expires_at: row.expires_at, score: row.score,
        acknowledged_by: row.acknowledged_by, acknowledged_at: row.acknowledged_at,
        reason_codes: JSON.parse(row.reason_codes_json) as string[],
        remaining_seconds: Math.max(0, Math.ceil((Date.parse(row.expires_at) - now.getTime()) / 1000)),
      })), total, twin_now: isoNow, next_cursor: rows.length > 20 && last ?
        Buffer.from(JSON.stringify([last.expires_at, last.id])).toString("base64url") : null };
    });
  app.post<{ Params: { id: string } }>("/api/operator/risk-reviews/:id/acknowledge",
    async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!campaign || !operatorSessions) return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const identity = operatorSessions.identity(request.headers.cookie);
      if (!identity) return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      if (!/^[a-zA-Z0-9_-]{1,128}$/.test(request.params.id))
        return reply.code(400).send({ code: "INVALID_REVIEW" });
      try {
        const ack = campaign.runtime.bank.acknowledgeRiskPixHold(request.params.id, identity.id);
        return { hold_id: ack.hold_id, acknowledged_by: ack.reviewer,
          acknowledged_at: ack.acknowledged_at };
      } catch (error) {
        if (error instanceof BankError)
          return reply.code(error.code === "DEF_NOT_FOUND" ? 404 : 409)
            .send({ code: error.code });
        throw error;
      }
    });
  app.post<{ Params: { id: string }; Body: { decision?: string } }>(
    "/api/operator/risk-reviews/:id", { bodyLimit: 512 }, async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!campaign || !operatorSessions) return reply.code(404).send({ code: "OPERATOR_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const identity = operatorSessions.identity(request.headers.cookie);
      if (!identity) return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      if (!/^[a-zA-Z0-9_-]{1,128}$/.test(request.params.id) ||
        !["approve", "reject"].includes(request.body?.decision ?? ""))
        return reply.code(400).send({ code: "INVALID_REVIEW" });
      try {
        const result = campaign.runtime.bank.resolveRiskPixHold(request.params.id,
          request.body.decision as "approve" | "reject", identity.id);
        return { id: result.hold.id, status: result.hold.status,
          transfer_id: result.transfer?.id ?? null };
      } catch (error) {
        if (error instanceof BankError)
          return reply.code(error.code === "DEF_NOT_FOUND" ? 404 : 409)
            .send({ code: error.code });
        throw error;
      }
    });
  app.get<{ Querystring: { cursor?: string } }>("/api/operator/cautelar-reviews",
    async (request, reply) => {
      if (!requireOperatorRead(request, reply)) return;
      if (!campaign) return reply.code(404).send({ code: "BANK_UNAVAILABLE" });
      let afterExpiry = "", afterId = "";
      if (request.query.cursor !== undefined) {
        const raw = request.query.cursor;
        if (!/^[A-Za-z0-9_-]{1,256}$/.test(raw))
          return reply.code(400).send({ code: "INVALID_CURSOR" });
        try {
          const pair: unknown = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
          if (!Array.isArray(pair) || pair.length !== 2 ||
            typeof pair[0] !== "string" || typeof pair[1] !== "string" ||
            !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(pair[0]) ||
            !/^[a-zA-Z0-9_-]{1,128}$/.test(pair[1]))
            return reply.code(400).send({ code: "INVALID_CURSOR" });
          [afterExpiry, afterId] = pair;
        } catch { return reply.code(400).send({ code: "INVALID_CURSOR" }); }
      }
      const bank = campaign.runtime.bank;
      const now = bank.now();
      const isoNow = now.toISOString();
      const splitPage = campaign.runtime.separatedEcosystem ?
        await campaign.runtime.ecosystemCautelarReviewPage(now, afterExpiry, afterId) : undefined;
      const total = splitPage?.total ??
        (bank.db.prepare(`SELECT COUNT(*) n FROM psp_cautelar_holds
          WHERE status='active' AND expires_at>?`).get(isoNow) as { n: number }).n;
      const rows = splitPage?.rows ?? bank.db.prepare(`SELECT id,account_id,
        root_transfer_id,amount_cents,reason,created_at,expires_at
        FROM psp_cautelar_holds WHERE status='active' AND expires_at>?
          AND (expires_at>? OR (expires_at=? AND id>?))
        ORDER BY expires_at,id LIMIT 21`)
        .all(isoNow, afterExpiry, afterExpiry, afterId) as
        { id: string; account_id: string; root_transfer_id: string; amount_cents: number;
          reason: string; created_at: string; expires_at: string }[];
      const visible = rows.slice(0, 20);
      const last = visible.at(-1);
      return { reviews: visible.map((row) => ({ ...row,
        remaining_seconds: Math.max(0, Math.ceil((Date.parse(row.expires_at) - now.getTime()) / 1000)),
      })), total, twin_now: isoNow, next_cursor: rows.length > 20 && last ?
        Buffer.from(JSON.stringify([last.expires_at, last.id])).toString("base64url") : null };
    });
  app.post<{ Params: { id: string }; Body: { decision?: string } }>(
    "/api/operator/cautelar-reviews/:id", { bodyLimit: 512 }, async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!campaign || !operatorSessions)
        return reply.code(404).send({ code: "BANK_UNAVAILABLE" });
      if (!localOperatorAllowed(request.ip))
        return reply.code(403).send({ code: "LOCAL_OPERATOR_ONLY" });
      if (!localMutationAllowed(request.headers, request.protocol))
        return reply.code(403).send({ code: "LOCAL_ORIGIN_REQUIRED" });
      const identity = operatorSessions.identity(request.headers.cookie);
      if (!identity) return reply.code(401).send({ code: "OPERATOR_AUTH_REQUIRED" });
      if (!/^[a-zA-Z0-9_-]{1,128}$/.test(request.params.id) ||
        !["release", "return"].includes(request.body?.decision ?? ""))
        return reply.code(400).send({ code: "INVALID_REVIEW" });
      try {
        if (campaign.runtime.separatedEcosystem) {
          const result = await campaign.runtime.resolveSeparatedPspCautelar(
            request.params.id, request.body.decision as "release" | "return", identity.id);
          if (result.pending) reply.code(202);
          return { id: result.id, status: result.status,
            resolved_by: result.resolved_by, returned_cents: result.returned_cents };
        }
        const result = campaign.runtime.bank.resolvePspCautelar(request.params.id,
          request.body.decision as "release" | "return", identity.id);
        return { id: result.hold.id, status: result.hold.status,
          resolved_by: result.hold.resolved_by,
          returned_cents: result.returned?.amount ?? 0 };
      } catch (error) {
        if (error instanceof BankError)
          return reply.code(error.code === "DEF_NOT_FOUND" ? 404 : 409)
            .send({ code: error.code });
        throw error;
      }
    });
  const latestLedgerProof = () => {
    const row = events.db.prepare(`SELECT seq FROM events
      WHERE type='ledger.hourly_proof' ORDER BY seq DESC LIMIT 1`)
      .get() as { seq: number } | undefined;
    const event = row ? events.get(row.seq) : undefined;
    return event?.type === "ledger.hourly_proof" ? event.public : null;
  };
  const crossBookSummary = () => campaign ? publicCrossBookSummary(
    campaign.runtime.lastCrossBook, campaign.runtime.realNow()) : null;
  app.get("/api/bank/operations", async (_request, reply) => {
    reply.header("cache-control", "no-store");
    if (!campaign || ops.read().level >= 2)
      return reply.code(404).send({ code: "BANK_OPERATIONS_UNAVAILABLE" });
    const db = campaign.runtime.bank.db;
    const ecosystem = campaign.runtime.separatedEcosystem ?
      await campaign.runtime.ecosystemOperations() : undefined;
    const activity = (table: string, timestamp: string) => db.prepare(
      `SELECT COUNT(*) total,MAX(${timestamp}) last_at FROM ${table}`)
      .get() as { total: number; last_at: string | null };
    return {
      pix: activity("pix_transfers", "initiated_at"),
      automatic: activity("pix_automatic_charges", "created_at"),
      cards: db.prepare(`SELECT SUM(total) total,MAX(last_at) last_at FROM (
        SELECT COUNT(*) total,MAX(created_at) last_at FROM card_network_authorizations
        UNION ALL
        SELECT COUNT(*) total,MAX(created_at) last_at FROM card_network_rejections
      )`).get(),
      spi: ecosystem?.spi ?? activity("spi_messages", "created_at"),
      dict: activity("telemetry_events WHERE source='dict'", "ts"),
      cautelar: ecosystem?.cautelar ?? activity("psp_cautelar_holds", "created_at"),
      risk: activity("risk_decisions", "created_at"),
      closed_credits: activity("closed_account_credits", "created_at"),
      pi_accounts: ecosystem?.pi_accounts.length ??
        (db.prepare("SELECT COUNT(*) total FROM spi_participants")
          .get() as { total: number }).total,
      reconciliation_ok: campaign.runtime.bank.closedCreditReconciliation().ok,
      ledger_proof: latestLedgerProof(),
      cross_book: crossBookSummary(),
      last_close: (db.prepare(`SELECT brt_date,ledger_entries_count FROM period_closes
        ORDER BY brt_date DESC LIMIT 1`).get() as
        { brt_date: string; ledger_entries_count: number } | undefined) ?? null,
    };
  });
  const incidentFlow = (incidentId: string | null, transferId?: string,
    allowedIspbs?: ReadonlySet<string>) => {
    if (!campaign) throw new Error("CAMPAIGN_UNAVAILABLE");
    const runtime = campaign.runtime;
    return runtime.separatedEcosystem ? incidentMoneyFlowSeparated(runtime.bank,
      (rootId, caseId) => runtime.ecosystemMoneyFlowProjection(rootId, caseId),
      incidentId, transferId, allowedIspbs) :
      Promise.resolve(incidentMoneyFlow(runtime.bank, incidentId, transferId));
  };
  const disclosedMoneyFlow = async (incidentId: string | null) => {
    if (!campaign || ops.read().level >= 2) return null;
    const bank = campaign.runtime.bank;
    const snapshots = bank.db.prepare(`SELECT incident_id,transfer_id,edges_json
      FROM presentation_money_flow_disclosures
      WHERE (? IS NULL OR incident_id=?) ORDER BY id DESC`)
      .all(incidentId, incidentId) as { incident_id: string;
        transfer_id: string; edges_json: string }[];
    for (const snapshot of snapshots) {
      if (!events.db.prepare(`SELECT 1 FROM attack_incident_links
        WHERE incident_id=? AND disclosed=1`).get(snapshot.incident_id)) continue;
      const edges = JSON.parse(snapshot.edges_json) as DisclosedMoneyEdge[];
      const disclosedIspbs = new Set(edges.flatMap((edge) => [edge.from_ispb, edge.to_ispb]));
      const flow = await incidentFlow(snapshot.incident_id, snapshot.transfer_id,
        disclosedIspbs);
      if (!flow.edges.length) continue;
      return presentationMoneyFlow({ ...flow,
        med: campaign.runtime.separatedEcosystem ? flow.med :
          moneyFlowMedState(bank, snapshot.transfer_id, disclosedIspbs) }, edges);
    }
    return incidentId === null && snapshots.length === 0 ? { edges: [], med: null } : null;
  };
  app.get("/api/presentation/bank/money-flow", async (_request, reply) => {
    const flow = await disclosedMoneyFlow(null);
    return flow ?? reply.code(404).send({ code: "MONEY_FLOW_UNAVAILABLE" });
  });
  app.get<{ Params: { incidentId: string } }>("/api/presentation/bank/money-flow/:incidentId",
    async (request, reply) => {
    const { incidentId } = request.params;
    if (!/^[a-zA-Z0-9_-]{1,128}$/.test(incidentId))
      return reply.code(404).send({ code: "MONEY_FLOW_UNAVAILABLE" });
    const flow = await disclosedMoneyFlow(incidentId);
    return flow ?? reply.code(404).send({ code: "MONEY_FLOW_UNAVAILABLE" });
  });
  app.get("/api/operator/bank/money-flow", async (request, reply) => {
    if (!requireOperatorRead(request, reply)) return;
    if (!campaign || ops.read().level >= 2)
      return reply.code(404).send({ code: "MONEY_FLOW_UNAVAILABLE" });
    return incidentFlow(null);
  });
  app.get<{ Params: { incidentId: string } }>("/api/operator/bank/money-flow/:incidentId",
    async (request, reply) => {
    if (!requireOperatorRead(request, reply)) return;
    if (!campaign || ops.read().level >= 2)
      return reply.code(404).send({ code: "MONEY_FLOW_UNAVAILABLE" });
    const { incidentId } = request.params;
    if (!/^[a-zA-Z0-9_-]{1,128}$/.test(incidentId) ||
      !campaign.runtime.bank.db.prepare("SELECT 1 FROM sentinel_incidents WHERE id=?")
        .get(incidentId))
      return reply.code(404).send({ code: "INCIDENT_NOT_FOUND" });
    return incidentFlow(incidentId);
  });
  app.get("/api/operator/bank/operations", async (request, reply) => {
    if (!requireOperatorRead(request, reply)) return;
    if (!campaign || ops.read().level >= 2)
      return reply.code(404).send({ code: "BANK_OPERATIONS_UNAVAILABLE" });
    const bank = campaign.runtime.bank;
    const db = bank.db;
    const ecosystem = campaign.runtime.separatedEcosystem ?
      await campaign.runtime.ecosystemOperations() : undefined;
    return {
      pix: db.prepare(`SELECT substr(id,-8) ref,substr(from_account,-8) sender,
        substr(to_account,-8) recipient,amount amount_cents,status,product,
        substr(end_to_end_id,-8) end_to_end_ref,initiated_at
        FROM pix_transfers ORDER BY initiated_at DESC,id DESC LIMIT 12`).all(),
      automatic: db.prepare(`SELECT substr(c.id,-8) ref,
        substr(m.merchant_account,-8) merchant, c.amount_cents,c.status,c.error_code,
        c.due_at,c.attempt_count,c.next_attempt_at,
        (SELECT COUNT(*) FROM pix_automatic_post_due_retries r
          WHERE r.charge_id=c.id) post_due_retry_count FROM pix_automatic_charges c
        JOIN pix_automatic_mandates m ON m.id=c.mandate_id
        ORDER BY c.created_at DESC,c.id DESC LIMIT 12`).all(),
      automatic_notifications: db.prepare(`SELECT substr(id,-8) ref,
        substr(customer_id,-8) customer_ref,kind,message_pt,created_at
        FROM pix_automatic_notifications ORDER BY created_at DESC,id DESC LIMIT 12`).all(),
      cards: db.prepare(`SELECT * FROM (
        SELECT substr(id,-8) ref,merchant_id,amount_cents,status,
          response_code,mcc,created_at FROM card_network_authorizations
        UNION ALL
        SELECT substr(r.id,-8) ref,r.merchant_id,r.amount_cents,'declined' status,
          r.response_code,m.mcc,r.created_at FROM card_network_rejections r
          JOIN card_merchants m ON m.id=r.merchant_id
      ) ORDER BY created_at DESC,ref DESC LIMIT 12`).all(),
      spi: ecosystem?.recent_spi ?? db.prepare(`SELECT id,message_type,
        substr(end_to_end_id,-8) end_to_end_ref,
        created_at FROM spi_messages ORDER BY id DESC LIMIT 12`).all(),
      cautelar: ecosystem?.recent_cautelar ?? db.prepare(`SELECT substr(id,-8) ref,substr(account_id,-8) account_ref,
        amount_cents,reason,status,created_at,resolved_at,resolved_by
        FROM psp_cautelar_holds ORDER BY created_at DESC,id DESC LIMIT 12`).all(),
      psp_notices: ecosystem?.recent_notices ?? db.prepare(`SELECT id,substr(account_id,-8) account_ref,
        kind,amount_cents,message_pt,created_at FROM psp_cautelar_notices
        ORDER BY id DESC LIMIT 12`).all(),
      dict: db.prepare(`SELECT id,action,outcome,ts FROM telemetry_events
        WHERE source='dict' ORDER BY id DESC LIMIT 12`).all(),
      risk: db.prepare(`SELECT substr(id,-8) ref,area,score,outcome,reason_codes_json,
        created_at FROM risk_decisions ORDER BY created_at DESC,id DESC LIMIT 12`).all(),
      pi_accounts: ecosystem?.pi_accounts ?? db.prepare(`SELECT ispb,name,pi_balance_cents FROM spi_participants
        ORDER BY ispb`).all(),
      closed_credits: {
        reconciliation: bank.closedCreditReconciliation(),
        recent: db.prepare(`SELECT substr(id,-8) ref,substr(source_account,-8) source,
          source_kind,amount_cents,status,created_at,paid_at
          FROM closed_account_credits ORDER BY COALESCE(paid_at,created_at) DESC,id DESC
          LIMIT 12`).all(),
      },
      last_close: db.prepare(`SELECT brt_date,ledger_entries_count,ledger_sum
        FROM period_closes ORDER BY brt_date DESC LIMIT 1`).get() ?? null,
      ledger_proof: latestLedgerProof(),
      cross_book: crossBookSummary(),
    };
  });
  app.get<{ Querystring: { limit?: string } }>("/api/soc/incidents", async (request, reply) => {
    if (!campaign) return reply.code(404).send({ code: "SOC_UNAVAILABLE" });
    const limit = intParam(request.query.limit, 20, 100) || 20;
    const db = campaign.runtime.bank.db;
    const excluded = JSON.stringify(hiddenSocRows().incidents);
    const open_total = (db.prepare(`SELECT COUNT(*) n FROM sentinel_incidents
      WHERE state<>'resolved' AND id NOT IN (SELECT value FROM json_each(?))`)
      .get(excluded) as { n: number }).n;
    const since = new Date(campaign.runtime.bank.now().getTime() - 86_400_000).toISOString();
    const rows = db.prepare(`SELECT id,area,severity,state,alert_count,opened_at,last_seen_at
      FROM sentinel_incidents WHERE (state<>'resolved' OR last_seen_at>=?)
      AND id NOT IN (SELECT value FROM json_each(?))
      ORDER BY CASE WHEN state='resolved' THEN 1 ELSE 0 END,last_seen_at DESC,id DESC LIMIT ?`)
      .all(since, excluded, limit) as { id: string; area: string; severity: string; state: string;
        alert_count: number; opened_at: string; last_seen_at: string }[];
    const incidents = rows.map((incident) => ({ ...incident, entity_key: "Entidade protegida" }));
    return { incidents, open_total };
  });
  app.get<{ Querystring: { limit?: string } }>("/api/operator/soc/incidents",
    async (request, reply) => {
      if (!requireOperatorRead(request, reply)) return;
      if (!campaign) return reply.code(404).send({ code: "SOC_UNAVAILABLE" });
      const limit = intParam(request.query.limit, 20, 100) || 20;
      const open_total = (campaign.runtime.bank.db.prepare(`SELECT COUNT(*) n
        FROM sentinel_incidents WHERE state<>'resolved'`).get() as { n: number }).n;
      return { incidents: campaign.runtime.sentinels.recentIncidents(limit), open_total };
    });
  const incidentEntity = (id: string) => {
    if (!campaign || !/^[a-zA-Z0-9_-]{1,128}$/.test(id)) return null;
    const db = campaign.runtime.bank.db;
    const incident = db.prepare("SELECT entity_key FROM sentinel_incidents WHERE id=?")
      .get(id) as { entity_key: string } | undefined;
    if (!incident) return null;
    const customer = db.prepare(`SELECT id,status,kyc_status,risk_score FROM customers WHERE id=?`)
      .get(incident.entity_key) as { id: string; status: string; kyc_status: string;
        risk_score: number } | undefined;
    if (!customer) return { kind: "other" as const };
    const customerId = customer.id;
    const accounts = db.prepare(`SELECT id,kind,status FROM accounts
      WHERE customer_id=? ORDER BY opened_at DESC,id DESC LIMIT 20`).all(customerId);
    const devices = db.prepare(`SELECT id,first_seen_at,trusted_at,revoked_at,synthetic_geo
      FROM auth_devices WHERE customer_id=? ORDER BY first_seen_at DESC,id DESC LIMIT 20`)
      .all(customerId);
    const deviceLinks = db.prepare(`SELECT own.id device_id,other.customer_id linked_customer_id
      FROM auth_devices own JOIN auth_devices other
      ON other.fingerprint=own.fingerprint AND other.customer_id<>own.customer_id
      WHERE own.customer_id=? ORDER BY own.first_seen_at DESC,other.first_seen_at DESC
      LIMIT 8`).all(customerId);
    const pix = db.prepare(`SELECT id,amount amount_cents,status,initiated_at,end_to_end_id,
      CASE WHEN from_account IN (SELECT id FROM accounts WHERE customer_id=?)
        THEN 'out' ELSE 'in' END direction,
      CASE WHEN from_account IN (SELECT id FROM accounts WHERE customer_id=?)
        THEN to_account ELSE from_account END peer_account
      FROM pix_transfers WHERE from_account IN (SELECT id FROM accounts WHERE customer_id=?)
        OR to_account IN (SELECT id FROM accounts WHERE customer_id=?)
      ORDER BY initiated_at DESC,id DESC LIMIT 12`)
      .all(customerId, customerId, customerId, customerId);
    const relationships = db.prepare(`WITH owned AS
      (SELECT id FROM accounts WHERE customer_id=?), linked AS
      (SELECT CASE WHEN from_account IN (SELECT id FROM owned)
        THEN to_account ELSE from_account END peer_account,
        amount FROM pix_transfers WHERE status IN ('settled','returned_partial','returned_full')
        AND (from_account IN (SELECT id FROM owned) OR to_account IN (SELECT id FROM owned))
        AND NOT (from_account IN (SELECT id FROM owned) AND to_account IN (SELECT id FROM owned)))
      SELECT peer_account,COUNT(*) transfer_count,SUM(amount) total_cents FROM linked
      GROUP BY peer_account ORDER BY transfer_count DESC,peer_account LIMIT 8`).all(customerId);
    const risk = db.prepare(`SELECT area,outcome,score,reason_codes_json,trace_id,created_at
      FROM risk_decisions WHERE customer_id=? ORDER BY created_at DESC,id DESC LIMIT 12`)
      .all(customerId);
    return { kind: "customer" as const, customer, accounts, devices, device_links: deviceLinks,
      pix, relationships, risk };
  };
  app.get<{ Params: { id: string } }>("/api/soc/incidents/:id/entity", async (request, reply) => {
    if (!campaign || !/^[a-zA-Z0-9_-]{1,128}$/.test(request.params.id))
      return reply.code(404).send({ code: "INCIDENT_NOT_FOUND" });
    const db = campaign.runtime.bank.db;
    const incident = db.prepare("SELECT entity_key FROM sentinel_incidents WHERE id=?")
      .get(request.params.id) as { entity_key: string } | undefined;
    if (!incident || hiddenSocRows().incidents.includes(request.params.id))
      return reply.code(404).send({ code: "INCIDENT_NOT_FOUND" });
    const customer = db.prepare("SELECT 1 FROM customers WHERE id=?")
      .get(incident.entity_key);
    return customer ? { kind: "restricted" as const } : { kind: "other" as const };
  });
  app.get<{ Params: { id: string } }>("/api/operator/soc/incidents/:id/entity",
    async (request, reply) => {
      if (!requireOperatorRead(request, reply)) return;
      const entity = incidentEntity(request.params.id);
      return entity ?? reply.code(404).send({ code: "INCIDENT_NOT_FOUND" });
  });
  app.get<{ Params: { id: string; entryId: string } }>(
    "/api/operator/soc/incidents/:id/evidence/:entryId", async (request, reply) => {
      if (!requireOperatorRead(request, reply)) return;
      if (!campaign || !/^[a-zA-Z0-9_-]{1,128}$/.test(request.params.id) ||
        !/^[1-9]\d{0,14}$/.test(request.params.entryId))
        return reply.code(404).send({ code: "EVIDENCE_NOT_FOUND" });
      const incident = campaign.runtime.bank.db.prepare("SELECT 1 FROM sentinel_incidents WHERE id=?")
        .get(request.params.id);
      if (!incident) return reply.code(404).send({ code: "EVIDENCE_NOT_FOUND" });
      const row = events.db.prepare(`SELECT kind,attempt_no,round_id,payload_json
        FROM incident_case_entries WHERE incident_id=? AND id=?`)
        .get(request.params.id, Number(request.params.entryId)) as { kind: string;
          attempt_no: number | null; round_id: string | null; payload_json: string } | undefined;
      if (!row || (ops.read().level >= 2 && row.round_id &&
        ops.read().hiddenRoundIds.includes(row.round_id)))
        return reply.code(404).send({ code: "EVIDENCE_NOT_FOUND" });
      const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
      const text = (value: unknown, max = 128_000) =>
        typeof value === "string" ? value.slice(0, max) : "";
      const step = (value: unknown) => {
        if (!value || typeof value !== "object") return null;
        const item = value as Record<string, unknown>;
        return { ok: item.ok === true, exit_code: typeof item.exitCode === "number" ?
          item.exitCode : null, duration_ms: typeof item.durationMs === "number" ?
            item.durationMs : null, output: text(item.output, 6_000) };
      };
      let detail: Record<string, unknown>;
      if (row.kind === "patch.diff") {
        detail = { sha256: text(payload.sha256, 64), diff: text(payload.diff),
          truncated: payload.truncated === true };
      } else if (row.kind === "ci.result") {
        const result = payload.result && typeof payload.result === "object" ?
          payload.result as Record<string, unknown> : {};
        detail = { ready_for_review: result.readyForReview === true,
          red_first: text(result.redFirst, 40), typecheck: step(result.typecheck),
          world_tests: step(result.worldTests),
          red_first_before: step(result.redFirstBefore),
          red_first_after: step(result.redFirstAfter) };
      } else if (row.kind === "ci.failure") {
        detail = { typecheck: payload.typecheck === true,
          world_tests: payload.world_tests === true,
          red_first: text(payload.red_first, 40),
          failure_output: text(payload.failure_output, 6_000) };
      } else if (row.kind === "dossier.review") {
        detail = { verdict: text(payload.verdict, 20),
          findings: Array.isArray(payload.findings) ? payload.findings.slice(0, 20)
            .map((finding) => {
              const item = finding && typeof finding === "object" ?
                finding as Record<string, unknown> : {};
              return { severity: text(item.severity, 20), issue: text(item.issue, 2_000),
                evidence_run_id: text(item.evidence_run_id, 128) };
            }) : [],
          reasons_for_rejection: Array.isArray(payload.reasons_for_rejection) ?
            payload.reasons_for_rejection.slice(0, 20).map((value) => text(value, 2_000)) : [],
          required_changes: Array.isArray(payload.required_changes) ?
            payload.required_changes.slice(0, 20).map((value) => text(value, 2_000)) : [],
          diff_assessment: text(payload.diff_assessment, 4_000) };
      } else if (row.kind === "dossier.incident_map" ||
        row.kind === "dossier.root_cause" || row.kind === "dossier.fix_design") {
        const schema = row.kind === "dossier.incident_map" ? incidentMapBody :
          row.kind === "dossier.root_cause" ? rootCauseReportBody : fixDesignBody;
        const parsed = schema.safeParse(payload);
        if (!parsed.success) return reply.code(404).send({ code: "EVIDENCE_NOT_FOUND" });
        detail = parsed.data as Record<string, unknown>;
      } else return reply.code(404).send({ code: "EVIDENCE_NOT_FOUND" });
      return { key: `case:${request.params.entryId}`, kind: row.kind,
        attempt: row.attempt_no, detail };
    });
  app.get<{ Params: { id: string } }>(
    "/api/operator/soc/incidents/:id/deployment", async (request, reply) => {
      if (!requireOperatorRead(request, reply)) return;
      if (!campaign || !/^[a-zA-Z0-9_-]{1,128}$/.test(request.params.id) ||
        !campaign.runtime.bank.db.prepare("SELECT 1 FROM sentinel_incidents WHERE id=?")
          .get(request.params.id))
        return reply.code(404).send({ code: "INCIDENT_NOT_FOUND" });
      if (!events.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
        AND name='deployment_watches'`).get()) return { deployment: null };
      const hidden = ops.read();
      const watches = events.db.prepare(`SELECT run_id,round_id FROM deployment_watches
        WHERE incident_id=? ORDER BY started_at DESC,run_id DESC`)
        .all(request.params.id) as { run_id: string; round_id: string }[];
      const visible = watches.find((row) => hidden.level < 2 ||
        !hidden.hiddenRoundIds.includes(row.round_id));
      if (!visible) return { deployment: null };
      const latest = events.db.prepare(`SELECT run_id,started_at,state,reason,
        baseline_5xx,baseline_p95,samples_json FROM deployment_watches WHERE run_id=?`)
        .get(visible.run_id) as { run_id: string; started_at: string;
          state: string; reason: string | null; baseline_5xx: number;
          baseline_p95: number; samples_json: string };
      const values = JSON.parse(latest.samples_json) as unknown;
      const samples = Array.isArray(values) ? values.slice(-180).flatMap((value) => {
        if (!value || typeof value !== "object") return [];
        const sample = value as Record<string, unknown>;
        const numeric = (key: string) => typeof sample[key] === "number" &&
          Number.isFinite(sample[key]) && Number(sample[key]) >= 0 ? Number(sample[key]) : null;
        const requests = numeric("requests");
        const errors = numeric("errors5xx");
        const honestRequests = numeric("honestRequests");
        const wronglyBlocked = numeric("wronglyBlocked");
        const p95 = numeric("p95Ms");
        if (typeof sample.at !== "string" || !Number.isFinite(Date.parse(sample.at)) ||
          requests === null || errors === null || honestRequests === null ||
          wronglyBlocked === null || p95 === null || errors > requests ||
          wronglyBlocked > honestRequests) return [];
        return [{ at: sample.at, requests, errors_5xx: errors, honest_requests: honestRequests,
          wrongly_blocked: wronglyBlocked, p95_ms: p95 }];
      }) : [];
      return { deployment: { run_id: latest.run_id, started_at: latest.started_at,
        state: latest.state, reason: latest.reason,
        baseline_5xx: latest.baseline_5xx, baseline_p95_ms: latest.baseline_p95,
        samples } };
    });
  let socMetricsCache: { key: string; value: ReturnType<typeof calculateSocMetrics> } | undefined;
  app.get("/api/soc/metrics", async (_request, reply) => {
    if (!campaign) return reply.code(404).send({ code: "SOC_UNAVAILABLE" });
    const hasLinks = events.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='attack_incident_links'`).get();
    const links = hasLinks ? events.db.prepare(`SELECT attack_id,incident_id
      FROM attack_incident_links ORDER BY attack_id,incident_id`)
      .all() as { attack_id: string; incident_id: string }[] : [];
    const bankDb = campaign.runtime.bank.db;
    const returnVersion = (bankDb.prepare(`SELECT COALESCE(MAX(rowid),0) n
      FROM pix_returns`).get() as { n: number }).n;
    const hasTransferEvidence = bankDb.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='sentinel_incident_transfer_evidence'`).get();
    const evidenceVersion = hasTransferEvidence ? (bankDb.prepare(`SELECT COALESCE(MAX(rowid),0) n
      FROM sentinel_incident_transfer_evidence`).get() as { n: number }).n : 0;
    const key = `${events.latestSeq()}:${JSON.stringify(ops.read())}:${
      JSON.stringify(links)}:${returnVersion}:${evidenceVersion}`;
    if (socMetricsCache?.key === key) return socMetricsCache.value;
    const types: EventType[] = ["agent.spawned", "attack.attempted", "attack.failed", "attack.succeeded",
      "incident.opened", "incident.updated", "containment.applied", "task.opened",
      "patch.merged", "damage.assessed", "damage.restored",
      "impact.caused", "sim.tick", "review.rejected", "deploy.rolled_back"];
    const visible: Omit<ArenaEvent, "private">[] = [];
    const visibleCompensations = new Set<string>();
    const effectLinks = [...links];
    const linkedPairs = new Set(links.map((link) => `${link.attack_id}:${link.incident_id}`));
    const transferIncidents = hasTransferEvidence ? bankDb.prepare(`SELECT DISTINCT incident_id
      FROM sentinel_incident_transfer_evidence WHERE transfer_id=?`) : undefined;
    let after = 0;
    for (;;) {
      const batch = events.list({ after, types, limit: 500 });
      for (const raw of batch) {
        const shown = project(raw);
        if (!shown) continue;
        const privateData = raw.type === "damage.restored" || raw.type === "impact.caused" ?
          events.getPrivate(raw.seq) : undefined;
        if (raw.type === "damage.restored" && raw.public.recovered_cents === undefined &&
          typeof privateData?.recovered_cents === "number" &&
          typeof privateData?.bank_loss_cents === "number")
          visible.push({ ...shown, public: { ...shown.public,
            recovered_cents: privateData.recovered_cents,
            absorbed_cents: privateData.bank_loss_cents } });
        else visible.push(shown);
        if (raw.type === "impact.caused" && raw.public.deferred && transferIncidents) {
          const successSeq = privateData?.evidence_event_seq;
          const transferId = typeof successSeq === "number" ?
            events.getPrivate(successSeq)?.transfer_id : undefined;
          if (typeof transferId === "string") for (const { incident_id } of
            transferIncidents.all(transferId) as { incident_id: string }[]) {
            const attackId = String(raw.public.attack_id);
            const pair = `${attackId}:${incident_id}`;
            if (!linkedPairs.has(pair)) {
              effectLinks.push({ attack_id: attackId, incident_id });
              linkedPairs.add(pair);
            }
          }
        }
        const compensationId = privateData?.compensation_id;
        if (raw.type === "damage.restored" && typeof compensationId === "string")
          visibleCompensations.add(compensationId);
      }
      if (batch.length < 500) break;
      after = batch.at(-1)!.seq;
    }
    let bankReimbursedCents = 0;
    if (visibleCompensations.size && bankDb.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='blue_external_compensations'`).get()) {
      const bankLoss = campaign.runtime.bank.systemAccountId("bank_loss");
      const returnedToBank = bankDb.prepare(`SELECT COALESCE(SUM(amount),0) n FROM ledger_entries
        WHERE kind='pix_return_bank_recovery' AND account_id=? AND ref_id=(SELECT transfer_id
          FROM blue_external_compensations WHERE id=?)`);
      for (const compensationId of visibleCompensations)
        bankReimbursedCents += (returnedToBank.get(bankLoss, compensationId) as { n: number }).n;
    }
    const value = calculateSocMetrics(visible, effectLinks, bankReimbursedCents);
    socMetricsCache = { key, value };
    return value;
  });
  app.get<{ Params: { id: string } }>("/api/soc/incidents/:id/events", async (request, reply) => {
    if (!campaign || !/^[a-zA-Z0-9_-]{1,128}$/.test(request.params.id))
      return reply.code(404).send({ code: "INCIDENT_NOT_FOUND" });
    const incident = campaign.runtime.bank.db.prepare("SELECT id FROM sentinel_incidents WHERE id=?")
      .get(request.params.id);
    if (!incident || hiddenSocRows().incidents.includes(request.params.id))
      return reply.code(404).send({ code: "INCIDENT_NOT_FOUND" });
    const rows = events.db.prepare(`SELECT seq FROM events WHERE incident_id=?
      ORDER BY seq DESC LIMIT 100`).all(request.params.id) as { seq: number }[];
    const stepRows = events.db.prepare(`SELECT seq FROM events WHERE incident_id=?
      AND type IN ('incident.opened','containment.applied','damage.assessed',
        'task.opened','patch.proposed','review.rejected','review.approved','patch.merged',
        'deploy.succeeded','deploy.rolled_back','damage.restored',
        'postmortem.published','postmortem.narrated') ORDER BY seq`)
      .all(request.params.id) as { seq: number }[];
    const financialRows = events.db.prepare(`SELECT seq FROM events WHERE incident_id=?
      AND type IN ('damage.assessed','damage.restored') ORDER BY seq`).all(request.params.id) as { seq: number }[];
    let lossCents: number | null = null;
    let blockedCents: number | null = null;
    let escapedCents: number | null = null;
    let madeWholeCents: number | null = null;
    let recoveredCents = 0;
    let absorbedCents = 0;
    let completeBreakdown = true;
    let latestRestorationSeq = 0;
    const cents = (value: unknown): number | null => typeof value === "number" &&
      Number.isSafeInteger(value) && value >= 0 ? value : null;
    for (const { seq } of financialRows) {
      const event = events.get(seq);
      const visible = event && project(event);
      if (!visible) continue;
      if (visible.type === "damage.assessed") {
        lossCents = cents(visible.public.loss_cents);
        blockedCents = cents(visible.public.blocked_cents);
        escapedCents = cents(visible.public.escaped_cents);
      }
      if (visible.type === "damage.restored") {
        latestRestorationSeq = seq;
        const restored = cents(visible.public.restored_cents) ?? 0;
        madeWholeCents = (madeWholeCents ?? 0) + restored;
        const recovered = cents(visible.public.recovered_cents);
        const absorbed = cents(visible.public.absorbed_cents);
        if (recovered === null || absorbed === null || recovered + absorbed !== restored) {
          if (restored > 0) completeBreakdown = false;
        } else {
          recoveredCents += recovered;
          absorbedCents += absorbed;
        }
      }
    }
    const postmortemSeq = [...stepRows].reverse().find(({ seq }) => events.get(seq)?.type ===
      "postmortem.published")?.seq;
    const postmortemEvent = postmortemSeq ? events.get(postmortemSeq) : undefined;
    const postmortem = postmortemEvent && project(postmortemEvent);
    const caseKinds = new Set(["dossier.investigation", "dossier.incident_map",
      "dossier.root_cause", "dossier.fix_design", "ci.result", "ci.failure",
      "dossier.review", "dossier.rejection_report", "dossier.damage_1",
      "dossier.restoration", "dossier.damage_2", "dossier.hardening",
      "hardening.ci", "hardening.rejection", "dossier.hardening_review",
      "dossier.postmortem"]);
    const control = ops.read();
    const caseHistory = events.caseFile.history(request.params.id).filter((entry) =>
      !(control.level >= 2 && entry.round_id &&
        control.hiddenRoundIds.includes(entry.round_id)));
    const caseSteps = caseHistory.filter((entry) =>
      !entry.source_event_seq && caseKinds.has(entry.kind))
      .map((entry) => ({ key: `case:${entry.id}`, type: entry.kind,
        at: entry.created_at, attempt: entry.attempt_no }));
    const evidence = caseHistory.flatMap<{
      key: string; kind: "patch.diff" | "ci.result" | "ci.failure" | "dossier.review";
      attempt: number | null; sha256?: string | null; truncated?: boolean;
      ready_for_review?: boolean; typecheck?: boolean; world_tests?: boolean | null;
      verdict?: "approve" | "reject" | "unknown"; findings_count?: number;
    }>((entry) => {
      if (entry.kind === "patch.diff") {
        const sha = entry.payload.sha256;
        return [{ key: `case:${entry.id}`, kind: "patch.diff", attempt: entry.attempt_no,
          sha256: typeof sha === "string" && /^[a-f0-9]{64}$/.test(sha) ? sha : null,
          truncated: entry.payload.truncated === true }];
      }
      if (entry.kind === "ci.result") {
        const result = entry.payload.result;
        const row = result && typeof result === "object" ?
          result as Record<string, unknown> : {};
        const typecheck = row.typecheck && typeof row.typecheck === "object" ?
          row.typecheck as Record<string, unknown> : {};
        const worldTests = row.worldTests && typeof row.worldTests === "object" ?
          row.worldTests as Record<string, unknown> : null;
        return [{ key: `case:${entry.id}`, kind: "ci.result", attempt: entry.attempt_no,
          ready_for_review: row.readyForReview === true, typecheck: typecheck.ok === true,
          world_tests: worldTests === null ? null : worldTests.ok === true }];
      }
      if (entry.kind === "ci.failure") return [{ key: `case:${entry.id}`,
        kind: "ci.failure", attempt: entry.attempt_no,
        typecheck: entry.payload.typecheck === true,
        world_tests: entry.payload.world_tests === true }];
      if (entry.kind === "dossier.review") return [{ key: `case:${entry.id}`,
        kind: "dossier.review", attempt: entry.attempt_no,
        verdict: entry.payload.verdict === "approve" ? "approve" :
          entry.payload.verdict === "reject" ? "reject" : "unknown",
        findings_count: Array.isArray(entry.payload.findings) ?
          entry.payload.findings.length : 0 }];
      return [];
    }).slice(-24);
    const eventSteps = stepRows.flatMap(({ seq }) => {
      const event = events.get(seq);
      const visible = event && project(event);
      return visible ? [{ key: `event:${seq}`, seq, type: visible.type, at: visible.ts,
        ...(visible.type === "patch.merged" ? { phase: visible.public.phase } : {}) }] : [];
    });
    const finalRecovery = postmortem?.type === "postmortem.published" &&
      postmortemSeq !== undefined && postmortemSeq >= latestRestorationSeq ?
      postmortem.public : null;
    return { damage: { last_assessed_open_cents: lossCents,
      blocked_cents: blockedCents, escaped_cents: escapedCents,
      made_whole_cents: madeWholeCents,
      recovered_cents: completeBreakdown ? recoveredCents :
        cents(finalRecovery?.recovered_cents),
      absorbed_cents: completeBreakdown ? absorbedCents :
        cents(finalRecovery?.absorbed_cents) },
      postmortem: postmortem?.type === "postmortem.published" ? postmortem.public : null,
      evidence,
      steps: [...eventSteps, ...caseSteps].sort((left, right) =>
        Date.parse(left.at) - Date.parse(right.at) ||
        Number(right.key.startsWith("event:")) - Number(left.key.startsWith("event:")) ||
        left.key.localeCompare(right.key)),
      events: rows.reverse().flatMap(({ seq }) => {
      const event = events.get(seq);
      const visible = event && project(event);
      return visible ? [visible] : [];
    }) };
  });
  const roundEventCount = events.db.prepare(`SELECT COUNT(*) n FROM events WHERE
    (round_id=? AND seq>=?) OR (round_id IS NULL AND seq>=? AND seq<=?)`);
  app.get("/api/rounds", async () => ({ rounds: events.rounds().filter((round) =>
    ops.read().level < 2 || !ops.read().hiddenRoundIds.includes(round.round_id)).map((round) => ({ round_id: round.round_id,
    round_no: round.round_no, first_seq: round.first_seq, last_seq: round.last_seq, status: round.status,
    event_count: (roundEventCount.get(round.round_id, round.first_seq, round.first_seq,
      round.last_seq ?? events.latestSeq()) as { n: number }).n,
    score: round.score_json ? JSON.parse(round.score_json) : null,
    headline_pt: ops.read().level >= 2 && round.last_seq && ops.read().hiddenSeqs.includes(round.last_seq)
      ? "Conteúdo oculto temporariamente" : round.headline_pt ?
        isSafePublicText(round.headline_pt) ? round.headline_pt : safeFallback() : null })) }));
  const summaryTypes = ["attack.succeeded", "impact.caused", "incident.updated", "damage.restored",
    "review.rejected", "regression.result", "feature.launched", "health.updated",
    "round.ended", "score.updated"] as EventType[];
  const summaryHead = events.db.prepare(`SELECT COALESCE(MAX(seq),0) n FROM events WHERE type IN
    (${summaryTypes.map(() => "?").join(",")})`);
  let summaryCache: { key: string; value: Record<string, unknown> } | undefined;
  app.get("/api/launch-summary", async () => {
    const key = `${(summaryHead.get(...summaryTypes) as { n: number }).n}:${JSON.stringify(ops.read())}`;
    if (summaryCache?.key === key) return summaryCache.value;
    const breaches = new Set<string>();
    const resolved = new Set<string>();
    const regressionTests = new Set<string>();
    const features = new Set<string>();
    let loss = 0; let restored = 0; let rejections = 0; let latestHealth = 100;
    let lastFeature: Omit<ArenaEvent, "private"> | null = null;
    let after = 0;
    while (true) {
      const batch = events.list({ after, types: summaryTypes, limit: 500 });
      for (const raw of batch) {
        const event = project(raw);
        if (!event) continue;
        const data = event.public;
        switch (event.type) {
          case "attack.succeeded": breaches.add(String(data.attack_id)); break;
          case "impact.caused": loss += Number(data.loss_cents); break;
          case "incident.updated":
            if (data.state === "resolved") resolved.add(String(data.incident_id));
            break;
          case "damage.restored": restored += Number(data.restored_cents); break;
          case "review.rejected": rejections++; break;
          case "regression.result":
            if (typeof data.added_test_id === "string") regressionTests.add(data.added_test_id);
            break;
          case "feature.launched": features.add(String(data.feature_id)); lastFeature = event; break;
          case "health.updated": latestHealth = Number(data.overall); break;
        }
      }
      if (batch.length < 500) break;
      after = batch.at(-1)!.seq;
    }
    const completed = events.rounds().filter((round) => round.status !== "started" &&
      !(ops.read().level >= 2 && ops.read().hiddenRoundIds.includes(round.round_id)));
    const mean = (key: "mttd_s" | "mttr_s") => {
      const values = completed.map((round) => round.score_json ?
        (JSON.parse(round.score_json) as Record<string, unknown>)[key] : null)
        .filter((value): value is number => typeof value === "number" && Number.isFinite(value));
      return values.length ? Math.round(values.reduce((sum, value) => sum + value, 0) / values.length) : null;
    };
    const value = { played: completed.length, breaches: breaches.size, resolved: resolved.size, loss, restored,
      regressionTests: regressionTests.size, rejections, features: features.size, latestHealth,
      lastFeature, mttd: mean("mttd_s"), mttr: mean("mttr_s") };
    summaryCache = { key, value };
    return value;
  });
  app.get<{ Params: { id: string }; Querystring: { after?: string; limit?: string } }>("/api/rounds/:id/events",
    async (request, reply) => {
      if (ops.read().level >= 2 && ops.read().hiddenRoundIds.includes(request.params.id))
        return reply.code(404).send({ code: "ROUND_NOT_FOUND" });
      return page({ roundId: request.params.id,
        after: intParam(request.query.after, 0), limit: intParam(request.query.limit, 500, 500) || 500 });
    });
  app.get<{ Querystring: { after?: string; before?: string; round?: string; types?: string; limit?: string } }>("/api/events", async (request, reply) => {
    const query = request.query;
    const requested = query.types?.split(",").filter(Boolean);
    if (requested && (requested.length > EVENT_TYPES.length || requested.some((type) => !EVENT_TYPES.includes(type as EventType))))
      return reply.code(400).send({ code: "EVENT_TYPE_INVALID" });
    const types = requested as EventType[] | undefined;
    return page({ after: intParam(query.after, 0), before: intParam(query.before, Number.MAX_SAFE_INTEGER),
      ...(query.round ? { roundId: query.round } : {}), ...(types?.length ? { types } : {}),
      limit: intParam(query.limit, 500, 500) || 500 });
  });
  const hiddenPublicTelemetry = (entry: TelemetryEvent): boolean => {
    const state = ops.read();
    if (state.level < 2 || !state.hiddenRoundIds.length) return false;
    if (platformAgentRules.includes(entry.rule_id as typeof platformAgentRules[number])) return true;
    if (entry.source !== "agent") return true;
    try {
      const row = events.db.prepare(`SELECT e.seq FROM events e
        JOIN event_integrity i ON i.seq=e.seq WHERE e.id=?`).get(entry.trace_id) as
        { seq: number } | undefined;
      const source = row && events.get(row.seq);
      if (!source || source.type !== entry.action ||
        !["agent.spawned", "tool.called", "agent.finished", "integrity.violation"].includes(source.type))
        return true;
      return isHidden(source, state);
    } catch { return true; }
  };
  app.get<{ Querystring: { after?: string; limit?: string } }>("/api/telemetry", async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!campaign) return reply.code(404).send({ code: "TELEMETRY_UNAVAILABLE" });
    const after = intParam(request.query.after, 0);
    const limit = intParam(request.query.limit, 200, 500) || 200;
    const entries = campaign.runtime.bank.telemetry.list(after, limit);
    return { entries: entries.filter((entry) => !hiddenPublicTelemetry(entry)).map(publicTelemetry),
      next_after: entries.at(-1)?.id ?? after };
  });
  const operatorTelemetryAllowed = operatorReadAllowed;
  app.get<{ Querystring: { after?: string; limit?: string } }>("/api/operator/telemetry",
    async (request, reply) => {
      reply.header("cache-control", "no-store");
      if (!operatorTelemetryAllowed(request))
        return reply.code(localOperatorAllowed(request.ip) ? 401 : 403)
          .send({ code: "OPERATOR_AUTH_REQUIRED" });
      if (!campaign) return reply.code(404).send({ code: "TELEMETRY_UNAVAILABLE" });
      const after = intParam(request.query.after, 0);
      const limit = intParam(request.query.limit, 200, 500) || 200;
      const entries = campaign.runtime.bank.telemetry.list(after, limit);
      return { entries, next_after: entries.at(-1)?.id ?? after };
    });
  const sendTelemetryStream = (request: FastifyRequest<{ Querystring: { after?: string } }>,
    reply: FastifyReply, privileged: boolean): void => {
    if (!telemetryStream) { reply.code(404).send({ code: "TELEMETRY_UNAVAILABLE" }); return; }
    reply.hijack();
    const response = reply.raw;
    trackEventStream(response);
    response.writeHead(200, { "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform", connection: "keep-alive" });
    response.write("retry: 3000\n\n");
    const header = request.headers["last-event-id"];
    const after = intParam((Array.isArray(header) ? header[0] : header) ?? request.query.after, 0);
    const recent = telemetryStream.recent();
    const oldest = recent[0]?.id ?? 0;
    if (after && oldest && after < oldest - 1)
      response.write(`event: reset\ndata: ${JSON.stringify({ next_after: oldest - 1 })}\n\n`);
    const send = (entry: typeof recent[number]) => {
      if (response.destroyed) return;
      if (privileged && !operatorTelemetryAllowed(request)) { response.end(); return; }
      if (!privileged && hiddenPublicTelemetry(entry)) return;
      response.write(`id: ${entry.id}\nevent: telemetry\ndata: ${JSON.stringify(
        privileged ? entry : publicTelemetry(entry))}\n\n`);
    };
    for (const entry of recent) if (entry.id > after) send(entry);
    const unsubscribe = telemetryStream.subscribe((entry) => { if (entry.id > after) send(entry); });
    const ping = setInterval(() => {
      if (response.destroyed) return;
      if (privileged && !operatorTelemetryAllowed(request)) { response.end(); return; }
      response.write(": ping\n\n");
    }, 15_000);
    ping.unref();
    response.on("close", () => { clearInterval(ping); unsubscribe(); });
  };
  app.get<{ Querystring: { after?: string } }>("/api/telemetry/stream", async (request, reply) => {
    sendTelemetryStream(request, reply, false);
  });
  app.get<{ Querystring: { after?: string } }>("/api/operator/telemetry/stream",
    async (request, reply) => {
      if (!operatorTelemetryAllowed(request))
        return reply.code(localOperatorAllowed(request.ip) ? 401 : 403)
          .send({ code: "OPERATOR_AUTH_REQUIRED" });
      sendTelemetryStream(request, reply, true);
    });
  app.get<{ Params: { traceId: string } }>("/api/telemetry/traces/:traceId", async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!campaign) return reply.code(404).send({ code: "TRACE_NOT_FOUND" });
    const entries = campaign.runtime.bank.telemetry.trace(request.params.traceId)
      .filter((entry) => !hiddenPublicTelemetry(entry));
    return entries.length ? { trace_id: request.params.traceId,
      entries: entries.map(publicTelemetry) } :
      reply.code(404).send({ code: "TRACE_NOT_FOUND" });
  });
  app.get<{ Params: { traceId: string } }>("/api/operator/telemetry/traces/:traceId",
    async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!operatorTelemetryAllowed(request))
      return reply.code(localOperatorAllowed(request.ip) ? 401 : 403)
        .send({ code: "OPERATOR_AUTH_REQUIRED" });
    if (!campaign) return reply.code(404).send({ code: "TRACE_NOT_FOUND" });
    const entries = campaign.runtime.bank.telemetry.trace(request.params.traceId);
    return entries.length ? { trace_id: request.params.traceId, entries } :
      reply.code(404).send({ code: "TRACE_NOT_FOUND" });
  });
  app.get<{ Querystring: { seq?: string } }>("/api/keyframe", async (request, reply) => {
    if (ops.read().level >= 2) return reply.code(404).send({ code: "KEYFRAME_UNAVAILABLE" });
    const frame = events.nearestKeyframe(intParam(request.query.seq, events.latestSeq()));
    if (!frame) return reply.code(404).send({ code: "KEYFRAME_NOT_FOUND" });
    return { seq: frame.seq, reducer_version: frame.reducer_version, state: decodeKeyframe(frame.state_gz) };
  });
  app.get<{ Querystring: { after?: string } }>("/api/stream", async (request, reply) => {
    reply.hijack();
    const response = reply.raw;
    trackEventStream(response);
    response.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache, no-transform",
      connection: "keep-alive", "x-accel-buffering": "no" });
    response.write("retry: 3000\n\n");
    const header = request.headers["last-event-id"];
    const after = intParam((Array.isArray(header) ? header[0] : header) ?? request.query.after, 0);
    if (after > events.latestSeq()) response.write(`event: reset\ndata: ${JSON.stringify({ latest_seq: events.latestSeq() })}\n\n`);
    const pending: ArenaEvent[] = [];
    let catchingUp = true;
    const unsubscribe = events.subscribe((event) => {
      if (event.seq <= after) return;
      if (catchingUp) pending.push(event);
      else if (!response.destroyed) { const visible = project(event); if (visible) response.write(sseFrame(visible)); }
    });
    let cursor = after;
    while (true) {
      const batch = events.list({ after: cursor, limit: 500 });
      if (!batch.length) break;
      for (const event of batch) { const visible = project(event);
        if (visible && !response.destroyed) response.write(sseFrame(visible)); }
      cursor = batch.at(-1)!.seq;
      if (batch.length < 500) break;
    }
    catchingUp = false;
    for (const event of pending) if (event.seq > cursor && !response.destroyed) {
      const visible = project(event); if (visible) response.write(sseFrame(visible));
    }
    const heartbeat = setInterval(() => { if (!response.destroyed) response.write(`event: heartbeat\ndata: ${JSON.stringify({
      ts: new Date().toISOString(), telemetry: ops.read().level < 2 ? campaign?.runtime.lastTelemetry ?? null : null,
    })}\n\n`); }, 2000);
    const ping = setInterval(() => { if (!response.destroyed) response.write(": ping\n\n"); }, 15_000);
    response.on("close", () => { clearInterval(heartbeat); clearInterval(ping); unsubscribe(); });
  });
  app.get("/*", async (request, reply) => {
    const requested = request.url.split("?")[0] ?? "/";
    if (requested === "/api" || requested.startsWith("/api/"))
      return reply.code(404).send({ code: "NOT_FOUND" });
    const candidate = resolve(staticDir, requested === "/" ? "index.html" : `.${decodeURIComponent(requested)}`);
    const inside = relative(staticDir, candidate);
    if (inside.startsWith("..") || inside.includes("..") || !existsSync(candidate) || !statSync(candidate).isFile()) {
      if (!requested.includes(".") && existsSync(join(staticDir, "index.html"))) return reply.type(MIME[".html"]!).send(readFileSync(join(staticDir, "index.html")));
      return reply.code(404).send({ code: "NOT_FOUND" });
    }
    return reply.type(MIME[extname(candidate)] ?? "application/octet-stream").send(readFileSync(candidate));
  });
  const closeForRestart = () => {
    preserveFaultsOnClose = true;
    return app.close();
  };
  return { app, events, ops, campaign, defense, closeForRestart };
}

export async function buildSeparatedServer(dataDir: string,
  staticDir = DEFAULT_STATIC,
  campaignOptions: Omit<CampaignServerOptions, "prepared">) {
  mkdirSync(dataDir, { recursive: true });
  const events = new EventStore(join(dataDir, "events.sqlite"));
  const localAgentRuntime = campaignOptions.localCodex ?
    new CodexRuntime({ events, dataDir,
      usageCaps: campaignOptions.faultLab ? FAULT_LAB_USAGE_CAPS : undefined }) : undefined;
  let campaign: ReturnType<typeof createCampaignApp> | undefined;
  try {
    campaign = await createSeparatedCampaignApp({ dataDir, events,
      ...campaignOptions,
      ...(localAgentRuntime ? { runtime: localAgentRuntime } : {}) });
    return buildServer(dataDir, staticDir, { ...campaignOptions,
      prepared: { events, campaign,
        ...(localAgentRuntime ? { localAgentRuntime } : {}) } });
  } catch (error) {
    await campaign?.runtime.close().catch(() => undefined);
    await localAgentRuntime?.close().catch(() => undefined);
    events.close();
    throw error;
  }
}

export async function buildLocalServer(dataDir: string,
  staticDir = DEFAULT_STATIC,
  campaignOptions: Omit<CampaignServerOptions, "prepared">,
  ecosystemMode: "separated" | "embedded" = "separated") {
  if (campaignOptions.faultLab) {
    if (!campaignOptions.bankOnly || campaignOptions.campaignMode !== "fault_lab")
      throw new Error("FAULT_LAB_REQUIRES_BANK_ONLY");
    if (ecosystemMode !== "separated") throw new Error("FAULT_LAB_REQUIRES_SEPARATED_DATA");
    mkdirSync(dataDir, { recursive: true });
    const marker = join(dataDir, "fault-lab.marker");
    if (!existsSync(marker)) {
      if (["bank.sqlite", "ecosystem.sqlite", "events.sqlite"].some((name) =>
        existsSync(join(dataDir, name))))
        throw new Error("FAULT_LAB_DATA_DIR_NOT_DISPOSABLE");
      writeFileSync(marker, "banco-vivo-fault-lab-v1\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
    } else if (readFileSync(marker, "utf8") !== "banco-vivo-fault-lab-v1\n") {
      throw new Error("FAULT_LAB_MARKER_INVALID");
    }
  }
  if (ecosystemMode === "embedded") return buildServer(dataDir, staticDir, campaignOptions);
  ensureSeparatedData(dataDir, campaignOptions.seed);
  return buildSeparatedServer(dataDir, staticDir, campaignOptions);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const faultLab = process.env.FAULT_LAB_MODE === "1";
  if (faultLab && process.env.BANK_ONLY_MODE === "1")
    throw new Error("FAULT_LAB_AND_BANK_ONLY_CONFLICT");
  const bankOnly = faultLab || process.env.BANK_ONLY_MODE === "1";
  const seedProfile = process.env.FAKEBANK_SEED_PROFILE ?? "demo";
  if (seedProfile !== "demo" && seedProfile !== "full") throw new Error("FAKEBANK_SEED_PROFILE_INVALID");
  const dataDir = faultLab ?
    (process.env.FAULT_LAB_DATA_DIR || resolve("data/fault-lab")) :
    (process.env.DATA_DIR || resolve("data"));
  const host = process.env.HOST?.trim() || "127.0.0.1";
  if (faultLab && host !== "127.0.0.1" && host !== "::1")
    throw new Error("FAULT_LAB_LOOPBACK_ONLY");
  const port = intParam(process.env.PORT, 3000, 65535);
  const scheduledStart = process.env.CAMPAIGN_START_BRT?.trim();
  const continuousText = process.env.CAMPAIGN_CONTINUOUS_INTERVAL_MINUTES?.trim();
  const continuousIntervalMinutes = continuousText ? Number(continuousText) : undefined;
  if (scheduledStart && continuousIntervalMinutes !== undefined)
    throw new Error("CAMPAIGN_MODES_CONFLICT");
  if (bankOnly && (scheduledStart || continuousIntervalMinutes !== undefined))
    throw new Error("BANK_ONLY_SCHEDULE_DISABLED");
  const startBrtDate = scheduledStart || new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Sao_Paulo", year: "numeric", month: "2-digit", day: "2-digit",
  }).format(new Date());
  const ecosystemMode = process.env.BANK_ECOSYSTEM_MODE?.trim() || "separated";
  if (ecosystemMode !== "separated" && ecosystemMode !== "embedded")
    throw new Error("BANK_ECOSYSTEM_MODE_INVALID");
  let server: ReturnType<typeof buildServer>;
  let shutdownRequested = false;
  const closeServer = (exitCode: number) => {
    if (shutdownRequested) return;
    shutdownRequested = true;
    setImmediate(() => {
      const closing = exitCode === 75 ? server.closeForRestart() : server.app.close();
      void closing.then(() => process.exit(exitCode)).catch((error) => {
        console.error("server shutdown error", error);
        process.exit(1);
      });
    });
  };
  const options: CampaignServerOptions = {
    startBrtDate, repoRoot: faultLab && process.env.FAULT_LAB_CODE_SOURCE_REPO ?
      resolve(process.env.FAULT_LAB_CODE_SOURCE_REPO) : resolve("."),
    bankOnly, faultLab,
    ...(faultLab ? { twinSpeed: 60 } : {}),
    ...(faultLab || seedProfile === "demo" ? { seed: { customers: 48, accounts: 60,
      historyTransactions: 600, openWeaknesses: false } } : {}),
    localCodex: faultLab && process.env.FAKEBANK_LOCAL_CODEX === "1",
    campaignMode: faultLab ? "fault_lab" : bankOnly ? "bank_only" : "defensive_only",
    plantCanaries: !bankOnly,
    onDemand: bankOnly || !scheduledStart,
    ...(continuousIntervalMinutes !== undefined ? { continuousIntervalMinutes } : {}),
    onError: (error) => console.error("campaign runtime error", error),
    onRestart: () => closeServer(75) };
  server = await buildLocalServer(dataDir, DEFAULT_STATIC, options, ecosystemMode);
  const mailbox = server.campaign ?
    await startCustomerOtpMailbox(server.campaign.runtime.auth, dataDir) : undefined;
  server.app.addHook("onClose", async () => { await mailbox?.close(); });
  process.on("SIGINT", () => closeServer(0));
  process.on("SIGTERM", () => closeServer(0));
  server.campaign?.runtime.start();
  server.defense?.start();
  server.app.listen({ host, port }).catch((error: unknown) => {
    console.error(error);
    closeServer(1);
  });
}
