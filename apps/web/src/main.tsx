import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { AREAS, EVENT_TYPES, TELEMETRY_FRAME, parseEvent, publicView,
  type ArenaEvent, type Area, type LiveTelemetry } from "../../../packages/contracts/src/index.ts";
import { initialWorld, reduceWorld, REDUCER_VERSION, type WorldState } from "../../../packages/world-reducer/src/index.ts";
import { nextReplayStep } from "./replay-timing.ts";
import { replayChapters } from "./replay-chapters.ts";
import { parseMomentPosition, resolveMomentCursor, type MomentPosition } from "../../../packages/replay-link/src/index.ts";
import { sanitizePublicEvent } from "../../../packages/contracts/src/public-safety.ts";
import { publicEventDetails } from "./public-event-details.ts";
import { TelemetryPanel } from "./TelemetryPanel.tsx";
import { DefenseFlow } from "./DefenseFlow.tsx";
import { defenseIncidents, type DefenseIncident } from "./defense-flow.ts";
import { AlertQueue } from "./AlertQueue.tsx";
import { RecoveryOverview } from "./RecoveryOverview.tsx";
import { MoneyFlow } from "./MoneyFlow.tsx";
import { replayMoneyFlow } from "./replay-money-flow.ts";
import { initialPresentationMode, pathWithPresentationMode, presentationEventSummary, presentationShareUrl } from "./presentation-mode.ts";
import { BankOperationsPanel } from "./BankOperationsPanel.tsx";
import { CustomerInbox } from "./CustomerInbox.tsx";
import { AgentLivePanel } from "./AgentLivePanel.tsx";
import { FaultLabPanel } from "./FaultLabPanel.tsx";
import { ThreeLaneTimeline } from "./ThreeLaneTimeline.tsx";
import { PspCustomerInbox } from "./PspCustomerInbox.tsx";
import type { SocMetrics } from "../../server/src/soc-metrics.ts";
import "./style.css";

type Page = "control" | "lab" | "soc" | "bank" | "history" | "score" | "customer" | "psp" | "about";
function pageForLocation(): Page {
  const path = location.pathname.replace(/\/+$/, "") || "/";
  if (path === "/soc" || new URLSearchParams(location.search).get("page") === "soc") return "soc";
  if (path === "/laboratorio" || new URLSearchParams(location.search).get("page") === "lab") return "lab";
  if (path === "/banco" || new URLSearchParams(location.search).get("page") === "bank") return "bank";
  if (path === "/historico" || new URLSearchParams(location.search).get("page") === "history") return "history";
  if (path === "/placar" || new URLSearchParams(location.search).get("page") === "score") return "score";
  if (path === "/cliente" || new URLSearchParams(location.search).get("page") === "customer") return "customer";
  if (path === "/psp" || new URLSearchParams(location.search).get("page") === "psp") return "psp";
  if (path === "/sobre" || new URLSearchParams(location.search).get("page") === "about") return "about";
  return "control";
}
function historyPush(path: string): void {
  const target = pathWithPresentationMode(path, location.search);
  if (location.pathname + location.search !== target) window.history.pushState(null, "", target);
}
interface RoundIndex { round_id: string; round_no: number; status: string;
  headline_pt: string | null; first_seq: number; last_seq: number | null; event_count: number;
  score?: { red_points?: number; blue_points?: number; attacks_succeeded: number;
    loss_cents: number; restored_cents: number; mttd_s?: number | null;
    mttc_s?: number | null; mttr_s?: number | null } | null; }
interface RoundHistory { events: ArenaEvent[]; keyframe: WorldState | null; }
const LABEL: Record<Area, string> = { auth: "Autenticação", accounts: "Contas", pix: "Pix", cards: "Cartões", loans: "Crédito", api_gateway: "Entrada digital", ledger: "Livro-razão" };
const ROOMS: { area: Area; x: number; y: number; w: number; h: number; parts: string[] }[] = [
  { area: "auth", x: 120, y: 120, w: 380, h: 230, parts: ["LOGIN", "MFA", "SESSÕES", "RISCO"] },
  { area: "pix", x: 560, y: 120, w: 480, h: 230, parts: ["CHAVES", "LIMITES", "MED", "ANTIFRAUDE"] },
  { area: "cards", x: 1100, y: 120, w: 380, h: 230, parts: ["EMISSOR", "3DS", "TOKEN", "ESTORNO"] },
  { area: "accounts", x: 120, y: 640, w: 380, h: 230, parts: ["KYC", "SALDOS", "EXTRATOS", "LIMITES"] },
  { area: "ledger", x: 560, y: 400, w: 480, h: 300, parts: ["DÉBITO", "CRÉDITO", "CONCILIAÇÃO"] },
  { area: "loans", x: 1100, y: 640, w: 380, h: 230, parts: ["SCORE", "CONTRATOS", "COBRANÇA"] },
];
const IMPORTANT = new Set(["attack.attempted", "attack.succeeded", "impact.caused", "sentinel.alert", "incident.opened", "containment.applied", "review.rejected", "review.approved", "patch.merged", "deploy.succeeded", "deploy.rolled_back", "regression.result", "damage.restored", "postmortem.published", "postmortem.narrated", "narration.published", "round.ended"]);
const clock = (iso?: string | null) => iso ? new Intl.DateTimeFormat("pt-BR", { timeZone: "America/Sao_Paulo", hour: "2-digit", minute: "2-digit" }).format(new Date(iso)) : "--:--";
const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", { style: "currency", currency: "BRL", maximumFractionDigits: 0 });
const metricSeconds = (value?: number | null) => value == null ? "—" : `${Math.round(value)} s`;
function elapsed(first?: string, last?: string): string { if (!first || !last) return "00:00"; const s = Math.max(0, Math.floor((Date.parse(last) - Date.parse(first)) / 1000)); return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`; }
function requestedMoment(): { roundNo: number; position: MomentPosition } | null {
  const path = /^\/rodada\/(\d{1,2})\/?$/.exec(location.pathname);
  const params = new URLSearchParams(location.search);
  const legacy = /^#r(\d{2})-t(\d+)$/.exec(location.hash);
  const roundText = path?.[1] ?? params.get("round") ?? legacy?.[1];
  const position = parseMomentPosition(params.get("t") ?? legacy?.[2] ?? undefined);
  if (!roundText || !/^\d{1,2}$/.test(roundText) || !position) return null;
  const roundNo = Number(roundText);
  return roundNo >= 1 && roundNo <= 14 ? { roundNo, position } : null;
}
function requestedSpeed(): 1 | 4 | 16 {
  const value = new URLSearchParams(location.search).get("speed");
  return value === "4" || value === "16" ? Number(value) as 4 | 16 : 1;
}
function roundEvents(events: ArenaEvent[], round: RoundIndex): ArenaEvent[] {
  return events.filter((event) => (event.round_id === round.round_id && event.seq >= round.first_seq) ||
    (event.round_id === null && event.seq >= round.first_seq &&
      (round.last_seq === null || event.seq <= round.last_seq)));
}
function liveRoundEvents(events: ArenaEvent[], round: RoundIndex): ArenaEvent[] {
  if (round.last_seq === null) return roundEvents(events, round);
  return events.filter((event) => (event.round_id === round.round_id && event.seq >= round.first_seq) ||
    (event.round_id === null && event.seq >= round.first_seq));
}
function momentPath(roundNo: number, seconds: number, archive: boolean): string {
  return archive ? `/?round=${roundNo}&t=${seconds}` : `/rodada/${roundNo}?t=${seconds}`;
}
function RoundStory({ event, onSelectRef, presentation }: { event: ArenaEvent | undefined;
  onSelectRef: (seq: number) => void; presentation: boolean }) {
  if (!event || typeof event.public.summary_pt !== "string" ||
    !Array.isArray(event.public.chapters)) return null;
  if (presentation) return <article className="round-story"><small>RESUMO DA RODADA</small>
    <h2>Rodada concluída</h2><p>Os acontecimentos observados estão na linha do tempo.</p></article>;
  const chapters = event.public.chapters as { title_pt: string; body_pt: string; refs: number[] }[];
  return <article className="round-story"><small>RESUMO DA RODADA</small>
    <h2>{String(event.public.headline_pt ?? event.public.text_pt)}</h2>
    <p>{event.public.summary_pt}</p><div className="story-chapters">{chapters.map((chapter, index) =>
      <section key={`${chapter.title_pt}-${index}`}><h3>{chapter.title_pt}</h3>
        <p>{chapter.body_pt}</p><div>{chapter.refs.map((seq) =>
          <button key={seq} onClick={() => onSelectRef(seq)}>Ver evento {seq} ↗</button>)}</div>
      </section>)}</div><p className="story-takeaway">{String(event.public.takeaway_for_banks_pt ?? "")}</p>
  </article>;
}
interface LaunchSummary {
  played: number; breaches: number; resolved: number; loss: number; restored: number;
  regressionTests: number; rejections: number; features: number; latestHealth: number;
  mttd: number | null; mttr: number | null; lastFeature: ArenaEvent | null;
}
function IdleSinceLaunch({ stats, onArea, presentation }: {
  stats: LaunchSummary; onArea: (area: Area) => void; presentation: boolean;
}) {
  const feature = stats.lastFeature;
  const featureArea = feature?.public.area;
  return <div className="idle-since-launch"><div className="idle-panel-heading"><small>DESDE O LANÇAMENTO</small>
      <span>Dados públicos confirmados</span></div>
    <div className="idle-summary-grid">
      <div><span>Rodadas realizadas</span><strong>{stats.played}</strong></div>
      <div><span>Invasões confirmadas</span><strong>{stats.breaches}</strong></div>
      <div><span>Incidentes resolvidos</span><strong>{stats.resolved}</strong></div>
      <div><span>Impacto / restaurado</span><strong>{presentation ? "Valor reservado" : money(stats.loss)} <em>/ {presentation ? "Valor reservado" : money(stats.restored)}</em></strong></div>
      <div><span>Testes de regressão</span><strong>{stats.regressionTests}</strong></div>
      <div><span>Rejeições / recursos</span><strong>{stats.rejections} <em>/ {stats.features}</em></strong></div>
      <div><span>TTD / TTC / TTM</span><strong>{stats.mttd === null ? "—" : `${stats.mttd}s`} <em>/ — / {stats.mttr === null ? "—" : `${stats.mttr}s`}</em></strong></div>
      <div><span>Saúde inicial / atual</span><strong>100 <em>→ {Math.round(stats.latestHealth)}</em></strong></div>
    </div>
    {feature && <div className="idle-feature"><small>ÚLTIMO RECURSO LANÇADO</small>
      <strong>{presentation ? "Nova proteção" : String(feature.public.name_pt)}</strong><p>{presentation ? "Recurso lançado e registrado" : String(feature.public.summary_pt)}</p>
      <span>Construído em {clock(feature.ts)} · {LABEL[featureArea as Area] ?? "Banco"}</span>
      {AREAS.includes(featureArea as Area) && <button onClick={() => onArea(featureArea as Area)}>Ver sala ↗</button>}
    </div>}
  </div>;
}
function SocMetricsPanel({ metrics, presentation }: { metrics: SocMetrics | null; presentation: boolean }) {
  if (!metrics) return <p className="soc-page-unavailable">Calculando métricas do SOC…</p>;
  const duration = (value: number | null) => value === null ? "—" : `${value}s`;
  return <section aria-label="Métricas do SOC"><div className="soc-page-heading">
    <small>RESPOSTA COM EVIDÊNCIA</small><h2>Métricas do SOC</h2>
    <p>Tempos médios consideram apenas ataques com eventos vinculados ao incidente.</p></div>
    <div className="score-grid soc-metrics-grid">
      <article><small>DETECÇÃO / AÇÃO / CONTENÇÃO</small><strong>{duration(metrics.mttdSeconds)} / {duration(metrics.mttaSeconds)} / {duration(metrics.mttcSeconds)}</strong><span>MTTD · MTTA · MTTC</span></article>
      <article><small>CORREÇÃO / RECUPERAÇÃO</small><strong>{duration(metrics.mttrFixSeconds)} / {duration(metrics.mttrRecoverySeconds)}</strong><span>MTTR fix · MTTR recovery</span></article>
      <article><small>ATAQUES CONCLUÍDOS</small><strong>{metrics.blockedInlinePct}% / {metrics.detectedAfterPct}% / {metrics.undetectedPct}%</strong><span>barrados inline · detectados depois · sem detecção</span><span>{metrics.unclassifiedPct}% sem classificação de bloqueio · {metrics.pending} em andamento</span></article>
      <article><small>IMPACTO</small><strong>{presentation ? "Valor reservado" : money(metrics.lossCents)}</strong><span>perda observada</span></article>
      <article><small>RECUPERADO / ABSORVIDO</small><strong>{presentation ? "Valores reservados" : `${money(metrics.recoveredCents)} / ${money(metrics.absorbedCents)}`}</strong><span>valores internos e externos recuperados · perda líquida do banco</span><span>{presentation ? "Valor reservado" : money(metrics.bankReimbursedCents)} devolvidos ao banco após ressarcimento</span></article>
      <article><small>FALSO BLOQUEIO / REJEIÇÕES / ROLLBACKS</small><strong>{metrics.honestFalseBlocks} / {metrics.reviewRejections} / {metrics.rollbacks}</strong><span>contagens observadas</span></article>
    </div></section>;
}
const THUMB_COLOR: Record<string, string> = {
  normal: "#4DA3FF", probed: "#FFB84D", under_attack: "#FF5A5F", breached: "#FF5A5F",
  contained: "#4DA3FF", patching: "#4DA3FF", quarantined: "#B79BFF", hardened: "#3DDC97",
};
function RoundThumbnail({ state }: { state: WorldState | null }) {
  return <svg className="history-thumb" viewBox="0 0 240 150" role="img"
    aria-label={state ? "Mapa final da rodada" : "Mapa final ainda não carregado"}>
    <rect width="240" height="150" fill="#0B1220"/>
    <path d="M120 8V139 M15 75H225" stroke="#F6E7C1" strokeOpacity=".16" strokeWidth="4"/>
    {ROOMS.map((room) => <g key={room.area}>
      <rect x={8 + room.x * .14} y={5 + room.y * .14} width={room.w * .14}
        height={room.h * .14} rx="3" fill="#13213A"
        stroke={state ? THUMB_COLOR[state.area_states[room.area]] : "#405472"}/>
      <text x={12 + room.x * .14} y={18 + room.y * .14} fill="#D8E4F5"
        fontSize="6" fontWeight="700">{LABEL[room.area].toUpperCase()}</text>
      {state && <text x={12 + room.x * .14} y={30 + room.y * .14}
        fill={THUMB_COLOR[state.area_states[room.area]]} fontSize="9" fontWeight="700">
        {Math.round(state.health.areas[room.area])}</text>}
    </g>)}
  </svg>;
}
function HistoryPage({ rounds, frames, opening, low, stats, onOpen, onDemo, source,
  roundMode, presentation }: {
  rounds: RoundIndex[]; frames: Map<string, WorldState>; opening: Map<string, WorldState>;
  low: Map<string, number>;
  stats: Map<string, { events: number; attacks: number; loss: number; restored: number;
    agents: number; rejections: number; usageTokens: number | null; date: string | null }>;
  onOpen: (round: RoundIndex) => void;
  onDemo: () => void; source: "loading" | "demo" | "live" | "archive";
  roundMode: "none" | "scheduled" | "manual" | "continuous"; presentation: boolean;
}) {
  const played = new Set(rounds.map((round) => round.round_no));
  if (!rounds.length && source === "demo") played.add(7);
  const latestRoundNo = Math.max(0, ...played);
  const upcoming = Array.from({ length: source === "live" &&
    (roundMode === "manual" || roundMode === "continuous") ?
    Math.min(1, 14 - latestRoundNo) : 14 - latestRoundNo },
    (_, index) => latestRoundNo + index + 1);
  return <main className="page history-page"><small>ARQUIVO DE RODADAS</small><h1>Histórico</h1>
    <p>Reproduza decisões, falhas, correções e seus efeitos no banco.</p>
    {rounds.length > 0 && <HealthTrend rounds={rounds} frames={frames} opening={opening} low={low} onOpen={onOpen}/>}
    <div className="history-grid">{[...rounds].sort((left, right) => right.round_no - left.round_no).map((round) => {
      const frame = frames.get(round.round_id) ?? null;
      const previousRound = rounds.find((item) => item.round_no === round.round_no - 1);
      const before = opening.get(round.round_id)?.health.overall ??
        (previousRound ? frames.get(previousRound.round_id)?.health.overall :
          round.round_no === 1 ? 100 : undefined);
      const amounts = stats.get(round.round_id);
      const attacks = amounts?.attacks ?? round.score?.attacks_succeeded;
      const loss = amounts?.loss ?? round.score?.loss_cents;
      const restored = amounts?.restored ?? round.score?.restored_cents;
      return <button key={round.round_id} className="history-tile" onClick={() => onOpen(round)}>
        <RoundThumbnail state={frame}/><span className="history-tile-head"><strong>Rodada {String(round.round_no).padStart(2, "0")}</strong>
          <em>{round.status === "started" ? "AO VIVO" : "ARQUIVO"}</em></span>
        <span className="history-tile-title">{presentation ? round.status === "started" ? "Em andamento" : "Concluída" : round.headline_pt ?? (round.status === "started" ? "Em andamento" : "Concluída")}</span>
        <span className="history-tile-stats">{amounts?.events ?? round.event_count} eventos
          {attacks !== undefined && <> · {attacks} {attacks === 1 ? "invasão" : "invasões"}</>}
          {frame && <> · saúde {before === undefined ? "" : `${Math.round(before)} → `}{Math.round(frame.health.overall)}</>}</span>
        {amounts?.date && <span className="history-tile-meta">{amounts.date}</span>}
        {loss !== undefined && <span className="history-tile-money">{presentation ? "Valor reservado" : money(loss)} extraídos
          {restored !== undefined && restored > 0 && <> · {presentation ? "Valor reservado" : money(restored)} devolvidos a clientes</>}</span>}
        {amounts && <span className="history-tile-meta">{amounts.agents} {amounts.agents === 1 ? "agente" : "agentes"} · {amounts.rejections} {amounts.rejections === 1 ? "rejeição" : "rejeições"}
          {amounts.usageTokens !== null && <> · {amounts.usageTokens.toLocaleString("pt-BR")} tokens</>}</span>}
        {round.score && <span className="history-tile-meta">MTTD {metricSeconds(round.score.mttd_s)} · MTTC {metricSeconds(round.score.mttc_s)} · MTTR correção {metricSeconds(round.score.mttr_s)}</span>}
        <span className="history-tile-cta">ABRIR MAPA ↗</span>
      </button>;
    })}{!rounds.length && source === "demo" && <button className="history-tile" onClick={onDemo}>
      <RoundThumbnail state={null}/><span className="history-tile-head"><strong>Rodada 07</strong><em>DEMONSTRAÇÃO</em></span>
      <span className="history-tile-title">Roteiro demonstrativo</span><span className="history-tile-cta">REPRODUZIR ↗</span>
    </button>}{upcoming.map((number) => <article key={`upcoming-${number}`} className="history-tile future"
      aria-label={`Rodada ${number} ainda não realizada`}><RoundThumbnail state={null}/>
      <span className="history-tile-head"><strong>Rodada {String(number).padStart(2, "0")}</strong><em>EM BREVE</em></span>
      <span className="history-tile-title">{source === "live" && roundMode === "manual" ?
        "Próxima rodada sob demanda" : source === "live" && roundMode === "continuous" ?
          "Próxima rodada automática" : "Aguardando a próxima sessão"}</span></article>)}</div>
  </main>;
}
function HealthTrend({ rounds, frames, opening, low, onOpen }: {
  rounds: RoundIndex[]; frames: Map<string, WorldState>; opening: Map<string, WorldState>;
  low: Map<string, number>; onOpen: (round: RoundIndex) => void;
}) {
  const [showTable, setShowTable] = useState(false);
  const [focusedArea, setFocusedArea] = useState<Area | null>(null);
  const points = rounds.filter((round) => frames.has(round.round_id))
    .sort((left, right) => left.round_no - right.round_no)
    .map((round) => ({ round, health: frames.get(round.round_id)!.health.overall,
      areas: frames.get(round.round_id)!.health.areas,
      before: opening.get(round.round_id)?.health.overall, minimum: low.get(round.round_id) }));
  const x = (roundNo: number) => 42 + (roundNo - 1) * 48;
  const y = (health: number) => 206 - Math.max(0, Math.min(100, health)) * 1.7;
  const last = points.at(-1);
  const labelY = new Map<Area, number>(last ? [...AREAS].sort((left, right) =>
    last.areas[right] - last.areas[left]).map((area, index): [Area, number] => [area, 46 + index * 23]) : []);
  const labelX = last ? Math.min(685, x(last.round.round_no) + 28) : 685;
  const trend = points.length > 1 ? (() => {
    const meanX = points.reduce((sum, point) => sum + point.round.round_no, 0) / points.length;
    const meanY = points.reduce((sum, point) => sum + point.health, 0) / points.length;
    const numerator = points.reduce((sum, point) =>
      sum + (point.round.round_no - meanX) * (point.health - meanY), 0);
    const denominator = points.reduce((sum, point) =>
      sum + (point.round.round_no - meanX) ** 2, 0);
    const slope = denominator ? numerator / denominator : 0;
    return { at: (roundNo: number) => meanY + slope * (roundNo - meanX) };
  })() : null;
  return <section className="health-trend" aria-label="Evolução da saúde do banco">
    <div className="health-trend-heading"><div><small>EVOLUÇÃO</small><h2>O banco fica mais forte</h2>
      <p>Saúde de 0 a 100. A linha clara mostra o banco; as outras mostram as sete áreas.</p></div>
      <button onClick={() => setShowTable((value) => !value)} aria-pressed={showTable}>
        {showTable ? "Ver gráfico" : "Ver tabela"}</button></div>
    {showTable ? <div className="health-table-wrap"><table><thead><tr><th>Rodada</th><th>Antes</th>
      <th>Mínima</th><th>Depois</th>{AREAS.map((area) => <th key={area}>{LABEL[area]}</th>)}
      <th>Estado</th></tr></thead><tbody>{rounds.map((round) => <tr key={round.round_id}>
        <th scope="row">{String(round.round_no).padStart(2, "0")}</th>
        <td>{opening.has(round.round_id) ? Math.round(opening.get(round.round_id)!.health.overall) : "—"}</td>
        <td>{low.has(round.round_id) ? Math.round(low.get(round.round_id)!) : "—"}</td>
        <td>{frames.has(round.round_id) ? Math.round(frames.get(round.round_id)!.health.overall) : "—"}</td>
        {AREAS.map((area) => <td key={area}>{frames.has(round.round_id) ?
          Math.round(frames.get(round.round_id)!.health.areas[area]) : "—"}</td>)}
        <td>{round.status === "started" ? "Em andamento" : "Encerrada"}</td>
      </tr>)}</tbody></table></div> : <div className="health-chart-wrap"><svg viewBox="0 0 800 244"
      role="group" aria-label={points.length ? `Saúde geral: ${points.map(({ round, health, before, minimum }) =>
        `rodada ${round.round_no}, antes ${before === undefined ? "sem registro" : Math.round(before)}, mínima ${minimum === undefined ? "sem registro" : Math.round(minimum)}, depois ${Math.round(health)}`).join("; ")}` : "Aguardando dados de saúde das rodadas"}>
      {[0, 25, 50, 75, 100].map((value) => <g key={value}><line x1="42" x2="666"
        y1={y(value)} y2={y(value)} stroke="#34445F" strokeOpacity=".55"/>
        <text x="32" y={y(value) + 4} textAnchor="end" fill="#8FA2C4" fontSize="11">{value}</text></g>)}
      {Array.from({ length: 14 }, (_, index) => <g key={index}><text x={x(index + 1)} y="232"
        textAnchor="middle" fill="#8FA2C4" fontSize="11">{index + 1}</text></g>)}
      {points.length > 1 && <polygon fill="#EAF0FB" fillOpacity=".035"
        points={`${points.map(({ round, health }) => `${x(round.round_no)},${y(health)}`).join(" ")} ${x(last!.round.round_no)},206 ${x(points[0]!.round.round_no)},206`}/>}
      {trend && <line x1={x(points[0]!.round.round_no)} y1={y(trend.at(points[0]!.round.round_no))}
        x2={x(last!.round.round_no)} y2={y(trend.at(last!.round.round_no))}
        stroke="#EAF0FB" strokeOpacity=".4" strokeWidth="1.5" strokeDasharray="4 5"/>}
      {AREAS.map((area) => <g key={area}>
        {points.length > 1 && <polyline fill="none" stroke="#7F9CCB"
          strokeOpacity={focusedArea === null ? ".25" : focusedArea === area ? ".95" : ".06"}
          strokeWidth={focusedArea === area ? "2.5" : "1.5"}
          points={points.map(({ round, areas }) => `${x(round.round_no)},${y(areas[area])}`).join(" ")}
          onMouseEnter={() => setFocusedArea(area)} onMouseLeave={() => setFocusedArea(null)}/>}
        {last && <g className="health-area-label" role="button" tabIndex={0}
          aria-label={`${LABEL[area]}: saúde ${Math.round(last.areas[area])}; destacar curva`}
          aria-pressed={focusedArea === area}
          onFocus={() => setFocusedArea(area)} onBlur={() => setFocusedArea(null)}
          onMouseEnter={() => setFocusedArea(area)} onMouseLeave={() => setFocusedArea(null)}
          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setFocusedArea(area); } }}>
          <line x1={x(last.round.round_no)} y1={y(last.areas[area])}
            x2={labelX - 5} y2={labelY.get(area)!} stroke="#7F9CCB"
            strokeOpacity={focusedArea === null ? ".25" : focusedArea === area ? ".95" : ".06"}/>
          <circle cx={x(last.round.round_no)} cy={y(last.areas[area])} r="3"
            fill={focusedArea === area ? "#4DA3FF" : "#7F9CCB"}/>
          <text x={labelX} y={labelY.get(area)! + 4} fill={focusedArea === area ? "#EAF0FB" : "#8FA2C4"}
            fontSize="10">{LABEL[area]} {Math.round(last.areas[area])}</text>
        </g>}
      </g>)}
      {points.length > 1 && <polyline fill="none" stroke="#EAF0FB" strokeWidth="2.5"
        points={points.map(({ round, health }) => `${x(round.round_no)},${y(health)}`).join(" ")}/>}
      {points.map(({ round, health, before, minimum }) => before !== undefined && minimum !== undefined ?
        <g key={`${round.round_id}-trajectory`} aria-hidden="true">
          {minimum < before && <line x1={x(round.round_no) - 14} y1={y(before)}
            x2={x(round.round_no)} y2={y(minimum)} stroke="#FF5A5F" strokeWidth="2"/>}
          {health > minimum && <line x1={x(round.round_no)} y1={y(minimum)}
            x2={x(round.round_no) + 14} y2={y(health)} stroke="#3DDC97" strokeWidth="2"/>}
        </g> : null)}
      {points.map(({ round, health }) => <g key={round.round_id} onClick={() => onOpen(round)}
        className="health-chart-point" role="button" tabIndex={0}
        onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onOpen(round); } }}
        aria-label={`Abrir rodada ${round.round_no}, saúde ${Math.round(health)}`}>
        <circle cx={x(round.round_no)} cy={y(health)} r="12" fill="transparent"/>
        <circle cx={x(round.round_no)} cy={y(health)} r="5" fill="#EAF0FB"/>
        <text x={x(round.round_no)} y={y(health) - 13} textAnchor="middle" fill="#EAF0FB"
          fontSize="12" fontWeight="700">{Math.round(health)}</text></g>)}
      {last && <text x="678" y="20" fill="#EAF0FB" fontSize="10" fontWeight="700">
        SAÚDE GERAL {Math.round(last.health)}</text>}
    </svg></div>}
    {!points.length && <p className="health-trend-empty">Os dados aparecem após o primeiro registro de saúde.</p>}
  </section>;
}
function AreaHeatmap({ rounds, frames, onOpen }: {
  rounds: RoundIndex[]; frames: Map<string, WorldState>; onOpen: (round: RoundIndex) => void;
}) {
  const byNumber = new Map(rounds.map((round) => [round.round_no, round]));
  return <section className="area-heatmap"><small>SAÚDE POR ÁREA</small><h2>Onde o banco mudou</h2>
    <p>Cada célula mostra a saúde registrada ao fim da rodada. Selecione uma para abrir o mapa.</p>
    <div className="area-heatmap-scroll"><table><thead><tr><th scope="col">Área</th>
      {Array.from({ length: 14 }, (_, index) => <th scope="col" key={index}>{String(index + 1).padStart(2, "0")}</th>)}
    </tr></thead><tbody>{AREAS.map((area) => <tr key={area}><th scope="row">{LABEL[area]}</th>
      {Array.from({ length: 14 }, (_, index) => {
        const round = byNumber.get(index + 1);
        const frame = round && frames.get(round.round_id);
        const health = frame?.health.areas[area];
        return <td key={index}>{round && health !== undefined ? <button
          className={`area-heat-cell ${health >= 90 ? "good" : health >= 70 ? "mid" : "low"}`}
          onClick={() => onOpen(round)} title={`${LABEL[area]} · rodada ${round.round_no} · saúde ${Math.round(health)}`}
          aria-label={`${LABEL[area]}, rodada ${round.round_no}, saúde ${Math.round(health)}; abrir mapa`}>{Math.round(health)}</button>
          : <span aria-label={`Rodada ${index + 1} sem dados`}>—</span>}</td>;
      })}</tr>)}</tbody></table></div>
  </section>;
}
function bestMoment(events: ArenaEvent[]): number {
  let best = { index: -1, weight: -1 };
  for (const [index, event] of events.entries()) {
    if (event.type !== "attack.succeeded" && event.type !== "attack.failed") continue;
    const later = events.slice(index + 1).filter((item) => item.area === event.area);
    const weight = event.type === "attack.failed" ? 0 :
      later.some((item) => item.type === "review.rejected") &&
      later.some((item) => item.type === "damage.restored") ? 3 :
      later.some((item) => item.type === "deploy.succeeded") ? 2 : 1;
    if (weight > best.weight) best = { index, weight };
  }
  return best.index < 0 ? 0 : Math.max(0, best.index - 3);
}
function highlightCursors(events: ArenaEvent[]): number[] {
  const chapters = ["attack.succeeded", "sentinel.alert", "review.rejected",
    "deploy.succeeded", "damage.restored", "postmortem.published"];
  const positions = chapters.map((type) => events.findIndex((event) => event.type === type) + 1)
    .filter((position) => position > 0);
  return positions.length ? [...new Set(positions)].sort((left, right) => left - right) :
    events.length ? [events.length] : [];
}
async function getRoundEvents(round: RoundIndex, latestSeq: number): Promise<RoundHistory> {
  const all: ArenaEvent[] = []; let after = round.first_seq - 1;
  const end = round.last_seq ?? latestSeq;
  for (let page = 0; page < 200; page++) {
    const response = await fetch(`/api/events?after=${after}&before=${end + 1}&limit=500`);
    if (!response.ok) throw new Error("History unavailable");
    const payload = await response.json() as { events: unknown[]; next_after: number; has_more: boolean };
    const batch = payload.events.map(parseEvent); all.push(...batch);
    if (!payload.has_more || payload.next_after >= end) break;
    after = payload.next_after;
  }
  if (round.last_seq !== null && round.last_seq < latestSeq) {
    let lateAfter = round.last_seq;
    for (let page = 0; page < 200; page++) {
      const response = await fetch(`/api/events?round=${encodeURIComponent(round.round_id)}` +
        `&after=${lateAfter}&limit=500`);
      if (!response.ok) throw new Error("Late round history unavailable");
      const payload = await response.json() as { events: unknown[]; next_after: number; has_more: boolean };
      all.push(...payload.events.map(parseEvent));
      if (!payload.has_more || payload.next_after <= lateAfter) break;
      lateAfter = payload.next_after;
    }
  }
  const frameResponse = await fetch(`/api/keyframe?seq=${round.first_seq}`);
  const frame = frameResponse.ok ? await frameResponse.json() as {
    seq: number; reducer_version: number; state: WorldState } : null;
  return { events: all, keyframe: frame?.seq === round.first_seq && frame.reducer_version === REDUCER_VERSION
    ? frame.state : null };
}
async function getDemo(): Promise<ArenaEvent[]> {
  const response = await fetch("/demo.jsonl"); if (!response.ok) throw new Error("Demo unavailable");
  return (await response.text()).trim().split("\n").map((line) => publicView(parseEvent(JSON.parse(line))));
}
async function getStaticReplay(): Promise<{ rounds: RoundIndex[]; events: ArenaEvent[] }> {
  const manifest = await fetch("/static-replay.json");
  if (!manifest.ok) throw new Error("Static replay unavailable");
  const data = await manifest.json() as { version: number; rounds: RoundIndex[] };
  if (data.version !== 1 || !Array.isArray(data.rounds)) throw new Error("Static replay invalid");
  const response = await fetch("/events.jsonl");
  if (!response.ok) throw new Error("Static events unavailable");
  const raw = (await response.text()).trim();
  return { rounds: data.rounds,
    events: raw ? raw.split("\n").map((line) => parseEvent(JSON.parse(line))) : [] };
}
async function getRounds(): Promise<RoundIndex[]> {
  const response = await fetch("/api/rounds");
  if (!response.ok) throw new Error("Round index unavailable");
  const payload = await response.json() as { rounds: RoundIndex[] };
  return payload.rounds;
}
async function getLaunchSummary(): Promise<LaunchSummary> {
  const response = await fetch("/api/launch-summary");
  if (!response.ok) throw new Error("Launch summary unavailable");
  return response.json() as Promise<LaunchSummary>;
}
async function getSocMetrics(): Promise<SocMetrics> {
  const response = await fetch("/api/soc/metrics");
  if (!response.ok) throw new Error("SOC metrics unavailable");
  return response.json() as Promise<SocMetrics>;
}
async function getEventsAfter(afterSeq: number, latestSeq: number): Promise<ArenaEvent[]> {
  const result: ArenaEvent[] = [];
  let after = afterSeq;
  while (after < latestSeq) {
    const response = await fetch(`/api/events?after=${after}&before=${latestSeq + 1}&limit=500`);
    if (!response.ok) throw new Error("Recent events unavailable");
    const payload = await response.json() as { events: unknown[]; next_after: number; has_more: boolean };
    result.push(...payload.events.map(parseEvent));
    if (!payload.has_more || payload.next_after <= after) break;
    after = payload.next_after;
  }
  return result;
}
function Room({ room, state, selected, onClick }: { room: typeof ROOMS[number]; state: WorldState; selected: boolean; onClick: () => void }) {
  const mode = state.area_states[room.area]; const health = state.health.areas[room.area].toFixed(0);
  const partWidth = room.w > 400 ? 118 : 102;
  return <g className={`room ${mode}${selected ? " selected" : ""}`} onClick={onClick} role="button" tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onClick(); } }} aria-label={`${LABEL[room.area]}: ${mode}`}>
    <rect className="room-fill" x={room.x} y={room.y} width={room.w} height={room.h}/><rect className="room-wall" x={room.x} y={room.y} width={room.w} height={room.h}/><rect className="room-wall inner" x={room.x + 5} y={room.y + 5} width={room.w - 10} height={room.h - 10}/>
    <path className="room-door" d={`M ${room.x + room.w / 2 - 23} ${room.y + room.h} h 46 a 46 46 0 0 0 -46 -46`}/>
    <circle className="sentinel-ring" cx={room.x + 27} cy={room.y + 29} r="10"/><path className="sentinel-arc" d={`M ${room.x + 27} ${room.y + 19} a 10 10 0 0 1 10 10`}/>
    <text className="room-name" x={room.x + 48} y={room.y + 36}>{LABEL[room.area].toUpperCase()}</text><text className="room-health" textAnchor="end" x={room.x + room.w - 24} y={room.y + 36}>{health}</text>
    <text className="room-status" x={room.x + 25} y={room.y + 75}>{mode.replaceAll("_", " ").toUpperCase()}</text>
    <g className="room-parts">{room.parts.map((part, index) => { const x = room.x + 42 + (index % 2) * (room.w / 2); const y = room.y + 105 + Math.floor(index / 2) * 65; return <g key={part}><rect className="component" x={x} y={y} width={partWidth} height="38"/><path className="component-lines" d={`M${x + 15} ${y + 13}h${partWidth - 30} M${x + 15} ${y + 22}h${partWidth / 3}`}/><text className="component-label" x={x + partWidth / 2} y={y + 52} textAnchor="middle">{part}</text></g>; })}</g>
    {state.scars[room.area] > 0 && <text className="scar" x={room.x + 22} y={room.y + room.h - 22}>◇ ×{state.scars[room.area]}</text>}
    {mode === "quarantined" && <text className="quarantine" x={room.x + room.w / 2} y={room.y + room.h / 2} textAnchor="middle">QUARENTENA</text>}
  </g>;
}
const AGENT_ANCHORS: Record<Area, [number, number]> = {
  auth: [310, 365], accounts: [310, 625], pix: [800, 365], cards: [1290, 365],
  loans: [1290, 625], api_gateway: [800, 100], ledger: [800, 715],
};
function AgentNodes({ agents }: { agents: WorldState["agents"] }) {
  const counts = new Map<Area, number>();
  const nodes = Object.entries(agents).slice(-25).map(([id, agent]) => {
    const area = agent.area ?? "api_gateway";
    const position = counts.get(area) ?? 0;
    counts.set(area, position + 1);
    const [baseX, baseY] = AGENT_ANCHORS[area];
    const x = baseX + (position % 5 - 2) * 27;
    const y = baseY + Math.floor(position / 5) * 27;
    const red = ["historian", "scout", "intruder", "exploiter"].includes(agent.role);
    return <g key={id} className={`agent-node ${red ? "red" : "blue"}${agent.outcome ? " finished" : ""}`}
      transform={`translate(${x} ${y})`} aria-hidden="true">
      <circle className="agent-halo" r="14"/><circle className="agent-core" r="10"/>
      <text textAnchor="middle" dominantBaseline="central">{agent.role[0]?.toUpperCase()}</text>
    </g>;
  });
  return <g className="agent-nodes">{nodes}</g>;
}
function EventTrace({ event }: { event: ArenaEvent | undefined }) {
  if (!event) return null;
  const area = event.area ?? event.public.area;
  if (typeof area !== "string" || !AREAS.includes(area as Area)) return null;
  const room = ROOMS.find((item) => item.area === area);
  const x = room ? room.x + room.w / 2 : 800;
  const y = room ? room.y + room.h / 2 : 100;
  const kind = event.type.startsWith("attack.") || event.type === "impact.caused" ? "attack" :
    event.type === "sentinel.alert" || event.type === "containment.applied" ? "defense" :
    event.type === "deploy.succeeded" ? "seal" :
    event.type === "deploy.rolled_back" ? "rollback" :
    event.type === "damage.restored" ? "restore" : null;
  if (!kind) return null;
  return <g key={event.seq} className={`event-trace ${kind}`} aria-hidden="true">
    {kind === "attack" && <path d={`M800 50 L${x} ${y}`}/>}
    {kind === "defense" && <path d={`M${x} ${y} L1550 500`}/>}
    {kind === "restore" && <path d={`M${x} ${y} L800 550`}/>}
    {(kind === "seal" || kind === "rollback") && <circle cx={x} cy={y} r="72"/>}
    {kind === "rollback" && <path d={`M${x - 35} ${y - 35} l70 70 m0 -70 l-70 70`}/>}
  </g>;
}
const FLOW_PATHS: { from: [number, number]; to: [number, number]; area: Area }[] = [
  { from: [800, 50], to: [800, 350], area: "auth" },
  { from: [500, 235], to: [1100, 235], area: "pix" },
  { from: [310, 350], to: [310, 640], area: "accounts" },
  { from: [1290, 350], to: [1290, 640], area: "cards" },
  { from: [800, 350], to: [800, 740], area: "ledger" },
  { from: [500, 755], to: [1100, 755], area: "loans" },
];
function AmbientFlow({ state, speed }: { state: WorldState; speed: 1 | 4 | 16 }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const current = useRef({ state, speed });
  current.current = { state, speed };
  useEffect(() => {
    const element = canvas.current;
    const context = element?.getContext("2d");
    if (!element || !context) return;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let width = 0; let height = 0; let frame = 0;
    let lastFrame = 0; let windowStart = 0; let sampled = 0; let slow = 0; let level = 0;
    const resize = () => {
      const rect = element.getBoundingClientRect();
      width = rect.width; height = rect.height;
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      element.width = Math.round(width * ratio); element.height = Math.round(height * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    const observer = new ResizeObserver(resize);
    observer.observe(element); resize();
    const draw = (now: number) => {
      frame = window.requestAnimationFrame(draw);
      if (!width || !height || window.innerWidth < 768 || reducedMotion.matches || document.hidden) return;
      if (lastFrame) { sampled++; if (now - lastFrame > 22) slow++; }
      lastFrame = now;
      if (!windowStart) windowStart = now;
      if (now - windowStart >= 3000) {
        if (sampled >= 30 && slow / sampled > 0.05) level = Math.min(level + 1, 4);
        else if (sampled >= 30 && slow === 0) level = Math.max(level - 1, 0);
        windowStart = now; sampled = 0; slow = 0;
      }
      context.clearRect(0, 0, width, height);
      const baseCount = current.current.speed === 16 ? 42 : 140;
      const count = Math.floor(baseCount * [1, 0.5, 0.25, 0.1, 0][level]!);
      const scale = Math.min(width / 1600, height / 1000);
      const offsetX = (width - scale * 1600) / 2;
      const offsetY = (height - scale * 1000) / 2;
      for (let index = 0; index < count; index++) {
        const path = FLOW_PATHS[index % FLOW_PATHS.length]!;
        const progress = (now * (0.000018 + index % 7 * 0.000004) + index * 0.618034) % 1;
        const x = offsetX + (path.from[0] + (path.to[0] - path.from[0]) * progress) * scale;
        const y = offsetY + (path.from[1] + (path.to[1] - path.from[1]) * progress) * scale;
        const mode = current.current.state.area_states[path.area];
        context.fillStyle = mode === "breached" || mode === "under_attack" ? "#FF5A5F" :
          mode === "hardened" ? "#3DDC97" : "#8FA2C4";
        context.globalAlpha = 0.25 + (index % 5) * 0.08;
        context.beginPath(); context.arc(x, y, Math.max(1, scale * (2 + index % 3)), 0, Math.PI * 2);
        context.fill();
      }
      context.globalAlpha = 1;
    };
    frame = window.requestAnimationFrame(draw);
    return () => { window.cancelAnimationFrame(frame); observer.disconnect(); };
  }, []);
  return <canvas ref={canvas} className="ambient-flow" aria-hidden="true"/>;
}
function BankMap({ state, selected, onSelect, heat, roundNo, speed, idle, event, presentation }: { state: WorldState; selected: Area | null; onSelect: (area: Area) => void; heat: boolean; roundNo: number | null; speed: 1 | 4 | 16; presentation: boolean;
  idle?: { countdown: string; progress: number; nextRoundNo: number; slot: string } | undefined;
  event?: ArenaEvent | undefined }) {
  return <div className={`map-wrap${heat ? " heat" : ""}`}><div className="map-header"><span>◈ PLANTA OPERACIONAL</span><span>07 ÁREAS · {Object.keys(state.features).length} NOVO(S)</span></div><div className="map-viewport"><AmbientFlow state={state} speed={speed}/><svg viewBox="0 0 1600 1000" role="img" aria-label="Planta do Banco Jacarandá com sete áreas">
    <defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M 40 0 H 0 V 40" fill="none" stroke="#4C6A9E" strokeOpacity=".16"/></pattern><pattern id="hatch" width="10" height="10" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><path d="M 0 0 V 10" stroke="#FF5A5F" strokeOpacity=".28" strokeWidth="2"/></pattern></defs>
    <rect width="1600" height="1000" fill="#0B1220"/><rect width="1600" height="1000" fill="url(#grid)"/><path className="dimension" d="M 40 25 H 1560 M 25 40 V 960 M 40 975 H 1560"/><text className="dimension-label" x="800" y="18" textAnchor="middle">1520 U · PERÍMETRO PROTEGIDO</text>
    <path className="corridor" d="M800 45 V120 M800 350 V400 M500 235 H560 M1040 235 H1100 M310 350 V640 M1290 350 V640 M500 755 H560 M1040 755 H1100 M800 700 V740"/>
    <rect className="perimeter" x="42" y="42" width="1516" height="916"/><rect className="perimeter-inner" x="49" y="49" width="1502" height="902"/>
    <text className="gate" x="800" y="88" textAnchor="middle">WEB</text><text className="gate" x="1516" y="500" textAnchor="end">APP</text><text className="gate" x="800" y="925" textAnchor="middle">OPEN FINANCE</text><text className="gate" x="75" y="500">PARCEIROS</text>
    {ROOMS.map((room) => <Room key={room.area} room={room} state={state} selected={room.area === selected} onClick={() => onSelect(room.area)}/>)}
    <AgentNodes agents={state.agents}/>
    <EventTrace event={event}/>
    <g className="vault"><circle cx="800" cy="550" r="60"/><circle cx="800" cy="550" r="45"/><path d="M800 512V588 M762 550H838 M773 523L827 577 M827 523L773 577"/><circle cx="800" cy="550" r="12"/></g>
    <g className="lab"><rect x="560" y="740" width="480" height="165"/><text x="584" y="773">LABORATÓRIO · NOVOS RECURSOS</text>{Object.values(state.features).slice(0, 7).map((feature, index) => <g key={index}><rect x={584 + index % 3 * 145} y={790 + Math.floor(index / 3) * 37} width="130" height="28"/><text x={592 + index % 3 * 145} y={809 + Math.floor(index / 3) * 37}>{presentation ? `PROTEÇÃO ${index + 1}` : feature.name_pt.slice(0, 17)}</text></g>)}</g>
    <g className="title-block"><rect x="1110" y="898" width="375" height="42"/><text x="1127" y="917">BANCO JACARANDÁ · PLANTA GERAL</text><text x="1127" y="933">RODADA {roundNo === null ? "--" : String(roundNo).padStart(2, "0")} · ESCALA 1:∞</text></g>
  </svg>{idle && <div className={`idle-countdown${idle.progress > .98 ? " imminent" : ""}`}>
    <svg viewBox="0 0 108 108" aria-hidden="true"><circle cx="54" cy="54" r="42" className="idle-ring-track"/>
      <circle cx="54" cy="54" r="42" className="idle-ring-progress" strokeDasharray="264"
        strokeDashoffset={264 * (1 - idle.progress)}/></svg>
    <div><small>PRÓXIMA RODADA EM</small><strong>{idle.countdown}</strong>
      <span>Rodada {String(idle.nextRoundNo).padStart(2, "0")} · {idle.slot} (São Paulo)</span></div>
  </div>}</div><div className="map-bottom"><span>● RELÓGIO DO BANCO <b>{clock(state.twin_ts)}</b></span><span>TOQUE UMA ÁREA PARA INSPECIONAR</span></div></div>;
}
function SentinelRow({ area, status, ticks, telemetry, nowMs, isLive, onSelect }: {
  area: Area; status: WorldState["sentinels"][Area]; ticks: ArenaEvent[];
  telemetry: LiveTelemetry | null; nowMs: number; isLive: boolean; onSelect: () => void;
}) {
  const current = isLive && telemetry ? { ...status, ...telemetry.areas[area], last_tick_at: telemetry.checked_at } : status;
  const samples = ticks.map((event) => Number((event.public.by_area as Record<string, number>)[area] ?? 0) / 10);
  const max = Math.max(1, ...samples);
  const points = samples.map((value, index) => `${index * 9},${14 - value / max * 12}`).join(" ");
  const latest = samples.at(-1);
  const signalAge = current.last_tick_at ? Math.max(0, Math.floor((nowMs - Date.parse(current.last_tick_at)) / 1000)) : null;
  const displayState = isLive && (signalAge === null || signalAge > 30) ? "silent" : current.state;
  return <button className="sentinel-row" onClick={onSelect}>
    <span className={displayState}>◌</span><span className="sentinel-copy"><strong>{LABEL[area]}</strong>
      <small>{latest === undefined ? "Tráfego sem amostra" :
        `${latest.toLocaleString("pt-BR", { minimumFractionDigits: 1, maximumFractionDigits: 1 })} op/s simuladas`}</small>
      <small>{current.checks_total.toLocaleString("pt-BR")} verificações · {signalAge === null ? "sem sinal" : `sinal há ${signalAge} s`}</small>
    </span>{samples.length > 1 && <svg className="sentinel-spark" viewBox="0 0 48 16" aria-hidden="true">
      <polyline points={points}/></svg>}<em>{({ ok: "ATIVA", alerting: "ALERTA", degraded: "DEGRADADA", silent: "SILENCIOSA" })[displayState]}</em>
  </button>;
}
function App() {
  const showFps = new URLSearchParams(location.search).get("perf") === "1";
  const [fps, setFps] = useState<number | null>(null);
  const [minimumFps, setMinimumFps] = useState<number | null>(null);
  const [fpsSamples, setFpsSamples] = useState(0);
  const [seekMs, setSeekMs] = useState<number | null>(null);
  const seekProbe = useRef<{ target: number; started: number } | null>(null);
  const [events, setEvents] = useState<ArenaEvent[]>([]); const [source, setSource] = useState<"loading" | "demo" | "live" | "archive">("loading");
  const [liveTelemetry, setLiveTelemetry] = useState<LiveTelemetry | null>(null);
  const [cursor, setCursor] = useState(0); const [playing, setPlaying] = useState(false); const [speed, setSpeed] = useState<1 | 4 | 16>(requestedSpeed);
  const [rounds, setRounds] = useState<RoundIndex[]>([]);
  const [launchSummary, setLaunchSummary] = useState<LaunchSummary | null>(null);
  const [socMetrics, setSocMetrics] = useState<SocMetrics | null>(null);
  const [finalFrames, setFinalFrames] = useState<Map<string, WorldState>>(new Map());
  const [campaignMode, setCampaignMode] = useState<"live" | "idle" | "paused" | "replay_only">("idle");
  const [operationMode, setOperationMode] = useState<"none" | "legacy" | "defensive_only" | "bank_only" | "fault_lab">("none");
  const [defensiveNoticeSeen, setDefensiveNoticeSeen] = useState(() => {
    try { return sessionStorage.getItem("banco-vivo:defensive-notice:v1") === "seen"; }
    catch { return false; }
  });
  useEffect(() => {
    if (operationMode !== "defensive_only" || defensiveNoticeSeen) return;
    const priorOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = priorOverflow; };
  }, [operationMode, defensiveNoticeSeen]);
  const [roundMode, setRoundMode] = useState<"none" | "scheduled" | "manual" | "continuous">("none");
  const [startingRound, setStartingRound] = useState(false);
  const visibilityVersion = useRef("");
  const [nextRoundAt, setNextRoundAt] = useState<string | null>(null);
  const [quotaResumeAt, setQuotaResumeAt] = useState<string | null>(null);
  const [wallNow, setWallNow] = useState(Date.now());
  const [selectedRoundId, setSelectedRoundId] = useState<string | null>(null);
  const [reelStep, setReelStep] = useState(() => new URLSearchParams(location.search).get("replay") === "last" ? 0 : -1);
  const [reelPaused, setReelPaused] = useState(false);
  const loadedRounds = useRef(new Set<string>());
  const roundKeyframes = useRef(new Map<string, WorldState>());
  const [keyframeVersion, setKeyframeVersion] = useState(0);
  const checkpoints = useRef<{ roundId: string | null; firstSeq: number; version: number;
    states: Map<number, WorldState> }>({
    roundId: null, firstSeq: 0, version: 0, states: new Map([[0, initialWorld()]]) });
  const followLive = useRef(true);
  const seenSeq = useRef(0);
  const [page, setPage] = useState<Page>(pageForLocation); const [mobile, setMobile] = useState<"map" | "red" | "blue">("map");
  const [selectedArea, setSelectedArea] = useState<Area | null>(null); const [selectedEvent, setSelectedEvent] = useState<ArenaEvent | null>(null);
  const [selectedDefenseIncident, setSelectedDefenseIncident] = useState<DefenseIncident | null>(null);
  const [presenter, setPresenter] = useState(() => initialPresentationMode(location.search, window.innerWidth)); const [heat, setHeat] = useState(false);
  const [error, setError] = useState("");
  const [reconnecting, setReconnecting] = useState(false);
  useEffect(() => {
    if (page !== "soc" || source !== "live" || operationMode === "none") return;
    let active = true;
    const refresh = () => { void getSocMetrics().then((value) => {
      if (active) setSocMetrics(value);
    }).catch(() => { if (active) setSocMetrics(null); }); };
    refresh();
    const timer = window.setInterval(refresh, 10_000);
    return () => { active = false; window.clearInterval(timer); };
  }, [page, source, operationMode]);
  const drawerRef = useRef<HTMLElement | null>(null);
  const drawerOpen = Boolean(selectedArea || selectedEvent);
  useEffect(() => {
    if (!drawerOpen) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const drawer = drawerRef.current;
    const controls = () => Array.from(drawer?.querySelectorAll<HTMLElement>("button, [href], input, [tabindex]:not([tabindex='-1'])") ?? []);
    controls()[0]?.focus();
    const trap = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const focusable = controls();
      if (!focusable.length) return;
      const first = focusable[0]!;
      const last = focusable.at(-1)!;
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", trap);
    return () => { document.removeEventListener("keydown", trap); if (previous?.isConnected) previous.focus(); };
  }, [drawerOpen]);
  useEffect(() => {
    if (!showFps || !playing) return;
    setFps(null);
    setMinimumFps(null);
    setFpsSamples(0);
    let frame = 0;
    let frames = 0;
    let started = 0;
    const sample = (now: number) => {
      if (!started) started = now;
      frames++;
      if (now - started >= 1000) {
        const sampledFps = Math.round(frames * 1000 / (now - started));
        setFps(sampledFps);
        setMinimumFps((current) => current === null ? sampledFps : Math.min(current, sampledFps));
        setFpsSamples((current) => current + 1);
        frames = 0;
        started = now;
      }
      frame = window.requestAnimationFrame(sample);
    };
    frame = window.requestAnimationFrame(sample);
    return () => window.cancelAnimationFrame(frame);
  }, [showFps, playing]);
  useLayoutEffect(() => {
    const probe = seekProbe.current;
    if (!showFps || !probe || probe.target !== cursor) return;
    let secondFrame = 0;
    const firstFrame = window.requestAnimationFrame(() => {
      secondFrame = window.requestAnimationFrame(() => {
        if (seekProbe.current !== probe) return;
        setSeekMs(Math.round(performance.now() - probe.started));
        seekProbe.current = null;
      });
    });
    return () => { window.cancelAnimationFrame(firstFrame); window.cancelAnimationFrame(secondFrame); };
  }, [cursor, showFps]);
  useEffect(() => { const timer = window.setInterval(() => setWallNow(Date.now()), 1000);
    return () => window.clearInterval(timer); }, []);
  useEffect(() => {
    let disposed = false; let stream: EventSource | undefined;
    let reconnectTimer: number | undefined;
    (async () => { try {
      const statusResponse = await fetch("/api/status", { signal: AbortSignal.timeout(1800) }); if (!statusResponse.ok) throw new Error("Backend unavailable");
      const status = await statusResponse.json() as { latest_seq: number; next_round_at: string | null;
        quota_resume_at: string | null;
        mode: "live" | "idle" | "paused" | "replay_only";
        campaign_mode: "none" | "legacy" | "defensive_only" | "bank_only" | "fault_lab";
        round_mode: "none" | "scheduled" | "manual" | "continuous"; visibility_version: string };
      void getLaunchSummary().then((summary) => { if (!disposed) setLaunchSummary(summary); })
        .catch(() => undefined);
      const index = await getRounds();
      const requested = requestedMoment();
      const latestRound = index.find((round) => round.status === "started") ?? index[0];
      const replayRound = requested ? index.find((round) => round.round_no === requested.roundNo) : undefined;
      const needed = [latestRound, replayRound].filter((round): round is RoundIndex => Boolean(round));
      const unique = [...new Map(needed.map((round) => [round.round_id, round])).values()];
      const loaded = await Promise.all(unique.map((round) => getRoundEvents(round, status.latest_seq)));
      const trailing = !latestRound ? await getEventsAfter(0, status.latest_seq) :
        latestRound.last_seq !== null ? await getEventsAfter(latestRound.last_seq, status.latest_seq) : [];
      const live = [...new Map([...loaded.flatMap((item) => item.events), ...trailing]
        .map((event) => [event.seq, event])).values()].sort((left, right) => left.seq - right.seq);
      if (disposed) return; unique.forEach((round) => loadedRounds.current.add(round.round_id));
      loaded.forEach((item, index) => { if (item.keyframe) roundKeyframes.current.set(unique[index]!.round_id, item.keyframe); });
      visibilityVersion.current = status.visibility_version;
      setEvents(live); setRounds(index); setNextRoundAt(status.next_round_at);
      setQuotaResumeAt(status.quota_resume_at); setCampaignMode(status.mode);
      setOperationMode(status.campaign_mode);
      setRoundMode(status.round_mode);
      setCursor(latestRound ? liveRoundEvents(live, latestRound).length : live.length);
      setSource("live");
      seenSeq.current = Math.max(status.latest_seq, live.at(-1)?.seq ?? 0);
      if (requested && replayRound) {
        followLive.current = false; setSelectedRoundId(replayRound.round_id);
        const replayEvents = roundEvents(live, replayRound);
        setCursor(resolveMomentCursor(replayEvents, requested.position) ?? replayEvents.length);
        setPlaying(false);
      }
      stream = new EventSource(`/api/stream?after=${seenSeq.current}`);
      stream.onopen = () => { window.clearTimeout(reconnectTimer); reconnectTimer = undefined; if (!disposed) setReconnecting(false); };
      stream.onerror = () => { if (reconnectTimer === undefined) reconnectTimer = window.setTimeout(() => {
        reconnectTimer = undefined; if (!disposed) setReconnecting(true);
      }, 20_000); };
      stream.addEventListener("reset", () => location.reload());
      stream.addEventListener("heartbeat", (message) => { try {
        const frame = TELEMETRY_FRAME.safeParse(JSON.parse((message as MessageEvent).data));
        if (frame.success && !disposed) setLiveTelemetry(frame.data.telemetry);
      } catch { /* invalid frame */ } });
      for (const type of EVENT_TYPES) stream.addEventListener(type, (message) => { try { const event = parseEvent(JSON.parse((message as MessageEvent).data)); if (event.seq <= seenSeq.current) return; seenSeq.current = event.seq; setEvents((current) => [...current, event]); if (followLive.current) setCursor((value) => value + 1); if (event.type === "round.started") setNextRoundAt(null); if (event.type === "round.scheduled") setNextRoundAt(String(event.public.starts_at)); if (event.type === "round.started" || event.type === "round.ended") void getRounds().then(setRounds).catch(() => undefined); if (["attack.succeeded", "impact.caused", "incident.updated", "damage.restored", "review.rejected", "regression.result", "feature.launched", "health.updated", "round.ended"].includes(event.type)) void getLaunchSummary().then(setLaunchSummary).catch(() => undefined); } catch { /* invalid frame */ } });
    } catch { try {
      const archive = await getStaticReplay();
      if (!disposed) {
        followLive.current = false;
        archive.rounds.forEach((round) => loadedRounds.current.add(round.round_id));
        setRounds(archive.rounds); setEvents(archive.events);
        const requested = requestedMoment();
        const replayRound = requested ? archive.rounds.find((round) => round.round_no === requested.roundNo) : undefined;
        const selected = replayRound ?? archive.rounds[0];
        const replayEvents = selected ? roundEvents(archive.events, selected) : [];
        setSelectedRoundId(selected?.round_id ?? null);
        setCursor(replayRound && requested ? resolveMomentCursor(replayEvents, requested.position) ??
          replayEvents.length : 0);
        setPlaying(!replayRound); setSource("archive"); setCampaignMode("replay_only");
      }
    } catch { try {
      const demo = await getDemo();
      if (!disposed) { followLive.current = false; setEvents(demo);
        const requested = requestedMoment();
        const replay = requested && demo.some((event) => event.round_id === `r${String(requested.roundNo).padStart(2, "0")}`);
        setCursor(replay && requested ? resolveMomentCursor(demo, requested.position) ??
          demo.length : Math.min(32, demo.length));
        setSource("demo"); setPlaying(!replay); }
    } catch { if (!disposed) { setSource("demo"); setError("Demonstração indisponível."); } } } } })();
    return () => { disposed = true; window.clearTimeout(reconnectTimer); stream?.close(); };
  }, []);
  useEffect(() => {
    if (source !== "live") return;
    const timer = window.setInterval(() => { void (async () => {
      try {
        const response = await fetch("/api/status", { cache: "no-store" });
        if (!response.ok) return;
        const status = await response.json() as { mode: "live" | "idle" | "paused" | "replay_only";
          next_round_at: string | null; quota_resume_at: string | null;
          campaign_mode: "none" | "legacy" | "defensive_only" | "bank_only" | "fault_lab";
          round_mode: "none" | "scheduled" | "manual" | "continuous"; visibility_version: string };
        if (visibilityVersion.current && status.visibility_version !== visibilityVersion.current) {
          location.reload(); return;
        }
        setCampaignMode(status.mode); setNextRoundAt(status.next_round_at);
        setOperationMode(status.campaign_mode);
        setRoundMode(status.round_mode);
        setQuotaResumeAt(status.quota_resume_at);
      } catch { /* SSE reconnect handles transient outages. */ }
    })(); }, 10_000);
    return () => window.clearInterval(timer);
  }, [source]);
  useEffect(() => {
    const active = rounds.find((round) => round.status === "started");
    if (!active || roundKeyframes.current.has(active.round_id)) return;
    let cancelled = false;
    void fetch(`/api/keyframe?seq=${active.first_seq}`).then(async (response) =>
      response.ok ? await response.json() as { seq: number; reducer_version: number; state: WorldState } : null)
      .then((frame) => {
        if (cancelled || !frame || frame.seq !== active.first_seq || frame.reducer_version !== REDUCER_VERSION) return;
        roundKeyframes.current.set(active.round_id, frame.state);
        setKeyframeVersion((value) => value + 1);
      }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [rounds]);
  const liveRound = rounds.find((round) => round.status === "started") ?? rounds[0];
  const timelineRoundId = selectedRoundId ?? liveRound?.round_id ?? null;
  const timelineRound = rounds.find((round) => round.round_id === timelineRoundId);
  const openRound = async (round: RoundIndex, position: MomentPosition = { kind: "final" }, updateUrl = true) => {
    let history = roundEvents(events, round);
    if (!loadedRounds.current.has(round.round_id)) {
      const response = await fetch("/api/status");
      if (!response.ok) { setError("Histórico indisponível."); return; }
      const status = await response.json() as { latest_seq: number };
      try {
        const archive = await getRoundEvents(round, status.latest_seq);
        history = archive.events;
        setEvents((current) => {
          const merged = new Map(current.map((event) => [event.seq, event]));
          archive.events.forEach((event) => merged.set(event.seq, event));
          return [...merged.values()].sort((left, right) => left.seq - right.seq);
        });
        if (archive.keyframe) { roundKeyframes.current.set(round.round_id, archive.keyframe);
          setKeyframeVersion((value) => value + 1); }
        loadedRounds.current.add(round.round_id);
      } catch { setError("Histórico indisponível."); return; }
    }
    followLive.current = false; setSelectedRoundId(round.round_id);
    setPage("control"); setCursor(resolveMomentCursor(history, position) ?? history.length); setPlaying(false);
    if (updateUrl) historyPush(source === "archive" ? `/?round=${round.round_no}` : `/rodada/${round.round_no}`);
  };
  const navigatePage = (target: Page) => {
    if (target === "control") {
      followLive.current = source === "live";
      setSelectedRoundId(null); setPlaying(false);
      setCursor(liveRound ? liveRoundEvents(events, liveRound).length : events.length);
    }
    setPage(target);
    const path = source === "archive" ? target === "control" ? "/" : `/?page=${target}` :
      { control: "/", lab: "/laboratorio", soc: "/soc", bank: "/banco", history: "/historico", score: "/placar", customer: "/cliente", psp: "/psp", about: "/sobre" }[target];
    historyPush(path);
  };
  useEffect(() => {
    const restore = () => {
      setPresenter(initialPresentationMode(location.search, window.innerWidth));
      const requested = requestedMoment();
      if (requested) {
        const round = rounds.find((item) => item.round_no === requested.roundNo);
        if (round) void openRound(round, requested.position, false);
        else { setPage("control"); setError("Rodada não encontrada."); }
        return;
      }
      const target = pageForLocation();
      setPage(target);
      if (target === "control") {
        followLive.current = source === "live";
        setSelectedRoundId(null); setPlaying(false);
        const current = rounds.find((round) => round.status === "started") ?? rounds[0];
        setCursor(current ? liveRoundEvents(events, current).length : events.length);
      }
    };
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, [rounds, events, source]);
  const timelineEvents = useMemo(() => timelineRound ? source === "live" && !selectedRoundId ?
    liveRoundEvents(events, timelineRound) : roundEvents(events, timelineRound) :
    timelineRoundId ? events.filter((event) => event.round_id === timelineRoundId) : events,
    [events, timelineRoundId, timelineRound, source, selectedRoundId]);
  const chapters = useMemo(() => replayChapters(timelineEvents), [timelineEvents]);
  useEffect(() => {
    if ((page !== "history" && page !== "score") || source !== "live") return;
    const pending = rounds.filter((round) => round.last_seq !== null && !finalFrames.has(round.round_id));
    if (!pending.length) return;
    let cancelled = false;
    void Promise.all(pending.map(async (round) => {
      try {
        const response = await fetch(`/api/keyframe?seq=${round.last_seq}`);
        if (!response.ok) return null;
        const frame = await response.json() as { seq: number; reducer_version: number; state: WorldState };
        return frame.seq === round.last_seq && frame.reducer_version === REDUCER_VERSION ?
          [round.round_id, frame.state] as const : null;
      } catch { return null; }
    })).then((loaded) => {
      if (cancelled || loaded.every((entry) => entry === null)) return;
      setFinalFrames((previous) => {
        const next = new Map(previous);
        for (const entry of loaded) if (entry) next.set(...entry);
        return next;
      });
    });
    return () => { cancelled = true; };
  }, [page, source, rounds, finalFrames]);
  const archiveFrames = useMemo(() => {
    const opening = new Map<string, WorldState>();
    const closing = new Map<string, WorldState>();
    const low = new Map<string, number>();
    if (source !== "archive") return { opening, closing, low };
    const begins = new Map(rounds.map((round) => [round.first_seq, round.round_id]));
    const ends = new Map(rounds.filter((round) => round.last_seq !== null)
      .map((round) => [round.last_seq!, round.round_id]));
    let current = initialWorld();
    let activeRound: string | null = null;
    for (const event of events) {
      const starting = begins.get(event.seq);
      if (starting) { opening.set(starting, current); low.set(starting, current.health.overall); activeRound = starting; }
      current = reduceWorld(current, event);
      if (activeRound) low.set(activeRound, Math.min(low.get(activeRound) ?? 100, current.health.overall));
      const ending = ends.get(event.seq);
      if (ending) { closing.set(ending, current); activeRound = null; }
    }
    return { opening, closing, low };
  }, [source, rounds, events]);
  const historyFrames = useMemo(() => new Map([...finalFrames, ...archiveFrames.closing]),
    [finalFrames, archiveFrames]);
  const historyStats = useMemo(() => {
    const stats = new Map<string, { events: number; attacks: number; loss: number; restored: number;
      agents: number; rejections: number; usageTokens: number | null; date: string | null }>();
    for (const round of rounds) {
      if (source !== "archive" && !loadedRounds.current.has(round.round_id)) continue;
      const history = roundEvents(events, round);
      const usage = history.filter((event) => event.type === "usage.updated").at(-1)?.public;
      const startedAt = history.find((event) => event.type === "round.started")?.ts;
      stats.set(round.round_id, {
        events: history.length,
        attacks: history.filter((event) => event.type === "attack.succeeded").length,
        loss: history.filter((event) => event.type === "impact.caused")
          .reduce((sum, event) => sum + Number(event.public.loss_cents), 0),
        restored: history.filter((event) => event.type === "damage.restored")
          .reduce((sum, event) => sum + Number(event.public.restored_cents), 0),
        agents: history.filter((event) => event.type === "agent.spawned").length,
        rejections: history.filter((event) => event.type === "review.rejected").length,
        usageTokens: usage ? Number(usage.input_tokens) + Number(usage.output_tokens) : null,
        date: startedAt ? new Intl.DateTimeFormat("pt-BR", { timeZone: "America/Sao_Paulo",
          day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }).format(new Date(startedAt)) : null,
      });
    }
    return stats;
  }, [rounds, events, source]);
  useEffect(() => { if (followLive.current) setCursor(timelineEvents.length); }, [timelineRoundId, timelineEvents.length]);
  useEffect(() => {
    if (!playing || followLive.current) return;
    const step = nextReplayStep(timelineEvents, cursor, speed);
    if (!step) return;
    const timer = window.setTimeout(() => setCursor(step.cursor), step.delayMs);
    return () => window.clearTimeout(timer);
  }, [playing, speed, timelineEvents, cursor]);
  useEffect(() => { if (!followLive.current && cursor >= timelineEvents.length) setPlaying(false); }, [cursor, timelineEvents.length]);
  const visible = useMemo(() => timelineEvents.slice(0, cursor), [timelineEvents, cursor]);
  const recentTraffic = useMemo(() => visible.filter((event) => event.type === "sim.tick" &&
    event.public.by_area && typeof event.public.by_area === "object").slice(-6), [visible]);
  const state = useMemo(() => {
    const firstSeq = timelineEvents[0]?.seq ?? 0;
    if (checkpoints.current.roundId !== timelineRoundId || checkpoints.current.firstSeq !== firstSeq ||
      checkpoints.current.version !== keyframeVersion) {
      const frame = timelineRoundId ? roundKeyframes.current.get(timelineRoundId) : undefined;
      const opening = timelineRoundId ? archiveFrames.opening.get(timelineRoundId) : undefined;
      const states = new Map<number, WorldState>([[0, opening ?? initialWorld()]]);
      if (frame && frame.seq === firstSeq) states.set(1, frame);
      checkpoints.current = { roundId: timelineRoundId, firstSeq, version: keyframeVersion, states };
    }
    const states = checkpoints.current.states;
    const index = Math.max(0, ...[...states.keys()].filter((value) => value <= cursor));
    let next = states.get(index)!;
    for (let position = index; position < Math.min(cursor, timelineEvents.length); position++) {
      next = reduceWorld(next, timelineEvents[position]!);
      if ((position + 1) % 250 === 0) states.set(position + 1, next);
    }
    return next;
  }, [timelineEvents, timelineRoundId, cursor, keyframeVersion, archiveFrames]); const latest = visible.at(-1);
  const scoreRound = [...rounds].sort((left, right) => right.round_no - left.round_no)[0];
  const scoreState = scoreRound ? historyFrames.get(scoreRound.round_id) ??
    (state.round_id === scoreRound.round_id ? state : null) : state;
  const scoreImpact = scoreRound && historyStats.get(scoreRound.round_id);
  const displayRoundNo = selectedRoundId ?
    rounds.find((round) => round.round_id === selectedRoundId)?.round_no ?? state.round_no : state.round_no;
  useEffect(() => {
    if (page !== "control" || followLive.current || playing || displayRoundNo === null || source === "loading") return;
    const timer = window.setTimeout(() => {
      const seconds = latest && timelineEvents[0] ? Math.max(0,
        Math.round((Date.parse(latest.ts) - Date.parse(timelineEvents[0].ts)) / 1000)) : 0;
      const next = new URL(location.href);
      next.pathname = source === "live" ? `/rodada/${displayRoundNo}` : "/";
      if (source === "live") next.searchParams.delete("round");
      else next.searchParams.set("round", String(displayRoundNo));
      next.searchParams.set("t", String(seconds)); next.hash = "";
      history.replaceState(null, "", next.pathname + next.search);
    }, 500);
    return () => window.clearTimeout(timer);
  }, [cursor, displayRoundNo, latest, playing, source, timelineEvents, page]);
  const activeRound = rounds.some((round) => round.status === "started");
  const reelEligible = source === "live" && campaignMode === "idle" && !activeRound &&
    !selectedRoundId && page === "control" && timelineEvents.length > 0;
  const reelCursors = useMemo(() => highlightCursors(timelineEvents), [timelineEvents]);
  const reelActive = reelEligible && !reelPaused && reelStep >= 0 && reelCursors.length > 0;
  useEffect(() => {
    if (!reelEligible || reelPaused) return;
    const timer = window.setTimeout(() => setReelStep((step) => step < 0 ? 0 :
      step + 1 < reelCursors.length ? step + 1 : -1), reelStep < 0 ? 20_000 : 1_250);
    return () => window.clearTimeout(timer);
  }, [reelEligible, reelPaused, reelStep, reelCursors.length]);
  useEffect(() => {
    if (!reelEligible || reelPaused) return;
    const pause = () => setReelPaused(true);
    window.addEventListener("pointerdown", pause, { once: true });
    window.addEventListener("keydown", pause, { once: true });
    return () => { window.removeEventListener("pointerdown", pause); window.removeEventListener("keydown", pause); };
  }, [reelEligible, reelPaused]);
  const reelState = useMemo(() => {
    if (!reelActive) return null;
    const first = timelineEvents[0];
    const frame = timelineRoundId ? roundKeyframes.current.get(timelineRoundId) : undefined;
    const hasFrame = first && frame?.seq === first.seq;
    return timelineEvents.slice(hasFrame ? 1 : 0, reelCursors[reelStep])
      .reduce(reduceWorld, hasFrame ? frame : initialWorld());
  }, [reelActive, timelineEvents, timelineRoundId, reelCursors, reelStep, keyframeVersion]);
  const reelEvent = reelActive ? timelineEvents[reelCursors[reelStep]! - 1] : undefined;
  const countdownSeconds = nextRoundAt ? Math.max(0, Math.ceil((Date.parse(nextRoundAt) - wallNow) / 1000)) : null;
  const countdown = countdownSeconds === null ? null : `${String(Math.floor(countdownSeconds / 3600)).padStart(2, "0")}:${String(Math.floor(countdownSeconds % 3600 / 60)).padStart(2, "0")}:${String(countdownSeconds % 60).padStart(2, "0")}`;
  const nextSlot = nextRoundAt ? clock(nextRoundAt) : null;
  const idleCountdown = source === "live" && roundMode === "scheduled" && campaignMode === "idle" && !activeRound &&
    !selectedRoundId && countdown && countdownSeconds !== null && nextSlot ? {
      countdown, slot: nextSlot, nextRoundNo: Math.min(14, Math.max(1, ...rounds.map((round) => round.round_no)) + (rounds.length ? 1 : 0)),
      progress: 1 - Math.min(1, countdownSeconds / ((nextSlot.startsWith("09") ? 15 : 9) * 3600)),
    } : undefined;
  const idleTips = operationMode === "fault_lab" ? [
    "Escolha uma ou mais falhas no Laboratório para observar os Sentinelas.",
    "O laboratório não entrega o gabarito aos agentes de defesa.",
    "Uma falha observada ainda precisa de correção, reparo e conciliação.",
    "Dados, clientes e pagamentos deste modo são sintéticos.",
  ] : [
    "Cada ataque confirmado gera uma prova que permanece nas próximas rodadas.",
    "A defesa só recebe crédito quando a correção passa pelos testes e funciona no banco.",
    "Valores, clientes e operações desta experiência são inteiramente sintéticos.",
    "A saúde do banco registra danos, contenção e recuperação comprovados.",
  ];
  const idleTip = source === "live" && campaignMode === "idle" && !activeRound &&
    !selectedRoundId && !reelActive ? idleTips[Math.floor(wallNow / 10_000) % idleTips.length] : null;
  const important = visible.filter((event) => IMPORTANT.has(event.type)); const recent = important.slice(-7).reverse();
  const narrativeEvent = scoreRound ? roundEvents(events, scoreRound)
    .filter((event) => event.type === "narration.published").at(-1) :
    visible.filter((event) => event.type === "narration.published").at(-1);
  const red = Object.entries(state.agents).filter(([, agent]) => ["historian", "scout", "intruder", "exploiter"].includes(agent.role));
  const blue = Object.entries(state.agents).filter(([, agent]) => ["investigator", "engineer", "reviewer", "damage_assessor", "restorer"].includes(agent.role));
  const loss = visible.filter((event) => event.type === "impact.caused").reduce((sum, event) => sum + Number(event.public.loss_cents), 0);
  const share = () => { if (displayRoundNo === null) return; const seconds = latest && timelineEvents[0] ? Math.max(0, Math.round((Date.parse(latest.ts) - Date.parse(timelineEvents[0].ts)) / 1000)) : 0; const path = momentPath(displayRoundNo, seconds, source !== "live"); void navigator.clipboard?.writeText(presentationShareUrl(path, location.origin)); };
  useEffect(() => {
    const jump = (position: number, play = false) => {
      followLive.current = false;
      setCursor(Math.max(0, Math.min(position, timelineEvents.length)));
      setPlaying(play); setPage("control");
      if (displayRoundNo !== null) historyPush(source === "archive" ?
        `/?round=${displayRoundNo}` : `/rodada/${displayRoundNo}`);
    };
    const key = (event: KeyboardEvent) => {
      if (drawerOpen && event.key !== "Escape") return;
      if (event.altKey || event.ctrlKey || event.metaKey || event.target instanceof HTMLInputElement ||
        event.target instanceof HTMLTextAreaElement) return;
      const lower = event.key.toLowerCase();
      if (event.key === " ") {
        event.preventDefault(); followLive.current = false;
        if (!playing && cursor >= timelineEvents.length) setCursor(0);
        setPlaying((value) => !value);
      }
      else if (event.key === "1") setSpeed(1);
      else if (event.key === "2" || event.key === "4") setSpeed(4);
      else if (event.key === "3" || event.key === "6") setSpeed(16);
      else if (event.key === "ArrowLeft") { event.preventDefault(); jump(cursor - 1); }
      else if (event.key === "ArrowRight") { event.preventDefault(); jump(cursor + 1); }
      else if (event.key === "[" || event.key === "]") {
        const markers = timelineEvents.flatMap((item, index) => IMPORTANT.has(item.type) ? [index + 1] : []);
        const next = event.key === "[" ? markers.filter((index) => index < cursor).at(-1) :
          markers.find((index) => index > cursor);
        if (next !== undefined) { event.preventDefault(); jump(next); }
      } else if (lower === "b" || lower === "m") {
        const index = timelineEvents.findIndex((item) => lower === "b" ?
          item.type === "attack.succeeded" :
          item.type === "patch.merged" || item.type === "deploy.succeeded");
        if (index >= 0) jump(index + 1);
      }
      else if (lower === "e") jump(timelineEvents.length);
      else if (lower === "g") navigatePage("score");
      else if (lower === "l") share();
      else if (lower === "h") setHeat((value) => !value);
      else if (lower === "n") jump(bestMoment(timelineEvents), true);
      else if (event.key === "Escape") { setSelectedArea(null); setSelectedEvent(null); }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [cursor, playing, share, timelineEvents, drawerOpen]);
  const selectedPublicEvent = selectedEvent ? sanitizePublicEvent(selectedEvent) : null;
  const selectedDetails = selectedPublicEvent ? publicEventDetails(selectedPublicEvent, presenter) : [];
  const openIncidents = Object.values(state.incidents).filter((incident) => incident.state !== "resolved");
  const visibleDefenseIncidents = defenseIncidents(visible);
  const defenseSelection = selectedDefenseIncident &&
    visibleDefenseIncidents.some(({ id }) => id === selectedDefenseIncident.id) ?
    selectedDefenseIncident : null;
  const moneyIncidentId = selectedEvent ?
    selectedEvent.area === "pix" ? selectedEvent.incident_id ?? undefined : undefined :
    defenseSelection ? defenseSelection.area === "pix" ? defenseSelection.id : undefined : null;
  const replayFlow = useMemo(() => replayMoneyFlow(visible, moneyIncidentId),
    [visible, moneyIncidentId]);
  const highlightedDefenseId = selectedEvent?.incident_id &&
    visibleDefenseIncidents.some(({ id }) => id === selectedEvent.incident_id) ?
    selectedEvent.incident_id : defenseSelection?.id ?? null;
  const alarm = openIncidents.some((incident) => incident.severity.toLowerCase() === "critical") ?
    "critical" : openIncidents.length || AREAS.some((area) => state.sentinels[area].state === "alerting") ?
      "warning" : "normal";
  const displayNowMs = source === "live" && followLive.current ? wallNow :
    latest ? Date.parse(latest.ts) : wallNow;
  const togglePresentation = () => {
    const next = !presenter;
    const url = new URL(location.href);
    url.searchParams.set("mode", next ? "presenter" : "operator");
    history.replaceState(null, "", url.pathname + url.search + url.hash);
    setPresenter(next);
  };
  const defensiveCurrent = (operationMode === "defensive_only" || operationMode === "bank_only" || operationMode === "fault_lab") &&
    source === "live" && !selectedRoundId;
  const aboutModeText = operationMode === "bank_only" ?
    "Esta execução mostra o funcionamento do banco sintético. As rodadas de agentes estão desligadas." :
    operationMode === "fault_lab" ?
    "Esta execução usa falhas controladas e dados descartáveis no localhost. A defesa observa os efeitos no banco sem receber o gabarito do laboratório." :
    operationMode === "defensive_only" ?
    "Esta execução mostra somente agentes de defesa: eles investigam, corrigem e restauram o serviço. Não há agentes de ataque em operação." :
    "Agentes de ataque procuram falhas; sentinelas e agentes de defesa investigam, corrigem e restauram o serviço.";
  const navPages: Page[] = operationMode === "fault_lab" ?
    ["control", "lab", "soc", "bank", "customer", "psp", "about"] :
    ["control", "soc", "bank", "history", "score", "customer", "psp", "about"];
  useEffect(() => {
    if (operationMode === "fault_lab" && (page === "history" || page === "score")) {
      setPage("lab");
      historyPush("/laboratorio");
    }
  }, [operationMode, page]);
  return <div className={`app${presenter ? " presenter" : ""} alarm-${alarm}`}>
    {operationMode === "defensive_only" && !defensiveNoticeSeen &&
      <div className="defensive-mode-intro" role="alertdialog" aria-modal="true"
        aria-label="Modo defensivo desta execução"
        onKeyDown={(event) => {
          if (event.key === "Tab") {
            event.preventDefault();
            event.currentTarget.querySelector("button")?.focus();
          }
        }}>
        <div><small>BANCO VIVO · MODO DE OPERAÇÃO</small>
          <h1>Simulação ofensiva desativada</h1>
          <p>Esta execução mostra somente a defesa do banco sintético. Não há agentes de ataque em operação e as rodadas são parciais.</p>
          <button autoFocus onClick={() => {
            setDefensiveNoticeSeen(true);
            try { sessionStorage.setItem("banco-vivo:defensive-notice:v1", "seen"); }
            catch { /* The notice still closes when session storage is unavailable. */ }
          }}>Entendi, abrir a sala de controle</button>
        </div>
      </div>}
    <header className="topbar"><div className="brand"><span className="brand-glyph">◇</span><div><strong>BANCO VIVO</strong><small>JACARANDÁ · SALA DE CONTROLE</small></div></div><div className="top-center"><span className={`source-badge ${source}`}>{selectedRoundId ? "◌ REPRODUÇÃO" : source === "live" ? campaignMode === "replay_only" ? "◌ REPRODUÇÃO" : campaignMode === "paused" ? quotaResumeAt ? "◌ AGUARDANDO COTA DO CODEX" : "◌ PAUSADO" : operationMode === "bank_only" ? "● BANCO ATIVO" : operationMode === "fault_lab" ? "● LAB LOCAL" : operationMode === "defensive_only" ? activeRound ? "● DEFESA LOCAL" : "◌ DEFESA LOCAL" : activeRound ? "● AO VIVO" : "◌ AGUARDANDO" : source === "demo" ? "◌ DEMONSTRAÇÃO" : "◌ CARREGANDO"}</span><span className={`alarm-badge ${alarm}`} role="status" aria-live="polite" aria-label={alarm === "critical" ? "Alarme: incidente crítico" : alarm === "warning" ? "Alarme: alerta em investigação" : "Alarme: operação normal"}>{alarm === "critical" ? "● CRÍTICO" : alarm === "warning" ? "● ALERTA" : "● NORMAL"}</span>{quotaResumeAt && <span className="desktop-only">RETOMA <b>{new Date(quotaResumeAt).toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo", hour: "2-digit", minute: "2-digit" })}</b></span>}{operationMode !== "fault_lab" && <span>RODADA <b>{displayRoundNo === null ? "--" : String(displayRoundNo).padStart(2, "0")}</b></span>}<span className="desktop-only">RELÓGIO <b>{clock(state.twin_ts)}</b></span>{!selectedRoundId && !activeRound && campaignMode !== "paused" && countdown && <span className="desktop-only">PRÓXIMA <b>{countdown}</b></span>}</div><div className="top-right"><div><small>SAÚDE DO BANCO</small><strong>{state.health.overall.toFixed(0)}</strong></div><div className="live-rate"><small>PIX OP/S</small><strong>{state.traffic_by_area?.pix === undefined ? "—" : (state.traffic_by_area.pix / 10).toLocaleString("pt-BR", { maximumFractionDigits: 1 })}</strong></div><div className="live-rate"><small>CARTÕES OP/S</small><strong>{state.traffic_by_area?.cards === undefined ? "—" : (state.traffic_by_area.cards / 10).toLocaleString("pt-BR", { maximumFractionDigits: 1 })}</strong></div><div className="spi-availability"><small>SPI REDE</small><strong className={state.spi_available === false ? "offline" : ""}>{state.spi_available === true ? "ONLINE" : state.spi_available === false ? "OFFLINE" : "—"}</strong></div><div className="spi-state"><small>CONTA PI / SPI</small><strong className={state.spi_reconciled === false ? "divergent" : ""}>{state.spi_reconciled === true ? "OK" : state.spi_reconciled === false ? "DIVERGENTE" : "—"}</strong></div><div className="risk-queue"><small>FILA RISCO PIX</small><strong>{state.risk_queue_pending ?? "—"}</strong></div>{operationMode !== "fault_lab" && <div><small>USO DA RODADA</small><strong>{state.usage.agents} agentes · {state.usage.turns} turnos · {(state.usage.input_tokens + state.usage.output_tokens).toLocaleString("pt-BR")} tokens</strong></div>}<button title={presenter ? "Desativar apresentação" : "Ativar apresentação"} aria-label="Modo apresentação" aria-pressed={presenter} onClick={togglePresentation}>▣</button></div></header>
    {operationMode === "defensive_only" && <div className="defensive-mode-banner" role="status" aria-live="polite">
      <strong>SIMULAÇÃO OFENSIVA DESATIVADA</strong>
      <span>Esta execução mostra apenas a defesa. Nenhum agente invasor está em operação; rodadas são parciais.</span>
    </div>}
    <nav className="main-nav" aria-label="Navegação">{navPages.map((item) => <button key={item} className={page === item ? "active" : ""} onClick={() => navigatePage(item)}>{ { control: "Sala de Controle", lab: "Laboratório", soc: "SOC", bank: "Banco", history: "Histórico", score: "Pontuação", customer: "Cliente", psp: "Recebedor PSP", about: "Sobre" }[item]}</button>)}</nav>
    {error && <div className="error">{error}</div>}
    {source === "live" && reconnecting && <div className="reconnect-banner" role="status">Reconectando… A transmissão será retomada automaticamente.</div>}
    {page === "control" && source === "live" && operationMode === "defensive_only" && roundMode === "manual" &&
      <div className="manual-round-toolbar"><div><strong>Rodadas sob demanda</strong>
        <span>{activeRound ? "Uma rodada defensiva está em andamento." : "Inicie quando quiser. O resultado será parcial enquanto a etapa ofensiva estiver desativada."}</span></div>
        <button disabled={startingRound || activeRound || campaignMode === "paused" || campaignMode === "replay_only"}
          onClick={() => { void (async () => {
            setStartingRound(true); setError("");
            try {
              const response = await fetch("/api/rounds/start", { method: "POST" });
              if (!response.ok) throw new Error(response.status === 409 ?
                "Já existe uma rodada em andamento ou não há mais rodadas disponíveis." :
                "Não foi possível iniciar a rodada.");
              setRounds(await getRounds());
            } catch (failure) { setError(failure instanceof Error ? failure.message : "Falha ao iniciar a rodada."); }
            finally { setStartingRound(false); }
          })(); }}>
          {startingRound ? "Iniciando…" : activeRound ? "Rodada em andamento" : "Iniciar rodada defensiva"}
        </button></div>}
    {page === "control" && source === "live" && operationMode === "defensive_only" && roundMode === "continuous" &&
      <div className="manual-round-toolbar" role="status"><div><strong>Rodadas contínuas</strong>
        <span>{activeRound ? "Uma rodada defensiva está em andamento." : nextRoundAt ?
          `A próxima rodada começa em ${countdown ?? "instantes"}.` :
          "As rodadas planejadas terminaram ou estão pausadas."}</span></div></div>}
    {page === "control" ? <><div className="mobile-tabs"><button className={mobile === "map" ? "active" : ""} onClick={() => setMobile("map")}>Planta</button><button className={mobile === "red" ? "active" : ""} onClick={() => setMobile("red")}>{operationMode === "fault_lab" ? "Laboratório" : defensiveCurrent ? "Ataque desativado" : "Ataque"}</button><button className={mobile === "blue" ? "active" : ""} onClick={() => setMobile("blue")}>Defesa</button></div><main className="control-grid">
      {operationMode === "fault_lab" ? <aside className={`side-panel red-panel fault-lab-side mobile-${mobile}`}><div className="panel-title"><span className="sigil blue">◇</span><div><small>FALHAS CONTROLADAS</small><h2>Laboratório</h2></div></div><p className="panel-intro">Selecione falhas no banco local e acompanhe os Sentinelas por evidências reais.</p><div className="agents"><button onClick={() => navigatePage("lab")}>Abrir laboratório ↗</button></div><p className="panel-foot">● Não há agentes invasores neste modo.</p></aside> :
      <aside className={`side-panel red-panel mobile-${mobile}`}><div className="panel-title"><span className="sigil red">◇</span><div><small>{defensiveCurrent ? "SIMULAÇÃO OFENSIVA" : "EQUIPE VERMELHA"}</small><h2>{defensiveCurrent ? "Desativada" : "Ataque"}</h2></div><span className="count">{String(red.length).padStart(2, "0")}</span></div><p className="panel-intro">{defensiveCurrent ? "Esta execução acompanha apenas a defesa. Não há agentes de ataque ativos." : "Da hipótese ao teste. Cada agente recebe uma missão e passa sua conclusão."}</p><div className="agents">{red.length ? red.map(([id, agent], index) => <button key={id} onClick={() => { const found = visible.find((event) => event.type === "agent.spawned" && event.public.agent_id === id); if (found) setSelectedEvent(found); }}><span className="agent-icon">{index ? "◇" : "◆"}</span><span><strong>{agent.role.toUpperCase()}</strong><small>{presenter ? "Missão em investigação" : agent.goal_pt}</small></span><em>{agent.outcome ? "✓" : "●"}</em></button>) : !defensiveCurrent && idleCountdown ? <div className="idle-agent-tree" aria-label="Equipe vermelha aguardando próxima rodada"><p>Aguardando a próxima rodada</p><span>HISTORIADOR</span><span>EXPLORADORES</span><span>INTRUSOS</span><span>AVALIADOR DE IMPACTO</span></div> : <p>{defensiveCurrent ? "A simulação ofensiva está desativada nesta execução." : "Aguardando a equipe vermelha."}</p>}</div>{idleCountdown && launchSummary && <IdleSinceLaunch stats={launchSummary} onArea={setSelectedArea} presentation={presenter}/>}<div className="panel-stat"><span>TENTATIVAS <b>{visible.filter((event) => event.type === "attack.attempted").length}</b></span><span>CONFIRMADAS <b>{visible.filter((event) => event.type === "attack.succeeded").length}</b></span></div><p className="panel-foot">{defensiveCurrent ? "● A defesa continua observando o banco sintético." : "● A luz vermelha parte de fora e busca uma abertura na planta."}</p></aside>}
      <section className={`map-column mobile-${mobile}`}>{reelActive && <div className="idle-reel-ribbon"><span>▶ MELHORES MOMENTOS DA RODADA {String(displayRoundNo ?? 0).padStart(2, "0")} · 4×</span><button onClick={() => setReelPaused(true)}>Pular</button></div>}<BankMap state={reelState ?? state} selected={selectedArea} onSelect={setSelectedArea} heat={heat} roundNo={displayRoundNo} speed={reelActive ? 4 : speed} idle={idleCountdown} event={reelEvent ?? latest} presentation={presenter}/><div className="caption"><span>{reelActive ? "● DESTAQUE" : idleTip ? "● DICA" : "● REGISTRO"}</span><p aria-live="polite" aria-atomic="true">{presenter ? reelEvent ? presentationEventSummary(reelEvent) : idleTip ?? (latest ? presentationEventSummary(latest) : "O banco segue em observação.") : reelEvent?.public_summary_pt ?? idleTip ?? state.captions.at(-1)?.text ?? (source === "demo" ? "Reprodução demonstrativa baseada no roteiro do projeto." : "O banco segue em observação.")}</p><time>{idleTip ? "" : clock(reelEvent?.twin_ts ?? latest?.twin_ts)}</time></div>{!reelActive && (source === "live" && followLive.current && !selectedRoundId && cursor >= timelineEvents.length ? <MoneyFlow incidentId={moneyIncidentId} presentation={presenter}/> : replayFlow && <MoneyFlow incidentId={moneyIncidentId} presentation={presenter} replaySnapshot={replayFlow}/>)}<RecoveryOverview events={visible} presentation={presenter}/></section>
      <aside className={`side-panel blue-panel mobile-${mobile}`}><div className="panel-title"><span className="sigil blue">◎</span><div><small>EQUIPE AZUL</small><h2>Defesa</h2></div><span className="count">07</span></div><AlertQueue events={visible} nowMs={displayNowMs} presentation={presenter} onSelect={setSelectedEvent}/><div className="subheading">SENTINELAS <span>24 HORAS POR DIA</span></div><div className="sentinels">{AREAS.map((area) => <SentinelRow key={area} area={area} status={state.sentinels[area]} ticks={recentTraffic} telemetry={liveTelemetry} nowMs={displayNowMs} isLive={source === "live" && followLive.current} onSelect={() => setSelectedArea(area)} />)}</div><div className="subheading">RESPOSTA <span>{blue.length} AGENTES</span></div><div className="response">{blue.length ? blue.slice(-5).map(([id, agent]) => <div key={id}><span>{agent.outcome ? "✓" : "●"}</span><strong>{agent.role.replace("_", " ")}</strong><small>{presenter ? agent.outcome ? "concluída" : "em ação" : agent.outcome ?? "em ação"}</small></div>) : <p>Sem incidentes em resposta.</p>}</div><AgentLivePanel events={visible} nowMs={displayNowMs} presentation={presenter} onSelect={setSelectedEvent}/><DefenseFlow events={visible} presentation={presenter} selectedId={highlightedDefenseId} onIncidentSelect={(incident) => { setSelectedDefenseIncident(incident); setSelectedEvent(null); }} onSelect={setSelectedEvent}/><div className="collateral">CLIENTES BLOQUEADOS INDEVIDAMENTE <strong>{state.honest_blocked}</strong></div></aside>
    </main>{operationMode !== "fault_lab" && <ThreeLaneTimeline events={visible} selectedIncident={highlightedDefenseId} presentation={presenter} attackEnabled={!defensiveCurrent} onSelect={setSelectedEvent}/>}<TelemetryPanel enabled={source === "live" && operationMode !== "none"} presentation={presenter} compact/><section className="timeline"><div className="timeline-head"><div><small>LINHA DO TEMPO</small><strong>{elapsed(timelineEvents[0]?.ts, latest?.ts)} <em>/ {elapsed(timelineEvents[0]?.ts, timelineEvents.at(-1)?.ts)}</em></strong></div><div className="controls"><button onClick={() => { followLive.current = false; setCursor(0); setPlaying(false); }} title="Início">|◀</button><button onClick={() => { followLive.current = false; if (!playing && cursor >= timelineEvents.length) setCursor(0); setPlaying((value) => !value); }} title="Reproduzir ou pausar">{playing ? "Ⅱ" : "▶"}</button>{([1, 4, 16] as const).map((value) => <button key={value} className={speed === value ? "active" : ""} onClick={() => setSpeed(value)}>{value}×</button>)}<button onClick={share} title="Compartilhar este momento">↗</button>{source === "live" && !followLive.current && <button onClick={() => { setSelectedRoundId(null); setCursor(events.length); setPlaying(false); followLive.current = true; }} title="Voltar ao vivo">●</button>}</div></div><div className="track"><input aria-label="Posição da reprodução" type="range" min="0" max={timelineEvents.length || 1} value={cursor} onChange={(event) => { const target = Number(event.target.value); if (showFps) seekProbe.current = { target, started: performance.now() }; followLive.current = false; setCursor(target); setPlaying(false); }}/><div className="markers">{timelineEvents.map((event, index) => IMPORTANT.has(event.type) ? <button key={event.seq} className={event.type.replaceAll(".", "-")} title={presenter ? presentationEventSummary(event) : event.public_summary_pt} style={{ left: `${index / Math.max(timelineEvents.length - 1, 1) * 100}%` }} onClick={() => { followLive.current = false; setCursor(index + 1); setPlaying(false); setSelectedEvent(event); }}/> : null)}</div></div><div className="chapters" aria-label="Capítulos da rodada">{chapters.map((chapter, index) => <button key={chapter.key} className={cursor >= chapter.cursor && (index === chapters.length - 1 || cursor < chapters[index + 1]!.cursor) ? "active" : ""} onClick={() => { followLive.current = false; setCursor(chapter.cursor); setPlaying(false); }} aria-label={`Ir para ${chapter.label.toLocaleLowerCase("pt-BR")}`}>{chapter.label}</button>)}</div><div className="recent">{recent.map((event) => <button key={event.seq} onClick={() => setSelectedEvent(event)}><time>{clock(event.twin_ts)}</time><span>{presenter ? presentationEventSummary(event) : event.public_summary_pt}</span></button>)}</div></section></>
    : page === "lab" ? <FaultLabPanel enabled={source === "live" &&
      operationMode === "fault_lab"} presentation={presenter}/>
    : page === "soc" ? <main className="soc-page"><div className="soc-page-heading"><small>OPERAÇÃO LOCAL</small><h1>Centro de operações de segurança</h1><p>Investigue alertas recentes e siga os eventos correlacionados por trace e EndToEndId.</p></div>
      {source === "live" && operationMode !== "none" ? <><SocMetricsPanel metrics={socMetrics} presentation={presenter}/><TelemetryPanel enabled presentation={presenter} showRiskReview /></> :
        <p className="soc-page-unavailable">A visão do SOC estará disponível quando o banco local estiver em operação.</p>}
    </main>
    : page === "bank" ? source === "live" && operationMode !== "none" ?
      <BankOperationsPanel enabled presentation={presenter} /> : <main className="bank-page"><p className="bank-empty">A operação bancária estará disponível quando o banco local estiver ativo.</p></main>
    : page === "history" ? <HistoryPage rounds={rounds} frames={historyFrames} opening={archiveFrames.opening} low={archiveFrames.low} stats={historyStats} source={source} roundMode={roundMode} presentation={presenter}
      onOpen={(round) => { void openRound(round); }}
      onDemo={() => { navigatePage("control"); setCursor(0); setPlaying(true); }}/>
    : page === "score" ? <main className="page"><small>MÉTRICAS COM EVIDÊNCIA</small><h1>Pontuação</h1><p>Erros e impactos aparecem junto com os acertos.</p>
      <HealthTrend rounds={rounds} frames={historyFrames} opening={archiveFrames.opening}
        low={archiveFrames.low} onOpen={(round) => { void openRound(round); }}/>
      <AreaHeatmap rounds={rounds} frames={historyFrames} onOpen={(round) => { void openRound(round); }}/>
      <div className="score-grid"><article><small>EQUIPE VERMELHA</small><strong>{(scoreRound?.score?.red_points ?? scoreState?.score.red)?.toFixed(1) ?? "—"}</strong><span>pontos</span></article><article><small>EQUIPE AZUL</small><strong>{(scoreRound?.score?.blue_points ?? scoreState?.score.blue)?.toFixed(1) ?? "—"}</strong><span>pontos</span></article><article><small>IMPACTO OBSERVADO</small><strong>{presenter ? "Valor reservado" : scoreImpact ? money(scoreImpact.loss) : scoreRound?.score ? money(scoreRound.score.loss_cents) : scoreState ? money(loss) : "—"}</strong><span>moeda sintética</span></article><article><small>REJEIÇÕES / REVERSÕES</small><strong>{scoreState ? `${scoreState.rejections} / ${scoreState.rollbacks}` : "—"}</strong><span>decisões auditáveis</span></article></div><RoundStory event={narrativeEvent} presentation={presenter} onSelectRef={(seq) => { const found = events.find((event) => event.seq === seq); if (found) setSelectedEvent(found); }}/></main>
    : page === "customer" ? <CustomerInbox available={source === "live" && operationMode !== "none"} presentation={presenter}/>
    : page === "psp" ? <PspCustomerInbox available={source === "live" && operationMode !== "none"} presentation={presenter}/>
    : <main className="page about"><small>SISTEMA FICCIONAL</small><h1>O banco como organismo vivo.</h1><p>{`O Banco Vivo mostra uma instituição sintética em simulação. ${aboutModeText} Toda afirmação de efeito precisa de evidência no banco simulado.`}</p><div className="about-grid"><article><b>{operationMode === "fault_lab" ? "◇ LABORATÓRIO" : "◇ ATAQUE"}</b><p>{operationMode === "fault_lab" ? "Falhas locais controladas, sem agentes invasores." : operationMode === "defensive_only" ? "Desativado nesta execução." : "Hipóteses e testes controlados."}</p></article><article><b>◎ DEFESA</b><p>Alertas, contenção e correção.</p></article><article><b>◇ MEMÓRIA</b><p>Erros e aprendizados de cada rodada.</p></article></div><p>Clientes, saldos e transferências exibidos são sintéticos.</p></main>}
    {(selectedArea || selectedEvent) && <div className="drawer-overlay" onClick={() => { setSelectedArea(null); setSelectedEvent(null); }}><aside ref={drawerRef} className="drawer" role="dialog" aria-modal="true" aria-labelledby="inspection-title" onClick={(event) => event.stopPropagation()}><button className="close" aria-label="Fechar inspeção" onClick={() => { setSelectedArea(null); setSelectedEvent(null); }}>×</button><small>INSPEÇÃO · DADOS PÚBLICOS</small><h2 id="inspection-title">{selectedPublicEvent ? presenter ? presentationEventSummary(selectedPublicEvent) : selectedPublicEvent.public_summary_pt : selectedArea ? LABEL[selectedArea] : ""}</h2><p>{selectedPublicEvent ? `Evento ${selectedPublicEvent.seq} · ${clock(selectedPublicEvent.twin_ts ?? selectedPublicEvent.ts)}` : selectedArea ? state.area_states[selectedArea].replaceAll("_", " ") : ""}</p>{selectedDetails.length > 0 && <div className="fields">{selectedDetails.map(({ label, value }) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}</div>}{selectedArea && <div className="area-events"><h3>ATIVIDADE RECENTE</h3>{visible.filter((event) => event.area === selectedArea && IMPORTANT.has(event.type)).slice(-8).reverse().map((event) => <button key={event.seq} onClick={() => setSelectedEvent(event)}><time>{clock(event.twin_ts)}</time>{presenter ? presentationEventSummary(event) : event.public_summary_pt}</button>)}</div>}</aside></div>}
    {showFps && <output className="fps-probe" aria-label="Desempenho da reprodução">{
      fps === null ? "FPS --" : `FPS ${fps}`} · MIN {minimumFps ?? "--"} / {fpsSamples}s · {
      seekMs === null ? "SEEK --" : `SEEK ${seekMs} ms`}</output>}
  </div>;
}
createRoot(document.getElementById("root")!).render(<App/>);
