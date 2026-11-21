import { useEffect, useRef, useState } from "react";
import { DetectionCoverage } from "./DetectionCoverage.tsx";
import { RiskReviewPanel } from "./RiskReviewPanel.tsx";
import { IncidentEvidenceDetail, type IncidentEvidenceDetailData } from "./IncidentEvidenceDetail.tsx";
import { DeploymentObservation, type DeploymentObservationData } from "./DeploymentObservation.tsx";

interface LogEntry {
  id: number;
  ts: string;
  trace_id: string;
  e2e_id: string | null;
  card_token: string | null;
  rule_id: string | null;
  risk_score: number | null;
  reason_codes_json: string | null;
  user_id: string | null;
  source: string;
  category: string;
  action: string;
  outcome: "success" | "failure" | "unknown";
  severity: "info" | "warn" | "error";
  message: string;
  redacted: number;
}
interface SocAlert {
  alert_id: string;
  rule_id: string;
  area: string;
  severity: "low" | "medium" | "high" | "critical";
  entity: string;
  observed: Record<string, string | number>;
  first_seen: string;
  last_seen: string;
  count: number;
  evidence_ref: string;
  triage?: {
    owner_role: string;
    status: "pending" | "acknowledged" | "escalated";
    sla_seconds: number;
    queued_at_real: string;
    due_at_real: string;
    queue_seconds: number;
    acknowledged_by: string | null;
    acknowledged_at_real: string | null;
    escalated_at_real: string | null;
  } | null;
}
interface SocIncident {
  id: string;
  entity_key: string;
  area: string;
  severity: "low" | "medium" | "high" | "critical";
  state: string;
  alert_count: number;
  opened_at: string;
  last_seen_at: string;
}
interface IncidentEntityView {
  kind: "customer" | "other" | "restricted";
  customer?: { id: string; status: string; kyc_status: string; risk_score: number };
  accounts?: { id: string; kind: string; status: string }[];
  devices?: { id: string; first_seen_at: string; trusted_at: string | null;
    revoked_at: string | null; synthetic_geo: string | null }[];
  device_links?: { device_id: string; linked_customer_id: string }[];
  pix?: { id: string; amount_cents: number; status: string; initiated_at: string;
    end_to_end_id: string | null; direction: "in" | "out"; peer_account: string }[];
  relationships?: { peer_account: string; transfer_count: number; total_cents: number }[];
  risk?: { area: string; outcome: string; score: number; reason_codes_json: string;
    trace_id: string; created_at: string }[];
}
interface IncidentEvent {
  seq: number;
  ts: string;
  type: string;
  public_summary_pt: string;
  public: Record<string, unknown>;
}
interface IncidentDamage {
  last_assessed_open_cents: number | null;
  blocked_cents: number | null;
  escaped_cents: number | null;
  made_whole_cents: number | null;
  recovered_cents: number | null;
  absorbed_cents: number | null;
}
interface IncidentStep { key: string; seq?: number; type: string; phase?: string;
  attempt?: number | null; }
interface IncidentEvidence { key: string; kind: "patch.diff" | "ci.result" | "ci.failure" | "dossier.review";
  attempt: number | null; sha256?: string | null; truncated?: boolean;
  ready_for_review?: boolean; typecheck?: boolean; world_tests?: boolean | null;
  verdict?: "approve" | "reject" | "unknown"; findings_count?: number; }
interface IncidentPostmortem {
  mttd_s: number | null; mtta_s: number | null; mttc_s: number | null;
  mttr_fix_s: number | null; mttr_recovery_s: number | null;
  loss_cents: number; recovered_cents: number; absorbed_cents: number;
  permanent_actions: number;
}

const incidentStepsByType: Record<string, string> = {
  "incident.opened": "Alerta", "containment.applied": "Contenção",
  "damage.assessed": "Avaliação de dano", "task.opened": "Correção aberta",
  "patch.proposed": "Correção proposta", "review.rejected": "Revisão reprovada",
  "review.approved": "Revisão aprovada", "patch.merged": "Correção integrada",
  "deploy.succeeded": "Aplicação local", "deploy.rolled_back": "Reversão",
  "damage.restored": "Ressarcimento", "postmortem.published": "Postmortem",
  "postmortem.narrated": "Lições",
  "dossier.investigation": "Triagem", "dossier.incident_map": "Mapa forense",
  "dossier.root_cause": "Causa raiz", "dossier.fix_design": "Design",
  "ci.result": "CI", "ci.failure": "CI falhou",
  "dossier.review": "Revisor", "dossier.rejection_report": "Revisão detalhada",
  "dossier.damage_1": "Dano inicial", "dossier.restoration": "Plano de recuperação",
  "dossier.damage_2": "Segunda checagem", "dossier.hardening": "Hardening",
  "hardening.ci": "CI da regra", "hardening.rejection": "Redesenho da regra",
  "dossier.hardening_review": "Revisão da regra",
  "dossier.postmortem": "Relatório final",
};
const formatCents = (value: number) => (value / 100).toLocaleString("pt-BR", {
  style: "currency", currency: "BRL" });
const formatTime = (value: string) => new Date(value).toLocaleString("pt-BR", {
  timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit",
  hour: "2-digit", minute: "2-digit" });
const formatDuration = (seconds: number | null) => seconds === null ? "Sem dado" :
  seconds < 60 ? `${seconds.toFixed(0)} s` : `${(seconds / 60).toFixed(1)} min`;
function alertAge(firstSeen: string, now: number): string {
  const started = Date.parse(firstSeen);
  if (!Number.isFinite(started)) return "idade indisponível";
  const minutes = Math.max(0, Math.floor((now - started) / 60_000));
  if (minutes < 1) return "agora";
  if (minutes < 60) return `há ${minutes} min`;
  const hours = Math.floor(minutes / 60);
  return hours < 24 ? `há ${hours} h` : `há ${Math.floor(hours / 24)} d`;
}

const sources = ["all", "gateway", "auth", "pix", "spi", "dict", "ledger", "cards", "network", "risk", "siem", "audit", "agent"];
const sourceLabel: Record<string, string> = {
  all: "Todas", gateway: "Entrada", auth: "Acesso", pix: "Pix", ledger: "Razão",
  cards: "Cartões", spi: "SPI", dict: "DICT", network: "Bandeira", risk: "Risco", siem: "SOC", agent: "Agentes",
  api_gateway: "Entrada", accounts: "Contas", loans: "Crédito", audit: "Auditoria",
};
const displayedSource = (source: string, presentation: boolean): string =>
  sourceLabel[source] ?? (presentation ? "Área protegida" : source);
const severityLabel = { low: "BAIXA", medium: "MÉDIA", high: "ALTA", critical: "CRÍTICA" };
const triageOwnerLabel: Record<string, string> = {
  identity_oncall: "Identidade", payments_oncall: "Pagamentos",
  cards_oncall: "Cartões", credit_oncall: "Crédito",
  platform_oncall: "Plataforma", finance_oncall: "Controle financeiro",
};

function parseEntry(value: unknown): LogEntry | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  if (!Number.isSafeInteger(row.id) || typeof row.ts !== "string" ||
    typeof row.trace_id !== "string" || (row.e2e_id !== null && row.e2e_id !== undefined &&
      typeof row.e2e_id !== "string") || typeof row.source !== "string" ||
    typeof row.category !== "string" ||
    typeof row.action !== "string" || typeof row.message !== "string" ||
    (row.user_id !== null && row.user_id !== undefined &&
      typeof row.user_id !== "string") ||
    !["success", "failure", "unknown"].includes(String(row.outcome)) ||
    !["info", "warn", "error"].includes(String(row.severity))) return null;
  if (row.risk_score !== null && row.risk_score !== undefined &&
    (!Number.isSafeInteger(row.risk_score) || Number(row.risk_score) < 0 || Number(row.risk_score) > 1000))
    return null;
  if (row.reason_codes_json !== null && row.reason_codes_json !== undefined &&
    typeof row.reason_codes_json !== "string") return null;
  if ((row.card_token !== null && row.card_token !== undefined &&
    typeof row.card_token !== "string") ||
    (row.rule_id !== null && row.rule_id !== undefined && typeof row.rule_id !== "string"))
    return null;
  return { ...row, user_id: row.user_id ?? null, e2e_id: row.e2e_id ?? null,
    card_token: row.card_token ?? null, rule_id: row.rule_id ?? null,
    risk_score: row.risk_score ?? null,
    reason_codes_json: row.reason_codes_json ?? null } as unknown as LogEntry;
}

function parseReasonCodes(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const value: unknown = JSON.parse(raw);
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
  } catch { return []; }
}
function riskReasons(entry: LogEntry): string[] { return parseReasonCodes(entry.reason_codes_json); }
function detectionNarrative(entry: LogEntry): string | null {
  if (entry.source === "risk" && entry.action === "decision") return "Decisão imediata";
  if (entry.source === "siem" && entry.action === "alert") return "Alerta posterior do SOC";
  return null;
}

export function TelemetryPanel({ enabled, presentation = false, showRiskReview = false, compact = false }: {
  enabled: boolean; presentation?: boolean; showRiskReview?: boolean; compact?: boolean }) {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [filter, setFilter] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [query, setQuery] = useState("");
  const [customerFilter, setCustomerFilter] = useState("");
  const [frozenEntries, setFrozenEntries] = useState<LogEntry[] | null>(null);
  const recentIds = useRef(new Map<number, { second: number; source: string }>());
  const [recentCount, setRecentCount] = useState(0);
  const [sourceRates, setSourceRates] = useState<[string, number][]>([]);
  const [connection, setConnection] = useState<"connecting" | "live" | "retrying">("connecting");
  const [traceId, setTraceId] = useState<string | null>(null);
  const [traceEntries, setTraceEntries] = useState<LogEntry[]>([]);
  const [staffLogs, setStaffLogs] = useState(false);
  useEffect(() => { if (!staffLogs) setCustomerFilter(""); }, [staffLogs]);
  const [alerts, setAlerts] = useState<SocAlert[]>([]);
  const [ackPending, setAckPending] = useState<string | null>(null);
  const [ackError, setAckError] = useState<string | null>(null);
  const [alertNow, setAlertNow] = useState<number | null>(null);
  const [alertTotal, setAlertTotal] = useState(0);
  const [riskReviewSummary, setRiskReviewSummary] = useState<{
    pending_total: number; due_within_hour: number;
    unacknowledged_due_within_hour: number } | null>(null);
  const [incidents, setIncidents] = useState<SocIncident[]>([]);
  const [openIncidentTotal, setOpenIncidentTotal] = useState(0);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [loadedEntity, setLoadedEntity] = useState<{
    incidentId: string; presentation: boolean; staffLogs: boolean;
    view: IncidentEntityView | null;
  } | null>(null);
  const [loadedTimeline, setLoadedTimeline] = useState<{
    incidentId: string; events: IncidentEvent[]; steps: IncidentStep[];
    evidence: IncidentEvidence[]; damage: IncidentDamage | null;
    postmortem: IncidentPostmortem | null;
  } | null>(null);
  const [selectedEvidenceKey, setSelectedEvidenceKey] = useState<string | null>(null);
  const [evidenceDetail, setEvidenceDetail] = useState<IncidentEvidenceDetailData | null>(null);
  const [deploymentView, setDeploymentView] = useState<{
    incidentId: string; deployment: DeploymentObservationData | null } | null>(null);
  const incidentEntity = loadedEntity?.incidentId === selectedIncidentId &&
    loadedEntity.presentation === presentation && loadedEntity.staffLogs === staffLogs ?
    loadedEntity.view : null;
  const timeline = loadedTimeline?.incidentId === selectedIncidentId ? loadedTimeline : null;
  const incidentEvents = timeline?.events ?? [];
  const incidentSteps = timeline?.steps ?? [];
  const incidentEvidence = timeline?.evidence ?? [];
  const incidentDamage = timeline?.damage ?? null;
  const incidentPostmortem = timeline?.postmortem ?? null;
  useEffect(() => {
    if (!enabled) return;
    let disposed = false;
    const refresh = () => { void fetch("/api/operator/session", { cache: "no-store" })
      .then((response) => response.ok ? response.json() : null)
      .then((value: { authenticated?: boolean } | null) => {
        if (!disposed) setStaffLogs(value?.authenticated === true);
      }).catch(() => { if (!disposed) setStaffLogs(false); }); };
    const sessionChanged = () => {
      setStaffLogs(false);
      setAlerts([]);
      setIncidents([]);
      setLoadedEntity(null);
      setLoadedTimeline(null);
      setSelectedEvidenceKey(null); setEvidenceDetail(null);
      setDeploymentView(null);
      refresh();
    };
    refresh();
    window.addEventListener("bv-operator-session", sessionChanged);
    return () => { disposed = true; window.removeEventListener("bv-operator-session", sessionChanged); };
  }, [enabled]);
  useEffect(() => {
    if (!enabled) return;
    setEntries([]); setFrozenEntries(null); setTraceId(null); setTraceEntries([]);
    recentIds.current.clear(); setRecentCount(0); setSourceRates([]);
    setConnection("connecting");
    const stream = new EventSource(staffLogs && !presentation ?
      "/api/operator/telemetry/stream" : "/api/telemetry/stream");
    stream.onopen = () => setConnection("live");
    stream.onerror = () => { setConnection("retrying");
      if (staffLogs) window.dispatchEvent(new Event("bv-operator-session")); };
    stream.addEventListener("reset", () => {
      recentIds.current.clear();
      setRecentCount(0);
      setSourceRates([]);
      setEntries([]);
    });
    stream.addEventListener("telemetry", (message) => {
      try {
        const entry = parseEntry(JSON.parse((message as MessageEvent).data));
        if (!entry) return;
        const second = Math.floor(Date.parse(entry.ts) / 1000);
        if (Number.isFinite(second)) recentIds.current.set(entry.id,
          { second, source: entry.source });
        setEntries((current) => current.some((item) => item.id === entry.id) ? current :
          [...current, entry].slice(-500));
      } catch { /* Ignore malformed frames and keep the stream open. */ }
    });
    return () => stream.close();
  }, [enabled, presentation, staffLogs]);
  useEffect(() => {
    if (!enabled) return;
    const timer = window.setInterval(() => {
      const threshold = Math.floor(Date.now() / 1000) - 59;
      const rates = new Map<string, number>();
      for (const [id, item] of recentIds.current) {
        if (item.second < threshold) recentIds.current.delete(id);
        else if (item.second >= threshold + 50)
          rates.set(item.source, (rates.get(item.source) ?? 0) + 1);
      }
      setRecentCount(recentIds.current.size);
      setSourceRates([...rates].sort((left, right) => right[1] - left[1]));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [enabled]);
  useEffect(() => {
    if (!enabled || compact) return;
    let disposed = false;
    const staff = staffLogs && !presentation;
    setAlerts([]);
    setIncidents([]);
    const refresh = () => { void fetch(staff ? "/api/operator/soc/alerts?limit=5" :
      "/api/soc/alerts?limit=5", { cache: "no-store" })
      .then((response) => response.ok ? response.json() : null)
      .then((payload: { alerts?: SocAlert[]; total?: number; twin_now?: string } | null) => {
        if (!disposed && Array.isArray(payload?.alerts)) {
          setAlerts(payload.alerts);
          const twinNow = Date.parse(payload.twin_now ?? "");
          setAlertNow(Number.isFinite(twinNow) ? twinNow : null);
          const total = payload.total;
          setAlertTotal(typeof total === "number" && Number.isSafeInteger(total) && total >= 0
            ? total : payload.alerts.length);
        }
      }).catch(() => undefined);
      void fetch(staff ? "/api/operator/soc/incidents?limit=5" :
        "/api/soc/incidents?limit=5", { cache: "no-store" })
        .then((response) => response.ok ? response.json() : null)
        .then((payload: { incidents?: SocIncident[]; open_total?: number } | null) => {
          if (!disposed && Array.isArray(payload?.incidents)) {
            setIncidents(payload.incidents);
            const total = payload.open_total;
            setOpenIncidentTotal(typeof total === "number" && Number.isSafeInteger(total) && total >= 0
              ? total : payload.incidents.filter((item) => item.state !== "resolved").length);
          }
        }).catch(() => undefined);
      void fetch("/api/soc/risk-review-summary", { cache: "no-store" })
        .then((response) => response.ok ? response.json() : null)
        .then((payload: { pending_total?: number; due_within_hour?: number;
          unacknowledged_due_within_hour?: number } | null) => {
          const pending = payload?.pending_total;
          const due = payload?.due_within_hour;
          const unacknowledged = payload?.unacknowledged_due_within_hour;
          if (!disposed && typeof pending === "number" && typeof due === "number" &&
            typeof unacknowledged === "number" && Number.isSafeInteger(pending) &&
            Number.isSafeInteger(due) && Number.isSafeInteger(unacknowledged) &&
            pending >= 0 && due >= 0 && due <= pending &&
            unacknowledged >= 0 && unacknowledged <= due)
            setRiskReviewSummary({ pending_total: pending, due_within_hour: due,
              unacknowledged_due_within_hour: unacknowledged });
        }).catch(() => undefined); };
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => { disposed = true; window.clearInterval(timer); };
  }, [enabled, presentation, staffLogs, compact]);
  useEffect(() => {
    if (!traceId) { setTraceEntries([]); return; }
    const controller = new AbortController();
    const prefix = staffLogs && !presentation ? "/api/operator/telemetry/traces/" :
      "/api/telemetry/traces/";
    void fetch(`${prefix}${encodeURIComponent(traceId)}`, { signal: controller.signal })
      .then((response) => response.ok ? response.json() : null)
      .then((payload: { entries?: unknown[] } | null) => {
        if (!controller.signal.aborted) setTraceEntries((payload?.entries ?? [])
          .map(parseEntry).filter((entry): entry is LogEntry => Boolean(entry)));
      }).catch(() => { if (!controller.signal.aborted) setTraceEntries([]); });
    return () => controller.abort();
  }, [traceId, presentation, staffLogs]);
  useEffect(() => {
    if (!selectedIncidentId) { setLoadedTimeline(null); setLoadedEntity(null); return; }
    const controller = new AbortController();
    setLoadedTimeline(null);
    setLoadedEntity(null);
    const refresh = () => { void fetch(`/api/soc/incidents/${encodeURIComponent(selectedIncidentId)}/events`,
      { signal: controller.signal, cache: "no-store" })
      .then((response) => response.ok ? response.json() : null)
      .then((payload: { events?: IncidentEvent[]; steps?: IncidentStep[];
        evidence?: IncidentEvidence[];
        damage?: IncidentDamage; postmortem?: IncidentPostmortem | null } | null) => {
        if (!controller.signal.aborted) {
          setLoadedTimeline({ incidentId: selectedIncidentId,
            events: Array.isArray(payload?.events) ? payload.events : [],
            steps: Array.isArray(payload?.steps) ? payload.steps : [],
            evidence: Array.isArray(payload?.evidence) ? payload.evidence : [],
            damage: payload?.damage ?? null, postmortem: payload?.postmortem ?? null });
        }
      }).catch(() => undefined);
      const prefix = staffLogs && !presentation ? "/api/operator/soc/incidents/" :
        "/api/soc/incidents/";
      void fetch(`${prefix}${encodeURIComponent(selectedIncidentId)}/entity`,
        { signal: controller.signal, cache: "no-store" })
        .then((response) => response.ok ? response.json() : null)
        .then((payload: IncidentEntityView | null) => {
          if (!controller.signal.aborted)
            setLoadedEntity({ incidentId: selectedIncidentId, presentation, staffLogs,
              view: payload });
        }).catch(() => undefined); };
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => { window.clearInterval(timer); controller.abort(); };
  }, [selectedIncidentId, presentation, staffLogs]);
  useEffect(() => {
    setEvidenceDetail(null);
    if (!selectedIncidentId || !selectedEvidenceKey || !staffLogs || presentation) return;
    const match = /^case:([1-9]\d{0,14})$/.exec(selectedEvidenceKey);
    if (!match) return;
    const controller = new AbortController();
    void fetch(`/api/operator/soc/incidents/${encodeURIComponent(selectedIncidentId)}/evidence/${match[1]}`,
      { signal: controller.signal, cache: "no-store" })
      .then((response) => {
        if (response.status === 401) window.dispatchEvent(new Event("bv-operator-session"));
        return response.ok ? response.json() as Promise<IncidentEvidenceDetailData> : null;
      })
      .then((detail) => { if (!controller.signal.aborted) setEvidenceDetail(detail); })
      .catch(() => { if (!controller.signal.aborted) setEvidenceDetail(null); });
    return () => controller.abort();
  }, [selectedIncidentId, selectedEvidenceKey, presentation, staffLogs]);
  useEffect(() => {
    if (!selectedIncidentId || !staffLogs || presentation) return;
    const controller = new AbortController();
    const refresh = () => { void fetch(`/api/operator/soc/incidents/${
      encodeURIComponent(selectedIncidentId)}/deployment`,
    { signal: controller.signal, cache: "no-store" })
      .then((response) => {
        if (response.status === 401) window.dispatchEvent(new Event("bv-operator-session"));
        return response.ok ? response.json() as Promise<{
          deployment: DeploymentObservationData | null }> : null;
      })
      .then((payload) => { if (!controller.signal.aborted)
        setDeploymentView({ incidentId: selectedIncidentId,
          deployment: payload?.deployment ?? null }); })
      .catch(() => { if (!controller.signal.aborted)
        setDeploymentView({ incidentId: selectedIncidentId, deployment: null }); }); };
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => { window.clearInterval(timer); controller.abort(); };
  }, [selectedIncidentId, staffLogs, presentation]);
  if (!enabled) return null;
  const needle = presentation ? "" : query.trim().toLocaleLowerCase("pt-BR");
  const customerNeedle = staffLogs && !presentation ? customerFilter.trim() : "";
  const visible = (frozenEntries ?? entries).filter((entry) =>
    (filter === "all" || (filter === "audit" ? entry.category === "audit" : entry.source === filter)) &&
    (severity === "all" || entry.severity === severity) &&
    (!customerNeedle || entry.user_id === customerNeedle) &&
    (!needle || [entry.action, entry.message, entry.trace_id, entry.e2e_id ?? "",
      entry.card_token ?? "", entry.rule_id ?? "",
      ...riskReasons(entry)]
      .some((value) => value.toLocaleLowerCase("pt-BR").includes(needle)))).slice(compact ? -3 : -40).reverse();
  const selectedAlert = alerts.find((alert) => alert.alert_id === selectedAlertId);
  const acknowledgeAlert = async (alertId: string) => {
    setAckPending(alertId); setAckError(null);
    try {
      const response = await fetch(`/api/operator/soc/alerts/${encodeURIComponent(alertId)}/acknowledge`,
        { method: "POST" });
      if (!response.ok) throw new Error("ACK_FAILED");
      const triage = await response.json() as NonNullable<SocAlert["triage"]>;
      setAlerts((current) => current.map((alert) => alert.alert_id === alertId ?
        { ...alert, triage } : alert));
    } catch { setAckError("Não foi possível registrar ciência. Tente novamente."); }
    finally { setAckPending(null); }
  };
  const loss = incidentDamage?.last_assessed_open_cents ?? null;
  const madeWhole = incidentDamage?.made_whole_cents ?? null;
  const damageAmount = (value: number | null, absent: string) => presentation ?
    "Valor oculto" : value === null ? absent : formatCents(value);
  const steps = incidentSteps.filter((event) => incidentStepsByType[event.type]);
  const caseDocuments = incidentSteps.filter((event) =>
    ["dossier.incident_map", "dossier.root_cause", "dossier.fix_design"].includes(event.type));
  const selectedIncident = incidents.find((incident) => incident.id === selectedIncidentId);
  const workflowActive = selectedIncident && ["open", "contained", "patching",
    "awaiting_next_window"].includes(selectedIncident.state);
  const narrated = incidentEvents.filter((event) => event.type === "postmortem.narrated").at(-1);
  return <section className={`telemetry-panel${compact ? " telemetry-compact" : ""}`} aria-label="Logs estruturados ao vivo">
    {!compact && <>
    <div className="soc-risk-review" aria-label="Revisão Pix pendente">
      <div><small>REVISÃO PIX</small><strong>{riskReviewSummary === null ? "—" :
        `${riskReviewSummary.pending_total} ${riskReviewSummary.pending_total === 1 ? "caso aguardando" : "casos aguardando"}`}</strong></div>
      <span>{riskReviewSummary === null ? "Prazo indisponível" :
        `${riskReviewSummary.due_within_hour} ${riskReviewSummary.due_within_hour === 1 ? "caso vence" : "casos vencem"} em até 1 h do banco · ${riskReviewSummary.unacknowledged_due_within_hour} sem ciência`}</span>
      <small>{showRiskReview && !presentation ?
        "Detalhes e decisão na fila autenticada abaixo." :
        "Revisão na área autenticada do SOC."}</small>
    </div>
    {showRiskReview && !presentation && <RiskReviewPanel />}
    {showRiskReview && staffLogs && !presentation && <DetectionCoverage />}
    <div className="soc-alerts"><div><small>FILA DO SOC · 24 H</small><strong>{alertTotal} {alertTotal === 1 ? "alerta recente" : "alertas recentes"}</strong>
      {alertTotal > alerts.length && <small>{alerts.length} mais recentes exibidos</small>}</div>
      {alerts.length ? <div className="soc-alert-list">{alerts.map((alert) =>
        <button key={alert.alert_id} className={`soc-alert ${alert.severity}`}
          aria-expanded={selectedAlertId === alert.alert_id}
          onClick={() => { setAckError(null);
            setSelectedAlertId((current) => current === alert.alert_id ? null : alert.alert_id); }}>
          <strong>{presentation ? "REGRA" : alert.rule_id}</strong><span>{displayedSource(alert.area, presentation)}</span>
          <em>{severityLabel[alert.severity]}</em>
          <span className="soc-alert-entity">{presentation ? "Entidade oculta" : alert.entity}</span>
          <small>{alertNow === null ? "idade indisponível" : alertAge(alert.first_seen, alertNow)} · {alert.count} {alert.count === 1 ? "ocorrência" : "ocorrências"}</small>
        </button>)}</div> : <p>Sem alertas recentes.</p>}
      {selectedAlert && <div className="soc-alert-detail" role="region" aria-label={presentation ? "Detalhes do alerta" : `Detalhes do alerta ${selectedAlert.rule_id}`}>
        <div><strong>{presentation ? "REGRA" : selectedAlert.rule_id} · {displayedSource(selectedAlert.area, presentation)}</strong>
          <button onClick={() => setSelectedAlertId(null)} aria-label="Fechar alerta">×</button></div>
        <dl><div><dt>Entidade</dt><dd>{presentation ? "Oculta na apresentação" : selectedAlert.entity}</dd></div>
          <div><dt>Primeiro sinal</dt><dd>{new Date(selectedAlert.first_seen).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}</dd></div>
          <div><dt>Último sinal</dt><dd>{new Date(selectedAlert.last_seen).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}</dd></div>
          {staffLogs && !presentation && selectedAlert.triage && <>
            <div><dt>Dono da triagem</dt><dd>{triageOwnerLabel[selectedAlert.triage.owner_role] ?? selectedAlert.triage.owner_role}</dd></div>
            <div><dt>Prazo</dt><dd>{formatTime(selectedAlert.triage.due_at_real)} · {formatDuration(selectedAlert.triage.sla_seconds)}</dd></div>
            <div><dt>Tempo na fila</dt><dd>{formatDuration(selectedAlert.triage.queue_seconds)} · {
              selectedAlert.triage.status === "acknowledged" ? "Ciência registrada" :
                selectedAlert.triage.status === "escalated" ? "Escalonado" : "Aguardando ciência"}</dd></div>
          </>}
          {!presentation && <div><dt>Evidência</dt><dd>{selectedAlert.evidence_ref}</dd></div>}
          {!presentation && Object.entries(selectedAlert.observed).map(([key, value]) =>
            <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{String(value)}</dd></div>)}</dl>
        {staffLogs && !presentation && selectedAlert.triage &&
          selectedAlert.triage.status !== "acknowledged" && <div className="soc-triage-action">
            <button disabled={ackPending === selectedAlert.alert_id}
              onClick={() => { void acknowledgeAlert(selectedAlert.alert_id); }}>
              {ackPending === selectedAlert.alert_id ? "Registrando…" : "Registrar ciência"}
            </button>
            {ackError && <span role="alert">{ackError}</span>}
          </div>}
      </div>}</div>
    <div className="soc-incidents"><div><small>INCIDENTES CORRELACIONADOS</small>
      <strong>{openIncidentTotal} em aberto</strong>
      {openIncidentTotal > incidents.filter((item) => item.state !== "resolved").length &&
        <small>{incidents.length} mais recentes exibidos</small>}</div>
      {incidents.length ? <div className="soc-incident-list">{incidents.map((incident) =>
        <article key={incident.id} className={`soc-incident ${incident.severity}`}>
          <div><strong>{displayedSource(incident.area, presentation)}</strong>
            <em>{incident.state === "resolved" ? "RESOLVIDO" : "EM ABERTO"}</em></div>
          <span>{presentation ? "Entidade oculta na apresentação" : incident.entity_key}</span>
          <small>{incident.alert_count} {incident.alert_count === 1 ? "alerta" : "alertas"} · último sinal {new Date(incident.last_seen_at).toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo" })}</small>
          <button aria-expanded={selectedIncidentId === incident.id}
            onClick={() => { setSelectedEvidenceKey(null); setEvidenceDetail(null);
              setSelectedIncidentId((current) => current === incident.id ? null : incident.id); }}>
            {selectedIncidentId === incident.id ? "Fechar linha do tempo" : "Ver linha do tempo"}
          </button>
        </article>)}</div> : <p>Sem incidentes correlacionados.</p>}</div>
    {selectedIncidentId && <div className="soc-incident-timeline" role="region" aria-label="Linha do tempo do incidente">
      <div><strong>INCIDENTE · {presentation ? "IDENTIFICAÇÃO OCULTA" : selectedIncidentId}</strong>
        <button onClick={() => { setSelectedEvidenceKey(null); setSelectedIncidentId(null); }}
          aria-label="Fechar linha do tempo">×</button></div>
      {incidentEntity?.kind === "customer" && incidentEntity.customer && <section
        className="soc-entity" aria-label="Visão da entidade afetada">
        <h3>Entidade 360</h3>
        <div className="soc-entity-summary">
          <span>Cliente <strong>{presentation ? "Identidade oculta" : incidentEntity.customer.id}</strong></span>
          <span>Situação <strong>{presentation ? "Oculta" : incidentEntity.customer.status}</strong></span>
          <span>KYC <strong>{presentation ? "Oculto" : incidentEntity.customer.kyc_status}</strong></span>
          <span>Risco <strong>{presentation ? "Oculto" : incidentEntity.customer.risk_score}</strong></span>
          <span>Contas exibidas <strong>{incidentEntity.accounts?.length ?? 0}</strong></span>
          <span>Dispositivos exibidos <strong>{incidentEntity.devices?.length ?? 0}</strong></span>
        </div>
        <div className="soc-entity-columns">
          <div><h4>Contas e dispositivos</h4>
            {(incidentEntity.accounts ?? []).map((account) => <p key={account.id}>Conta {
              presentation ? "oculta" : account.id} · {presentation ? "detalhes ocultos" :
                `${account.kind} · ${account.status}`}</p>)}
            {(incidentEntity.devices ?? []).map((device) => <p key={device.id}>Dispositivo {
              presentation ? "oculto" : device.id} · {device.revoked_at ? "revogado" :
                device.trusted_at ? "confiável" : "novo"} · desde {formatTime(device.first_seen_at)}{
                !presentation && device.synthetic_geo ? ` · ${device.synthetic_geo}` : ""}</p>)}
          </div>
          <div><h4>Decisões de risco recentes</h4>
            {(incidentEntity.risk ?? []).length ? (incidentEntity.risk ?? []).slice(0, 6)
              .map((decision, index) => <p key={`${decision.trace_id}-${index}`}>{
                formatTime(decision.created_at)} · {displayedSource(decision.area, presentation)} · {
                  presentation ? "decisão registrada" : decision.outcome} · {presentation ? "score e sinais ocultos" :
                  `score ${decision.score} · ${parseReasonCodes(decision.reason_codes_json).join(", ") || "sem sinal"}`}</p>) :
              <p>Sem decisão de risco recente.</p>}
          </div>
        </div>
        <div className="soc-entity-relations" aria-label="Relações por Pix liquidado">
          <h4>Relações Pix</h4>
          <div className="soc-entity-graph"><strong>Cliente afetado</strong><ul>{
            (incidentEntity.relationships ?? []).length ?
              (incidentEntity.relationships ?? []).map((link, index) => <li key={link.peer_account}>
                <span>{presentation ? `Destino ${index + 1}` : link.peer_account}</span>
                <small>{link.transfer_count} Pix{presentation ? "" : ` · ${formatCents(link.total_cents)}`}</small>
              </li>) : <li>Sem contraparte liquidada.</li>}</ul></div>
        </div>
        {(incidentEntity.device_links ?? []).length > 0 && <div className="soc-entity-relations"
          aria-label="Relações por dispositivo compartilhado">
          <h4>Dispositivos compartilhados</h4>
          <div className="soc-entity-graph"><strong>Cliente afetado</strong><ul>{
            (incidentEntity.device_links ?? []).map((link, index) => <li
              key={`${link.device_id}-${link.linked_customer_id}`}>
              <span>{presentation ? `Cliente relacionado ${index + 1}` : link.linked_customer_id}</span>
              <small>mesmo dispositivo {presentation ? "oculto" : link.device_id}</small>
            </li>)}</ul></div>
        </div>}
        {(incidentEntity.pix ?? []).length > 0 && <div className="soc-entity-pix">
          <h4>Pix recentes</h4><ol>{(incidentEntity.pix ?? []).slice(0, 6).map((transfer) =>
            <li key={transfer.id}>{formatTime(transfer.initiated_at)} · {
              transfer.direction === "out" ? "Saída" : "Entrada"} · {
                presentation ? "estado oculto" : transfer.status} · {
              presentation ? "valor e contraparte ocultos" :
                `${formatCents(transfer.amount_cents)} · ${transfer.peer_account}${
                  transfer.end_to_end_id ? ` · ${transfer.end_to_end_id}` : ""}`}</li>)}</ol>
        </div>}
      </section>}
      {incidentEntity?.kind === "restricted" && <p>Detalhes da entidade disponíveis após entrar como operador local.</p>}
      {incidentEntity?.kind === "other" && <p>Esta entidade não está vinculada a um cliente local.</p>}
      {steps.length > 0 && <div className="soc-incident-workflow" aria-label="Etapas registradas da resposta">
        {steps.map((event, index) => <span key={event.key} className={[
          event.type === "review.rejected" || event.type === "deploy.rolled_back" ||
            event.type === "hardening.rejection" ? "setback" : "",
          workflowActive && index === steps.length - 1 ? "active" : "",
        ].filter(Boolean).join(" ")}>{event.type === "patch.merged" &&
            event.phase === "hardening" ? "Nova regra de detecção" : incidentStepsByType[event.type]}
            {event.attempt && event.attempt > 1 ? ` ${event.attempt}` : ""}</span>)}
      </div>}
      {staffLogs && !presentation && caseDocuments.length > 0 && <section
        className="soc-incident-evidence" aria-label="Diagnóstico e desenhos da correção">
        <h3>Diagnóstico e desenhos da correção</h3>
        <div>{caseDocuments.map((item) => <article key={item.key}>
          <small>{item.attempt ? `TENTATIVA ${item.attempt}` : "DIAGNÓSTICO"}</small>
          <strong>{item.type === "dossier.incident_map" ? "Mapa forense" :
            item.type === "dossier.root_cause" ? "Causa raiz" : "Desenho da correção"}</strong>
          <button aria-expanded={selectedEvidenceKey === item.key}
            onClick={() => setSelectedEvidenceKey((current) => current === item.key ? null : item.key)}>
            {selectedEvidenceKey === item.key ? "Fechar detalhes" : "Ver detalhes"}</button>
        </article>)}</div>
        {evidenceDetail?.key === selectedEvidenceKey &&
          caseDocuments.some((item) => item.key === selectedEvidenceKey) &&
          <IncidentEvidenceDetail evidence={evidenceDetail}
            onClose={() => setSelectedEvidenceKey(null)}/>}
      </section>}
      {incidentEvidence.length > 0 && <section className="soc-incident-evidence" aria-label="Evidências da correção">
        <h3>Evidências da correção</h3>
        <div>{incidentEvidence.map((item) => <article key={item.key}>
          <small>{item.attempt === null ? "TENTATIVA" : `TENTATIVA ${item.attempt}`}</small>
          {item.kind === "patch.diff" ? <><strong>Alteração registrada</strong>
            <span>{presentation ? "Hash oculto na apresentação" : item.sha256 ?
              `SHA-256 ${item.sha256.slice(0, 12)}…${item.truncated ? " · resumo parcial" : ""}` :
              "Hash indisponível"}</span></> : item.kind === "ci.result" ? <>
            <strong>{item.ready_for_review ? "CI pronta para revisão" : "CI com pendências"}</strong>
            <span>Tipos {item.typecheck ? "aprovados" : "pendentes"} · testes {
              item.world_tests === null ? "não executados" : item.world_tests ? "aprovados" : "pendentes"}</span>
          </> : item.kind === "ci.failure" ? <>
            <strong>CI falhou</strong><span>Tipos {item.typecheck ? "aprovados" : "pendentes"} · testes {
              item.world_tests ? "aprovados" : "pendentes"}</span>
          </> : <><strong>{item.verdict === "approve" ? "Revisão aprovada" :
            item.verdict === "reject" ? "Revisão reprovada" : "Revisão registrada"}</strong>
            <span>{item.findings_count ?? 0} achados registrados</span></>}
          {staffLogs && !presentation && <button aria-expanded={selectedEvidenceKey === item.key}
            onClick={() => setSelectedEvidenceKey((current) => current === item.key ? null : item.key)}>
            {selectedEvidenceKey === item.key ? "Fechar detalhes" : "Ver detalhes"}</button>}
        </article>)}</div>
        {staffLogs && !presentation && evidenceDetail?.key === selectedEvidenceKey &&
          incidentEvidence.some((item) => item.key === selectedEvidenceKey) &&
          <IncidentEvidenceDetail evidence={evidenceDetail}
            onClose={() => setSelectedEvidenceKey(null)}/>}
      </section>}
      {staffLogs && !presentation && deploymentView?.incidentId === selectedIncidentId &&
        deploymentView.deployment && <DeploymentObservation
          deployment={deploymentView.deployment}/>}
      {(loss !== null || madeWhole !== null) && <div className="soc-incident-damage" aria-label="Cascata do dano financeiro">
        <span>Aberto na última avaliação <strong>{damageAmount(loss, "Aguardando avaliação")}</strong></span>
        <span>Bloqueado na avaliação <strong>{damageAmount(incidentDamage?.blocked_cents ?? null, "Sem dado")}</strong></span>
        <span>Escapou na avaliação <strong>{damageAmount(incidentDamage?.escaped_cents ?? null, "Sem dado")}</strong></span>
        <span>Devolvido ao cliente <strong>{damageAmount(madeWhole, "Aguardando restauração")}</strong></span>
        <span>Recuperado <strong>{damageAmount(incidentDamage?.recovered_cents ?? null, "Sem detalhe")}</strong></span>
        <span>Absorvido pelo banco <strong>{damageAmount(incidentDamage?.absorbed_cents ?? null, "Sem detalhe")}</strong></span>
      </div>}
      {incidentPostmortem && <div className="soc-incident-damage" aria-label="Postmortem do incidente">
        <span>Detecção <strong>{formatDuration(incidentPostmortem.mttd_s)}</strong></span>
        <span>Primeira ação <strong>{formatDuration(incidentPostmortem.mtta_s)}</strong></span>
        <span>Contenção <strong>{formatDuration(incidentPostmortem.mttc_s)}</strong></span>
        <span>Correção <strong>{formatDuration(incidentPostmortem.mttr_fix_s)}</strong></span>
        <span>Recuperação <strong>{formatDuration(incidentPostmortem.mttr_recovery_s)}</strong></span>
        <span>Ações permanentes <strong>{incidentPostmortem.permanent_actions}</strong></span>
        {!presentation && <><span>Perda apurada <strong>{formatCents(incidentPostmortem.loss_cents)}</strong></span>
          <span>Recuperado <strong>{formatCents(incidentPostmortem.recovered_cents)}</strong></span>
          <span>Absorvido <strong>{formatCents(incidentPostmortem.absorbed_cents)}</strong></span></>}
      </div>}
      {narrated && typeof narrated.public.learning_pt === "string" &&
        <p className="soc-incident-learning">{presentation ?
          "Lições do incidente registradas. Consulte a visão do operador para os detalhes." :
          narrated.public.learning_pt}</p>}
      {incidentEvents.length ? <ol>{incidentEvents.map((event) => <li key={event.seq}>
        <time>{new Date(event.ts).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}</time>
        <strong>{incidentStepsByType[event.type] ?? (presentation ? "Evento" : event.type)}</strong><span>{presentation ? "Resumo oculto na apresentação" : event.public_summary_pt}</span>
      </li>)}</ol> : <p>Nenhum evento público registrado para este incidente.</p>}
    </div>}
    </>}
    <div className="telemetry-heading"><div><small>OBSERVABILIDADE</small><h2>Logs ao vivo</h2>
      <p>Eventos sintéticos do banco. Dados privados aparecem apenas para operador autenticado.</p></div>
      <div className="telemetry-controls"><span className={`telemetry-connection ${connection}`}>{connection === "live" ? "● AO VIVO" :
        connection === "retrying" ? "◌ RECONECTANDO" : "◌ CONECTANDO"}</span>
        <span className="telemetry-rate">{recentCount} eventos/min</span>
        {sourceRates.length > 0 && <span className="telemetry-source-rates"
          aria-label="Eventos por segundo por fonte">
          {sourceRates.map(([source, count]) =>
            <span key={source}>{displayedSource(source, presentation)} {(count / 10).toFixed(1)}/s</span>)}
        </span>}
        <label>Origem <select value={filter} onChange={(event) => setFilter(event.target.value)}>
          {sources.map((source) => <option key={source} value={source}>{sourceLabel[source]}</option>)}
        </select></label>
        <label>Severidade <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="all">Todas</option><option value="info">Info</option>
          <option value="warn">Atenção</option><option value="error">Erro</option>
        </select></label>
        <label>Buscar <input type="search" value={presentation ? "" : query} disabled={presentation}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={presentation ? "Oculto na apresentação" : "Trace, regra, cartão ou texto"} /></label>
        {staffLogs && !presentation && <label>Cliente <input type="search"
          value={customerFilter} onChange={(event) => setCustomerFilter(event.target.value)}
          placeholder="ID exato do cliente" autoComplete="off" /></label>}
        <button className="telemetry-pause" aria-pressed={frozenEntries !== null}
          onClick={() => setFrozenEntries((current) => current ? null : [...entries])}>
          {frozenEntries ? "Retomar lista" : "Pausar lista"}
        </button></div></div>
    {frozenEntries && <p className="telemetry-frozen" role="status">Lista pausada · novos eventos continuam sendo recebidos.</p>}
    <div className="telemetry-list" role="log" aria-live="off">{visible.length ? visible.map((entry) =>
      <button key={entry.id} className={`telemetry-row ${entry.severity} ${entry.source === "risk" ? "risk" : ""}`}
        onClick={() => setTraceId(entry.trace_id)} title="Abrir trilha do trace">
        <time>{new Date(entry.ts).toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo",
          hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time>
        <span className="telemetry-source">{displayedSource(entry.source, presentation)}</span>
        <strong>{detectionNarrative(entry) ?? (presentation ? "EVENTO" : entry.action)}</strong>
        <span>{presentation ? `${detectionNarrative(entry) ?? "Atividade do banco"}. Detalhes ocultos.` :
          `${detectionNarrative(entry) ? `${detectionNarrative(entry)} · ` : ""}${entry.source === "risk"
            ? `${entry.message} · ${riskReasons(entry).join(", ") || "sem sinal adicional"}` : entry.message}`}</span>
        <em>{!presentation && entry.source === "risk" && entry.risk_score !== null ? `RISCO ${entry.risk_score}` :
          entry.redacted ? "MASCARADO" : entry.outcome === "failure" ? "FALHA" : entry.severity.toUpperCase()}</em>
      </button>) : <p className="telemetry-empty">Aguardando eventos da operação local.</p>}</div>
    {traceId && <div className="telemetry-trace" role="region" aria-label="Trilha do trace">
      <div><strong>Trilha {presentation ? "oculta" : `${traceId.slice(0, 16)}…`}</strong><button onClick={() => setTraceId(null)} aria-label="Fechar trilha">×</button></div>
      {traceEntries.length ? traceEntries.map((entry) => <p key={entry.id}>
        <time>{new Date(entry.ts).toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo" })}</time> · {displayedSource(entry.source, presentation)} {presentation ? " · detalhes ocultos" : ` · ${entry.action} · ${entry.message}${entry.risk_score !== null ? ` · score ${entry.risk_score}` : ""}${riskReasons(entry).length ? ` · ${riskReasons(entry).join(", ")}` : ""}${entry.e2e_id ? ` · ${entry.e2e_id}` : ""}${entry.card_token ? ` · cartão ${entry.card_token}` : ""}${entry.rule_id ? ` · regra ${entry.rule_id}` : ""}`}
      </p>) : <p>Nenhum evento encontrado para este trace.</p>}
    </div>}
  </section>;
}
