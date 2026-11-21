import { useEffect, useState } from "react";
import { CautelarReviewPanel } from "./CautelarReviewPanel.tsx";
import { MedReviewPanel } from "./MedReviewPanel.tsx";

interface PixRow { ref: string; sender: string; recipient: string; amount_cents: number;
  status: string; product: string; end_to_end_ref: string | null; initiated_at: string; }
interface AutomaticRow { ref: string; merchant: string; amount_cents: number;
  status: string; error_code: string | null; due_at: string;
  attempt_count: number; next_attempt_at: string | null;
  post_due_retry_count: number; }
interface AutomaticNotificationRow { ref: string; customer_ref: string; kind: string;
  message_pt: string; created_at: string; }
interface CardRow { ref: string; merchant_id: string; amount_cents: number; status: string;
  response_code: string; mcc: string; created_at: string; }
interface SpiRow { id: number; message_type: string; end_to_end_ref: string; created_at: string; }
interface CautelarRow { ref: string; account_ref: string; amount_cents: number;
  reason: string; status: string; created_at: string; resolved_at: string | null;
  resolved_by: string | null; }
interface PspNoticeRow { id: number; account_ref: string; kind: string;
  amount_cents: number; message_pt: string; created_at: string; }
interface DictRow { id: number; action: string; outcome: string; ts: string; }
interface RiskRow { ref: string; area: string; score: number; outcome: string;
  reason_codes_json: string; created_at: string; }
interface PiAccount { ispb: string; name: string; pi_balance_cents: number; }
interface ClosedCreditRow { ref: string; source: string; source_kind: "pix_return" | "med_recovery";
  amount_cents: number; status: "pending" | "paid"; created_at: string; paid_at: string | null; }
interface LedgerProof { hour_start: string; root_sha256: string;
  entries: number; net_cents: number; }
interface CrossBookSummary { checked_at: string;
  status: "balanced" | "processing" | "drift" | "unavailable" | "stale";
  pending_commands: number; drift_checks: number; }
interface BankSnapshot {
  pix: PixRow[]; automatic: AutomaticRow[]; automatic_notifications: AutomaticNotificationRow[];
  cards: CardRow[]; spi: SpiRow[]; cautelar: CautelarRow[];
  psp_notices: PspNoticeRow[]; dict: DictRow[];
  risk: RiskRow[]; pi_accounts: PiAccount[];
  closed_credits: { reconciliation: { ok: boolean; pending_cents: number;
    suspense_cents: number; mismatches: number }; recent: ClosedCreditRow[] };
  last_close: { brt_date: string; ledger_entries_count: number; ledger_sum: number } | null;
  ledger_proof: LedgerProof | null;
  cross_book: CrossBookSummary | null;
}
interface BankActivity { total: number; last_at: string | null; }
interface PublicBankSnapshot {
  pix: BankActivity; automatic: BankActivity; cards: BankActivity; spi: BankActivity;
  dict: BankActivity; cautelar: BankActivity; risk: BankActivity;
  closed_credits: BankActivity; pi_accounts: number; reconciliation_ok: boolean;
  last_close: { brt_date: string; ledger_entries_count: number } | null;
  ledger_proof: LedgerProof | null;
  cross_book: CrossBookSummary | null;
}

const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", {
  style: "currency", currency: "BRL" });
const time = (iso: string) => new Date(iso).toLocaleTimeString("pt-BR", {
  timeZone: "America/Sao_Paulo", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const statusLabel: Record<string, string> = {
  settled: "liquidado", returned_partial: "devolvido em parte", returned_full: "devolvido",
  rejected: "rejeitado", approved: "aprovado", declined: "negado", pending: "pendente",
  captured: "capturado", reversed: "revertido", approve: "aprovado",
  step_up: "autenticação", hold: "em análise", decline: "negado",
  success: "sucesso", failure: "falha", unknown: "desconhecido",
  review_pending: "em análise", reauthorization_required: "nova autorização",
  cancelled: "cancelado", failed: "falhou",
  paid: "resgatado",
  active: "bloqueado", released: "liberado", returned: "devolvido",
  expired: "expirado", superseded_by_med: "transferido ao MED",
  held: "bloqueado", med_review: "em análise MED",
};
const localizedStatus = (status: string) => statusLabel[status] ?? status;
const displayedStatus = (status: string, presentation: boolean) =>
  presentation ? statusLabel[status] ?? "em análise" : localizedStatus(status);
function crossBookLabel(summary: CrossBookSummary | null): string {
  if (!summary) return "aguardando primeira leitura";
  if (summary.status === "unavailable") return "verificador indisponível";
  if (summary.status === "stale") return "leitura desatualizada";
  if (summary.status === "balanced") return "conciliados · 0 pendências · drift 0";
  if (summary.status === "processing")
    return `em processamento · ${summary.pending_commands} pendências · drift 0`;
  return `divergência · ${summary.drift_checks} verificações · ${summary.pending_commands} pendências`;
}
const automaticNoticeLabel: Record<string, string> = {
  mandate_granted: "Autorização concedida", mandate_revoked: "Autorização revogada",
  charge_scheduled: "Cobrança agendada", charge_cancelled: "Cobrança cancelada",
  charge_reauthorized: "Cobrança reautorizada", charge_retry_scheduled: "Nova tentativa agendada",
  charge_post_due_retry: "Nova data solicitada", charge_failed: "Cobrança não liquidada",
  charge_settled: "Cobrança liquidada", charge_held: "Cobrança em análise",
  charge_reauthorization_required: "Nova autorização necessária",
};
const localizedNotice = (kind: string) => automaticNoticeLabel[kind.replace(/_post_due_\d+$/, "")] ??
  automaticNoticeLabel[kind.replace(/_\d+$/, "")] ?? "Aviso de cobrança";
const dictActionLabel: Record<string, string> = {
  resolve_key: "Chave consultada", key_deregister: "Chave desregistrada",
  fraud_flag: "Marcador de fraude atualizado", claim_complete: "Reivindicação concluída",
};
function reasons(value: string): string {
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string =>
      typeof item === "string").join(", ") : "";
  } catch { return ""; }
}

function BankDetailsPanel({ presentation }: { presentation: boolean }) {
  const [snapshot, setSnapshot] = useState<BankSnapshot | null>(null);
  const [connection, setConnection] = useState<"connecting" | "live" | "retrying">("connecting");
  useEffect(() => {
    let disposed = false;
    let scheduled: number | undefined;
    let controller: AbortController | undefined;
    const refresh = () => {
      scheduled = undefined;
      controller?.abort();
      controller = new AbortController();
      const signal = controller.signal;
      void fetch("/api/operator/bank/operations", { signal, cache: "no-store" })
        .then((response) => {
          if (response.status === 401) window.dispatchEvent(new Event("bv-operator-session"));
          return response.ok ? response.json() : null;
        })
        .then((value: BankSnapshot | null) => {
          if (!disposed && !signal.aborted) setSnapshot(value);
        }).catch(() => { if (!disposed && !signal.aborted) setConnection("retrying"); });
    };
    const schedule = () => { if (scheduled === undefined) scheduled = window.setTimeout(refresh, 200); };
    const stream = new EventSource("/api/telemetry/stream");
    stream.onopen = () => { setConnection("live"); schedule(); };
    stream.onerror = () => setConnection("retrying");
    stream.addEventListener("telemetry", (message) => {
      try {
        const value: unknown = JSON.parse((message as MessageEvent).data);
        if (value && typeof value === "object" && "source" in value &&
          ["pix", "cards", "network", "spi", "dict", "risk", "ledger"].includes(
            String(value.source))) schedule();
      } catch { /* Keep listening after a malformed frame. */ }
    });
    const fallback = window.setInterval(schedule, 5000);
    window.addEventListener("bv-bank-operations-updated", schedule);
    schedule();
    return () => {
      disposed = true;
      stream.close();
      window.clearInterval(fallback);
      window.removeEventListener("bv-bank-operations-updated", schedule);
      controller?.abort();
      if (scheduled !== undefined) window.clearTimeout(scheduled);
    };
  }, []);
  return <main className="bank-page">
    <header className="bank-page-heading"><div><small>BANCO SINTÉTICO · OPERAÇÃO LOCAL</small>
      <h1>Operações bancárias</h1><p>Pagamentos, autorizações e liquidação com evidência do motor de risco.</p></div>
      <span className={`telemetry-connection ${connection}`}>{connection === "live" ? "● AO VIVO" :
        connection === "retrying" ? "◌ RECONECTANDO" : "◌ CONECTANDO"}</span></header>
    {!presentation && <CautelarReviewPanel />}
    {!snapshot ? <p className="bank-empty">Aguardando dados do banco local.</p> : <>
      <section className="bank-pi" aria-label="Contas PI e conciliação">
        <div className="bank-section-title"><small>LIQUIDAÇÃO</small><h2>Contas PI simuladas</h2></div>
        <div className="bank-pi-grid">{snapshot.pi_accounts.map((account) =>
          <article key={account.ispb}><small>{presentation ? "CONTA PI" : `ISPB ${account.ispb}`}</small>
            <strong>{account.name === "External cash-out clearing" ? "Câmara de saque externa" : account.name}</strong>
            <b>{presentation ? "Valor oculto" : money(account.pi_balance_cents)}</b></article>)}</div>
        <p className="bank-close">Último fechamento: {snapshot.last_close ?
          `${snapshot.last_close.brt_date} · ${snapshot.last_close.ledger_entries_count} lançamentos${presentation ? "" : ` · soma ${money(snapshot.last_close.ledger_sum)}`}` :
          "aguardando fechamento diário"}</p>
        <p className="bank-close">Prova horária do razão: {snapshot.ledger_proof ?
          `${snapshot.ledger_proof.hour_start} · ${snapshot.ledger_proof.entries} lançamentos · saldo líquido ${money(snapshot.ledger_proof.net_cents)}` :
          "aguardando a primeira hora completa"}</p>
        {snapshot.ledger_proof && <code style={{ overflowWrap: "anywhere" }}>
          SHA-256 {snapshot.ledger_proof.root_sha256}</code>}
        <p className="bank-close">Banco, SPI e PSPs: {crossBookLabel(snapshot.cross_book)}</p>
        <p className="bank-close">Créditos de contas encerradas: {presentation ?
          "valores ocultos" : `${money(snapshot.closed_credits.reconciliation.pending_cents)} pendentes · ${
            snapshot.closed_credits.reconciliation.ok ? "conciliados" : "divergência contábil"}`}</p>
      </section>
      <div className="bank-feed-grid">
        <section aria-label="Créditos de contas encerradas"><div className="bank-section-title">
          <small>CONTAS ENCERRADAS</small><h2>Devoluções e resgates</h2></div>
          {snapshot.closed_credits.recent.length ? <ol>{snapshot.closed_credits.recent.map((row) =>
            <li key={row.ref}><time>{time(row.paid_at ?? row.created_at)}</time>
              <strong>{presentation ? "Valor oculto" : money(row.amount_cents)}</strong>
              <em>{displayedStatus(row.status, presentation)}</em>
              <span>{row.source_kind === "pix_return" ? "Devolução Pix" : "Recuperação MED"}
                {presentation ? "" : ` · conta …${row.source}`}</span></li>)}</ol> :
            <p className="bank-empty">Nenhum crédito de conta encerrada.</p>}</section>
        <section aria-label="Transferências Pix"><div className="bank-section-title"><small>PIX</small><h2>Transferências</h2></div>
          {snapshot.pix.length ? <ol>{snapshot.pix.map((row) => <li key={row.ref}>
            <time>{time(row.initiated_at)}</time><strong>{presentation ? "Valor oculto" : money(row.amount_cents)}</strong>
            <span>{presentation ? "Origem → destino ocultos" : `${row.sender} → ${row.recipient}`}</span><em>{displayedStatus(row.status, presentation)}</em>
            {(row.product === "automatic" || row.end_to_end_ref && !presentation) &&
              <small>{row.product === "automatic" ? "PIX AUTOMÁTICO" : ""}
                {row.end_to_end_ref && !presentation ?
                  `${row.product === "automatic" ? " · " : ""}E2E …${row.end_to_end_ref}` : ""}</small>}
          </li>)}</ol> : <p className="bank-empty">Nenhum Pix recente.</p>}</section>
        <section aria-label="Cobranças Pix Automático"><div className="bank-section-title"><small>PIX AUTOMÁTICO</small><h2>Cobranças</h2></div>
          {snapshot.automatic.length ? <ol>{snapshot.automatic.map((row) => <li key={row.ref}>
            <time>{time(row.due_at)}</time><strong>{presentation ? "Valor oculto" : money(row.amount_cents)}</strong>
            <span>{presentation ? "Recebedor oculto" : `Recebedor …${row.merchant}`}</span>
            <em>{displayedStatus(row.status, presentation)}</em>
            {row.post_due_retry_count > 0 && <small>
              {`Nova tentativa após vencimento ${row.post_due_retry_count}/3`}</small>}
            {(row.next_attempt_at || row.error_code && !presentation) && <small>
              {row.next_attempt_at ? `Nova tentativa às ${time(row.next_attempt_at)}` : ""}
              {row.error_code && !presentation ?
                `${row.next_attempt_at ? " · " : ""}${row.error_code}` : ""}</small>}
          </li>)}</ol> : <p className="bank-empty">Nenhuma cobrança automática recente.</p>}</section>
        <section aria-label="Avisos Pix Automático"><div className="bank-section-title">
          <small>PIX AUTOMÁTICO</small><h2>Avisos ao pagador</h2></div>
          {snapshot.automatic_notifications.length ? <ol>{snapshot.automatic_notifications.map((row) =>
            <li key={row.ref}><time>{time(row.created_at)}</time>
              <strong>{presentation ? "Aviso ao pagador" : localizedNotice(row.kind)}</strong>
              <span>{presentation ? "Detalhes ocultos na apresentação" : row.message_pt}</span>
              {!presentation && <small>Cliente …{row.customer_ref}</small>}
            </li>)}</ol> : <p className="bank-empty">Nenhum aviso automático recente.</p>}</section>
        <section aria-label="Autorizações de cartão"><div className="bank-section-title"><small>CARTÕES</small><h2>Autorizações</h2></div>
          {snapshot.cards.length ? <ol>{snapshot.cards.map((row) => <li key={row.ref}>
            <time>{time(row.created_at)}</time><strong>{presentation ? "Valor oculto" : money(row.amount_cents)}</strong>
            <span>{presentation ? "Categoria do comércio oculta" : `${row.merchant_id} · MCC ${row.mcc}`}</span><em>{displayedStatus(row.status, presentation)}{presentation ? "" : ` · ${row.response_code}`}</em>
          </li>)}</ol> : <p className="bank-empty">Nenhuma autorização recente.</p>}</section>
        <section aria-label="Mensagens SPI"><div className="bank-section-title"><small>SPI</small><h2>Mensagens</h2></div>
          {snapshot.spi.length ? <ol>{snapshot.spi.map((row) => <li key={row.id}>
            <time>{time(row.created_at)}</time><strong>{row.message_type}</strong>
            {!presentation && <span>E2E …{row.end_to_end_ref}</span>}
          </li>)}</ol> : <p className="bank-empty">Nenhuma mensagem recente.</p>}</section>
        <section aria-label="Bloqueios cautelares"><div className="bank-section-title"><small>PSP</small><h2>Bloqueios cautelares</h2></div>
          {snapshot.cautelar.length ? <ol>{snapshot.cautelar.map((row) =>
            <li key={row.ref}><time>{time(row.resolved_at ?? row.created_at)}</time>
              <strong>{presentation ? "Valor oculto" : money(row.amount_cents)}</strong>
              <em>{displayedStatus(row.status, presentation)}</em>
              <span>{presentation ? "Crédito sob revisão" :
                `Conta …${row.account_ref} · ${row.reason}${row.resolved_by ?
                  ` · por ${row.resolved_by}` : ""}`}</span>
            </li>)}</ol> : <p className="bank-empty">Nenhum bloqueio cautelar recente.</p>}</section>
        <section aria-label="Avisos do PSP"><div className="bank-section-title"><small>PSP</small><h2>Avisos da conta recebedora</h2></div>
          {snapshot.psp_notices.length ? <ol>{snapshot.psp_notices.map((row) =>
            <li key={row.id}><time>{time(row.created_at)}</time>
              <strong>{presentation ? "Aviso de crédito" : money(row.amount_cents)}</strong>
              <em>{displayedStatus(row.kind, presentation)}</em>
              <span>{presentation ? "Detalhes ocultos na apresentação" :
                `${row.message_pt} · conta …${row.account_ref}`}</span>
            </li>)}</ol> : <p className="bank-empty">Nenhum aviso cautelar recente.</p>}</section>
        <section aria-label="Atividade DICT"><div className="bank-section-title"><small>DICT</small><h2>Atividade de chaves</h2></div>
          {snapshot.dict.length ? <ol>{snapshot.dict.map((row) => <li key={row.id}>
            <time>{time(row.ts)}</time><strong>{dictActionLabel[row.action] ?? (presentation ? "Atividade de chave" : row.action)}</strong>
            <em>{displayedStatus(row.outcome, presentation)}</em>
          </li>)}</ol> : <p className="bank-empty">Nenhuma atividade recente.</p>}</section>
        <section className="bank-risk" aria-label="Decisões de risco"><div className="bank-section-title"><small>ANTIFRAUDE</small><h2>Decisões em tempo real</h2></div>
          {snapshot.risk.length ? <ol>{snapshot.risk.map((row) => <li key={row.ref}>
            <time>{time(row.created_at)}</time><strong>{presentation ? "Risco avaliado" : `${row.area.toUpperCase()} · ${row.score}/1000`}</strong>
            <em>{displayedStatus(row.outcome, presentation)}</em><span>{presentation ? "Detalhes ocultos" :
              reasons(row.reason_codes_json) || "Sem sinais adicionais"}</span>
          </li>)}</ol> : <p className="bank-empty">Nenhuma decisão recente.</p>}</section>
      </div>
    </>}
  </main>;
}

function BankPublicPanel() {
  const [snapshot, setSnapshot] = useState<PublicBankSnapshot | null>(null);
  useEffect(() => {
    let disposed = false;
    let scheduled: number | undefined;
    let controller: AbortController | undefined;
    const refresh = () => {
      scheduled = undefined;
      controller?.abort();
      controller = new AbortController();
      const signal = controller.signal;
      void fetch("/api/bank/operations", { cache: "no-store", signal })
        .then((response) => response.ok ? response.json() : null)
        .then((value: PublicBankSnapshot | null) => {
          if (!disposed && !signal.aborted) setSnapshot(value);
        }).catch(() => { if (!disposed && !signal.aborted) setSnapshot(null); }); };
    const schedule = () => { if (scheduled === undefined) scheduled = window.setTimeout(refresh, 200); };
    refresh();
    const stream = new EventSource("/api/telemetry/stream");
    stream.addEventListener("telemetry", schedule);
    const fallback = window.setInterval(schedule, 5000);
    return () => { disposed = true; stream.close(); window.clearInterval(fallback);
      controller?.abort(); if (scheduled !== undefined) window.clearTimeout(scheduled); };
  }, []);
  const feeds: { label: string; activity: BankActivity }[] = snapshot ? [
    { label: "Transferências Pix", activity: snapshot.pix },
    { label: "Cobranças automáticas", activity: snapshot.automatic },
    { label: "Autorizações de cartão", activity: snapshot.cards },
    { label: "Mensagens SPI", activity: snapshot.spi },
    { label: "Consultas DICT", activity: snapshot.dict },
    { label: "Bloqueios cautelares", activity: snapshot.cautelar },
    { label: "Decisões de risco", activity: snapshot.risk },
    { label: "Créditos de contas encerradas", activity: snapshot.closed_credits },
  ] : [];
  return <main className="bank-page">
    <header className="bank-page-heading"><div><small>BANCO SINTÉTICO · OPERAÇÃO LOCAL</small>
      <h1>Operações bancárias</h1><p>Atividade agregada do banco fictício.</p></div></header>
    {!snapshot ? <p className="bank-empty">Aguardando dados do banco local.</p> : <>
      <section className="bank-pi" aria-label="Conciliação pública">
        <div className="bank-section-title"><small>LIQUIDAÇÃO</small><h2>Estado do banco</h2></div>
        <p>{snapshot.pi_accounts} contas PI simuladas · créditos de contas encerradas {
          snapshot.reconciliation_ok ? "conciliados" : "em revisão"}</p>
        <p className="bank-close">Último fechamento: {snapshot.last_close ?
          `${snapshot.last_close.brt_date} · ${snapshot.last_close.ledger_entries_count} lançamentos` :
          "aguardando fechamento diário"}</p>
        <p className="bank-close">Prova horária do razão: {snapshot.ledger_proof ?
          `${snapshot.ledger_proof.hour_start} · ${snapshot.ledger_proof.entries} lançamentos` :
          "aguardando a primeira hora completa"}</p>
        {snapshot.ledger_proof && <code style={{ overflowWrap: "anywhere" }}>
          SHA-256 {snapshot.ledger_proof.root_sha256}</code>}
        <p className="bank-close">Banco, SPI e PSPs: {crossBookLabel(snapshot.cross_book)}</p>
      </section>
      <div className="bank-feed-grid">{feeds.map(({ label, activity }) =>
        <section key={label}><div className="bank-section-title"><h2>{label}</h2></div>
          <p>{activity.total} {activity.total === 1 ? "registro" : "registros"}</p>
          <small>{activity.last_at ? `Última atividade às ${time(activity.last_at)}` :
            "Sem atividade registrada"}</small></section>)}</div>
      <p className="bank-empty">Entre como operador pelo SOC para ver valores e histórico detalhado.</p>
    </>}
  </main>;
}

export function BankOperationsPanel({ enabled, presentation }: { enabled: boolean; presentation: boolean }) {
  const [staff, setStaff] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    let disposed = false;
    const refresh = () => { void fetch("/api/operator/session", { cache: "no-store" })
      .then((response) => response.ok ? response.json() : null)
      .then((value: { authenticated?: boolean; role?: string } | null) => {
        if (!disposed) setStaff(value?.authenticated === true && value.role !== "maker");
      }).catch(() => { if (!disposed) setStaff(false); }); };
    const sessionChanged = () => { setStaff(false); refresh(); };
    refresh();
    window.addEventListener("bv-operator-session", sessionChanged);
    const poll = window.setInterval(refresh, 30_000);
    return () => { disposed = true; window.clearInterval(poll);
      window.removeEventListener("bv-operator-session", sessionChanged); };
  }, [enabled]);
  if (!enabled) return null;
  return <>{staff ? <BankDetailsPanel presentation={presentation} /> : <BankPublicPanel />}
    {!presentation && <div className="bank-page"><MedReviewPanel /></div>}</>;
}
