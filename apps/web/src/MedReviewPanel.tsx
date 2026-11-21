import { useEffect, useState, type FormEvent } from "react";

type Role = "maker" | "reviewer" | "admin";
type Decision = "approved" | "rejected";
type Basis = "fraud_indicators" | "no_fraud_indicators" | "insufficient_evidence";

interface OperatorSession {
  authenticated: boolean;
  operator_id?: string;
  role?: Role;
}
interface MedReview {
  id: string;
  transfer_id: string;
  claim_amount_cents: number;
  opened_at: string;
  resolve_after: string;
  proposal_id: string | null;
  proposed_decision: Decision | null;
  proposed_by: string | null;
  basis_code: Basis | null;
  evidence_ref: string | null;
  evidence_summary: string | null;
  review_decision: Decision | null;
  decided_at: string | null;
  initiation_deadline_at: string | null;
  initiation_state: "awaiting_analysis" | "pending" | "on_time" |
    "late" | "overdue" | null;
}
interface ReviewPage { reviews: MedReview[]; next_cursor: string | null;
  opening_sla: { target_seconds: number; completed: number; pending: number;
    overdue_pending: number; p95_seconds: number | null; target_met: boolean | null }; }
interface ProposalForm {
  caseId: string;
  decision: Decision;
  basis: Basis;
  evidenceRef: string;
  evidenceSummary: string;
}
interface PendingAction {
  kind: "confirm" | "settle";
  caseId: string;
  proposalId?: string;
}

const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", {
  style: "currency", currency: "BRL",
});
const localTime = (value: string) => new Date(value).toLocaleString("pt-BR", {
  timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit",
  hour: "2-digit", minute: "2-digit",
});
const roleName: Record<Role, string> = {
  maker: "Proponente", reviewer: "Revisor", admin: "Administrador",
};
const basisName: Record<Basis, string> = {
  fraud_indicators: "Indícios de fraude",
  no_fraud_indicators: "Sem indícios de fraude",
  insufficient_evidence: "Prova insuficiente",
};

export function MedReviewPanel() {
  const [session, setSession] = useState<OperatorSession | null>(null);
  const [loginRole, setLoginRole] = useState<"maker" | "reviewer">("maker");
  const [operatorId, setOperatorId] = useState("");
  const [password, setPassword] = useState("");
  const [page, setPage] = useState<ReviewPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [history, setHistory] = useState<(string | null)[]>([]);
  const [proposal, setProposal] = useState<ProposalForm | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let disposed = false;
    const refresh = () => {
      void fetch("/api/operator/session", { cache: "no-store" })
        .then((response) => response.ok ? response.json() as Promise<OperatorSession> :
          { authenticated: false })
        .then((value) => { if (!disposed) setSession(value); })
        .catch(() => { if (!disposed) setSession({ authenticated: false }); });
    };
    refresh();
    window.addEventListener("bv-operator-session", refresh);
    const timer = window.setInterval(refresh, 30_000);
    return () => { disposed = true; window.removeEventListener("bv-operator-session", refresh);
      window.clearInterval(timer); };
  }, []);

  useEffect(() => {
    if (!session?.authenticated) { setPage(null); return; }
    let disposed = false;
    let controller: AbortController | null = null;
    const refresh = () => {
      controller?.abort();
      controller = new AbortController();
      const signal = controller.signal;
      const url = `/api/operator/med-reviews${cursor ?
        `?cursor=${encodeURIComponent(cursor)}` : ""}`;
      void fetch(url, { cache: "no-store", signal })
        .then((response) => {
          if (response.status === 401) {
            setSession({ authenticated: false });
            window.dispatchEvent(new Event("bv-operator-session"));
            throw new Error("SESSION_EXPIRED");
          }
          if (!response.ok) throw new Error("QUEUE_UNAVAILABLE");
          return response.json() as Promise<ReviewPage>;
        }).then((result) => {
          if (!disposed && !signal.aborted && Array.isArray(result.reviews)) setPage(result);
        }).catch((error: unknown) => {
          if (!disposed && !signal.aborted)
            setMessage(error instanceof Error && error.message === "SESSION_EXPIRED" ?
              "Sessão encerrada. Entre novamente para revisar MED." :
              "Não foi possível atualizar a fila MED.");
        });
    };
    refresh();
    const timer = window.setInterval(refresh, 10_000);
    return () => { disposed = true; controller?.abort(); window.clearInterval(timer); };
  }, [session?.authenticated, session?.operator_id, cursor, refreshVersion]);

  useEffect(() => {
    setCursor(null); setHistory([]); setPage(null);
    setProposal(null); setPending(null);
  }, [session?.operator_id]);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setMessage("");
    try {
      const url = loginRole === "maker" ? "/api/operator/med/login" :
        "/api/operator/login";
      const response = await fetch(url, { method: "POST", cache: "no-store",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: operatorId, password }) });
      if (!response.ok) throw new Error("LOGIN_FAILED");
      const identity = await response.json() as OperatorSession;
      setSession(identity); setCursor(null); setHistory([]);
      setPage(null); setProposal(null); setPending(null);
      setMessage("Sessão de revisão MED iniciada.");
      window.dispatchEvent(new Event("bv-operator-session"));
    } catch { setMessage("Acesso não autorizado. Confira identidade e senha."); }
    finally { setPassword(""); setBusy(false); }
  }

  async function logout() {
    setBusy(true); setMessage("");
    try {
      const response = await fetch("/api/operator/logout", {
        method: "POST", cache: "no-store" });
      if (!response.ok) throw new Error("LOGOUT_FAILED");
      setSession({ authenticated: false }); setPage(null); setCursor(null);
      setHistory([]); setProposal(null); setPending(null);
      window.dispatchEvent(new Event("bv-operator-session"));
    } catch { setMessage("Não foi possível encerrar a sessão. Tente novamente."); }
    finally { setBusy(false); }
  }

  async function postAction(url: string, body: object | null, success: string,
    settlementClaimCents?: number) {
    setBusy(true); setMessage("");
    try {
      const response = await fetch(url, { method: "POST", cache: "no-store",
        ...(body ? { headers: { "content-type": "application/json" },
          body: JSON.stringify(body) } : {}) });
      if (response.status === 401) {
        setSession({ authenticated: false });
        window.dispatchEvent(new Event("bv-operator-session"));
        throw new Error("SESSION_EXPIRED");
      }
      if (!response.ok) throw new Error(response.status === 503 ? "SPI_UNAVAILABLE" :
        "ACTION_FAILED");
      const result: unknown = await response.json().catch(() => null);
      const replayPending = result !== null && typeof result === "object" &&
        "replay_update_pending" in result && result.replay_update_pending === true;
      const refundedCents = result !== null && typeof result === "object" &&
        "refunded_cents" in result && typeof result.refunded_cents === "number" &&
        Number.isSafeInteger(result.refunded_cents) ? result.refunded_cents : null;
      const status = result !== null && typeof result === "object" &&
        "status" in result ? result.status : null;
      const outcome = status === "analysis_pending_dict" ?
        "Aguardando análise DICT. O prazo de 72 horas ainda não começou." :
        status === "settlement_pending_psp" ?
          "Devolução solicitada ao PSP. Aguardando confirmação e conciliação." :
          settlementClaimCents !== undefined && refundedCents !== null ?
            `Liquidação MED concluída. Devolvido ${money(refundedCents)} de ${
              money(settlementClaimCents)} reclamados.` : success;
      setProposal(null); setPending(null); setPage(null); setCursor(null);
      setHistory([]); setRefreshVersion((value) => value + 1);
      setMessage(replayPending ?
        `${outcome} A atualização do replay está pendente de nova tentativa.` : outcome);
      window.dispatchEvent(new Event("bv-bank-operations-updated"));
    } catch (error) {
      const code = error instanceof Error ? error.message : "ACTION_FAILED";
      setMessage(code === "SESSION_EXPIRED" ? "Sessão encerrada. Entre novamente." :
        code === "SPI_UNAVAILABLE" ?
          "SPI indisponível. A decisão permanece registrada; tente liquidar novamente." :
          "Operação não concluída. Atualize a fila e confira o estado do caso.");
    } finally { setBusy(false); }
  }

  const mayPropose = session?.role === "maker" || session?.role === "admin";
  const mayReview = session?.role === "reviewer" || session?.role === "admin";
  return <section className="soc-review-panel bank-med-review"
    aria-label="Revisão MED do Pix">
    <div className="soc-review-heading"><div><small>MED · OPERAÇÃO LOCAL</small>
      <h3>Revisão e devolução</h3>
      <p>Uma proposta precisa de confirmação por outra pessoa antes de qualquer devolução.</p>
    </div>{session?.authenticated && <button disabled={busy} onClick={() => void logout()}>
      Sair · {session.operator_id}</button>}</div>
    {message && <p role="status" className={message.includes("não") ||
      message.includes("indisponível") ? "soc-review-error" : ""}>{message}</p>}
    {session === null ? <p>Verificando sessão do operador.</p> :
      !session.authenticated ? <form className="soc-review-login" onSubmit={(event) =>
        void login(event)}>
        <label>Função<select value={loginRole} onChange={(event) =>
          setLoginRole(event.target.value as "maker" | "reviewer")}>
          <option value="maker">Proponente</option>
          <option value="reviewer">Revisor ou administrador</option>
        </select></label>
        <label>Operador<input autoComplete="username" required maxLength={80}
          value={operatorId} onChange={(event) => setOperatorId(event.target.value)} /></label>
        <label>Senha<input type="password" autoComplete="current-password" required
          value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        <button disabled={busy} type="submit">Entrar para revisar</button>
      </form> : <>
        <p>{session.role ? roleName[session.role] : "Operador"} ·
          prazos pelo relógio da simulação</p>
        {page?.opening_sla && <p role={page.opening_sla.overdue_pending > 0 ||
          page.opening_sla.target_met === false ? "alert" : undefined}>
          Abertura MED: {page.opening_sla.completed} confirmados · {
            page.opening_sla.pending} aguardando · p95 {
              page.opening_sla.p95_seconds === null ? "—" :
                `${Math.ceil(page.opening_sla.p95_seconds / 60)} min`} (meta 30 min){
              page.opening_sla.overdue_pending > 0 ?
                ` · ${page.opening_sla.overdue_pending} acima do prazo` : ""}
        </p>}
        {page === null ? <p>Atualizando a fila MED.</p> : page.reviews.length ?
          <div className="soc-review-list">{page.reviews.map((row) =>
            <article key={row.id}>
              <div><strong>Pix …{row.transfer_id.slice(-8)}</strong>
                <em>{row.review_decision === "approved" ?
                  "Aprovado, aguardando liquidação" : row.proposal_id ?
                    "Proposta aguardando revisor" : "Análise pendente"}</em></div>
              <p>{money(row.claim_amount_cents)} · caso …{row.id.slice(-8)}</p>
              <small>Aberto {localTime(row.opened_at)} · prazo {localTime(row.resolve_after)}</small>
              {row.decided_at && <small> · decisão registrada {localTime(row.decided_at)}</small>}
              {row.initiation_state === "awaiting_analysis" &&
                <p>Aguardando confirmação ANALYSED do DICT; o prazo de 72 horas ainda não começou.</p>}
              {row.initiation_deadline_at && <p role={row.initiation_state === "overdue" ?
                "alert" : undefined}>Início da devolução: prazo {localTime(row.initiation_deadline_at)} · {
                  row.initiation_state === "overdue" ? "prazo vencido" :
                    row.initiation_state === "pending" ? "aguardando início" :
                      row.initiation_state === "late" ? "iniciada fora do prazo" :
                        "iniciada no prazo"}</p>}
              {row.proposal_id && <p>Proposta: {row.proposed_decision === "approved" ?
                "aprovar" : "rejeitar"} · por {row.proposed_by}<br />
                Fundamento: {row.basis_code ? basisName[row.basis_code] : "não informado"}<br />
                Evidência {row.evidence_ref}: {row.evidence_summary}</p>}
              {proposal?.caseId === row.id ? <form className="bank-med-form" onSubmit={(event) => {
                event.preventDefault();
                void postAction(`/api/operator/med-reviews/${encodeURIComponent(row.id)}/proposals`,
                  { decision: proposal.decision, evidence_ref: proposal.evidenceRef,
                    basis_code: proposal.basis, evidence_summary: proposal.evidenceSummary },
                  "Proposta registrada. Outra pessoa deve confirmar a decisão.");
              }}>
                <label>Decisão<select value={proposal.decision} onChange={(event) => {
                  const decision = event.target.value as Decision;
                  setProposal({ ...proposal, decision, basis: decision === "approved" ?
                    "fraud_indicators" : "insufficient_evidence" });
                }}><option value="approved">Aprovar</option>
                  <option value="rejected">Rejeitar</option></select></label>
                <label>Fundamento<select value={proposal.basis} onChange={(event) =>
                  setProposal({ ...proposal, basis: event.target.value as Basis })}>
                  {proposal.decision === "approved" ?
                    <option value="fraud_indicators">Indícios de fraude</option> : <>
                      <option value="insufficient_evidence">Prova insuficiente</option>
                      <option value="no_fraud_indicators">Sem indícios de fraude</option>
                    </>}</select></label>
                <label>Referência da evidência<input required minLength={8} maxLength={128}
                  pattern="[A-Za-z0-9:_-]{8,128}" value={proposal.evidenceRef}
                  onChange={(event) => setProposal({ ...proposal,
                    evidenceRef: event.target.value })} /></label>
                <label>Resumo da análise<textarea required minLength={24} maxLength={500}
                  value={proposal.evidenceSummary} onChange={(event) =>
                    setProposal({ ...proposal, evidenceSummary: event.target.value })} /></label>
                <div className="soc-review-actions"><button disabled={busy} type="submit">
                  Registrar proposta</button><button disabled={busy} type="button" onClick={() =>
                    setProposal(null)}>Cancelar</button></div>
              </form> : pending?.caseId === row.id ?
                <div className="soc-review-confirm"><strong>{pending.kind === "confirm" ?
                  "Confirmar decisão de outra pessoa" : "Confirmar liquidação MED"}</strong>
                  <p>{money(row.claim_amount_cents)} · {row.evidence_summary ??
                    "Decisão aprovada"}</p><div>
                    <button disabled={busy} onClick={() => void postAction(
                      pending.kind === "confirm" ?
                        `/api/operator/med-reviews/proposals/${encodeURIComponent(
                          pending.proposalId ?? "")}/confirm` :
                        `/api/operator/med-reviews/${encodeURIComponent(row.id)}/settle`,
                      null, pending.kind === "confirm" ?
                        row.proposed_decision === "rejected" ?
                          "Contestação rejeitada; bloqueios liberados sem devolução MED." :
                          "Análise aprovada. A devolução ainda precisa ser liquidada." :
                        "Liquidação MED concluída. Confira os valores recuperados.",
                      pending.kind === "settle" ? row.claim_amount_cents : undefined)}>
                      Confirmar</button>
                    <button disabled={busy} onClick={() => setPending(null)}>Cancelar</button>
                  </div></div> : <div className="soc-review-actions">
                  {mayPropose && !row.review_decision && <button disabled={busy}
                    onClick={() => setProposal({ caseId: row.id, decision: "approved",
                      basis: "fraud_indicators", evidenceRef: "", evidenceSummary: "" })}>
                    Propor decisão</button>}
                  {mayReview && !row.review_decision && row.proposal_id &&
                    row.proposed_by !== session.operator_id && <button disabled={busy}
                      onClick={() => {
                        if (row.proposal_id) setPending({ kind: "confirm", caseId: row.id,
                          proposalId: row.proposal_id });
                      }}>
                      Confirmar proposta</button>}
                  {mayReview && row.review_decision === "approved" && <button disabled={busy}
                    onClick={() => setPending({ kind: "settle", caseId: row.id })}>
                    Liquidar ou tentar novamente</button>}
                </div>}
            </article>)}</div> : <p className="bank-empty">Nenhum MED aberto nesta página.</p>}
        {(history.length > 0 || page?.next_cursor) && <div className="soc-review-pages">
          <button disabled={busy || history.length === 0} onClick={() => {
            setCursor(history.at(-1) ?? null); setHistory((value) => value.slice(0, -1));
            setPage(null); setProposal(null); setPending(null);
          }}>Anterior</button>
          <button disabled={busy || !page?.next_cursor} onClick={() => {
            if (!page?.next_cursor) return;
            setHistory((value) => [...value, cursor]); setCursor(page.next_cursor);
            setPage(null); setProposal(null); setPending(null);
          }}>Próxima</button>
        </div>}
      </>}
  </section>;
}
