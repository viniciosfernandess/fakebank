import { useEffect, useState } from "react";

interface CautelarReview {
  id: string;
  account_id: string;
  root_transfer_id: string;
  amount_cents: number;
  reason: string;
  created_at: string;
  expires_at: string;
  remaining_seconds: number;
}

interface ReviewPage {
  reviews: CautelarReview[];
  total: number;
  next_cursor: string | null;
}

const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", {
  style: "currency", currency: "BRL" });
const localTime = (value: string) => new Date(value).toLocaleString("pt-BR", {
  timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit",
  hour: "2-digit", minute: "2-digit" });
function remaining(seconds: number): string {
  if (seconds < 3_600) return `${Math.ceil(seconds / 60)} min`;
  if (seconds < 86_400)
    return `${Math.floor(seconds / 3_600)} h ${Math.ceil(seconds % 3_600 / 60)} min`;
  return `${Math.floor(seconds / 86_400)} d ${Math.floor(seconds % 86_400 / 3_600)} h`;
}

export function CautelarReviewPanel() {
  const [page, setPage] = useState<ReviewPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [history, setHistory] = useState<(string | null)[]>([]);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [busy, setBusy] = useState<string | null>(null);
  const [pending, setPending] = useState<{
    id: string; decision: "release" | "return" } | null>(null);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let disposed = false;
    let controller: AbortController | null = null;
    const refresh = () => {
      controller?.abort();
      controller = new AbortController();
      const signal = controller.signal;
      const url = `/api/operator/cautelar-reviews${cursor ?
        `?cursor=${encodeURIComponent(cursor)}` : ""}`;
      void fetch(url, { cache: "no-store", signal }).then((response) => {
        if (response.status === 401) {
          window.dispatchEvent(new Event("bv-operator-session"));
          throw new Error("SESSION_EXPIRED");
        }
        if (!response.ok) throw new Error("REVIEW_LIST_UNAVAILABLE");
        return response.json() as Promise<ReviewPage>;
      }).then((result) => {
        if (!disposed && !signal.aborted && Array.isArray(result.reviews)) {
          setPage(result);
          setPending((current) => current && result.reviews.some((row) => row.id === current.id) ?
            current : null);
        }
      }).catch((error: unknown) => {
        if (!disposed && !signal.aborted)
          setMessage(error instanceof Error && error.message === "SESSION_EXPIRED" ?
            "Sessão encerrada. Entre novamente pelo SOC." :
            "Não foi possível atualizar os bloqueios cautelares.");
      });
    };
    refresh();
    const timer = window.setInterval(refresh, 5_000);
    return () => { disposed = true; controller?.abort(); window.clearInterval(timer); };
  }, [cursor, refreshVersion]);

  async function decide(id: string, decision: "release" | "return") {
    setBusy(id); setMessage("");
    try {
      const response = await fetch(`/api/operator/cautelar-reviews/${encodeURIComponent(id)}`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ decision }), cache: "no-store",
      });
      if (response.status === 401) {
        window.dispatchEvent(new Event("bv-operator-session"));
        setMessage("Sessão encerrada. Entre novamente pelo SOC.");
        return;
      }
      if (!response.ok) throw new Error("REVIEW_FAILED");
      setPending(null); setPage(null); setCursor(null); setHistory([]);
      setMessage(decision === "release" ? "Crédito liberado e decisão registrada." :
        "Crédito devolvido ao pagador e decisão registrada.");
      setRefreshVersion((value) => value + 1);
      window.dispatchEvent(new Event("bv-bank-operations-updated"));
    } catch {
      setMessage("Decisão não concluída. Atualize a fila e confira o estado do bloqueio.");
    } finally { setBusy(null); }
  }

  return <section className="soc-review-panel bank-cautelar-review"
    aria-label="Revisão de bloqueios cautelares do PSP">
    <div className="soc-review-heading"><div><small>PSP RECEBEDOR · ACESSO DO OPERADOR</small>
      <h3>Revisão cautelar</h3><p>Libere o crédito ou devolva ao pagador após analisar o caso.</p></div></div>
    {message && <p role="status">{message}</p>}
    <div className="soc-review-count"><strong>{page?.total ?? "—"} {page?.total === 1 ? "ativo" : "ativos"}</strong>
      <small>ordenados pelo prazo do banco</small></div>
    {page?.reviews.length ? <div className="soc-review-list">{page.reviews.map((row) =>
      <article key={row.id} className={row.remaining_seconds <= 3_600 ? "urgent" : ""}>
        <div><strong>Conta …{row.account_id.slice(-8)}</strong>
          <em>{remaining(row.remaining_seconds)} restantes</em></div>
        <p>{money(row.amount_cents)} · {row.reason}</p>
        <small>Pix …{row.root_transfer_id.slice(-8)} · expira {localTime(row.expires_at)}</small>
        {pending?.id === row.id ? <div className="soc-review-confirm">
          <strong>{pending.decision === "release" ? "Confirmar liberação" :
            "Confirmar devolução ao pagador"}</strong>
          <p>{money(row.amount_cents)} · conta …{row.account_id.slice(-8)}</p>
          <div><button disabled={busy !== null} onClick={() => void decide(row.id, pending.decision)}>
            Confirmar decisão</button><button disabled={busy !== null} onClick={() => setPending(null)}>
            Cancelar</button></div>
        </div> : <div className="soc-review-actions">
          <button disabled={busy !== null} onClick={() => setPending({ id: row.id, decision: "release" })}>
            Liberar crédito</button>
          <button disabled={busy !== null} onClick={() => setPending({ id: row.id, decision: "return" })}>
            Devolver ao pagador</button>
        </div>}</article>)}</div> : <p className="bank-empty">Nenhum bloqueio cautelar ativo.</p>}
    {(history.length > 0 || page?.next_cursor) && <div className="soc-review-pages">
      <button disabled={busy !== null || history.length === 0} onClick={() => {
        const previous = history.at(-1) ?? null;
        setHistory((current) => current.slice(0, -1)); setCursor(previous); setPending(null);
      }}>Anterior</button>
      <button disabled={busy !== null || !page?.next_cursor} onClick={() => {
        if (!page?.next_cursor) return;
        setHistory((current) => [...current, cursor]); setCursor(page.next_cursor); setPending(null);
      }}>Próxima</button>
    </div>}
  </section>;
}
