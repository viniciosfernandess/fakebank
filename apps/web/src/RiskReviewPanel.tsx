import { useEffect, useState, type FormEvent } from "react";

interface Review {
  id: string;
  from_account: string;
  to_account: string;
  amount_cents: number;
  actor: string;
  product: "standard" | "automatic";
  created_at: string;
  expires_at: string;
  score: number;
  reason_codes: string[];
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  remaining_seconds: number;
}

interface ReviewPage {
  reviews: Review[];
  total: number;
  twin_now: string;
  next_cursor: string | null;
}

interface Session {
  authenticated: boolean;
  operator_id?: string;
  role?: "admin" | "reviewer";
}
interface RiskProfile {
  customer_id: string;
  risk_tier: "low" | "medium" | "high";
  verified_income_cents: number;
  declared_income_cents: number | null;
  tenure_days: number;
  history: { actor: string; risk_tier: string; verified_income_cents: number;
    declared_income_cents: number | null; changed_at: string }[];
}

const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", {
  style: "currency", currency: "BRL" });
const localTime = (value: string) => new Date(value).toLocaleString("pt-BR", {
  timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit",
  hour: "2-digit", minute: "2-digit" });
function remaining(seconds: number): string {
  if (seconds < 3_600) return `${Math.ceil(seconds / 60)} min`;
  return `${Math.floor(seconds / 3_600)} h ${Math.ceil(seconds % 3_600 / 60)} min`;
}

export function RiskReviewPanel() {
  const [session, setSession] = useState<Session | null>(null);
  const [operatorId, setOperatorId] = useState("");
  const [password, setPassword] = useState("");
  const [page, setPage] = useState<ReviewPage | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [history, setHistory] = useState<(string | null)[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [pendingDecision, setPendingDecision] = useState<{
    id: string; decision: "approve" | "reject" } | null>(null);
  const [error, setError] = useState("");
  const [profileCustomerId, setProfileCustomerId] = useState("");
  const [profile, setProfile] = useState<RiskProfile | null>(null);
  const [profileTier, setProfileTier] = useState<RiskProfile["risk_tier"]>("low");
  const [verifiedIncome, setVerifiedIncome] = useState("");
  const [confirmProfileChange, setConfirmProfileChange] = useState(false);

  useEffect(() => { window.dispatchEvent(new Event("bv-operator-session")); },
    [session?.authenticated]);

  useEffect(() => {
    let cancelled = false;
    void fetch("/api/operator/session", { cache: "no-store" })
      .then((response) => response.ok ? response.json() as Promise<Session> : null)
      .then((result) => { if (!cancelled) setSession(result?.authenticated ? result :
        { authenticated: false }); })
      .catch(() => { if (!cancelled) setSession({ authenticated: false }); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!session?.authenticated) { setPage(null); setProfile(null); return; }
    let cancelled = false;
    const refresh = () => {
      const url = `/api/operator/risk-reviews${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`;
      void fetch(url, { cache: "no-store" }).then((response) => {
        if (response.status === 401) {
          if (!cancelled) { setSession({ authenticated: false }); setError("Sessão encerrada. Entre novamente."); }
          return null;
        }
        if (!response.ok) throw new Error("REVIEW_LIST_UNAVAILABLE");
        return response.json() as Promise<ReviewPage>;
      }).then((result) => {
        if (!cancelled && result && Array.isArray(result.reviews)) setPage(result);
      }).catch(() => { if (!cancelled) setError("Não foi possível atualizar a fila."); });
    };
    refresh();
    const timer = window.setInterval(refresh, 5_000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [session?.authenticated, cursor]);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("login"); setError("");
    const secret = password;
    setPassword("");
    try {
      const response = await fetch("/api/operator/login", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: operatorId, password: secret }), cache: "no-store",
      });
      if (!response.ok) throw new Error("LOGIN_FAILED");
      const identity = await response.json() as Session;
      setCursor(null); setHistory([]); setPendingDecision(null); setSession(identity);
      setProfile(null); setConfirmProfileChange(false);
    } catch { setError("Acesso negado. Confira as credenciais e o papel do operador."); }
    finally { setBusy(null); }
  }

  async function logout() {
    setBusy("logout"); setError("");
    try {
      const response = await fetch("/api/operator/logout", { method: "POST", cache: "no-store" });
      if (!response.ok) throw new Error("LOGOUT_FAILED");
      setSession({ authenticated: false }); setPage(null);
      setCursor(null); setHistory([]); setPendingDecision(null);
      setProfile(null); setConfirmProfileChange(false);
    } catch { setError("Não foi possível encerrar a sessão. Tente novamente."); }
    finally { setBusy(null); }
  }

  async function review(id: string, decision: "approve" | "reject") {
    setBusy(id); setError("");
    try {
      const response = await fetch(`/api/operator/risk-reviews/${encodeURIComponent(id)}`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ decision }), cache: "no-store",
      });
      if (response.status === 401) {
        setSession({ authenticated: false });
        setError("Sessão encerrada. Entre novamente.");
        return;
      }
      if (!response.ok) throw new Error("REVIEW_FAILED");
      setPendingDecision(null);
      setCursor(null); setHistory([]);
      setPage(null);
      try {
        const next = await fetch("/api/operator/risk-reviews", { cache: "no-store" });
        if (!next.ok) throw new Error("REFRESH_FAILED");
        setPage(await next.json() as ReviewPage);
      } catch { setError("Decisão registrada. A fila será atualizada automaticamente."); }
    } catch { setError("A decisão não foi concluída. Atualize a fila e verifique o caso."); }
    finally { setBusy(null); }
  }

  async function acknowledge(id: string) {
    setBusy(id); setError("");
    try {
      const response = await fetch(`/api/operator/risk-reviews/${encodeURIComponent(id)}/acknowledge`, {
        method: "POST", cache: "no-store",
      });
      if (response.status === 401) {
        setSession({ authenticated: false });
        setError("Sessão encerrada. Entre novamente.");
        return;
      }
      if (!response.ok) throw new Error("ACK_FAILED");
      const ack = await response.json() as { acknowledged_by: string; acknowledged_at: string };
      setPage((current) => current ? { ...current, reviews: current.reviews.map((item) =>
        item.id === id ? { ...item, ...ack } : item) } : current);
    } catch { setError("Não foi possível registrar ciência. Atualize a fila e verifique o caso."); }
    finally { setBusy(null); }
  }

  async function loadProfile(customerId: string) {
    setBusy("profile"); setError(""); setConfirmProfileChange(false);
    setProfileCustomerId(customerId);
    setProfile(null);
    try {
      const response = await fetch(`/api/operator/risk-profiles/${encodeURIComponent(customerId)}`,
        { cache: "no-store" });
      if (response.status === 401) {
        setSession({ authenticated: false }); setError("Sessão encerrada. Entre novamente.");
        return;
      }
      if (response.status === 404) { setError("Cliente não encontrado."); return; }
      if (!response.ok) throw new Error("PROFILE_FAILED");
      const result = await response.json() as RiskProfile;
      setProfile(result); setProfileTier(result.risk_tier);
      setVerifiedIncome(String(result.verified_income_cents));
    } catch { setError("Não foi possível carregar o perfil de risco."); }
    finally { setBusy(null); }
  }

  async function updateProfile() {
    if (!profile || !/^(?:0|[1-9]\d*)$/.test(verifiedIncome) ||
      !Number.isSafeInteger(Number(verifiedIncome))) {
      setError("Informe a renda verificada em centavos inteiros."); return;
    }
    setBusy("profile"); setError("");
    try {
      const response = await fetch(`/api/operator/risk-profiles/${encodeURIComponent(profile.customer_id)}`,
        { method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ risk_tier: profileTier,
            verified_income_cents: Number(verifiedIncome) }), cache: "no-store" });
      if (response.status === 401) {
        setSession({ authenticated: false }); setError("Sessão encerrada. Entre novamente.");
        return;
      }
      if (!response.ok) throw new Error("PROFILE_UPDATE_FAILED");
      setConfirmProfileChange(false);
      setProfile((current) => current ? { ...current, risk_tier: profileTier,
        verified_income_cents: Number(verifiedIncome) } : current);
      try {
        const refreshed = await fetch(`/api/operator/risk-profiles/${encodeURIComponent(profile.customer_id)}`,
          { cache: "no-store" });
        if (!refreshed.ok) throw new Error("PROFILE_REFRESH_FAILED");
        setProfile(await refreshed.json() as RiskProfile);
      } catch { setError("Perfil atualizado. Consulte novamente para ver o histórico."); }
    } catch { setError("Alteração não confirmada. Consulte o perfil antes de tentar novamente."); }
    finally { setBusy(null); }
  }

  return <section className="soc-review-panel" aria-label="Fila autenticada de revisão Pix">
    <div className="soc-review-heading"><div><small>ACESSO DE OPERADOR</small><h3>Casos Pix retidos</h3>
      <p>Prazo no relógio do banco. Aprovação e rejeição ficam registradas no caso.</p></div>
      {session?.authenticated && <button onClick={() => void logout()} disabled={busy !== null}>
        Sair · {session.operator_id}</button>}</div>
    {session === null ? <p>Verificando sessão…</p> : !session.authenticated ?
      <form className="soc-review-login" onSubmit={(event) => void login(event)}>
        <label>Operador<input autoComplete="username" required maxLength={80} value={operatorId}
          onChange={(event) => setOperatorId(event.target.value)} /></label>
        <label>Senha<input type="password" autoComplete="current-password" required
          value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        <button type="submit" disabled={busy !== null}>Entrar como revisor</button>
      </form> : <>
        <div className="soc-review-count"><strong>{page?.total ?? "—"} {
          page?.total === 1 ? "pendente" : "pendentes"}</strong>
          <small>{page ? `Atualizado ${localTime(page.twin_now)}` : "Carregando…"}</small></div>
        {page?.reviews.length ? <div className="soc-review-list">{page.reviews.map((item) =>
          <article key={item.id} className={item.remaining_seconds <= 3_600 ? "urgent" : ""}>
            <div><strong>CASO {item.id} · {item.product === "automatic" ?
              "PIX AUTOMÁTICO" : "PIX"}</strong><em>{remaining(item.remaining_seconds)} restantes</em></div>
            <p>{item.from_account} → {item.to_account} · {money(item.amount_cents)}</p>
            <small>Risco {item.score} · {item.reason_codes.join(", ") || "Sem sinal"}</small>
            <small>Aberto {localTime(item.created_at)} · vence {localTime(item.expires_at)}</small>
            <button className="soc-review-ack" disabled={busy !== null}
              onClick={() => void loadProfile(item.actor)}>Ver perfil do pagador</button>
            {item.acknowledged_by && item.acknowledged_at ? <small>Ciência por {
              item.acknowledged_by} · {localTime(item.acknowledged_at)}</small> :
              <button className="soc-review-ack"
                disabled={busy !== null} onClick={() => void acknowledge(item.id)}>
                Registrar ciência</button>}
            <div className="soc-review-actions"><button disabled={busy !== null}
              onClick={() => setPendingDecision({ id: item.id, decision: "approve" })}>Aprovar Pix</button>
              <button disabled={busy !== null} onClick={() => setPendingDecision({
                id: item.id, decision: "reject" })}>
                Rejeitar Pix</button></div>
            {pendingDecision?.id === item.id && <div className="soc-review-confirm">
              <strong>{pendingDecision.decision === "approve" ? "Confirmar liquidação" :
                "Confirmar rejeição"} · {item.id}</strong>
              <p>{pendingDecision.decision === "approve" ?
                `O Pix de ${money(item.amount_cents)} será reavaliado e poderá ser liquidado.` :
                "A reserva será liberada e o Pix não será liquidado."}</p>
              <div><button disabled={busy !== null} onClick={() => void review(item.id,
                pendingDecision.decision)}>Confirmar decisão</button>
                <button disabled={busy !== null} onClick={() => setPendingDecision(null)}>
                  Cancelar</button></div>
            </div>}
          </article>)}</div> : <p>Nenhum caso pendente nesta página.</p>}
        <div className="soc-review-pages"><button disabled={!history.length || busy !== null}
          onClick={() => { setPendingDecision(null); setCursor(history.at(-1) ?? null);
            setHistory((items) => items.slice(0, -1)); }}>
            Anterior</button><button disabled={!page?.next_cursor || busy !== null}
          onClick={() => { setPendingDecision(null); setHistory((items) => [...items, cursor]);
            setCursor(page!.next_cursor); }}>
            Próxima</button></div>
        <section className="soc-risk-profile" aria-label="Perfil de risco do cliente">
          <h4>Perfil de risco do cliente</h4>
          <form onSubmit={(event) => { event.preventDefault(); void loadProfile(profileCustomerId.trim()); }}>
            <label>ID do cliente<input name="customer-id" required maxLength={128}
              disabled={busy !== null} value={profileCustomerId}
              onChange={(event) => { setProfileCustomerId(event.target.value); setProfile(null);
                setConfirmProfileChange(false); }} /></label>
            <button type="submit" disabled={busy !== null}>Consultar</button>
          </form>
          {profile && <div className="soc-risk-profile-detail">
            <p><strong>{profile.customer_id}</strong> · tier {profile.risk_tier} · {
              profile.tenure_days} dias de relacionamento</p>
            <p>Renda verificada {money(profile.verified_income_cents)} · declarada {
              profile.declared_income_cents === null ? "não informada" :
                money(profile.declared_income_cents)}</p>
            {session.role === "admin" && <form onSubmit={(event) => {
              event.preventDefault();
              if (!/^(?:0|[1-9]\d*)$/.test(verifiedIncome) ||
                !Number.isSafeInteger(Number(verifiedIncome))) {
                setError("Informe a renda verificada em centavos inteiros."); return;
              }
              setConfirmProfileChange(true); setError(""); }}>
              <label>Tier<select value={profileTier} disabled={busy !== null} onChange={(event) => {
                setProfileTier(event.target.value as RiskProfile["risk_tier"]);
                setConfirmProfileChange(false); }}>
                <option value="low">Baixo</option><option value="medium">Médio</option>
                <option value="high">Alto</option></select></label>
              <label>Renda verificada em centavos<input type="number" min="0" step="1" required
                disabled={busy !== null}
                value={verifiedIncome} onChange={(event) => {
                  setVerifiedIncome(event.target.value); setConfirmProfileChange(false); }} /></label>
              <button type="submit" disabled={busy !== null}>Preparar alteração</button>
            </form>}
            {confirmProfileChange && session.role === "admin" && <div className="soc-review-confirm">
              <strong>Confirmar perfil de {profile.customer_id}</strong>
              <p>Tier {profileTier} · renda verificada {money(Number(verifiedIncome))}.</p>
              <button disabled={busy !== null} onClick={() => void updateProfile()}>
                Confirmar alteração</button>
              <button disabled={busy !== null} onClick={() => setConfirmProfileChange(false)}>
                Cancelar</button>
            </div>}
            <small>{profile.history.length ? `Última alteração: ${profile.history[0]!.actor} · ${
              localTime(profile.history[0]!.changed_at)}` : "Sem alterações registradas."}</small>
          </div>}
        </section>
      </>}
    {error && <p className="soc-review-error" role="alert">{error}</p>}
  </section>;
}
