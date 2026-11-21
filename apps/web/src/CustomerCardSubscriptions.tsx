import { type FormEvent, useEffect, useRef, useState } from "react";
import { signDeviceMessage } from "./customer-device.ts";

interface Card { id: string; kind: "debit" | "virtual" | "credit";
  status: string; last4: string; }
interface Mandate { id: string; card_id: string; merchant_id: string; amount_cents: number;
  frequency: "weekly" | "monthly"; next_due_at: string;
  status: "active" | "revoked" | "completed"; }
interface Charge { id: string; due_at: string; status: "approved" | "declined" | "failed";
  response_code: string | null; failure_code: string | null; }

type Authorized = (path: string, init?: RequestInit) => Promise<Response>;
const merchants = [
  { id: "shop_ipe", label: "Loja Ipê" },
  { id: "market_aroeira", label: "Mercado Aroeira" },
];
const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", {
  style: "currency", currency: "BRL" });
const dateTime = (value: string) => new Date(value).toLocaleString("pt-BR", {
  timeZone: "America/Sao_Paulo", dateStyle: "short", timeStyle: "short" });

async function json<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let code = "";
    try { code = (await response.clone().json() as { error?: string }).error ?? ""; }
    catch { /* The response may not be JSON. */ }
    const messages: Record<string, string> = {
      DEF_STEP_UP_REQUIRED: "Confirme sua senha antes de continuar.",
      DEF_DEVICE_PROOF_INVALID: "A assinatura do dispositivo falhou. Tente novamente.",
      BIZ_CARD_RECURRING_DATE: "Confira as datas da recorrência.",
      BIZ_CARD_RECURRING_INVALID: "Confira o cartão e os dados da recorrência.",
      BIZ_NEW_DEVICE_LIMIT: "O limite para este aparelho novo foi atingido.",
      BIZ_CARD_NOT_ACTIVE: "Este cartão não está ativo para cobranças recorrentes.",
      BIZ_INVALID_MERCHANT: "Esta loja não está disponível.",
    };
    throw new Error(messages[code] ?? (response.status === 403 ?
      "Acesso negado ou sessão expirada." : "Não foi possível concluir a solicitação."));
  }
  return response.json() as Promise<T>;
}

export function CustomerCardSubscriptions({ authorized, customer }: {
  authorized: Authorized; customer: string;
}) {
  const [cards, setCards] = useState<Card[]>([]);
  const [mandates, setMandates] = useState<Mandate[]>([]);
  const [charges, setCharges] = useState<Record<string, Charge[]>>({});
  const [selected, setSelected] = useState<string | null>(null);
  const [cardId, setCardId] = useState("");
  const [merchantId, setMerchantId] = useState(merchants[0]!.id);
  const [amount, setAmount] = useState("");
  const [frequency, setFrequency] = useState<"weekly" | "monthly">("monthly");
  const [startsAt, setStartsAt] = useState("");
  const [password, setPassword] = useState("");
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [revokePassword, setRevokePassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const attempt = useRef<{ fingerprint: string; key: string } | null>(null);

  async function load(): Promise<void> {
    const nextCards = await json<Card[]>(await authorized("/cards"));
    const nextMandates = await Promise.all(nextCards.map(async (card) =>
      json<Mandate[]>(await authorized(`/cards/${encodeURIComponent(card.id)}/recurring`))));
    setCards(nextCards);
    setMandates(nextMandates.flat());
    setCardId((current) => nextCards.some((card) => card.id === current &&
      card.status === "active" && card.kind !== "virtual") ? current :
      nextCards.find((card) => card.status === "active" && card.kind !== "virtual")?.id ?? "");
  }

  useEffect(() => {
    let mounted = true;
    void load().catch((failure: unknown) => {
      if (mounted) setError(failure instanceof Error ? failure.message : "Falha ao carregar recorrências.");
    });
    return () => { mounted = false; };
  }, [customer]);

  async function signedPost(path: string, body: object | undefined, secret: string): Promise<void> {
    await json(await authorized("/auth/step-up", { method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: secret }) }));
    const proof = await json<{ challenge_id: string; message: string }>(
      await authorized("/devices/current/operation-challenge", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ method: "POST", path, ...(body === undefined ? {} : { body }) }) }));
    await json(await authorized(path, { method: "POST", headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      "x-device-challenge": proof.challenge_id,
      "x-device-signature": await signDeviceMessage(customer, proof.message) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
  }

  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const match = /^(\d{1,5})(?:,(\d{1,2}))?$/.exec(amount.trim());
    const cents = match ? Number(match[1]) * 100 + Number((match[2] ?? "").padEnd(2, "0")) : 0;
    const card = cards.find((item) => item.id === cardId && item.status === "active" &&
      item.kind !== "virtual");
    const instant = new Date(startsAt);
    if (!card || !Number.isSafeInteger(cents) || cents < 1 || cents > 2_000_000 ||
      !Number.isFinite(instant.getTime())) {
      setError("Selecione um cartão ativo, um valor até R$ 20.000,00 e uma data válida.");
      return;
    }
    setBusy(true); setError(""); setNotice("");
    try {
      const fingerprint = [cardId, merchantId, cents, frequency, instant.toISOString()].join(":");
      if (attempt.current?.fingerprint !== fingerprint)
        attempt.current = { fingerprint, key: crypto.randomUUID() };
      const path = `/cards/${encodeURIComponent(cardId)}/recurring`;
      await signedPost(path, { merchant_id: merchantId, amount_cents: cents, frequency,
        starts_at: instant.toISOString(), idempotency_key: attempt.current.key }, password);
      attempt.current = null;
      setPassword(""); setAmount(""); setStartsAt("");
      await load();
      setNotice("Recorrência criada. As cobranças seguem o relógio da simulação.");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Falha ao criar recorrência.");
    } finally { setBusy(false); }
  }

  async function revoke(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!revokeId) return;
    setBusy(true); setError(""); setNotice("");
    try {
      await signedPost(`/cards/recurring/${encodeURIComponent(revokeId)}/revoke`,
        undefined, revokePassword);
      setRevokeId(null); setRevokePassword("");
      await load();
      setNotice("Recorrência cancelada. Cobranças anteriores continuam no histórico.");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Falha ao cancelar recorrência.");
    } finally { setBusy(false); }
  }

  async function toggleCharges(id: string): Promise<void> {
    if (selected === id) { setSelected(null); return; }
    setBusy(true); setError("");
    try {
      const list = await json<Charge[]>(await authorized(
        `/cards/recurring/${encodeURIComponent(id)}/charges`));
      setCharges((current) => ({ ...current, [id]: list }));
      setSelected(id);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Falha ao carregar cobranças.");
    } finally { setBusy(false); }
  }

  async function refresh(): Promise<void> {
    setBusy(true); setError("");
    try {
      await load();
      if (selected) {
        const list = await json<Charge[]>(await authorized(
          `/cards/recurring/${encodeURIComponent(selected)}/charges`));
        setCharges((current) => ({ ...current, [selected]: list }));
      }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Falha ao atualizar recorrências.");
    } finally { setBusy(false); }
  }

  return <section aria-label="Cobranças recorrentes no cartão">
    <h2>Cobranças recorrentes no cartão</h2>
    <p>Autorize um valor fixo para uma loja fictícia. As cobranças acontecem no horário de São Paulo, pelo relógio da simulação.</p>
    <button type="button" disabled={busy} onClick={() => { void refresh(); }}>Atualizar recorrências</button>
    {error && <p role="alert" className="customer-error">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    <form onSubmit={(event) => { void create(event); }}>
      <h3>Nova recorrência</h3>
      <label>Cartão<select required disabled={busy} value={cardId}
        onChange={(event) => setCardId(event.target.value)}>
        <option value="">Selecione um cartão</option>
        {cards.filter((card) => card.status === "active" && card.kind !== "virtual").map((card) =>
          <option key={card.id} value={card.id}>{card.kind === "credit" ? "Crédito" :
            "Débito"} •••• {card.last4}</option>)}
      </select></label>
      <label>Loja<select disabled={busy} value={merchantId}
        onChange={(event) => setMerchantId(event.target.value)}>
        {merchants.map((merchant) => <option key={merchant.id} value={merchant.id}>{
          merchant.label}</option>)}
      </select></label>
      <label>Valor fixo em reais<input required inputMode="decimal" placeholder="0,00"
        disabled={busy} value={amount} onChange={(event) => setAmount(event.target.value)} /></label>
      <label>Frequência<select disabled={busy} value={frequency}
        onChange={(event) => setFrequency(event.target.value as "weekly" | "monthly")}>
        <option value="weekly">Semanal</option><option value="monthly">Mensal</option>
      </select></label>
      <label>Primeira cobrança (horário do seu dispositivo)<input required type="datetime-local"
        disabled={busy} value={startsAt} onChange={(event) => setStartsAt(event.target.value)} /></label>
      <label>Senha atual<input required type="password" autoComplete="current-password"
        disabled={busy} value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      <button disabled={busy || !cards.some((card) => card.status === "active" &&
        card.kind !== "virtual")}>
        {busy ? "Processando…" : "Autorizar recorrência"}</button>
    </form>
    <h3>Suas recorrências</h3>
    {mandates.length ? <ol>{mandates.map((mandate) => <li key={mandate.id}>
      <strong>{merchants.find((item) => item.id === mandate.merchant_id)?.label ??
        mandate.merchant_id} · {money(mandate.amount_cents)} {mandate.frequency === "weekly" ?
          "por semana" : "por mês"}</strong>
      <p>Cartão •••• {cards.find((card) => card.id === mandate.card_id)?.last4 ?? "????"} · {
        mandate.status === "active" ? "ativa" : mandate.status === "revoked" ?
          "cancelada" : "concluída"}{mandate.status === "active" ?
            ` · próxima cobrança ${dateTime(mandate.next_due_at)}` : ""}</p>
      <button disabled={busy} onClick={() => { void toggleCharges(mandate.id); }}>
        {selected === mandate.id ? "Ocultar cobranças" : "Ver cobranças"}</button>
      {mandate.status === "active" && <button disabled={busy} onClick={() => {
        setRevokeId(revokeId === mandate.id ? null : mandate.id);
        setRevokePassword(""); setError(""); }}>
        {revokeId === mandate.id ? "Voltar" : "Cancelar recorrência"}</button>}
      {revokeId === mandate.id && <form onSubmit={(event) => { void revoke(event); }}>
        <p>Confirme sua senha para impedir as próximas cobranças.</p>
        <label>Senha atual<input required type="password" autoComplete="current-password"
          disabled={busy} value={revokePassword}
          onChange={(event) => setRevokePassword(event.target.value)} /></label>
        <button disabled={busy}>Confirmar cancelamento</button>
      </form>}
      {selected === mandate.id && (charges[mandate.id]?.length ?
        <ol>{charges[mandate.id]!.map((charge) => <li key={charge.id}>
          {dateTime(charge.due_at)} · {charge.status === "approved" ? "Aprovada" :
            charge.status === "declined" ? "Recusada" : "Falhou"}
          {charge.response_code ? ` · código ${charge.response_code}` : ""}
          {charge.failure_code ? ` · ${charge.failure_code}` : ""}
        </li>)}</ol> : <p>Nenhuma cobrança até agora.</p>)}
    </li>)}</ol> : <p>Nenhuma recorrência criada.</p>}
  </section>;
}
