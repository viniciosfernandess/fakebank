import { type FormEvent, useEffect, useRef, useState } from "react";
import { signDeviceMessage } from "./customer-device.ts";

type Authorized = (path: string, init?: RequestInit) => Promise<Response>;
interface Account { id: string; kind: string; status: string; account_number: string; }
interface Loan { id: string; account_id: string; principal_cents: number; fee_cents: number;
  status: string; started_at: string; }
interface Offer { id: string; max_amount_cents: number; rate_bps_month: number; expires_at: string; }
interface ScheduleLine { number: number; due_date: string; payment_cents: number; }
interface Quote { principal_cents: number; fee_cents: number;
  total_installments_cents: number; installments: ScheduleLine[]; }
interface RenegotiationQuote { payoff_cents: number; financed_fee_cents: number;
  new_principal_cents: number; total_installments_cents: number;
  installments: ScheduleLine[]; }
interface Installment extends ScheduleLine {
  paid_cents: number; status: string; }
interface Contract { contract: { method: "PRICE" | "SAC"; term_months: number };
  installments: Installment[]; }

const money = (cents: number) => (cents / 100).toLocaleString("pt-BR", {
  style: "currency", currency: "BRL" });

async function json<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let code = "";
    try { code = (await response.clone().json() as { error?: string }).error ?? ""; }
    catch { /* No structured response. */ }
    const messages: Record<string, string> = {
      DEF_STEP_UP_REQUIRED: "Confirme sua senha para continuar.",
      BIZ_LOAN_INELIGIBLE: "Crédito indisponível para este cadastro.",
      BIZ_ACTIVE_LOAN: "Já existe um empréstimo ativo.",
      BIZ_OFFER_AMOUNT: "O valor excede o limite da oferta.",
      BIZ_NEW_DEVICE_LIMIT: "Aguarde o prazo de segurança deste aparelho ou reduza o valor.",
      BIZ_LOAN_DUE_INSTALLMENT: "Pague a parcela vencida antes da quitação antecipada.",
      BIZ_LOAN_NOT_OVERDUE: "A renegociação está disponível somente após o vencimento.",
      BIZ_INSUFFICIENT_FUNDS: "Saldo insuficiente para concluir o pagamento.",
      BIZ_IDEMPOTENCY_CONFLICT: "Os termos desta renegociação já foram definidos.",
      BIZ_LOAN_PARTIAL_NOT_OVERDUE: "O pagamento parcial está disponível após o vencimento.",
      BIZ_LOAN_PARTIAL_MIN_CHARGES: "O valor precisa cobrir os encargos vencidos e parte da parcela.",
      BIZ_LOAN_PAYMENT_EXCESS: "O valor supera o saldo devido nesta parcela.",
    };
    throw new Error(messages[code] ?? (response.status === 403 ?
      "Acesso negado ou sessão expirada." : "Não foi possível concluir a operação de crédito."));
  }
  return response.json() as Promise<T>;
}

export function CustomerLoans({ authorized, customer, accounts, onFinancialChange }: {
  authorized: Authorized; customer: string; accounts: Account[];
  onFinancialChange: () => Promise<void>;
}) {
  const [loans, setLoans] = useState<Loan[]>([]);
  const [contracts, setContracts] = useState<Record<string, Contract | null>>({});
  const [offer, setOffer] = useState<Offer | null>(null);
  const [quote, setQuote] = useState<Quote | null>(null);
  const [renegotiationQuote, setRenegotiationQuote] =
    useState<RenegotiationQuote | null>(null);
  const [accountId, setAccountId] = useState("");
  const [amount, setAmount] = useState("");
  const [method, setMethod] = useState<"PRICE" | "SAC">("PRICE");
  const [months, setMonths] = useState("12");
  const [password, setPassword] = useState("");
  const [partialAmount, setPartialAmount] = useState("");
  const [selected, setSelected] = useState<{ id: string; action: "pay" | "partial" | "prepay" |
    "renegotiate"; installment?: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const partialAttempt = useRef<{ fingerprint: string; key: string } | null>(null);

  async function load(): Promise<void> {
    const nextLoans = await json<Loan[]>(await authorized("/loans"));
    const pairs = await Promise.all(nextLoans.map(async (loan) => [loan.id,
      await json<Contract | null>(await authorized(`/loans/${encodeURIComponent(loan.id)}/contract`))
    ] as const));
    setLoans(nextLoans);
    setContracts(Object.fromEntries(pairs));
    if (!nextLoans.some((loan) => loan.status === "active")) {
      try { setOffer(await json<Offer>(await authorized("/loans/offers"))); }
      catch { setOffer(null); }
    } else setOffer(null);
  }

  useEffect(() => {
    let mounted = true;
    void load().catch((failure: unknown) => {
      if (mounted) setError(failure instanceof Error ? failure.message :
        "Não foi possível carregar os empréstimos.");
    });
    return () => { mounted = false; };
  }, [customer]);

  async function signedPost<T>(path: string, body: object | undefined): Promise<T> {
    await json(await authorized("/auth/step-up", { method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password }) }));
    const proof = await json<{ challenge_id: string; message: string }>(
      await authorized("/devices/current/operation-challenge", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ method: "POST", path,
          ...(body === undefined ? {} : { body }) }) }));
    return json<T>(await authorized(path, { method: "POST", headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      "x-device-challenge": proof.challenge_id,
      "x-device-signature": await signDeviceMessage(customer, proof.message) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
  }

  async function accept(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!offer || !accountId) return;
    const match = /^(\d{1,7})(?:,(\d{1,2}))?$/.exec(amount.trim());
    const cents = match ? Number(match[1]) * 100 +
      Number((match[2] ?? "").padEnd(2, "0")) : 0;
    if (!Number.isSafeInteger(cents) || cents <= 0 || cents > offer.max_amount_cents ||
      !quote || quote.principal_cents !== cents || quote.installments.length !== Number(months)) {
      setError("Informe um valor positivo dentro do limite da oferta."); return;
    }
    setBusy(true); setError(""); setNotice("");
    try {
      await signedPost<Loan>("/loans", { offer_id: offer.id, account_id: accountId,
        amount_cents: cents, method, term_months: Number(months) });
      setPassword(""); setAmount(""); setQuote(null);
      await Promise.all([load(), onFinancialChange()]);
      setNotice("Empréstimo contratado. O cronograma está disponível abaixo.");
    } catch (failure) { setError(failure instanceof Error ? failure.message :
      "Falha ao contratar o empréstimo."); }
    finally { setBusy(false); }
  }

  async function simulate(): Promise<void> {
    if (!offer) return;
    const match = /^(\d{1,7})(?:,(\d{1,2}))?$/.exec(amount.trim());
    const cents = match ? Number(match[1]) * 100 +
      Number((match[2] ?? "").padEnd(2, "0")) : 0;
    if (!Number.isSafeInteger(cents) || cents <= 0 || cents > offer.max_amount_cents) {
      setError("Informe um valor positivo dentro do limite da oferta."); return;
    }
    setBusy(true); setError(""); setQuote(null);
    try {
      const body = { offer_id: offer.id, amount_cents: cents, method,
        term_months: Number(months) };
      const result = await json<Quote>(await authorized("/loans/quote", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(body) }));
      setQuote(result);
    } catch (failure) { setError(failure instanceof Error ? failure.message :
      "Falha ao simular o empréstimo."); }
    finally { setBusy(false); }
  }

  async function act(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!selected) return;
    if (selected.action === "renegotiate" &&
      (!renegotiationQuote || renegotiationQuote.installments.length !== Number(months))) {
      setError("Simule o novo contrato antes de confirmar."); return;
    }
    let partialBody: { amount_cents: number; idempotency_key: string } | undefined;
    if (selected.action === "partial") {
      const match = /^(\d{1,7})(?:,(\d{1,2}))?$/.exec(partialAmount.trim());
      const cents = match ? Number(match[1]) * 100 +
        Number((match[2] ?? "").padEnd(2, "0")) : 0;
      if (!Number.isSafeInteger(cents) || cents <= 0) {
        setError("Informe um valor positivo para o pagamento parcial."); return;
      }
      const fingerprint = `${selected.id}:${selected.installment}:${cents}`;
      if (partialAttempt.current?.fingerprint !== fingerprint)
        partialAttempt.current = { fingerprint, key: crypto.randomUUID() };
      partialBody = { amount_cents: cents,
        idempotency_key: partialAttempt.current.key };
    }
    const path = selected.action === "pay" ?
      `/loans/${encodeURIComponent(selected.id)}/installments/${selected.installment}/pay` :
      selected.action === "partial" ?
        `/loans/${encodeURIComponent(selected.id)}/installments/${selected.installment}/partial-pay` :
      `/loans/${encodeURIComponent(selected.id)}/${selected.action}`;
    const body = selected.action === "renegotiate" ?
      { method, term_months: Number(months) } : partialBody;
    setBusy(true); setError(""); setNotice("");
    try {
      await signedPost(path, body);
      setPassword(""); setSelected(null); setRenegotiationQuote(null);
      setPartialAmount(""); partialAttempt.current = null;
      await Promise.all([load(), onFinancialChange()]);
      setNotice(selected.action === "renegotiate" ?
        "Dívida renegociada. Confira o novo cronograma." :
        selected.action === "prepay" ? "Empréstimo quitado antecipadamente." :
          selected.action === "partial" ? "Pagamento parcial registrado." : "Parcela paga.");
    } catch (failure) { setError(failure instanceof Error ? failure.message :
      "Falha ao processar o empréstimo."); }
    finally { setBusy(false); }
  }

  async function simulateRenegotiation(): Promise<void> {
    if (!selected || selected.action !== "renegotiate") return;
    setBusy(true); setError(""); setRenegotiationQuote(null);
    try {
      const result = await json<RenegotiationQuote>(await authorized(
        `/loans/${encodeURIComponent(selected.id)}/renegotiation-quote`, {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ method, term_months: Number(months) }) }));
      setRenegotiationQuote(result);
    } catch (failure) { setError(failure instanceof Error ? failure.message :
      "Falha ao simular a renegociação."); }
    finally { setBusy(false); }
  }

  return <section aria-label="Empréstimos">
    <h2>Empréstimos</h2>
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {loans.length ? <ol>{loans.map((loan) => {
      const contract = contracts[loan.id];
      const next = contract?.installments.find((item) => item.status === "scheduled");
      return <li key={loan.id}>
        <strong>{money(loan.principal_cents)} · {loan.status === "active" ? "ativo" :
          loan.status === "settled" ? "quitado" : loan.status === "refinanced" ?
            "renegociado" : "quitado antecipadamente"}</strong>
        {contract && <p>{contract.contract.method} · {contract.contract.term_months} parcelas
          {next ? ` · próxima parcela ${next.number} em ${next.due_date}: ${money(next.payment_cents - next.paid_cents)}` : ""}
        </p>}
        {loan.status === "active" && next && <>
          <button disabled={busy} onClick={() => { setSelected({ id: loan.id, action: "pay",
            installment: next.number }); setPassword(""); setError("");
            setRenegotiationQuote(null); }}>Pagar parcela</button>
          <button disabled={busy} onClick={() => { setSelected({ id: loan.id,
            action: "partial", installment: next.number }); setPassword("");
            setPartialAmount(""); setError(""); setRenegotiationQuote(null); }}>
            Pagar parte da parcela vencida</button>
          <button disabled={busy} onClick={() => { setSelected({ id: loan.id,
            action: "prepay" }); setPassword(""); setError("");
            setRenegotiationQuote(null); }}>Quitar antecipadamente</button>
          <button disabled={busy} onClick={() => { setSelected({ id: loan.id,
            action: "renegotiate" }); setPassword(""); setError("");
            setRenegotiationQuote(null); }}>
            Renegociar atraso</button>
        </>}
      </li>;
    })}</ol> : <p>Nenhum empréstimo contratado.</p>}
    {selected && <form onSubmit={(event) => { void act(event); }}>
      <p>{selected.action === "renegotiate" ?
        "O novo contrato quita a dívida vencida e financia os encargos e a taxa. Confira os termos antes de confirmar." :
        selected.action === "prepay" ? "A quitação antecipada exige saldo para o principal restante." :
        selected.action === "partial" ? "Disponível após o vencimento. O valor cobre primeiro multa e mora, depois juros e principal." :
          "O valor da parcela pode incluir multa e mora após o vencimento."}</p>
      {selected.action === "partial" && <label>Valor em reais<input required
        inputMode="decimal" disabled={busy} value={partialAmount}
        onChange={(event) => setPartialAmount(event.target.value)} /></label>}
      {selected.action === "renegotiate" && <>
        <label>Amortização<select disabled={busy} value={method}
          onChange={(event) => { setMethod(event.target.value as "PRICE" | "SAC");
            setRenegotiationQuote(null); }}>
          <option value="PRICE">Price</option><option value="SAC">SAC</option></select></label>
        <label>Parcelas<select disabled={busy} value={months}
          onChange={(event) => { setMonths(event.target.value);
            setRenegotiationQuote(null); }}>
          {Array.from({ length: 60 }, (_, index) => index + 1).map((count) =>
            <option key={count} value={count}>{count}</option>)}</select></label>
        <button type="button" disabled={busy}
          onClick={() => { void simulateRenegotiation(); }}>Simular renegociação</button>
        {renegotiationQuote && <p role="status">Dívida liquidada: {
          money(renegotiationQuote.payoff_cents)}. Taxa financiada: {
          money(renegotiationQuote.financed_fee_cents)}. Novo principal: {
          money(renegotiationQuote.new_principal_cents)}. Total das parcelas: {
          money(renegotiationQuote.total_installments_cents)}. Primeira parcela: {
          money(renegotiationQuote.installments[0]!.payment_cents)} em {
          renegotiationQuote.installments[0]!.due_date}.</p>}
      </>}
      <label>Senha atual<input type="password" autoComplete="current-password"
        required disabled={busy} value={password}
        onChange={(event) => setPassword(event.target.value)} /></label>
      <button disabled={busy || selected.action === "renegotiate" &&
        !renegotiationQuote}>{busy ? "Processando…" : "Confirmar"}</button>
      <button type="button" disabled={busy} onClick={() => { setSelected(null);
        setPassword(""); setRenegotiationQuote(null);
        partialAttempt.current = null; }}>Cancelar</button>
    </form>}
    {offer && !selected && <form onSubmit={(event) => { void accept(event); }}>
      <h3>Oferta de crédito</h3>
      <p>Até {money(offer.max_amount_cents)} · taxa mensal {
        (offer.rate_bps_month / 100).toLocaleString("pt-BR")}% · válida até {
          new Date(offer.expires_at).toLocaleDateString("pt-BR")}</p>
      <label>Valor em reais<input required inputMode="decimal" disabled={busy}
        placeholder="0,00" value={amount} onChange={(event) => {
          setAmount(event.target.value); setQuote(null); }} /></label>
      <label>Conta para receber<select required disabled={busy} value={accountId}
        onChange={(event) => setAccountId(event.target.value)}>
        <option value="">Selecione uma conta</option>
        {accounts.filter((item) => item.kind === "checking" && item.status === "active")
          .map((item) => <option key={item.id} value={item.id}>{
            item.account_number}</option>)}
      </select></label>
      <label>Amortização<select disabled={busy} value={method}
        onChange={(event) => { setMethod(event.target.value as "PRICE" | "SAC");
          setQuote(null); }}>
        <option value="PRICE">Price</option><option value="SAC">SAC</option></select></label>
      <label>Parcelas<select disabled={busy} value={months}
        onChange={(event) => { setMonths(event.target.value); setQuote(null); }}>
        {Array.from({ length: 60 }, (_, index) => index + 1).map((count) =>
          <option key={count} value={count}>{count}</option>)}</select></label>
      <label>Senha atual<input type="password" autoComplete="current-password"
        required disabled={busy} value={password}
        onChange={(event) => setPassword(event.target.value)} /></label>
      <button type="button" disabled={busy} onClick={() => { void simulate(); }}>
        Simular parcelas</button>
      {quote && <p role="status">Recebimento líquido após taxa de abertura: {
        money(quote.principal_cents - quote.fee_cents)}. Taxa de abertura: {
          money(quote.fee_cents)}. Total das parcelas: {
          money(quote.total_installments_cents)}. Primeira parcela: {
          money(quote.installments[0]!.payment_cents)} em {
          quote.installments[0]!.due_date}. Consulte o cronograma completo após contratar.</p>}
      <button disabled={busy || !quote}>{busy ? "Contratando…" : "Contratar"}</button>
    </form>}
  </section>;
}
