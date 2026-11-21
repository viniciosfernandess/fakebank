import { type FormEvent, useEffect, useRef, useState } from "react";
import { customerDevice, signDeviceMessage } from "./customer-device.ts";
import { CustomerCardSubscriptions } from "./CustomerCardSubscriptions.tsx";
import { CustomerLoans } from "./CustomerLoans.tsx";

interface Notice { id: string; kind: string; message_pt: string; created_at: string; }
interface IncidentNotice { id: number; kind: "card_issuer_recovered" | "revoked_device_access" |
  "suspicious_pix_review";
  message_pt: string; created_at: string; }
interface DeviceNotice { id: number; twin_at: string; }
interface LoginChallenge { challenge_id: string; device_proof_message: string; }
interface CustomerSession { access_token: string; refresh_token: string; }
interface Transfer { id: string; to_account: string; amount: number; status: string;
  initiated_at: string; med_case_id: string | null; med_status: string | null;
  psp_credit_status: "pending" | "credited" | null; }
interface MedCase { id: string; status: string; review_state: string; refunded_cents: number;
  claim_amount_cents: number; }
interface Account { id: string; kind: string; status: string; branch_code: string;
  account_number: string; account_digit: string; balance_cached: number;
  available_balance_cents: number; }
interface ClosedCredit { id: string; source_account: string;
  source_kind: "pix_return" | "med_recovery"; amount_cents: number;
  created_at: string; }
interface CreditStatement { id: string; closing_date: string; due_date: string;
  due_cents: number; paid_cents: number; minimum_due_cents: number; status: string; }
interface CreditCardAccount { id: string; limit_cents: number; outstanding_cents: number;
  available_limit_cents: number; status: string;
  policy: { invoice_plan_interest_bps: number }; statements: CreditStatement[]; }

const PAGE_SIZE = 20;
const endpoint = "/api/client";

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let code = "";
    try { code = (await response.clone().json() as { error?: string }).error ?? ""; }
    catch { /* The response may not be JSON. */ }
    const messages: Record<string, string> = {
      BIZ_MED_EXPIRED: "O prazo de 80 dias para contestar este Pix terminou.",
      BIZ_MED_NOT_SETTLED: "Este Pix não está disponível para contestação MED.",
      DEF_DEVICE_PROOF_INVALID: "A assinatura do dispositivo falhou. Tente novamente.",
      DEF_STEP_UP_REQUIRED: "Confirme sua senha novamente antes de encerrar a conta.",
      BIZ_ACCOUNT_CLOSE_BALANCE: "A conta precisa ter saldo contábil zero para ser encerrada.",
      BIZ_ACCOUNT_CLOSE_PENDING: "Há chaves, cobranças, cartões, disputas ou outras obrigações pendentes nesta conta.",
      DEF_ACCOUNT_FROZEN: "Uma conta bloqueada não pode ser encerrada.",
      BIZ_CLOSED_CREDIT_ALREADY_PAID: "Este crédito já foi recebido em outra conta.",
      BIZ_CREDIT_PAYMENT_CONFLICT: "Esta tentativa de pagamento já foi usada com outros dados.",
      BIZ_CREDIT_PAYMENT_EXCESS: "O valor supera o saldo restante da fatura.",
      BIZ_STATEMENT_NOT_PAYABLE: "Esta fatura não está aberta para pagamento.",
      BIZ_STATEMENT_NOT_FINANCEABLE: "Esta fatura não está disponível para parcelamento.",
      BIZ_CREDIT_PLAN_MINIMUM: "Pague pelo menos o mínimo da fatura antes de parcelar o restante.",
      BIZ_CREDIT_PLAN_INVALID: "Escolha de 2 a 24 parcelas.",
      BIZ_CREDIT_PLAN_CONFLICT: "Esta fatura já foi parcelada com outra quantidade de parcelas.",
      INTEGRITY_CLOSED_CREDIT_DRIFT: "O banco encontrou uma divergência contábil. Procure o operador local.",
    };
    throw new Error(messages[code] ?? (response.status === 403 ?
      "Acesso negado ou sessão expirada." : response.status === 404 ?
        "O registro não foi encontrado." : "Não foi possível concluir a solicitação."));
  }
  return response.json() as Promise<T>;
}

async function expiredAccess(response: Response): Promise<boolean> {
  if (response.status !== 403) return false;
  try { return (await response.clone().json() as { error?: string }).error === "DEF_UNAUTHORIZED"; }
  catch { return false; }
}

function transferStatus(status: string): string {
  return ({ settled: "Concluído", returned_partial: "Devolvido em parte",
    returned_full: "Devolvido", rejected: "Recusado", pending: "Pendente" } as
    Record<string, string>)[status] ?? status;
}

function medStatus(status: string): string {
  return ({ open: "Em análise", refunded: "Devolvido", resolved: "Análise concluída",
    rejected: "Contestação não aprovada" } as
    Record<string, string>)[status] ?? status;
}
function medReviewState(state: string): string {
  return ({ awaiting_review: "Aguardando decisão da análise",
    review_overdue: "Prazo de análise vencido; aguardando decisão",
    approved_pending_settlement: "Análise aprovada; devolução pendente",
    approved_overdue_settlement: "Análise aprovada; devolução atrasada",
    rejected: "Contestação não aprovada", complete: "Análise concluída" } as
    Record<string, string>)[state] ?? "Estado da análise indisponível";
}

async function renewSession(refreshToken: string, account: string): Promise<CustomerSession> {
  const challenge = await readJson<{ proof_required: boolean; challenge_id?: string;
    message?: string }>(await fetch(`${endpoint}/auth/refresh/challenge`, { method: "POST",
    headers: { "content-type": "application/json" }, cache: "no-store",
    body: JSON.stringify({ refresh_token: refreshToken }) }));
  const proof = challenge.proof_required && challenge.challenge_id && challenge.message ? {
    challenge_id: challenge.challenge_id,
    signature: await signDeviceMessage(account, challenge.message) } : {};
  return readJson<CustomerSession>(await fetch(`${endpoint}/auth/refresh`, { method: "POST",
    headers: { "content-type": "application/json" }, cache: "no-store",
    body: JSON.stringify({ refresh_token: refreshToken, ...proof }) }));
}

export function CustomerInbox({ available, presentation }: {
  available: boolean; presentation: boolean;
}) {
  const [cpf, setCpf] = useState("");
  const [password, setPassword] = useState("");
  const [signupMode, setSignupMode] = useState(false);
  const [signupName, setSignupName] = useState("");
  const [signupPersona, setSignupPersona] = useState("salaried");
  const [signupPassword, setSignupPassword] = useState("");
  const [signupMessage, setSignupMessage] = useState("");
  const [otp, setOtp] = useState("");
  const [challenge, setChallenge] = useState<LoginChallenge | null>(null);
  const [access, setAccess] = useState<string | null>(null);
  const [notices, setNotices] = useState<Notice[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [incidentNotices, setIncidentNotices] = useState<IncidentNotice[]>([]);
  const [incidentCursor, setIncidentCursor] = useState<number | null>(null);
  const incidentPageLoaded = useRef(false);
  const [deviceNotices, setDeviceNotices] = useState<DeviceNotice[]>([]);
  const [deviceCursor, setDeviceCursor] = useState<number | null>(null);
  const [deviceNoticeError, setDeviceNoticeError] = useState(false);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [moreTransfers, setMoreTransfers] = useState(false);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [openingPayment, setOpeningPayment] = useState(false);
  const [paymentOpenPassword, setPaymentOpenPassword] = useState("");
  const [portingSalaryId, setPortingSalaryId] = useState<string | null>(null);
  const [salaryDestination, setSalaryDestination] = useState("");
  const [salaryAmount, setSalaryAmount] = useState("");
  const [salaryPassword, setSalaryPassword] = useState("");
  const [salaryInstructionDestination, setSalaryInstructionDestination] =
    useState<string | null>(null);
  const [salaryInstructionLoaded, setSalaryInstructionLoaded] = useState(false);
  const [salaryAutoMessage, setSalaryAutoMessage] = useState("");
  const [closedCredits, setClosedCredits] = useState<ClosedCredit[]>([]);
  const [creditCards, setCreditCards] = useState<CreditCardAccount[]>([]);
  const [payingStatement, setPayingStatement] = useState<{ cardId: string; statementId: string } | null>(null);
  const [paymentAmount, setPaymentAmount] = useState("");
  const [paymentAccount, setPaymentAccount] = useState("");
  const [paymentPassword, setPaymentPassword] = useState("");
  const [planningStatement, setPlanningStatement] = useState<{ cardId: string;
    statementId: string } | null>(null);
  const [planInstallments, setPlanInstallments] = useState("3");
  const [planPassword, setPlanPassword] = useState("");
  const [planNotice, setPlanNotice] = useState("");
  const [creditsCursor, setCreditsCursor] = useState<number | null>(null);
  const [claimCreditId, setClaimCreditId] = useState<string | null>(null);
  const [claimDestination, setClaimDestination] = useState("");
  const [claimPassword, setClaimPassword] = useState("");
  const [closingAccountId, setClosingAccountId] = useState<string | null>(null);
  const [closePassword, setClosePassword] = useState("");
  const [selectedCase, setSelectedCase] = useState<MedCase | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const sessionGeneration = useRef(0);
  const refreshToken = useRef<string | null>(null);
  const currentAccess = useRef<string | null>(null);
  const activeAccount = useRef<string | null>(null);
  const renewing = useRef<Promise<CustomerSession> | null>(null);
  const paymentAttempt = useRef<{ fingerprint: string; key: string } | null>(null);
  const salaryPortAttempt = useRef<{ fingerprint: string; key: string } | null>(null);

  useEffect(() => { if (presentation) { setClosingAccountId(null); setClosePassword("");
    setOpeningPayment(false); setPaymentOpenPassword("");
    setPortingSalaryId(null); setSalaryDestination(""); setSalaryAmount("");
    setSalaryPassword(""); setSalaryInstructionDestination(null);
    setSalaryInstructionLoaded(false); setSalaryAutoMessage("");
    salaryPortAttempt.current = null;
    setClaimCreditId(null); setClaimDestination(""); setClaimPassword("");
    setPayingStatement(null); setPaymentPassword("");
    setPlanningStatement(null); setPlanPassword(""); } },
    [presentation]);

  function clearSession(): void {
    sessionGeneration.current++;
    refreshToken.current = null; currentAccess.current = null;
    activeAccount.current = null; renewing.current = null;
    setAccess(null); setNotices([]); setHasMore(false);
    setIncidentNotices([]); setIncidentCursor(null); incidentPageLoaded.current = false;
    setSignupMode(false); setSignupName(""); setSignupPassword("");
    setSignupMessage("");
    setDeviceNotices([]); setDeviceCursor(null); setDeviceNoticeError(false);
    setTransfers([]); setMoreTransfers(false); setSelectedCase(null); setBusy(false);
    setAccounts([]); setClosingAccountId(null); setClosePassword("");
    setOpeningPayment(false); setPaymentOpenPassword("");
    setPortingSalaryId(null); setSalaryDestination(""); setSalaryAmount("");
    setSalaryPassword(""); setSalaryInstructionDestination(null);
    setSalaryInstructionLoaded(false); setSalaryAutoMessage("");
    salaryPortAttempt.current = null;
    setClosedCredits([]); setCreditsCursor(null); setClaimCreditId(null);
    setClaimDestination(""); setClaimPassword("");
    setCreditCards([]); setPayingStatement(null); setPaymentAmount("");
    setPaymentAccount(""); setPaymentPassword(""); paymentAttempt.current = null;
    setPlanningStatement(null); setPlanInstallments("3"); setPlanPassword("");
    setPlanNotice("");
  }

  async function authorized(path: string, init?: RequestInit): Promise<Response> {
    const generation = sessionGeneration.current;
    const send = (token: string) => fetch(`${endpoint}${path}`, { ...init, cache: "no-store",
      headers: { ...init?.headers, authorization: `Bearer ${token}` } });
    const sentWith = currentAccess.current;
    if (!sentWith) throw new Error("Sessão encerrada.");
    let response = await send(sentWith);
    if (generation !== sessionGeneration.current) throw new Error("Sessão encerrada.");
    if (await expiredAccess(response) && refreshToken.current && activeAccount.current) {
      try {
        if (currentAccess.current === sentWith) {
          renewing.current ??= renewSession(refreshToken.current, activeAccount.current).then((session) => {
            if (generation === sessionGeneration.current) {
              refreshToken.current = session.refresh_token;
              currentAccess.current = session.access_token;
              setAccess(session.access_token);
            }
            return session;
          }).finally(() => { renewing.current = null; });
          await renewing.current;
        }
        if (generation !== sessionGeneration.current) throw new Error("Sessão encerrada.");
        if (!currentAccess.current) throw new Error("Sessão encerrada.");
        response = await send(currentAccess.current);
      } catch (failure) {
        if (generation === sessionGeneration.current) clearSession();
        throw failure;
      }
    }
    if (generation !== sessionGeneration.current) throw new Error("Sessão encerrada.");
    if (await expiredAccess(response)) clearSession();
    return response;
  }

  async function load(before?: string): Promise<void> {
    const generation = sessionGeneration.current;
    const query = new URLSearchParams({ limit: String(PAGE_SIZE) });
    if (before) query.set("before", before);
    const rows = await readJson<Notice[]>(await authorized(`/pix/automatic/notifications?${query}`));
    if (generation !== sessionGeneration.current) return;
    setNotices((current) => before ? [...current, ...rows] : rows);
    setHasMore(rows.length === PAGE_SIZE);
  }

  async function loadIncidentNotices(before?: number): Promise<void> {
    const generation = sessionGeneration.current;
    const query = new URLSearchParams({ limit: String(PAGE_SIZE) });
    if (before !== undefined) query.set("before", String(before));
    const page = await readJson<{ items: IncidentNotice[]; next_cursor: number | null }>(
      await authorized(`/incidents/notices?${query}`));
    if (generation !== sessionGeneration.current) return;
    setIncidentNotices((current) => {
      const merged = new Map(current.map((notice) => [notice.id, notice]));
      for (const notice of page.items) merged.set(notice.id, notice);
      return [...merged.values()].sort((left, right) => right.id - left.id);
    });
    if (before !== undefined || !incidentPageLoaded.current)
      setIncidentCursor(page.next_cursor);
    incidentPageLoaded.current = true;
  }

  useEffect(() => {
    if (!access) return;
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible")
        void loadIncidentNotices().catch(() => undefined);
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [access]);

  async function loadDeviceNotices(before?: number): Promise<void> {
    const generation = sessionGeneration.current;
    const account = activeAccount.current;
    if (!account) throw new Error("Sessão encerrada.");
    const path = "/devices/current/security-notices";
    const body = before === undefined ? { limit: PAGE_SIZE } : { limit: PAGE_SIZE, before };
    const proof = await readJson<{ challenge_id: string; message: string }>(
      await authorized("/devices/current/operation-challenge", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ method: "GET", path, body }) }));
    const signature = await signDeviceMessage(account, proof.message);
    if (generation !== sessionGeneration.current) return;
    const query = new URLSearchParams({ limit: String(PAGE_SIZE) });
    if (before !== undefined) query.set("before", String(before));
    const page = await readJson<{ items: DeviceNotice[]; next_cursor: number | null }>(
      await authorized(`${path}?${query}`, { headers: {
        "x-device-challenge": proof.challenge_id, "x-device-signature": signature } }));
    if (generation !== sessionGeneration.current) return;
    setDeviceNotices((current) => before === undefined ? page.items : [...current, ...page.items]);
    setDeviceCursor(page.next_cursor);
    setDeviceNoticeError(false);
  }

  async function refreshDeviceNotices(before?: number): Promise<void> {
    const generation = sessionGeneration.current;
    setBusy(true);
    try { await loadDeviceNotices(before); }
    catch { if (generation === sessionGeneration.current) setDeviceNoticeError(true); }
    finally { if (generation === sessionGeneration.current) setBusy(false); }
  }

  async function loadTransfers(before?: string): Promise<void> {
    const generation = sessionGeneration.current;
    const query = new URLSearchParams({ limit: String(PAGE_SIZE) });
    if (before) query.set("before", before);
    const rows = await readJson<Transfer[]>(await authorized(`/pix/transfers?${query}`));
    if (generation !== sessionGeneration.current) return;
    setTransfers((current) => before ? [...current, ...rows] : rows);
    setMoreTransfers(rows.length === PAGE_SIZE);
  }

  async function loadAccounts(): Promise<void> {
    const generation = sessionGeneration.current;
    const rows = await readJson<Account[]>(await authorized("/accounts"));
    if (generation === sessionGeneration.current) setAccounts(rows);
  }

  async function loadCreditCards(): Promise<void> {
    const generation = sessionGeneration.current;
    const cards = await readJson<Omit<CreditCardAccount, "statements">[]>(
      await authorized("/cards/credit"));
    const withStatements = await Promise.all(cards.map(async (card) => ({ ...card,
      statements: await readJson<CreditStatement[]>(await authorized(
        `/cards/credit/${encodeURIComponent(card.id)}/statements`)) })));
    if (generation === sessionGeneration.current) setCreditCards(withStatements);
  }

  async function loadClosedCredits(after?: number): Promise<void> {
    const generation = sessionGeneration.current;
    const path = after === undefined ? "/accounts/closed-credits" :
      `/accounts/closed-credits?after=${after}`;
    const page = await readJson<{ items: ClosedCredit[]; next_cursor: number | null }>(
      await authorized(path));
    if (generation !== sessionGeneration.current) return;
    setClosedCredits((current) => after === undefined ? page.items : [...current, ...page.items]);
    setCreditsCursor(page.next_cursor);
  }

  async function begin(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true); setError("");
    try {
      const account = cpf.replace(/\D/g, "");
      const device = await customerDevice(account);
      const response = await fetch(`${endpoint}/auth/login`, { method: "POST",
        headers: { "content-type": "application/json" }, cache: "no-store",
        body: JSON.stringify({ cpf: account, password,
          device_id: device.deviceId }) });
      const next = await readJson<LoginChallenge>(response);
      activeAccount.current = account;
      setChallenge(next);
      setPassword("");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Falha ao entrar.");
    } finally { setBusy(false); }
  }

  async function submitSignup(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const normalizedCpf = cpf.replace(/\D/g, "");
    if (normalizedCpf.length !== 11 || signupPassword.length < 12) {
      setError("Informe um CPF fictício de 11 dígitos e uma senha com pelo menos 12 caracteres.");
      return;
    }
    setBusy(true); setError(""); setSignupMessage("");
    try {
      await readJson(await fetch(`${endpoint}/onboarding/apply`, {
        method: "POST", cache: "no-store",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ cpf: normalizedCpf, name: signupName.trim(),
          persona: signupPersona, password: signupPassword }) }));
      setSignupPassword(""); setSignupMode(false);
      setSignupMessage("Solicitação recebida. Entre com sua senha para acompanhar a análise da conta.");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Falha ao solicitar a conta.");
    } finally { setBusy(false); }
  }

  async function verify(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!challenge) return;
    setBusy(true); setError("");
    try {
      const account = activeAccount.current;
      if (!account) throw new Error("Reinicie o login.");
      const device = await customerDevice(account);
      const response = await fetch(`${endpoint}/auth/otp`, { method: "POST",
        headers: { "content-type": "application/json" }, cache: "no-store",
        body: JSON.stringify({ challenge_id: challenge.challenge_id, otp,
          device_public_key: device.publicKey,
          device_signature: await signDeviceMessage(account, challenge.device_proof_message) }) });
      const session = await readJson<CustomerSession>(response);
      sessionGeneration.current++;
      refreshToken.current = session.refresh_token;
      currentAccess.current = session.access_token;
      setAccess(session.access_token);
      setChallenge(null); setOtp("");
      const generation = sessionGeneration.current;
      const [security, ...content] = await Promise.allSettled([
        loadDeviceNotices(), load(), loadIncidentNotices(), loadTransfers(),
        loadAccounts(), loadClosedCredits(),
        loadCreditCards(),
      ]);
      if (generation === sessionGeneration.current) {
        if (security.status === "rejected") setDeviceNoticeError(true);
        if (content.some((result) => result.status === "rejected"))
          setError("Sessão iniciada, mas alguns dados não puderam ser carregados.");
      }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Falha ao confirmar código.");
    } finally { setBusy(false); }
  }

  async function more(): Promise<void> {
    const last = notices.at(-1);
    if (!last) return;
    setBusy(true); setError("");
    try { await load(last.id); }
    catch (failure) {
      setError(failure instanceof Error ? failure.message : "Falha ao carregar avisos.");
    } finally { setBusy(false); }
  }

  async function morePix(): Promise<void> {
    const last = transfers.at(-1);
    if (!last) return;
    setBusy(true); setError("");
    try { await loadTransfers(last.id); }
    catch (failure) {
      setError(failure instanceof Error ? failure.message : "Falha ao carregar Pix.");
    } finally { setBusy(false); }
  }

  async function openCase(transfer: Transfer): Promise<void> {
    if (!transfer.med_case_id && !window.confirm("Abrir uma contestação MED para este Pix fictício?")) return;
    const generation = sessionGeneration.current;
    setBusy(true); setError(""); setSelectedCase(null);
    try {
      let caseId = transfer.med_case_id;
      if (!caseId) {
        const account = activeAccount.current;
        if (!account) throw new Error("Sessão encerrada.");
        const body = { transfer_id: transfer.id };
        const proof = await readJson<{ challenge_id: string; message: string }>(
          await authorized("/devices/current/operation-challenge", { method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ method: "POST", path: "/pix/med", body }) }));
        const opened = await readJson<{ id: string }>(await authorized("/pix/med", {
          method: "POST", headers: { "content-type": "application/json",
            "x-device-challenge": proof.challenge_id,
            "x-device-signature": await signDeviceMessage(account, proof.message) },
          body: JSON.stringify(body) }));
        caseId = opened.id;
        await loadTransfers();
      }
      const result = await readJson<MedCase>(await authorized(`/pix/med/${encodeURIComponent(caseId)}`));
      if (generation === sessionGeneration.current) setSelectedCase(result);
    } catch (failure) {
      if (generation === sessionGeneration.current)
        setError(failure instanceof Error ? failure.message : "Falha ao consultar a contestação.");
    } finally { if (generation === sessionGeneration.current) setBusy(false); }
  }

  async function closeAccount(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const id = closingAccountId;
    if (!id) return;
    const account = accounts.find((item) => item.id === id);
    if (!account || account.status !== "active" ||
      !window.confirm(`Encerrar a conta fictícia ${account.branch_code}/${account.account_number}-${account.account_digit}? Esta ação não pode ser desfeita.`))
      return;
    const generation = sessionGeneration.current;
    setBusy(true); setError("");
    try {
      const customer = activeAccount.current;
      if (!customer) throw new Error("Sessão encerrada.");
      await readJson(await authorized("/auth/step-up", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: closePassword }) }));
      const path = `/accounts/${encodeURIComponent(id)}/close`;
      const proof = await readJson<{ challenge_id: string; message: string }>(
        await authorized("/devices/current/operation-challenge", { method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ method: "POST", path }) }));
      await readJson(await authorized(path, { method: "POST",
        headers: { "x-device-challenge": proof.challenge_id,
          "x-device-signature": await signDeviceMessage(customer, proof.message) } }));
      if (generation === sessionGeneration.current) {
        setClosingAccountId(null);
        await loadAccounts();
      }
    } catch (failure) {
      if (generation === sessionGeneration.current)
        setError(failure instanceof Error ? failure.message : "Falha ao encerrar a conta.");
    } finally { if (generation === sessionGeneration.current) {
      setClosePassword(""); setBusy(false); } }
  }

  async function openPaymentAccount(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const generation = sessionGeneration.current;
    setBusy(true); setError("");
    try {
      const customer = activeAccount.current;
      if (!customer) throw new Error("Sessão encerrada.");
      await readJson(await authorized("/auth/step-up", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: paymentOpenPassword }) }));
      const path = "/accounts/payment";
      const proof = await readJson<{ challenge_id: string; message: string }>(
        await authorized("/devices/current/operation-challenge", { method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ method: "POST", path }) }));
      await readJson(await authorized(path, { method: "POST", headers: {
        "x-device-challenge": proof.challenge_id,
        "x-device-signature": await signDeviceMessage(customer, proof.message) } }));
      if (generation === sessionGeneration.current) {
        setOpeningPayment(false);
        await loadAccounts();
      }
    } catch (failure) {
      if (generation === sessionGeneration.current)
        setError(failure instanceof Error ? failure.message : "Falha ao abrir a conta de pagamento.");
    } finally { if (generation === sessionGeneration.current) {
      setPaymentOpenPassword(""); setBusy(false); } }
  }

  async function portSalary(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const salary = accounts.find((account) => account.id === portingSalaryId &&
      account.kind === "salary" && account.status === "active");
    const destination = accounts.find((account) => account.id === salaryDestination &&
      (account.kind === "checking" || account.kind === "payment") &&
      account.status === "active");
    const match = /^(\d{1,9})(?:,(\d{1,2}))?$/.exec(salaryAmount.trim());
    const amount = match ? Number(match[1]) * 100 +
      Number((match[2] ?? "").padEnd(2, "0")) : 0;
    if (!salary || !destination || !Number.isSafeInteger(amount) || amount <= 0 ||
      amount > salary.available_balance_cents) {
      setError("Informe uma conta sua e um valor até o saldo disponível da conta-salário.");
      return;
    }
    const generation = sessionGeneration.current;
    setBusy(true); setError("");
    try {
      const customer = activeAccount.current;
      if (!customer) throw new Error("Sessão encerrada.");
      const fingerprint = [salary.id, destination.id, amount].join(":");
      if (salaryPortAttempt.current?.fingerprint !== fingerprint)
        salaryPortAttempt.current = { fingerprint, key: crypto.randomUUID() };
      const path = `/accounts/${encodeURIComponent(salary.id)}/salary-port`;
      const body = { destination_account_id: destination.id, amount_cents: amount,
        idempotency_key: salaryPortAttempt.current.key };
      await readJson(await authorized("/auth/step-up", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: salaryPassword }) }));
      const proof = await readJson<{ challenge_id: string; message: string }>(
        await authorized("/devices/current/operation-challenge", { method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ method: "POST", path, body }) }));
      await readJson(await authorized(path, { method: "POST", headers: {
        "content-type": "application/json",
        "x-device-challenge": proof.challenge_id,
        "x-device-signature": await signDeviceMessage(customer, proof.message) },
        body: JSON.stringify(body) }));
      if (generation === sessionGeneration.current) {
        salaryPortAttempt.current = null; setPortingSalaryId(null);
        setSalaryAmount(""); await loadAccounts();
      }
    } catch (failure) {
      if (generation === sessionGeneration.current)
        setError(failure instanceof Error ? failure.message : "Falha ao transferir o salário.");
    } finally { if (generation === sessionGeneration.current) {
      setSalaryPassword(""); setBusy(false); } }
  }

  async function openSalaryOptions(account: Account): Promise<void> {
    if (portingSalaryId === account.id) { setPortingSalaryId(null); return; }
    setPortingSalaryId(account.id); setSalaryInstructionLoaded(false);
    setSalaryAutoMessage(""); setError(""); setSalaryPassword("");
    setSalaryAmount((account.available_balance_cents / 100).toFixed(2).replace(".", ","));
    salaryPortAttempt.current = null;
    const generation = sessionGeneration.current;
    setBusy(true);
    try {
      const instruction = await readJson<{ destination_account_id: string | null }>(
        await authorized(`/accounts/${encodeURIComponent(account.id)}/salary-portability`));
      if (generation !== sessionGeneration.current) return;
      setSalaryInstructionDestination(instruction.destination_account_id);
      setSalaryDestination(instruction.destination_account_id ??
        accounts.find((item) => item.status === "active" &&
          (item.kind === "checking" || item.kind === "payment"))?.id ?? "");
      setSalaryInstructionLoaded(true);
    } catch (failure) {
      if (generation === sessionGeneration.current)
        setError(failure instanceof Error ? failure.message : "Falha ao consultar a portabilidade.");
    } finally { if (generation === sessionGeneration.current) setBusy(false); }
  }

  async function configureSalaryPortability(destinationId: string | null): Promise<void> {
    const salary = accounts.find((account) => account.id === portingSalaryId &&
      account.kind === "salary" && account.status === "active");
    const destination = destinationId === null ? null : accounts.find((account) =>
      account.id === destinationId && account.status === "active" &&
      (account.kind === "checking" || account.kind === "payment"));
    if (!salary || destinationId !== null && !destination) {
      setError("Escolha uma conta corrente ou de pagamento em seu nome."); return;
    }
    const generation = sessionGeneration.current;
    setBusy(true); setError(""); setSalaryAutoMessage("");
    try {
      const customer = activeAccount.current;
      if (!customer) throw new Error("Sessão encerrada.");
      const path = `/accounts/${encodeURIComponent(salary.id)}/salary-portability`;
      const body = { destination_account_id: destinationId };
      await readJson(await authorized("/auth/step-up", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: salaryPassword }) }));
      const proof = await readJson<{ challenge_id: string; message: string }>(
        await authorized("/devices/current/operation-challenge", { method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ method: "POST", path, body }) }));
      await readJson(await authorized(path, { method: "POST", headers: {
        "content-type": "application/json", "x-device-challenge": proof.challenge_id,
        "x-device-signature": await signDeviceMessage(customer, proof.message) },
        body: JSON.stringify(body) }));
      if (generation === sessionGeneration.current) {
        setSalaryInstructionDestination(destinationId);
        setSalaryAutoMessage(destinationId === null ?
          "Portabilidade automática cancelada." :
          "Os próximos salários serão transferidos automaticamente para a conta escolhida.");
      }
    } catch (failure) {
      if (generation === sessionGeneration.current)
        setError(failure instanceof Error ? failure.message : "Falha ao configurar a portabilidade.");
    } finally { if (generation === sessionGeneration.current) {
      setSalaryPassword(""); setBusy(false); } }
  }

  async function claimClosedCredit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const credit = closedCredits.find((item) => item.id === claimCreditId);
    const destination = accounts.find((item) => item.id === claimDestination &&
      item.status === "active");
    if (!credit || !destination || !window.confirm(`Receber ${
      (credit.amount_cents / 100).toLocaleString("pt-BR", { style: "currency", currency: "BRL" })
    } na conta ${destination.account_number}-${destination.account_digit}?`)) return;
    const generation = sessionGeneration.current;
    setBusy(true); setError("");
    try {
      const customer = activeAccount.current;
      if (!customer) throw new Error("Sessão encerrada.");
      await readJson(await authorized("/auth/step-up", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: claimPassword }) }));
      const path = `/accounts/closed-credits/${encodeURIComponent(credit.id)}/claim`;
      const body = { destination_account_id: destination.id };
      const proof = await readJson<{ challenge_id: string; message: string }>(
        await authorized("/devices/current/operation-challenge", { method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ method: "POST", path, body }) }));
      await readJson(await authorized(path, { method: "POST",
        headers: { "content-type": "application/json",
          "x-device-challenge": proof.challenge_id,
          "x-device-signature": await signDeviceMessage(customer, proof.message) },
        body: JSON.stringify(body) }));
      if (generation === sessionGeneration.current) {
        setClaimCreditId(null); setClaimDestination("");
        await Promise.all([loadClosedCredits(), loadAccounts()]);
      }
    } catch (failure) {
      if (generation === sessionGeneration.current)
        setError(failure instanceof Error ? failure.message : "Falha ao receber o crédito.");
    } finally { if (generation === sessionGeneration.current) {
      setClaimPassword(""); setBusy(false); } }
  }

  async function payCreditStatement(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const target = payingStatement;
    if (!target) return;
    const match = /^(\d{1,9})(?:,(\d{1,2}))?$/.exec(paymentAmount.trim());
    const amount = match ? Number(match[1]) * 100 + Number((match[2] ?? "").padEnd(2, "0")) : 0;
    const account = accounts.find((item) => item.id === paymentAccount &&
      item.kind === "checking" && item.status === "active");
    const statement = creditCards.find((card) => card.id === target.cardId)?.statements
      .find((item) => item.id === target.statementId);
    if (!Number.isSafeInteger(amount) || amount <= 0 || !account || !statement ||
      amount > statement.due_cents - statement.paid_cents) {
      setError("Informe um valor válido, dentro do saldo da fatura, e uma conta corrente ativa.");
      return;
    }
    const generation = sessionGeneration.current;
    setBusy(true); setError("");
    try {
      const customer = activeAccount.current;
      if (!customer) throw new Error("Sessão encerrada.");
      const fingerprint = [target.cardId, target.statementId, account.id, amount].join(":");
      if (paymentAttempt.current?.fingerprint !== fingerprint)
        paymentAttempt.current = { fingerprint, key: crypto.randomUUID() };
      const path = `/cards/credit/${encodeURIComponent(target.cardId)}/statements/${
        encodeURIComponent(target.statementId)}/pay`;
      const body = { source_account_id: account.id, amount_cents: amount,
        idempotency_key: paymentAttempt.current.key };
      await readJson(await authorized("/auth/step-up", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: paymentPassword }) }));
      const proof = await readJson<{ challenge_id: string; message: string }>(
        await authorized("/devices/current/operation-challenge", { method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ method: "POST", path, body }) }));
      await readJson(await authorized(path, { method: "POST",
        headers: { "content-type": "application/json",
          "x-device-challenge": proof.challenge_id,
          "x-device-signature": await signDeviceMessage(customer, proof.message) },
        body: JSON.stringify(body) }));
      if (generation === sessionGeneration.current) {
        paymentAttempt.current = null;
        setPayingStatement(null); setPaymentAmount("");
        await Promise.all([loadCreditCards(), loadAccounts()]);
      }
    } catch (failure) {
      if (generation === sessionGeneration.current)
        setError(failure instanceof Error ? failure.message : "Falha ao pagar a fatura.");
    } finally { if (generation === sessionGeneration.current) {
      setPaymentPassword(""); setBusy(false); } }
  }

  async function installmentCreditStatement(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const target = planningStatement;
    if (!target) return;
    const installments = Number(planInstallments);
    const statement = creditCards.find((card) => card.id === target.cardId)?.statements
      .find((item) => item.id === target.statementId);
    if (!Number.isSafeInteger(installments) || installments < 2 || installments > 24 ||
      !statement || statement.status !== "open" ||
      statement.paid_cents < statement.minimum_due_cents ||
      statement.due_cents - statement.paid_cents < installments) {
      setError("Pague o mínimo e escolha de 2 a 24 parcelas para o saldo restante.");
      return;
    }
    const generation = sessionGeneration.current;
    setBusy(true); setError(""); setPlanNotice("");
    try {
      const customer = activeAccount.current;
      if (!customer) throw new Error("Sessão encerrada.");
      const path = `/cards/credit/${encodeURIComponent(target.cardId)}/statements/${
        encodeURIComponent(target.statementId)}/installment-plan`;
      const body = { installments };
      await readJson(await authorized("/auth/step-up", { method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: planPassword }) }));
      const proof = await readJson<{ challenge_id: string; message: string }>(
        await authorized("/devices/current/operation-challenge", { method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ method: "POST", path, body }) }));
      const result = await readJson<{ principal_cents: number; interest_cents: number }>(
        await authorized(path, { method: "POST", headers: {
          "content-type": "application/json", "x-device-challenge": proof.challenge_id,
          "x-device-signature": await signDeviceMessage(customer, proof.message) },
          body: JSON.stringify(body) }));
      if (generation === sessionGeneration.current) {
        setPlanningStatement(null);
        setPlanNotice(`Fatura parcelada em ${installments} vezes. Saldo financiado ${
          (result.principal_cents / 100).toLocaleString("pt-BR", { style: "currency",
            currency: "BRL" })}; juros ${
              (result.interest_cents / 100).toLocaleString("pt-BR", { style: "currency",
                currency: "BRL" })}.`);
        await loadCreditCards();
      }
    } catch (failure) {
      if (generation === sessionGeneration.current)
        setError(failure instanceof Error ? failure.message : "Falha ao parcelar a fatura.");
    } finally { if (generation === sessionGeneration.current) {
      setPlanPassword(""); setBusy(false); } }
  }

  async function logout(): Promise<void> {
    const token = currentAccess.current;
    const renewalToken = refreshToken.current;
    const account = activeAccount.current;
    clearSession(); setChallenge(null);
    setCpf(""); setPassword(""); setOtp(""); setError("");
    if (token) try {
      const signout = (accessToken: string) => fetch(`${endpoint}/auth/logout`, { method: "POST",
        headers: { authorization: `Bearer ${accessToken}` }, cache: "no-store" });
      const response = await signout(token);
      if (await expiredAccess(response) && renewalToken && account) {
        await signout((await renewSession(renewalToken, account)).access_token);
      }
    } catch { /* The local session has already been cleared. */ }
  }

  return <main className="customer-page"><small>APP DO CLIENTE · AMBIENTE FICTÍCIO</small>
    <h1>Suas contas, Pix e avisos</h1>
    {!available ? <p>O banco local precisa estar em execução para abrir esta página.</p> :
    presentation ? <p>Conteúdo do cliente oculto no modo apresentação.</p> : <>
      {error && <p role="alert" className="customer-error">{error}</p>}
      {signupMessage && !access && <p role="status">{signupMessage}</p>}
      {!access && !challenge && !signupMode && <form onSubmit={(event) => { void begin(event); }}>
        <label>CPF fictício<input inputMode="numeric" autoComplete="username" required disabled={busy}
          value={cpf} onChange={(event) => setCpf(event.target.value)}/></label>
        <label>Senha<input type="password" autoComplete="current-password" required disabled={busy}
          value={password} onChange={(event) => setPassword(event.target.value)}/></label>
        <button disabled={busy}>{busy ? "Entrando…" : "Continuar"}</button>
        <button type="button" disabled={busy} onClick={() => { setSignupMode(true);
          setSignupMessage(""); setError(""); }}>Solicitar nova conta</button>
      </form>}
      {!access && !challenge && signupMode && <form onSubmit={(event) => {
        void submitSignup(event); }}>
        <p>Solicite uma conta fictícia. A análise de identidade será concluída pelos operadores locais.</p>
        <label>CPF fictício<input inputMode="numeric" autoComplete="username" required
          disabled={busy} value={cpf} onChange={(event) => setCpf(event.target.value)}/></label>
        <label>Nome<input autoComplete="name" required minLength={3} maxLength={120}
          disabled={busy} value={signupName}
          onChange={(event) => setSignupName(event.target.value)}/></label>
        <label>Perfil<select disabled={busy} value={signupPersona}
          onChange={(event) => setSignupPersona(event.target.value)}>
          <option value="salaried">Assalariado</option>
          <option value="merchant">Comerciante</option>
          <option value="student">Estudante</option>
          <option value="retiree">Aposentado</option>
          <option value="gig">Autônomo</option>
          <option value="saver">Poupador</option>
          <option value="night_owl">Noturno</option>
        </select></label>
        <label>Crie uma senha<input type="password" autoComplete="new-password" required
          minLength={12} maxLength={256} disabled={busy} value={signupPassword}
          onChange={(event) => setSignupPassword(event.target.value)}/></label>
        <button disabled={busy}>{busy ? "Enviando…" : "Enviar solicitação"}</button>
        <button type="button" disabled={busy} onClick={() => { setSignupMode(false);
          setSignupPassword(""); setError(""); }}>Voltar</button>
      </form>}
      {!access && challenge && <form onSubmit={(event) => { void verify(event); }}>
        <p>Este banco é uma simulação local. Em outro terminal, na pasta do projeto, rode <code>pnpm customer:otp {cpf.replace(/\D/g, "")} {challenge.challenge_id}</code> e digite o código de seis dígitos. Ele não aparece nesta página.</p>
        <label>Código<input inputMode="numeric" autoComplete="one-time-code"
          pattern="[0-9]{6}" maxLength={6} required value={otp}
          onChange={(event) => setOtp(event.target.value)}/></label>
        <button disabled={busy}>{busy ? "Confirmando…" : "Confirmar código"}</button>
        <button type="button" disabled={busy} onClick={() => { setChallenge(null); setOtp("");
          activeAccount.current = null; setError(""); }}>Voltar</button>
      </form>}
      {access && <><section aria-label="Contas do cliente">
        <h2>Suas contas</h2>
        {accounts.length ? <ol>{accounts.map((account) => <li key={account.id}>
          <strong>{account.kind === "merchant" ? "Conta mercantil" :
            account.kind === "payment" ? "Conta de pagamento" :
            account.kind === "salary" ? "Conta-salário" : "Conta corrente"} · agência {
            account.branch_code} · conta {account.account_number}-{account.account_digit}</strong>
          <p>Situação: {account.status === "active" ? "ativa" : account.status === "closed" ?
            "encerrada" : account.status === "under_review" ? "em análise" : "bloqueada"} · saldo contábil {(account.balance_cached / 100)
              .toLocaleString("pt-BR", { style: "currency", currency: "BRL" })} · disponível {
                (account.available_balance_cents / 100).toLocaleString("pt-BR", {
                  style: "currency", currency: "BRL" })}</p>
          {!presentation && account.kind === "salary" && account.status === "active" &&
            <button disabled={busy} onClick={() => { void openSalaryOptions(account); }}>
            {portingSalaryId === account.id ? "Fechar portabilidade" : "Portabilidade de salário"}</button>}
          {!presentation && portingSalaryId === account.id &&
            <form onSubmit={(event) => { void portSalary(event); }}>
              <p>Escolha uma conta corrente ou de pagamento em seu nome.</p>
              {salaryInstructionLoaded && <p>Portabilidade automática: {
                salaryInstructionDestination ? "ativa" : "desativada"}.</p>}
              {salaryAutoMessage && <p role="status">{salaryAutoMessage}</p>}
              <label>Conta de destino<select required disabled={busy} value={salaryDestination}
                onChange={(event) => setSalaryDestination(event.target.value)}>
                <option value="">Selecione uma conta</option>
                {accounts.filter((item) => item.status === "active" &&
                  (item.kind === "checking" || item.kind === "payment")).map((item) =>
                  <option key={item.id} value={item.id}>{item.account_number}-{item.account_digit}</option>)}
              </select></label>
              {account.available_balance_cents > 0 &&
                <label>Valor para transferir agora, em reais<input required
                  inputMode="decimal" disabled={busy} value={salaryAmount}
                  onChange={(event) => setSalaryAmount(event.target.value)} /></label>}
              <label>Senha atual<input type="password" autoComplete="current-password"
                required disabled={busy} value={salaryPassword}
                onChange={(event) => setSalaryPassword(event.target.value)} /></label>
              {account.available_balance_cents > 0 &&
                <button disabled={busy}>{busy ? "Transferindo…" : "Transferir saldo agora"}</button>}
              <button type="button" disabled={busy || !salaryInstructionLoaded ||
                !salaryDestination || !salaryPassword}
                onClick={() => { void configureSalaryPortability(salaryDestination); }}>
                Ativar portabilidade automática</button>
              {salaryInstructionDestination && <button type="button"
                disabled={busy || !salaryPassword}
                onClick={() => { void configureSalaryPortability(null); }}>
                Cancelar portabilidade automática</button>}
            </form>}
          {account.status === "active" && account.balance_cached !== 0 &&
            <small>Para encerrar esta conta, primeiro deixe o saldo contábil em zero.</small>}
          {account.status === "active" && account.balance_cached === 0 && <button disabled={busy}
            onClick={() => { setClosingAccountId((current) => current === account.id ? null : account.id);
              setClosePassword(""); setError(""); }}>
            {closingAccountId === account.id ? "Cancelar encerramento" : "Encerrar conta"}</button>}
          {closingAccountId === account.id && account.balance_cached === 0 &&
            <form className="customer-close-form"
            onSubmit={(event) => { void closeAccount(event); }}>
            <p>Confirme sua senha. O banco só encerra contas com saldo zero e sem obrigações pendentes.</p>
            <label>Senha atual<input type="password" autoComplete="current-password" required
              disabled={busy} value={closePassword}
              onChange={(event) => setClosePassword(event.target.value)}/></label>
            <button disabled={busy}>{busy ? "Verificando…" : "Confirmar encerramento"}</button>
          </form>}
        </li>)}</ol> : <p>Nenhuma conta disponível.</p>}
        {!presentation && accounts.some((account) => account.status === "active") &&
          accounts.filter((account) => account.status !== "closed").length < 2 && <>
          <button disabled={busy} onClick={() => { setOpeningPayment((current) => !current);
            setPaymentOpenPassword(""); setError(""); }}>
            {openingPayment ? "Cancelar abertura" : "Abrir conta de pagamento"}</button>
          {openingPayment && <form onSubmit={(event) => { void openPaymentAccount(event); }}>
            <p>A conta de pagamento é pré-paga e não possui cheque especial.</p>
            <label>Senha atual<input type="password" autoComplete="current-password"
              required disabled={busy} value={paymentOpenPassword}
              onChange={(event) => setPaymentOpenPassword(event.target.value)} /></label>
            <button disabled={busy}>{busy ? "Abrindo…" : "Confirmar abertura"}</button>
          </form>}</>}
      </section>{!presentation && <CustomerLoans authorized={authorized}
        customer={activeAccount.current ?? ""} accounts={accounts}
        onFinancialChange={loadAccounts} />}<section aria-label="Cartão de crédito">
        <h2>Cartão de crédito</h2>
        {planNotice && <p role="status">{planNotice}</p>}
        {creditCards.length ? <ol>{creditCards.map((card) => <li key={card.id}>
          <strong>Limite {(card.limit_cents / 100).toLocaleString("pt-BR", {
            style: "currency", currency: "BRL" })}</strong>
          <p>Disponível {(card.available_limit_cents / 100).toLocaleString("pt-BR", {
            style: "currency", currency: "BRL" })} · em aberto {
              (card.outstanding_cents / 100).toLocaleString("pt-BR", {
                style: "currency", currency: "BRL" })} · {
                card.status === "active" ? "ativo" : "bloqueado"}</p>
          {card.statements.length ? <ol>{card.statements.slice(0, 6).map((statement) => {
            const remaining = statement.due_cents - statement.paid_cents;
            const selected = payingStatement?.cardId === card.id &&
              payingStatement.statementId === statement.id;
            const planning = planningStatement?.cardId === card.id &&
              planningStatement.statementId === statement.id;
            const planInterest = Math.round(remaining * card.policy.invoice_plan_interest_bps / 10_000);
            return <li key={statement.id}>
              <strong>Fatura de {new Date(`${statement.closing_date}T12:00:00Z`)
                .toLocaleDateString("pt-BR", { timeZone: "UTC" })}</strong>
              <p>Vencimento {new Date(`${statement.due_date}T12:00:00Z`)
                .toLocaleDateString("pt-BR", { timeZone: "UTC" })} · {
                  statement.status === "financed" ? <>fatura parcelada; saldo financiado {
                    (remaining / 100).toLocaleString("pt-BR", {
                      style: "currency", currency: "BRL" })}; parcelas nas próximas faturas</> :
                  statement.status === "paid" ? "fatura paga" : <>restante {
                    (remaining / 100).toLocaleString("pt-BR", {
                      style: "currency", currency: "BRL" })} · pagamento mínimo {
                    (statement.minimum_due_cents / 100).toLocaleString("pt-BR", {
                      style: "currency", currency: "BRL" })}</>}</p>
              {statement.status === "open" && remaining > 0 &&
                <button disabled={busy} onClick={() => {
                  setPayingStatement(selected ? null : { cardId: card.id, statementId: statement.id });
                  setPaymentAmount((remaining / 100).toFixed(2).replace(".", ","));
                  setPaymentAccount(accounts.find((item) => item.kind === "checking" &&
                    item.status === "active")?.id ?? "");
                  setPlanningStatement(null); setPlanPassword("");
                  setPaymentPassword(""); setError(""); paymentAttempt.current = null;
                }}>{selected ? "Cancelar pagamento" : "Pagar fatura"}</button>}
              {selected && <form onSubmit={(event) => { void payCreditStatement(event); }}>
                <p>Confirme sua senha e escolha quanto pagar. Valores abaixo do mínimo ou após o vencimento podem gerar encargos.</p>
                <label>Valor em reais<input required inputMode="decimal" disabled={busy}
                  value={paymentAmount} onChange={(event) => setPaymentAmount(event.target.value)}
                  placeholder="0,00" /></label>
                <label>Conta de pagamento<select required disabled={busy} value={paymentAccount}
                  onChange={(event) => setPaymentAccount(event.target.value)}>
                  <option value="">Selecione uma conta</option>
                  {accounts.filter((item) => item.kind === "checking" && item.status === "active")
                    .map((item) => <option key={item.id} value={item.id}>{
                      item.branch_code}/{item.account_number}-{item.account_digit}</option>)}
                </select></label>
                <label>Senha atual<input type="password" autoComplete="current-password"
                  required disabled={busy} value={paymentPassword}
                  onChange={(event) => setPaymentPassword(event.target.value)} /></label>
                <button disabled={busy}>{busy ? "Processando…" : "Confirmar pagamento"}</button>
              </form>}
              {statement.status === "open" && remaining >= 2 &&
                statement.paid_cents >= statement.minimum_due_cents &&
                <button disabled={busy} onClick={() => {
                  setPlanningStatement(planning ? null : {
                    cardId: card.id, statementId: statement.id });
                  setPlanInstallments(String(Math.min(3, remaining)));
                  setPlanPassword(""); setPayingStatement(null); setPaymentPassword("");
                  setError(""); setPlanNotice("");
                }}>{planning ? "Cancelar parcelamento" : "Parcelar saldo restante"}</button>}
              {statement.status === "open" && remaining > 0 &&
                statement.paid_cents < statement.minimum_due_cents &&
                <small>Após pagar o mínimo, você pode parcelar o saldo restante.</small>}
              {planning && <form onSubmit={(event) => {
                void installmentCreditStatement(event); }}>
                <p>Saldo exibido: {(remaining / 100).toLocaleString("pt-BR", {
                  style: "currency", currency: "BRL" })}. Juros fixos estimados: {
                    (planInterest / 100).toLocaleString("pt-BR", {
                      style: "currency", currency: "BRL" })} ({
                        (card.policy.invoice_plan_interest_bps / 100).toLocaleString("pt-BR")}%);
                  total estimado: {((remaining + planInterest) / 100).toLocaleString("pt-BR", {
                    style: "currency", currency: "BRL" })}. Encargos por atraso podem mudar
                  o valor final antes da contratação.</p>
                <label>Quantidade de parcelas<select required disabled={busy}
                  value={planInstallments}
                  onChange={(event) => setPlanInstallments(event.target.value)}>
                  {Array.from({ length: Math.min(23, remaining - 1) }, (_, index) => index + 2)
                    .map((count) => <option key={count} value={count}>{count} parcelas</option>)}
                </select></label>
                <label>Senha atual<input type="password" autoComplete="current-password"
                  required disabled={busy} value={planPassword}
                  onChange={(event) => setPlanPassword(event.target.value)} /></label>
                <button disabled={busy}>{busy ? "Processando…" : "Confirmar parcelamento"}</button>
              </form>}
            </li>;
          })}</ol> : <p>Nenhuma fatura fechada.</p>}
        </li>)}</ol> : <p>Nenhum cartão de crédito ativo.</p>}
      </section><CustomerCardSubscriptions authorized={authorized}
        customer={activeAccount.current ?? ""} /><section aria-label="Créditos de contas encerradas">
        <h2>Créditos de contas encerradas</h2>
        {closedCredits.length ? <ol>{closedCredits.map((credit) => <li key={credit.id}>
          <strong>{credit.source_kind === "pix_return" ? "Devolução Pix" : "Recuperação MED"} · {
            (credit.amount_cents / 100).toLocaleString("pt-BR", {
              style: "currency", currency: "BRL" })}</strong>
          <p>Recebido em {new Date(credit.created_at).toLocaleString("pt-BR", {
            timeZone: "America/Sao_Paulo" })} após o encerramento da conta de origem.</p>
          {accounts.some((account) => account.status === "active" && account.kind !== "salary") ? <button disabled={busy}
            onClick={() => { setClaimCreditId((current) => current === credit.id ? null : credit.id);
              setClaimDestination(accounts.find((account) => account.status === "active" &&
                account.kind !== "salary")?.id ?? "");
              setClaimPassword(""); setError(""); }}>
            {claimCreditId === credit.id ? "Cancelar recebimento" : "Receber crédito"}</button> :
            <small>É preciso ter uma conta ativa para receber este crédito.</small>}
          {claimCreditId === credit.id && <form onSubmit={(event) => {
            void claimClosedCredit(event); }}>
            <label>Conta de destino<select required disabled={busy} value={claimDestination}
              onChange={(event) => setClaimDestination(event.target.value)}>
              {accounts.filter((account) => account.status === "active" &&
                account.kind !== "salary").map((account) =>
                <option key={account.id} value={account.id}>{account.branch_code} / {
                  account.account_number}-{account.account_digit}</option>)}</select></label>
            <label>Senha atual<input type="password" autoComplete="current-password" required
              disabled={busy} value={claimPassword}
              onChange={(event) => setClaimPassword(event.target.value)}/></label>
            <button disabled={busy}>{busy ? "Verificando…" : "Confirmar recebimento"}</button>
          </form>}
        </li>)}</ol> : <p>Nenhum crédito pendente.</p>}
        {creditsCursor !== null && <button disabled={busy} onClick={() => {
          setBusy(true); setError("");
          void loadClosedCredits(creditsCursor).catch((failure: unknown) =>
            setError(failure instanceof Error ? failure.message : "Falha ao carregar créditos."))
            .finally(() => setBusy(false)); }}>Carregar mais créditos</button>}
      </section><section aria-label="Segurança do dispositivo">
        <h2>Segurança do dispositivo</h2>
        {deviceNotices.length > 0 && <ol>{deviceNotices.map((notice) => <li key={notice.id}>
          Um novo aparelho foi vinculado à sua conta em {new Date(notice.twin_at)
            .toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" })} (horário da simulação).
        </li>)}</ol>}
        {deviceNoticeError && <p role="alert">Não foi possível consultar os avisos de segurança.
          <button disabled={busy} onClick={() => { void refreshDeviceNotices(); }}>Tentar novamente</button></p>}
        {deviceCursor !== null && <button disabled={busy}
          onClick={() => { void refreshDeviceNotices(deviceCursor); }}>Mais avisos de segurança</button>}
      </section><section aria-label="Avisos do pagador">
        <div className="customer-inbox-heading"><h2>Seus avisos</h2>
          <button disabled={busy} onClick={() => { void logout(); }}>Sair</button></div>
        <h3>Incidentes e recuperação</h3>
        <button disabled={busy} onClick={() => { void loadIncidentNotices().catch(
          () => setError("Não foi possível atualizar os avisos de incidentes.")); }}>
          Atualizar avisos de incidentes</button>
        {incidentNotices.length ? <ol>{incidentNotices.map((notice) => <li key={notice.id}>
          <time dateTime={notice.created_at}>{new Date(notice.created_at).toLocaleString("pt-BR",
            { timeZone: "America/Sao_Paulo" })}</time>
          <p>{notice.message_pt}</p></li>)}</ol> :
          <p>Nenhum aviso de incidente por enquanto.</p>}
        {incidentCursor !== null && <button disabled={busy}
          onClick={() => { void loadIncidentNotices(incidentCursor).catch(
            () => setError("Não foi possível carregar os avisos anteriores.")); }}>
          Mais avisos de incidentes</button>}
        <h3>Pix Automático</h3>
        {notices.length ? <ol>{notices.map((notice) => <li key={notice.id}>
          <time dateTime={notice.created_at}>{new Date(notice.created_at).toLocaleString("pt-BR",
            { timeZone: "America/Sao_Paulo" })}</time>
          <p>{notice.message_pt}</p></li>)}</ol> : <p>Nenhum aviso por enquanto.</p>}
        {hasMore && <button disabled={busy} onClick={() => { void more(); }}>
          {busy ? "Carregando…" : "Carregar avisos anteriores"}</button>}
      </section><section aria-label="Pix enviados">
        <h2>Pix enviados</h2>
        {transfers.length ? <ol>{transfers.map((transfer) => <li key={transfer.id}>
          <time dateTime={transfer.initiated_at}>{new Date(transfer.initiated_at).toLocaleString("pt-BR",
            { timeZone: "America/Sao_Paulo" })}</time>
          <p>{(transfer.amount / 100).toLocaleString("pt-BR", { style: "currency",
            currency: "BRL" })} para conta •••• {transfer.to_account.slice(-4)} ·
            {" "}{transferStatus(transfer.status)}
            {transfer.psp_credit_status === "pending" ? " · Crédito no banco recebedor pendente" : ""}</p>
          {(transfer.med_case_id || transfer.status === "settled" ||
            transfer.status === "returned_partial") &&
            <button disabled={busy} onClick={() => { void openCase(transfer); }}>
              {transfer.med_case_id ? "Ver contestação MED" : "Contestar pelo MED"}</button>}
        </li>)}</ol> : <p>Nenhum Pix enviado por enquanto.</p>}
        {moreTransfers && <button disabled={busy} onClick={() => { void morePix(); }}>
          Carregar Pix anteriores</button>}
        {selectedCase && <div role="status"><h3>Contestação {selectedCase.id}</h3>
          <p>Situação: {medStatus(selectedCase.status)}. {medReviewState(selectedCase.review_state)}. Valor contestado:
            {" "}{(selectedCase.claim_amount_cents / 100).toLocaleString("pt-BR", {
              style: "currency", currency: "BRL" })}. Valor devolvido:
            {" "}{(selectedCase.refunded_cents / 100).toLocaleString("pt-BR", {
              style: "currency", currency: "BRL" })}.</p></div>}
      </section>
        {error && <button disabled={busy} onClick={() => { setBusy(true); setError("");
          void Promise.all([load(), loadTransfers(), loadAccounts(), loadClosedCredits()]).catch((failure: unknown) =>
            setError(failure instanceof Error ? failure.message : "Falha ao carregar dados."))
            .finally(() => setBusy(false)); }}>
          Tentar novamente</button>}
      </>}
    </>}
  </main>;
}
