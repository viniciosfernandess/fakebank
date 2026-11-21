import { useEffect, useState } from "react";
import { generatePspKey, loginPsp, logoutPsp, PSP_IDENTITY, readPspNotices,
  type PspNotice, type PspStoredKey } from "./psp-notice-client.ts";

const NOTICE_KIND: Record<string, string> = {
  held: "Valor retido", released: "Valor liberado", returned: "Valor devolvido",
  expired: "Retenção encerrada", med_review: "Em análise MED",
  blocked: "Valor bloqueado", recovered: "Valor recuperado",
};
const noticeKey = (notice: PspNotice): string => JSON.stringify([
  notice.type, notice.kind, notice.amount_cents, notice.message_pt,
  notice.created_at,
]);

function keyStore(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("banco-vivo-psp-keys", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("keys", { keyPath: "identityId" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function storedKey(identityId: string): Promise<PspStoredKey | null> {
  const db = await keyStore();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction("keys", "readonly").objectStore("keys").get(identityId);
      request.onsuccess = () => resolve(request.result as PspStoredKey | undefined ?? null);
      request.onerror = () => reject(request.error);
    });
  } finally { db.close(); }
}
async function saveKey(key: PspStoredKey): Promise<void> {
  const db = await keyStore();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction("keys", "readwrite");
      transaction.objectStore("keys").add(key);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  } finally { db.close(); }
}
export function PspCustomerInbox({ available, presentation }: {
  available: boolean; presentation: boolean;
}) {
  const [identityId, setIdentityId] = useState("");
  const [key, setKey] = useState<PspStoredKey | null>(null);
  const [session, setSession] = useState<string | null>(null);
  const [items, setItems] = useState<PspNotice[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [systemNotices, setSystemNotices] = useState(() =>
    typeof Notification !== "undefined" && Notification.permission === "granted");
  useEffect(() => {
    let current = true;
    setKey(null); setSession(null); setItems([]); setCursor(null); setLoaded(false); setError(null);
    if (PSP_IDENTITY.test(identityId)) void storedKey(identityId)
      .then((found) => { if (current) setKey(found); })
      .catch(() => { if (current) setError("Não foi possível abrir a chave local."); });
    return () => { current = false; };
  }, [identityId]);
  useEffect(() => {
    if (!session || !key || !available || presentation) return;
    let active = true;
    let initialized = false;
    const observed = new Set<string>();
    const refresh = async () => {
      try {
        const page = await readPspNotices(session, key.privateKey);
        if (!active) return;
        const fresh = page.items.filter((item) => !observed.has(noticeKey(item)));
        for (const item of page.items) observed.add(noticeKey(item));
        if (initialized && fresh.length && systemNotices &&
          typeof Notification !== "undefined" && Notification.permission === "granted") {
          try {
            new Notification("Banco Vivo — aviso do PSP", {
              body: "Abra a caixa assinada para consultar.",
            });
          } catch { /* Browser system notices are optional; the signed inbox still updates. */ }
        }
        initialized = true;
        setItems((previous) => {
          const seen = new Set(page.items.map(noticeKey));
          const merged = [...page.items, ...previous.filter((item) =>
            !seen.has(noticeKey(item)))].slice(0, 100);
          return merged.length === previous.length &&
            merged.every((item, index) => noticeKey(item) === noticeKey(previous[index]!))
            ? previous : merged;
        });
        setCursor((previous) => previous ?? page.next_cursor);
        setLoaded(true);
      } catch (cause) {
        if (active && cause instanceof Error && cause.message === "HTTP 403") {
          setSession(null); setItems([]); setCursor(null); setLoaded(false);
          setError("A sessão terminou. Entre novamente para consultar os avisos.");
        }
      }
    };
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 15_000);
    return () => { active = false; window.clearInterval(timer); };
  }, [session, key, available, presentation, systemNotices]);

  async function enableSystemNotices(): Promise<void> {
    if (typeof Notification === "undefined" || !window.isSecureContext) return;
    try { setSystemNotices(await Notification.requestPermission() === "granted"); }
    catch { setSystemNotices(false); }
  }

  async function run(work: () => Promise<void>): Promise<void> {
    setBusy(true); setError(null);
    try { await work(); }
    catch (cause) {
      if (session && cause instanceof Error && cause.message === "HTTP 403") {
        setSession(null); setItems([]); setCursor(null); setLoaded(false);
        setError("A sessão terminou. Entre novamente para consultar os avisos.");
      } else setError("Não foi possível concluir a operação. Confira a identidade, a conexão e tente novamente.");
    }
    finally { setBusy(false); }
  }
  async function generateKey(): Promise<void> {
    if (!PSP_IDENTITY.test(identityId) || key) return;
    await run(async () => {
      const created = await generatePspKey(identityId);
      await saveKey(created);
      setKey(created);
    });
  }
  async function login(): Promise<void> {
    if (!key || key.identityId !== identityId) return;
    await run(async () => {
      setSession(await loginPsp(identityId, key.privateKey));
      setItems([]); setCursor(null); setLoaded(false);
    });
  }
  async function loadNotices(nextCursor: string | null = null): Promise<void> {
    await run(async () => {
      if (!session || !key) throw new Error("No PSP session");
      const page = await readPspNotices(session, key.privateKey, nextCursor);
      setItems((previous) => nextCursor ? [...previous, ...page.items] : page.items);
      setCursor(page.next_cursor);
      setLoaded(true);
    });
  }
  async function logout(): Promise<void> {
    await run(async () => {
      if (!session || !key) throw new Error("No PSP session");
      await logoutPsp(session, key.privateKey);
      setSession(null); setItems([]); setCursor(null); setLoaded(false);
    });
  }

  return <main className="page psp-customer-page"><small>BANCO EXTERNO SINTÉTICO</small>
    <h1>Avisos do recebedor</h1>
    {presentation ? <p>Conteúdo do recebedor oculto no modo apresentação.</p> :
      !available ? <p>O banco local precisa estar ativo para consultar os avisos.</p> : <>
      <p>Consulte avisos de cautelar e MED da sua conta no PSP. A chave privada fica somente neste navegador.</p>
      <label>Identidade provisionada<input value={identityId} maxLength={80}
        autoComplete="off" spellCheck={false} onChange={(event) => setIdentityId(event.target.value)}
        placeholder="Ex.: ipe_ana" disabled={busy || Boolean(session)}/></label>
      {PSP_IDENTITY.test(identityId) && !key && <section>
        <p>Gere uma chave local. Entregue apenas a chave pública ao administrador para vincular esta identidade à sua conta.</p>
        <button disabled={busy} onClick={() => { void generateKey(); }}>Gerar chave neste navegador</button>
      </section>}
      {key && <section><h2>Chave pública</h2><textarea readOnly rows={3} value={key.publicKey}
        aria-label="Chave pública para provisionamento"/>
        <p>O administrador precisa provisionar esta chave. Se os dados deste navegador forem apagados, solicite revogação e uma nova chave.</p>
        {!session ? <button disabled={busy} onClick={() => { void login(); }}>Entrar com assinatura</button> :
          <><div className="psp-customer-actions">
            <button disabled={busy} onClick={() => { void loadNotices(); }}>Atualizar avisos</button>
            {typeof Notification !== "undefined" && window.isSecureContext &&
              Notification.permission !== "denied" &&
              <button disabled={busy || systemNotices} onClick={() => { void enableSystemNotices(); }}>
                {systemNotices ? "Avisos do sistema ativos" : "Ativar avisos do sistema"}</button>}
            <button disabled={busy} onClick={() => { void logout(); }}>Sair</button>
          </div>
          {loaded && <><h2>Avisos</h2><p>Esta lista atualiza automaticamente enquanto esta página estiver aberta e você estiver conectado.</p>
            {items.length ? <ol aria-live="polite">{items.map((item, index) =>
            <li key={`${item.created_at}-${item.type}-${index}`}>
              <strong>{item.type === "med" ? "MED" : "Cautelar"} · {NOTICE_KIND[item.kind] ?? item.kind}</strong>
              <p>{item.message_pt}</p><small>{new Date(item.created_at).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })} ·
                {` ${(item.amount_cents / 100).toLocaleString("pt-BR", { style: "currency", currency: "BRL" })}`}</small>
            </li>)}</ol> : <p>Nenhum aviso para esta conta.</p>}
            {cursor && <button disabled={busy} onClick={() => { void loadNotices(cursor); }}>Carregar mais</button>}</>}
          </>}
      </section>}
      {error && <p role="alert">{error}</p>}
    </>}
  </main>;
}
