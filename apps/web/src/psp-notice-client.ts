export interface PspStoredKey { identityId: string; privateKey: CryptoKey; publicKey: string; }
export interface PspNotice { type: "cautelar" | "med"; kind: string;
  amount_cents: number; message_pt: string; created_at: string; }
export interface PspNoticePage { items: PspNotice[]; next_cursor: string | null; }

export const PSP_IDENTITY = /^[A-Za-z0-9_-]{3,80}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const API = "/api/client/psp/notices";
const encoder = new TextEncoder();
type Transport = typeof fetch;

function base64url(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
async function signMessage(key: CryptoKey, message: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", key, encoder.encode(message))));
}
async function sha256(value: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function requestJson<T>(transport: Transport, path: string, init: RequestInit): Promise<T> {
  const response = await transport(path, { ...init, cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json() as T;
}
async function post<T>(transport: Transport, path: string, body: object,
  headers: Record<string, string> = {}): Promise<T> {
  return requestJson<T>(transport, path, { method: "POST",
    headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
}
function requireSession(token: string): void {
  if (!TOKEN.test(token)) throw new Error("Invalid PSP session");
}

export async function generatePspKey(identityId: string): Promise<PspStoredKey> {
  if (!PSP_IDENTITY.test(identityId)) throw new Error("Invalid PSP identity");
  const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]) as CryptoKeyPair;
  const publicKey = base64url(new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)));
  return { identityId, privateKey: pair.privateKey, publicKey };
}

export async function loginPsp(identityId: string, privateKey: CryptoKey,
  transport: Transport = fetch): Promise<string> {
  if (!PSP_IDENTITY.test(identityId)) throw new Error("Invalid PSP identity");
  const clientNonce = base64url(crypto.getRandomValues(new Uint8Array(24)));
  const signature = await signMessage(privateKey,
    `BancoVivo:psp-notice:begin-login:v1:${identityId}:${clientNonce}`);
  const challenge = await post<{ challenge_id: string; message: string }>(transport,
    `${API}/login-challenge`, { identity_id: identityId, client_nonce: clientNonce, signature });
  const loginParts = typeof challenge.message === "string" ? challenge.message.split(":") : [];
  if (loginParts.length !== 7 || loginParts[0] !== "BancoVivo" ||
    loginParts[1] !== "psp-notice" || loginParts[2] !== "login" ||
    loginParts[3] !== "v1" || loginParts[4] !== challenge.challenge_id ||
    loginParts[5] !== identityId || !/^[A-Za-z0-9_-]{32}$/.test(loginParts[6] ?? ""))
    throw new Error("Invalid PSP login challenge");
  const result = await post<{ session_token: string }>(transport, `${API}/login`, {
    identity_id: identityId, challenge_id: challenge.challenge_id,
    signature: await signMessage(privateKey, challenge.message),
  });
  requireSession(result.session_token);
  return result.session_token;
}

async function operation(token: string, privateKey: CryptoKey, method: "GET" | "POST",
  cursor: string | null, limit: number, transport: Transport):
  Promise<{ headers: Record<string, string>; path: string }> {
  requireSession(token);
  const body = method === "GET" ? { method, cursor: cursor ?? undefined, limit } : { method };
  const request = method === "GET" ? { cursor, limit } : {};
  const challenge = await post<{ challenge_id: string; message: string }>(transport,
    `${API}/operation-challenge`, body, { authorization: `Bearer ${token}` });
  const parts = typeof challenge.message === "string" ? challenge.message.split(":") : [];
  if (parts.length !== 10 || parts[0] !== "BancoVivo" || parts[1] !== "psp-notice" ||
    parts[2] !== "operation" || parts[3] !== "v1" || parts[4] !== challenge.challenge_id ||
    parts[5] !== await sha256(token) || parts[6] !== method ||
    parts[7] !== (method === "GET" ? "/psp/notices" : "/psp/notices/logout") ||
    parts[8] !== await sha256(JSON.stringify(request)) ||
    !/^[A-Za-z0-9_-]{32}$/.test(parts[9] ?? ""))
    throw new Error("Invalid PSP operation challenge");
  return { path: method === "GET" ? `${API}?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}` :
    `${API}/logout`, headers: { authorization: `Bearer ${token}`,
      "x-psp-challenge": challenge.challenge_id,
      "x-psp-signature": await signMessage(privateKey, challenge.message) } };
}

export async function readPspNotices(token: string, privateKey: CryptoKey,
  cursor: string | null = null, transport: Transport = fetch, limit = 20): Promise<PspNoticePage> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50 ||
    (cursor !== null && !TOKEN.test(cursor))) throw new Error("Invalid PSP notice query");
  const proof = await operation(token, privateKey, "GET", cursor, limit, transport);
  const page = await requestJson<PspNoticePage>(transport, proof.path, { headers: proof.headers });
  if (!page || !Array.isArray(page.items) || !page.items.every((item) =>
    (item.type === "cautelar" || item.type === "med") &&
    typeof item.kind === "string" && typeof item.message_pt === "string" &&
    typeof item.created_at === "string" && Number.isSafeInteger(item.amount_cents)) ||
    (page.next_cursor !== null && (typeof page.next_cursor !== "string" ||
      !TOKEN.test(page.next_cursor)))) throw new Error("Invalid PSP notice page");
  return page;
}

export async function logoutPsp(token: string, privateKey: CryptoKey,
  transport: Transport = fetch): Promise<void> {
  const proof = await operation(token, privateKey, "POST", null, 20, transport);
  await post(transport, proof.path, {}, proof.headers);
}
