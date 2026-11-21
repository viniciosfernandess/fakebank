interface BrowserDevice {
  deviceId: string;
  publicKey: string;
  privateKey: CryptoKey;
}

const DATABASE = "banco-vivo-customer-device";
const STORE = "identity";

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function readDevice(db: IDBDatabase, account: string): Promise<BrowserDevice | undefined> {
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get(account);
    request.onsuccess = () => resolve(request.result as BrowserDevice | undefined);
    request.onerror = () => reject(request.error);
  });
}

function saveDevice(db: IDBDatabase, account: string, device: BrowserDevice): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE, "readwrite");
    transaction.objectStore(STORE).add(device, account);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

const pending = new Map<string, Promise<BrowserDevice>>();

export function customerDevice(account: string): Promise<BrowserDevice> {
  if (!/^\d{11}$/.test(account)) return Promise.reject(new Error("CPF fictício inválido."));
  let request = pending.get(account);
  if (request) return request;
  request = (async () => {
    const db = await openDatabase();
    try {
      const existing = await readDevice(db, account);
      if (existing) return existing;
      const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, false,
        ["sign", "verify"]);
      const exported = await crypto.subtle.exportKey("spki", keys.publicKey);
      const device: BrowserDevice = {
        deviceId: `browser-${crypto.randomUUID()}`,
        publicKey: base64url(new Uint8Array(exported)),
        privateKey: keys.privateKey,
      };
      try { await saveDevice(db, account, device); return device; }
      catch (failure) {
        const savedByAnotherTab = await readDevice(db, account);
        if (savedByAnotherTab) return savedByAnotherTab;
        throw failure;
      }
    } finally { db.close(); }
  })().catch((error: unknown) => { pending.delete(account); throw error; });
  pending.set(account, request);
  return request;
}

export async function signDeviceMessage(account: string, message: string): Promise<string> {
  const device = await customerDevice(account);
  const signature = await crypto.subtle.sign("Ed25519", device.privateKey,
    new TextEncoder().encode(message));
  return base64url(new Uint8Array(signature));
}
