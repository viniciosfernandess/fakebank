import type { DatabaseSync } from "node:sqlite";

export type PixKeyType = "cpf" | "cnpj" | "email" | "phone" | "evp";

export type DictRateBucketOwner = "embedded" | "bank";
function rateBucketTable(owner: DictRateBucketOwner): string {
  return owner === "bank" ? "pix_lookup_rate_buckets" : "dict_rate_buckets";
}

export function installDictRateBuckets(db: DatabaseSync,
  owner: DictRateBucketOwner = "embedded"): void {
  db.exec(`CREATE TABLE IF NOT EXISTS ${rateBucketTable(owner)} (
    scope TEXT NOT NULL CHECK(scope IN ('user','participant')),
    subject_hash TEXT NOT NULL, tokens REAL NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY(scope,subject_hash)
  )`);
}

export function consumeDictToken(db: DatabaseSync, scope: "user" | "participant",
  subjectHash: string, capacity: number, refillPerSecond: number, nowMs: number,
  owner: DictRateBucketOwner = "embedded"): boolean {
  const table = rateBucketTable(owner);
  const row = db.prepare(`SELECT tokens,updated_at_ms FROM ${table} WHERE scope=? AND subject_hash=?`)
    .get(scope, subjectHash) as { tokens: number; updated_at_ms: number } | undefined;
  const available = row ? Math.min(capacity,
    row.tokens + Math.max(0, nowMs - row.updated_at_ms) * refillPerSecond / 1000) : capacity;
  if (available < 1) return false;
  db.prepare(`INSERT INTO ${table} (scope,subject_hash,tokens,updated_at_ms)
    VALUES (?,?,?,?) ON CONFLICT(scope,subject_hash) DO UPDATE SET
    tokens=excluded.tokens,updated_at_ms=excluded.updated_at_ms`)
    .run(scope, subjectHash, available - 1, nowMs);
  return true;
}

function cpfValid(value: string): boolean {
  if (/^(\d)\1{10}$/.test(value)) return false;
  const digits = [...value].map(Number);
  for (let length = 9; length <= 10; length++) {
    const weighted = digits.slice(0, length).reduce((sum, digit, index) =>
      sum + digit * (length + 1 - index), 0);
    const check = (weighted * 10) % 11;
    if (digits[length] !== (check === 10 ? 0 : check)) return false;
  }
  return true;
}

function cnpjValid(value: string): boolean {
  if (/^(\d)\1{13}$/.test(value)) return false;
  const digits = [...value].map(Number);
  for (let length = 12; length <= 13; length++) {
    const weights = length === 12 ? [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
      : [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const sum = digits.slice(0, length).reduce((total, digit, index) =>
      total + digit * weights[index]!, 0);
    const check = sum % 11 < 2 ? 0 : 11 - sum % 11;
    if (digits[length] !== check) return false;
  }
  return true;
}

export function parsePixKey(value: string): { type: PixKeyType; value: string } | null {
  if (/^\d{11}$/.test(value)) return cpfValid(value) ? { type: "cpf", value } : null;
  if (/^\d{14}$/.test(value)) return cnpjValid(value) ? { type: "cnpj", value } : null;
  if (/^\+55\d{10,11}$/.test(value)) return { type: "phone", value };
  if (/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@.]{2,}$/.test(value))
    return { type: "email", value: value.toLowerCase() };
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value))
    return { type: "evp", value: value.toLowerCase() };
  return null;
}
