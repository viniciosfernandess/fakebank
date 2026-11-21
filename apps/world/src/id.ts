import { createHash, randomBytes } from "node:crypto";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SEED_TIMESTAMP = Date.parse("2026-11-11T00:00:00.000Z");
export const SYSTEM_ROLES = ["pix_settlement", "cash_in", "cash_out", "fees", "loan_funding",
  "card_settlement", "cashback_pool", "rounding", "suspense", "recovery",
  "bank_loss", "loan_loss_allowance", "loan_provision_expense",
  "loan_interest_receivable", "loan_interest_revenue", "equity_capital",
  "retained_earnings"] as const;
export type SystemRole = typeof SYSTEM_ROLES[number];

function encode(value: bigint, length: number): string {
  let result = "";
  for (let index = 0; index < length; index++) {
    result = ALPHABET[Number(value & 31n)] + result;
    value >>= 5n;
  }
  return result;
}

function format(prefix: string, timestamp: number, entropy: Uint8Array): string {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || timestamp >= 2 ** 48 || entropy.length !== 10)
    throw new Error("Invalid ULID source");
  const random = BigInt(`0x${Buffer.from(entropy).toString("hex")}`);
  return `${prefix}_${encode(BigInt(timestamp), 10)}${encode(random, 16)}`;
}

export function newId(prefix: string, now = Date.now()): string {
  return format(prefix, now, randomBytes(10));
}

function deterministicId(prefix: string, key: string, timestamp: number): string {
  const entropy = createHash("sha256").update(`banco-vivo:${prefix}:${key}`).digest().subarray(0, 10);
  return format(prefix, timestamp, entropy);
}

function seedId(prefix: "cus" | "acc", index: number): string {
  if (!Number.isSafeInteger(index) || index < 1) throw new Error("Invalid seed index");
  return deterministicId(prefix, String(index), SEED_TIMESTAMP);
}

export const seedCustomerId = (index: number): string => seedId("cus", index);
export const seedAccountId = (index: number): string => seedId("acc", index);
export function seedSystemAccountId(role: SystemRole): string {
  if (!SYSTEM_ROLES.includes(role)) throw new Error("Invalid system account role");
  return deterministicId("sys", role, SEED_TIMESTAMP);
}
export function seedRecordId(prefix: "tx" | "le", key: string, timestamp: number): string {
  if (!key) throw new Error("Invalid seed record key");
  return deterministicId(prefix, key, timestamp);
}
