import { createHash } from "node:crypto";

export const JACARANDA_ISPB = "12345678";

export function pixEndToEndId(transferId: string, initiatedAt: Date): string {
  return pixEndToEndIdForIspb(transferId, initiatedAt, JACARANDA_ISPB);
}

export function pixEndToEndIdForIspb(transferId: string, initiatedAt: Date, ispb: string): string {
  if (!transferId || transferId.length > 128 ||
    !Number.isFinite(initiatedAt.getTime()) || !/^\d{8}$/.test(ispb))
    throw new Error("PIX_E2E_SOURCE_INVALID");
  const minute = initiatedAt.toISOString().slice(0, 16).replace(/[-T:]/g, "");
  const entropy = createHash("sha256").update(transferId).digest().readBigUInt64BE();
  const suffix = (entropy % (36n ** 11n)).toString(36).toUpperCase().padStart(11, "0");
  return `E${ispb}${minute}${suffix}`;
}
