import type { DatabaseSync } from "node:sqlite";

export const DEVICE_QUARANTINE_V1 = Object.freeze({
  duration_ms: 24 * 60 * 60_000,
  card_limit_cents: 20_000,
  loan_amount_cents: 100_000,
});

export function deviceQuarantine(db: DatabaseSync, customerId: string, deviceId: string,
  now: Date): { quarantined: boolean; quarantineEndsAt: string; pixRegistered: boolean } | null {
  const device = db.prepare(`SELECT customer_id,first_seen_at,bound_at,revoked_at,pix_registered_at
    FROM auth_devices WHERE id=?`).get(deviceId) as { customer_id: string; first_seen_at: string;
      bound_at: string | null; revoked_at: string | null; pix_registered_at: string | null } | undefined;
  if (!device || device.customer_id !== customerId || device.revoked_at) return null;
  const firstSeen = Date.parse(device.first_seen_at);
  const bound = device.bound_at ? Date.parse(device.bound_at) : NaN;
  const current = now.getTime();
  if (!Number.isFinite(firstSeen) || !Number.isFinite(bound) || !Number.isFinite(current) ||
    firstSeen > current || bound > current ||
    new Date(firstSeen).toISOString() !== device.first_seen_at ||
    new Date(bound).toISOString() !== device.bound_at) return null;
  const quarantineEnds = Math.max(firstSeen, bound) + DEVICE_QUARANTINE_V1.duration_ms;
  if (!Number.isFinite(new Date(quarantineEnds).getTime())) return null;
  return { quarantined: current < quarantineEnds,
    quarantineEndsAt: new Date(quarantineEnds).toISOString(),
    pixRegistered: Boolean(device.pix_registered_at) };
}
