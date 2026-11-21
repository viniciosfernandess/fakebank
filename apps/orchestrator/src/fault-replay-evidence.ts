import type { DatabaseSync } from "node:sqlite";

export type FaultReplay = {
  kind: "verify_identity_containment" | "verify_pix_control";
  runId: string;
  alertId: string;
  customerId: string;
  targetId: string;
  amountCents: number | null;
  evidenceRefs: string[];
};

export function readFaultReplay(db: DatabaseSync,
  alert: Record<string, unknown>): FaultReplay | undefined {
  if (typeof alert.id !== "string" || typeof alert.entity !== "string") return;
  const alertId = alert.id;
  const sentinelRef = `sentinel_alerts:${alertId}`;
  const tableExists = (name: string) => db.prepare(`SELECT 1 FROM sqlite_master
    WHERE type='table' AND name=?`).get(name);
  if (alert.rule_id === "S-AUTH-08" && tableExists("lab_identity_replays")) {
    const observed = alert.observed as Record<string, unknown> | undefined;
    const event = observed?.source_event_id;
    if (typeof event !== "number" || !Number.isSafeInteger(event) ||
      typeof observed?.device_id !== "string") return;
    const match = db.prepare(`SELECT r.run_id FROM lab_identity_replays p
      JOIN lab_revoked_device_receipts r ON r.run_id=p.run_id
        AND r.telemetry_event_id=p.telemetry_event_id
      WHERE r.telemetry_event_id=? AND r.customer_id=? AND r.device_id=?`)
      .get(event, alert.entity, observed.device_id) as { run_id: string } | undefined;
    if (match) return { kind: "verify_identity_containment", runId: match.run_id,
      alertId, customerId: alert.entity, targetId: alert.entity, amountCents: null,
      evidenceRefs: [sentinelRef, `telemetry_events:${event}`] };
  }
  if (alert.rule_id === "S-PIX-02" && tableExists("lab_pix_history_replays")) {
    const match = db.prepare(`SELECT r.run_id,r.customer_id,r.transfer_id,t.amount
      FROM lab_pix_history_replays p JOIN lab_risk_miss_receipts r
        ON r.run_id=p.run_id AND r.account_id=p.account_id
      JOIN pix_transfers t ON t.id=r.transfer_id AND t.from_account=r.account_id
        AND t.to_account=r.recipient_account_id AND t.actor='synthetic_pix_history'
      WHERE r.account_id=?`).get(alert.entity) as
      { run_id: string; customer_id: string; transfer_id: string; amount: number } | undefined;
    if (match) return { kind: "verify_pix_control", runId: match.run_id, alertId,
      customerId: match.customer_id, targetId: match.transfer_id, amountCents: match.amount,
      evidenceRefs: [sentinelRef, `pix_transfers:${match.transfer_id}`] };
  }
}
