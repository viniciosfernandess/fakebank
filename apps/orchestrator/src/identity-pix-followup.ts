import type { DatabaseSync } from "node:sqlite";
import type { ContainedIdentityWindow } from "./identity-session-activity.ts";

export interface IdentityPixWindow extends ContainedIdentityWindow {
  containedAtReal: string;
}

export function readIdentityPixFollowup(db: DatabaseSync, window: IdentityPixWindow) {
  const limit = 50;
  const rows = db.prepare(`WITH accesses AS (
    SELECT e.id,e.trace_id,e.ts,e.twin_ts FROM auth_sessions s
    JOIN telemetry_events e ON e.session_id=s.id
    WHERE s.customer_id=$customer AND s.device_id=$device
      AND e.user_id=$customer AND e.device_id=$device AND e.twin_ts>=$revoked
      AND e.id<=$through AND e.source='auth' AND e.category='audit' AND e.outcome='success'
      AND e.action='access_revoked_device'
  ) SELECT p.id,MIN(a.id) access_event_id,p.status,p.amount,p.from_account,p.to_account,
    p.end_to_end_id,p.settled_at,p.ledger_tx_id,o.response_status,o.end_to_end_id command_e2e,
    o.amount_cents command_amount,o.trace_id,
    q.transfer_id credit_id,q.end_to_end_id credit_e2e,q.amount_cents credit_amount,
    q.from_account credit_source,q.to_account credit_recipient,
    q.settled_at credit_settled_at,q.trace_id credit_trace,q.created_at credit_created_at,
    q.acknowledged_at
    FROM accesses a JOIN pix_spi_outbox o ON o.trace_id=a.trace_id
    JOIN pix_transfers p ON p.id=o.transfer_id
    JOIN accounts owner ON owner.id=p.from_account AND owner.customer_id=$customer
    LEFT JOIN pix_psp_inbound_outbox q ON q.transfer_id=p.id
    WHERE p.initiating_device_id=$device AND p.spi_command_version=2
      AND o.queued_at_real>=a.ts AND o.queued_at_real<=$contained AND o.created_at>=a.twin_ts
    GROUP BY p.id ORDER BY p.id LIMIT $limit`).all({
      $customer: window.customerId, $device: window.deviceId, $revoked: window.revokedAt,
      $through: window.throughEventId, $contained: window.containedAtReal, $limit: limit + 1,
    }) as { id: string; access_event_id: number; status: string; amount: number;
      from_account: string; to_account: string; end_to_end_id: string; settled_at: string | null;
      ledger_tx_id: string | null; response_status: string | null; command_e2e: string;
      command_amount: number; trace_id: string; credit_id: string | null;
      credit_e2e: string | null; credit_amount: number | null; credit_source: string | null;
      credit_recipient: string | null; credit_settled_at: string | null;
      credit_trace: string | null; credit_created_at: string | null;
      acknowledged_at: string | null }[];
  const commands = rows.slice(0, limit).map((row) => {
    const bound = row.command_e2e === row.end_to_end_id &&
      row.command_amount === row.amount && Number.isSafeInteger(row.amount) && row.amount > 0;
    const state = (() => {
      if (!bound) return "unresolved";
      if (!row.response_status && row.status === "in_processing" &&
        !row.ledger_tx_id && !row.credit_id) return "pending_spi";
      if (row.response_status === "RJCT" && row.status === "rejected" &&
        !row.ledger_tx_id && !row.credit_id) return "rejected";
      if (row.response_status !== "ACSC" ||
        !["settled", "returned_partial", "returned_full"].includes(row.status) ||
        !row.ledger_tx_id || !row.settled_at || row.credit_id !== row.id ||
        row.credit_e2e !== row.end_to_end_id || row.credit_amount !== row.amount ||
        row.credit_source !== row.from_account || row.credit_recipient !== row.to_account ||
        row.credit_settled_at !== row.settled_at || row.credit_trace !== row.trace_id)
        return "unresolved";
      const proof = db.prepare(`SELECT COUNT(*) entries,COALESCE(SUM(e.amount),0) net,
        COALESCE(SUM(CASE WHEN e.account_id=? AND e.amount=? THEN 1 ELSE 0 END),0) debits,
        COALESCE(SUM(CASE WHEN a.system_role='pix_settlement' AND e.amount=? THEN 1 ELSE 0 END),0) credits
        FROM ledger_entries e JOIN accounts a ON a.id=e.account_id
        WHERE e.tx_id=? AND e.kind='pix' AND e.ref_type='pix' AND e.ref_id=?`)
        .get(row.from_account, -row.amount, row.amount, row.ledger_tx_id, row.id) as
          { entries: number; net: number; debits: number; credits: number };
      const total = db.prepare("SELECT COUNT(*) n FROM ledger_entries WHERE tx_id=?")
        .get(row.ledger_tx_id) as { n: number };
      if (total.n !== 2 || proof.entries !== 2 || proof.net !== 0 ||
        proof.debits !== 1 || proof.credits !== 1) return "unresolved";
      if (!row.acknowledged_at) return "pending_psp";
      return row.credit_created_at && row.acknowledged_at >= row.credit_created_at ?
        "settled" : "unresolved";
    })();
    return { transfer_id: row.id, access_event_id: row.access_event_id, state };
  });
  return { commands, truncated: rows.length > limit };
}

export function describeIdentityPixFollowup(payload: Record<string, unknown>): string {
  const commands = Array.isArray(payload.commands) ? payload.commands : [];
  const labels = {
    pending_spi: "Aguardando SPI", pending_psp: "Aguardando crédito no PSP",
    settled: "Crédito confirmado", rejected: "Recusados pelo SPI",
    unresolved: "Evidência em apuração",
  };
  return [...Object.entries(labels).flatMap(([state, label]) => {
    const count = commands.filter((command) => command?.state === state).length;
    return count ? [`${label} (${count}).`] : [];
  }), ...(payload.truncated === true ? ["A busca atingiu o limite de comandos."] : [])].join(" ");
}
