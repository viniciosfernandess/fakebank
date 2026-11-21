import type { DatabaseSync } from "node:sqlite";
import { JACARANDA_ISPB } from "./pix-id.ts";

export interface DuePixCommand {
  id: string;
  end_to_end_id: string;
  from_account: string;
  to_account: string;
  amount: number;
  actor: string;
  from_ispb: string;
  to_ispb: string;
  trace_id: string | null;
  deadline_at_real: string | null;
}

export interface PendingPspCredit {
  transfer_id: string;
  end_to_end_id: string;
  to_account: string;
  amount_cents: number;
  from_account: string;
  settled_at: string;
  trace_id: string | null;
}

type PspCommandRow = PendingPspCredit & { transfer_e2e: string;
  transfer_to: string; transfer_amount: number; transfer_from: string;
  transfer_settled_at: string | null; status: string;
  response_status: string | null };

const PSP_COMMAND_SELECT = `SELECT o.transfer_id,o.end_to_end_id,o.to_account,
  o.amount_cents,o.from_account,o.settled_at,o.trace_id,
  p.end_to_end_id transfer_e2e,p.to_account transfer_to,
  p.amount transfer_amount,p.from_account transfer_from,
  p.settled_at transfer_settled_at,p.status,s.response_status
  FROM pix_psp_inbound_outbox o
  JOIN pix_transfers p ON p.id=o.transfer_id
  JOIN pix_spi_outbox s ON s.transfer_id=o.transfer_id`;

function validatePspCommand(row: PspCommandRow): PendingPspCredit {
  const { transfer_e2e, transfer_to, transfer_amount, transfer_from,
    transfer_settled_at, status, response_status, ...command } = row;
  if (transfer_e2e !== command.end_to_end_id || transfer_to !== command.to_account ||
    transfer_amount !== command.amount_cents || transfer_from !== command.from_account ||
    transfer_settled_at !== command.settled_at || response_status !== "ACSC" ||
    !["settled", "returned_partial", "returned_full"].includes(status))
    throw new Error("INTEGRITY_PIX_PSP_COMMAND");
  return command;
}

export function readPendingPspCredits(db: DatabaseSync, limit = 100): PendingPspCredit[] {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000)
    throw new Error("BIZ_INVALID_LIMIT");
  const rows = db.prepare(`${PSP_COMMAND_SELECT}
    WHERE o.acknowledged_at IS NULL ORDER BY o.created_at,o.transfer_id LIMIT ?`)
    .all(limit) as unknown as PspCommandRow[];
  return rows.map(validatePspCommand);
}

export function readPendingPspCredit(db: DatabaseSync,
  transferId: string): PendingPspCredit | null {
  const row = db.prepare(`${PSP_COMMAND_SELECT}
    WHERE o.transfer_id=? AND o.acknowledged_at IS NULL`)
    .get(transferId) as unknown as PspCommandRow | undefined;
  return row ? validatePspCommand(row) : null;
}

export function readDuePixCommands(db: DatabaseSync, realNow: Date,
  limit = 100): DuePixCommand[] {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000)
    throw new Error("BIZ_INVALID_LIMIT");
  const pending = db.prepare(`SELECT p.id,p.end_to_end_id,p.from_account,p.to_account,
    p.amount,p.actor,o.end_to_end_id command_end_to_end_id,
    o.from_ispb,o.to_ispb,o.amount_cents,o.trace_id,o.deadline_at_real
    FROM pix_transfers p JOIN pix_spi_outbox o ON o.transfer_id=p.id
    WHERE p.status='in_processing' AND (o.eligible_at_real IS NULL OR o.eligible_at_real<=?)
    ORDER BY p.initiated_at,p.id LIMIT ?`)
    .all(realNow.toISOString(), limit) as unknown as (DuePixCommand & {
      command_end_to_end_id: string; amount_cents: number })[];
  return pending.map(({ command_end_to_end_id, amount_cents, ...command }) => {
    if (command.end_to_end_id !== command_end_to_end_id ||
      command.amount !== amount_cents || command.from_ispb !== JACARANDA_ISPB)
      throw new Error("INTEGRITY_PIX_SPI_COMMAND");
    return command;
  });
}
