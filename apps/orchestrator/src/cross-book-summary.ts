import type { CrossBookReport } from "../../ecosystem/src/verifier-client.ts";

export interface CrossBookObservation {
  checked_at: string;
  report: CrossBookReport | null;
  proof_ref?: string;
}

const pendingFields = ["pending_pix", "pending_inbound", "pending_med",
  "pending_returns", "pending_cautelar_returns"] as const;
const driftFields = ["bank_schema_drift", "ecosystem_schema_drift",
  "ledger_drift", "psp_account_drift", "root_overflow", "transfer_drift",
  "spi_message_drift", "command_drift", "return_command_drift",
  "cautelar_return_drift", "med_hold_drift", "med_command_drift"] as const;

export function publicCrossBookSummary(observation: CrossBookObservation | null,
  now: Date): { checked_at: string; status: "balanced" | "processing" | "drift" |
    "unavailable" | "stale"; pending_commands: number; drift_checks: number } | null {
  if (!observation) return null;
  const report = observation.report;
  if (!report) return { checked_at: observation.checked_at, status: "unavailable",
    pending_commands: 0, drift_checks: 0 };
  const pending = pendingFields.reduce((sum, key) => sum + report[key], 0);
  const countedDrift = driftFields.reduce((sum, key) => sum + report[key], 0) +
    Number(report.bank_pi_cents === null || report.spi_pi_cents === null ||
      report.bank_pi_cents - report.spi_pi_cents !== report.pending_spi_cents);
  const drift = countedDrift + Number(!report.ok && pending === 0 && countedDrift === 0);
  const age = now.getTime() - Date.parse(observation.checked_at);
  const status = !Number.isFinite(age) || age < 0 || age > 30_000 ? "stale" :
    drift > 0 || !report.ok && pending === 0 ? "drift" :
      pending > 0 ? "processing" : "balanced";
  return { checked_at: observation.checked_at, status,
    pending_commands: pending, drift_checks: drift };
}
