import { z } from "zod";
import { Bank, BankError } from "../../world/src/bank.ts";
import type { AgentTool } from "./agent-loop.ts";
import { BlueInvestigation, logInput } from "./blue-investigation.ts";
import { createArchitectTools, type PatchToolContext } from "./patch-tools.ts";
import type { EcosystemClient } from "../../ecosystem/src/client.ts";

const id = z.string().min(1).max(128);
const traceInput = z.strictObject({ account_id: id.optional(), tx_id: id.optional(),
  depth: z.literal(1) });
const scopedTool = <T>(name: string, schema: z.ZodType<T>, description: string,
  execute: (input: T) => unknown): AgentTool => ({ name, kind: "investigate", schema,
  description, execute: async (raw) => execute(schema.parse(raw)) });

export function createForensicTools(input: { bank: Bank; incidentId: string;
  context: () => Record<string, unknown>; onAlertsRead?: () => void;
  paymentMessages?: (endToEndId: string) =>
    ReturnType<EcosystemClient["paymentMessages"]> }): AgentTool[] {
  const investigation = new BlueInvestigation(input.bank, input.incidentId);
  const incident = input.bank.db.prepare(`SELECT entity_key,area,opened_at,last_seen_at
    FROM sentinel_incidents WHERE id=?`).get(input.incidentId) as
    { entity_key: string; area: string; opened_at: string; last_seen_at: string };
  return [
    scopedTool("case.history", z.strictObject({}),
      "Read the bounded investigator report and verified task for this incident.",
      () => input.context()),
    scopedTool("alerts.get", z.strictObject({}),
      "Read only this incident and its correlated sentinel alerts.",
      () => { const result = investigation.alerts(); input.onAlertsRead?.(); return result; }),
    scopedTool("logs.query", logInput,
      "Read bounded access logs in this incident area.",
      (value) => {
        if (value.area !== incident.area && value.area !== "ledger")
          throw new BankError("DEF_AREA_SCOPE");
        const span = Date.parse(value.to) - Date.parse(value.from);
        if (span < 0 || span > 90 * 86_400_000) throw new BankError("BIZ_QUERY_WINDOW");
        if (!value.filters && ["ledger", "spi", "psp", "card_settlement"].includes(incident.entity_key)) {
          return input.bank.db.prepare(`SELECT id,rule_id,entity,observed_json,
            first_seen,last_seen,count FROM sentinel_alerts
            WHERE entity=? AND last_seen>=? AND first_seen<=?
            ORDER BY last_seen DESC,id DESC LIMIT ?`).all(incident.entity_key,
            value.from, value.to, value.limit);
        }
        if (!value.filters && ["auth", "api_gateway"].includes(incident.area) &&
          (incident.entity_key.startsWith("/api/") || /^[0-9a-f:.]+$/i.test(incident.entity_key))) {
          const field = incident.entity_key.startsWith("/api/") ? "route" : "peer_ip";
          const from = new Date(Math.max(Date.parse(value.from),
            Date.parse(incident.opened_at) - 10 * 60_000)).toISOString();
          const to = new Date(Math.min(Date.parse(value.to),
            Date.parse(incident.last_seen_at) + 10 * 60_000)).toISOString();
          if (from > to) return [];
          return input.bank.db.prepare(`SELECT id,ts,kind,route,status
            FROM access_log WHERE ts>=? AND ts<=? AND ${field}=?
            ORDER BY ts DESC,id DESC LIMIT ?`).all(from, to,
            incident.entity_key, value.limit);
        }
        const filters = value.filters;
        if (!filters?.customerId && !filters?.accountId) throw new BankError("DEF_INCIDENT_SCOPE");
        const linked = input.bank.db.prepare(`SELECT 1 FROM sentinel_incidents i
          LEFT JOIN accounts a ON a.id=?
          WHERE i.id=? AND
          (i.entity_key=? OR i.entity_key=? OR i.entity_key=a.customer_id OR
            i.entity_key IN (SELECT id FROM accounts WHERE customer_id=?)) LIMIT 1`)
          .get(filters.accountId ?? null, input.incidentId,
            filters.customerId ?? null, filters.accountId ?? null, filters.customerId ?? null);
        if (!linked) throw new BankError("DEF_INCIDENT_SCOPE");
        return investigation.logs(value);
      }),
    scopedTool("trace.get", z.strictObject({ trace_id: id }),
      "Read a telemetry trace only when its ID is the incident entity.", (value) => {
        if (incident.entity_key !== value.trace_id) throw new BankError("DEF_INCIDENT_SCOPE");
        return input.bank.telemetry.trace(value.trace_id).slice(0, 50).map((row) => ({
          id: row.id, twin_ts: row.twin_ts, source: row.source, category: row.category,
          action: row.action, outcome: row.outcome, severity: row.severity,
          account_id: row.account_id, e2e_id: row.e2e_id, message: row.message }));
      }),
    scopedTool("ledger.trace", traceInput,
      "Trace scoped ledger postings by account or transaction.",
      (value) => {
        if (!value.account_id && !value.tx_id) throw new BankError("DEF_INCIDENT_SCOPE");
        const linked = value.account_id ? input.bank.db.prepare(`SELECT 1 FROM accounts a
          JOIN sentinel_incidents i ON i.id=?
          WHERE a.id=? AND (i.entity_key=a.id OR i.entity_key=a.customer_id) LIMIT 1`)
          .get(input.incidentId, value.account_id) : input.bank.db.prepare(`SELECT 1
          FROM ledger_entries e JOIN accounts a ON a.id=e.account_id
          JOIN sentinel_incidents i ON i.id=? WHERE e.tx_id=? AND
          (i.entity_key=a.id OR i.entity_key=a.customer_id) LIMIT 1`)
          .get(input.incidentId, value.tx_id!);
        if (!linked) throw new BankError("DEF_INCIDENT_SCOPE");
        return investigation.trace({
        ...(value.account_id ? { accountId: value.account_id } : {}),
        ...(value.tx_id ? { txId: value.tx_id } : {}), depth: value.depth });
      }),
    scopedTool("spi.messages", z.strictObject({ end_to_end_id: id }),
      "Read SPI messages for a Pix transfer linked to this incident.", (value) => {
        const linked = input.bank.db.prepare(`SELECT 1 FROM pix_transfers p
          LEFT JOIN accounts src ON src.id=p.from_account
          LEFT JOIN accounts dst ON dst.id=p.to_account
          JOIN sentinel_incidents i ON i.id=?
          WHERE p.end_to_end_id=? AND (i.entity_key=p.from_account OR
            i.entity_key=p.to_account OR i.entity_key=src.customer_id OR
            i.entity_key=dst.customer_id) LIMIT 1`).get(input.incidentId, value.end_to_end_id);
        if (!linked) throw new BankError("DEF_INCIDENT_SCOPE");
        if (input.bank.isSeparatedEcosystem) {
          if (!input.paymentMessages) throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
          return input.paymentMessages(value.end_to_end_id).then((messages) =>
            messages.slice(0, 20));
        }
        return input.bank.spi.messages(value.end_to_end_id).slice(0, 20);
      }),
    scopedTool("sessions.list", z.strictObject({ customer_id: id }),
      "List session and device metadata for the incident customer without token hashes.",
      (value) => {
        const linked = input.bank.db.prepare(`SELECT 1 FROM sentinel_incidents i
          WHERE i.id=? AND (i.entity_key=? OR i.entity_key IN
            (SELECT id FROM accounts WHERE customer_id=?)) LIMIT 1`)
          .get(input.incidentId, value.customer_id, value.customer_id);
        if (!linked) throw new BankError("DEF_INCIDENT_SCOPE");
        return input.bank.db.prepare(`SELECT s.id,s.device_id,s.access_exp,s.refresh_exp,
          s.revoked_at,d.first_seen_at,d.revoked_at device_revoked_at
          FROM auth_sessions s LEFT JOIN auth_devices d ON d.id=s.device_id
          WHERE s.customer_id=? ORDER BY s.access_exp DESC LIMIT 30`)
          .all(value.customer_id);
      }),
  ];
}

export function createRootCauseTools(input: { bank: Bank; incidentId: string;
  context: () => Record<string, unknown>; patch: PatchToolContext;
  symptoms: string[]; onScenarioRead?: (id: string) => void }): AgentTool[] {
  const forensic = createForensicTools(input).filter((tool) =>
    ["case.history", "alerts.get", "logs.query", "trace.get", "ledger.trace"].includes(tool.name));
  const sourceTools = createArchitectTools(input.patch, input.context).filter((tool) =>
    ["repo.read", "repo.search"].includes(tool.name));
  return [...forensic, ...sourceTools,
    scopedTool("scenario.get", z.strictObject({ regression_id: id }),
      "Read only bank-side symptoms for a verified regression scenario.", (value) => {
        if (!input.patch.regressionIds.includes(value.regression_id))
          throw new BankError("DEF_REGRESSION_SCOPE");
        input.onScenarioRead?.(value.regression_id);
        return { regression_id: value.regression_id,
          violated_invariant: input.symptoms[0] ?? "Unspecified invariant",
          bank_side_symptoms: input.symptoms.slice(1, 6) };
      })];
}
