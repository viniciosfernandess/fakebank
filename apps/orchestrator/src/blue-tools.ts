import { randomUUID } from "node:crypto";
import { z } from "zod";
import { Bank, BankError } from "../../world/src/bank.ts";
import { BlueContainment, type ContainmentKind } from "./blue-containment.ts";
import { BlueInvestigation, logInput, queryInput } from "./blue-investigation.ts";
import type { AgentTool } from "./agent-loop.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";

const id = z.string().min(1).max(128);
const reason = z.string().trim().min(5).max(500);
const refs = z.array(z.string().regex(/^[a-zA-Z0-9:_-]{3,128}$/)).min(1).max(8);
const ttl = z.number().int().min(1).max(30).optional();
const actionBase = { reason, evidence_refs: refs, ttl_min: ttl };
const freezeInput = z.strictObject({ account_id: id, direction: z.enum(["inbound", "outbound", "both"]), ...actionBase });
const routeInput = z.strictObject({ route_id: z.string().min(1).max(256), ...actionBase });
const flagInput = z.strictObject({ flag: id, ...actionBase });
const sessionInput = z.strictObject({ session_id: id, ...actionBase });
const traceInput = z.strictObject({ account_id: id.optional(), tx_id: id.optional(), depth: z.union([z.literal(1), z.literal(2)]) });
const taskInput = z.strictObject({ title: z.string().trim().min(5).max(160), kind: z.enum(["patch_code", "patch_rule"]),
  priority: z.number().int().min(1).max(3), acceptance_invariants: z.array(z.string().max(300)).min(1).max(5),
  do_not_break: z.array(z.string().max(300)).max(5), regression_test_ids: z.array(id).max(10) });
const impactInput = z.strictObject({ action: z.strictObject({ kind: z.enum(["freeze_account", "block_route",
  "disable_flag", "revoke_session"]), target: id }) });

export function createInvestigatorTools(input: { bank: Bank; events?: EventStore; incidentId: string;
  agentId: string }): AgentTool[] {
  const investigation = new BlueInvestigation(input.bank, input.incidentId);
  const containment = new BlueContainment(input.bank, input.events);
  const tool = <T>(name: string, kind: AgentTool["kind"], schema: z.ZodType<T>,
    execute: (value: T) => unknown, description: string): AgentTool => ({ name, kind, schema, description,
      execute: async (value: unknown) => execute(schema.parse(value)) });
  const contain = (kind: ContainmentKind, target: string, value: { reason: string;
    evidence_refs: string[]; ttl_min?: number | undefined; direction?: "inbound" | "outbound" | "both" | undefined }) =>
    containment.apply({ incidentId: input.incidentId, actorId: input.agentId, kind, target,
      reason: value.reason, evidenceRefs: value.evidence_refs,
      ...(value.ttl_min === undefined ? {} : { ttlMin: value.ttl_min }),
      ...(value.direction === undefined ? {} : { direction: value.direction }) });
  return [
    tool("alerts.get", "investigate", z.strictObject({ cluster_id: id }), (value) => {
      if (value.cluster_id !== input.incidentId) throw new BankError("DEF_INCIDENT_SCOPE");
      return investigation.alerts();
    }, "Read this incident's alert cluster and observed private signals."),
    tool("logs.query", "investigate", logInput, (value) => investigation.logs(value),
      "Read at most 50 private access-log rows in the incident area."),
    tool("ledger.trace", "investigate", traceInput, (value) => investigation.trace({
      ...(value.account_id === undefined ? {} : { accountId: value.account_id }),
      ...(value.tx_id === undefined ? {} : { txId: value.tx_id }), depth: value.depth }),
    "Trace balanced postings by account or transaction, at most two hops."),
    tool("ledger.query", "investigate", queryInput, (value) => investigation.ledger(value),
      "Run one of six bounded, parameterized ledger queries. Raw SQL is unavailable."),
    tool("entity.profile", "investigate", z.strictObject({ id }), (value) => investigation.profile(value.id),
      "Read tenure and behavior signals; signals are not honesty ground truth."),
    tool("sim.honest_impact", "investigate", impactInput, (value) => ({
      honest_customers_affected_estimate: containment.estimate(value.action) }),
    "Estimate honest-customer impact before applying containment."),
    tool("contain.freeze_account", "contain", freezeInput, (value) => contain("freeze_account",
      value.account_id, { ...value, direction: value.direction }),
    "Freeze one account direction for up to 30 real minutes; requires evidence."),
    tool("contain.block_route", "contain", routeInput, (value) => contain("block_route", value.route_id, value),
      "Block one allowed API route briefly; login and health remain available."),
    tool("contain.disable_flag", "contain", flagInput, (value) => contain("disable_flag", value.flag, value),
      "Temporarily suppress a flag marked disableSafe."),
    tool("contain.revoke_session", "contain", sessionInput, (value) => contain("revoke_session", value.session_id, value),
      "Revoke one known session and its refresh token."),
    tool("task.open", "action", taskInput, (value) => {
      const row = input.bank.db.prepare("SELECT area,severity,state FROM sentinel_incidents WHERE id=?")
        .get(input.incidentId) as { area: string; severity: string; state: string } | undefined;
      if (!row || !["open", "awaiting_next_window"].includes(row.state))
        throw new BankError("DEF_INCIDENT_NOT_OPEN");
      input.bank.db.exec(`CREATE TABLE IF NOT EXISTS blue_tasks (
        id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, actor_id TEXT NOT NULL,
        title TEXT NOT NULL, kind TEXT NOT NULL, priority INTEGER NOT NULL,
        acceptance_json TEXT NOT NULL, do_not_break_json TEXT NOT NULL,
        regression_json TEXT NOT NULL, state TEXT NOT NULL, opened_at TEXT NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS blue_tasks_one_open ON blue_tasks(incident_id) WHERE state='open';`);
      const existing = input.bank.db.prepare(`SELECT id,title,kind,priority,acceptance_json,
        do_not_break_json,regression_json FROM blue_tasks WHERE incident_id=? AND state='open' LIMIT 1`)
        .get(input.incidentId) as { id: string; title: string; kind: string; priority: number;
          acceptance_json: string; do_not_break_json: string; regression_json: string } | undefined;
      if (existing) {
        if (existing.title !== value.title || existing.kind !== value.kind ||
          existing.priority !== value.priority ||
          existing.acceptance_json !== JSON.stringify(value.acceptance_invariants) ||
          existing.do_not_break_json !== JSON.stringify(value.do_not_break) ||
          existing.regression_json !== JSON.stringify(value.regression_test_ids))
          throw new BankError("DEF_TASK_ALREADY_OPEN");
        return { task_id: existing.id, reused: true };
      }
      const taskId = `task_${randomUUID()}`;
      input.bank.db.prepare("INSERT INTO blue_tasks VALUES (?,?,?,?,?,?,?,?,?,'open',?)")
        .run(taskId, input.incidentId, input.agentId, value.title, value.kind, value.priority,
          JSON.stringify(value.acceptance_invariants), JSON.stringify(value.do_not_break),
          JSON.stringify(value.regression_test_ids), input.bank.now().toISOString());
      input.events?.append({ round_id: null, ts: new Date().toISOString(), twin_ts: input.bank.now().toISOString(),
        type: "task.opened", actor: { id: input.agentId, role: "investigator" },
        area: row.area as "pix", incident_id: input.incidentId, task_id: taskId,
        public_summary_pt: "Tarefa de correção aberta",
        public: { task_id: taskId, incident_id: input.incidentId, title_pt: "Correção do incidente",
          area: row.area as "pix", severity: row.severity as "high" },
        private: { title: value.title, kind: value.kind, priority: value.priority,
          acceptance_invariants: value.acceptance_invariants, do_not_break: value.do_not_break } });
      return { task_id: taskId };
    }, "Open a single evidence-backed patch task for this incident."),
  ];
}
