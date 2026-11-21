import { createHash } from "node:crypto";
import type { Bank } from "../../world/src/bank.ts";
import type { EcosystemClient } from "../../ecosystem/src/client.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import { CASHOUT_ISPB, PSP_PARTICIPANTS } from "../../world/src/ecosystem/spi.ts";
import { presentationInstitution } from "../../../packages/contracts/src/money-flow-presentation.ts";

export interface DisclosedMoneyEdge {
  from_ispb: string; to_ispb: string; kind: "payment" | "transfer" | "cashout";
}

export interface MoneyFlowMedState {
  status: "open" | "refunded" | "resolved" | "rejected";
  recovery: "pending" | "none" | "partial" | "full";
  institutions: { name: string; state: "held" | "recovered" | "mixed" | "released" }[];
  accounts?: { name: string; slot: number;
    state: "held" | "recovered" | "mixed" | "released" }[];
}

type MedAccountHold = { account_id: string; ispb: string; created_at: string;
  blocked_cents: number; refunded_cents: number; released_at: string | null };

function publicMedAccountStates(holds: readonly MedAccountHold[],
  allowedIspbs?: ReadonlySet<string>): MoneyFlowMedState["accounts"] {
  const accounts = new Map<string, { ispb: string; accountId: string;
    firstAt: string; held: number; recovered: number }>();
  for (const hold of holds) {
    if (allowedIspbs && !allowedIspbs.has(hold.ispb)) continue;
    const key = JSON.stringify([hold.ispb, hold.account_id]);
    const account = accounts.get(key) ?? { ispb: hold.ispb,
      accountId: hold.account_id, firstAt: hold.created_at, held: 0, recovered: 0 };
    if (hold.created_at < account.firstAt) account.firstAt = hold.created_at;
    if (hold.released_at === null) account.held += hold.blocked_cents;
    account.recovered += hold.refunded_cents;
    accounts.set(key, account);
  }
  const rows = [...accounts.values()].sort((a, b) =>
    a.ispb.localeCompare(b.ispb) || a.firstAt.localeCompare(b.firstAt) ||
    a.accountId.localeCompare(b.accountId));
  const counts = new Map<string, number>();
  for (const row of rows) counts.set(row.ispb, (counts.get(row.ispb) ?? 0) + 1);
  if (![...counts.values()].some((count) => count > 1)) return undefined;
  const slots = new Map<string, number>();
  return rows.map((row) => {
    const name = presentationInstitution(moneyFlowInstitutionName(row.ispb));
    const slot = (slots.get(name) ?? 0) + 1;
    slots.set(name, slot);
    return { name, slot,
      state: row.held > 0 && row.recovered > 0 ? "mixed" as const :
        row.held > 0 ? "held" as const : row.recovered > 0 ?
          "recovered" as const : "released" as const };
  });
}

const participantNames = new Map<string, string>([
  ...PSP_PARTICIPANTS.map((participant): [string, string] =>
    [participant.ispb, participant.name]),
  [CASHOUT_ISPB, "Saída externa"],
]);

export function moneyFlowInstitutionName(ispb: string): string {
  return participantNames.get(ispb) ?? "Instituição externa";
}

export function publicMoneyFlowEdges(edges: readonly DisclosedMoneyEdge[]) {
  return edges.map((edge) => ({
    from: presentationInstitution(moneyFlowInstitutionName(edge.from_ispb)),
    to: presentationInstitution(moneyFlowInstitutionName(edge.to_ispb)),
    kind: edge.kind,
  }));
}

function disclosedRows(bank: Bank, incidentId: string):
  { transfer_id: string; edges_json: string }[] {
  const table = bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='presentation_money_flow_disclosures'`).get();
  if (!table) return [];
  return bank.db.prepare(`SELECT transfer_id,edges_json
    FROM presentation_money_flow_disclosures WHERE incident_id=? ORDER BY id`)
    .all(incidentId) as { transfer_id: string; edges_json: string }[];
}

function incidentIsDisclosed(events: EventStore, incidentId: string): boolean {
  const table = events.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='attack_incident_links'`).get();
  return Boolean(table && events.db.prepare(`SELECT 1 FROM attack_incident_links
    WHERE incident_id=? AND disclosed=1`).get(incidentId));
}

export function moneyFlowMedState(bank: Bank, transferId: string,
  allowedIspbs?: ReadonlySet<string>): MoneyFlowMedState | null {
  const row = bank.db.prepare(`SELECT id,status,claim_amount_cents,refunded_cents,
    unrecovered_cents FROM med_cases WHERE transfer_id=?`).get(transferId) as {
    id: string; status: string; claim_amount_cents: number | null;
    refunded_cents: number; unrecovered_cents: number;
  } | undefined;
  if (!row || !["open", "settlement_pending_psp", "refunded", "resolved", "rejected"]
    .includes(row.status)) return null;
  const holds = bank.db.prepare(`SELECT a.ispb,
    SUM(CASE WHEN h.released_at IS NULL THEN h.blocked_cents ELSE 0 END) held_cents,
    SUM(h.refunded_cents) recovered_cents FROM med_hops h
    JOIN psp_accounts a ON a.id=h.account_id WHERE h.case_id=?
    GROUP BY a.ispb ORDER BY a.ispb`).all(row.id) as
    { ispb: string; held_cents: number; recovered_cents: number }[];
  const accounts = bank.db.prepare(`SELECT h.account_id,a.ispb,h.created_at,
    h.blocked_cents,h.refunded_cents,h.released_at FROM med_hops h
    JOIN psp_accounts a ON a.id=h.account_id WHERE h.case_id=?`)
    .all(row.id) as MedAccountHold[];
  const state = moneyFlowMedStateFromHolds(row, holds, allowedIspbs);
  const accountStates = publicMedAccountStates(accounts, allowedIspbs);
  return accountStates ? { ...state, accounts: accountStates } : state;
}

function moneyFlowMedStateFromHolds(row: { status: string;
  claim_amount_cents: number | null; refunded_cents: number;
  unrecovered_cents: number }, holds: readonly { ispb: string;
  held_cents: number; recovered_cents: number }[],
  allowedIspbs?: ReadonlySet<string>): MoneyFlowMedState {
  const claim = row.claim_amount_cents ?? row.refunded_cents + row.unrecovered_cents;
  const pending = row.status === "open" || row.status === "settlement_pending_psp";
  const recovery = pending ? "pending" : row.refunded_cents <= 0 ? "none" :
    row.refunded_cents >= claim && claim > 0 ? "full" : "partial";
  return { status: pending ? "open" : row.status as MoneyFlowMedState["status"], recovery,
    institutions: holds.filter((hold) => !allowedIspbs || allowedIspbs.has(hold.ispb))
      .map((hold) => ({ name: moneyFlowInstitutionName(hold.ispb),
        state: hold.held_cents > 0 && hold.recovered_cents > 0 ? "mixed" :
          hold.held_cents > 0 ? "held" : hold.recovered_cents > 0 ? "recovered" : "released" })) };
}

export function moneyFlowMedStateFromPspHops(bank: Bank, transferId: string,
  hops: readonly { id: string; root_transfer_id: string; account_id: string;
    ispb: string; blocked_cents: number; refunded_cents: number;
    released_at: string | null }[],
  allowedIspbs?: ReadonlySet<string>): MoneyFlowMedState | null {
  const row = bank.db.prepare(`SELECT status,claim_amount_cents,refunded_cents,
    unrecovered_cents FROM med_cases WHERE transfer_id=?`).get(transferId) as {
    status: string; claim_amount_cents: number | null; refunded_cents: number;
    unrecovered_cents: number;
  } | undefined;
  if (!row || !["open", "settlement_pending_psp", "refunded", "resolved", "rejected"]
    .includes(row.status)) return null;
  const localHops = bank.db.prepare(`SELECT id,root_transfer_id,account_id,created_at,
    blocked_cents,refunded_cents,
    released_at FROM med_hops WHERE case_id=(SELECT id FROM med_cases WHERE transfer_id=?)
    ORDER BY id`).all(transferId) as { id: string; root_transfer_id: string;
    account_id: string; created_at: string;
    blocked_cents: number; refunded_cents: number; released_at: string | null }[];
  const localById = new Map(localHops.map((hop) => [hop.id, hop]));
  const seenIds = new Set<string>();
  if (localHops.length !== hops.length || hops.some((hop) => {
    if (seenIds.has(hop.id)) return true;
    seenIds.add(hop.id);
    const local = localById.get(hop.id);
    const workerAhead = row.status === "settlement_pending_psp" &&
      local?.released_at === null && hop.released_at !== null &&
      Number.isFinite(Date.parse(hop.released_at)) &&
      Number.isSafeInteger(hop.refunded_cents) && hop.refunded_cents >= 0 &&
      hop.refunded_cents <= hop.blocked_cents;
    return !local || local.account_id !== hop.account_id ||
      local.root_transfer_id !== hop.root_transfer_id ||
      local.blocked_cents !== hop.blocked_cents ||
      !workerAhead && (local.refunded_cents !== hop.refunded_cents ||
        local.released_at !== hop.released_at);
  })) throw new Error("MONEY_FLOW_MED_PROJECTION_DRIFT");
  const byIspb = new Map<string, { ispb: string; held_cents: number;
    recovered_cents: number }>();
  for (const hop of hops) {
    const totals = byIspb.get(hop.ispb) ?? { ispb: hop.ispb, held_cents: 0,
      recovered_cents: 0 };
    const bankHop = localById.get(hop.id)!;
    if (bankHop.released_at === null) totals.held_cents += bankHop.blocked_cents;
    totals.recovered_cents += bankHop.refunded_cents;
    byIspb.set(hop.ispb, totals);
  }
  const state = moneyFlowMedStateFromHolds(row,
    [...byIspb.values()].sort((a, b) => a.ispb.localeCompare(b.ispb)), allowedIspbs);
  const accountStates = publicMedAccountStates(hops.map((hop) => ({
    ...localById.get(hop.id)!, ispb: hop.ispb,
  })), allowedIspbs);
  return accountStates ? { ...state, accounts: accountStates } : state;
}

export function publishMoneyFlowDisclosures(bank: Bank, events: EventStore,
  roundId: string, incidentId: string): void {
  if (!incidentIsDisclosed(events, incidentId)) return;
  for (const disclosure of disclosedRows(bank, incidentId)) {
    const edges = publicMoneyFlowEdges(JSON.parse(disclosure.edges_json) as DisclosedMoneyEdge[]);
    if (!edges.length) continue;
    events.append({ round_id: roundId, ts: new Date().toISOString(),
      twin_ts: bank.now().toISOString(), type: "money_flow.disclosed",
      actor: { id: "campaign-controller", role: "system" }, area: "pix", incident_id: incidentId,
      public_summary_pt: "Cadeia Pix divulgada após prova verificada",
      public: { incident_id: incidentId, edges } },
    `money-flow:${roundId}:${incidentId}:${disclosure.transfer_id}`);
  }
}

function appendMoneyFlowMedSnapshot(bank: Bank, events: EventStore,
  roundId: string, incidentId: string, transferId: string,
  disclosureSeq: number, med: MoneyFlowMedState): void {
    const institutions = med.institutions.map((institution) => ({
      name: presentationInstitution(institution.name), state: institution.state,
    }));
    const accounts = med.accounts?.map((account) => ({
      name: presentationInstitution(account.name), slot: account.slot,
      state: account.state,
    }));
    const marker = bank.db.prepare("SELECT resolve_after FROM med_cases WHERE transfer_id=?")
      .get(transferId) as { resolve_after: string };
    const snapshot = { incident_id: incidentId, disclosure_seq: disclosureSeq,
      status: med.status, recovery: med.recovery, institutions,
      ...(accounts ? { accounts } : {}) };
    const digest = createHash("sha256").update(JSON.stringify([snapshot, marker.resolve_after]))
      .digest("hex");
    events.append({ round_id: roundId, ts: new Date().toISOString(),
      twin_ts: bank.now().toISOString(), type: "money_flow.med_updated",
      actor: { id: "med-recovery", role: "system" }, area: "pix", incident_id: incidentId,
      public_summary_pt: med.status === "rejected" ? "MED não aprovado; bloqueio liberado" :
        med.status === "open" ?
        institutions.some((institution) => institution.state === "held" ||
          institution.state === "mixed") ? "MED bloqueou valores na cadeia Pix" :
          "MED em análise na cadeia Pix" : "MED concluiu a análise da cadeia Pix",
      public: snapshot },
    `money-flow-med:${roundId}:${incidentId}:${transferId}:${digest}`);
}

function appendVerifiedPspRefundSteps(bank: Bank, events: EventStore,
  roundId: string, incidentId: string, transferId: string,
  disclosureSeq: number, allowedIspbs: ReadonlySet<string>,
  hops: readonly MedAccountHold[],
  workerSteps: Awaited<ReturnType<EcosystemClient["medRefundTimeline"]>>): void {
  const med = bank.db.prepare(`SELECT id,status FROM med_cases WHERE transfer_id=?`)
    .get(transferId) as { id: string; status: string } | undefined;
  if (med?.status !== "resolved" && med?.status !== "settlement_pending_psp") return;
  const priorPending = events.db.prepare(`SELECT 1 FROM events
    WHERE type='money_flow.med_updated' AND round_id=? AND incident_id=?
      AND json_extract(public_json,'$.disclosure_seq')=?
      AND json_extract(public_json,'$.recovery')='pending' LIMIT 1`)
    .get(roundId, incidentId, disclosureSeq);
  if (!priorPending) return;
  const bankSteps = bank.db.prepare(`SELECT ispb,sequence,processed_at,refunded_cents
    FROM med_psp_refund_steps WHERE case_id=? ORDER BY sequence`)
    .all(med.id) as { ispb: string; sequence: number; processed_at: string;
      refunded_cents: number }[];
  const steps = med.status === "resolved" ? bankSteps : workerSteps;
  const participants = [...new Set(hops.map((hop) => hop.ispb))]
    .sort().map((ispb) => ({ ispb }));
  if (steps.length === 0 && med.status === "settlement_pending_psp") return;
  if (steps.length > participants.length ||
    med.status === "resolved" && steps.length !== participants.length ||
    steps.some((step, index) =>
    step.sequence !== index + 1 ||
    !participants.some((participant) => participant.ispb === step.ispb)))
    throw new Error("MONEY_FLOW_MED_STEP_DRIFT");
  if (med.status === "settlement_pending_psp") {
    let unprocessed = false;
    let previousProcessedAt: number | null = null;
    for (const step of workerSteps) {
      const requestedAt = Date.parse(step.requested_at);
      const deadlineAt = Date.parse(step.deadline_at);
      if (step.case_id !== med.id || !Number.isFinite(requestedAt) ||
        !Number.isFinite(deadlineAt) || deadlineAt - requestedAt !== 6 * 3_600_000 ||
        previousProcessedAt !== null && requestedAt < previousProcessedAt)
        throw new Error("MONEY_FLOW_MED_STEP_DRIFT");
      if (step.processed_at === null) unprocessed = true;
      else if (unprocessed || !Number.isFinite(Date.parse(step.processed_at)) ||
        Date.parse(step.processed_at) < requestedAt ||
        Date.parse(step.processed_at) > bank.now().getTime() ||
        !Number.isSafeInteger(step.refunded_cents) || step.refunded_cents! < 0)
        throw new Error("MONEY_FLOW_MED_STEP_DRIFT");
      if (step.processed_at === null && step.refunded_cents !== null)
        throw new Error("MONEY_FLOW_MED_STEP_DRIFT");
      if (step.processed_at !== null)
        previousProcessedAt = Date.parse(step.processed_at);
      const workerHops = hops.filter((hop) => hop.ispb === step.ispb);
      if (workerHops.some((hop) => step.processed_at === null ?
        hop.released_at !== null || hop.refunded_cents !== 0 :
        hop.released_at !== step.processed_at) ||
        (step.processed_at !== null && workerHops.reduce((sum, hop) =>
          sum + hop.refunded_cents, 0) !== step.refunded_cents))
        throw new Error("MONEY_FLOW_MED_STEP_DRIFT");
    }
    if (hops.some((hop) => !steps.some((step) => step.ispb === hop.ispb) &&
      (hop.released_at !== null || hop.refunded_cents !== 0)))
      throw new Error("MONEY_FLOW_MED_STEP_DRIFT");
  }
  const processed = new Map<string, "recovered" | "released">();
  for (const step of steps.slice(0, steps.length === participants.length ? -1 : undefined)) {
    if (step.processed_at === null) break;
    processed.set(step.ispb, step.refunded_cents! > 0 ? "recovered" : "released");
    if (!allowedIspbs.has(step.ispb)) continue;
    const institutions = participants.filter(({ ispb }) => allowedIspbs.has(ispb))
      .map(({ ispb }) => ({ name: presentationInstitution(moneyFlowInstitutionName(ispb)),
        state: processed.get(ispb) ?? "held" }));
    const accounts = publicMedAccountStates(hops.map((hop) =>
      processed.has(hop.ispb) ? hop : { ...hop, refunded_cents: 0, released_at: null }),
    allowedIspbs)?.map((account) => ({
      name: presentationInstitution(account.name), slot: account.slot,
      state: account.state,
    }));
    const snapshot = { incident_id: incidentId, disclosure_seq: disclosureSeq,
      status: "open" as const, recovery: "pending" as const, institutions,
      ...(accounts ? { accounts } : {}) };
    events.append({ round_id: roundId, ts: new Date().toISOString(),
      twin_ts: step.processed_at, type: "money_flow.med_updated",
      actor: { id: "med-recovery", role: "system" }, area: "pix", incident_id: incidentId,
      public_summary_pt: "MED processou uma instituição da cadeia Pix",
      public: snapshot },
    `money-flow-med-step:${roundId}:${incidentId}:${transferId}:${step.sequence}`);
  }
}

export function publishMoneyFlowMedSnapshots(bank: Bank, events: EventStore,
  roundId: string, incidentId: string): void {
  if (!incidentIsDisclosed(events, incidentId)) return;
  for (const disclosure of disclosedRows(bank, incidentId)) {
    const link = events.db.prepare("SELECT seq FROM events WHERE idem=?")
      .get(`money-flow:${roundId}:${incidentId}:${disclosure.transfer_id}`) as
      { seq: number } | undefined;
    if (!link) continue;
    const disclosedEdges = JSON.parse(disclosure.edges_json) as DisclosedMoneyEdge[];
    const allowedIspbs = new Set(disclosedEdges.flatMap((edge) =>
      [edge.from_ispb, edge.to_ispb]));
    const med = moneyFlowMedState(bank, disclosure.transfer_id, allowedIspbs);
    if (med) appendMoneyFlowMedSnapshot(bank, events, roundId, incidentId,
      disclosure.transfer_id, link.seq, med);
  }
}

export async function publishSeparatedMoneyFlowMedSnapshots(bank: Bank,
  events: EventStore, roundId: string, incidentId: string,
  project: (rootTransferId: string, caseId: string) =>
    ReturnType<EcosystemClient["moneyFlowProjection"]>): Promise<void> {
  if (!incidentIsDisclosed(events, incidentId)) return;
  for (const disclosure of disclosedRows(bank, incidentId)) {
    const link = events.db.prepare("SELECT seq FROM events WHERE idem=?")
      .get(`money-flow:${roundId}:${incidentId}:${disclosure.transfer_id}`) as
      { seq: number } | undefined;
    if (!link) continue;
    const medCase = bank.db.prepare("SELECT id FROM med_cases WHERE transfer_id=?")
      .get(disclosure.transfer_id) as { id: string } | undefined;
    if (!medCase) continue;
    const disclosedEdges = JSON.parse(disclosure.edges_json) as DisclosedMoneyEdge[];
    const allowedIspbs = new Set(disclosedEdges.flatMap((edge) =>
      [edge.from_ispb, edge.to_ispb]));
    const projection = await project(disclosure.transfer_id, medCase.id);
    const med = moneyFlowMedStateFromPspHops(bank, disclosure.transfer_id,
      projection.hops, allowedIspbs);
    if (med) {
      appendVerifiedPspRefundSteps(bank, events, roundId, incidentId,
        disclosure.transfer_id, link.seq, allowedIspbs, projection.hops,
        projection.refundSteps);
      appendMoneyFlowMedSnapshot(bank, events, roundId, incidentId,
        disclosure.transfer_id, link.seq, med);
    }
  }
}

export async function publishSeparatedMoneyFlowMedProgress(bank: Bank,
  events: EventStore, transferId: string,
  project: (rootTransferId: string, caseId: string) =>
    ReturnType<EcosystemClient["moneyFlowProjection"]>): Promise<void> {
  if (!bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='presentation_money_flow_disclosures'`).get()) return;
  const incidents = bank.db.prepare(`SELECT DISTINCT incident_id FROM
    presentation_money_flow_disclosures WHERE transfer_id=?`)
    .all(transferId) as { incident_id: string }[];
  for (const { incident_id: incidentId } of incidents) {
    if (!incidentIsDisclosed(events, incidentId)) continue;
    const links = events.db.prepare(`SELECT round_id,idem FROM events
      WHERE type='money_flow.disclosed' AND incident_id=?`)
      .all(incidentId) as { round_id: string | null; idem: string | null }[];
    for (const link of links) {
      if (link.round_id && link.idem ===
        `money-flow:${link.round_id}:${incidentId}:${transferId}`)
        await publishSeparatedMoneyFlowMedSnapshots(bank, events, link.round_id,
          incidentId, project);
    }
  }
}

export function recordMoneyFlowDisclosure(bank: Bank, incidentId: string,
  proofRefs: readonly string[]): number {
  const find = bank.db.prepare(`SELECT DISTINCT e.transfer_id FROM sentinel_incident_transfer_evidence e
    JOIN pix_transfers p ON p.id=e.transfer_id
    WHERE e.incident_id=? AND e.evidence_ref=?
      AND p.status IN ('settled','returned_partial','returned_full')`);
  const insert = bank.db.prepare(`INSERT OR IGNORE INTO presentation_money_flow_disclosures
    (incident_id,transfer_id,edges_json,disclosed_at) VALUES (?,?,?,?)`);
  let recorded = 0;
  for (const ref of new Set(proofRefs)) {
    const transfers = find.all(incidentId, `red_sandbox_calls:${ref}`) as
      { transfer_id: string }[];
    for (const transfer of transfers) {
      const edges = bank.psp.path(transfer.transfer_id).map((edge) => ({
        from_ispb: edge.from_ispb, to_ispb: edge.to_ispb, kind: edge.kind,
      }));
      if (edges.length) recorded += Number(insert.run(incidentId, transfer.transfer_id,
        JSON.stringify(edges), bank.now().toISOString()).changes);
    }
  }
  return recorded;
}

export async function recordSeparatedMoneyFlowDisclosure(bank: Bank,
  incidentId: string, proofRefs: readonly string[],
  project: (rootTransferId: string) =>
    ReturnType<EcosystemClient["moneyFlowProjection"]>): Promise<number> {
  if (!bank.isSeparatedEcosystem) throw new Error("MONEY_FLOW_SEPARATED_BANK_REQUIRED");
  const find = bank.db.prepare(`SELECT DISTINCT p.id FROM sentinel_incident_transfer_evidence e
    JOIN pix_transfers p ON p.id=e.transfer_id
    WHERE e.incident_id=? AND e.evidence_ref=?
      AND p.status IN ('settled','returned_partial','returned_full')
      AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id=p.to_account)`);
  const ids = new Set<string>();
  for (const ref of new Set(proofRefs))
    for (const row of find.all(incidentId, `red_sandbox_calls:${ref}`) as { id: string }[])
      ids.add(row.id);
  const snapshots: { id: string; edges: DisclosedMoneyEdge[] }[] = [];
  for (const id of ids) {
    const root = bank.db.prepare(`SELECT p.amount,p.end_to_end_id,
      o.from_ispb,o.to_ispb,o.amount_cents,o.response_status
      FROM pix_transfers p LEFT JOIN pix_spi_outbox o ON o.transfer_id=p.id
      WHERE p.id=?`).get(id) as { amount: number; end_to_end_id: string;
        from_ispb: string | null; to_ispb: string | null;
        amount_cents: number | null; response_status: string | null } | undefined;
    if (!root || root.response_status !== "ACSC")
      throw new Error("MONEY_FLOW_ROOT_DRIFT");
    const projection = await project(id);
    const first = projection.path[0];
    if (first?.kind !== "payment" || first.end_to_end_id !== root.end_to_end_id ||
      first.from_ispb !== root.from_ispb || first.to_ispb !== root.to_ispb ||
      first.amount_cents !== root.amount || root.amount_cents !== root.amount)
      throw new Error("MONEY_FLOW_ROOT_DRIFT");
    snapshots.push({ id, edges: projection.path.map((edge) => ({
      from_ispb: edge.from_ispb, to_ispb: edge.to_ispb, kind: edge.kind })) });
  }
  const insert = bank.db.prepare(`INSERT OR IGNORE INTO presentation_money_flow_disclosures
    (incident_id,transfer_id,edges_json,disclosed_at) VALUES (?,?,?,?)`);
  return bank.transaction(() => snapshots.reduce((count, snapshot) =>
    count + Number(insert.run(incidentId, snapshot.id,
      JSON.stringify(snapshot.edges), bank.now().toISOString()).changes), 0));
}
