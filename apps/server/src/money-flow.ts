import type { Bank } from "../../world/src/bank.ts";
import { moneyFlowInstitutionName, moneyFlowMedState,
  moneyFlowMedStateFromPspHops, publicMoneyFlowEdges,
  type DisclosedMoneyEdge, type MoneyFlowMedState } from
  "../../orchestrator/src/money-flow-disclosure.ts";
import type { EcosystemClient } from "../../ecosystem/src/client.ts";
import { presentationInstitution } from "../../../packages/contracts/src/money-flow-presentation.ts";

export interface IncidentMoneyFlow {
  incidentId: string | null;
  edges: { from: string; to: string; kind: "payment" | "transfer" | "cashout" }[];
  med: MoneyFlowMedState | null;
}

export function presentationMoneyFlow(flow: IncidentMoneyFlow,
  disclosedEdges: DisclosedMoneyEdge[]) {
  return {
    edges: publicMoneyFlowEdges(disclosedEdges),
    med: flow.med ? { recovery: flow.med.recovery,
      institutions: flow.med.institutions.map((institution) => ({
        name: presentationInstitution(institution.name), state: institution.state,
      })), ...(flow.med.accounts ? { accounts: flow.med.accounts.map((account) => ({
        name: presentationInstitution(account.name), slot: account.slot,
        state: account.state,
      })) } : {}) } : null,
  };
}

export function incidentMoneyFlow(bank: Bank, incidentId: string | null,
  transferId?: string): IncidentMoneyFlow {
  const root = bank.db.prepare(`SELECT e.incident_id,p.id
    FROM sentinel_incident_transfer_evidence e
    JOIN pix_transfers p ON p.id=e.transfer_id
    JOIN psp_accounts a ON a.id=p.to_account
    WHERE (? IS NULL OR e.incident_id=?) AND (? IS NULL OR p.id=?) AND
      p.status IN ('settled','returned_partial','returned_full')
    ORDER BY e.linked_at DESC,p.initiated_at DESC,p.id DESC LIMIT 1`)
    .get(incidentId, incidentId, transferId ?? null, transferId ?? null) as
    { incident_id: string; id: string } | undefined;
  if (!root) return { incidentId, edges: [], med: null };
  const edges = bank.psp.path(root.id).map((edge) => ({
    from: moneyFlowInstitutionName(edge.from_ispb),
    to: moneyFlowInstitutionName(edge.to_ispb),
    kind: edge.kind,
  }));
  return { incidentId: root.incident_id, edges, med: moneyFlowMedState(bank, root.id) };
}

export async function incidentMoneyFlowSeparated(bank: Bank,
  project: (rootTransferId: string, caseId?: string) =>
    ReturnType<EcosystemClient["moneyFlowProjection"]>,
  incidentId: string | null, transferId?: string,
  allowedIspbs?: ReadonlySet<string>): Promise<IncidentMoneyFlow> {
  const roots = bank.db.prepare(`SELECT e.incident_id,p.id
    FROM sentinel_incident_transfer_evidence e
    JOIN pix_transfers p ON p.id=e.transfer_id
    WHERE (? IS NULL OR e.incident_id=?) AND (? IS NULL OR p.id=?) AND
      p.status IN ('settled','returned_partial','returned_full') AND
      NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id=p.to_account)
    ORDER BY e.linked_at DESC,p.initiated_at DESC,p.id DESC LIMIT 100`)
    .all(incidentId, incidentId, transferId ?? null, transferId ?? null) as
    { incident_id: string; id: string }[];
  for (const root of roots) {
    const medCase = bank.db.prepare("SELECT id FROM med_cases WHERE transfer_id=?")
      .get(root.id) as { id: string } | undefined;
    const projection = await project(root.id, medCase?.id);
    if (!projection.path.length) continue;
    return { incidentId: root.incident_id, edges: projection.path.map((edge) => ({
      from: moneyFlowInstitutionName(edge.from_ispb),
      to: moneyFlowInstitutionName(edge.to_ispb), kind: edge.kind,
    })), med: moneyFlowMedStateFromPspHops(bank, root.id,
      projection.hops, allowedIspbs) };
  }
  return { incidentId, edges: [], med: null };
}
