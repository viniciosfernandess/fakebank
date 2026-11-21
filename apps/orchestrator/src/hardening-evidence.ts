import type { Bank } from "../../world/src/bank.ts";

export interface RiskSample {
  decisionId: string;
  features: Record<string, number>;
  outcome: string;
}
export interface HardeningEvidence {
  attack: RiskSample[];
  honest: RiskSample[];
  ambiguousTransferIds: string[];
  affectedHonestTruncated: boolean;
  attackTruncated: boolean;
}

function sample(row: { id: string; features_json: string; outcome: string }): RiskSample {
  const features = JSON.parse(row.features_json) as Record<string, unknown>;
  if (!features || typeof features !== "object" || Array.isArray(features) ||
    Object.values(features).some((value) => typeof value !== "number" || !Number.isFinite(value)))
    throw new Error("HARDENING_FEATURES_INVALID");
  return { decisionId: row.id, features: features as Record<string, number>,
    outcome: row.outcome };
}

export function collectPixHardeningEvidence(bank: Bank, incidentId: string): HardeningEvidence {
  const linked = bank.db.prepare(`SELECT DISTINCT p.id transfer_id,p.from_account,p.to_account,
    p.amount,p.initiated_at,r.id decision_id,r.features_json,r.outcome,
    r.area,r.account_id,r.entity_id,r.amount_cents
    FROM sentinel_incident_transfer_evidence e
    JOIN pix_transfers p ON p.id=e.transfer_id
    LEFT JOIN risk_decisions r ON r.id=p.risk_decision_id
    WHERE e.incident_id=? AND e.evidence_ref LIKE 'red_sandbox_calls:%'
    ORDER BY p.initiated_at,p.id LIMIT 51`).all(incidentId) as {
      transfer_id: string; from_account: string; to_account: string;
      amount: number; initiated_at: string;
      decision_id: string | null; features_json: string | null; outcome: string | null;
      area: string | null; account_id: string | null; entity_id: string | null;
      amount_cents: number | null;
    }[];
  const attackTruncated = linked.length > 50;
  const attack: RiskSample[] = [];
  const ambiguousTransferIds: string[] = [];
  for (const transfer of linked.slice(0, 50)) {
    if (transfer.decision_id && transfer.features_json && transfer.outcome &&
      transfer.area === "pix" && transfer.account_id === transfer.from_account &&
      transfer.entity_id === transfer.to_account && transfer.amount_cents === transfer.amount)
      attack.push(sample({ id: transfer.decision_id, features_json: transfer.features_json,
        outcome: transfer.outcome }));
    else ambiguousTransferIds.push(transfer.transfer_id);
  }
  const affectedAccounts = [...new Set(linked.map((transfer) => transfer.from_account))];
  const attackIds = attack.map((item) => item.decisionId);
  const placeholders = (count: number) => Array(count).fill("?").join(",");
  const affectedRows = affectedAccounts.length ? bank.db.prepare(`SELECT r.id,r.features_json,r.outcome
    FROM risk_decisions r JOIN accounts a ON a.id=r.account_id
    JOIN customers c ON c.id=a.customer_id
    WHERE r.area='pix' AND r.outcome='approve' AND c.is_attacker_owned=0
      AND r.account_id IN (${placeholders(affectedAccounts.length)})
      ${attackIds.length ? `AND r.id NOT IN (${placeholders(attackIds.length)})` : ""}
    ORDER BY r.created_at DESC,r.id DESC LIMIT 201`)
    .all(...affectedAccounts, ...attackIds) as
    { id: string; features_json: string; outcome: string }[] : [];
  const affectedHonestTruncated = affectedRows.length > 200;
  const otherRows = bank.db.prepare(`SELECT r.id,r.features_json,r.outcome
    FROM risk_decisions r JOIN accounts a ON a.id=r.account_id
    JOIN customers c ON c.id=a.customer_id
    WHERE r.area='pix' AND r.outcome='approve' AND c.is_attacker_owned=0
      ${affectedAccounts.length ? `AND r.account_id NOT IN (${
        placeholders(affectedAccounts.length)})` : ""}
    ORDER BY r.created_at DESC,r.id DESC LIMIT 200`)
    .all(...affectedAccounts) as { id: string; features_json: string; outcome: string }[];
  return { attack, honest: [...affectedRows.slice(0, 200), ...otherRows].map(sample),
    ambiguousTransferIds, affectedHonestTruncated, attackTruncated };
}
