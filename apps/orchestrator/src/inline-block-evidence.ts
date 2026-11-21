import type { Area } from "../../../packages/contracts/src/index.ts";
import type { Bank } from "../../world/src/bank.ts";

export function inlineBlockEvidence(bank: Bank, roundId: string, agentId: string,
  area: Area): { requestId: string } | null {
  const prefix = area === "pix" ? "/api/v1/pix/" :
    area === "cards" ? "/api/v1/cards/" : null;
  if (!prefix) return null;
  const calls = bank.db.prepare(`SELECT c.request_id,c.status,c.response_json,d.outcome
    FROM red_sandbox_calls c
    LEFT JOIN risk_decisions d ON d.trace_id=c.request_id AND d.area=?
    WHERE c.round_id=? AND c.agent_id=?
      AND c.method NOT IN ('GET','HEAD') AND c.path LIKE ?
    ORDER BY c.rowid DESC LIMIT 1`).all(area, roundId, agentId, `${prefix}%`) as
    { request_id: string; status: number; response_json: string;
      outcome: string | null }[];
  const call = calls[0];
  if (!call || !["step_up", "hold", "decline"].includes(call.outcome ?? "")) return null;
  let response: unknown;
  try { response = JSON.parse(call.response_json); } catch { return null; }
  if (!response || typeof response !== "object" || Array.isArray(response)) return null;
  if (area === "pix") {
    const expected = call.outcome === "step_up" ? ["DEF_STEP_UP_REQUIRED"] :
      call.outcome === "hold" ? ["BIZ_RISK_HOLD"] :
        ["BIZ_RISK_DECLINE", "BIZ_FRAUD_DESTINATION"];
    return call.status >= 400 && "error" in response &&
      expected.includes(String(response.error)) ? { requestId: call.request_id } : null;
  }
  if (call.status !== 200 || !("id" in response) || typeof response.id !== "string")
    return null;
  const authorization = bank.db.prepare(`SELECT risk_blocked FROM card_network_authorizations
    WHERE id=?`).get(response.id) as { risk_blocked: number } | undefined;
  return authorization?.risk_blocked === 1 ? { requestId: call.request_id } : null;
}
