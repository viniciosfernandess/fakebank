import type { DatabaseSync } from "node:sqlite";
import { gatewayRouteTemplate } from "../../world/src/gateway.ts";
import { hasUnresolvedNestedFields, parseGatewayRequestObservation } from
  "../../world/src/response-field-evidence.ts";

export interface ContainedIdentityWindow {
  customerId: string; deviceId: string; revokedAt: string;
  sourceEventId: number; throughEventId: number;
}

interface ActivityRow {
  id: number;
  trace_id: string;
  source: string;
  category: string;
  action: string;
  outcome: string;
  account_id: string | null;
  amount_cents: number | null;
  message: string;
}
type ScopedActivity = Omit<ActivityRow, "trace_id" | "category" | "message">;
type GatewayActivity = ScopedActivity & NonNullable<ReturnType<typeof parseGatewayRequestObservation>>;

export function readIdentitySessionActivity(db: DatabaseSync, input: {
  customerId: string; deviceId: string; sessionId: string | null; revokedAt: string;
  sourceEventId?: number;
}) {
  const limit = 20;
  const rows = input.sessionId ? db.prepare(`SELECT id,trace_id,source,category,action,
    outcome,account_id,amount_cents,message FROM telemetry_events
    WHERE session_id=? AND user_id=? AND device_id=? AND twin_ts>=?
    ORDER BY id LIMIT ?`).all(input.sessionId, input.customerId, input.deviceId,
      input.revokedAt, limit + 1) as unknown as ActivityRow[] : [];
  const traceLimit = 6;
  // Keep the exact alert source and its completion even if the general sample
  // filled up earlier. Both sides must retain the same customer, device and session.
  const traceRows = input.sessionId && input.sourceEventId !== undefined ?
    db.prepare(`SELECT e.id,e.trace_id,e.source,e.category,e.action,e.outcome,
      e.account_id,e.amount_cents,e.message
      FROM telemetry_events s JOIN telemetry_events e
        ON e.trace_id=s.trace_id AND e.session_id=s.session_id
        AND e.user_id=s.user_id AND e.device_id=s.device_id
      WHERE s.id=? AND s.session_id=? AND s.user_id=? AND s.device_id=? AND s.twin_ts>=?
        AND s.source='auth' AND s.category='audit' AND s.outcome='success'
        AND s.action IN ('access_revoked_device','refresh_revoked_device')
        AND (e.id=s.id OR (e.id>s.id AND e.twin_ts>=?
          AND e.source='gateway' AND e.category='request' AND e.action='request'))
      ORDER BY e.id LIMIT ?`).all(input.sourceEventId, input.sessionId,
        input.customerId, input.deviceId, input.revokedAt, input.revokedAt,
        traceLimit + 1) as unknown as ActivityRow[] : [];
  const window = [...new Map([...rows.slice(0, limit), ...traceRows.slice(0, traceLimit)]
    .map((row) => [row.id, row])).values()].sort((a, b) => a.id - b.id);
  const completedTraces = new Set<string>();
  const activity = window.map<ScopedActivity | GatewayActivity>(({ trace_id, category, message, ...row }) => {
    if (row.source !== "gateway" || category !== "request" || row.action !== "request")
      return row;
    const observation = parseGatewayRequestObservation(message, row.outcome);
    if (!observation || gatewayRouteTemplate(observation.routeTemplate) !== observation.routeTemplate)
      return row;
    completedTraces.add(trace_id);
    return { ...row, ...observation };
  });
  const accessWithoutRequestCompletion = window.filter((row) => row.source === "auth" &&
    (row.action === "access_revoked_device" || row.action === "refresh_revoked_device") &&
    row.outcome === "success" &&
    !completedTraces.has(row.trace_id)).map((row) => row.id);
  return { activity, activityTruncated: rows.length > limit || traceRows.length > traceLimit,
    sessionAttributionMissing: input.sessionId === null, accessWithoutRequestCompletion };
}

export function describeIdentityActivity(observations: unknown): string {
  if (!Array.isArray(observations) || observations.length === 0)
    return "Atividade registrada com escopo ainda em apuração.";
  const requests = new Map<number, boolean>();
  const incompleteAccess = new Set<number>();
  const nestedPixRequests = new Set<number>();
  let truncated = false;
  let sessionMissing = false;
  for (const observation of observations) {
    if (!observation || typeof observation !== "object") continue;
    truncated ||= observation.activityTruncated === true;
    sessionMissing ||= observation.sessionAttributionMissing === true;
    if (Array.isArray(observation.accessWithoutRequestCompletion))
      for (const id of observation.accessWithoutRequestCompletion)
        if (Number.isSafeInteger(id) && id > 0) incompleteAccess.add(id);
    if (!Array.isArray(observation.request_completions)) continue;
    for (const request of observation.request_completions) {
      if (!request || typeof request !== "object" ||
        !Number.isSafeInteger(request.event_id) || request.event_id < 1) continue;
      const fields = request.response_fields;
      const verified = Array.isArray(fields) && fields.every((field) => typeof field === "string");
      requests.set(request.event_id, verified || requests.get(request.event_id) === true);
      if (verified && hasUnresolvedNestedFields(request.route_template, fields))
        nestedPixRequests.add(request.event_id);
    }
  }
  const verified = [...requests.values()].filter(Boolean).length;
  return [
    `Respostas com prova de campos na amostra (${verified}).`,
    `Respostas sem prova de campos (${requests.size - verified}).`,
    ...(incompleteAccess.size ? [`Acessos sem resposta vinculada (${incompleteAccess.size}).`] : []),
    ...(nestedPixRequests.size ?
      [`Detalhes de Pix com campos internos em apuração (${nestedPixRequests.size}).`] : []),
    ...(sessionMissing ? ["Há acessos sem vínculo com uma sessão."] : []),
    ...(truncated ? ["A amostra atingiu o limite de registros."] : []),
  ].join(" ");
}

export function readContainedIdentityWindow(db: DatabaseSync, input: ContainedIdentityWindow) {
  const limit = 500;
  const rows = db.prepare(`WITH owned_sessions AS (
      SELECT id FROM auth_sessions WHERE customer_id=? AND device_id=?
    ), scoped_event_ids AS (
      SELECT id FROM telemetry_events WHERE device_id=? AND twin_ts>=? AND id<=?
      UNION
      SELECT e.id FROM owned_sessions s JOIN telemetry_events e ON e.session_id=s.id
      WHERE e.twin_ts>=? AND e.id<=?
    ) SELECT e.id,e.trace_id,e.session_id,e.user_id,e.device_id,
      s.id AS owned_session,e.source,e.outcome,e.message
    FROM scoped_event_ids ids JOIN telemetry_events e ON e.id=ids.id
    LEFT JOIN owned_sessions s ON s.id=e.session_id
    WHERE ((e.source='auth' AND e.category='audit' AND e.outcome='success'
        AND e.action IN ('access_revoked_device','refresh_revoked_device'))
        OR (e.source='gateway' AND e.category='request' AND e.action='request'))
    ORDER BY e.id LIMIT ?`).all(input.customerId, input.deviceId, input.deviceId,
      input.revokedAt, input.throughEventId, input.revokedAt, input.throughEventId, limit + 1) as {
      id: number; trace_id: string; session_id: string | null; user_id: string | null;
      device_id: string | null; owned_session: string | null;
      source: string; outcome: string; message: string;
    }[];
  const window = rows.slice(0, limit);
  const responses = window.filter((event) => event.source === "gateway");
  const accesses = window.filter((event) => event.source === "auth");
  const attributed = (event: typeof window[number]) =>
    event.user_id === input.customerId && event.device_id === input.deviceId &&
    event.owned_session !== null;
  const linkedResponseIds = new Set<number>();
  const unresolvedAccessIds: number[] = [];
  const observed = accesses.flatMap((access) => {
    const matches = responses.filter((response) => response.id > access.id &&
      response.trace_id === access.trace_id && response.session_id === access.session_id);
    if (!attributed(access) || matches.length !== 1 || !attributed(matches[0]!)) {
      unresolvedAccessIds.push(access.id);
      return [];
    }
    const response = matches[0]!;
    if (linkedResponseIds.has(response.id)) {
      unresolvedAccessIds.push(access.id);
      return [];
    }
    linkedResponseIds.add(response.id);
    const proof = parseGatewayRequestObservation(response.message, response.outcome);
    if (!proof?.responseFields || gatewayRouteTemplate(proof.routeTemplate) !== proof.routeTemplate ||
      hasUnresolvedNestedFields(proof.routeTemplate, proof.responseFields)) {
      unresolvedAccessIds.push(access.id);
      return [];
    }
    return [{ access_event_id: access.id, response_event_id: response.id,
      route_template: proof.routeTemplate, response_fields: proof.responseFields }];
  });
  const unlinkedResponseIds = responses.filter((event) => !linkedResponseIds.has(event.id))
    .map((event) => event.id);
  const truncated = rows.length > limit;
  const triggerIncluded = accesses.some((event) => event.id === input.sourceEventId);
  const watermarkExists = db.prepare("SELECT 1 FROM telemetry_events WHERE id=?")
    .get(input.throughEventId);
  return { through_event_id: input.throughEventId, truncated,
    complete: Boolean(watermarkExists) && triggerIncluded && !truncated && unresolvedAccessIds.length === 0 &&
      unlinkedResponseIds.length === 0 && linkedResponseIds.size === accesses.length,
    observed, unresolved_access_ids: unresolvedAccessIds, unlinked_response_ids: unlinkedResponseIds };
}

export function readIdentityFinancialWindow(db: DatabaseSync, input: ContainedIdentityWindow,
  observedScope: ReturnType<typeof readContainedIdentityWindow>) {
  const limit = 100;
  const rows = db.prepare(`WITH owned_sessions AS (
    SELECT id FROM auth_sessions WHERE customer_id=$customer AND device_id=$device
  ), accesses AS (
    SELECT e.id,e.trace_id,e.session_id FROM owned_sessions s
    JOIN telemetry_events e ON e.session_id=s.id
    WHERE e.user_id=$customer AND e.device_id=$device AND e.twin_ts>=$revoked AND e.id<=$through
      AND e.source='auth' AND e.category='audit' AND e.outcome='success'
      AND e.action IN ('access_revoked_device','refresh_revoked_device')
  ), scoped_event_ids AS (
    SELECT id FROM telemetry_events WHERE device_id=$device AND twin_ts>=$revoked AND id<=$through
    UNION
    SELECT e.id FROM owned_sessions s JOIN telemetry_events e ON e.session_id=s.id
      WHERE e.twin_ts>=$revoked AND e.id<=$through
    UNION
    SELECT e.id FROM accesses a JOIN telemetry_events e ON e.trace_id=a.trace_id
      WHERE a.id<e.id AND e.twin_ts>=$revoked AND e.id<=$through
  ) SELECT e.id,e.counterparty,e.amount_cents,
      EXISTS (SELECT 1 FROM accesses a WHERE a.trace_id=e.trace_id
        AND a.session_id=e.session_id AND a.id<e.id) AS trace_linked,
      e.user_id=$customer AND e.device_id=$device AS owner_matched
    FROM scoped_event_ids ids JOIN telemetry_events e ON e.id=ids.id
    WHERE e.source='ledger' AND e.category='transaction' AND e.action='post'
      AND e.outcome='success'
    ORDER BY e.id LIMIT $limit`).all({
      $customer: input.customerId, $device: input.deviceId, $revoked: input.revokedAt,
      $through: input.throughEventId, $limit: limit + 1,
    }) as {
      id: number; counterparty: string | null; amount_cents: number | null;
      trace_linked: number; owner_matched: number | null;
    }[];
  const unresolvedPostingIds: number[] = [];
  const confirmedTransactions = new Set<string>();
  const verifiedPostings = rows.slice(0, limit).flatMap((row) => {
    const txId = row.counterparty;
    const totals = row.trace_linked === 1 && row.owner_matched === 1 && txId &&
      !confirmedTransactions.has(txId) ?
      db.prepare(`SELECT COUNT(*) entries,COALESCE(SUM(e.amount),0) balance,
        COALESCE(SUM(CASE WHEN e.amount>0 THEN e.amount ELSE 0 END),0) posted,
        COALESCE(SUM(CASE WHEN a.customer_id=? AND e.amount<0 THEN -e.amount ELSE 0 END),0) customer_debits
        FROM ledger_entries e JOIN accounts a ON a.id=e.account_id
        WHERE e.tx_id=?`).get(input.customerId, txId) as
          { entries: number; balance: number; posted: number; customer_debits: number } : undefined;
    if (!txId || !totals || totals.entries < 2 || totals.balance !== 0 ||
      totals.posted <= 0 || totals.posted !== row.amount_cents) {
      unresolvedPostingIds.push(row.id);
      return [];
    }
    confirmedTransactions.add(txId);
    return [{ posting_event_id: row.id, ledger_tx_id: txId,
      customer_debit_cents: totals.customer_debits }];
  });
  return { verified_postings: verifiedPostings, unresolved_posting_ids: unresolvedPostingIds,
    truncated: rows.length > limit, no_observed_posting: observedScope.complete && !rows.length };
}

export function describeMeasuredIdentityScope(payload: Record<string, unknown>): string {
  const coverage = payload.complete === true ?
    "Todos os acessos registrados nessa janela têm resposta vinculada e campos identificados." :
    "A janela contém acessos ou respostas com evidência insuficiente.";
  if (!payload.financial || typeof payload.financial !== "object") return coverage;
  const financial = payload.financial as Record<string, unknown>;
  if (financial.no_observed_posting === true)
    return `${coverage} Nenhum lançamento associado foi encontrado na janela registrada.`;
  const verified = Array.isArray(financial.verified_postings) ? financial.verified_postings.length : 0;
  const unresolved = Array.isArray(financial.unresolved_posting_ids) ?
    financial.unresolved_posting_ids.length : 0;
  return [coverage,
    ...(verified ? [`Lançamentos vinculados ao acesso (${verified}).`] : []),
    ...(unresolved ? [`Lançamentos com vínculo ainda em apuração (${unresolved}).`] : []),
    ...(financial.truncated === true ? ["A busca de lançamentos atingiu o limite."] : []),
  ].join(" ");
}
