import type { DatabaseSync } from "node:sqlite";
import type { Bank } from "./bank.ts";
import { BankError } from "./bank.ts";
import { parseGatewayRequestObservation, responseCategoryPt } from "./response-field-evidence.ts";

export interface IncidentNotice {
  id: number;
  kind: "card_issuer_recovered" | "revoked_device_access" |
    "suspicious_pix_review";
  message_pt: string;
  created_at: string;
}

const recoveryMessage = "Identificamos uma tentativa de pagamento com cartão recusada durante uma indisponibilidade do emissor. O serviço voltou. A tentativa recusada não gerou cobrança; se ainda precisar concluir a compra, tente novamente. Se houve outro prejuízo, procure o atendimento.";
const identityMessage = "Detectamos um acesso aceito por um aparelho que estava revogado. Encerramos as sessões desse aparelho e corrigimos a validação de acesso.";

export function installIncidentNotices(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS incident_customer_notices (
    customer_id TEXT NOT NULL REFERENCES customers(id),
    id INTEGER NOT NULL CHECK(id>0),
    incident_id TEXT NOT NULL REFERENCES sentinel_incidents(id),
    outage_history_id INTEGER NOT NULL REFERENCES card_issuer_history(id),
    rejection_id TEXT NOT NULL REFERENCES card_network_rejections(id),
    restored_history_id INTEGER NOT NULL REFERENCES card_issuer_history(id),
    authorization_id TEXT NOT NULL REFERENCES card_network_authorizations(id),
    kind TEXT NOT NULL CHECK(kind='card_issuer_recovered'),
    message_pt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(customer_id,id),
    UNIQUE(incident_id,outage_history_id,customer_id,kind)
  );
  CREATE INDEX IF NOT EXISTS incident_customer_notices_incident
    ON incident_customer_notices(incident_id,outage_history_id);
  CREATE TRIGGER IF NOT EXISTS incident_customer_notices_no_update
    BEFORE UPDATE ON incident_customer_notices BEGIN
      SELECT RAISE(ABORT,'INCIDENT_NOTICE_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS incident_customer_notices_no_delete
    BEFORE DELETE ON incident_customer_notices BEGIN
      SELECT RAISE(ABORT,'INCIDENT_NOTICE_IMMUTABLE'); END;
  CREATE TABLE IF NOT EXISTS identity_incident_notices (
    customer_id TEXT NOT NULL REFERENCES customers(id),
    id INTEGER NOT NULL CHECK(id>0),
    incident_id TEXT NOT NULL REFERENCES sentinel_incidents(id),
    alert_id TEXT NOT NULL REFERENCES sentinel_alerts(id),
    source_event_id INTEGER NOT NULL REFERENCES telemetry_events(id),
    device_id TEXT NOT NULL REFERENCES auth_devices(id),
    kind TEXT NOT NULL CHECK(kind='revoked_device_access'),
    message_pt TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY(customer_id,id),
    UNIQUE(incident_id,customer_id,source_event_id)
  );
  CREATE TRIGGER IF NOT EXISTS identity_incident_notices_no_update
    BEFORE UPDATE ON identity_incident_notices BEGIN
      SELECT RAISE(ABORT,'INCIDENT_NOTICE_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS identity_incident_notices_no_delete
    BEFORE DELETE ON identity_incident_notices BEGIN
      SELECT RAISE(ABORT,'INCIDENT_NOTICE_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS identity_incident_notices_no_collision
    BEFORE INSERT ON identity_incident_notices WHEN EXISTS
      (SELECT 1 FROM incident_customer_notices c WHERE
        c.customer_id=NEW.customer_id AND c.id=NEW.id)
    BEGIN SELECT RAISE(ABORT,'INCIDENT_NOTICE_ID_COLLISION'); END;
  CREATE TRIGGER IF NOT EXISTS incident_customer_notices_no_identity_collision
    BEFORE INSERT ON incident_customer_notices WHEN EXISTS
      (SELECT 1 FROM identity_incident_notices i WHERE
        i.customer_id=NEW.customer_id AND i.id=NEW.id)
    BEGIN SELECT RAISE(ABORT,'INCIDENT_NOTICE_ID_COLLISION'); END;
  CREATE TABLE IF NOT EXISTS fraud_incident_notices (
    customer_id TEXT NOT NULL REFERENCES customers(id),
    id INTEGER NOT NULL CHECK(id>0),
    incident_id TEXT NOT NULL REFERENCES sentinel_incidents(id),
    alert_id TEXT NOT NULL REFERENCES sentinel_alerts(id),
    transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
    kind TEXT NOT NULL CHECK(kind='suspicious_pix_review'),
    message_pt TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY(customer_id,id),
    UNIQUE(incident_id,customer_id,transfer_id)
  );
  CREATE TRIGGER IF NOT EXISTS fraud_incident_notices_no_update
    BEFORE UPDATE ON fraud_incident_notices BEGIN
      SELECT RAISE(ABORT,'INCIDENT_NOTICE_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS fraud_incident_notices_no_delete
    BEFORE DELETE ON fraud_incident_notices BEGIN
      SELECT RAISE(ABORT,'INCIDENT_NOTICE_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS fraud_incident_notices_no_collision
    BEFORE INSERT ON fraud_incident_notices WHEN EXISTS
      (SELECT 1 FROM incident_customer_notices c WHERE
        c.customer_id=NEW.customer_id AND c.id=NEW.id) OR EXISTS
      (SELECT 1 FROM identity_incident_notices i WHERE
        i.customer_id=NEW.customer_id AND i.id=NEW.id)
    BEGIN SELECT RAISE(ABORT,'INCIDENT_NOTICE_ID_COLLISION'); END;
  CREATE TRIGGER IF NOT EXISTS identity_incident_notices_no_fraud_collision
    BEFORE INSERT ON identity_incident_notices WHEN EXISTS
      (SELECT 1 FROM fraud_incident_notices f WHERE
        f.customer_id=NEW.customer_id AND f.id=NEW.id)
    BEGIN SELECT RAISE(ABORT,'INCIDENT_NOTICE_ID_COLLISION'); END;
  CREATE TRIGGER IF NOT EXISTS incident_customer_notices_no_fraud_collision
    BEFORE INSERT ON incident_customer_notices WHEN EXISTS
      (SELECT 1 FROM fraud_incident_notices f WHERE
        f.customer_id=NEW.customer_id AND f.id=NEW.id)
    BEGIN SELECT RAISE(ABORT,'INCIDENT_NOTICE_ID_COLLISION'); END;`);
}

function nextNoticeId(db: DatabaseSync, customerId: string): number {
  const row = db.prepare(`SELECT MAX(id) id FROM (
    SELECT id FROM incident_customer_notices WHERE customer_id=?
    UNION ALL SELECT id FROM identity_incident_notices WHERE customer_id=?
    UNION ALL SELECT id FROM fraud_incident_notices WHERE customer_id=?
  )`).get(customerId, customerId, customerId) as { id: number | null };
  return (row.id ?? 0) + 1;
}

export function recordIssuerRecoveryNotice(bank: Bank, input: {
  incidentId: string; customerId: string; outageHistoryId: number;
  rejectionId: string; restoredHistoryId: number; authorizationId: string;
}): IncidentNotice {
  installIncidentNotices(bank.db);
  return bank.transaction(() => {
    const incident = bank.db.prepare(`SELECT area,entity_key FROM sentinel_incidents
      WHERE id=?`).get(input.incidentId) as
      { area: string; entity_key: string } | undefined;
    const evidence = bank.db.prepare(`SELECT r.card_id,c.customer_id,
      r.response_code,r.created_at,down.available down_available,
      down.id down_id,down.changed_at down_at,up.available up_available,
      up.id up_id,
      up.changed_at up_at,a.response_code auth_code,a.created_at auth_at
      FROM card_network_rejections r
      JOIN cards c ON c.id=r.card_id
      JOIN card_issuer_history down ON down.id=?
      JOIN card_issuer_history up ON up.id=?
      JOIN card_network_authorizations a ON a.id=?
      WHERE r.id=?`).get(input.outageHistoryId, input.restoredHistoryId,
        input.authorizationId, input.rejectionId) as {
      card_id: string; customer_id: string; response_code: string;
      created_at: string; down_available: number; down_id: number;
      down_at: string; up_available: number; up_id: number; up_at: string;
      auth_code: string; auth_at: string;
    } | undefined;
    const networkResponse = bank.db.prepare(`SELECT 1 FROM card_network_messages
      WHERE authorization_id=? AND mti='0110'
        AND created_at>=?
        AND json_extract(payload_json,'$.response_code')='00' LIMIT 1`)
      .get(input.authorizationId, evidence?.auth_at ?? "");
    if (!incident || incident.area !== "cards" ||
      incident.entity_key !== "card_issuer" || !evidence ||
      evidence.customer_id !== input.customerId ||
      evidence.response_code !== "91" || evidence.down_available !== 0 ||
      evidence.up_available !== 1 || evidence.up_id <= evidence.down_id ||
      evidence.down_at > evidence.created_at ||
      evidence.created_at >= evidence.up_at || evidence.up_at >= evidence.auth_at ||
      evidence.auth_code !== "00" || !networkResponse)
      throw new BankError("DEF_INCIDENT_NOTICE_EVIDENCE");
    const existing = bank.db.prepare(`SELECT id,kind,message_pt,created_at
      FROM incident_customer_notices WHERE incident_id=? AND outage_history_id=?
        AND customer_id=? AND kind='card_issuer_recovered'`).get(
          input.incidentId, input.outageHistoryId, input.customerId) as
      IncidentNotice | undefined;
    if (existing) return existing;
    const next = nextNoticeId(bank.db, input.customerId);
    const createdAt = bank.now().toISOString();
    bank.db.prepare(`INSERT INTO incident_customer_notices
      (customer_id,id,incident_id,outage_history_id,rejection_id,
        restored_history_id,authorization_id,kind,message_pt,created_at)
      VALUES (?,?,?,?,?,?,?,'card_issuer_recovered',?,?)`).run(
      input.customerId, next, input.incidentId, input.outageHistoryId,
        input.rejectionId, input.restoredHistoryId, input.authorizationId,
        recoveryMessage, createdAt);
    return { id: next, kind: "card_issuer_recovered",
      message_pt: recoveryMessage, created_at: createdAt };
  });
}

/** Resolve the empty account-list response of an explicitly imported lab record. */
export function readLabIdentityEmptyResponse(db: DatabaseSync, input: {
  customerId: string; sourceEventId: number; deviceId: string;
}): number | undefined {
  if (!db.prepare(`SELECT 1 FROM sqlite_master
    WHERE type='table' AND name='lab_identity_replays'`).get()) return;
  const rows = db.prepare(`SELECT e.id,e.message,e.outcome
    FROM lab_identity_replays p JOIN lab_revoked_device_receipts r
      ON r.run_id=p.run_id AND r.telemetry_event_id=p.telemetry_event_id
    JOIN telemetry_events s ON s.id=r.telemetry_event_id AND s.user_id=r.customer_id
      AND s.device_id=r.device_id AND s.source='auth' AND s.category='audit'
      AND s.action='access_revoked_device' AND s.outcome='success'
      AND s.message='Synthetic historical identity replay'
    JOIN auth_sessions a ON a.id=s.session_id AND a.device_id=s.device_id
      AND a.customer_id=s.user_id AND a.revoked_at IS NOT NULL
    JOIN telemetry_events e ON e.trace_id=s.trace_id AND e.session_id=s.session_id
      AND e.user_id=s.user_id AND e.device_id=s.device_id AND e.id>s.id
      AND e.source='gateway' AND e.category='request' AND e.action='request'
    WHERE r.telemetry_event_id=? AND r.customer_id=? AND r.device_id=?
      AND NOT EXISTS (SELECT 1 FROM accounts WHERE customer_id=r.customer_id)
    ORDER BY e.id LIMIT 2`).all(input.sourceEventId, input.customerId, input.deviceId) as
    { id: number; message: string; outcome: string }[];
  if (rows.length !== 1) return;
  const response = rows[0]!;
  const proof = parseGatewayRequestObservation(response.message, response.outcome);
  return proof?.method === "GET" && proof.routeTemplate === "/api/v1/accounts" &&
    proof.responseFields?.length === 0 ? response.id : undefined;
}

export function recordIdentityIncidentNotice(bank: Bank, input: {
  incidentId: string; customerId: string; alertId: string;
  sourceEventId: number; deviceId: string;
}): IncidentNotice {
  installIncidentNotices(bank.db);
  return bank.transaction(() => {
    const incident = bank.db.prepare(`SELECT area,entity_key FROM sentinel_incidents
      WHERE id=?`).get(input.incidentId) as
      { area: string; entity_key: string } | undefined;
    const alert = bank.db.prepare(`SELECT rule_id,entity,observed_json
      FROM sentinel_alerts WHERE id=?`).get(input.alertId) as
      { rule_id: string; entity: string; observed_json: string } | undefined;
    let observed: Record<string, unknown> = {};
    try { observed = JSON.parse(alert?.observed_json ?? "{}"); }
    catch { /* Invalid source evidence must fail closed. */ }
    const event = bank.db.prepare(`SELECT source,action,outcome,user_id,device_id,session_id,trace_id,twin_ts
      FROM telemetry_events WHERE id=?`).get(input.sourceEventId) as
      { source: string; action: string; outcome: string; user_id: string | null;
        device_id: string | null; session_id: string | null; trace_id: string;
        twin_ts: string } | undefined;
    const device = bank.db.prepare(`SELECT revoked_at FROM auth_devices
      WHERE id=? AND customer_id=?`).get(input.deviceId, input.customerId) as
      { revoked_at: string | null } | undefined;
    const live = bank.db.prepare(`SELECT 1 FROM auth_sessions WHERE customer_id=?
      AND device_id=? AND revoked_at IS NULL LIMIT 1`).get(
        input.customerId, input.deviceId);
    if (!incident || incident.area !== "auth" ||
      incident.entity_key !== input.customerId || !alert ||
      alert.rule_id !== "S-AUTH-08" || alert.entity !== input.customerId ||
      observed.source_event_id !== input.sourceEventId ||
      observed.device_id !== input.deviceId || !event ||
      event.source !== "auth" ||
      !["access_revoked_device", "refresh_revoked_device"].includes(event.action) ||
      event.outcome !== "success" || event.user_id !== input.customerId ||
      event.device_id !== input.deviceId || !device?.revoked_at || event.twin_ts < device.revoked_at || live)
      throw new BankError("DEF_INCIDENT_NOTICE_EVIDENCE");
    const existing = bank.db.prepare(`SELECT id,kind,message_pt,created_at
      FROM identity_incident_notices WHERE incident_id=? AND customer_id=?
        AND source_event_id=?`).get(input.incidentId, input.customerId,
          input.sourceEventId) as IncidentNotice | undefined;
    if (existing) return existing;
    const completions = event.session_id ? bank.db.prepare(`SELECT message,outcome FROM telemetry_events
      WHERE trace_id=? AND session_id=? AND user_id=? AND device_id=? AND id>? AND twin_ts>=?
        AND source='gateway' AND category='request' AND action='request'
      ORDER BY id LIMIT 5`).all(event.trace_id, event.session_id, input.customerId,
        input.deviceId, input.sourceEventId, device.revoked_at) as
          { message: string; outcome: string }[] : [];
    const categories = new Set(completions.flatMap((row) => {
      const proof = parseGatewayRequestObservation(row.message, row.outcome);
      if (!proof?.responseFields?.length) return [];
      const label = responseCategoryPt(proof.routeTemplate);
      return label ? [label] : [];
    }));
    const observedResponse = categories.size ?
      ` A resposta vinculada incluiu ${new Intl.ListFormat("pt-BR").format([...categories])}.` : "";
    const message = readLabIdentityEmptyResponse(bank.db, input) ?
      "Exercício de identidade. A consulta simulada retornou uma lista de contas vazia. O aparelho continua bloqueado e suas sessões foram encerradas." :
      identityMessage + observedResponse +
        " O alcance do incidente ainda está em apuração. Se não reconhecer uma operação, procure o atendimento do banco.";
    const id = nextNoticeId(bank.db, input.customerId);
    const createdAt = bank.now().toISOString();
    bank.db.prepare(`INSERT INTO identity_incident_notices
      (customer_id,id,incident_id,alert_id,source_event_id,device_id,
        kind,message_pt,created_at)
      VALUES (?,?,?,?,?,?,'revoked_device_access',?,?)`).run(
        input.customerId, id, input.incidentId, input.alertId,
        input.sourceEventId, input.deviceId, message, createdAt);
    return { id, kind: "revoked_device_access",
      message_pt: message, created_at: createdAt };
  });
}

export function recordSuspiciousPixNotice(bank: Bank, input: {
  incidentId: string; customerId: string; alertId: string; transferId: string;
}): IncidentNotice {
  installIncidentNotices(bank.db);
  return bank.transaction(() => {
    const incident = bank.db.prepare(`SELECT area,entity_key,opened_at,last_seen_at FROM sentinel_incidents
      WHERE id=?`).get(input.incidentId) as
      { area: string; entity_key: string; opened_at: string;
        last_seen_at: string } | undefined;
    const alert = bank.db.prepare(`SELECT rule_id,entity,observed_json,first_seen,last_seen
      FROM sentinel_alerts WHERE id=?`).get(input.alertId) as
      { rule_id: string; entity: string; observed_json: string;
        first_seen: string; last_seen: string } | undefined;
    const transfer = bank.db.prepare(`SELECT p.amount,p.status,p.from_account,
      p.ledger_tx_id,p.settled_at,a.customer_id FROM pix_transfers p
      JOIN accounts a ON a.id=p.from_account WHERE p.id=?`)
      .get(input.transferId) as { amount: number; status: string;
        from_account: string; ledger_tx_id: string | null;
        settled_at: string | null; customer_id: string } | undefined;
    let observed: Record<string, unknown> = {};
    try { observed = JSON.parse(alert?.observed_json ?? "{}"); }
    catch { /* Invalid source evidence must fail closed. */ }
    if (!incident || incident.area !== "pix" ||
      incident.entity_key !== input.customerId || !alert ||
      alert.rule_id !== "S-PIX-02" || !transfer ||
      alert.last_seen < incident.opened_at ||
      alert.first_seen > incident.last_seen_at ||
      alert.entity !== transfer.from_account ||
      transfer.customer_id !== input.customerId ||
      transfer.status !== "settled" || !transfer.ledger_tx_id ||
      !transfer.settled_at || transfer.settled_at > alert.first_seen ||
      observed.outbound_cents !== transfer.amount ||
      !bank.reconcile().ok)
      throw new BankError("DEF_INCIDENT_NOTICE_EVIDENCE");
    const existing = bank.db.prepare(`SELECT id,kind,message_pt,created_at
      FROM fraud_incident_notices WHERE incident_id=? AND customer_id=?
        AND transfer_id=?`).get(input.incidentId, input.customerId,
          input.transferId) as IncidentNotice | undefined;
    if (existing) return existing;
    const id = nextNoticeId(bank.db, input.customerId);
    const createdAt = bank.now().toISOString();
    const amount = new Intl.NumberFormat("pt-BR", { style: "currency",
      currency: "BRL" }).format(transfer.amount / 100);
    const message = `Detectamos um Pix de saída de ${amount} em uma sequência incomum. A transferência já tinha sido concluída quando o alerta surgiu. Corrigimos a retenção para novas operações; ainda apuramos se você autorizou esta transferência e se houve prejuízo. Se não reconhecer o Pix, abra uma contestação MED no extrato. A contestação inicia a análise e não garante estorno.`;
    bank.db.prepare(`INSERT INTO fraud_incident_notices
      (customer_id,id,incident_id,alert_id,transfer_id,kind,message_pt,created_at)
      VALUES (?,?,?,?,?,'suspicious_pix_review',?,?)`).run(
      input.customerId, id, input.incidentId, input.alertId,
      input.transferId, message, createdAt);
    return { id, kind: "suspicious_pix_review", message_pt: message,
      created_at: createdAt };
  });
}

export function listIncidentNotices(db: DatabaseSync, customerId: string,
  before?: number, limit = 20): { items: IncidentNotice[]; next_cursor: number | null } {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
    before !== undefined && (!Number.isSafeInteger(before) || before < 1))
    throw new BankError("BIZ_NOTICE_CURSOR_INVALID");
  if (before !== undefined && !db.prepare(`SELECT 1 FROM (
    SELECT id FROM incident_customer_notices WHERE customer_id=?
    UNION ALL SELECT id FROM identity_incident_notices WHERE customer_id=?
    UNION ALL SELECT id FROM fraud_incident_notices WHERE customer_id=?
  ) WHERE id=?`).get(customerId, customerId, customerId, before))
    throw new BankError("DEF_NOT_FOUND");
  const rows = db.prepare(`SELECT id,kind,message_pt,created_at FROM (
    SELECT id,kind,message_pt,created_at FROM incident_customer_notices
      WHERE customer_id=?
    UNION ALL
    SELECT id,kind,message_pt,created_at FROM identity_incident_notices
      WHERE customer_id=?
    UNION ALL
    SELECT id,kind,message_pt,created_at FROM fraud_incident_notices
      WHERE customer_id=?
  ) WHERE (? IS NULL OR id<?) ORDER BY id DESC LIMIT ?`)
    .all(customerId, customerId, customerId, before ?? null, before ?? null,
      limit + 1) as unknown as IncidentNotice[];
  return { items: rows.slice(0, limit),
    next_cursor: rows.length > limit ? rows[limit - 1]!.id : null };
}
