import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { Gateway, gatewayRouteTemplate } from "../apps/world/src/gateway.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { seedCustomerId } from "../apps/world/src/id.ts";
import { AccountService } from "../apps/world/src/accounts.ts";
import { CardsEngine } from "../apps/world/src/cards.ts";
import { verifyTelemetryChain } from "../apps/world/src/telemetry-integrity.ts";
import { decodeResponseFieldEvidence, encodeResponseFieldEvidence,
  hasUnresolvedNestedFields, parseGatewayRequestObservation } from
  "../apps/world/src/response-field-evidence.ts";

test("gateway route templates have bounded labels without customer identifiers", () => {
  assert.equal(gatewayRouteTemplate("/api/v1/accounts/acc_private/statement"),
    "/api/v1/accounts/:id/statement");
  assert.equal(gatewayRouteTemplate("/api/v1/pix/keys/lookup"), "/api/v1/pix/keys/lookup");
  assert.equal(gatewayRouteTemplate("/api/v1/cards/card_private/cvv"), "/api/v1/cards/:id/cvv");
  for (const route of ["/api/v1/incidents/notices", "/api/v1/pix/limits/night"])
    assert.equal(gatewayRouteTemplate(route), route);
  assert.equal(gatewayRouteTemplate("/api/v1/pix/automatic/mandates/private/migrate"),
    "/api/v1/pix/automatic/mandates/:id/migrate");
  assert.equal(gatewayRouteTemplate("/api/v1/internal/ping"), "/api/v1/internal/ping");
  assert.equal(gatewayRouteTemplate("/api/v0/accounts/secret"), "/api/v0/:path");
  assert.equal(gatewayRouteTemplate("/api/v1/no-such-route/secret"), "/api/v1/:unmatched");
  assert.equal(gatewayRouteTemplate("/other/secret"), "/unmatched");
});

test("gateway telemetry uses a stable action and a sanitized route template", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-gateway-telemetry-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-11T12:00:00.000Z"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const api = createTwinApi(bank);
  try {
    const gateway = new Gateway(bank, api);
    await gateway.call({ method: "GET", path: "/api/v1/accounts/acc_private/statement",
      peerIp: "10.0.0.1" });
    const events = bank.telemetry.list().filter((event) => event.source === "gateway");
    assert.equal(events.length, 1);
    assert.equal(events[0].action, "request");
    assert.equal(events[0].message, "Gateway GET /api/v1/accounts/:id/statement completed");
    assert.equal(JSON.stringify(events).includes("acc_private"), false);
  } finally {
    await api.close(); bank.close(); rmSync(dir, { recursive: true, force: true });
  }
});

test("a normal authenticated gateway response preserves its scoped session attribution", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-gateway-attribution-"));
  const bank = new Bank(join(dir, "bank.sqlite"));
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const customer = bank.customer(seedCustomerId(1));
  const auth = new AuthEngine(bank);
  const password = "synthetic-session-trace-password";
  const peerIp = "127.0.0.1";
  const api = createTwinApi(bank, auth);
  try {
    const email = "receipt-test@example.test";
    const phone = "+5511987654321";
    auth.setPassword(customer.id, password);
    const login = auth.beginLogin(customer.cpf, password, peerIp, "trace-test-device");
    const session = auth.verifyOtp(login.challenge_id,
      auth.simulatedOtp(login.challenge_id, customer.id), peerIp);
    const gateway = new Gateway(bank, api);
    const path = "/api/v1/customers/me";
    const request = { method: "GET", path, peerIp,
      headers: { authorization: `Bearer ${session.access_token}` } };
    const completion = (requestId) => bank.telemetry.trace(requestId).find((event) =>
      event.source === "gateway" && event.category === "request" && event.action === "request");
    const empty = await gateway.call(request);
    assert.deepEqual(empty.body, { email: null, phone: null });
    assert.equal(completion(empty.request_id).message,
      "Gateway GET /api/v1/customers/me completed fields=none");
    new AccountService(bank).updateContact(customer.id, { email, phone });
    const response = await gateway.call(request);
    assert.equal(response.status, 200);
    const record = completion(response.request_id);
    assert.ok(record);
    assert.equal(record.user_id, customer.id);
    assert.equal(record.session_id, bank.db.prepare("SELECT id FROM auth_sessions WHERE customer_id=?")
      .get(customer.id).id);
    assert.ok(record.device_id);
    assert.deepEqual(response.body, { email, phone });
    assert.equal(record.message, "Gateway GET /api/v1/customers/me completed fields=email,phone");
    for (const value of [session.access_token, customer.cpf, email, phone])
      assert.equal(JSON.stringify(record).includes(value), false);
    const denied = await gateway.call({ method: "GET", path, peerIp });
    assert.equal(denied.status, 403);
    assert.equal(completion(denied.request_id).message, "Gateway GET /api/v1/customers/me completed");
    const kyc = await gateway.call({ ...request, path: "/api/v1/kyc/status" });
    assert.equal(kyc.status, 200);
    assert.equal(completion(kyc.request_id).message, "Gateway GET /api/v1/kyc/status completed fields=tier,status");
    const loan = await gateway.call({ ...request, path: "/api/v1/loans/offers" });
    assert.equal(loan.status, 200);
    const loanRecord = completion(loan.request_id);
    assert.deepEqual(parseGatewayRequestObservation(loanRecord.message, loanRecord.outcome)
      .responseFields, ["id", "customer_id", "max_amount_cents", "rate_bps_month", "expires_at"]);
    assert.equal(loanRecord.message.includes(loan.body.id), false);
    const accountId = bank.db.prepare(`SELECT id FROM accounts WHERE customer_id=?
      AND kind='checking' ORDER BY id LIMIT 1`).get(customer.id).id;
    const account = await gateway.call({ ...request, path: `/api/v1/accounts/${accountId}` });
    assert.equal(account.status, 200);
    const accountRecord = completion(account.request_id);
    const fields = Object.keys(account.body).filter((key) => account.body[key] !== null);
    assert.equal(accountRecord.message,
      `Gateway GET /api/v1/accounts/:id completed fields=${fields.join(",")}`);
    assert.equal(JSON.stringify(accountRecord).includes(accountId), false);
    assert.deepEqual(decodeResponseFieldEvidence("GET", "/api/v1/accounts/:id", "success",
      fields.join(",")), fields);
    for (const invalid of ["status", "tier,status,status", "tier,status,email", "none"])
      assert.equal(decodeResponseFieldEvidence("GET", "/api/v1/kyc/status", "success", invalid), null);
    assert.equal(encodeResponseFieldEvidence("GET", "/api/v1/kyc/status", 200,
      { ...kyc.body, unexpected: "synthetic private value" }), undefined);
    assert.equal(encodeResponseFieldEvidence("GET", "/api/v1/kyc/status", 200,
      { ...kyc.body, tier: "unexpected type" }), undefined);
    const statementPath = `/api/v1/accounts/${accountId}/statement`;
    const statementRoute = "/api/v1/accounts/:id/statement";
    const emptyStatement = await gateway.call({ ...request, path: statementPath +
      "?from=2020-01-01T00:00:00.000Z&to=2020-01-01T00:00:01.000Z" });
    assert.equal(emptyStatement.status, 200);
    assert.deepEqual(emptyStatement.body, []);
    assert.equal(completion(emptyStatement.request_id).message,
      `Gateway GET ${statementRoute} completed fields=none`);
    assert.deepEqual(decodeResponseFieldEvidence("GET", statementRoute, "success", "none"), []);
    const fundedTx = bank.fund(accountId, 2_371);
    const statement = await gateway.call({ ...request, path: statementPath });
    assert.equal(statement.status, 200);
    const fundedRow = statement.body.find((row) => row.tx_id === fundedTx);
    assert.ok(fundedRow);
    const statementRecord = completion(statement.request_id);
    assert.equal(statementRecord.message,
      `Gateway GET ${statementRoute} completed fields=tx_id,amount,kind,created_at`);
    assert.equal(JSON.stringify(statementRecord).includes(fundedTx), false);
    assert.equal(statementRecord.message.includes(String(fundedRow.amount)), false);
    assert.deepEqual(decodeResponseFieldEvidence("GET", statementRoute, "success",
      "tx_id,amount,kind,created_at"), ["tx_id", "amount", "kind", "created_at"]);
    assert.equal(encodeResponseFieldEvidence("GET", statementRoute, 200,
      [fundedRow, { ...fundedRow, unexpected: "synthetic private value" }]), undefined);
    assert.equal(decodeResponseFieldEvidence("GET", statementRoute, "success", "tx_id"), null);
    const recipient = bank.db.prepare(`SELECT id FROM accounts WHERE customer_id=?
      AND kind='checking' ORDER BY id LIMIT 1`).get(seedCustomerId(2)).id;
    const pix = bank.transferPix({ from: accountId, to: recipient, amount: 197,
      actor: customer.id, idempotencyKey: "receipt-coverage-own-pix" });
    assert.equal(pix.status, "settled");
    const card = new CardsEngine(bank).issueDebit(customer.id, accountId);
    for (const [route, expectedField, privateValues] of [
      ["/api/v1/accounts", "balance_cached", [accountId]],
      ["/api/v1/devices", "first_seen_at", [record.device_id]],
      ["/api/v1/pix/transfers", "from_account", [accountId, recipient]],
      ["/api/v1/cards", "last4", [card.id, card.last4, accountId]],
    ]) {
      const result = await gateway.call({ ...request, path: route });
      assert.equal(result.status, 200);
      assert.ok(result.body.length > 0);
      const observed = completion(result.request_id);
      const fields = observed.message.split("fields=")[1];
      const included = decodeResponseFieldEvidence("GET", route, observed.outcome, fields);
      assert.ok(included.includes(expectedField), observed.message);
      assert.deepEqual(parseGatewayRequestObservation(observed.message, observed.outcome)
        .responseFields, included);
      for (const value of privateValues) assert.equal(observed.message.includes(value), false);
    }
    assert.deepEqual(decodeResponseFieldEvidence("GET", "/api/v1/pix/transfers", "success", "none"), []);
    assert.equal(encodeResponseFieldEvidence("GET", "/api/v1/devices", 200, {}), undefined);
    const pixDetail = await gateway.call({ ...request, path: `/api/v1/pix/transfers/${pix.id}` });
    assert.equal(pixDetail.status, 200);
    const pixDetailRecord = completion(pixDetail.request_id);
    const pixDetailFields = decodeResponseFieldEvidence("GET", "/api/v1/pix/transfers/:id",
      pixDetailRecord.outcome, pixDetailRecord.message.split("fields=")[1]);
    assert.ok(pixDetailFields.includes("status_history"));
    assert.ok(pixDetailFields.includes("status_history.status"));
    assert.ok(pixDetailFields.includes("status_history.changed_at"));
    assert.equal(pixDetailFields.includes("returns"), false);
    assert.equal(pixDetailRecord.message.includes(pix.id), false);
    assert.equal(pixDetailRecord.message.includes(pix.end_to_end_id), false);
    const pixRoute = "/api/v1/pix/transfers/:id";
    assert.deepEqual(parseGatewayRequestObservation(pixDetailRecord.message,
      pixDetailRecord.outcome).responseFields, pixDetailFields);
    assert.equal(hasUnresolvedNestedFields(pixRoute, pixDetailFields), false);
    const legacy = pixDetailFields.filter((field) => !field.includes(".")).join(",");
    assert.equal(hasUnresolvedNestedFields(pixRoute,
      decodeResponseFieldEvidence("GET", pixRoute, "success", legacy)), true);
    const unknownChild = encodeResponseFieldEvidence("GET", pixRoute, 200, {
      ...pixDetail.body, status_history: [{ ...pixDetail.body.status_history[0],
        private_extension: "sensitive test value" }],
    });
    const incomplete = decodeResponseFieldEvidence("GET", pixRoute, "success", unknownChild);
    assert.equal(hasUnresolvedNestedFields(pixRoute, incomplete), true);
    assert.doesNotMatch(unknownChild, /private_extension|sensitive test value/);
    assert.equal(decodeResponseFieldEvidence("GET", pixRoute, "success",
      legacy.replace("status_history", "status_history,status_history.status")), null);
    assert.equal(decodeResponseFieldEvidence("GET", "__proto__", "success", "none"), null);
    const external = bank.transferPix({ from: accountId, to: "psp_ipe_ana", amount: 237,
      actor: customer.id, idempotencyKey: "receipt-coverage-external-pix" });
    assert.equal(external.status, "settled");
    const refund = bank.returnExternalPix(external.id, 101, "receipt-coverage-external-return");
    const externalDetail = await gateway.call({ ...request,
      path: `/api/v1/pix/transfers/${external.id}` });
    assert.equal(externalDetail.status, 200);
    const externalRecord = completion(externalDetail.request_id);
    const externalFields = parseGatewayRequestObservation(externalRecord.message,
      externalRecord.outcome).responseFields;
    for (const field of ["spi_messages.amount_cents", "spi_messages.return_id",
      "returns.id", "returns.amount", "returns.created_at"])
      assert.ok(externalFields.includes(field), externalRecord.message);
    assert.equal(hasUnresolvedNestedFields(pixRoute, externalFields), false);
    for (const value of [external.id, external.end_to_end_id, refund.id, "psp_ipe_ana"])
      assert.equal(externalRecord.message.includes(value), false);
    assert.equal(verifyTelemetryChain(bank.db), true);
  } finally {
    await api.close(); bank.close(); rmSync(dir, { recursive: true, force: true });
  }
});
