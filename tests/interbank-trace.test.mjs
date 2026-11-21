import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { Gateway } from "../apps/world/src/gateway.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { bindDeviceKey, signedOperationHeaders } from "./device-proof-helper.mjs";

test("one external Pix trace links gateway, risk, SPI, ledger, and settlement", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-interbank-trace-"));
  let realNow = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-13T12:00:00Z"),
    () => realNow);
  let api;
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const auth = new AuthEngine(bank);
    const customer = seedCustomerId(1);
    auth.setPassword(customer, "local-trace-test-password");
    const challenge = auth.beginLogin(bank.customer(customer).cpf,
      "local-trace-test-password", "127.0.0.1", "trace-device");
    const session = auth.verifyOtp(challenge.challenge_id,
      auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
    api = createTwinApi(bank, auth);
    auth.stepUp(session.access_token, "local-trace-test-password");
    const deviceHeaders = { authorization: `Bearer ${session.access_token}` };
    const privateKey = await bindDeviceKey(api, deviceHeaders);
    const gateway = new Gateway(bank, api);
    const payment = { from_account: seedAccountId(1), to_account: "psp_ipe_ana",
      amount_cents: 100, idempotency_key: "interbank-trace" };
    const response = await gateway.call({ method: "POST", path: "/api/v1/pix/transfers",
      peerIp: "127.0.0.1", headers: {
        ...await signedOperationHeaders(api, deviceHeaders, privateKey,
          "/pix/transfers", payment), "user-agent": "SyntheticBankClient/1.0" },
      body: payment });
    assert.equal(response.status, 202);
    assert.equal(response.body.status, "in_processing");
    assert.equal(bank.spi.messages(response.body.end_to_end_id).length, 0);
    assert.equal(bank.db.prepare(`SELECT trace_id FROM pix_spi_outbox
      WHERE transfer_id=?`).get(response.body.id).trace_id, response.request_id);
    realNow = new Date(bank.db.prepare(`SELECT eligible_at_real FROM pix_spi_outbox
      WHERE transfer_id=?`).get(response.body.id).eligible_at_real);
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 1, deferred: 0 });
    assert.equal(bank.db.prepare("SELECT status FROM pix_transfers WHERE id=?")
      .get(response.body.id).status, "settled");
    const trace = bank.telemetry.trace(response.request_id);
    assert.deepEqual(new Set(trace.map((entry) => entry.source)),
      new Set(["risk", "spi", "ledger", "pix", "gateway"]));
    assert.deepEqual(trace.filter((entry) => entry.source === "spi")
      .map((entry) => [entry.action, entry.outcome, entry.e2e_id]), [
      ["pacs.008", "success", response.body.end_to_end_id],
      ["pacs.002", "success", response.body.end_to_end_id],
    ]);
    assert.ok(trace.every((entry) => entry.trace_id === response.request_id));
    assert.deepEqual(bank.spi.messages(response.body.end_to_end_id)
      .map((message) => message.type), ["pacs.008", "pacs.002"]);
    assert.equal(bank.reconcile().ok, true);
  } finally { await api?.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
