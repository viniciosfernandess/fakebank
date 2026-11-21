import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildServer } from "../apps/server/src/main.ts";
import { OperatorAuth } from "../apps/world/src/operator-auth.ts";

test("SOC triage is operator-only and acknowledgment requires a local authenticated origin", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-soc-triage-api-"));
  const { app, campaign } = buildServer(dir, resolve("apps/web/dist"), {
    startBrtDate: "2026-11-16", repoRoot: process.cwd(),
    transport: { async send() { assert.fail("no agent is due"); } },
    seed: { customers: 2, accounts: 2, historyTransactions: 0 },
  });
  try {
    const bank = campaign.runtime.bank;
    new OperatorAuth(bank).bootstrap("soc_admin", "local-soc-triage-password");
    bank.telemetry.emit({ source: "gateway", category: "test", action: "dlp",
      outcome: "failure", message: "PAN=4111111111111111" });
    campaign.runtime.sentinels.scan();
    const publicList = await app.inject({ method: "GET", url: "/api/soc/alerts" });
    const publicAlert = publicList.json().alerts.find((item) => item.rule_id === "S-GW-05");
    assert.equal(publicAlert?.triage, undefined);
    assert.equal((await app.inject({ method: "GET", url: "/api/operator/soc/alerts" }))
      .statusCode, 401);
    const login = await app.inject({ method: "POST", url: "/api/operator/login",
      headers: { host: "127.0.0.1:3000", origin: "http://127.0.0.1:3000" },
      payload: { id: "soc_admin", password: "local-soc-triage-password" } });
    assert.equal(login.statusCode, 200);
    const cookie = login.headers["set-cookie"].split(";")[0];
    const operatorList = await app.inject({ method: "GET", url: "/api/operator/soc/alerts",
      headers: { cookie } });
    const alert = operatorList.json().alerts.find((item) => item.rule_id === "S-GW-05");
    assert.equal(alert?.triage.owner_role, "platform_oncall");
    assert.equal(alert?.triage.status, "pending");
    assert.equal(alert?.triage.sla_seconds, 300);
    const url = `/api/operator/soc/alerts/${alert.alert_id}/acknowledge`;
    const forged = await app.inject({ method: "POST", url,
      headers: { cookie, host: "127.0.0.1:3000", origin: "http://other.local" } });
    assert.equal(forged.statusCode, 403);
    const headers = { cookie, host: "127.0.0.1:3000", origin: "http://127.0.0.1:3000" };
    const acknowledged = await app.inject({ method: "POST", url, headers });
    assert.equal(acknowledged.statusCode, 200);
    assert.equal(acknowledged.json().status, "acknowledged");
    assert.equal(acknowledged.json().acknowledged_by, "soc_admin");
    assert.equal((await app.inject({ method: "POST", url, headers })).json().status,
      "acknowledged");
    assert.equal(publicList.body.includes("soc_admin"), false);
  } finally { await app.close(); rmSync(dir, { recursive: true, force: true }); }
});
