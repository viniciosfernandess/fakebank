import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { ensureSeparatedData } from "../apps/server/src/separated-bootstrap.ts";
import { buildLocalServer } from "../apps/server/src/main.ts";
import { syntheticCpf } from "../apps/world/src/bank.ts";

test("fresh server data is seeded into separate bank and ecosystem owners", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-separated-bootstrap-"));
  let server;
  try {
    server = await buildLocalServer(dir, resolve("apps/web/dist"), {
      repoRoot: process.cwd(), startBrtDate: "2026-11-17", onDemand: true,
      seed: { customers: 2, accounts: 2, historyTransactions: 0 },
      red: { async run() { return { missions: 0, attempts: 0,
        verifiedBreaches: 0, memoryAdded: 0, failures: [] }; } },
    });
    const bank = new DatabaseSync(join(dir, "bank.sqlite"), { readOnly: true });
    const ecosystem = new DatabaseSync(join(dir, "ecosystem.sqlite"), { readOnly: true });
    try {
      assert.equal(bank.prepare("SELECT COUNT(*) n FROM customers").get().n, 2);
      assert.equal(bank.prepare("SELECT 1 FROM sqlite_master WHERE name='psp_accounts'").get(), undefined);
      assert.equal(ecosystem.prepare("SELECT 1 FROM sqlite_master WHERE name='accounts'").get(), undefined);
      assert.ok(ecosystem.prepare("SELECT COUNT(*) n FROM psp_accounts").get().n > 0);
    } finally { bank.close(); ecosystem.close(); }
    ensureSeparatedData(dir, { customers: 3, accounts: 3, historyTransactions: 0 });
    assert.equal(server.campaign.runtime.bank.db.prepare("SELECT COUNT(*) n FROM customers").get().n, 2);
    assert.equal((await server.app.inject({ method: "GET", url: "/api/bank/operations" })).statusCode, 200);
  } finally {
    await server?.app.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("bank-only server keeps financial runtime without enabling agent rounds", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-bank-only-"));
  let server;
  try {
    server = await buildLocalServer(dir, resolve("apps/web/dist"), {
      repoRoot: process.cwd(), startBrtDate: "2026-11-18",
      onDemand: true, localCodex: false, campaignMode: "bank_only", bankOnly: true,
      publicOrigin: "https://bank.example.test",
      seed: { customers: 3, accounts: 3, historyTransactions: 0 },
      red: { async run() { return { missions: 0, attempts: 0,
        verifiedBreaches: 0, memoryAdded: 0, failures: [] }; } },
    });
    server.campaign.runtime.start();
    const health = await server.app.inject({ method: "GET", url: "/healthz" });
    assert.equal(health.statusCode, 200);
    const status = await server.app.inject({ method: "GET", url: "/api/status" });
    assert.equal(status.statusCode, 200);
    assert.equal(status.json().campaign_mode, "bank_only");
    assert.equal(status.json().round_mode, "none");
    assert.equal((await server.app.inject({ method: "POST",
      url: "/api/rounds/start" })).statusCode, 404);
    const remote = "10.0.1.7";
    assert.equal((await server.app.inject({ method: "GET",
      url: "/api/client/tariffs", remoteAddress: remote })).statusCode, 200);
    const signup = { cpf: syntheticCpf(90_001), name: "Remote Bank Customer",
      persona: "salaried", password: "synthetic-password-123" };
    const request = { method: "POST", url: "/api/client/onboarding/apply",
      remoteAddress: remote, headers: { host: "bank.example.test",
        origin: "https://bank.example.test", "sec-fetch-site": "same-origin",
        "x-forwarded-proto": "https", "x-real-ip": "198.51.100.10" },
      payload: signup };
    assert.equal((await server.app.inject({ ...request,
      headers: { ...request.headers, origin: "https://other.example.test" } })).statusCode, 403);
    const accepted = await server.app.inject(request);
    assert.equal(accepted.statusCode, 200, accepted.body);
    for (let index = 0; index < 2; index++) {
      const next = await server.app.inject({ ...request,
        payload: { ...signup, cpf: syntheticCpf(90_002 + index) } });
      assert.equal(next.statusCode, 200, next.body);
    }
    const limited = await server.app.inject({ ...request,
      payload: { ...signup, cpf: syntheticCpf(90_004) } });
    assert.equal(limited.statusCode, 429);
    const otherCustomer = await server.app.inject({ ...request,
      headers: { ...request.headers, "x-real-ip": "198.51.100.11" },
      payload: { ...signup, cpf: syntheticCpf(90_005) } });
    assert.equal(otherCustomer.statusCode, 200, otherCustomer.body);
    for (let index = 0; index < 3; index++) {
      const direct = await server.app.inject({ ...request,
        remoteAddress: "203.0.113.7",
        headers: { ...request.headers, "x-real-ip": `198.51.100.${20 + index}` },
        payload: { ...signup, cpf: syntheticCpf(90_006 + index) } });
      assert.equal(direct.statusCode, 200, direct.body);
    }
    const spoofed = await server.app.inject({ ...request,
      remoteAddress: "203.0.113.7",
      headers: { ...request.headers, "x-real-ip": "198.51.100.99" },
      payload: { ...signup, cpf: syntheticCpf(90_009) } });
    assert.equal(spoofed.statusCode, 429);
    assert.equal((await server.app.inject({ method: "GET",
      url: "/api/operator/bank/operations", remoteAddress: remote })).statusCode, 404);
    assert.equal((await server.app.inject({ method: "POST", url: "/api/operator/login",
      remoteAddress: "127.0.0.1", headers: request.headers,
      payload: { id: "admin", password: "synthetic-password-123" } })).statusCode, 404);
    assert.equal(server.campaign.runtime.bank.reconcile().ok, true);
  } finally { await server?.app.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("separated bootstrap preserves an existing combined or incomplete data directory", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-separated-legacy-"));
  try {
    const bankPath = join(dir, "bank.sqlite");
    writeFileSync(bankPath, "existing bank data");
    const before = readFileSync(bankPath);
    assert.throws(() => ensureSeparatedData(dir), /SEPARATED_DATA_INCOMPLETE/);
    assert.deepEqual(readFileSync(bankPath), before);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
