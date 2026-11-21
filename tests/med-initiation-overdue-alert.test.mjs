import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank } from "../apps/world/src/bank.ts";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { EventStore } from "../packages/event-store/src/index.ts";
import { reviewMedForTest } from "./med-review-helper.mjs";

test("MED payer initiation breach alerts once and retries a private event", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-initiation-alert-"));
  let now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  const events = new EventStore(join(dir, "events.sqlite"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const from = seedAccountId(1);
    const early = bank.transferPix({ from, to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-alert-early", actor: customer });
    const late = bank.transferPix({ from, to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-alert-late", actor: customer });
    const internal = bank.transferPix({ from, to: seedAccountId(2), amount: 1_000,
      idempotencyKey: "med-alert-internal", actor: customer });
    const earlyCase = bank.requestMed(customer, early.id);
    const lateCase = bank.requestMed(customer, late.id);
    const internalCase = bank.requestMed(customer, internal.id);
    for (const [caseId, transferId] of [[earlyCase.id, early.id],
      [lateCase.id, late.id], [internalCase.id, internal.id]])
      reviewMedForTest(bank, caseId, transferId);
    bank.resolveMed(earlyCase.id);
    let sentinel = new SentinelEngine(bank, events);
    const alerts = () => sentinel.scan().filter((alert) => alert.rule_id === "S-PIX-39");
    now = new Date(now.getTime() + 72 * 3_600_000);
    assert.deepEqual(alerts(), []);
    now = new Date(now.getTime() + 1);
    const append = events.append.bind(events);
    events.append = (...args) => {
      if (args[0].public?.rule_id === "S-PIX-39")
        throw new Error("event store unavailable");
      return append(...args);
    };
    const first = alerts();
    assert.equal(first.length, 1);
    assert.equal(first[0].entity, lateCase.id);
    assert.equal(first[0].severity, "medium");
    assert.equal(first[0].observed.initiation_state, "overdue");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM sentinel_med_initiation_outbox
      WHERE case_id=? AND published_at IS NULL`).get(lateCase.id).n, 1);
    events.append = append;
    sentinel = new SentinelEngine(bank, events);
    assert.deepEqual(alerts(), []);
    assert.equal(events.list({ types: ["sentinel.alert"] })
      .filter((event) => event.public.rule_id === "S-PIX-39").length, 1);
    assert.equal(JSON.stringify(events.listPublic({ types: ["sentinel.alert"] }))
      .includes(lateCase.id), false);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM sentinel_med_initiation_outbox
      WHERE case_id=? AND published_at IS NOT NULL`).get(lateCase.id).n, 1);
    bank.resolveMed(lateCase.id);
    assert.equal(bank.medInitiationSla().find((row) => row.case_id === lateCase.id).state,
      "late");
    assert.deepEqual(alerts(), []);
    assert.equal(sentinel.recentAlerts().filter((alert) =>
      alert.rule_id === "S-PIX-39").length, 1);
    assert.equal(bank.reconcile().ok, true);
  } finally { events.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
