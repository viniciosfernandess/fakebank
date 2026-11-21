import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bank, BankError } from "../apps/world/src/bank.ts";
import { moneyFlowMedState } from "../apps/orchestrator/src/money-flow-disclosure.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { reviewMedForTest } from "./med-review-helper.mjs";
import { SentinelEngine } from "../apps/world/src/sentinels.ts";

const DAY = 86_400_000;

function reviewer(bank) {
  return (caseId, transferId, decision = "approved") =>
    reviewMedForTest(bank, caseId, transferId, decision);
}

test("MED opening accepts the eightieth day and rejects the next millisecond", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-opening-window-"));
  let now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const from = seedAccountId(1), to = seedAccountId(2);
    const inside = bank.transferPix({ from, to, amount: 1_000,
      idempotencyKey: "med-opening-inside", actor: customer });
    const outside = bank.transferPix({ from, to, amount: 1_000,
      idempotencyKey: "med-opening-outside", actor: customer });
    now = new Date(now.getTime() + 80 * DAY);
    assert.equal(bank.requestMed(customer, inside.id).status, "open");
    now = new Date(now.getTime() + 1);
    assert.throws(() => bank.requestMed(customer, outside.id), (error) =>
      error instanceof BankError && error.code === "BIZ_MED_EXPIRED");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM med_cases
      WHERE transfer_id=?`).get(outside.id).n, 0);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("MED opening rejects an invalid or future transfer timestamp", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-opening-time-"));
  const now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const from = seedAccountId(1), to = seedAccountId(2);
    for (const [index, timestamp] of ["invalid",
      new Date(now.getTime() + 1).toISOString()].entries()) {
      const payment = bank.transferPix({ from, to, amount: 1_000,
        idempotencyKey: `med-invalid-time-${index}`, actor: customer });
      bank.db.prepare("UPDATE pix_transfers SET initiated_at=? WHERE id=?")
        .run(timestamp, payment.id);
      assert.throws(() => bank.requestMed(customer, payment.id), (error) =>
        error instanceof BankError && error.code === "BIZ_MED_EXPIRED");
      assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM med_cases
        WHERE transfer_id=?`).get(payment.id).n, 0);
    }
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("repeated MED resolutions alert on the third case for one source account", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-resolution-coverage-"));
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-11T12:00:00.000Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    const customer = seedCustomerId(1);
    const sentinel = new SentinelEngine(bank);
    for (let index = 0; index < 2; index++) {
      const payment = bank.transferPix({ from, to: "psp_ipe_ana", amount: 1_000,
        idempotencyKey: `med-coverage-${index}`, actor: customer });
      const med = bank.requestMed(customer, payment.id);
      reviewMedForTest(bank, med.id, payment.id);
      bank.resolveMed(med.id);
    }
    assert.equal(sentinel.scan().some((alert) => alert.rule_id === "S-PIX-35"), false);
    const third = bank.transferPix({ from, to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-coverage-2", actor: customer });
    const med = bank.requestMed(customer, third.id);
    reviewMedForTest(bank, med.id, third.id);
    bank.resolveMed(med.id);
    const alert = sentinel.scan().find((item) => item.rule_id === "S-PIX-35");
    assert.equal(alert?.entity, from);
    assert.equal(alert?.observed.med_resolutions, 3);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM telemetry_events
      WHERE source='pix' AND action='med_resolve' AND account_id=?`)
      .get(from).n, 3);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("MED has a seven-day review deadline and an approved case can resolve early", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-timing-"));
  let now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const from = seedAccountId(1);
    const internal = bank.transferPix({ from, to: seedAccountId(2), amount: 1_000,
      idempotencyKey: "med-internal-window", actor: customer });
    const external = bank.transferPix({ from, to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-external-window", actor: customer });
    const internalCase = bank.requestMed(customer, internal.id);
    const externalCase = bank.requestMed(customer, external.id);
    const decide = reviewer(bank);
    const expected = new Date(now.getTime() + 7 * DAY).toISOString();
    for (const item of [internalCase, externalCase]) {
      const row = bank.db.prepare(`SELECT resolve_after,timing_policy_version FROM med_cases
        WHERE id=?`).get(item.id);
      assert.equal(row.resolve_after, expected);
      assert.equal(row.timing_policy_version, 2);
      assert.throws(() => bank.resolveMed(item.id), (error) =>
        error instanceof BankError && error.code === "DEF_MED_DECISION_REQUIRED");
    }
    decide(internalCase.id, internal.id);
    assert.equal(bank.resolveMed(internalCase.id).refunded_cents, 1_000);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM med_replay_outbox
      WHERE case_id=? AND published_at IS NULL`).get(internalCase.id).n, 1);
    now = new Date(Date.parse(expected) - 1);
    assert.equal(bank.resolvePendingMed(), 0);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM med_refunds").get().n, 1);
    now = new Date(expected);
    assert.equal(bank.resolvePendingMed(), 0);
    assert.equal(bank.db.prepare("SELECT status FROM med_cases WHERE id=?")
      .get(externalCase.id).status, "open");
    decide(externalCase.id, external.id);
    assert.equal(bank.resolvePendingMed(), 1);
    assert.equal(bank.resolvePendingMed(), 0);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM med_replay_outbox
      WHERE case_id=? AND published_at IS NULL`).get(externalCase.id).n, 1);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM med_replay_outbox")
      .get().n, 2);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("MED settlement worker initiates an approved recovery before the review deadline", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-early-settlement-"));
  let now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const payment = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-early-worker", actor: customer });
    const med = bank.requestMed(customer, payment.id);
    assert.equal(bank.resolvePendingMed(), 0);
    reviewMedForTest(bank, med.id, payment.id);
    now = new Date(now.getTime() + 60_000);
    assert.equal(bank.resolvePendingMed(), 1);
    assert.equal(bank.resolvePendingMed(), 0);
    assert.equal(bank.db.prepare("SELECT status FROM med_cases WHERE id=?")
      .get(med.id).status, "resolved");
    assert.deepEqual(bank.medInitiationSla().map(({ case_id, state }) =>
      ({ case_id, state })), [{ case_id: med.id, state: "on_time" }]);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("MED records a payer initiation breach without denying a late recovery", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-initiation-sla-"));
  let now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const payment = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-initiation-late", actor: customer });
    const med = bank.requestMed(customer, payment.id);
    reviewMedForTest(bank, med.id, payment.id);
    const deadline = new Date(now.getTime() + 72 * 3_600_000);
    assert.deepEqual(bank.medInitiationSla().map(({ state, deadline_at }) =>
      ({ state, deadline_at })), [{ state: "pending", deadline_at: deadline.toISOString() }]);
    now = deadline;
    assert.equal(bank.medInitiationSla()[0].state, "pending");
    now = new Date(deadline.getTime() + 1);
    assert.equal(bank.medInitiationSla()[0].state, "overdue");
    assert.equal(bank.resolveMed(med.id).refunded_cents, 1_000);
    assert.equal(bank.medInitiationSla()[0].state, "late");
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("MED does not invent an initiation time for a historical resolved case", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-legacy-initiation-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-11T12:00:00.000Z");
  let bank = new Bank(path, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const payment = bank.transferPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "med-legacy-initiation", actor: customer });
    const med = bank.requestMed(customer, payment.id);
    reviewMedForTest(bank, med.id, payment.id);
    bank.resolveMed(med.id);
    bank.db.exec("ALTER TABLE med_cases DROP COLUMN recovery_initiated_at");
    bank.close();
    now = new Date(now.getTime() + 4 * DAY);
    bank = new Bank(path, () => now);
    assert.equal(bank.medInitiationSla()[0].state, "unknown");
    assert.equal(bank.medInitiationSla()[0].initiated_at, null);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("approved external MED recovers funds before the review deadline", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-early-external-"));
  const now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const transfer = bank.transferPix({ from: seedAccountId(1), to: "psp_ipe_ana",
      amount: 1_000, idempotencyKey: "med-early-external", actor: customer });
    const med = bank.requestMed(customer, transfer.id);
    const due = bank.db.prepare("SELECT resolve_after FROM med_cases WHERE id=?")
      .get(med.id).resolve_after;
    assert.equal(due, new Date(now.getTime() + 7 * DAY).toISOString());
    const decide = reviewer(bank);
    decide(med.id, transfer.id);
    assert.equal(bank.resolvePendingMed(), 1);
    assert.equal(bank.resolveMed(med.id).refunded_cents, 1_000);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("legacy open MED cases with short windows migrate conservatively once", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-legacy-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-11T12:00:00.000Z");
  let bank = new Bank(path, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const transfer = bank.transferPix({ from: seedAccountId(1), to: seedAccountId(2),
      amount: 1_000, idempotencyKey: "med-legacy-window", actor: customer });
    const med = bank.requestMed(customer, transfer.id);
    const decide = reviewer(bank);
    decide(med.id, transfer.id);
    bank.db.prepare("UPDATE med_cases SET resolve_after=?,timing_policy_version=1 WHERE id=?")
      .run(new Date(now.getTime() + 7 * 60_000).toISOString(), med.id);
    bank.db.exec("ALTER TABLE med_cases DROP COLUMN timing_policy_version");
    bank.close();
    now = new Date(now.getTime() + 3 * DAY);
    bank = new Bank(path, () => now);
    const expected = new Date(now.getTime() + 4 * DAY).toISOString();
    const migrated = bank.db.prepare(`SELECT resolve_after,timing_policy_version FROM med_cases
      WHERE id=?`).get(med.id);
    assert.equal(migrated.resolve_after, expected);
    assert.equal(migrated.timing_policy_version, 2);
    assert.equal(bank.resolvePendingMed(), 1);
    bank.close();
    bank = new Bank(path, () => now);
    assert.equal(bank.db.prepare("SELECT resolve_after FROM med_cases WHERE id=?")
      .get(med.id).resolve_after, expected);
    assert.equal(bank.resolveMed(med.id).refunded_cents, 1_000);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("legacy MED already older than seven days is ready without another review window", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-overdue-"));
  const path = join(dir, "bank.sqlite");
  let now = new Date("2026-11-11T12:00:00.000Z");
  let bank = new Bank(path, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const transfer = bank.transferPix({ from: seedAccountId(1), to: seedAccountId(2),
      amount: 1_000, idempotencyKey: "med-overdue-window", actor: customer });
    const med = bank.requestMed(customer, transfer.id);
    const decide = reviewer(bank);
    decide(med.id, transfer.id);
    bank.db.prepare("UPDATE med_cases SET resolve_after=?,timing_policy_version=1 WHERE id=?")
      .run(new Date(now.getTime() + 7 * 60_000).toISOString(), med.id);
    bank.close();
    now = new Date(now.getTime() + 8 * DAY);
    bank = new Bank(path, () => now);
    const migrated = bank.db.prepare(`SELECT resolve_after,timing_policy_version FROM med_cases
      WHERE id=?`).get(med.id);
    assert.equal(migrated.resolve_after, now.toISOString());
    assert.equal(migrated.timing_policy_version, 2);
    assert.equal(bank.resolveMed(med.id).refunded_cents, 1_000);
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("internal MED records partial or zero recovery without debiting downstream accounts", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-partial-"));
  let now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const decide = reviewer(bank);
    const victim = seedCustomerId(1);
    const recipient = seedCustomerId(2);
    const downstream = seedAccountId(2);
    for (const [index, spent, expectedRefund] of [[1, 600, 400], [2, 1_000, 0]]) {
      const account = `acc_med_review_${index}`;
      bank.addAccount({ id: account, customer_id: recipient, kind: "checking",
        system_role: null, overdraft_limit: 0, status: "active" });
      const payment = bank.transferPix({ from: seedAccountId(1), to: account,
        amount: 1_000, idempotencyKey: `med-partial-${index}`, actor: victim });
      bank.transferPix({ from: account, to: downstream, amount: spent,
        idempotencyKey: `med-spend-${index}`, actor: recipient });
      const med = bank.requestMed(victim, payment.id);
      decide(med.id, payment.id);
      const beforeDownstream = bank.account(downstream).balance_cached;
      now = new Date("2026-11-18T12:00:00.000Z");
      const resolved = bank.resolveMed(med.id);
      assert.equal(resolved.status, "resolved");
      assert.equal(resolved.refunded_cents, expectedRefund);
      assert.equal(bank.db.prepare("SELECT unrecovered_cents FROM med_cases WHERE id=?")
        .get(med.id).unrecovered_cents, 1_000 - expectedRefund);
      assert.equal(bank.account(downstream).balance_cached, beforeDownstream);
      assert.equal(bank.requestMed(victim, payment.id).status, "resolved");
      now = new Date("2026-11-11T12:00:00.000Z");
    }
    assert.equal(bank.reconcile().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a rejected MED decision releases PSP holds without posting a refund", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-med-rejected-"));
  let now = new Date("2026-11-11T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const customer = seedCustomerId(1);
    const payment = bank.transferPix({ from: seedAccountId(1), to: "psp_ipe_ana",
      amount: 1_000, idempotencyKey: "med-rejected", actor: customer });
    const med = bank.requestMed(customer, payment.id);
    const decide = reviewer(bank);
    assert.throws(() => bank.recordMedDecision(med.id, "approved", "medmaker",
      "medreviewer", "unlinked-evidence"), (error) => error instanceof BankError &&
      error.code === "DEF_MED_DECISION_INVALID");
    const before = bank.account(seedAccountId(1)).balance_cached;
    decide(med.id, payment.id, "rejected");
    assert.equal(bank.db.prepare("SELECT status FROM med_cases WHERE id=?")
      .get(med.id).status, "rejected");
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM med_replay_outbox
      WHERE case_id=? AND published_at IS NULL`).get(med.id).n, 1);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM med_hops
      WHERE case_id=? AND released_at IS NULL`).get(med.id).n, 0);
    assert.deepEqual(moneyFlowMedState(bank, payment.id)?.institutions,
      [{ name: "Banco Ipê", state: "released" }]);
    assert.equal(moneyFlowMedState(bank, payment.id)?.status, "rejected");
    now = new Date(now.getTime() + 8 * DAY);
    assert.equal(bank.resolvePendingMed(), 0);
    assert.equal(bank.resolveMed(med.id).status, "rejected");
    assert.equal(bank.account(seedAccountId(1)).balance_cached, before);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM med_refunds WHERE case_id=?")
      .get(med.id).n, 0);
    assert.throws(() => bank.db.prepare("DELETE FROM med_decisions WHERE case_id=?")
      .run(med.id), /MED_DECISION_IMMUTABLE/);
    const ordinary = bank.returnExternalPix(payment.id, 1_000, "return-after-med-rejection");
    assert.equal(bank.returnExternalPix(payment.id, 1_000,
      "return-after-med-rejection").id, ordinary.id);
    assert.equal(bank.account(seedAccountId(1)).balance_cached, before + 1_000);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM pix_returns WHERE transfer_id=?")
      .get(payment.id).n, 1);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
