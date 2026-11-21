import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Bank } from "../apps/world/src/bank.ts";
import { AuthEngine } from "../apps/world/src/auth.ts";
import { createTwinApi } from "../apps/world/src/api.ts";
import { seedBank } from "../apps/world/src/seed.ts";
import { seedAccountId, seedCustomerId } from "../apps/world/src/id.ts";
import { readDuePixCommands, readPendingPspCredits } from
  "../apps/world/src/pix-outbox-commands.ts";
import { exportBankSnapshot } from "../scripts/export-ecosystem-snapshot.mjs";

test("queued external Pix reserves funds until its SPI response is posted once", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-queue-"));
  let now = new Date("2026-11-13T12:00:00Z");
  let realNow = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"), () => now, () => realNow);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    const balance = bank.account(from).balance_cached;
    const available = bank.availableBalance(from);
    const payment = bank.enqueueExternalPix({ from, to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "queued-once", actor: "test" });
    assert.equal(payment.status, "in_processing");
    assert.equal(bank.account(from).balance_cached, balance);
    assert.equal(bank.availableBalance(from), available - 1_000);
    assert.equal(bank.spi.messages(payment.end_to_end_id).length, 0);
    const eligibleAt = bank.db.prepare(`SELECT queued_at_real,eligible_at_real,
      deadline_at_real,latency_policy_version
      FROM pix_spi_outbox WHERE transfer_id=?`).get(payment.id);
    assert.equal(eligibleAt.latency_policy_version, 3);
    assert.equal(eligibleAt.queued_at_real, realNow.toISOString());
    assert.equal(Date.parse(eligibleAt.deadline_at_real) - realNow.getTime(), 10_000);
    assert.deepEqual(bank.pixLatencyMetrics(), { count: 0, p50_ms: null,
      p99_ms: null, max_ms: null });
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 0 });
    assert.equal(bank.spi.messages(payment.end_to_end_id).length, 0);
    const holdId = bank.db.prepare(`SELECT id FROM balance_holds
      WHERE kind='pix_cautelar' AND ref=?`).get(payment.id).id;
    assert.throws(() => bank.releaseHold(holdId, "operator"), /DEF_PIX_PROCESSING_HOLD/);
    assert.equal(bank.enqueueExternalPix({ from, to: "psp_ipe_ana", amount: 1_000,
      idempotencyKey: "queued-once", actor: "test" }).id, payment.id);
    now = new Date("2026-11-13T12:10:00Z");
    assert.equal(bank.availableBalance(from), available - 1_000);
    assert.equal(bank.reconcileSpi().ok, true);
    realNow = new Date(eligibleAt.eligible_at_real);
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 1, deferred: 0 });
    const elapsedMs = Date.parse(eligibleAt.eligible_at_real) -
      Date.parse(eligibleAt.queued_at_real);
    assert.deepEqual(bank.pixLatencyMetrics(), { count: 1, p50_ms: elapsedMs,
      p99_ms: elapsedMs, max_ms: elapsedMs });
    assert.equal(bank.db.prepare(`SELECT responded_at_real FROM pix_spi_outbox
      WHERE transfer_id=?`).get(payment.id).responded_at_real, realNow.toISOString());
    assert.throws(() => bank.db.prepare(`UPDATE pix_spi_outbox
      SET queued_at_real=? WHERE transfer_id=?`).run(realNow.toISOString(), payment.id),
    /PIX_SPI_COMMAND_IMMUTABLE/);
    assert.throws(() => bank.db.prepare(`UPDATE pix_spi_outbox
      SET deadline_at_real=? WHERE transfer_id=?`).run(realNow.toISOString(), payment.id),
    /PIX_SPI_COMMAND_IMMUTABLE/);
    assert.throws(() => bank.db.prepare(`UPDATE pix_spi_outbox
      SET responded_at_real=? WHERE transfer_id=?`).run(realNow.toISOString(), payment.id),
    /PIX_SPI_RESPONSE_IMMUTABLE/);
    assert.equal(bank.db.prepare("SELECT status FROM pix_transfers WHERE id=?")
      .get(payment.id).status, "settled");
    assert.equal(bank.account(from).balance_cached, balance - 1_000);
    assert.equal(bank.availableBalance(from), available - 1_000);
    assert.equal(bank.spi.account("psp_ipe_ana").balance_cents, 1_000);
    assert.equal(bank.spi.messages(payment.end_to_end_id).length, 2);
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 0 });
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
    bank.db.exec("DROP TRIGGER pix_psp_inbound_no_delete");
    bank.db.prepare("DELETE FROM pix_psp_inbound_outbox WHERE transfer_id=?")
      .run(payment.id);
    assert.equal(bank.reconcileSpi().ok, false);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("bank applies only a matching durable SPI response and replays it once", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-response-"));
  const now = () => new Date("2026-11-13T12:00:00.000Z");
  const bank = new Bank(join(dir, "bank.sqlite"), now, now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    const before = bank.account(from).balance_cached;
    const payment = bank.enqueueExternalPix({ from, to: "psp_ipe_ana",
      amount: 700, idempotencyKey: "response-validation", actor: "test" });
    const command = bank.db.prepare(`SELECT from_ispb,to_ispb,amount_cents,deadline_at_real
      FROM pix_spi_outbox WHERE transfer_id=?`).get(payment.id);
    const response = bank.spi.submitPayment(payment.end_to_end_id,
      command.from_ispb, command.to_ispb, command.amount_cents,
      from, payment.id, command.deadline_at_real);
    assert.equal(response.status, "ACSC");
    assert.throws(() => bank.applyQueuedSpiResponse(payment.id,
      { ...response, amount_cents: 701 }), /INTEGRITY_PIX_SPI_RESPONSE/);
    assert.throws(() => bank.applyQueuedSpiResponse(payment.id,
      { ...response, end_to_end_id: "wrong" }), /INTEGRITY_PIX_SPI_RESPONSE/);
    assert.equal(bank.account(from).balance_cached, before);
    assert.equal(bank.db.prepare("SELECT response_status FROM pix_spi_outbox WHERE transfer_id=?")
      .get(payment.id).response_status, null);
    bank.applyQueuedSpiResponse(payment.id, response);
    bank.applyQueuedSpiResponse(payment.id, response);
    assert.equal(bank.account(from).balance_cached, before - 700);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries WHERE ref_id=?")
      .get(payment.id).n, 2);
    const bankOnly = join(dir, "bank-only.sqlite");
    exportBankSnapshot(join(dir, "bank.sqlite"), bankOnly);
    const isolated = new DatabaseSync(bankOnly, { readOnly: true });
    try {
      const pending = readPendingPspCredits(isolated);
      assert.equal(pending.length, 1);
      assert.equal(pending[0].transfer_id, payment.id);
      assert.equal(pending[0].amount_cents, 700);
      assert.equal(isolated.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='psp_accounts'`).get(), undefined);
    } finally { isolated.close(); }
    assert.throws(() => bank.acknowledgePspCredit(payment.id, "bad reason"),
      /INTEGRITY_PIX_PSP_ACK/);
    assert.equal(bank.db.prepare(`SELECT acknowledged_at FROM pix_psp_inbound_outbox
      WHERE transfer_id=?`).get(payment.id).acknowledged_at, null);
    assert.equal(bank.dispatchPendingPspCredits(), 1);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("due SPI commands can be read from a bank-only file", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-bank-outbox-"));
  const source = join(dir, "combined.sqlite");
  const bankOnly = join(dir, "bank.sqlite");
  const now = new Date("2026-11-13T12:00:00.000Z");
  const bank = new Bank(source, () => now, () => now);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const payment = bank.enqueueExternalPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 700, idempotencyKey: "bank-only-outbox",
      actor: "test" });
    exportBankSnapshot(source, bankOnly);
    const isolated = new DatabaseSync(bankOnly, { readOnly: true });
    try {
      assert.equal(isolated.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='psp_accounts'`).get(), undefined);
      const dueAt = new Date(now.getTime() + 3_000);
      const commands = readDuePixCommands(isolated, dueAt);
      assert.equal(commands.length, 1);
      assert.equal(commands[0].id, payment.id);
      assert.equal(commands[0].amount, 700);
      assert.equal(commands[0].to_ispb, "87654321");
    } finally { isolated.close(); }
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("an SPI outage leaves a committed pending instruction for restart recovery", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-restart-"));
  const path = join(dir, "bank.sqlite");
  const now = () => new Date("2026-11-13T12:00:00Z");
  let realNow = new Date("2026-11-13T12:00:00Z");
  const realClock = () => realNow;
  const immediatePolicy = Buffer.from(JSON.stringify({ version: 1,
    min_ms: 0, p50_ms: 0, p99_ms: 0, max_ms: 0 }));
  let bank = new Bank(path, now, realClock);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    const before = bank.account(from).balance_cached;
    const payment = bank.enqueueExternalPix({ from, to: "psp_ipe_ana", amount: 900,
      idempotencyKey: "queued-restart", actor: "test" });
    const eligibleAt = bank.db.prepare(`SELECT eligible_at_real FROM pix_spi_outbox
      WHERE transfer_id=?`).get(payment.id).eligible_at_real;
    bank.close();
    bank = new Bank(path, now, realClock, { spiLatencyBytes: immediatePolicy });
    assert.equal(bank.db.prepare(`SELECT eligible_at_real FROM pix_spi_outbox
      WHERE transfer_id=?`).get(payment.id).eligible_at_real, eligibleAt);
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 0 });
    assert.equal(bank.spi.messages(payment.end_to_end_id).length, 0);
    realNow = new Date(eligibleAt);
    bank.spi.setAvailability(false, "operator");
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 1 });
    assert.equal(bank.db.prepare("SELECT status FROM pix_transfers WHERE id=?")
      .get(payment.id).status, "in_processing");
    bank.close();
    bank = new Bank(path, now, realClock, { spiLatencyBytes: immediatePolicy });
    assert.equal(bank.reconcileSpi().ok, true);
    bank.spi.setAvailability(true, "operator");
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 1, deferred: 0 });
    assert.equal(bank.account(from).balance_cached, before - 900);
    assert.equal(bank.spi.messages(payment.end_to_end_id).length, 2);
    assert.equal(bank.reconcileSpi().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a PSP outage after bank settlement keeps a durable inbound command for restart", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-psp-outbox-restart-"));
  const path = join(dir, "bank.sqlite");
  const now = () => new Date("2026-11-13T12:00:00Z");
  const immediatePolicy = Buffer.from(JSON.stringify({ version: 1,
    min_ms: 0, p50_ms: 0, p99_ms: 0, max_ms: 0 }));
  let bank = new Bank(path, now, now, { spiLatencyBytes: immediatePolicy });
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    const before = bank.account(from).balance_cached;
    const payment = bank.enqueueExternalPix({ from, to: "psp_ipe_ana", amount: 700,
      idempotencyKey: "psp-outage", actor: "test" });
    const creditInbound = bank.psp.creditInbound.bind(bank.psp);
    bank.psp.creditInbound = () => { throw new Error("PSP_DOWN"); };
    assert.throws(() => bank.dispatchPendingPix(), /PSP_DOWN/);
    assert.equal(bank.spi.messages(payment.end_to_end_id)[0].root_transfer_id, payment.id);
    assert.throws(() => creditInbound("psp_ipe_ana", "wrong_root", payment.end_to_end_id,
      700, from, now().toISOString()), /PSP_INBOUND_SPI_PROOF_INVALID/);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM psp_roots").get().n, 0);
    assert.equal(bank.account(from).balance_cached, before - 700);
    assert.equal(bank.db.prepare("SELECT status FROM pix_transfers WHERE id=?")
      .get(payment.id).status, "settled");
    assert.equal(bank.db.prepare(`SELECT acknowledged_at FROM pix_psp_inbound_outbox
      WHERE transfer_id=?`).get(payment.id).acknowledged_at, null);
    assert.equal(bank.spi.account("psp_ipe_ana").balance_cents, 0);
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().inbound_pending, 1);
    assert.equal(bank.reconcilePsp().ok, false);
    bank.close();
    bank = new Bank(path, now, now, { spiLatencyBytes: immediatePolicy });
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 0 });
    assert.equal(bank.spi.account("psp_ipe_ana").balance_cents, 700);
    assert.ok(bank.db.prepare(`SELECT acknowledged_at FROM pix_psp_inbound_outbox
      WHERE transfer_id=?`).get(payment.id).acknowledged_at);
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 0 });
    assert.equal(bank.spi.account("psp_ipe_ana").balance_cents, 700);
    assert.equal(bank.reconcile().ok, true);
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a crash after PSP credit retries its acknowledgement without a second credit", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-psp-outbox-ack-"));
  const path = join(dir, "bank.sqlite");
  const now = () => new Date("2026-11-13T12:00:00Z");
  const immediatePolicy = Buffer.from(JSON.stringify({ version: 1,
    min_ms: 0, p50_ms: 0, p99_ms: 0, max_ms: 0 }));
  let bank = new Bank(path, now, now,
    { spiLatencyBytes: immediatePolicy });
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const payment = bank.enqueueExternalPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 800, idempotencyKey: "psp-ack-crash", actor: "test" });
    bank.psp.reviewIncoming = () => { throw new Error("AFTER_PSP_CREDIT"); };
    assert.throws(() => bank.dispatchPendingPix(), /AFTER_PSP_CREDIT/);
    assert.equal(bank.spi.account("psp_ipe_ana").balance_cents, 800);
    assert.equal(bank.db.prepare(`SELECT acknowledged_at FROM pix_psp_inbound_outbox
      WHERE transfer_id=?`).get(payment.id).acknowledged_at, null);
    bank.close();
    bank = new Bank(path, now, now, { spiLatencyBytes: immediatePolicy });
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 0 });
    assert.equal(bank.spi.account("psp_ipe_ana").balance_cents, 800);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM psp_inbound_receipts
      WHERE root_transfer_id=?`).get(payment.id).n, 1);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a failed acknowledgement after PSP cautelar review reuses the original hold", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-psp-review-ack-"));
  const now = () => new Date("2026-11-13T12:00:00Z");
  const immediatePolicy = Buffer.from(JSON.stringify({ version: 1,
    min_ms: 0, p50_ms: 0, p99_ms: 0, max_ms: 0 }));
  const bank = new Bank(join(dir, "bank.sqlite"), now, now,
    { spiLatencyBytes: immediatePolicy });
  try {
    seedBank(bank, { customers: 5, accounts: 5, historyTransactions: 0 });
    for (let index = 1; index <= 4; index++) bank.transferPix({
      from: seedAccountId(index), to: "psp_ipe_ana", amount: 100,
      idempotencyKey: `review-source-${index}`, actor: "test" });
    const payment = bank.enqueueExternalPix({ from: seedAccountId(5),
      to: "psp_ipe_ana", amount: 100, idempotencyKey: "review-fifth", actor: "test" });
    const emit = bank.telemetry.emit.bind(bank.telemetry);
    bank.telemetry.emit = (input) => {
      if (input.action === "psp_cautelar") throw new Error("ACK_FAILURE");
      return emit(input);
    };
    assert.throws(() => bank.dispatchPendingPix(), /ACK_FAILURE/);
    assert.equal(bank.db.prepare(`SELECT acknowledged_at FROM pix_psp_inbound_outbox
      WHERE transfer_id=?`).get(payment.id).acknowledged_at, null);
    const holdCount = () => bank.db.prepare(`SELECT COUNT(*) n FROM psp_cautelar_holds
      WHERE root_transfer_id=? AND reason='PSP_FAN_IN_10M'`).get(payment.id).n;
    assert.equal(holdCount(), 1);
    bank.telemetry.emit = emit;
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 0 });
    assert.equal(holdCount(), 1);
    assert.equal(bank.db.prepare(`SELECT COUNT(*) n FROM psp_cautelar_notices n
      JOIN psp_cautelar_holds h ON h.id=n.hold_id WHERE h.root_transfer_id=?`)
      .get(payment.id).n, 1);
    assert.equal(bank.reconcilePsp().ok, true);
    assert.equal(bank.reconcileSpi().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("customer Pix history shows pending recipient credit until PSP acknowledgement", async () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-psp-customer-status-"));
  const now = () => new Date("2026-11-13T12:00:00Z");
  const immediatePolicy = Buffer.from(JSON.stringify({ version: 1,
    min_ms: 0, p50_ms: 0, p99_ms: 0, max_ms: 0 }));
  const bank = new Bank(join(dir, "bank.sqlite"), now, now,
    { spiLatencyBytes: immediatePolicy });
  seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
  const customer = seedCustomerId(1);
  const auth = new AuthEngine(bank);
  auth.setPassword(customer, "psp-status-password");
  const challenge = auth.beginLogin(bank.customer(customer).cpf,
    "psp-status-password", "127.0.0.1", "psp-status-device");
  const session = auth.verifyOtp(challenge.challenge_id,
    auth.simulatedOtp(challenge.challenge_id, customer), "127.0.0.1");
  const api = createTwinApi(bank, auth);
  const headers = { authorization: `Bearer ${session.access_token}` };
  try {
    const payment = bank.enqueueExternalPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 100, idempotencyKey: "psp-customer-status",
      actor: customer });
    const credit = bank.psp.creditInbound.bind(bank.psp);
    bank.psp.creditInbound = () => { throw new Error("PSP_DOWN"); };
    assert.throws(() => bank.dispatchPendingPix(), /PSP_DOWN/);
    const listing = await api.inject({ method: "GET", url: "/pix/transfers", headers });
    assert.equal(listing.statusCode, 200);
    assert.equal(listing.json().find((row) => row.id === payment.id).psp_credit_status, "pending");
    const detail = await api.inject({ method: "GET",
      url: `/pix/transfers/${payment.id}`, headers });
    assert.equal(detail.statusCode, 200);
    assert.equal(detail.json().psp_credit_status, "pending");
    bank.psp.creditInbound = credit;
    bank.dispatchPendingPix();
    const credited = await api.inject({ method: "GET",
      url: `/pix/transfers/${payment.id}`, headers });
    assert.equal(credited.json().psp_credit_status, "credited");
  } finally { await api.close(); bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a bank posting failure after SPI acceptance retries without a second PI debit", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-crash-"));
  const path = join(dir, "bank.sqlite");
  const now = () => new Date("2026-11-13T12:00:00Z");
  let realNow = new Date("2026-11-13T12:00:00Z");
  const realClock = () => realNow;
  let bank = new Bank(path, now, realClock);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    const balance = bank.account(from).balance_cached;
    const pi = bank.spi.balance("12345678");
    const payment = bank.enqueueExternalPix({ from, to: "psp_ipe_ana", amount: 700,
      idempotencyKey: "queued-crash", actor: "test" });
    realNow = new Date(bank.db.prepare(`SELECT eligible_at_real FROM pix_spi_outbox
      WHERE transfer_id=?`).get(payment.id).eligible_at_real);
    bank.db.exec(`CREATE TRIGGER fail_pix_final_post BEFORE INSERT ON ledger_entries
      WHEN NEW.ref_id='${payment.id}' BEGIN SELECT RAISE(ABORT,'POST_FAILURE'); END`);
    assert.throws(() => bank.dispatchPendingPix(), /POST_FAILURE/);
    assert.equal(bank.spi.balance("12345678"), pi - 700);
    assert.equal(bank.account(from).balance_cached, balance);
    assert.equal(bank.db.prepare("SELECT status FROM pix_transfers WHERE id=?")
      .get(payment.id).status, "in_processing");
    assert.equal(bank.reconcileSpi().ok, true);
    realNow = new Date(bank.db.prepare(`SELECT deadline_at_real FROM pix_spi_outbox
      WHERE transfer_id=?`).get(payment.id).deadline_at_real);
    bank.close();
    bank = new Bank(path, now, realClock);
    bank.db.exec("DROP TRIGGER fail_pix_final_post");
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 1, deferred: 0 });
    assert.equal(bank.account(from).balance_cached, balance - 700);
    assert.equal(bank.spi.balance("12345678"), pi - 700);
    assert.equal(bank.spi.messages(payment.end_to_end_id).length, 2);
    assert.equal(bank.db.prepare("SELECT COUNT(*) n FROM ledger_entries WHERE ref_id=?")
      .get(payment.id).n, 2);
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("an expired queued Pix receives AB03 without a bank or PI debit", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-ab03-"));
  let realNow = new Date("2026-11-13T12:00:00Z");
  const bank = new Bank(join(dir, "bank.sqlite"),
    () => new Date("2026-11-13T12:00:00Z"), () => realNow);
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    const balance = bank.account(from).balance_cached;
    const pi = bank.spi.balance("12345678");
    const payment = bank.enqueueExternalPix({ from, to: "psp_ipe_ana", amount: 600,
      idempotencyKey: "queued-expired", actor: "test" });
    const deadline = bank.db.prepare(`SELECT deadline_at_real FROM pix_spi_outbox
      WHERE transfer_id=?`).get(payment.id).deadline_at_real;
    realNow = new Date(deadline);
    bank.spi.setAvailability(false, "test");
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 1 });
    assert.equal(bank.db.prepare("SELECT status FROM pix_transfers WHERE id=?")
      .get(payment.id).status, "in_processing");
    bank.spi.setAvailability(true, "test");
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 1, deferred: 0 });
    assert.equal(bank.db.prepare(`SELECT response_status,response_reason FROM pix_spi_outbox
      WHERE transfer_id=?`).get(payment.id).response_reason, "AB03");
    assert.equal(bank.db.prepare("SELECT status FROM pix_transfers WHERE id=?")
      .get(payment.id).status, "rejected");
    assert.equal(bank.account(from).balance_cached, balance);
    assert.equal(bank.availableBalance(from), balance);
    assert.equal(bank.spi.balance("12345678"), pi);
    assert.equal(bank.spi.account("psp_ipe_ana").balance_cents, 0);
    assert.equal(bank.spi.messages(payment.end_to_end_id).length, 2);
    assert.equal(bank.spi.messages(payment.end_to_end_id)[1].reason, "AB03");
    assert.throws(() => bank.spi.submitPayment(payment.end_to_end_id,
      "12345678", "87654321", 600, from, payment.id,
      new Date(realNow.getTime() + 1_000).toISOString()),
    /SPI_PAYMENT_IDEMPOTENCY_CONFLICT/);
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 0 });
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a version-one queued command keeps its original no-timeout contract", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-timeout-migrate-"));
  const path = join(dir, "bank.sqlite");
  const now = () => new Date("2026-11-13T12:00:00Z");
  let realNow = new Date("2026-11-13T12:00:00Z");
  const realClock = () => realNow;
  const legacyPolicy = Buffer.from(JSON.stringify({ version: 1,
    min_ms: 50, p50_ms: 200, p99_ms: 2_000, max_ms: 3_000 }));
  let bank = new Bank(path, now, realClock, { spiLatencyBytes: legacyPolicy });
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const payment = bank.enqueueExternalPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 500, idempotencyKey: "legacy-no-timeout",
      actor: "test" });
    const command = bank.db.prepare(`SELECT deadline_at_real,latency_policy_version
      FROM pix_spi_outbox WHERE transfer_id=?`).get(payment.id);
    assert.equal(command.deadline_at_real, null);
    assert.equal(command.latency_policy_version, 1);
    bank.close();
    realNow = new Date(realNow.getTime() + 20_000);
    bank = new Bank(path, now, realClock);
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 1, deferred: 0 });
    assert.equal(bank.db.prepare("SELECT status FROM pix_transfers WHERE id=?")
      .get(payment.id).status, "settled");
    assert.equal(bank.reconcileSpi().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a version-two queued command keeps its due time and deadline under version three", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-latency-v2-restart-"));
  const path = join(dir, "bank.sqlite");
  const now = () => new Date("2026-11-13T12:00:00Z");
  let realNow = new Date("2026-11-13T12:00:00Z");
  const realClock = () => realNow;
  const oldPolicy = Buffer.from(JSON.stringify({ version: 2,
    min_ms: 50, p50_ms: 200, p99_ms: 2_000, max_ms: 3_000,
    timeout_ms: 10_000 }));
  let bank = new Bank(path, now, realClock, { spiLatencyBytes: oldPolicy });
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const payment = bank.enqueueExternalPix({ from: seedAccountId(1),
      to: "psp_ipe_ana", amount: 500, idempotencyKey: "old-latency-policy",
      actor: "test" });
    const original = bank.db.prepare(`SELECT queued_at_real,eligible_at_real,
      deadline_at_real,latency_policy_version FROM pix_spi_outbox
      WHERE transfer_id=?`).get(payment.id);
    assert.equal(original.latency_policy_version, 2);
    bank.close();
    bank = new Bank(path, now, realClock);
    assert.deepEqual(bank.db.prepare(`SELECT queued_at_real,eligible_at_real,
      deadline_at_real,latency_policy_version FROM pix_spi_outbox
      WHERE transfer_id=?`).get(payment.id), original);
    realNow = new Date(Date.parse(original.eligible_at_real) - 1);
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 0, deferred: 0 });
    realNow = new Date(original.eligible_at_real);
    assert.deepEqual(bank.dispatchPendingPix(), { processed: 1, deferred: 0 });
    assert.equal(bank.db.prepare(`SELECT status FROM pix_transfers WHERE id=?`)
      .get(payment.id).status, "settled");
    assert.equal(bank.reconcileSpi().ok, true);
    assert.equal(bank.reconcilePsp().ok, true);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("pending external Pix counts against the customer's night limit", () => {
  const dir = mkdtempSync(join(tmpdir(), "banco-vivo-pix-pending-limit-"));
  const bank = new Bank(join(dir, "bank.sqlite"), () => new Date("2026-11-14T00:00:00Z"));
  try {
    seedBank(bank, { customers: 2, accounts: 2, historyTransactions: 0 });
    const from = seedAccountId(1);
    bank.requestPixNightSetting(bank.account(from).customer_id, "night_limit_cents", 1_000);
    assert.equal(bank.enqueueExternalPix({ from, to: "psp_ipe_ana", amount: 600,
      idempotencyKey: "pending-limit-one", actor: "test" }).status, "in_processing");
    assert.throws(() => bank.enqueueExternalPix({ from, to: "psp_ipe_ana", amount: 500,
      idempotencyKey: "pending-limit-two", actor: "test" }), /BIZ_NIGHT_LIMIT/);
  } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
});
