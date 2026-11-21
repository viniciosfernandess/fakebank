import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SYNTHETIC_LOAN_POLICY_V1, buildLoanSchedule, assessLoanSchedule,
} from "../apps/world/src/loan-schedules.ts";

test("SAC amortizes principal evenly in cents and keeps the original month-end anchor", () => {
  const rows = buildLoanSchedule({
    principal_cents: 10_001, rate_bps_month: 100, term_months: 3,
    start_date: "2026-01-31", method: "SAC",
  });
  assert.deepEqual(rows.map((row) => row.due_date),
    ["2026-02-28", "2026-03-31", "2026-04-30"]);
  assert.deepEqual(rows.map((row) => row.principal_cents), [3_334, 3_334, 3_333]);
  assert.deepEqual(rows.map((row) => row.interest_cents), [100, 67, 33]);
  assert.deepEqual(rows.map((row) => row.closing_principal_cents), [6_667, 3_333, 0]);
  assert.equal(rows.reduce((sum, row) => sum + row.principal_cents, 0), 10_001);
});

test("Price payment remains fixed until the final cent adjustment and fully amortizes", () => {
  const rows = buildLoanSchedule({
    principal_cents: 120_000, rate_bps_month: 390, term_months: 12,
    start_date: "2026-11-15", method: "PRICE",
  });
  assert.equal(rows.length, 12);
  assert.equal(new Set(rows.slice(0, -1).map((row) => row.payment_cents)).size, 1);
  assert.equal(rows[0].interest_cents, 4_680);
  assert.equal(rows.at(-1).closing_principal_cents, 0);
  assert.equal(rows.reduce((sum, row) => sum + row.principal_cents, 0), 120_000);
  for (const row of rows) {
    assert.equal(row.payment_cents, row.principal_cents + row.interest_cents);
    assert.equal(row.closing_principal_cents, row.opening_principal_cents - row.principal_cents);
  }
});

test("zero-interest Price schedule reconciles rounding in its last installment", () => {
  const rows = buildLoanSchedule({
    principal_cents: 10_000, rate_bps_month: 0, term_months: 3,
    start_date: "2026-01-15", method: "PRICE",
  });
  assert.deepEqual(rows.map((row) => row.payment_cents), [3_333, 3_333, 3_334]);
});

test("synthetic arrears, mora, and provision use remaining scheduled debt", () => {
  const schedule = buildLoanSchedule({
    principal_cents: 10_000, rate_bps_month: 0, term_months: 1,
    start_date: "2026-01-15", method: "SAC",
  });
  assert.equal(SYNTHETIC_LOAN_POLICY_V1.version, 1);
  const current = assessLoanSchedule(schedule, [0], "2026-02-15");
  assert.deepEqual([current.max_days_past_due, current.provision_bps, current.provision_cents],
    [0, 100, 100]);
  const oneDayLate = assessLoanSchedule(schedule, [0], "2026-02-16");
  assert.deepEqual([oneDayLate.max_days_past_due, oneDayLate.provision_bps,
    oneDayLate.provision_cents], [1, 500, 500]);
  const late = assessLoanSchedule(schedule, [0], "2026-03-17");
  assert.deepEqual([late.max_days_past_due, late.installments[0].late_fee_cents,
    late.installments[0].mora_cents, late.installments[0].collectible_cents,
    late.provision_bps, late.provision_cents], [30, 200, 100, 10_300, 2_000, 2_000]);
  const partial = assessLoanSchedule(schedule, [5_000], "2026-03-17");
  assert.deepEqual([partial.outstanding_principal_cents,
    partial.installments[0].late_fee_cents, partial.installments[0].mora_cents,
    partial.provision_cents], [5_000, 100, 50, 1_000]);
  const paid = assessLoanSchedule(schedule, [10_000], "2026-05-16");
  assert.equal(paid.installments[0].collectible_cents, 0);
  assert.equal(paid.provision_cents, 0);
  assert.equal(assessLoanSchedule(schedule, [0], "2026-05-16").provision_cents, 10_000);
});

test("invalid amounts, impossible dates, and overpayments fail closed", () => {
  const valid = { principal_cents: 100_000, rate_bps_month: 390,
    term_months: 12, start_date: "2026-11-15", method: "PRICE" };
  assert.throws(() => buildLoanSchedule({ ...valid, start_date: "2026-02-30" }),
    /LOAN_DATE_INVALID/);
  assert.throws(() => buildLoanSchedule({ ...valid, term_months: 0 }),
    /LOAN_TERM_INVALID/);
  assert.throws(() => buildLoanSchedule({ ...valid, rate_bps_month: -1 }),
    /LOAN_RATE_INVALID/);
  const schedule = buildLoanSchedule(valid);
  assert.throws(() => assessLoanSchedule(schedule, [0], "2026-11-16"),
    /LOAN_PAYMENT_VECTOR_INVALID/);
  assert.throws(() => assessLoanSchedule(schedule,
    schedule.map((row, index) => index === 0 ? row.payment_cents + 1 : 0), "2026-11-16"),
  /LOAN_PAID_AMOUNT_INVALID/);
});
