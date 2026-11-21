// Simulation policy, not a representation of regulatory provisioning or a contract.
// Charges are snapshot estimates on unpaid scheduled amounts; callers must persist
// assessed charges and actual payment allocation in their own ledger transaction.
export const SYNTHETIC_LOAN_POLICY_V1 = Object.freeze({
  version: 1,
  late_fee_bps: 200,
  monthly_mora_bps: 100,
  mora_day_basis: 30,
  provision_current_bps: 100,
  provision_1_29_bps: 500,
  provision_30_89_bps: 2_000,
  provision_90_plus_bps: 10_000,
});

export type AmortizationMethod = "PRICE" | "SAC";

export interface LoanInstallment {
  number: number;
  due_date: string;
  opening_principal_cents: number;
  principal_cents: number;
  interest_cents: number;
  payment_cents: number;
  closing_principal_cents: number;
}

export interface AssessedLoanInstallment extends LoanInstallment {
  paid_cents: number;
  unpaid_cents: number;
  days_past_due: number;
  late_fee_cents: number;
  mora_cents: number;
  collectible_cents: number;
}

export interface LoanAssessment {
  policy_version: number;
  installments: AssessedLoanInstallment[];
  outstanding_principal_cents: number;
  max_days_past_due: number;
  provision_bps: number;
  provision_cents: number;
}

function assertMoney(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`LOAN_${label}_INVALID`);
}

function roundHalfEven(numerator: bigint, denominator: bigint): number {
  if (denominator <= 0n || numerator < 0n) throw new Error("LOAN_ARITHMETIC_INVALID");
  const quotient = numerator / denominator;
  const remainder = numerator % denominator;
  const rounded = quotient + (2n * remainder > denominator ||
    (2n * remainder === denominator && quotient % 2n === 1n) ? 1n : 0n);
  const result = Number(rounded);
  if (!Number.isSafeInteger(result)) throw new Error("LOAN_AMOUNT_OVERFLOW");
  return result;
}

function parseCivilDate(value: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error("LOAN_DATE_INVALID");
  const date = new Date(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value)
    throw new Error("LOAN_DATE_INVALID");
  return date;
}

function dueDate(startDate: string, month: number): string {
  const start = parseCivilDate(startDate);
  const originalDay = start.getUTCDate();
  start.setUTCDate(1);
  start.setUTCMonth(start.getUTCMonth() + month);
  const targetMonth = start.getUTCMonth();
  start.setUTCDate(originalDay);
  if (start.getUTCMonth() !== targetMonth) start.setUTCDate(0);
  return start.toISOString().slice(0, 10);
}

function pricePayment(principalCents: number, rateBpsMonthly: number, termMonths: number): number {
  if (rateBpsMonthly === 0) return roundHalfEven(BigInt(principalCents), BigInt(termMonths));
  const base = 10_000n;
  const rate = BigInt(rateBpsMonthly);
  const growth = (base + rate) ** BigInt(termMonths);
  return roundHalfEven(BigInt(principalCents) * rate * growth,
    base * (growth - base ** BigInt(termMonths)));
}

export function buildLoanSchedule(input: {
  principal_cents: number;
  rate_bps_month: number;
  term_months: number;
  start_date: string;
  method: AmortizationMethod;
}): LoanInstallment[] {
  const { principal_cents: principal, rate_bps_month: rate, term_months: terms, start_date: start,
    method } = input;
  assertMoney(principal, "PRINCIPAL");
  if (principal === 0 || principal > 1_000_000_000) throw new Error("LOAN_PRINCIPAL_INVALID");
  if (!Number.isSafeInteger(rate) || rate < 0 || rate > 10_000)
    throw new Error("LOAN_RATE_INVALID");
  if (!Number.isSafeInteger(terms) || terms < 1 || terms > 360)
    throw new Error("LOAN_TERM_INVALID");
  if (method !== "PRICE" && method !== "SAC") throw new Error("LOAN_METHOD_INVALID");
  parseCivilDate(start);
  const fixedPricePayment = method === "PRICE" ? pricePayment(principal, rate, terms) : 0;
  const baseSacPrincipal = Math.floor(principal / terms);
  const sacRemainder = principal % terms;
  const schedule: LoanInstallment[] = [];
  let balance = principal;
  for (let index = 0; index < terms; index++) {
    const interest = roundHalfEven(BigInt(balance) * BigInt(rate), 10_000n);
    const installmentPrincipal = index === terms - 1 ? balance :
      method === "SAC" ? baseSacPrincipal + (index < sacRemainder ? 1 : 0) :
        Math.max(0, Math.min(balance, fixedPricePayment - interest));
    const payment = installmentPrincipal + interest;
    if (!Number.isSafeInteger(payment)) throw new Error("LOAN_AMOUNT_OVERFLOW");
    schedule.push({
      number: index + 1, due_date: dueDate(start, index + 1),
      opening_principal_cents: balance, principal_cents: installmentPrincipal,
      interest_cents: interest, payment_cents: payment,
      closing_principal_cents: balance - installmentPrincipal,
    });
    balance -= installmentPrincipal;
  }
  return schedule;
}

export function assessLoanSchedule(
  schedule: readonly LoanInstallment[], paidCents: readonly number[], asOfDate: string,
): LoanAssessment {
  if (schedule.length === 0 || schedule.length !== paidCents.length)
    throw new Error("LOAN_PAYMENT_VECTOR_INVALID");
  const asOf = parseCivilDate(asOfDate).getTime();
  let outstandingPrincipal = 0;
  let maxDaysPastDue = 0;
  const installments = schedule.map((row, index): AssessedLoanInstallment => {
    const paid = paidCents[index];
    if (paid === undefined) throw new Error("LOAN_PAYMENT_VECTOR_INVALID");
    assertMoney(paid, "PAID_AMOUNT");
    if (paid > row.payment_cents) throw new Error("LOAN_PAID_AMOUNT_INVALID");
    const unpaid = row.payment_cents - paid;
    const principalPaid = Math.max(0, paid - row.interest_cents);
    outstandingPrincipal += row.principal_cents - principalPaid;
    const daysPastDue = unpaid > 0
      ? Math.max(0, Math.floor((asOf - parseCivilDate(row.due_date).getTime()) / 86_400_000))
      : 0;
    maxDaysPastDue = Math.max(maxDaysPastDue, daysPastDue);
    const lateFee = daysPastDue > 0
      ? roundHalfEven(BigInt(unpaid) * BigInt(SYNTHETIC_LOAN_POLICY_V1.late_fee_bps), 10_000n)
      : 0;
    const mora = daysPastDue > 0
      ? roundHalfEven(BigInt(unpaid) * BigInt(SYNTHETIC_LOAN_POLICY_V1.monthly_mora_bps) *
        BigInt(daysPastDue), BigInt(10_000 * SYNTHETIC_LOAN_POLICY_V1.mora_day_basis))
      : 0;
    return { ...row, paid_cents: paid, unpaid_cents: unpaid, days_past_due: daysPastDue,
      late_fee_cents: lateFee, mora_cents: mora, collectible_cents: unpaid + lateFee + mora };
  });
  if (!Number.isSafeInteger(outstandingPrincipal)) throw new Error("LOAN_AMOUNT_OVERFLOW");
  const provisionBps = maxDaysPastDue >= 90 ? SYNTHETIC_LOAN_POLICY_V1.provision_90_plus_bps
    : maxDaysPastDue >= 30 ? SYNTHETIC_LOAN_POLICY_V1.provision_30_89_bps
    : maxDaysPastDue >= 1 ? SYNTHETIC_LOAN_POLICY_V1.provision_1_29_bps
    : SYNTHETIC_LOAN_POLICY_V1.provision_current_bps;
  const provision = roundHalfEven(BigInt(outstandingPrincipal) * BigInt(provisionBps), 10_000n);
  return { policy_version: SYNTHETIC_LOAN_POLICY_V1.version, installments,
    outstanding_principal_cents: outstandingPrincipal, max_days_past_due: maxDaysPastDue,
    provision_bps: provisionBps, provision_cents: provision };
}

export function assessPartialLoanCharges(installment: LoanInstallment,
  paidCents: number, asOfDate: string, previousPaymentDate?: string): {
    late_fee_cents: number; mora_cents: number } {
  const assessed = assessLoanSchedule([installment], [paidCents], asOfDate)
    .installments[0]!;
  if (!previousPaymentDate) return { late_fee_cents: assessed.late_fee_cents,
    mora_cents: assessed.mora_cents };
  const elapsed = Math.max(0, Math.floor((parseCivilDate(asOfDate).getTime() -
    parseCivilDate(previousPaymentDate).getTime()) / 86_400_000));
  const mora = roundHalfEven(BigInt(assessed.unpaid_cents) *
    BigInt(SYNTHETIC_LOAN_POLICY_V1.monthly_mora_bps) * BigInt(elapsed),
    BigInt(10_000 * SYNTHETIC_LOAN_POLICY_V1.mora_day_basis));
  return { late_fee_cents: 0, mora_cents: mora };
}
