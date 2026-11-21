import type { DatabaseSync } from "node:sqlite";
import { accountingDates } from "./accounting-dates.ts";
import { buildLoanSchedule, SYNTHETIC_LOAN_POLICY_V1,
  assessPartialLoanCharges, type AmortizationMethod } from "./loan-schedules.ts";

interface ContractRow {
  loan_id: string; method: AmortizationMethod; term_months: number;
  rate_bps_month: number; policy_version: number; started_at: string;
  principal_cents: number; status: string; account_id: string;
}
interface InstallmentRow {
  installment_no: number; due_date: string; opening_principal_cents: number;
  principal_cents: number; interest_cents: number; payment_cents: number;
  closing_principal_cents: number; paid_cents: number; status: string;
}
interface PaymentRow {
  installment_no: number; amount_cents: number; principal_cents: number;
  interest_cents: number; late_fee_cents: number; mora_cents: number;
  principal_tx_id: string; interest_tx_id: string | null; charges_tx_id: string | null;
}
interface PartialPaymentRow extends Omit<PaymentRow, "principal_tx_id"> {
  id: string; principal_tx_id: string | null; paid_at: string;
}

export function reconcileLoanContracts(db: DatabaseSync): boolean {
  const installed = db.prepare(`SELECT name FROM sqlite_master WHERE type='table'
    AND name IN ('loan_contracts','loan_installments','loan_installment_payments')`).all() as
    { name: string }[];
  if (installed.length === 0) return true;
  if (installed.length !== 3) return false;
  const contracts = db.prepare(`SELECT c.*,l.started_at,l.principal_cents,l.status,l.account_id
    FROM loan_contracts c JOIN loans l ON l.id=c.loan_id`).all() as unknown as ContractRow[];
  const contractCount = (db.prepare("SELECT COUNT(*) n FROM loan_contracts").get() as { n: number }).n;
  if (contracts.length !== contractCount) return false;
  const funding = db.prepare(`SELECT id FROM accounts WHERE kind='system'
    AND system_role='loan_funding'`).get() as { id: string } | undefined;
  const fees = db.prepare(`SELECT id FROM accounts WHERE kind='system'
    AND system_role='fees'`).get() as { id: string } | undefined;
  const interestReceivable = db.prepare(`SELECT id FROM accounts WHERE kind='system'
    AND system_role='loan_interest_receivable'`).get() as { id: string } | undefined;
  const hasAccruals = Boolean(db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='loan_interest_accruals'`).get());
  const accrued = hasAccruals ? db.prepare(`SELECT 1 FROM loan_interest_accruals
    WHERE loan_id=? AND installment_no=?`) : null;
  const hasPartials = Boolean(db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='loan_installment_partial_payments'`).get());
  if (contracts.length && (!funding || !fees)) return false;
  const entries = db.prepare(`SELECT account_id,amount,kind,ref_type,ref_id,reverses_tx_id
    FROM ledger_entries WHERE tx_id=?`);
  const matches = (txId: string | null, loanId: string,
    expected: { accountId: string; amount: number; kind: string }[]): boolean => {
    if (!txId) return expected.length === 0;
    const actual = entries.all(txId) as { account_id: string; amount: number; kind: string;
      ref_type: string; ref_id: string; reverses_tx_id: string | null }[];
    if (actual.length !== expected.length || actual.some((row) => row.ref_type !== "loan" ||
      row.ref_id !== loanId || row.reverses_tx_id !== null)) return false;
    const canonical = (rows: { accountId: string; amount: number; kind: string }[]) =>
      rows.map((row) => `${row.accountId}\0${row.amount}\0${row.kind}`).sort();
    return JSON.stringify(canonical(actual.map((row) => ({ accountId: row.account_id,
      amount: row.amount, kind: row.kind })))) === JSON.stringify(canonical(expected));
  };
  for (const contract of contracts) {
    if (contract.policy_version !== SYNTHETIC_LOAN_POLICY_V1.version) return false;
    let expected;
    try {
      expected = buildLoanSchedule({ principal_cents: contract.principal_cents,
        rate_bps_month: contract.rate_bps_month, term_months: contract.term_months,
        start_date: accountingDates(contract.started_at).posting_date, method: contract.method });
    } catch { return false; }
    const installments = db.prepare(`SELECT installment_no,due_date,opening_principal_cents,
      principal_cents,interest_cents,payment_cents,closing_principal_cents,paid_cents,status
      FROM loan_installments WHERE loan_id=? ORDER BY installment_no`)
      .all(contract.loan_id) as unknown as InstallmentRow[];
    const payments = db.prepare(`SELECT installment_no,amount_cents,principal_cents,
      interest_cents,late_fee_cents,mora_cents,principal_tx_id,interest_tx_id,charges_tx_id
      FROM loan_installment_payments WHERE loan_id=? ORDER BY installment_no`)
      .all(contract.loan_id) as unknown as PaymentRow[];
    const partials = hasPartials ? db.prepare(`SELECT id,installment_no,amount_cents,
      principal_cents,interest_cents,late_fee_cents,mora_cents,
      principal_tx_id,interest_tx_id,charges_tx_id,paid_at
      FROM loan_installment_partial_payments WHERE loan_id=?
      ORDER BY installment_no,paid_at,id`).all(contract.loan_id) as unknown as
      PartialPaymentRow[] : [];
    if (installments.length !== expected.length) return false;
    let paid = 0, scheduled = 0, prepaid = 0, seenUnpaid = false;
    let paidWithPartials = 0;
    for (let i = 0; i < installments.length; i++) {
      const row = installments[i]!, original = expected[i]!;
      if (row.installment_no !== original.number || row.due_date !== original.due_date ||
        row.opening_principal_cents !== original.opening_principal_cents ||
        row.principal_cents !== original.principal_cents ||
        row.interest_cents !== original.interest_cents ||
        row.payment_cents !== original.payment_cents ||
        row.closing_principal_cents !== original.closing_principal_cents) return false;
      const payment = payments.find((item) => item.installment_no === row.installment_no);
      const pieces = partials.filter((item) => item.installment_no === row.installment_no);
      const partialPaid = pieces.reduce((total, piece) =>
        total + piece.principal_cents + piece.interest_cents, 0);
      if (payment && pieces.length) return false;
      let cumulative = 0, interestCollected = 0, principalCollected = 0;
      for (const [index, piece] of pieces.entries()) {
        const charges = piece.late_fee_cents + piece.mora_cents;
        const paymentDate = accountingDates(piece.paid_at).posting_date;
        const previousDate = index ? accountingDates(pieces[index - 1]!.paid_at)
          .posting_date : undefined;
        const expectedCharges = assessPartialLoanCharges({ ...row,
          number: row.installment_no }, cumulative, paymentDate, previousDate);
        if (!Number.isSafeInteger(piece.amount_cents) || piece.amount_cents <= 0 ||
          !Number.isSafeInteger(piece.principal_cents) || piece.principal_cents < 0 ||
          !Number.isSafeInteger(piece.interest_cents) || piece.interest_cents < 0 ||
          !Number.isSafeInteger(charges) || charges < 0 ||
          piece.amount_cents !== piece.principal_cents + piece.interest_cents + charges ||
          piece.principal_cents + piece.interest_cents <= 0 ||
          paymentDate <= row.due_date ||
          piece.late_fee_cents !== expectedCharges.late_fee_cents ||
          piece.mora_cents !== expectedCharges.mora_cents) return false;
        const interestRemaining = row.interest_cents - interestCollected;
        if (piece.interest_cents !== Math.min(
          piece.principal_cents + piece.interest_cents, interestRemaining)) return false;
        cumulative += piece.principal_cents + piece.interest_cents;
        interestCollected += piece.interest_cents;
        principalCollected += piece.principal_cents;
        if (cumulative > row.payment_cents ||
          interestCollected > row.interest_cents ||
          principalCollected > row.principal_cents ||
          !matches(piece.principal_tx_id, contract.loan_id,
            piece.principal_cents ? [
              { accountId: contract.account_id, amount: -piece.principal_cents,
                kind: "loan_principal_repay" },
              { accountId: funding!.id, amount: piece.principal_cents,
                kind: "loan_principal_repay" },
            ] : []) ||
          !matches(piece.interest_tx_id, contract.loan_id,
            piece.interest_cents ? [
              { accountId: contract.account_id, amount: -piece.interest_cents,
                kind: "loan_interest_payment" },
              { accountId: interestReceivable?.id ?? "", amount: piece.interest_cents,
                kind: "loan_interest_payment" },
            ] : []) ||
          !matches(piece.charges_tx_id, contract.loan_id, charges ? [
            { accountId: contract.account_id, amount: -charges,
              kind: "loan_late_charges" },
            ...(piece.late_fee_cents ? [{ accountId: fees!.id,
              amount: piece.late_fee_cents, kind: "loan_late_fee" }] : []),
            ...(piece.mora_cents ? [{ accountId: fees!.id,
              amount: piece.mora_cents, kind: "loan_mora" }] : []),
          ] : [])) return false;
      }
      if (row.status === "scheduled") {
        scheduled++;
        if (payment || row.paid_cents !== partialPaid ||
          row.paid_cents >= row.payment_cents) return false;
      } else if (row.status === "prepaid") {
        prepaid++;
        if (row.paid_cents !== 0 || payment || pieces.length) return false;
      } else if (row.status === "paid") {
        if (seenUnpaid) return false;
        paid++;
        if (pieces.length) {
          paidWithPartials++;
          if (row.paid_cents !== row.payment_cents ||
            partialPaid !== row.payment_cents) return false;
        } else if (row.paid_cents !== row.payment_cents || !payment ||
          payment.principal_cents !== row.principal_cents ||
          payment.interest_cents !== row.interest_cents ||
          !Number.isSafeInteger(payment.late_fee_cents) || payment.late_fee_cents < 0 ||
          !Number.isSafeInteger(payment.mora_cents) || payment.mora_cents < 0 ||
          payment.amount_cents !== row.payment_cents + payment.late_fee_cents +
            payment.mora_cents) return false;
        if (payment && (!matches(payment.principal_tx_id, contract.loan_id, [
          { accountId: contract.account_id, amount: -row.principal_cents,
            kind: "loan_principal_repay" },
          { accountId: funding!.id, amount: row.principal_cents,
            kind: "loan_principal_repay" },
        ]) || !matches(payment.interest_tx_id, contract.loan_id,
          row.interest_cents ? [
            { accountId: contract.account_id, amount: -row.interest_cents,
              kind: "loan_interest_payment" },
            { accountId: accrued?.get(contract.loan_id, row.installment_no)
              ? interestReceivable?.id ?? "" : fees!.id, amount: row.interest_cents,
              kind: "loan_interest_payment" },
          ] : []) || !matches(payment.charges_tx_id, contract.loan_id,
          payment.late_fee_cents + payment.mora_cents ? [
            { accountId: contract.account_id,
              amount: -payment.late_fee_cents - payment.mora_cents,
              kind: "loan_late_charges" },
            ...(payment.late_fee_cents ? [{ accountId: fees!.id,
              amount: payment.late_fee_cents, kind: "loan_late_fee" }] : []),
            ...(payment.mora_cents ? [{ accountId: fees!.id,
              amount: payment.mora_cents, kind: "loan_mora" }] : []),
          ] : []))) return false;
      } else return false;
      if (row.status !== "paid") seenUnpaid = true;
    }
    if (payments.length !== paid - paidWithPartials ||
      (contract.status === "active" && (scheduled === 0 || prepaid > 0)) ||
      (contract.status === "settled" && paid !== installments.length) ||
      (["prepaid", "refinanced"].includes(contract.status) &&
        (scheduled > 0 || prepaid === 0)) ||
      !["active", "settled", "prepaid", "refinanced"].includes(contract.status)) return false;
    const repayTransactions = db.prepare(`SELECT DISTINCT tx_id FROM ledger_entries
      WHERE ref_type='loan' AND ref_id=? AND kind='loan_principal_repay'`)
      .all(contract.loan_id) as { tx_id: string }[];
    if (repayTransactions.length !== payments.length +
      partials.filter((piece) => piece.principal_cents > 0).length +
      (prepaid ? 1 : 0) ||
      payments.some((payment) => !repayTransactions.some((tx) =>
        tx.tx_id === payment.principal_tx_id)) ||
      partials.some((piece) => piece.principal_tx_id &&
        !repayTransactions.some((tx) => tx.tx_id === piece.principal_tx_id))) return false;
  }
  if (db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
    AND name='loan_renegotiations'`).get()) {
    const rows = db.prepare(`SELECT r.previous_loan_id,r.next_loan_id,r.payoff_cents,
      r.financed_fee_cents,r.renegotiated_at,p.customer_id previous_customer,
      n.customer_id next_customer,p.account_id previous_account,
      n.account_id next_account,p.status previous_status,n.principal_cents,
      n.fee_cents,n.started_at FROM loan_renegotiations r
      JOIN loans p ON p.id=r.previous_loan_id
      JOIN loans n ON n.id=r.next_loan_id`).all() as {
        previous_loan_id: string; next_loan_id: string; payoff_cents: number;
        financed_fee_cents: number; renegotiated_at: string;
        previous_customer: string; next_customer: string;
        previous_account: string; next_account: string;
        previous_status: string; principal_cents: number; fee_cents: number;
        started_at: string;
      }[];
    const count = (db.prepare("SELECT COUNT(*) n FROM loan_renegotiations").get() as
      { n: number }).n;
    if (rows.length !== count || rows.some((row) =>
      row.previous_loan_id === row.next_loan_id ||
      row.previous_customer !== row.next_customer ||
      row.previous_account !== row.next_account ||
      row.previous_status !== "refinanced" ||
      row.principal_cents - row.fee_cents !== row.payoff_cents ||
      row.fee_cents !== row.financed_fee_cents ||
      row.started_at !== row.renegotiated_at)) return false;
  }
  return true;
}
