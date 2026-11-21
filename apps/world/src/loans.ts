import { newId } from "./id.ts";
import { Bank, BankError } from "./bank.ts";
import { AuthEngine } from "./auth.ts";
import { FeatureRegistry } from "./features.ts";
import { DEVICE_QUARANTINE_V1, deviceQuarantine } from "./device-quarantine.ts";
import { accountingDates } from "./accounting-dates.ts";
import { installLoanProvisions } from "./loan-provisions.ts";
import { accrueLoanInterest, installLoanInterestAccruals, loanInterestAccrued } from "./loan-interest-accruals.ts";
import { buildLoanSchedule, SYNTHETIC_LOAN_POLICY_V1, assessLoanSchedule, assessPartialLoanCharges, type AmortizationMethod, type LoanInstallment } from "./loan-schedules.ts";
export interface LoanOffer {
    id: string;
    customer_id: string;
    max_amount_cents: number;
    rate_bps_month: number;
    expires_at: string;
    accepted_at: string | null;
}
export interface Loan {
    id: string;
    customer_id: string;
    account_id: string;
    offer_id: string;
    principal_cents: number;
    fee_cents: number;
    rebate_cents: number;
    status: "active" | "settled" | "prepaid" | "refinanced";
    started_at: string;
    due_at: string;
}
export interface LoanContract {
    loan_id: string;
    method: AmortizationMethod;
    term_months: number;
    rate_bps_month: number;
    policy_version: number;
    created_at: string;
}
export interface StoredLoanInstallment extends LoanInstallment {
    paid_cents: number;
    status: "scheduled" | "paid" | "prepaid";
}
interface PartialPaymentRow {
    id: string;
    installment_no: number;
    amount_cents: number;
    principal_cents: number;
    interest_cents: number;
    late_fee_cents: number;
    mora_cents: number;
    principal_tx_id: string | null;
    interest_tx_id: string | null;
    charges_tx_id: string | null;
    paid_at: string;
}
function roundHalfEven(numerator: number, denominator: number): number {
    const floor = Math.floor(numerator / denominator);
    const remainder = numerator % denominator;
    return remainder * 2 > denominator || (remainder * 2 === denominator && floor % 2 === 1) ? floor + 1 : floor;
}
export class LoansEngine {
    readonly bank: Bank;
    readonly features: FeatureRegistry;
    constructor(bank: Bank) {
        this.bank = bank;
        new AuthEngine(bank);
        this.features = new FeatureRegistry(bank);
        bank.db.exec(`CREATE TABLE IF NOT EXISTS loan_offers (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      max_amount_cents INTEGER NOT NULL, rate_bps_month INTEGER NOT NULL,
      expires_at TEXT NOT NULL, accepted_at TEXT, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS loan_offer_customer ON loan_offers(customer_id);
    CREATE TABLE IF NOT EXISTS loans (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      account_id TEXT NOT NULL REFERENCES accounts(id), offer_id TEXT NOT NULL REFERENCES loan_offers(id),
      principal_cents INTEGER NOT NULL, fee_cents INTEGER NOT NULL, rebate_cents INTEGER NOT NULL,
      status TEXT NOT NULL, started_at TEXT NOT NULL, due_at TEXT NOT NULL,
      disbursement_tx_id TEXT NOT NULL, initiating_device_id TEXT
    );
    CREATE INDEX IF NOT EXISTS loan_customer ON loans(customer_id,status);
    CREATE TABLE IF NOT EXISTS loan_rebates (
      id TEXT PRIMARY KEY, loan_id TEXT NOT NULL REFERENCES loans(id), amount_cents INTEGER NOT NULL,
      ledger_tx_id TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS loan_renegotiations (
      previous_loan_id TEXT PRIMARY KEY REFERENCES loans(id),
      next_loan_id TEXT NOT NULL UNIQUE REFERENCES loans(id),
      payoff_cents INTEGER NOT NULL CHECK(payoff_cents>0),
      financed_fee_cents INTEGER NOT NULL CHECK(financed_fee_cents>=0),
      renegotiated_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS loan_renegotiations_no_update
      BEFORE UPDATE ON loan_renegotiations
      BEGIN SELECT RAISE(ABORT,'LOAN_RENEGOTIATION_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS loan_renegotiations_no_delete
      BEFORE DELETE ON loan_renegotiations
      BEGIN SELECT RAISE(ABORT,'LOAN_RENEGOTIATION_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS loan_contracts (
      loan_id TEXT PRIMARY KEY REFERENCES loans(id),
      method TEXT NOT NULL CHECK(method IN ('PRICE','SAC')),
      term_months INTEGER NOT NULL CHECK(term_months BETWEEN 1 AND 360),
      rate_bps_month INTEGER NOT NULL CHECK(rate_bps_month BETWEEN 0 AND 10000),
      policy_version INTEGER NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS loan_installments (
      loan_id TEXT NOT NULL REFERENCES loan_contracts(loan_id),
      installment_no INTEGER NOT NULL CHECK(installment_no>=1),
      due_date TEXT NOT NULL,
      opening_principal_cents INTEGER NOT NULL,
      principal_cents INTEGER NOT NULL CHECK(principal_cents>=0),
      interest_cents INTEGER NOT NULL CHECK(interest_cents>=0),
      payment_cents INTEGER NOT NULL CHECK(payment_cents>=0),
      closing_principal_cents INTEGER NOT NULL,
      paid_cents INTEGER NOT NULL DEFAULT 0 CHECK(paid_cents>=0 AND paid_cents<=payment_cents),
      status TEXT NOT NULL DEFAULT 'scheduled' CHECK(status IN ('scheduled','paid','prepaid')),
      PRIMARY KEY(loan_id,installment_no)
    );
    CREATE TABLE IF NOT EXISTS loan_installment_payments (
      loan_id TEXT NOT NULL REFERENCES loans(id), installment_no INTEGER NOT NULL,
      amount_cents INTEGER NOT NULL, principal_cents INTEGER NOT NULL,
      interest_cents INTEGER NOT NULL, late_fee_cents INTEGER NOT NULL,
      mora_cents INTEGER NOT NULL, principal_tx_id TEXT NOT NULL,
      interest_tx_id TEXT, charges_tx_id TEXT, paid_at TEXT NOT NULL,
      PRIMARY KEY(loan_id,installment_no),
      FOREIGN KEY(loan_id,installment_no) REFERENCES loan_installments(loan_id,installment_no)
    );
    CREATE TABLE IF NOT EXISTS loan_installment_partial_payments (
      id TEXT PRIMARY KEY, loan_id TEXT NOT NULL REFERENCES loans(id),
      installment_no INTEGER NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      principal_cents INTEGER NOT NULL CHECK(principal_cents>=0),
      interest_cents INTEGER NOT NULL CHECK(interest_cents>=0),
      late_fee_cents INTEGER NOT NULL CHECK(late_fee_cents>=0),
      mora_cents INTEGER NOT NULL CHECK(mora_cents>=0),
      principal_tx_id TEXT, interest_tx_id TEXT, charges_tx_id TEXT,
      paid_at TEXT NOT NULL, idempotency_key TEXT,
      FOREIGN KEY(loan_id,installment_no) REFERENCES loan_installments(loan_id,installment_no)
    );
    CREATE INDEX IF NOT EXISTS loan_partial_installment_order
      ON loan_installment_partial_payments(loan_id,installment_no,paid_at,id);
    CREATE TRIGGER IF NOT EXISTS loan_installment_partial_payments_no_update
      BEFORE UPDATE ON loan_installment_partial_payments
      BEGIN SELECT RAISE(ABORT,'LOAN_PAYMENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS loan_installment_partial_payments_no_delete
      BEFORE DELETE ON loan_installment_partial_payments
      BEGIN SELECT RAISE(ABORT,'LOAN_PAYMENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS loan_contracts_no_update BEFORE UPDATE ON loan_contracts
      BEGIN SELECT RAISE(ABORT,'LOAN_CONTRACT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS loan_contracts_no_delete BEFORE DELETE ON loan_contracts
      BEGIN SELECT RAISE(ABORT,'LOAN_CONTRACT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS loan_installments_terms_immutable BEFORE UPDATE OF
      loan_id,installment_no,due_date,opening_principal_cents,principal_cents,
      interest_cents,payment_cents,closing_principal_cents ON loan_installments
      BEGIN SELECT RAISE(ABORT,'LOAN_SCHEDULE_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS loan_installments_no_delete BEFORE DELETE ON loan_installments
      BEGIN SELECT RAISE(ABORT,'LOAN_SCHEDULE_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS loan_installment_payments_no_update
      BEFORE UPDATE ON loan_installment_payments
      BEGIN SELECT RAISE(ABORT,'LOAN_PAYMENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS loan_installment_payments_no_delete
      BEFORE DELETE ON loan_installment_payments
      BEGIN SELECT RAISE(ABORT,'LOAN_PAYMENT_IMMUTABLE'); END;`);
        const loanColumns = bank.db.prepare("PRAGMA table_info(loans)").all() as {
            name: string;
        }[];
        if (!loanColumns.some((column) => column.name === "initiating_device_id"))
            bank.db.exec("ALTER TABLE loans ADD COLUMN initiating_device_id TEXT");
        bank.db.exec(`CREATE INDEX IF NOT EXISTS loan_recent_device
      ON loans(started_at,initiating_device_id,account_id)`);
        const partialColumns = bank.db.prepare(`PRAGMA table_info(loan_installment_partial_payments)`)
            .all() as {
            name: string;
        }[];
        if (!partialColumns.some((column) => column.name === "idempotency_key"))
            bank.db.exec(`ALTER TABLE loan_installment_partial_payments
        ADD COLUMN idempotency_key TEXT`);
        bank.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS loan_partial_idempotency
      ON loan_installment_partial_payments(loan_id,idempotency_key)
      WHERE idempotency_key IS NOT NULL`);
        installLoanProvisions(bank.db);
        installLoanInterestAccruals(bank.db);
    }
    private maxOfferAmount(customerId: string): number {
        const customer = this.bank.customer(customerId);
        const tierCap = customer.kyc_tier === 1 ? 200000 : customer.kyc_tier === 2 ? 800000 : 2500000;
        const profile = this.bank.risk.profile(customerId);
        const scoreFactor = Math.max(10, 100 - customer.risk_score);
        const tenureFactor = Math.min(100, Math.max(25, Math.floor(profile.tenure_days * 100 / 30)));
        const incomeCap = Math.min(tierCap, roundHalfEven(Math.min(profile.verified_income_cents, tierCap * 5) * scoreFactor * 2, 100));
        return roundHalfEven(incomeCap * tenureFactor, 100);
    }
    offer(customerId: string): LoanOffer {
        const customer = this.bank.customer(customerId);
        if (customer.status !== "active" || customer.kyc_tier < 1 ||
            customer.kyc_status !== "approved")
            throw new BankError("BIZ_LOAN_INELIGIBLE");
        const existing = this.bank.db.prepare(`SELECT id,customer_id,max_amount_cents,rate_bps_month,expires_at,accepted_at
      FROM loan_offers WHERE customer_id=? AND accepted_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1`)
            .get(customerId, this.bank.now().toISOString()) as LoanOffer | undefined;
        const maxAmount = this.maxOfferAmount(customerId);
        const rateBps = Math.min(890, 390 + customer.risk_score * 8);
        if (existing && existing.max_amount_cents === maxAmount && existing.rate_bps_month === rateBps)
            return existing;
        if (existing)
            this.bank.db.prepare("UPDATE loan_offers SET expires_at=? WHERE id=?")
                .run(this.bank.now().toISOString(), existing.id);
        const id = newId("offer", this.bank.now().getTime());
        const expiresAt = new Date(this.bank.now().getTime() + 7 * 86400000).toISOString();
        this.bank.db.prepare("INSERT INTO loan_offers VALUES (?,?,?,?,?,NULL,?)")
            .run(id, customerId, maxAmount, rateBps, expiresAt, this.bank.now().toISOString());
        return { id, customer_id: customerId, max_amount_cents: maxAmount, rate_bps_month: rateBps,
            expires_at: expiresAt, accepted_at: null };
    }
    loan(customerId: string, id: string): Loan {
        const row = this.bank.db.prepare(`SELECT id,customer_id,account_id,offer_id,principal_cents,fee_cents,
      rebate_cents,status,started_at,due_at FROM loans WHERE id=? AND customer_id=?`)
            .get(id, customerId) as Loan | undefined;
        if (!row)
            throw new BankError("DEF_NOT_FOUND");
        return row;
    }
    list(customerId: string): Loan[] {
        this.bank.customer(customerId);
        return this.bank.db.prepare(`SELECT id,customer_id,account_id,offer_id,
      principal_cents,fee_cents,rebate_cents,status,started_at,due_at
      FROM loans WHERE customer_id=? ORDER BY started_at DESC,id DESC`)
            .all(customerId) as unknown as Loan[];
    }
    quote(customerId: string, offerId: string, amountCents: number, terms: {
        method: AmortizationMethod;
        term_months: number;
    }): {
        principal_cents: number;
        fee_cents: number;
        rate_bps_month: number;
        total_installments_cents: number;
        installments: LoanInstallment[];
    } {
        if (!Number.isSafeInteger(amountCents) || amountCents <= 0 ||
            !["PRICE", "SAC"].includes(terms.method) ||
            !Number.isSafeInteger(terms.term_months) || terms.term_months < 1 ||
            terms.term_months > 60)
            throw new BankError("BIZ_LOAN_TERMS_INVALID");
        const offer = this.bank.db.prepare(`SELECT id,customer_id,max_amount_cents,
      rate_bps_month,expires_at,accepted_at FROM loan_offers WHERE id=?`)
            .get(offerId) as LoanOffer | undefined;
        if (!offer || offer.customer_id !== customerId)
            throw new BankError("DEF_NOT_FOUND");
        if (offer.accepted_at || Date.parse(offer.expires_at) <= this.bank.now().getTime())
            throw new BankError("BIZ_OFFER_EXPIRED");
        const customer = this.bank.customer(customerId);
        if (customer.status !== "active" || customer.kyc_tier < 1 ||
            customer.kyc_status !== "approved")
            throw new BankError("BIZ_LOAN_INELIGIBLE");
        if (amountCents > Math.min(offer.max_amount_cents, this.maxOfferAmount(customerId)))
            throw new BankError("BIZ_OFFER_AMOUNT");
        const installments = buildLoanSchedule({ principal_cents: amountCents,
            rate_bps_month: offer.rate_bps_month, term_months: terms.term_months,
            start_date: accountingDates(this.bank.now().toISOString()).posting_date,
            method: terms.method });
        if (installments.some((item) => item.principal_cents <= 0))
            throw new BankError("BIZ_LOAN_TERMS_INVALID");
        return { principal_cents: amountCents,
            fee_cents: roundHalfEven(amountCents * 2, 100),
            rate_bps_month: offer.rate_bps_month,
            total_installments_cents: installments.reduce((total, item) => total + item.payment_cents, 0), installments };
    }
    contract(customerId: string, loanId: string): {
        contract: LoanContract;
        installments: StoredLoanInstallment[];
    } | null {
        this.loan(customerId, loanId);
        const contract = this.bank.db.prepare("SELECT * FROM loan_contracts WHERE loan_id=?")
            .get(loanId) as LoanContract | undefined;
        if (!contract)
            return null;
        const rows = this.bank.db.prepare(`SELECT installment_no number,due_date,
      opening_principal_cents,principal_cents,interest_cents,payment_cents,
      closing_principal_cents,paid_cents,status FROM loan_installments
      WHERE loan_id=? ORDER BY installment_no`).all(loanId) as unknown as StoredLoanInstallment[];
        if (rows.length !== contract.term_months)
            throw new BankError("INTEGRITY_LOAN_SCHEDULE");
        return { contract, installments: rows };
    }
    accept(customerId: string, offerId: string, accountId: string, amountCents: number, declaredIncomeCents?: number, deviceId?: string, terms: {
        method: AmortizationMethod;
        term_months: number;
    } = { method: "PRICE", term_months: 12 }, replacesLoanId?: string): Loan {
        if (!Number.isSafeInteger(amountCents) || amountCents <= 0)
            throw new BankError("BIZ_INVALID_AMOUNT");
        if ((terms.method !== "PRICE" && terms.method !== "SAC") ||
            !Number.isSafeInteger(terms.term_months) || terms.term_months < 1 ||
            terms.term_months > 60)
            throw new BankError("BIZ_LOAN_TERMS_INVALID");
        const account = this.bank.ownAccount(customerId, accountId);
        const customer = this.bank.customer(customerId);
        if (account.status !== "active" || customer.status !== "active")
            throw new BankError("DEF_ACCOUNT_FROZEN");
        if (customer.kyc_tier < 1 || customer.kyc_status !== "approved")
            throw new BankError("BIZ_LOAN_INELIGIBLE");
        return this.bank.transaction(() => {
            if (deviceId !== undefined) {
                const device = deviceQuarantine(this.bank.db, customerId, deviceId, this.bank.now());
                if (!device)
                    throw new BankError("DEF_UNAUTHORIZED");
                if (device.quarantined && amountCents > DEVICE_QUARANTINE_V1.loan_amount_cents)
                    throw new BankError("BIZ_NEW_DEVICE_LIMIT");
            }
            const offer = this.bank.db.prepare(`SELECT id,customer_id,max_amount_cents,rate_bps_month,expires_at,accepted_at
        FROM loan_offers WHERE id=?`).get(offerId) as LoanOffer | undefined;
            if (!offer || offer.customer_id !== customerId)
                throw new BankError("DEF_NOT_FOUND");
            if (offer.accepted_at || Date.parse(offer.expires_at) <= this.bank.now().getTime())
                throw new BankError("BIZ_OFFER_EXPIRED");
            const active = (this.bank.db.prepare("SELECT COUNT(*) n FROM loans WHERE customer_id=? AND status='active'")
                .get(customerId) as {
                n: number;
            }).n;
            if (active > 0 && !(replacesLoanId && active === 1 &&
                this.bank.db.prepare(`SELECT 1 FROM loans WHERE id=? AND customer_id=?
          AND account_id=? AND status='active'`).get(replacesLoanId, customerId, accountId)))
                throw new BankError("BIZ_ACTIVE_LOAN");
            const allowed = Math.min(offer.max_amount_cents, this.maxOfferAmount(customerId));
            if (amountCents > allowed)
                throw new BankError("BIZ_OFFER_AMOUNT");
            const id = newId("loan", this.bank.now().getTime());
            const fee = roundHalfEven(amountCents * 2, 100);
            const now = this.bank.now();
            const schedule = buildLoanSchedule({ principal_cents: amountCents,
                rate_bps_month: offer.rate_bps_month, term_months: terms.term_months,
                start_date: accountingDates(now.toISOString()).posting_date, method: terms.method });
            if (schedule.some((installment) => installment.principal_cents <= 0))
                throw new BankError("BIZ_LOAN_TERMS_INVALID");
            const disbursementTxId = this.bank.post([
                { accountId: this.bank.systemAccountId("loan_funding"), amount: -amountCents, kind: "loan_disbursement", actor: customerId, refType: "loan", refId: id },
                { accountId, amount: amountCents, kind: "loan_disbursement", actor: customerId, refType: "loan", refId: id },
            ]);
            this.bank.post([
                { accountId, amount: -fee, kind: "loan_fee", actor: customerId, refType: "loan", refId: id },
                { accountId: this.bank.systemAccountId("fees"), amount: fee, kind: "loan_fee", actor: customerId, refType: "loan", refId: id },
            ]);
            const dueAt = `${schedule.at(-1)!.due_date}T12:00:00.000Z`;
            this.bank.db.prepare(`INSERT INTO loans
        (id,customer_id,account_id,offer_id,principal_cents,fee_cents,rebate_cents,
          status,started_at,due_at,disbursement_tx_id,initiating_device_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
                .run(id, customerId, accountId, offerId, amountCents, fee, 0, "active", now.toISOString(), dueAt, disbursementTxId, deviceId ?? null);
            this.bank.db.prepare("INSERT INTO loan_contracts VALUES (?,?,?,?,?,?)")
                .run(id, terms.method, terms.term_months, offer.rate_bps_month, SYNTHETIC_LOAN_POLICY_V1.version, now.toISOString());
            const insert = this.bank.db.prepare(`INSERT INTO loan_installments
        (loan_id,installment_no,due_date,opening_principal_cents,principal_cents,
          interest_cents,payment_cents,closing_principal_cents) VALUES (?,?,?,?,?,?,?,?)`);
            for (const installment of schedule)
                insert.run(id, installment.number, installment.due_date, installment.opening_principal_cents, installment.principal_cents, installment.interest_cents, installment.payment_cents, installment.closing_principal_cents);
            this.bank.db.prepare("UPDATE loan_offers SET accepted_at=? WHERE id=?").run(now.toISOString(), offerId);
            if (declaredIncomeCents !== undefined)
                this.bank.risk.recordDeclaredIncome(customerId, declaredIncomeCents);
            return this.loan(customerId, id);
        });
    }
    acceptFlash(customerId: string, accountId: string, deviceId: string, amountCents: number): Loan {
        if (!this.features.isEnabled("emprestimo_relampago"))
            throw new BankError("DEF_NOT_FOUND");
        if (!Number.isSafeInteger(amountCents) || amountCents <= 0 || amountCents > 100000)
            throw new BankError("BIZ_INVALID_AMOUNT");
        this.bank.ownAccount(customerId, accountId);
        const opened = this.bank.db.prepare("SELECT opened_at FROM accounts WHERE id=?").get(accountId) as {
            opened_at: string;
        };
        if (this.bank.now().getTime() - Date.parse(opened.opened_at) < 7 * 86400000)
            throw new BankError("BIZ_ACCOUNT_TOO_NEW");
        return this.bank.transaction(() => {
            {
                const decisionTime = this.bank.now();
                const device = deviceQuarantine(this.bank.db, customerId, deviceId, decisionTime);
                const trusted = this.bank.db.prepare(`SELECT trusted_at FROM auth_devices
          WHERE customer_id=? AND id=?`).get(customerId, deviceId) as {
                    trusted_at: string | null;
                } | undefined;
                const trustedAt = trusted?.trusted_at ? Date.parse(trusted.trusted_at) : NaN;
                if (!device || device.quarantined || !Number.isFinite(trustedAt) ||
                    trustedAt > decisionTime.getTime() ||
                    new Date(trustedAt).toISOString() !== trusted?.trusted_at)
                    throw new BankError("BIZ_DEVICE_COOLDOWN");
                const active = (this.bank.db.prepare("SELECT COUNT(*) n FROM loans WHERE customer_id=? AND status='active'")
                    .get(customerId) as {
                    n: number;
                }).n;
                if (active)
                    throw new BankError("BIZ_ACTIVE_LOAN");
            }
            const now = this.bank.now();
            const offerId = newId("offer_flash", this.bank.now().getTime());
            this.bank.db.prepare("INSERT INTO loan_offers VALUES (?,?,?,?,?,?,?)")
                .run(offerId, customerId, amountCents, 390, new Date(now.getTime() + 60000).toISOString(), now.toISOString(), now.toISOString());
            const loanId = newId("loan_flash", this.bank.now().getTime());
            const txId = this.bank.post([
                { accountId: this.bank.systemAccountId("loan_funding"), amount: -amountCents, kind: "flash_loan", actor: customerId, refType: "loan", refId: loanId },
                { accountId, amount: amountCents, kind: "flash_loan", actor: customerId, refType: "loan", refId: loanId },
            ]);
            this.bank.db.prepare(`INSERT INTO loans
        (id,customer_id,account_id,offer_id,principal_cents,fee_cents,rebate_cents,
          status,started_at,due_at,disbursement_tx_id,initiating_device_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
                .run(loanId, customerId, accountId, offerId, amountCents, 0, 0, "active", now.toISOString(), new Date(now.getTime() + 30 * 86400000).toISOString(), txId, deviceId);
            return this.loan(customerId, loanId);
        });
    }
    private remainingPrincipal(loanId: string, originalPrincipal: number): number {
        const contract = this.bank.db.prepare("SELECT 1 FROM loan_contracts WHERE loan_id=?")
            .get(loanId);
        if (!contract)
            return originalPrincipal;
        return (this.bank.db.prepare(`SELECT COALESCE(SUM(principal_cents),0) cents
      FROM loan_installments WHERE loan_id=? AND status='scheduled'`)
            .get(loanId) as {
            cents: number;
        }).cents;
    }
    private partialPayments(loanId: string, installmentNo: number): PartialPaymentRow[] {
        return this.bank.db.prepare(`SELECT id,installment_no,amount_cents,
      principal_cents,interest_cents,late_fee_cents,mora_cents,
      principal_tx_id,interest_tx_id,charges_tx_id,paid_at
      FROM loan_installment_partial_payments WHERE loan_id=? AND installment_no=?
      ORDER BY paid_at,id`).all(loanId, installmentNo) as unknown as PartialPaymentRow[];
    }
    private partialCharges(next: StoredLoanInstallment, asOf: string, parts: PartialPaymentRow[]): {
        late_fee_cents: number;
        mora_cents: number;
    } {
        const previousDate = parts.length ? accountingDates(parts.at(-1)!.paid_at)
            .posting_date : undefined;
        return assessPartialLoanCharges(next, next.paid_cents, asOf, previousDate);
    }
    payInstallmentAmount(customerId: string, loanId: string, installmentNo: number, amountCents: number, idempotencyKey?: string): {
        loan: Loan;
        installment: StoredLoanInstallment;
        amount_cents: number;
        late_fee_cents: number;
        mora_cents: number;
    } {
        if (!Number.isSafeInteger(installmentNo) || installmentNo < 1 ||
            !Number.isSafeInteger(amountCents) || amountCents <= 0 ||
            (idempotencyKey !== undefined && (!idempotencyKey ||
                idempotencyKey.length > 128)))
            throw new BankError("BIZ_LOAN_INSTALLMENT_INVALID");
        return this.bank.transaction(() => {
            const loan = this.loan(customerId, loanId);
            if (idempotencyKey) {
                const prior = this.bank.db.prepare(`SELECT installment_no,amount_cents,
          late_fee_cents,mora_cents FROM loan_installment_partial_payments
          WHERE loan_id=? AND idempotency_key=?`).get(loanId, idempotencyKey) as {
                    installment_no: number;
                    amount_cents: number;
                    late_fee_cents: number;
                    mora_cents: number;
                } | undefined;
                if (prior) {
                    if (prior.installment_no !== installmentNo ||
                        prior.amount_cents !== amountCents)
                        throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
                    return { loan, installment: this.contract(customerId, loanId)!
                            .installments[installmentNo - 1]!, amount_cents: prior.amount_cents,
                        late_fee_cents: prior.late_fee_cents, mora_cents: prior.mora_cents };
                }
            }
            if (loan.status !== "active")
                throw new BankError("BIZ_LOAN_NOT_ACTIVE");
            const stored = this.contract(customerId, loanId);
            if (!stored)
                throw new BankError("BIZ_LOAN_CONTRACT_LEGACY");
            const next = stored.installments.find((item) => item.status === "scheduled");
            if (!next || next.number !== installmentNo)
                throw new BankError("BIZ_LOAN_INSTALLMENT_ORDER");
            const asOf = accountingDates(this.bank.now().toISOString()).posting_date;
            if (asOf <= next.due_date)
                throw new BankError("BIZ_LOAN_PARTIAL_NOT_OVERDUE");
            const parts = this.partialPayments(loanId, installmentNo);
            if (parts.length && asOf < accountingDates(parts.at(-1)!.paid_at).posting_date)
                throw new BankError("BIZ_LOAN_PAYMENT_DATE_ORDER");
            if (this.bank.db.prepare(`SELECT 1 FROM loan_installment_payments
        WHERE loan_id=? AND installment_no=?`).get(loanId, installmentNo))
                throw new BankError("INTEGRITY_LOAN_PAYMENT");
            const charges = this.partialCharges(next, asOf, parts);
            const unpaid = next.payment_cents - next.paid_cents;
            const collectible = unpaid + charges.late_fee_cents + charges.mora_cents;
            if (amountCents > collectible)
                throw new BankError("BIZ_LOAN_PAYMENT_EXCESS");
            if (amountCents <= charges.late_fee_cents + charges.mora_cents)
                throw new BankError("BIZ_LOAN_PARTIAL_MIN_CHARGES");
            const account = this.bank.ownAccount(customerId, loan.account_id);
            if (account.status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            if (this.bank.availableBalance(loan.account_id) < amountCents)
                throw new BankError("BIZ_INSUFFICIENT_FUNDS");
            if (!loanInterestAccrued(this.bank.db, loanId, installmentNo) &&
                next.interest_cents > 0)
                accrueLoanInterest(this.bank, loanId, installmentNo, next.interest_cents, next.due_date);
            const applied = amountCents - charges.late_fee_cents - charges.mora_cents;
            const interestPaid = parts.reduce((total, part) => total + part.interest_cents, 0);
            const interest = Math.min(applied, next.interest_cents - interestPaid);
            const principal = applied - interest;
            if (interest < 0 || principal < 0 ||
                principal + parts.reduce((total, part) => total + part.principal_cents, 0) >
                    next.principal_cents)
                throw new BankError("INTEGRITY_LOAN_PAYMENT");
            const principalTx = principal ? this.bank.post([
                { accountId: loan.account_id, amount: -principal,
                    kind: "loan_principal_repay", actor: customerId, refType: "loan", refId: loanId },
                { accountId: this.bank.systemAccountId("loan_funding"), amount: principal,
                    kind: "loan_principal_repay", actor: customerId, refType: "loan", refId: loanId },
            ]) : null;
            const interestTx = interest ? this.bank.post([
                { accountId: loan.account_id, amount: -interest,
                    kind: "loan_interest_payment", actor: customerId, refType: "loan", refId: loanId },
                { accountId: this.bank.systemAccountId("loan_interest_receivable"), amount: interest,
                    kind: "loan_interest_payment", actor: customerId, refType: "loan", refId: loanId },
            ]) : null;
            const chargeTotal = charges.late_fee_cents + charges.mora_cents;
            const chargesTx = chargeTotal ? this.bank.post([
                { accountId: loan.account_id, amount: -chargeTotal,
                    kind: "loan_late_charges", actor: customerId, refType: "loan", refId: loanId },
                ...(charges.late_fee_cents ? [{ accountId: this.bank.systemAccountId("fees"),
                        amount: charges.late_fee_cents, kind: "loan_late_fee", actor: customerId,
                        refType: "loan", refId: loanId }] : []),
                ...(charges.mora_cents ? [{ accountId: this.bank.systemAccountId("fees"),
                        amount: charges.mora_cents, kind: "loan_mora", actor: customerId,
                        refType: "loan", refId: loanId }] : []),
            ]) : null;
            this.bank.db.prepare(`INSERT INTO loan_installment_partial_payments
        (id,loan_id,installment_no,amount_cents,principal_cents,interest_cents,
          late_fee_cents,mora_cents,principal_tx_id,interest_tx_id,charges_tx_id,paid_at,
          idempotency_key)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(newId("loan_payment", this.bank.now().getTime()), loanId, installmentNo, amountCents, principal, interest, charges.late_fee_cents, charges.mora_cents, principalTx, interestTx, chargesTx, this.bank.now().toISOString(), idempotencyKey ?? null);
            this.bank.db.prepare(`UPDATE loan_installments SET
        paid_cents=paid_cents+?,status=CASE WHEN paid_cents+?=payment_cents
          THEN 'paid' ELSE 'scheduled' END
        WHERE loan_id=? AND installment_no=? AND status='scheduled'`)
                .run(applied, applied, loanId, installmentNo);
            if (!this.bank.db.prepare(`SELECT 1 FROM loan_installments
        WHERE loan_id=? AND status='scheduled' LIMIT 1`).get(loanId))
                this.bank.db.prepare("UPDATE loans SET status='settled' WHERE id=?").run(loanId);
            return { loan: this.loan(customerId, loanId),
                installment: this.contract(customerId, loanId)!.installments[installmentNo - 1]!,
                amount_cents: amountCents, late_fee_cents: charges.late_fee_cents,
                mora_cents: charges.mora_cents };
        });
    }
    payInstallment(customerId: string, loanId: string, installmentNo: number): {
        loan: Loan;
        installment: StoredLoanInstallment;
        amount_cents: number;
        late_fee_cents: number;
        mora_cents: number;
    } {
        if (!Number.isSafeInteger(installmentNo) || installmentNo < 1)
            throw new BankError("BIZ_LOAN_INSTALLMENT_INVALID");
        return this.bank.transaction(() => {
            const loan = this.loan(customerId, loanId);
            if (loan.status !== "active")
                throw new BankError("BIZ_LOAN_NOT_ACTIVE");
            const stored = this.contract(customerId, loanId);
            if (!stored)
                throw new BankError("BIZ_LOAN_CONTRACT_LEGACY");
            const next = stored.installments.find((item) => item.status === "scheduled");
            if (!next || next.number !== installmentNo)
                throw new BankError("BIZ_LOAN_INSTALLMENT_ORDER");
            const asOf = accountingDates(this.bank.now().toISOString()).posting_date;
            const parts = this.partialPayments(loanId, installmentNo);
            if (parts.length) {
                const charges = this.partialCharges(next, asOf, parts);
                return this.payInstallmentAmount(customerId, loanId, installmentNo, next.payment_cents - next.paid_cents + charges.late_fee_cents +
                    charges.mora_cents);
            }
            const assessed = assessLoanSchedule(stored.installments, stored.installments.map((item) => item.paid_cents), asOf)
                .installments[installmentNo - 1]!;
            const total = assessed.collectible_cents;
            const account = this.bank.ownAccount(customerId, loan.account_id);
            if (account.status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            if (this.bank.availableBalance(loan.account_id) < total)
                throw new BankError("BIZ_INSUFFICIENT_FUNDS");
            const principalTx = this.bank.post([
                { accountId: loan.account_id, amount: -next.principal_cents,
                    kind: "loan_principal_repay", actor: customerId, refType: "loan", refId: loanId },
                { accountId: this.bank.systemAccountId("loan_funding"), amount: next.principal_cents,
                    kind: "loan_principal_repay", actor: customerId, refType: "loan", refId: loanId },
            ]);
            if (next.interest_cents > 0 && asOf > next.due_date)
                accrueLoanInterest(this.bank, loanId, installmentNo, next.interest_cents, next.due_date);
            const interestAccount = loanInterestAccrued(this.bank.db, loanId, installmentNo)
                ? this.bank.systemAccountId("loan_interest_receivable")
                : this.bank.systemAccountId("fees");
            const interestTx = next.interest_cents > 0 ? this.bank.post([
                { accountId: loan.account_id, amount: -next.interest_cents,
                    kind: "loan_interest_payment", actor: customerId, refType: "loan", refId: loanId },
                { accountId: interestAccount, amount: next.interest_cents,
                    kind: "loan_interest_payment", actor: customerId, refType: "loan", refId: loanId },
            ]) : null;
            const charges = assessed.late_fee_cents + assessed.mora_cents;
            const chargesTx = charges > 0 ? this.bank.post([
                { accountId: loan.account_id, amount: -charges,
                    kind: "loan_late_charges", actor: customerId, refType: "loan", refId: loanId },
                ...(assessed.late_fee_cents > 0 ? [{ accountId: this.bank.systemAccountId("fees"),
                        amount: assessed.late_fee_cents, kind: "loan_late_fee", actor: customerId,
                        refType: "loan", refId: loanId }] : []),
                ...(assessed.mora_cents > 0 ? [{ accountId: this.bank.systemAccountId("fees"),
                        amount: assessed.mora_cents, kind: "loan_mora", actor: customerId,
                        refType: "loan", refId: loanId }] : []),
            ]) : null;
            this.bank.db.prepare(`INSERT INTO loan_installment_payments VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
                .run(loanId, installmentNo, total, next.principal_cents, next.interest_cents, assessed.late_fee_cents, assessed.mora_cents, principalTx, interestTx, chargesTx, this.bank.now().toISOString());
            this.bank.db.prepare(`UPDATE loan_installments SET paid_cents=payment_cents,status='paid'
        WHERE loan_id=? AND installment_no=? AND status='scheduled'`).run(loanId, installmentNo);
            if (!this.bank.db.prepare(`SELECT 1 FROM loan_installments
        WHERE loan_id=? AND status='scheduled' LIMIT 1`).get(loanId))
                this.bank.db.prepare("UPDATE loans SET status='settled' WHERE id=?").run(loanId);
            return { loan: this.loan(customerId, loanId),
                installment: this.contract(customerId, loanId)!.installments[installmentNo - 1]!,
                amount_cents: total, late_fee_cents: assessed.late_fee_cents,
                mora_cents: assessed.mora_cents };
        });
    }
    prepay(customerId: string, loanId: string): {
        loan: Loan;
        rebate_cents: number;
    } {
        return this.bank.transaction(() => {
            const loan = this.loan(customerId, loanId);
            if (loan.status !== "active")
                throw new BankError("BIZ_LOAN_NOT_ACTIVE");
            if (loan.status === "active") {
                const contract = this.contract(customerId, loanId);
                const asOf = accountingDates(this.bank.now().toISOString()).posting_date;
                if (contract?.installments.some((item) => item.status === "scheduled" &&
                    item.due_date <= asOf))
                    throw new BankError("BIZ_LOAN_DUE_INSTALLMENT");
                const remaining = this.remainingPrincipal(loanId, loan.principal_cents);
                if (remaining <= 0)
                    throw new BankError("INTEGRITY_LOAN_PRINCIPAL");
                if (this.bank.availableBalance(loan.account_id) < remaining)
                    throw new BankError("BIZ_INSUFFICIENT_FUNDS");
                this.bank.post([
                    { accountId: loan.account_id, amount: -remaining, kind: "loan_principal_repay", actor: customerId, refType: "loan", refId: loanId },
                    { accountId: this.bank.systemAccountId("loan_funding"), amount: remaining, kind: "loan_principal_repay", actor: customerId, refType: "loan", refId: loanId },
                ]);
            }
            const unusedDays = Math.max(0, Math.ceil((Date.parse(loan.due_at) - this.bank.now().getTime()) / 86400000));
            const rebate = Math.min(loan.fee_cents - loan.rebate_cents, roundHalfEven(loan.fee_cents * unusedDays, 365));
            if (rebate > 0) {
                const txId = this.bank.post([
                    { accountId: this.bank.systemAccountId("fees"), amount: -rebate, kind: "loan_rebate", actor: customerId, refType: "loan", refId: loanId },
                    { accountId: loan.account_id, amount: rebate, kind: "loan_rebate", actor: customerId, refType: "loan", refId: loanId },
                ]);
                this.bank.db.prepare("INSERT INTO loan_rebates VALUES (?,?,?,?,?)")
                    .run(newId("rebate", this.bank.now().getTime()), loanId, rebate, txId, this.bank.now().toISOString());
            }
            this.bank.db.prepare(`UPDATE loan_installments SET status='prepaid'
        WHERE loan_id=? AND status='scheduled'`).run(loanId);
            this.bank.db.prepare("UPDATE loans SET status='prepaid',rebate_cents=rebate_cents+? WHERE id=?").run(rebate, loanId);
            return { loan: this.loan(customerId, loanId), rebate_cents: rebate };
        });
    }
    refinance(customerId: string, loanId: string, deviceId?: string): {
        previous: Loan;
        next: Loan;
    } {
        return this.bank.transaction(() => {
            const previous = this.loan(customerId, loanId);
            if (previous.status !== "active")
                throw new BankError("BIZ_LOAN_NOT_ACTIVE");
            const remaining = this.remainingPrincipal(loanId, previous.principal_cents);
            const prepaid = this.prepay(customerId, loanId).loan;
            const offer = this.offer(customerId);
            const next = this.accept(customerId, offer.id, previous.account_id, Math.min(remaining, offer.max_amount_cents), undefined, deviceId);
            this.bank.db.prepare("UPDATE loans SET status='refinanced' WHERE id=?").run(loanId);
            return { previous: { ...prepaid, status: "refinanced" }, next };
        });
    }
    renegotiationQuote(customerId: string, loanId: string, terms: {
        method: AmortizationMethod;
        term_months: number;
    }): {
        offer_id: string;
        payoff_cents: number;
        financed_fee_cents: number;
        new_principal_cents: number;
        total_installments_cents: number;
        installments: LoanInstallment[];
        due_installment_numbers: number[];
    } {
        const previous = this.loan(customerId, loanId);
        if (previous.status !== "active")
            throw new BankError("BIZ_LOAN_NOT_ACTIVE");
        const stored = this.contract(customerId, loanId);
        if (!stored)
            throw new BankError("BIZ_LOAN_CONTRACT_LEGACY");
        const asOf = accountingDates(this.bank.now().toISOString()).posting_date;
        const due = stored.installments.filter((item) => item.status === "scheduled" &&
            item.due_date <= asOf);
        if (!due.some((item) => item.due_date < asOf))
            throw new BankError("BIZ_LOAN_NOT_OVERDUE");
        const assessment = assessLoanSchedule(stored.installments, stored.installments.map((item) => item.paid_cents), asOf);
        const dueTotal = due.reduce((total, item) => {
            const parts = this.partialPayments(loanId, item.number);
            if (!parts.length)
                return total +
                    assessment.installments[item.number - 1]!.collectible_cents;
            const charges = this.partialCharges(item, asOf, parts);
            return total + item.payment_cents - item.paid_cents +
                charges.late_fee_cents + charges.mora_cents;
        }, 0);
        const futurePrincipal = stored.installments.filter((item) => item.status === "scheduled" && item.due_date > asOf)
            .reduce((total, item) => total + item.principal_cents, 0);
        const payoff = dueTotal + futurePrincipal;
        if (!Number.isSafeInteger(payoff) || payoff <= 0)
            throw new BankError("INTEGRITY_LOAN_PRINCIPAL");
        // Capitalize the origination fee so repayment never requires pre-existing cash.
        let principal = Math.ceil(payoff * 100 / 98);
        while (principal - roundHalfEven(principal * 2, 100) > payoff)
            principal--;
        while (principal - roundHalfEven(principal * 2, 100) < payoff)
            principal++;
        if (principal - roundHalfEven(principal * 2, 100) !== payoff)
            throw new BankError("BIZ_LOAN_RENEGOTIATION_AMOUNT");
        const offer = this.offer(customerId);
        const quoted = this.quote(customerId, offer.id, principal, terms);
        return { offer_id: offer.id, payoff_cents: payoff,
            financed_fee_cents: principal - payoff, new_principal_cents: principal,
            total_installments_cents: quoted.total_installments_cents,
            installments: quoted.installments,
            due_installment_numbers: due.map((item) => item.number) };
    }
    renegotiate(customerId: string, loanId: string, deviceId?: string, terms: {
        method: AmortizationMethod;
        term_months: number;
    } = { method: "PRICE", term_months: 12 }): {
        previous: Loan;
        next: Loan;
        payoff_cents: number;
        financed_fee_cents: number;
    } {
        return this.bank.transaction(() => {
            const previous = this.loan(customerId, loanId);
            const existing = this.bank.db.prepare(`SELECT next_loan_id,payoff_cents,
        financed_fee_cents FROM loan_renegotiations WHERE previous_loan_id=?`)
                .get(loanId) as {
                next_loan_id: string;
                payoff_cents: number;
                financed_fee_cents: number;
            } | undefined;
            if (existing) {
                const nextTerms = this.contract(customerId, existing.next_loan_id)?.contract;
                if (!nextTerms || nextTerms.method !== terms.method ||
                    nextTerms.term_months !== terms.term_months)
                    throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
                return { previous, next: this.loan(customerId, existing.next_loan_id),
                    payoff_cents: existing.payoff_cents,
                    financed_fee_cents: existing.financed_fee_cents };
            }
            if (previous.status !== "active")
                throw new BankError("BIZ_LOAN_NOT_ACTIVE");
            const quoted = this.renegotiationQuote(customerId, loanId, terms);
            const next = this.accept(customerId, quoted.offer_id, previous.account_id, quoted.new_principal_cents, undefined, deviceId, terms, loanId);
            for (const number of quoted.due_installment_numbers)
                this.payInstallment(customerId, loanId, number);
            const prepaid = this.prepay(customerId, loanId).loan;
            this.bank.db.prepare("UPDATE loans SET status='refinanced' WHERE id=?").run(loanId);
            this.bank.db.prepare(`INSERT INTO loan_renegotiations
        (previous_loan_id,next_loan_id,payoff_cents,financed_fee_cents,renegotiated_at)
        VALUES (?,?,?,?,?)`).run(loanId, next.id, quoted.payoff_cents, quoted.financed_fee_cents, this.bank.now().toISOString());
            return { previous: { ...prepaid, status: "refinanced" }, next,
                payoff_cents: quoted.payoff_cents,
                financed_fee_cents: quoted.financed_fee_cents };
        });
    }
    rebateDrift(): number {
        return (this.bank.db.prepare(`SELECT COUNT(*) n FROM loans l LEFT JOIN
      (SELECT loan_id,SUM(amount_cents) total FROM loan_rebates GROUP BY loan_id) r ON r.loan_id=l.id
      WHERE l.rebate_cents<>COALESCE(r.total,0) OR COALESCE(r.total,0)>l.fee_cents`).get() as {
            n: number;
        }).n;
    }
}
