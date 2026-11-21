import { newId } from "./id.ts";
import { Bank, BankError } from "./bank.ts";

/** Versioned simulation rates in basis points. These are not regulatory defaults. */
export interface CreditCardPolicy {
  version: 1;
  minimum_payment_bps: number;
  revolving_daily_interest_bps: number;
  fixed_iof_bps: number;
  daily_iof_bps: number;
  invoice_plan_interest_bps: number; // Flat charge on the financed principal.
  due_days: number;
}

export const SYNTHETIC_CREDIT_CARD_POLICY_V1: CreditCardPolicy = Object.freeze({
  version: 1,
  minimum_payment_bps: 1_500,
  revolving_daily_interest_bps: 10,
  fixed_iof_bps: 30,
  daily_iof_bps: 1,
  invoice_plan_interest_bps: 250,
  due_days: 10,
});

export interface CreditCardAccount {
  id: string;
  customer_id: string;
  limit_cents: number;
  closing_day: number;
  status: "active" | "blocked";
  pending_credit_cents: number;
  opened_at: string;
  policy_json: string;
}

export interface CreditCardPurchase {
  id: string;
  credit_id: string;
  merchant_id: string;
  amount_cents: number;
  installment_count: number;
  refunded_cents: number;
  ledger_tx_id: string;
  created_at: string;
  network_authorization_id: string | null;
}

export interface CreditCardStatement {
  id: string;
  credit_id: string;
  closing_date: string;
  due_date: string;
  purchases_cents: number;
  plan_cents: number;
  carryover_cents: number;
  credit_applied_cents: number;
  refund_credit_cents: number;
  interest_cents: number;
  iof_cents: number;
  due_cents: number;
  paid_cents: number;
  minimum_due_cents: number;
  status: "open" | "paid" | "carried" | "financed";
  last_assessed_date: string | null;
  closed_at: string;
}

const saoPaulo = new Intl.DateTimeFormat("en-US", { timeZone: "America/Sao_Paulo",
  year: "numeric", month: "2-digit", day: "2-digit" });
function civilDate(instant: Date): string {
  if (!Number.isFinite(instant.getTime())) throw new BankError("BIZ_INVALID_DATE");
  const parts = saoPaulo.formatToParts(instant);
  const part = (name: string): string => parts.find((item) => item.type === name)?.value ?? "";
  return `${part("year")}-${part("month")}-${part("day")}`;
}
function addDays(date: string, days: number): string {
  const result = new Date(`${date}T12:00:00.000Z`);
  result.setUTCDate(result.getUTCDate() + days);
  return result.toISOString().slice(0, 10);
}
function monthClose(date: string, closingDay: number, offset = 0): string {
  const [yearText, monthText] = date.split("-");
  const year = Number(yearText), month = Number(monthText);
  const monthStart = new Date(Date.UTC(year, month - 1 + offset, 1));
  return `${monthStart.getUTCFullYear()}-${String(monthStart.getUTCMonth() + 1).padStart(2, "0")}-${String(closingDay).padStart(2, "0")}`;
}
function money(value: number): boolean { return Number.isSafeInteger(value) && value > 0; }
function roundedBps(amount: number, bps: number): number {
  const result = Math.round(amount * bps / 10_000);
  if (!Number.isSafeInteger(result)) throw new BankError("BIZ_AMOUNT_RANGE");
  return result;
}
function policyValid(policy: CreditCardPolicy): boolean {
  if (!policy || typeof policy !== "object") return false;
  const bps = [policy.minimum_payment_bps, policy.revolving_daily_interest_bps,
    policy.fixed_iof_bps, policy.daily_iof_bps, policy.invoice_plan_interest_bps];
  return policy.version === 1 && bps.every((value) => Number.isSafeInteger(value) && value >= 0 && value <= 10_000) &&
    policy.minimum_payment_bps > 0 && Number.isSafeInteger(policy.due_days) &&
    policy.due_days >= 1 && policy.due_days <= 25;
}

export class CreditCardsEngine {
  readonly bank: Bank;
  readonly policy: CreditCardPolicy;
  constructor(bank: Bank, policy: CreditCardPolicy) {
    if (!policyValid(policy)) throw new BankError("BIZ_CREDIT_POLICY_INVALID");
    this.bank = bank;
    this.policy = { ...policy };
    bank.db.exec(`CREATE TABLE IF NOT EXISTS credit_card_accounts (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      limit_cents INTEGER NOT NULL CHECK(limit_cents>0),
      closing_day INTEGER NOT NULL CHECK(closing_day BETWEEN 1 AND 28),
      status TEXT NOT NULL CHECK(status IN ('active','blocked')),
      pending_credit_cents INTEGER NOT NULL DEFAULT 0 CHECK(pending_credit_cents>=0),
      opened_at TEXT NOT NULL, policy_json TEXT NOT NULL CHECK(json_valid(policy_json))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS credit_card_customer ON credit_card_accounts(customer_id);
    CREATE TABLE IF NOT EXISTS credit_card_purchases (
      id TEXT PRIMARY KEY, credit_id TEXT NOT NULL REFERENCES credit_card_accounts(id),
      merchant_id TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      installment_count INTEGER NOT NULL CHECK(installment_count BETWEEN 1 AND 24),
      refunded_cents INTEGER NOT NULL DEFAULT 0 CHECK(refunded_cents>=0 AND refunded_cents<=amount_cents),
      ledger_tx_id TEXT NOT NULL, created_at TEXT NOT NULL,
      network_authorization_id TEXT UNIQUE
    );
    CREATE INDEX IF NOT EXISTS credit_card_purchases_account ON credit_card_purchases(credit_id,created_at);
    CREATE TABLE IF NOT EXISTS credit_card_statements (
      id TEXT PRIMARY KEY, credit_id TEXT NOT NULL REFERENCES credit_card_accounts(id),
      closing_date TEXT NOT NULL, due_date TEXT NOT NULL,
      purchases_cents INTEGER NOT NULL CHECK(purchases_cents>=0),
      plan_cents INTEGER NOT NULL DEFAULT 0 CHECK(plan_cents>=0),
      carryover_cents INTEGER NOT NULL CHECK(carryover_cents>=0),
      credit_applied_cents INTEGER NOT NULL CHECK(credit_applied_cents>=0),
      refund_credit_cents INTEGER NOT NULL DEFAULT 0 CHECK(refund_credit_cents>=0),
      interest_cents INTEGER NOT NULL DEFAULT 0 CHECK(interest_cents>=0),
      iof_cents INTEGER NOT NULL DEFAULT 0 CHECK(iof_cents>=0),
      due_cents INTEGER NOT NULL CHECK(due_cents>=0),
      paid_cents INTEGER NOT NULL DEFAULT 0 CHECK(paid_cents>=0 AND paid_cents<=due_cents),
      minimum_due_cents INTEGER NOT NULL CHECK(minimum_due_cents>=0),
      status TEXT NOT NULL CHECK(status IN ('open','paid','carried','financed')),
      last_assessed_date TEXT, closed_at TEXT NOT NULL,
      UNIQUE(credit_id,closing_date)
    );
    CREATE INDEX IF NOT EXISTS credit_card_statements_account ON credit_card_statements(credit_id,closing_date);
    CREATE TABLE IF NOT EXISTS credit_card_installments (
      purchase_id TEXT NOT NULL REFERENCES credit_card_purchases(id),
      installment_no INTEGER NOT NULL CHECK(installment_no>0),
      closing_date TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      statement_id TEXT REFERENCES credit_card_statements(id),
      PRIMARY KEY(purchase_id,installment_no)
    );
    CREATE INDEX IF NOT EXISTS credit_card_installments_due ON credit_card_installments(closing_date,statement_id);
    CREATE TABLE IF NOT EXISTS credit_card_invoice_plans (
      id TEXT PRIMARY KEY, credit_id TEXT NOT NULL REFERENCES credit_card_accounts(id),
      source_statement_id TEXT NOT NULL UNIQUE REFERENCES credit_card_statements(id),
      principal_cents INTEGER NOT NULL CHECK(principal_cents>0),
      interest_cents INTEGER NOT NULL CHECK(interest_cents>=0),
      installment_count INTEGER NOT NULL CHECK(installment_count BETWEEN 2 AND 24),
      fee_ledger_tx_id TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS credit_card_invoice_plan_installments (
      plan_id TEXT NOT NULL REFERENCES credit_card_invoice_plans(id),
      installment_no INTEGER NOT NULL CHECK(installment_no>0),
      closing_date TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      statement_id TEXT REFERENCES credit_card_statements(id),
      PRIMARY KEY(plan_id,installment_no)
    );
    CREATE INDEX IF NOT EXISTS credit_card_plan_installments_due
      ON credit_card_invoice_plan_installments(closing_date,statement_id);
    CREATE TABLE IF NOT EXISTS credit_card_payments (
      id TEXT PRIMARY KEY, credit_id TEXT NOT NULL REFERENCES credit_card_accounts(id),
      statement_id TEXT NOT NULL REFERENCES credit_card_statements(id),
      source_account_id TEXT NOT NULL REFERENCES accounts(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      ledger_tx_id TEXT NOT NULL, created_at TEXT NOT NULL,
      idempotency_key TEXT
    );
    CREATE TABLE IF NOT EXISTS credit_card_refunds (
      id TEXT PRIMARY KEY, credit_id TEXT NOT NULL REFERENCES credit_card_accounts(id),
      purchase_id TEXT NOT NULL REFERENCES credit_card_purchases(id),
      statement_id TEXT REFERENCES credit_card_statements(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      statement_credit_cents INTEGER NOT NULL CHECK(statement_credit_cents>=0),
      pending_credit_cents INTEGER NOT NULL CHECK(pending_credit_cents>=0),
      ledger_tx_id TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS credit_card_accruals (
      id TEXT PRIMARY KEY, credit_id TEXT NOT NULL REFERENCES credit_card_accounts(id),
      statement_id TEXT NOT NULL REFERENCES credit_card_statements(id),
      assessed_date TEXT NOT NULL, principal_cents INTEGER NOT NULL CHECK(principal_cents>0),
      interest_cents INTEGER NOT NULL CHECK(interest_cents>=0),
      iof_cents INTEGER NOT NULL CHECK(iof_cents>=0),
      ledger_tx_id TEXT, UNIQUE(statement_id,assessed_date)
    );
    CREATE TABLE IF NOT EXISTS credit_card_network_holds (
      authorization_id TEXT PRIMARY KEY,
      credit_id TEXT NOT NULL REFERENCES credit_card_accounts(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      expires_at TEXT NOT NULL,
      released_at TEXT
    );
    CREATE INDEX IF NOT EXISTS credit_card_holds_active
      ON credit_card_network_holds(credit_id,released_at,expires_at);
    CREATE TRIGGER IF NOT EXISTS credit_card_payments_no_update
      BEFORE UPDATE ON credit_card_payments BEGIN SELECT RAISE(ABORT,'CREDIT_PAYMENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS credit_card_payments_no_delete
      BEFORE DELETE ON credit_card_payments BEGIN SELECT RAISE(ABORT,'CREDIT_PAYMENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS credit_card_refunds_no_update
      BEFORE UPDATE ON credit_card_refunds BEGIN SELECT RAISE(ABORT,'CREDIT_REFUND_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS credit_card_refunds_no_delete
      BEFORE DELETE ON credit_card_refunds BEGIN SELECT RAISE(ABORT,'CREDIT_REFUND_IMMUTABLE'); END;`);
    const paymentColumns = bank.db.prepare("PRAGMA table_info(credit_card_payments)")
      .all() as { name: string }[];
    if (!paymentColumns.some((column) => column.name === "idempotency_key"))
      bank.db.exec("ALTER TABLE credit_card_payments ADD COLUMN idempotency_key TEXT");
    const purchaseColumns = bank.db.prepare("PRAGMA table_info(credit_card_purchases)")
      .all() as { name: string }[];
    if (!purchaseColumns.some((column) => column.name === "network_authorization_id"))
      bank.db.exec("ALTER TABLE credit_card_purchases ADD COLUMN network_authorization_id TEXT");
    bank.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS credit_card_purchase_network_auth
      ON credit_card_purchases(network_authorization_id)
      WHERE network_authorization_id IS NOT NULL`);
    bank.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS credit_card_payment_idempotency
      ON credit_card_payments(credit_id,idempotency_key) WHERE idempotency_key IS NOT NULL`);
  }

  account(customerId: string, id: string): CreditCardAccount {
    const row = this.bank.db.prepare("SELECT * FROM credit_card_accounts WHERE id=? AND customer_id=?")
      .get(id, customerId) as CreditCardAccount | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    return row;
  }

  list(customerId: string): CreditCardAccount[] {
    this.bank.customer(customerId);
    return this.bank.db.prepare(`SELECT * FROM credit_card_accounts
      WHERE customer_id=? ORDER BY opened_at,id`).all(customerId) as unknown as CreditCardAccount[];
  }

  statements(customerId: string, creditId: string): CreditCardStatement[] {
    this.account(customerId, creditId);
    return this.bank.db.prepare(`SELECT * FROM credit_card_statements
      WHERE credit_id=? ORDER BY closing_date DESC,id DESC`).all(creditId) as unknown as CreditCardStatement[];
  }

  statement(customerId: string, id: string): CreditCardStatement {
    const row = this.bank.db.prepare(`SELECT s.* FROM credit_card_statements s
      JOIN credit_card_accounts a ON a.id=s.credit_id
      WHERE s.id=? AND a.customer_id=?`).get(id, customerId) as CreditCardStatement | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    return row;
  }

  open(customerId: string, limitCents: number, closingDay: number): CreditCardAccount {
    if (!money(limitCents) || limitCents > 20_000_000 ||
      !Number.isSafeInteger(closingDay) || closingDay < 1 || closingDay > 28)
      throw new BankError("BIZ_INVALID_LIMIT");
    return this.bank.transaction(() => {
      const customer = this.bank.customer(customerId);
      if (customer.status !== "active" || customer.kyc_status !== "approved")
        throw new BankError("BIZ_CREDIT_INELIGIBLE");
      const existing = this.bank.db.prepare("SELECT 1 FROM credit_card_accounts WHERE customer_id=?")
        .get(customerId);
      if (existing) throw new BankError("BIZ_CREDIT_ACCOUNT_EXISTS");
      const id = newId("credit", this.bank.now().getTime());
      this.bank.db.prepare("INSERT INTO credit_card_accounts VALUES (?,?,?,?,?,0,?,?)")
        .run(id, customerId, limitCents, closingDay, "active", this.bank.now().toISOString(),
          JSON.stringify(this.policy));
      return this.account(customerId, id);
    });
  }

  outstanding(customerId: string, creditId: string): number {
    this.account(customerId, creditId);
    const row = this.bank.db.prepare(`SELECT COALESCE(SUM(-amount),0) cents FROM ledger_entries
      WHERE account_id=? AND ref_type='credit_card' AND ref_id=?`)
      .get(this.bank.systemAccountId("card_settlement"), creditId) as { cents: number };
    if (!Number.isSafeInteger(row.cents)) throw new BankError("INTEGRITY_CREDIT_BALANCE");
    return row.cents;
  }

  availableLimit(customerId: string, creditId: string): number {
    const account = this.account(customerId, creditId);
    const held = this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) cents
      FROM credit_card_network_holds WHERE credit_id=? AND released_at IS NULL AND expires_at>?`)
      .get(creditId, this.bank.now().toISOString()) as { cents: number };
    return Math.max(0, account.limit_cents - Math.max(0, this.outstanding(customerId, creditId)) - held.cents);
  }

  reserve(customerId: string, creditId: string, authorizationId: string,
    amountCents: number, expiresAt: Date): void {
    if (!money(amountCents) || !authorizationId || authorizationId.length > 128 ||
      !Number.isFinite(expiresAt.getTime()) || expiresAt <= this.bank.now())
      throw new BankError("BIZ_CREDIT_RESERVATION_INVALID");
    this.bank.transaction(() => {
      const account = this.account(customerId, creditId);
      if (account.status !== "active" || this.bank.customer(customerId).status !== "active")
        throw new BankError("BIZ_CREDIT_BLOCKED");
      if (this.availableLimit(customerId, creditId) < amountCents)
        throw new BankError("BIZ_CREDIT_LIMIT");
      this.bank.db.prepare(`INSERT INTO credit_card_network_holds
        (authorization_id,credit_id,amount_cents,expires_at) VALUES (?,?,?,?)`)
        .run(authorizationId, creditId, amountCents, expiresAt.toISOString());
    });
  }

  releaseReservation(authorizationId: string): boolean {
    return this.bank.db.prepare(`UPDATE credit_card_network_holds SET released_at=?
      WHERE authorization_id=? AND released_at IS NULL`)
      .run(this.bank.now().toISOString(), authorizationId).changes === 1;
  }

  private activeStatement(creditId: string): CreditCardStatement | undefined {
    return this.bank.db.prepare(`SELECT * FROM credit_card_statements WHERE credit_id=? AND status='open'
      ORDER BY closing_date DESC LIMIT 1`).get(creditId) as CreditCardStatement | undefined;
  }

  private policyFor(account: CreditCardAccount): CreditCardPolicy {
    const policy = JSON.parse(account.policy_json) as CreditCardPolicy;
    if (!policyValid(policy)) throw new BankError("INTEGRITY_CREDIT_POLICY");
    return policy;
  }

  purchase(customerId: string, creditId: string, merchantId: string, amountCents: number,
    installments = 1, networkAuthorizationId?: string): CreditCardPurchase {
    if (!money(amountCents) || !Number.isSafeInteger(installments) || installments < 1 ||
      installments > 24 || amountCents < installments || !merchantId || merchantId.length > 128 ||
      (networkAuthorizationId !== undefined &&
        (!/^[A-Za-z0-9_-]{1,128}$/.test(networkAuthorizationId))))
      throw new BankError("BIZ_CREDIT_PURCHASE_INVALID");
    return this.bank.transaction(() => {
      const account = this.account(customerId, creditId);
      if (account.status !== "active" || this.bank.customer(customerId).status !== "active")
        throw new BankError("BIZ_CREDIT_BLOCKED");
      if (amountCents > this.availableLimit(customerId, creditId)) throw new BankError("BIZ_CREDIT_LIMIT");
      const id = newId("ccp", this.bank.now().getTime());
      const ledgerTx = this.bank.post([
        { accountId: this.bank.systemAccountId("card_settlement"), amount: -amountCents,
          kind: "credit_card_purchase", actor: customerId, refType: "credit_card", refId: creditId },
        { accountId: this.bank.systemAccountId("cash_out"), amount: amountCents,
          kind: "credit_card_purchase", actor: customerId, refType: "credit_card", refId: creditId },
      ]);
      this.bank.db.prepare(`INSERT INTO credit_card_purchases
        (id,credit_id,merchant_id,amount_cents,installment_count,refunded_cents,
          ledger_tx_id,created_at,network_authorization_id)
        VALUES (?,?,?,?,?,0,?,?,?)`)
        .run(id, creditId, merchantId, amountCents, installments, ledgerTx,
          this.bank.now().toISOString(), networkAuthorizationId ?? null);
      const today = civilDate(this.bank.now());
      let first = monthClose(today, account.closing_day);
      if (today > first) first = monthClose(today, account.closing_day, 1);
      const latest = this.bank.db.prepare(`SELECT closing_date FROM credit_card_statements
        WHERE credit_id=? ORDER BY closing_date DESC LIMIT 1`).get(creditId) as
        { closing_date: string } | undefined;
      if (latest && first <= latest.closing_date)
        first = monthClose(latest.closing_date, account.closing_day, 1);
      const base = Math.floor(amountCents / installments), remainder = amountCents % installments;
      const insert = this.bank.db.prepare("INSERT INTO credit_card_installments VALUES (?,?,?,?,NULL)");
      for (let n = 0; n < installments; n++)
        insert.run(id, n + 1, monthClose(first, account.closing_day, n), base + (n < remainder ? 1 : 0));
      return this.bank.db.prepare("SELECT * FROM credit_card_purchases WHERE id=?").get(id) as unknown as CreditCardPurchase;
    });
  }

  closeNext(customerId: string, creditId: string): CreditCardStatement {
    return this.bank.transaction(() => {
      const account = this.account(customerId, creditId);
      const latest = this.bank.db.prepare(`SELECT * FROM credit_card_statements WHERE credit_id=?
        ORDER BY closing_date DESC LIMIT 1`).get(creditId) as CreditCardStatement | undefined;
      const today = civilDate(this.bank.now());
      const openedDate = civilDate(new Date(account.opened_at));
      const firstClose = openedDate <= monthClose(openedDate, account.closing_day)
        ? monthClose(openedDate, account.closing_day)
        : monthClose(openedDate, account.closing_day, 1);
      const closing = latest ? monthClose(latest.closing_date, account.closing_day, 1)
        : firstClose;
      if (today < closing) throw new BankError("BIZ_STATEMENT_NOT_CLOSED");
      if (latest?.last_assessed_date && latest.last_assessed_date > closing)
        throw new BankError("BIZ_STATEMENT_CUTOFF_PASSED");
      if (latest?.status === "open") this.accrue(customerId, creditId, latest.id, closing);
      const previous = latest ? this.statement(customerId, latest.id) : undefined;
      const carryover = previous && previous.status !== "financed"
        ? previous.due_cents - previous.paid_cents : 0;
      if (previous?.status === "open")
        this.bank.db.prepare("UPDATE credit_card_statements SET status='carried' WHERE id=?").run(previous.id);
      const item = this.bank.db.prepare(`SELECT COALESCE(SUM(i.amount_cents),0) cents
        FROM credit_card_installments i JOIN credit_card_purchases p ON p.id=i.purchase_id
        WHERE p.credit_id=? AND i.closing_date=? AND i.statement_id IS NULL`)
        .get(creditId, closing) as { cents: number };
      const plan = this.bank.db.prepare(`SELECT COALESCE(SUM(i.amount_cents),0) cents
        FROM credit_card_invoice_plan_installments i JOIN credit_card_invoice_plans p ON p.id=i.plan_id
        WHERE p.credit_id=? AND i.closing_date=? AND i.statement_id IS NULL`)
        .get(creditId, closing) as { cents: number };
      const beforeCredit = item.cents + plan.cents + carryover;
      const creditApplied = Math.min(beforeCredit, account.pending_credit_cents);
      const due = beforeCredit - creditApplied;
      const policy = this.policyFor(account);
      const minimum = due === 0 ? 0 : Math.min(due, Math.max(1, roundedBps(due, policy.minimum_payment_bps)));
      const id = newId("ccs", this.bank.now().getTime());
      this.bank.db.prepare(`INSERT INTO credit_card_statements
        (id,credit_id,closing_date,due_date,purchases_cents,plan_cents,carryover_cents,credit_applied_cents,
         refund_credit_cents,interest_cents,iof_cents,due_cents,paid_cents,minimum_due_cents,status,last_assessed_date,closed_at)
        VALUES (?,?,?,?,?,?,?,?,0,0,0,?,0,?,?,NULL,?)`)
        .run(id, creditId, closing, addDays(closing, policy.due_days), item.cents, plan.cents, carryover,
          creditApplied, due, minimum, due === 0 ? "paid" : "open", this.bank.now().toISOString());
      this.bank.db.prepare(`UPDATE credit_card_installments SET statement_id=? WHERE closing_date=?
        AND statement_id IS NULL AND purchase_id IN
        (SELECT id FROM credit_card_purchases WHERE credit_id=?)`).run(id, closing, creditId);
      this.bank.db.prepare(`UPDATE credit_card_invoice_plan_installments SET statement_id=?
        WHERE closing_date=? AND statement_id IS NULL AND plan_id IN
        (SELECT id FROM credit_card_invoice_plans WHERE credit_id=?)`).run(id, closing, creditId);
      this.bank.db.prepare(`UPDATE credit_card_accounts SET pending_credit_cents=pending_credit_cents-?
        WHERE id=?`).run(creditApplied, creditId);
      return this.statement(customerId, id);
    });
  }

  refund(customerId: string, creditId: string, purchaseId: string, amountCents: number): CreditCardAccount {
    if (!money(amountCents)) throw new BankError("BIZ_CREDIT_REFUND_INVALID");
    return this.bank.transaction(() => {
      const account = this.account(customerId, creditId);
      const purchase = this.bank.db.prepare("SELECT * FROM credit_card_purchases WHERE id=? AND credit_id=?")
        .get(purchaseId, creditId) as CreditCardPurchase | undefined;
      if (!purchase) throw new BankError("DEF_NOT_FOUND");
      if (amountCents > purchase.amount_cents - purchase.refunded_cents)
        throw new BankError("BIZ_CREDIT_REFUND_EXCESS");
      const activeBeforeAccrual = this.activeStatement(creditId);
      const active = activeBeforeAccrual ? this.accrue(customerId, creditId, activeBeforeAccrual.id) : undefined;
      const statementCredit = active ? Math.min(amountCents, active.due_cents - active.paid_cents) : 0;
      const pending = amountCents - statementCredit;
      const ledgerTx = this.bank.post([
        { accountId: this.bank.systemAccountId("cash_out"), amount: -amountCents,
          kind: "credit_card_refund", actor: customerId, refType: "credit_card", refId: creditId },
        { accountId: this.bank.systemAccountId("card_settlement"), amount: amountCents,
          kind: "credit_card_refund", actor: customerId, refType: "credit_card", refId: creditId },
      ]);
      const id = newId("ccr", this.bank.now().getTime());
      this.bank.db.prepare("UPDATE credit_card_purchases SET refunded_cents=refunded_cents+? WHERE id=?")
        .run(amountCents, purchaseId);
      if (active && statementCredit) {
        const newDue = active.due_cents - statementCredit;
        const newMinimum = Math.min(newDue, active.minimum_due_cents);
        this.bank.db.prepare(`UPDATE credit_card_statements SET due_cents=?, minimum_due_cents=?,
          refund_credit_cents=refund_credit_cents+?, status=? WHERE id=?`)
          .run(newDue, newMinimum, statementCredit,
            newDue === active.paid_cents ? "paid" : "open", active.id);
      }
      this.bank.db.prepare(`UPDATE credit_card_accounts SET pending_credit_cents=pending_credit_cents+?
        WHERE id=?`).run(pending, creditId);
      this.bank.db.prepare("INSERT INTO credit_card_refunds VALUES (?,?,?,?,?,?,?,?,?)")
        .run(id, creditId, purchaseId, active?.id ?? null, amountCents, statementCredit, pending,
          ledgerTx, this.bank.now().toISOString());
      return this.account(customerId, account.id);
    });
  }

  pay(customerId: string, creditId: string, statementId: string, sourceAccountId: string,
    amountCents: number, idempotencyKey?: string): CreditCardStatement {
    if (!money(amountCents) || (idempotencyKey !== undefined &&
      (!/^[A-Za-z0-9_-]{1,128}$/.test(idempotencyKey))))
      throw new BankError("BIZ_CREDIT_PAYMENT_INVALID");
    return this.bank.transaction(() => {
      if (idempotencyKey !== undefined) {
        const prior = this.bank.db.prepare(`SELECT statement_id,source_account_id,amount_cents
          FROM credit_card_payments WHERE credit_id=? AND idempotency_key=?`)
          .get(creditId, idempotencyKey) as { statement_id: string;
            source_account_id: string; amount_cents: number } | undefined;
        if (prior) {
          if (prior.statement_id !== statementId || prior.source_account_id !== sourceAccountId ||
            prior.amount_cents !== amountCents)
            throw new BankError("BIZ_CREDIT_PAYMENT_CONFLICT");
          return this.statement(customerId, statementId);
        }
      }
      const beforeAccrual = this.statement(customerId, statementId);
      const statement = beforeAccrual.status === "open"
        ? this.accrue(customerId, creditId, statementId) : beforeAccrual;
      if (statement.credit_id !== creditId || statement.status !== "open")
        throw new BankError("BIZ_STATEMENT_NOT_PAYABLE");
      const source = this.bank.ownAccount(customerId, sourceAccountId);
      if (source.status !== "active" || source.kind !== "checking")
        throw new BankError("BIZ_PAYMENT_SOURCE_INVALID");
      if (amountCents > statement.due_cents - statement.paid_cents)
        throw new BankError("BIZ_CREDIT_PAYMENT_EXCESS");
      if (this.bank.availableBalance(sourceAccountId) < amountCents)
        throw new BankError("BIZ_INSUFFICIENT_FUNDS");
      const ledgerTx = this.bank.post([
        { accountId: sourceAccountId, amount: -amountCents,
          kind: "credit_card_payment", actor: customerId, refType: "credit_card", refId: creditId },
        { accountId: this.bank.systemAccountId("card_settlement"), amount: amountCents,
          kind: "credit_card_payment", actor: customerId, refType: "credit_card", refId: creditId },
      ]);
      this.bank.db.prepare(`UPDATE credit_card_statements SET paid_cents=paid_cents+?, status=? WHERE id=?`)
        .run(amountCents, amountCents === statement.due_cents - statement.paid_cents ? "paid" : "open", statementId);
      this.bank.db.prepare(`INSERT INTO credit_card_payments
        (id,credit_id,statement_id,source_account_id,amount_cents,ledger_tx_id,created_at,idempotency_key)
        VALUES (?,?,?,?,?,?,?,?)`)
        .run(newId("ccy", this.bank.now().getTime()), creditId, statementId, sourceAccountId,
          amountCents, ledgerTx, this.bank.now().toISOString(), idempotencyKey ?? null);
      return this.statement(customerId, statementId);
    });
  }

  installmentStatement(customerId: string, creditId: string, statementId: string,
    installmentCount: number): { id: string; principal_cents: number; interest_cents: number } {
    if (!Number.isSafeInteger(installmentCount) || installmentCount < 2 || installmentCount > 24)
      throw new BankError("BIZ_CREDIT_PLAN_INVALID");
    return this.bank.transaction(() => {
      const account = this.account(customerId, creditId);
      const statement = this.statement(customerId, statementId);
      const existing = this.bank.db.prepare(`SELECT id,principal_cents,interest_cents,
        installment_count FROM credit_card_invoice_plans WHERE source_statement_id=?`)
        .get(statementId) as { id: string; principal_cents: number; interest_cents: number;
          installment_count: number } | undefined;
      if (existing) {
        if (existing.installment_count !== installmentCount)
          throw new BankError("BIZ_CREDIT_PLAN_CONFLICT");
        return { id: existing.id, principal_cents: existing.principal_cents,
          interest_cents: existing.interest_cents };
      }
      if (statement.credit_id !== creditId || statement.status !== "open" ||
        this.activeStatement(creditId)?.id !== statementId)
        throw new BankError("BIZ_STATEMENT_NOT_FINANCEABLE");
      const assessed = this.accrue(customerId, creditId, statementId);
      const principal = assessed.due_cents - assessed.paid_cents;
      if (assessed.paid_cents < assessed.minimum_due_cents || principal < installmentCount)
        throw new BankError("BIZ_CREDIT_PLAN_MINIMUM");
      const policy = this.policyFor(account);
      const interest = roundedBps(principal, policy.invoice_plan_interest_bps);
      const total = principal + interest;
      if (!Number.isSafeInteger(total)) throw new BankError("BIZ_AMOUNT_RANGE");
      const id = newId("cci", this.bank.now().getTime());
      const feeTx = interest > 0 ? this.bank.post([
        { accountId: this.bank.systemAccountId("card_settlement"), amount: -interest,
          kind: "credit_card_interest", actor: customerId, refType: "credit_card", refId: creditId },
        { accountId: this.bank.systemAccountId("fees"), amount: interest,
          kind: "credit_card_interest", actor: customerId, refType: "credit_card", refId: creditId },
      ]) : null;
      this.bank.db.prepare("INSERT INTO credit_card_invoice_plans VALUES (?,?,?,?,?,?,?,?)")
        .run(id, creditId, statementId, principal, interest, installmentCount,
          feeTx, this.bank.now().toISOString());
      const base = Math.floor(total / installmentCount), remainder = total % installmentCount;
      const first = monthClose(statement.closing_date, account.closing_day, 1);
      const insert = this.bank.db.prepare(`INSERT INTO credit_card_invoice_plan_installments
        VALUES (?,?,?,?,NULL)`);
      for (let n = 0; n < installmentCount; n++)
        insert.run(id, n + 1, monthClose(first, account.closing_day, n),
          base + (n < remainder ? 1 : 0));
      this.bank.db.prepare("UPDATE credit_card_statements SET status='financed' WHERE id=?")
        .run(statementId);
      return { id, principal_cents: principal, interest_cents: interest };
    });
  }

  accrue(customerId: string, creditId: string, statementId: string,
    throughDate?: string): CreditCardStatement {
    return this.bank.transaction(() => {
      const account = this.account(customerId, creditId);
      const statement = this.statement(customerId, statementId);
      if (statement.credit_id !== creditId) throw new BankError("DEF_NOT_FOUND");
      if (statement.status !== "open") return statement;
      const policy = this.policyFor(account);
      const today = civilDate(this.bank.now());
      if (throughDate && (!/^\d{4}-\d{2}-\d{2}$/.test(throughDate) || throughDate > today))
        throw new BankError("BIZ_ACCRUAL_DATE_INVALID");
      const cutoff = throughDate ?? today;
      let date = addDays(statement.last_assessed_date ?? statement.due_date, 1);
      let days = 0;
      while (date <= cutoff) {
        if (++days > 3660) throw new BankError("BIZ_ACCRUAL_WINDOW_TOO_LONG");
        const current = this.statement(customerId, statementId);
        const principal = current.due_cents - current.paid_cents;
        if (principal <= 0) break;
        const first = current.last_assessed_date === null;
        const interest = roundedBps(principal, policy.revolving_daily_interest_bps);
        const iof = roundedBps(principal, policy.daily_iof_bps) +
          (first ? roundedBps(principal, policy.fixed_iof_bps) : 0);
        const charge = interest + iof;
        const charges = [
          ...(interest > 0 ? [
            { accountId: this.bank.systemAccountId("card_settlement"), amount: -interest,
              kind: "credit_card_interest", actor: "credit_card_engine", refType: "credit_card", refId: creditId },
            { accountId: this.bank.systemAccountId("fees"), amount: interest,
              kind: "credit_card_interest", actor: "credit_card_engine", refType: "credit_card", refId: creditId },
          ] : []),
          ...(iof > 0 ? [
            { accountId: this.bank.systemAccountId("card_settlement"), amount: -iof,
              kind: "credit_card_iof", actor: "credit_card_engine", refType: "credit_card", refId: creditId },
            { accountId: this.bank.systemAccountId("fees"), amount: iof,
              kind: "credit_card_iof", actor: "credit_card_engine", refType: "credit_card", refId: creditId },
          ] : []),
        ];
        const ledgerTx = charge > 0 ? this.bank.post(charges, undefined, date) : null;
        this.bank.db.prepare("INSERT INTO credit_card_accruals VALUES (?,?,?,?,?,?,?,?)")
          .run(newId("cca", this.bank.now().getTime()), creditId, statementId, date,
            principal, interest, iof, ledgerTx);
        this.bank.db.prepare(`UPDATE credit_card_statements SET interest_cents=interest_cents+?,
          iof_cents=iof_cents+?, due_cents=due_cents+?, last_assessed_date=? WHERE id=?`)
          .run(interest, iof, charge, date, statementId);
        date = addDays(date, 1);
      }
      return this.statement(customerId, statementId);
    });
  }

  statementState(customerId: string, statementId: string): "open" | "paid" | "carried" | "financed" | "revolving" | "delinquent" {
    const statement = this.statement(customerId, statementId);
    if (statement.status !== "open" || civilDate(this.bank.now()) <= statement.due_date) return statement.status;
    return statement.paid_cents < statement.minimum_due_cents ? "delinquent" : "revolving";
  }

  runBilling(): { closed: number; accrued: number } {
    const accounts = this.bank.db.prepare(`SELECT id,customer_id FROM credit_card_accounts
      ORDER BY id`).all() as { id: string; customer_id: string }[];
    let closed = 0, accrued = 0;
    for (const account of accounts) {
      for (let cycle = 0; cycle < 24; cycle++) {
        try { this.closeNext(account.customer_id, account.id); closed++; }
        catch (error) {
          if (error instanceof BankError && error.code === "BIZ_STATEMENT_NOT_CLOSED") break;
          throw error;
        }
        if (cycle === 23) throw new BankError("BIZ_CREDIT_BILLING_BACKLOG");
      }
      const current = this.activeStatement(account.id);
      if (current && civilDate(this.bank.now()) > current.due_date) {
        const before = current.last_assessed_date;
        const after = this.accrue(account.customer_id, account.id, current.id);
        if (after.last_assessed_date !== before) accrued++;
      }
    }
    return { closed, accrued };
  }

  reconcile(customerId: string, creditId: string): { ok: boolean; mismatches: string[] } {
    const account = this.account(customerId, creditId);
    const mismatches: string[] = [];
    const sum = (sql: string): number => (this.bank.db.prepare(sql).get(creditId) as { cents: number }).cents;
    const purchases = sum("SELECT COALESCE(SUM(amount_cents),0) cents FROM credit_card_purchases WHERE credit_id=?");
    const refunds = sum("SELECT COALESCE(SUM(amount_cents),0) cents FROM credit_card_refunds WHERE credit_id=?");
    const payments = sum("SELECT COALESCE(SUM(amount_cents),0) cents FROM credit_card_payments WHERE credit_id=?");
    const charges = sum(`SELECT COALESCE(SUM(interest_cents+iof_cents),0) cents
      FROM credit_card_accruals WHERE credit_id=?`) +
      sum("SELECT COALESCE(SUM(interest_cents),0) cents FROM credit_card_invoice_plans WHERE credit_id=?");
    if (purchases - refunds - payments + charges !== this.outstanding(customerId, creditId))
      mismatches.push("ledger_outstanding");
    const rows = this.bank.db.prepare("SELECT * FROM credit_card_statements WHERE credit_id=?")
      .all(creditId) as unknown as CreditCardStatement[];
    if (rows.filter((row) => row.status === "open").length > 1) mismatches.push("multiple_open_statements");
    for (const row of rows) {
      if (row.purchases_cents + row.plan_cents + row.carryover_cents - row.credit_applied_cents -
        row.refund_credit_cents + row.interest_cents + row.iof_cents !== row.due_cents)
        mismatches.push(`statement:${row.id}:due`);
      const paid = this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) cents FROM credit_card_payments
        WHERE statement_id=?`).get(row.id) as { cents: number };
      if (paid.cents !== row.paid_cents) mismatches.push(`statement:${row.id}:payments`);
      const billed = this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) cents
        FROM credit_card_installments WHERE statement_id=?`).get(row.id) as { cents: number };
      if (billed.cents !== row.purchases_cents) mismatches.push(`statement:${row.id}:purchases`);
      const planned = this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) cents
        FROM credit_card_invoice_plan_installments WHERE statement_id=?`).get(row.id) as { cents: number };
      if (planned.cents !== row.plan_cents) mismatches.push(`statement:${row.id}:plan`);
      const credited = this.bank.db.prepare(`SELECT COALESCE(SUM(statement_credit_cents),0) cents
        FROM credit_card_refunds WHERE statement_id=?`).get(row.id) as { cents: number };
      if (credited.cents !== row.refund_credit_cents) mismatches.push(`statement:${row.id}:refunds`);
      const accrued = this.bank.db.prepare(`SELECT COALESCE(SUM(interest_cents),0) interest,
        COALESCE(SUM(iof_cents),0) iof FROM credit_card_accruals WHERE statement_id=?`)
        .get(row.id) as { interest: number; iof: number };
      if (accrued.interest !== row.interest_cents || accrued.iof !== row.iof_cents)
        mismatches.push(`statement:${row.id}:charges`);
    }
    const pending = sum(`SELECT COALESCE(SUM(pending_credit_cents),0) cents FROM credit_card_refunds
      WHERE credit_id=?`) - sum(`SELECT COALESCE(SUM(credit_applied_cents),0) cents
      FROM credit_card_statements WHERE credit_id=?`);
    if (pending !== account.pending_credit_cents) mismatches.push("pending_credits");
    const installmentRows = this.bank.db.prepare(`SELECT p.id, p.amount_cents,
      COALESCE(SUM(i.amount_cents),0) allocated FROM credit_card_purchases p
      LEFT JOIN credit_card_installments i ON i.purchase_id=p.id WHERE p.credit_id=? GROUP BY p.id`)
      .all(creditId) as { id: string; amount_cents: number; allocated: number }[];
    for (const row of installmentRows)
      if (row.amount_cents !== row.allocated) mismatches.push(`purchase:${row.id}:installments`);
    const planRows = this.bank.db.prepare(`SELECT p.id,p.principal_cents,p.interest_cents,
      p.source_statement_id, COALESCE(SUM(i.amount_cents),0) allocated FROM credit_card_invoice_plans p
      LEFT JOIN credit_card_invoice_plan_installments i ON i.plan_id=p.id
      WHERE p.credit_id=? GROUP BY p.id`).all(creditId) as unknown as
      { id: string; principal_cents: number; interest_cents: number;
        source_statement_id: string; allocated: number }[];
    for (const row of planRows) {
      if (row.principal_cents + row.interest_cents !== row.allocated)
        mismatches.push(`invoice_plan:${row.id}:installments`);
      const source = rows.find((statement) => statement.id === row.source_statement_id);
      if (!source || source.status !== "financed" ||
        source.due_cents - source.paid_cents !== row.principal_cents)
        mismatches.push(`invoice_plan:${row.id}:source`);
    }
    return { ok: mismatches.length === 0, mismatches };
  }

  reconcileAll(): { ok: boolean; accounts_checked: number; mismatches: string[] } {
    const accounts = this.bank.db.prepare("SELECT id,customer_id FROM credit_card_accounts ORDER BY id")
      .all() as { id: string; customer_id: string }[];
    const mismatches = accounts.flatMap((account) =>
      this.reconcile(account.customer_id, account.id).mismatches.map((item) => `${account.id}:${item}`));
    return { ok: mismatches.length === 0, accounts_checked: accounts.length, mismatches };
  }
}
