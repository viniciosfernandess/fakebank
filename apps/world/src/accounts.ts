import { Bank, BankError, type Account } from "./bank.ts";
import { newId } from "./id.ts";
import { parsePixKey } from "./ecosystem/dict.ts";

export interface BusinessAccountIdentity {
  account_id: string; cnpj: string; legal_name: string;
  representative_customer_id: string; verified_at: string; verified_by: string;
}
export interface SalaryAccountEmployer {
  account_id: string; employer_account_id: string;
  employee_customer_id: string; opened_at: string;
}
export interface SalaryMovement {
  id: string; amount_cents: number; ledger_tx_id: string;
}
export interface SalaryPortabilityInstruction {
  account_id: string; destination_account_id: string | null; updated_at: string;
}

export class AccountService {
  readonly bank: Bank;
  constructor(bank: Bank) {
    this.bank = bank;
    bank.db.exec(`CREATE TABLE IF NOT EXISTS customer_contacts (
      customer_id TEXT PRIMARY KEY REFERENCES customers(id), email TEXT, phone TEXT,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS customer_contact_changes (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      device_id TEXT, email_changed INTEGER NOT NULL CHECK(email_changed IN (0,1)),
      phone_changed INTEGER NOT NULL CHECK(phone_changed IN (0,1)),
      phone_replaced INTEGER NOT NULL CHECK(phone_replaced IN (0,1)),
      changed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS customer_contact_changes_recent
      ON customer_contact_changes(customer_id,changed_at);
    CREATE INDEX IF NOT EXISTS customer_contact_changes_window
      ON customer_contact_changes(changed_at,customer_id);
    CREATE TRIGGER IF NOT EXISTS customer_contact_changes_no_update
      BEFORE UPDATE ON customer_contact_changes
      BEGIN SELECT RAISE(ABORT, 'CONTACT_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS customer_contact_changes_no_delete
      BEFORE DELETE ON customer_contact_changes
      BEGIN SELECT RAISE(ABORT, 'CONTACT_HISTORY_IMMUTABLE'); END;`);
    if (!(bank.db.prepare("PRAGMA table_info(customer_contact_changes)").all() as { name: string }[])
      .some((column) => column.name === "phone_replaced"))
      bank.db.exec("ALTER TABLE customer_contact_changes ADD COLUMN phone_replaced INTEGER NOT NULL DEFAULT 0");
  }
  openSecond(customerId: string): Account {
    const customer = this.bank.customer(customerId);
    if (customer.status !== "active" || customer.kyc_tier === 0)
      throw new BankError("DEF_ACCOUNT_FROZEN");
    const count = (this.bank.db.prepare("SELECT COUNT(*) n FROM accounts WHERE customer_id=? AND status<>'closed'")
      .get(customerId) as { n: number }).n;
    if (count >= 2) throw new BankError("BIZ_ACCOUNT_LIMIT");
    const id = newId("acc", this.bank.now().getTime());
    this.bank.addAccount({ id, customer_id: customerId, kind: "checking", system_role: null,
      overdraft_limit: 0, status: "active" });
    return this.bank.account(id);
  }
  openPayment(customerId: string): Account {
    return this.bank.transaction(() => {
      const customer = this.bank.customer(customerId);
      if (customer.status !== "active" || customer.kyc_tier === 0 ||
        customer.kyc_status !== "approved") throw new BankError("DEF_ACCOUNT_FROZEN");
      const count = (this.bank.db.prepare(`SELECT COUNT(*) n FROM accounts
        WHERE customer_id=? AND status<>'closed'`).get(customerId) as { n: number }).n;
      if (count >= 2) throw new BankError("BIZ_ACCOUNT_LIMIT");
      const id = newId("acc", this.bank.now().getTime());
      this.bank.addAccount({ id, customer_id: customerId, kind: "payment",
        system_role: null, overdraft_limit: 0, status: "active" });
      return this.bank.account(id);
    });
  }
  salaryEmployer(accountId: string): SalaryAccountEmployer | null {
    this.bank.account(accountId);
    return this.bank.db.prepare(`SELECT account_id,employer_account_id,
      employee_customer_id,opened_at FROM salary_account_employers WHERE account_id=?`)
      .get(accountId) as SalaryAccountEmployer | undefined ?? null;
  }
  salaryPortabilityInstruction(customerId: string,
    salaryAccountId: string): SalaryPortabilityInstruction | null {
    const salary = this.bank.ownAccount(customerId, salaryAccountId);
    if (salary.kind !== "salary") throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
    return this.bank.db.prepare(`SELECT account_id,destination_account_id,updated_at
      FROM salary_portability_instructions WHERE account_id=?`)
      .get(salaryAccountId) as SalaryPortabilityInstruction | undefined ?? null;
  }
  setSalaryPortabilityInstruction(customerId: string, salaryAccountId: string,
    destinationAccountId: string | null): SalaryPortabilityInstruction {
    return this.bank.transaction(() => {
      const salary = this.bank.ownAccount(customerId, salaryAccountId);
      if (salary.kind !== "salary" || salary.status !== "active" ||
        this.bank.customer(customerId).status !== "active")
        throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
      if (destinationAccountId !== null) {
        const destination = this.bank.ownAccount(customerId, destinationAccountId);
        if (!["checking", "payment"].includes(destination.kind) ||
          destination.status !== "active")
          throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
      }
      const previous = this.salaryPortabilityInstruction(customerId, salaryAccountId);
      if (previous?.destination_account_id === destinationAccountId) return previous;
      const at = this.bank.now().toISOString();
      this.bank.db.prepare(`INSERT INTO salary_portability_instructions
        (account_id,destination_account_id,updated_at) VALUES (?,?,?)
        ON CONFLICT(account_id) DO UPDATE SET destination_account_id=excluded.destination_account_id,
          updated_at=excluded.updated_at`).run(salaryAccountId, destinationAccountId, at);
      this.bank.db.prepare(`INSERT INTO salary_portability_instruction_events
        (id,account_id,destination_account_id,actor_customer_id,changed_at)
        VALUES (?,?,?,?,?)`).run(newId("salary_instruction", this.bank.now().getTime()),
          salaryAccountId, destinationAccountId, customerId, at);
      return this.salaryPortabilityInstruction(customerId, salaryAccountId)!;
    });
  }
  openSalary(employerCustomerId: string, employerAccountId: string,
    employeeCustomerId: string): Account {
    return this.bank.transaction(() => {
      const employer = this.bank.ownAccount(employerCustomerId, employerAccountId);
      const employee = this.bank.customer(employeeCustomerId);
      if (employer.kind !== "merchant" || employer.status !== "active" ||
        !this.businessIdentity(employerAccountId) ||
        this.bank.customer(employerCustomerId).status !== "active" ||
        employee.status !== "active" || employee.kyc_tier === 0 ||
        employee.kyc_status !== "approved" || employerCustomerId === employeeCustomerId)
        throw new BankError("DEF_SALARY_EMPLOYER_REQUIRED");
      const count = (this.bank.db.prepare(`SELECT COUNT(*) n FROM accounts
        WHERE customer_id=? AND status<>'closed'`).get(employeeCustomerId) as { n: number }).n;
      if (count >= 2) throw new BankError("BIZ_ACCOUNT_LIMIT");
      const id = newId("acc", this.bank.now().getTime());
      this.bank.addAccount({ id, customer_id: employeeCustomerId, kind: "salary",
        system_role: null, overdraft_limit: 0, status: "active" });
      this.bank.db.prepare(`INSERT INTO salary_account_employers
        (account_id,employer_account_id,employee_customer_id,opened_at)
        VALUES (?,?,?,?)`).run(id, employerAccountId, employeeCustomerId,
          this.bank.now().toISOString());
      return this.bank.account(id);
    });
  }
  paySalary(employerCustomerId: string, employerAccountId: string,
    salaryAccountId: string, amountCents: number, idempotencyKey: string): SalaryMovement {
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0 ||
      !idempotencyKey || idempotencyKey.length > 128)
      throw new BankError("BIZ_SALARY_PAYMENT_INVALID");
    return this.bank.transaction(() => {
      this.bank.ownAccount(employerCustomerId, employerAccountId);
      const prior = this.bank.db.prepare(`SELECT id,amount_cents,ledger_tx_id,salary_account_id
        FROM salary_payments WHERE employer_account_id=? AND idempotency_key=?`)
        .get(employerAccountId, idempotencyKey) as (SalaryMovement &
          { salary_account_id: string }) | undefined;
      if (prior) {
        if (prior.amount_cents !== amountCents || prior.salary_account_id !== salaryAccountId)
          throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
        return { id: prior.id, amount_cents: prior.amount_cents,
          ledger_tx_id: prior.ledger_tx_id };
      }
      const employer = this.bank.ownAccount(employerCustomerId, employerAccountId);
      const salary = this.bank.account(salaryAccountId);
      const binding = this.salaryEmployer(salaryAccountId);
      if (employer.kind !== "merchant" || employer.status !== "active" ||
        this.bank.customer(employerCustomerId).status !== "active" ||
        salary.kind !== "salary" || salary.status !== "active" ||
        !binding || binding.employer_account_id !== employerAccountId ||
        !salary.customer_id || this.bank.customer(salary.customer_id).status !== "active")
        throw new BankError("DEF_SALARY_EMPLOYER_REQUIRED");
      if (this.bank.availableBalance(employerAccountId) < amountCents)
        throw new BankError("BIZ_INSUFFICIENT_FUNDS");
      const id = newId("salary", this.bank.now().getTime());
      const ledgerTxId = this.bank.post([
        { accountId: employerAccountId, amount: -amountCents,
          kind: "salary_payment", actor: employerCustomerId,
          refType: "salary_payment", refId: id },
        { accountId: salaryAccountId, amount: amountCents,
          kind: "salary_payment", actor: employerCustomerId,
          refType: "salary_payment", refId: id },
      ]);
      this.bank.db.prepare(`INSERT INTO salary_payments
        (id,employer_account_id,salary_account_id,amount_cents,idempotency_key,ledger_tx_id,paid_at)
        VALUES (?,?,?,?,?,?,?)`).run(id, employerAccountId, salaryAccountId,
          amountCents, idempotencyKey, ledgerTxId, this.bank.now().toISOString());
      const instruction = this.salaryPortabilityInstruction(salary.customer_id!, salaryAccountId);
      if (instruction?.destination_account_id) {
        const destination = this.bank.account(instruction.destination_account_id);
        const available = this.bank.availableBalance(salaryAccountId);
        if (destination.status === "active" && available > 0)
          this.portSalary(salary.customer_id!, salaryAccountId, destination.id,
            available, `salary_auto_${id}`, true);
      }
      return { id, amount_cents: amountCents, ledger_tx_id: ledgerTxId };
    });
  }
  portSalary(employeeCustomerId: string, salaryAccountId: string,
    destinationAccountId: string, amountCents: number,
    idempotencyKey: string, automatic = false): SalaryMovement {
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0 ||
      !idempotencyKey || idempotencyKey.length > 128 ||
      !automatic && idempotencyKey.startsWith("salary_auto_"))
      throw new BankError("BIZ_SALARY_PORTABILITY_INVALID");
    return this.bank.transaction(() => {
      this.bank.ownAccount(employeeCustomerId, salaryAccountId);
      const prior = this.bank.db.prepare(`SELECT id,amount_cents,ledger_tx_id,destination_account_id
        FROM salary_portabilities WHERE salary_account_id=? AND idempotency_key=?`)
        .get(salaryAccountId, idempotencyKey) as (SalaryMovement &
          { destination_account_id: string }) | undefined;
      if (prior) {
        if (prior.amount_cents !== amountCents ||
          prior.destination_account_id !== destinationAccountId)
          throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
        return { id: prior.id, amount_cents: prior.amount_cents,
          ledger_tx_id: prior.ledger_tx_id };
      }
      const source = this.bank.ownAccount(employeeCustomerId, salaryAccountId);
      const destination = this.bank.ownAccount(employeeCustomerId, destinationAccountId);
      if (source.kind !== "salary" || source.status !== "active" ||
        !["checking", "payment"].includes(destination.kind) ||
        destination.status !== "active" ||
        this.bank.customer(employeeCustomerId).status !== "active")
        throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
      if (this.bank.availableBalance(salaryAccountId) < amountCents)
        throw new BankError("BIZ_INSUFFICIENT_FUNDS");
      const id = newId("salary_port", this.bank.now().getTime());
      const ledgerTxId = this.bank.post([
        { accountId: salaryAccountId, amount: -amountCents,
          kind: "salary_portability", actor: employeeCustomerId,
          refType: "salary_portability", refId: id },
        { accountId: destinationAccountId, amount: amountCents,
          kind: "salary_portability", actor: employeeCustomerId,
          refType: "salary_portability", refId: id },
      ]);
      this.bank.db.prepare(`INSERT INTO salary_portabilities
        (id,salary_account_id,destination_account_id,amount_cents,idempotency_key,
         ledger_tx_id,transferred_at) VALUES (?,?,?,?,?,?,?)`)
        .run(id, salaryAccountId, destinationAccountId, amountCents,
          idempotencyKey, ledgerTxId, this.bank.now().toISOString());
      return { id, amount_cents: amountCents, ledger_tx_id: ledgerTxId };
    });
  }
  businessIdentity(accountId: string): BusinessAccountIdentity | null {
    this.bank.account(accountId);
    return this.bank.db.prepare(`SELECT account_id,cnpj,legal_name,
      representative_customer_id,verified_at,verified_by
      FROM business_account_identity WHERE account_id=?`)
      .get(accountId) as BusinessAccountIdentity | undefined ?? null;
  }
  verifyBusiness(customerId: string, accountId: string, cnpj: string,
    legalName: string, verifier: string): BusinessAccountIdentity {
    const parsed = parsePixKey(cnpj);
    const name = legalName.trim();
    if (parsed?.type !== "cnpj" || name.length < 3 || name.length > 160 ||
      !/^[a-zA-Z0-9_-]{1,80}$/.test(verifier))
      throw new BankError("BIZ_BUSINESS_IDENTITY_INVALID");
    return this.bank.transaction(() => {
      const customer = this.bank.customer(customerId);
      const account = this.bank.ownAccount(customerId, accountId);
      if (customer.status !== "active" || customer.kyc_tier < 2 ||
        customer.kyc_status !== "approved" || account.kind !== "merchant" ||
        account.status !== "active") throw new BankError("DEF_BUSINESS_VERIFICATION_REQUIRED");
      if (this.businessIdentity(accountId)) throw new BankError("BIZ_BUSINESS_ALREADY_VERIFIED");
      if (this.bank.db.prepare(`SELECT 1 FROM business_account_identity WHERE cnpj=?`)
        .get(parsed.value)) throw new BankError("BIZ_CNPJ_ALREADY_REGISTERED");
      this.bank.db.prepare(`INSERT INTO business_account_identity
        (account_id,cnpj,legal_name,representative_customer_id,verified_at,verified_by)
        VALUES (?,?,?,?,?,?)`).run(accountId, parsed.value, name, customerId,
          this.bank.now().toISOString(), verifier);
      return this.businessIdentity(accountId)!;
    });
  }
  openBusiness(customerId: string, cnpj: string, legalName: string,
    verifier: string): { account: Account; identity: BusinessAccountIdentity } {
    return this.bank.transaction(() => {
      const customer = this.bank.customer(customerId);
      if (customer.status !== "active" || customer.kyc_tier < 2 ||
        customer.kyc_status !== "approved")
        throw new BankError("DEF_BUSINESS_VERIFICATION_REQUIRED");
      const count = (this.bank.db.prepare(`SELECT COUNT(*) n FROM accounts
        WHERE customer_id=? AND status<>'closed'`).get(customerId) as { n: number }).n;
      if (count >= 2) throw new BankError("BIZ_ACCOUNT_LIMIT");
      const id = newId("acc", this.bank.now().getTime());
      this.bank.addAccount({ id, customer_id: customerId, kind: "merchant",
        system_role: null, overdraft_limit: 0, status: "active" });
      const identity = this.verifyBusiness(customerId, id, cnpj, legalName, verifier);
      return { account: this.bank.account(id), identity };
    });
  }
  contact(customerId: string): { email: string | null; phone: string | null } {
    this.bank.customer(customerId);
    const row = this.bank.db.prepare("SELECT email,phone FROM customer_contacts WHERE customer_id=?")
      .get(customerId) as { email: string | null; phone: string | null } | undefined;
    return row ?? { email: null, phone: null };
  }
  updateContact(customerId: string, patch: { email?: string | undefined; phone?: string | undefined },
    deviceId?: string):
    { email: string | null; phone: string | null } {
    this.bank.customer(customerId);
    if ((!patch.email && !patch.phone) || (patch.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(patch.email)) ||
      (patch.phone && !/^\+55\d{10,11}$/.test(patch.phone))) throw new BankError("BIZ_INVALID_CONTACT");
    return this.bank.transaction(() => {
      if (deviceId) {
        const device = this.bank.db.prepare(`SELECT 1 FROM auth_devices
          WHERE id=? AND customer_id=? AND revoked_at IS NULL`).get(deviceId, customerId);
        if (!device) throw new BankError("DEF_UNAUTHORIZED");
      }
      const current = this.contact(customerId);
      const email = patch.email ?? current.email;
      const phone = patch.phone ?? current.phone;
      const emailChanged = email !== current.email;
      const phoneChanged = phone !== current.phone;
      if (!emailChanged && !phoneChanged) return current;
      this.bank.db.prepare(`INSERT INTO customer_contacts VALUES (?,?,?,?) ON CONFLICT(customer_id)
        DO UPDATE SET email=excluded.email,phone=excluded.phone,updated_at=excluded.updated_at`)
        .run(customerId, email, phone, this.bank.now().toISOString());
      this.bank.db.prepare(`INSERT INTO customer_contact_changes
        (id,customer_id,device_id,email_changed,phone_changed,phone_replaced,changed_at)
        VALUES (?,?,?,?,?,?,?)`).run(newId("contact", this.bank.now().getTime()),
          customerId, deviceId ?? null, Number(emailChanged), Number(phoneChanged),
          Number(phoneChanged && current.phone !== null),
          this.bank.now().toISOString());
      this.bank.log({ actor: customerId, kind: "contact_changed", customerId,
        route: "customers.me", status: 200 });
      this.bank.telemetry.emit({ source: "auth", category: "profile", action: "contact_change",
        outcome: "success", userId: customerId, ...(deviceId ? { deviceId } : {}),
        message: "Customer contact changed" });
      return { email, phone };
    });
  }
}
