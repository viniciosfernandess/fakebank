import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { newId, seedAccountId, seedSystemAccountId, type SystemRole } from "./id.ts";
import { DatabaseSync } from "node:sqlite";
import { createHash, randomInt, timingSafeEqual } from "node:crypto";
import { WEAKNESSES } from "./catalog.ts";
import { canReadStatement, effectiveKycTier } from "./account-policy.ts";
import { lookupRateAllowed, medMayReopen, muleHoldEnabled, pixKeyResult, pixNightHour, pixRaceEnabled } from "./pix-policy.ts";
import { installLedgerIntegrity, verifyLedgerChain } from "./ledger-integrity.ts";
import { hasMedCustomerCredit, readMedIncidentCompensation } from "./med-incident-compensation.ts";
import { ACCOUNTING_CALENDAR_VERSION, installAccountingDates, verifyAccountingDates, withAccountingValueDate } from "./accounting-dates.ts";
import { CHART_VERSION, PERIOD_CUTOFF_POLICY_VERSION, installChartOfAccounts, trialBalance, trialBalanceAtDate, type TrialBalanceLine } from "./trial-balance.ts";
import { TelemetryStore, currentTrace, withTrace } from "./telemetry.ts";
import { JACARANDA_ISPB, pixEndToEndId } from "./pix-id.ts";
import { accountIdentifier } from "./bank-account-number.ts";
import { syntheticCnpj } from "./business-document.ts";
import { SpiNetwork } from "./ecosystem/spi.ts";
import { PspNetwork, type PspCautelarHold } from "./ecosystem/psp.ts";
import { consumeDictToken, installDictRateBuckets, parsePixKey } from "./ecosystem/dict.ts";
import { RiskEngine, type PixRecipientEvidence, type RiskDecision } from "./risk/engine.ts";
import { deviceQuarantine } from "./device-quarantine.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "./credit-cards.ts";
import { reconcileLoanContracts } from "./loan-contract-integrity.ts";
import { bookLoanProvisions, reconcileLoanProvisions } from "./loan-provisions.ts";
import { bookLoanInterestAccruals, installLoanInterestAccruals, reconcileLoanInterestAccruals } from "./loan-interest-accruals.ts";
import { installPeriodCloseSeals, recordPeriodCloseSeal, verifyPeriodCloseSeal } from "./period-close-seals.ts";
import { installPeriodResultTransfers, recordPeriodResultTransfer, reconcilePeriodResultTransfers } from "./period-result-transfer.ts";
import { AUDIT_SOURCE_BY_KIND, type BankAuditKind } from "./audit-actions.ts";
import { dictFraudCounter, installDictFraudHistory, type DictFraudCounter } from "./ecosystem/dict-fraud-history.ts";
import { parseSpiLatencyPolicy, spiLatencyMs, type SpiLatencyPolicy } from "./spi-latency.ts";
import { readDuePixCommands, readPendingPspCredit, readPendingPspCredits } from "./pix-outbox-commands.ts";
interface PixLimits {
    version: 1;
    max_transaction_cents: number;
    max_setting_cents: number;
    daily_by_tier_cents: [
        number,
        number,
        number,
        number
    ];
    night_limit_cents: number;
    night_start_hour: 20 | 22;
    new_device_transaction_cents: number;
    new_device_daily_cents: number;
}
const DEFAULT_PIX_LIMITS_PATH = fileURLToPath(new URL("../../../rules/pix/limits.json", import.meta.url));
const DEFAULT_SPI_LATENCY_PATH = fileURLToPath(new URL("../../../rules/spi/latency.json", import.meta.url));
export function parsePixLimits(bytes: Uint8Array): PixLimits {
    if (bytes.byteLength === 0 || bytes.byteLength > 16384)
        throw new Error("PIX_LIMITS_INVALID");
    let value: unknown;
    try {
        value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    }
    catch {
        throw new Error("PIX_LIMITS_INVALID");
    }
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("PIX_LIMITS_INVALID");
    const config = value as Partial<PixLimits>;
    const keys = ["version", "max_transaction_cents", "max_setting_cents", "daily_by_tier_cents",
        "night_limit_cents", "night_start_hour", "new_device_transaction_cents",
        "new_device_daily_cents"];
    const validAmount = (amount: unknown): amount is number => Number.isSafeInteger(amount) && (amount as number) >= 0 && (amount as number) <= 2000000;
    if (Object.keys(config).length !== keys.length || Object.keys(config).some((key) => !keys.includes(key)) ||
        config.version !== 1 || !validAmount(config.max_transaction_cents) || config.max_transaction_cents === 0 ||
        !validAmount(config.max_setting_cents) || !validAmount(config.night_limit_cents) ||
        config.night_limit_cents > config.max_setting_cents ||
        (config.night_start_hour !== 20 && config.night_start_hour !== 22) ||
        !validAmount(config.new_device_transaction_cents) || !validAmount(config.new_device_daily_cents) ||
        !Array.isArray(config.daily_by_tier_cents) || config.daily_by_tier_cents.length !== 4 ||
        config.daily_by_tier_cents.some((amount) => !validAmount(amount)))
        throw new Error("PIX_LIMITS_INVALID");
    return config as PixLimits;
}
export function loadPixLimits(path = DEFAULT_PIX_LIMITS_PATH): PixLimits {
    return parsePixLimits(readFileSync(path));
}
export type Persona = "salaried" | "merchant" | "student" | "retiree" | "gig" | "saver" | "night_owl";
export interface Customer {
    id: string;
    cpf: string;
    name: string;
    persona: Persona;
    kyc_tier: 0 | 1 | 2 | 3;
    kyc_status: "none" | "submitted" | "approved" | "rejected";
    risk_score: number;
    is_attacker_owned: boolean;
    status: "active" | "frozen" | "closed";
}
export interface Account {
    id: string;
    customer_id: string | null;
    kind: "checking" | "merchant" | "payment" | "salary" | "system";
    system_role: string | null;
    balance_cached: number;
    overdraft_limit: number;
    status: "under_review" | "active" | "frozen" | "closed";
    frozen_reason?: AccountFrozenReason | null;
    branch_code: string | null;
    account_number: string | null;
    account_digit: string | null;
}
export type AccountFrozenReason = "fraud_suspect" | "med" | "judicial" | "kyc";
export interface Posting {
    accountId: string;
    amount: number;
    kind: string;
    actor: string;
    refType: string;
    refId: string;
}
export interface ManualPostingLine {
    accountId: string;
    amount: number;
}
export interface ManualPostingRequest {
    id: string;
    maker_id: string;
    checker_id: string | null;
    reason: string;
    lines_json: string;
    status: "pending" | "approved" | "rejected";
    created_at: string;
    resolved_at: string | null;
    ledger_tx_id: string | null;
}
export type HoldKind = "card_auth" | "pix_cautelar" | "med_block" | "judicial";
export interface PixResult {
    id: string;
    end_to_end_id: string;
    from_account: string;
    to_account: string;
    amount: number;
    status: "in_processing" | "settled" | "rejected" | "returned_partial" | "returned_full";
    ledger_tx_id: string | null;
}
export interface PixReturnResult {
    id: string;
    transfer_id: string;
    amount: number;
    status: "returned_partial" | "returned_full";
    ledger_tx_id: string;
}
export interface ExternalPixReturnIntent {
    id: string;
    transfer_id: string;
    amount: number;
    status: "pending_psp" | "failed" | "returned_partial" | "returned_full";
    ledger_tx_id: string | null;
    failure_reason: string | null;
}
export interface PixTransferInput {
    from: string;
    to: string;
    amount: number;
    idempotencyKey: string;
    actor: string;
    deviceId?: string;
    stepUpVerified?: boolean;
    product?: "automatic";
    channel?: "scheduled";
}
export interface PixChannelLimit {
    channel: "app" | "scheduled";
    daily_limit_cents: number;
    pending: {
        value: number;
        effective_at: string;
    } | null;
    policy_version: number;
}
export interface ExternalPixRecipient {
    id: string;
    ispb: string;
    status: string;
    fraud_flag: number;
}
export interface ExternalPixKeyLookup {
    key: string;
    id: string;
    ispb: string;
    status: string;
    fraud_flag: number;
    holder_name: string;
    security: {
        key: DictFraudCounter;
        account: DictFraudCounter;
        cpf: DictFraudCounter;
    };
}
export interface RiskPixHold {
    id: string;
    from_account: string;
    to_account: string;
    amount_cents: number;
    idempotency_key: string;
    actor: string;
    device_id: string | null;
    step_up_verified: number;
    balance_hold_id: string;
    risk_decision_id: string;
    proximity_token_id: string | null;
    status: "pending" | "approved" | "rejected" | "expired";
    created_at: string;
    expires_at: string;
    resolved_at: string | null;
    reviewer: string | null;
    transfer_id: string | null;
    product: "standard" | "automatic";
    channel: "app" | "scheduled" | "automatic";
}
export interface RiskPixReviewAcknowledgement {
    hold_id: string;
    reviewer: string;
    acknowledged_at: string;
}
export interface PixNightSettings {
    night_limit_cents: number;
    night_start_hour: 20 | 22;
    pending_limit: {
        value: number;
        effective_at: string;
    } | null;
    pending_start_hour: {
        value: 20 | 22;
        effective_at: string;
    } | null;
}
export interface PixAutomaticLimit {
    account_id: string;
    daily_limit_cents: number;
    pending: {
        value: number;
        effective_at: string;
    } | null;
}
export interface PixKeyClaim {
    id: string;
    key: string;
    kind: "portability" | "ownership";
    status: "pending" | "verified" | "contested" | "completed" | "rejected";
    ready_at: string;
    verified_at: string | null;
    completed_at: string | null;
}
export interface ClosedAccountCredit {
    id: string;
    customer_id: string;
    source_account: string;
    source_kind: "pix_return" | "med_recovery";
    source_id: string;
    amount_cents: number;
    status: "pending" | "paid";
    ledger_tx_id: string;
    destination_account: string | null;
    payout_tx_id: string | null;
    created_at: string;
    paid_at: string | null;
}
export class BankError extends Error {
    readonly code: string;
    readonly risk: {
        score: number;
        reasonCodes: string[];
        holdId?: string;
    } | undefined;
    constructor(code: string, risk?: {
        score: number;
        reasonCodes: string[];
        holdId?: string;
    }) {
        super(code);
        this.code = code;
        this.risk = risk;
    }
}
export function brtHour(date: Date): number { return Number(new Intl.DateTimeFormat("en-GB", { timeZone: "America/Sao_Paulo", hour: "2-digit", hourCycle: "h23" }).format(date)); }
export function brtNightKey(date: Date): string {
    const anchor = brtHour(date) < 6 ? new Date(date.getTime() - 86400000) : date;
    const parts = new Intl.DateTimeFormat("en-US", { timeZone: "America/Sao_Paulo", year: "numeric",
        month: "2-digit", day: "2-digit" }).formatToParts(anchor);
    const value = (name: string): string => parts.find((part) => part.type === name)?.value ?? "";
    return `${value("year")}-${value("month")}-${value("day")}`;
}
export class Bank {
    readonly db: DatabaseSync;
    private readonly pixLimits: PixLimits;
    private readonly pixLimitsBytes: Buffer;
    private readonly spiLatencyPolicy: SpiLatencyPolicy;
    pixLimitsSnapshot(): {
        version: number;
        bytes: Buffer;
    } {
        return { version: this.pixLimits.version, bytes: Buffer.from(this.pixLimitsBytes) };
    }
    private readonly embeddedSpi?: SpiNetwork;
    private readonly embeddedPsp?: PspNetwork;
    private readonly separatedEcosystem: boolean;
    get isSeparatedEcosystem(): boolean { return this.separatedEcosystem; }
    get spi(): SpiNetwork {
        if (!this.embeddedSpi)
            throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
        return this.embeddedSpi;
    }
    get psp(): PspNetwork {
        if (!this.embeddedPsp)
            throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
        return this.embeddedPsp;
    }
    private periodCloseAnchor: {
        verify: () => void;
        prepare: (date: string, sha256: string) => void;
        confirm: (date: string, sha256: string) => void;
    } | undefined;
    readonly now: () => Date;
    readonly realNow: () => Date;
    readonly telemetry: TelemetryStore;
    readonly risk: RiskEngine;
    private readonly systemIds = new Map<SystemRole, string>();
    private readonly pixClaimProofs = new Map<string, string>();
    constructor(path: string, now: () => Date = () => new Date(), realNow: () => Date = () => new Date(), options: {
        pixLimitsBytes?: Uint8Array;
        pixLimitsPath?: string;
        spiLatencyBytes?: Uint8Array;
        spiLatencyPath?: string;
        ecosystemMode?: "embedded" | "separated";
    } = {}) {
        if (options.pixLimitsBytes !== undefined && options.pixLimitsPath !== undefined)
            throw new Error("PIX_LIMITS_SOURCE_CONFLICT");
        if (options.spiLatencyBytes !== undefined && options.spiLatencyPath !== undefined)
            throw new Error("SPI_LATENCY_SOURCE_CONFLICT");
        if (options.ecosystemMode !== undefined && options.ecosystemMode !== "embedded" &&
            options.ecosystemMode !== "separated")
            throw new Error("ECOSYSTEM_MODE_INVALID");
        this.pixLimitsBytes = Buffer.from(options.pixLimitsBytes ?? readFileSync(options.pixLimitsPath ?? DEFAULT_PIX_LIMITS_PATH));
        this.pixLimits = parsePixLimits(this.pixLimitsBytes);
        this.spiLatencyPolicy = parseSpiLatencyPolicy(options.spiLatencyBytes ??
            readFileSync(options.spiLatencyPath ?? DEFAULT_SPI_LATENCY_PATH));
        this.separatedEcosystem = options.ecosystemMode === "separated";
        this.db = new DatabaseSync(path, { timeout: 1000 });
        this.now = now;
        this.realNow = realNow;
        if (!this.separatedEcosystem && (this.db.prepare(`SELECT COUNT(*) n
      FROM sqlite_master WHERE type='table'
      AND name IN ('accounts','ledger_entries','pix_transfers')`).get() as {
            n: number;
        }).n === 3 &&
            (this.db.prepare(`SELECT COUNT(*) n FROM sqlite_master WHERE type='table'
        AND name IN ('spi_participants','psp_accounts')`).get() as {
                n: number;
            }).n !== 2) {
            this.db.close();
            throw new BankError("BANK_ONLY_REQUIRES_SEPARATED_MODE");
        }
        if (this.separatedEcosystem && this.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND (name GLOB 'spi_*' OR name GLOB 'psp_*'
        OR name GLOB 'dict_*') LIMIT 1`).get()) {
            this.db.close();
            throw new BankError("ECOSYSTEM_FILE_NOT_SEPARATED");
        }
        this.db.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;");
        if (!this.separatedEcosystem)
            installDictFraudHistory(this.db, this.now());
        this.db.exec(`
      CREATE TABLE IF NOT EXISTS customers (
        id TEXT PRIMARY KEY, cpf TEXT NOT NULL UNIQUE, name TEXT NOT NULL, persona TEXT NOT NULL,
        kyc_tier INTEGER NOT NULL, kyc_status TEXT NOT NULL, risk_score INTEGER NOT NULL,
        is_attacker_owned INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY, customer_id TEXT REFERENCES customers(id), kind TEXT NOT NULL,
        system_role TEXT, balance_cached INTEGER NOT NULL DEFAULT 0, overdraft_limit INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL, opened_at TEXT NOT NULL,
        branch_code TEXT, account_number TEXT, account_digit TEXT
      );
      CREATE INDEX IF NOT EXISTS account_customer ON accounts(customer_id);
      CREATE TABLE IF NOT EXISTS business_account_identity (
        account_id TEXT PRIMARY KEY REFERENCES accounts(id),
        cnpj TEXT NOT NULL UNIQUE, legal_name TEXT NOT NULL,
        representative_customer_id TEXT NOT NULL REFERENCES customers(id),
        verified_at TEXT NOT NULL, verified_by TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS salary_account_employers (
        account_id TEXT PRIMARY KEY REFERENCES accounts(id),
        employer_account_id TEXT NOT NULL REFERENCES accounts(id),
        employee_customer_id TEXT NOT NULL REFERENCES customers(id),
        opened_at TEXT NOT NULL
      );
      CREATE TRIGGER IF NOT EXISTS salary_employer_account_guard
        BEFORE INSERT ON salary_account_employers
        WHEN NOT EXISTS (SELECT 1 FROM accounts WHERE id=NEW.account_id
          AND kind='salary' AND customer_id=NEW.employee_customer_id)
          OR NOT EXISTS (SELECT 1 FROM accounts WHERE id=NEW.employer_account_id
            AND kind='merchant' AND status='active')
          OR NOT EXISTS (SELECT 1 FROM business_account_identity
            WHERE account_id=NEW.employer_account_id)
        BEGIN SELECT RAISE(ABORT,'SALARY_ACCOUNT_EMPLOYER_INVALID'); END;
      CREATE TRIGGER IF NOT EXISTS salary_employer_no_update
        BEFORE UPDATE ON salary_account_employers
        BEGIN SELECT RAISE(ABORT,'SALARY_EMPLOYER_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS salary_employer_no_delete
        BEFORE DELETE ON salary_account_employers
        BEGIN SELECT RAISE(ABORT,'SALARY_EMPLOYER_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS salary_portability_instructions (
        account_id TEXT PRIMARY KEY REFERENCES accounts(id),
        destination_account_id TEXT REFERENCES accounts(id),
        updated_at TEXT NOT NULL
      );
      CREATE TRIGGER IF NOT EXISTS salary_portability_instruction_insert_guard
        BEFORE INSERT ON salary_portability_instructions
        WHEN NOT EXISTS (SELECT 1 FROM accounts WHERE id=NEW.account_id
          AND kind='salary' AND customer_id IS NOT NULL)
          OR (NEW.destination_account_id IS NOT NULL AND NOT EXISTS
            (SELECT 1 FROM accounts destination JOIN accounts salary
              ON salary.id=NEW.account_id WHERE destination.id=NEW.destination_account_id
              AND destination.customer_id=salary.customer_id
              AND destination.kind IN ('checking','payment')))
        BEGIN SELECT RAISE(ABORT,'SALARY_INSTRUCTION_INVALID'); END;
      CREATE TRIGGER IF NOT EXISTS salary_portability_instruction_update_guard
        BEFORE UPDATE ON salary_portability_instructions
        WHEN NEW.account_id<>OLD.account_id OR NOT EXISTS
          (SELECT 1 FROM accounts WHERE id=NEW.account_id AND kind='salary')
          OR (NEW.destination_account_id IS NOT NULL AND NOT EXISTS
            (SELECT 1 FROM accounts destination JOIN accounts salary
              ON salary.id=NEW.account_id WHERE destination.id=NEW.destination_account_id
              AND destination.customer_id=salary.customer_id
              AND destination.kind IN ('checking','payment')))
        BEGIN SELECT RAISE(ABORT,'SALARY_INSTRUCTION_INVALID'); END;
      CREATE TRIGGER IF NOT EXISTS salary_portability_instructions_no_delete
        BEFORE DELETE ON salary_portability_instructions
        BEGIN SELECT RAISE(ABORT,'SALARY_INSTRUCTION_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS salary_portability_instruction_events (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
        destination_account_id TEXT REFERENCES accounts(id),
        actor_customer_id TEXT NOT NULL REFERENCES customers(id),
        changed_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS salary_portability_instruction_history
        ON salary_portability_instruction_events(account_id,changed_at,id);
      CREATE TRIGGER IF NOT EXISTS salary_portability_instruction_events_no_update
        BEFORE UPDATE ON salary_portability_instruction_events
        BEGIN SELECT RAISE(ABORT,'SALARY_INSTRUCTION_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS salary_portability_instruction_events_no_delete
        BEFORE DELETE ON salary_portability_instruction_events
        BEGIN SELECT RAISE(ABORT,'SALARY_INSTRUCTION_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS salary_payments (
        id TEXT PRIMARY KEY, employer_account_id TEXT NOT NULL REFERENCES accounts(id),
        salary_account_id TEXT NOT NULL REFERENCES accounts(id),
        amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        idempotency_key TEXT NOT NULL, ledger_tx_id TEXT NOT NULL,
        paid_at TEXT NOT NULL,
        UNIQUE(employer_account_id,idempotency_key)
      );
      CREATE TRIGGER IF NOT EXISTS salary_payments_no_update
        BEFORE UPDATE ON salary_payments
        BEGIN SELECT RAISE(ABORT,'SALARY_PAYMENT_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS salary_payments_no_delete
        BEFORE DELETE ON salary_payments
        BEGIN SELECT RAISE(ABORT,'SALARY_PAYMENT_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS salary_portabilities (
        id TEXT PRIMARY KEY, salary_account_id TEXT NOT NULL REFERENCES accounts(id),
        destination_account_id TEXT NOT NULL REFERENCES accounts(id),
        amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        idempotency_key TEXT NOT NULL, ledger_tx_id TEXT NOT NULL,
        transferred_at TEXT NOT NULL,
        UNIQUE(salary_account_id,idempotency_key)
      );
      CREATE TRIGGER IF NOT EXISTS salary_portabilities_no_update
        BEFORE UPDATE ON salary_portabilities
        BEGIN SELECT RAISE(ABORT,'SALARY_PORTABILITY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS salary_portabilities_no_delete
        BEFORE DELETE ON salary_portabilities
        BEGIN SELECT RAISE(ABORT,'SALARY_PORTABILITY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS business_identity_account_guard
        BEFORE INSERT ON business_account_identity
        WHEN NOT EXISTS (SELECT 1 FROM accounts WHERE id=NEW.account_id
          AND kind='merchant' AND customer_id=NEW.representative_customer_id)
        BEGIN SELECT RAISE(ABORT,'BUSINESS_ACCOUNT_OWNER_INVALID'); END;
      CREATE TRIGGER IF NOT EXISTS business_identity_no_replace
        BEFORE INSERT ON business_account_identity
        WHEN EXISTS (SELECT 1 FROM business_account_identity WHERE account_id=NEW.account_id)
        BEGIN SELECT RAISE(ABORT,'BUSINESS_IDENTITY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS business_identity_no_update
        BEFORE UPDATE ON business_account_identity
        BEGIN SELECT RAISE(ABORT,'BUSINESS_IDENTITY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS business_identity_no_delete
        BEFORE DELETE ON business_account_identity
        BEGIN SELECT RAISE(ABORT,'BUSINESS_IDENTITY_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS account_status_changes (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
        from_status TEXT NOT NULL, to_status TEXT NOT NULL,
        reason TEXT, actor TEXT NOT NULL, changed_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS account_status_history ON account_status_changes(account_id,changed_at,id);
      CREATE INDEX IF NOT EXISTS account_status_change_window
        ON account_status_changes(changed_at,account_id);
      CREATE TRIGGER IF NOT EXISTS account_status_no_update BEFORE UPDATE ON account_status_changes
      BEGIN SELECT RAISE(ABORT, 'ACCOUNT_STATUS_HISTORY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS account_status_no_delete BEFORE DELETE ON account_status_changes
      BEGIN SELECT RAISE(ABORT, 'ACCOUNT_STATUS_HISTORY_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS ledger_entries (
        id TEXT PRIMARY KEY, tx_id TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id),
        amount INTEGER NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL, ref_type TEXT NOT NULL,
        ref_id TEXT NOT NULL, created_at TEXT NOT NULL, reverses_tx_id TEXT
      );
      CREATE INDEX IF NOT EXISTS ledger_account ON ledger_entries(account_id,created_at);
      CREATE INDEX IF NOT EXISTS ledger_tx ON ledger_entries(tx_id);
      CREATE UNIQUE INDEX IF NOT EXISTS ledger_med_incident_loss
        ON ledger_entries(ref_id) WHERE kind='med_incident_loss' AND ref_type='med_case';
      CREATE TABLE IF NOT EXISTS manual_posting_requests (
        id TEXT PRIMARY KEY, maker_id TEXT NOT NULL, checker_id TEXT,
        reason TEXT NOT NULL, lines_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
        created_at TEXT NOT NULL, resolved_at TEXT, ledger_tx_id TEXT,
        CHECK(checker_id IS NULL OR checker_id<>maker_id),
        CHECK((status='pending' AND checker_id IS NULL AND resolved_at IS NULL AND ledger_tx_id IS NULL)
          OR (status='rejected' AND checker_id IS NOT NULL AND resolved_at IS NOT NULL AND ledger_tx_id IS NULL)
          OR (status='approved' AND checker_id IS NOT NULL AND resolved_at IS NOT NULL AND ledger_tx_id IS NOT NULL))
      );
      CREATE INDEX IF NOT EXISTS manual_posting_requests_maker_window
        ON manual_posting_requests(created_at,maker_id);
      CREATE INDEX IF NOT EXISTS manual_posting_requests_checker_window
        ON manual_posting_requests(resolved_at,checker_id,status);
      CREATE TRIGGER IF NOT EXISTS manual_posting_request_immutable
      BEFORE UPDATE OF id,maker_id,reason,lines_json,created_at ON manual_posting_requests
      BEGIN SELECT RAISE(ABORT, 'MANUAL_POSTING_REQUEST_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS manual_posting_request_no_delete
      BEFORE DELETE ON manual_posting_requests
      BEGIN SELECT RAISE(ABORT, 'MANUAL_POSTING_REQUEST_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS manual_posting_request_terminal
      BEFORE UPDATE OF status,checker_id,resolved_at,ledger_tx_id ON manual_posting_requests
      WHEN OLD.status<>'pending' OR NEW.status='pending'
      BEGIN SELECT RAISE(ABORT, 'MANUAL_POSTING_REQUEST_TERMINAL'); END;
      CREATE TABLE IF NOT EXISTS balance_holds (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
        amount INTEGER NOT NULL CHECK(amount>0),
        kind TEXT NOT NULL CHECK(kind IN ('card_auth','pix_cautelar','med_block','judicial')),
        ref TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL, released_at TEXT, release_actor TEXT,
        UNIQUE(kind,ref)
      );
      CREATE INDEX IF NOT EXISTS balance_holds_active ON balance_holds(account_id,released_at,expires_at);
      CREATE TABLE IF NOT EXISTS risk_pix_holds (
        id TEXT PRIMARY KEY, from_account TEXT NOT NULL REFERENCES accounts(id),
        to_account TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        idempotency_key TEXT NOT NULL, actor TEXT NOT NULL, device_id TEXT,
        step_up_verified INTEGER NOT NULL CHECK(step_up_verified IN (0,1)),
        balance_hold_id TEXT NOT NULL UNIQUE REFERENCES balance_holds(id),
        risk_decision_id TEXT NOT NULL UNIQUE REFERENCES risk_decisions(id),
        product TEXT NOT NULL DEFAULT 'standard',
        channel TEXT NOT NULL DEFAULT 'app' CHECK(channel IN ('app','scheduled','automatic')),
        proximity_token_id TEXT,
        status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','expired')),
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, resolved_at TEXT,
        reviewer TEXT, transfer_id TEXT REFERENCES pix_transfers(id),
        UNIQUE(from_account,idempotency_key)
      );
      CREATE INDEX IF NOT EXISTS risk_pix_holds_status ON risk_pix_holds(status,expires_at);
      CREATE INDEX IF NOT EXISTS risk_pix_review_window
        ON risk_pix_holds(resolved_at,reviewer,status);
      CREATE TABLE IF NOT EXISTS risk_pix_review_acknowledgements (
        hold_id TEXT PRIMARY KEY REFERENCES risk_pix_holds(id),
        reviewer TEXT NOT NULL, acknowledged_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS risk_pix_ack_window
        ON risk_pix_review_acknowledgements(acknowledged_at,reviewer);
      CREATE TRIGGER IF NOT EXISTS risk_pix_review_ack_no_update
      BEFORE UPDATE ON risk_pix_review_acknowledgements
        BEGIN SELECT RAISE(ABORT, 'RISK_REVIEW_ACK_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS risk_pix_review_ack_no_delete
      BEFORE DELETE ON risk_pix_review_acknowledgements
        BEGIN SELECT RAISE(ABORT, 'RISK_REVIEW_ACK_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS pix_transfers (
        id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL, from_account TEXT NOT NULL,
        to_account TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL,
        initiated_at TEXT NOT NULL, settled_at TEXT, ledger_tx_id TEXT,
        night_mode INTEGER NOT NULL, actor TEXT NOT NULL, end_to_end_id TEXT,
        initiating_device_id TEXT, risk_decision_id TEXT REFERENCES risk_decisions(id),
        product TEXT NOT NULL DEFAULT 'standard',
        channel TEXT NOT NULL DEFAULT 'app' CHECK(channel IN ('app','scheduled','automatic')),
        spi_command_version INTEGER NOT NULL DEFAULT 0,
        UNIQUE(from_account,idempotency_key)
      );
      CREATE TABLE IF NOT EXISTS pix_spi_outbox (
        transfer_id TEXT PRIMARY KEY REFERENCES pix_transfers(id),
        end_to_end_id TEXT NOT NULL UNIQUE,
        from_ispb TEXT NOT NULL, to_ispb TEXT NOT NULL,
        amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        trace_id TEXT,
        queued_at_real TEXT,
        eligible_at_real TEXT,
        deadline_at_real TEXT,
        latency_policy_version INTEGER,
        response_status TEXT CHECK(response_status IN ('ACSC','RJCT')),
        response_reason TEXT,
        created_at TEXT NOT NULL, responded_at TEXT, responded_at_real TEXT,
        CHECK((response_status IS NULL AND responded_at IS NULL AND response_reason IS NULL)
          OR (response_status IS NOT NULL AND responded_at IS NOT NULL))
      );
      CREATE TRIGGER IF NOT EXISTS pix_spi_outbox_request_immutable
      BEFORE UPDATE OF transfer_id,end_to_end_id,from_ispb,to_ispb,amount_cents,created_at
      ON pix_spi_outbox BEGIN SELECT RAISE(ABORT,'PIX_SPI_COMMAND_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS pix_spi_outbox_response_immutable
      BEFORE UPDATE OF response_status,response_reason,responded_at ON pix_spi_outbox
      WHEN OLD.response_status IS NOT NULL
      BEGIN SELECT RAISE(ABORT,'PIX_SPI_RESPONSE_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS pix_spi_outbox_no_delete
      BEFORE DELETE ON pix_spi_outbox
      BEGIN SELECT RAISE(ABORT,'PIX_SPI_COMMAND_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS pix_psp_inbound_outbox (
        transfer_id TEXT PRIMARY KEY REFERENCES pix_transfers(id),
        end_to_end_id TEXT NOT NULL UNIQUE,
        to_account TEXT NOT NULL,
        amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        from_account TEXT,
        settled_at TEXT,
        trace_id TEXT,
        created_at TEXT NOT NULL,
        acknowledged_at TEXT
      );
      CREATE TRIGGER IF NOT EXISTS pix_psp_inbound_command_immutable
      BEFORE UPDATE OF transfer_id,end_to_end_id,to_account,amount_cents,trace_id,created_at
      ON pix_psp_inbound_outbox
      BEGIN SELECT RAISE(ABORT,'PIX_PSP_COMMAND_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS pix_psp_inbound_ack_immutable
      BEFORE UPDATE OF acknowledged_at ON pix_psp_inbound_outbox
      WHEN OLD.acknowledged_at IS NOT NULL
      BEGIN SELECT RAISE(ABORT,'PIX_PSP_ACK_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS pix_psp_inbound_no_delete
      BEFORE DELETE ON pix_psp_inbound_outbox
      BEGIN SELECT RAISE(ABORT,'PIX_PSP_COMMAND_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS pix_status_history (
        id INTEGER PRIMARY KEY, transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        status TEXT NOT NULL, changed_at TEXT NOT NULL, reason TEXT
      );
      CREATE INDEX IF NOT EXISTS pix_status_transfer ON pix_status_history(transfer_id,id);
      CREATE INDEX IF NOT EXISTS pix_settled_time ON pix_transfers(settled_at);
      CREATE INDEX IF NOT EXISTS pix_outbound_time ON pix_transfers(from_account,settled_at);
      CREATE INDEX IF NOT EXISTS pix_outbound_initiated ON pix_transfers(from_account,initiated_at DESC,id DESC);
      CREATE TABLE IF NOT EXISTS pix_automatic_limits (
        account_id TEXT PRIMARY KEY REFERENCES accounts(id),
        daily_limit_cents INTEGER NOT NULL CHECK(daily_limit_cents BETWEEN 0 AND 2000000),
        pending_limit_cents INTEGER CHECK(pending_limit_cents BETWEEN 0 AND 2000000),
        pending_effective_at TEXT
      );
      CREATE TABLE IF NOT EXISTS pix_channel_limits (
        customer_id TEXT NOT NULL REFERENCES customers(id),
        channel TEXT NOT NULL CHECK(channel IN ('app','scheduled')),
        daily_limit_cents INTEGER NOT NULL CHECK(daily_limit_cents BETWEEN 0 AND 2000000),
        pending_limit_cents INTEGER CHECK(pending_limit_cents BETWEEN 0 AND 2000000),
        pending_effective_at TEXT,
        policy_version INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY(customer_id,channel)
      );
      CREATE INDEX IF NOT EXISTS pix_inbound_time ON pix_transfers(to_account,settled_at);
      CREATE TABLE IF NOT EXISTS pix_returns (
        id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        idempotency_key TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0),
        reason TEXT NOT NULL, status TEXT NOT NULL, ledger_tx_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(transfer_id,idempotency_key)
      );
      CREATE INDEX IF NOT EXISTS pix_returns_transfer ON pix_returns(transfer_id);
      CREATE TABLE IF NOT EXISTS pix_psp_return_outbox (
        id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        end_to_end_id TEXT NOT NULL, recipient_account TEXT NOT NULL,
        idempotency_key TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        reason TEXT NOT NULL CHECK(reason='ordinary'), created_at TEXT NOT NULL,
        acknowledged_at TEXT, rejected_at TEXT, failure_reason TEXT,
        UNIQUE(transfer_id,idempotency_key),
        CHECK(NOT (acknowledged_at IS NOT NULL AND rejected_at IS NOT NULL)),
        CHECK((rejected_at IS NULL AND failure_reason IS NULL) OR
          (rejected_at IS NOT NULL AND failure_reason IS NOT NULL))
      );
      CREATE INDEX IF NOT EXISTS pix_psp_return_pending
        ON pix_psp_return_outbox(acknowledged_at,rejected_at,created_at);
      CREATE TRIGGER IF NOT EXISTS pix_psp_return_command_immutable
        BEFORE UPDATE OF id,transfer_id,end_to_end_id,recipient_account,
          idempotency_key,amount_cents,reason,created_at ON pix_psp_return_outbox
        BEGIN SELECT RAISE(ABORT,'PIX_PSP_RETURN_COMMAND_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS pix_psp_return_terminal_once
        BEFORE UPDATE OF acknowledged_at,rejected_at,failure_reason ON pix_psp_return_outbox
        WHEN OLD.acknowledged_at IS NOT NULL OR OLD.rejected_at IS NOT NULL OR
          (NEW.acknowledged_at IS NULL AND NEW.rejected_at IS NULL)
        BEGIN SELECT RAISE(ABORT,'PIX_PSP_RETURN_TERMINAL_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS pix_psp_return_no_delete
        BEFORE DELETE ON pix_psp_return_outbox
        BEGIN SELECT RAISE(ABORT,'PIX_PSP_RETURN_COMMAND_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS pix_psp_cautelar_return_outbox (
        id TEXT PRIMARY KEY, hold_id TEXT NOT NULL UNIQUE,
        transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        end_to_end_id TEXT NOT NULL, recipient_account TEXT NOT NULL,
        amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        actor TEXT NOT NULL, created_at TEXT NOT NULL,
        acknowledged_at TEXT, rejected_at TEXT, failure_reason TEXT,
        CHECK(NOT (acknowledged_at IS NOT NULL AND rejected_at IS NOT NULL)),
        CHECK((rejected_at IS NULL AND failure_reason IS NULL) OR
          (rejected_at IS NOT NULL AND failure_reason IS NOT NULL))
      );
      CREATE INDEX IF NOT EXISTS pix_psp_cautelar_return_pending
        ON pix_psp_cautelar_return_outbox(acknowledged_at,rejected_at,created_at);
      CREATE TRIGGER IF NOT EXISTS pix_psp_cautelar_return_command_immutable
        BEFORE UPDATE OF id,hold_id,transfer_id,end_to_end_id,recipient_account,
          amount_cents,actor,created_at ON pix_psp_cautelar_return_outbox
        BEGIN SELECT RAISE(ABORT,'PIX_PSP_CAUTELAR_RETURN_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS pix_psp_cautelar_return_terminal_once
        BEFORE UPDATE OF acknowledged_at,rejected_at,failure_reason
        ON pix_psp_cautelar_return_outbox
        WHEN OLD.acknowledged_at IS NOT NULL OR OLD.rejected_at IS NOT NULL OR
          (NEW.acknowledged_at IS NULL AND NEW.rejected_at IS NULL)
        BEGIN SELECT RAISE(ABORT,'PIX_PSP_CAUTELAR_RETURN_TERMINAL_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS pix_psp_cautelar_return_no_delete
        BEFORE DELETE ON pix_psp_cautelar_return_outbox
        BEGIN SELECT RAISE(ABORT,'PIX_PSP_CAUTELAR_RETURN_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS closed_account_credits (
        id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
        source_account TEXT NOT NULL REFERENCES accounts(id),
        source_kind TEXT NOT NULL CHECK(source_kind IN ('pix_return','med_recovery')),
        source_id TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        status TEXT NOT NULL CHECK(status IN ('pending','paid')),
        ledger_tx_id TEXT NOT NULL, destination_account TEXT REFERENCES accounts(id),
        payout_tx_id TEXT, created_at TEXT NOT NULL, paid_at TEXT,
        UNIQUE(source_kind,source_id),
        CHECK((status='pending' AND destination_account IS NULL AND payout_tx_id IS NULL
          AND paid_at IS NULL) OR (status='paid' AND destination_account IS NOT NULL
          AND payout_tx_id IS NOT NULL AND paid_at IS NOT NULL))
      );
      CREATE INDEX IF NOT EXISTS closed_account_credits_customer
        ON closed_account_credits(customer_id,status,id);
      CREATE INDEX IF NOT EXISTS closed_account_credits_paid_window
        ON closed_account_credits(paid_at,customer_id) WHERE status='paid';
      CREATE TRIGGER IF NOT EXISTS closed_account_credits_no_delete
        BEFORE DELETE ON closed_account_credits
        BEGIN SELECT RAISE(ABORT, 'CLOSED_CREDIT_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS closed_account_credits_no_rewrite
        BEFORE UPDATE OF id,customer_id,source_account,source_kind,source_id,
          amount_cents,ledger_tx_id,created_at ON closed_account_credits
        BEGIN SELECT RAISE(ABORT, 'CLOSED_CREDIT_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS closed_account_credits_terminal
        BEFORE UPDATE OF status,destination_account,payout_tx_id,paid_at
        ON closed_account_credits
        WHEN OLD.status<>'pending' OR NEW.status<>'paid'
        BEGIN SELECT RAISE(ABORT, 'CLOSED_CREDIT_TERMINAL'); END;
      CREATE TABLE IF NOT EXISTS pix_limits (
        id INTEGER PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
        setting TEXT NOT NULL CHECK(setting IN ('night_limit_cents','night_start_hour')),
        value INTEGER NOT NULL CHECK((setting='night_limit_cents' AND value BETWEEN 0 AND 2000000)
          OR (setting='night_start_hour' AND value IN (20,22))),
        requested_at TEXT NOT NULL, effective_at TEXT NOT NULL,
        superseded_at TEXT
      );
      CREATE INDEX IF NOT EXISTS pix_limits_customer ON pix_limits(customer_id,setting,effective_at,id);
      CREATE TABLE IF NOT EXISTS access_log (
        id TEXT PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL,
        customer_id TEXT, account_id TEXT, route TEXT, status INTEGER NOT NULL, peer_ip TEXT
      );
      CREATE INDEX IF NOT EXISTS access_kind_time ON access_log(kind,ts);
      CREATE TABLE IF NOT EXISTS weakness_state (
        id TEXT PRIMARY KEY, open INTEGER NOT NULL, changed_at TEXT NOT NULL, changed_by TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS feature_flags (
        id TEXT PRIMARY KEY, day INTEGER NOT NULL, enabled INTEGER NOT NULL,
        flaw_open INTEGER NOT NULL, launched_at TEXT, changed_by TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS kyc_requests (
        customer_id TEXT PRIMARY KEY REFERENCES customers(id), requested_tier INTEGER NOT NULL,
        status TEXT NOT NULL, submitted_at TEXT NOT NULL, approved_at TEXT
      );
      CREATE TABLE IF NOT EXISTS kyc_history (
        id INTEGER PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
        event TEXT NOT NULL CHECK(event IN ('submitted','approved')),
        previous_tier INTEGER NOT NULL, requested_tier INTEGER NOT NULL,
        twin_at TEXT NOT NULL, recorded_at TEXT NOT NULL, reviewer TEXT
      );
      CREATE INDEX IF NOT EXISTS kyc_history_customer ON kyc_history(customer_id,id);
      CREATE TRIGGER IF NOT EXISTS kyc_history_no_replace BEFORE INSERT ON kyc_history
        WHEN NEW.id IS NOT NULL AND EXISTS (SELECT 1 FROM kyc_history WHERE id=NEW.id)
        BEGIN SELECT RAISE(ABORT,'KYC_HISTORY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS kyc_history_no_update BEFORE UPDATE ON kyc_history
        BEGIN SELECT RAISE(ABORT,'KYC_HISTORY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS kyc_history_no_delete BEFORE DELETE ON kyc_history
        BEGIN SELECT RAISE(ABORT,'KYC_HISTORY_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS onboarding_applications (
        customer_id TEXT PRIMARY KEY REFERENCES customers(id),
        account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id),
        bureau_score INTEGER NOT NULL CHECK(bureau_score BETWEEN 0 AND 100),
        liveness_status TEXT NOT NULL CHECK(liveness_status IN ('pending','passed','failed')),
        liveness_verifier TEXT,
        status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
        submitted_at TEXT NOT NULL, reviewed_at TEXT, reviewer TEXT,
        CHECK((status='pending' AND reviewed_at IS NULL AND reviewer IS NULL)
          OR (status<>'pending' AND reviewed_at IS NOT NULL AND reviewer IS NOT NULL))
      );
      CREATE TRIGGER IF NOT EXISTS onboarding_application_no_replace
        BEFORE INSERT ON onboarding_applications
        WHEN EXISTS (SELECT 1 FROM onboarding_applications WHERE customer_id=NEW.customer_id)
        BEGIN SELECT RAISE(ABORT,'ONBOARDING_APPLICATION_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS onboarding_application_identity_immutable
        BEFORE UPDATE OF customer_id,account_id,bureau_score,submitted_at ON onboarding_applications
        BEGIN SELECT RAISE(ABORT,'ONBOARDING_APPLICATION_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS onboarding_application_terminal
        BEFORE UPDATE ON onboarding_applications
        WHEN OLD.status<>'pending' OR
          (OLD.liveness_status<>'pending' AND NEW.liveness_status<>OLD.liveness_status) OR
          (OLD.liveness_verifier IS NOT NULL AND NEW.liveness_verifier IS NOT OLD.liveness_verifier) OR
          (NEW.status='approved' AND (NEW.liveness_status<>'passed' OR NEW.bureau_score<20
            OR NEW.liveness_verifier IS NULL OR NEW.reviewer=NEW.liveness_verifier))
        BEGIN SELECT RAISE(ABORT,'ONBOARDING_APPLICATION_TERMINAL'); END;
      CREATE TABLE IF NOT EXISTS onboarding_events (
        id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
        event TEXT NOT NULL CHECK(event IN ('submitted','liveness_passed','liveness_failed','approved','rejected')),
        actor TEXT NOT NULL, twin_at TEXT NOT NULL, recorded_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS onboarding_events_customer ON onboarding_events(customer_id,twin_at,id);
      CREATE TRIGGER IF NOT EXISTS onboarding_events_no_replace BEFORE INSERT ON onboarding_events
        WHEN EXISTS (SELECT 1 FROM onboarding_events WHERE id=NEW.id)
        BEGIN SELECT RAISE(ABORT,'ONBOARDING_HISTORY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS onboarding_events_no_update BEFORE UPDATE ON onboarding_events
        BEGIN SELECT RAISE(ABORT,'ONBOARDING_HISTORY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS onboarding_events_no_delete BEFORE DELETE ON onboarding_events
        BEGIN SELECT RAISE(ABORT,'ONBOARDING_HISTORY_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS pix_keys (
        id TEXT PRIMARY KEY, key_value TEXT NOT NULL UNIQUE, account_id TEXT NOT NULL REFERENCES accounts(id),
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pix_lookup_attempts (
        id TEXT PRIMARY KEY, session_hash TEXT NOT NULL, key_hash TEXT NOT NULL, ts TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS pix_lookup_session_time ON pix_lookup_attempts(session_hash,ts);
      CREATE TABLE IF NOT EXISTS pix_key_claims (
        id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES pix_keys(id),
        kind TEXT NOT NULL CHECK(kind IN ('portability','ownership')),
        from_account TEXT NOT NULL REFERENCES accounts(id),
        to_account TEXT NOT NULL REFERENCES accounts(id),
        requester_customer_id TEXT NOT NULL REFERENCES customers(id),
        status TEXT NOT NULL CHECK(status IN ('pending','verified','contested','completed','rejected')),
        requested_at TEXT NOT NULL, ready_at TEXT NOT NULL,
        verified_at TEXT, proof_hash TEXT, proof_expires_at TEXT,
        attempts INTEGER NOT NULL DEFAULT 0, proof_issues INTEGER NOT NULL DEFAULT 0,
        completed_at TEXT
      );
      CREATE UNIQUE INDEX IF NOT EXISTS pix_key_active_claim ON pix_key_claims(key_id)
        WHERE status IN ('pending','verified');
      CREATE TABLE IF NOT EXISTS med_cases (
        id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL UNIQUE REFERENCES pix_transfers(id),
        customer_id TEXT NOT NULL REFERENCES customers(id), status TEXT NOT NULL,
        opened_at TEXT NOT NULL, resolve_after TEXT NOT NULL,
        timing_policy_version INTEGER NOT NULL DEFAULT 2 CHECK(timing_policy_version IN (1,2)),
        recovery_initiated_at TEXT,
        refunded_cents INTEGER NOT NULL DEFAULT 0,
        unrecovered_cents INTEGER NOT NULL DEFAULT 0,
        claim_amount_cents INTEGER CHECK(claim_amount_cents>0)
      );
      CREATE TABLE IF NOT EXISTS med_refunds (
        id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES med_cases(id), amount INTEGER NOT NULL,
        ledger_tx_id TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS med_psp_open_outbox (
        case_id TEXT PRIMARY KEY REFERENCES med_cases(id),
        transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        claim_amount_cents INTEGER NOT NULL CHECK(claim_amount_cents>0),
        created_at TEXT NOT NULL, acknowledged_at TEXT
      );
      CREATE INDEX IF NOT EXISTS med_psp_open_pending
        ON med_psp_open_outbox(acknowledged_at,created_at);
      CREATE TRIGGER IF NOT EXISTS med_psp_open_command_immutable
        BEFORE UPDATE OF case_id,transfer_id,claim_amount_cents,created_at
        ON med_psp_open_outbox
        BEGIN SELECT RAISE(ABORT,'MED_PSP_OPEN_COMMAND_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_psp_open_ack_immutable
        BEFORE UPDATE OF acknowledged_at ON med_psp_open_outbox
        WHEN OLD.acknowledged_at IS NOT NULL OR NEW.acknowledged_at IS NULL
        BEGIN SELECT RAISE(ABORT,'MED_PSP_OPEN_ACK_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_psp_open_no_delete
        BEFORE DELETE ON med_psp_open_outbox
        BEGIN SELECT RAISE(ABORT,'MED_PSP_OPEN_COMMAND_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS med_psp_release_outbox (
        case_id TEXT PRIMARY KEY REFERENCES med_cases(id),
        transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        created_at TEXT NOT NULL, acknowledged_at TEXT
      );
      CREATE INDEX IF NOT EXISTS med_psp_release_pending
        ON med_psp_release_outbox(acknowledged_at,created_at);
      CREATE TRIGGER IF NOT EXISTS med_psp_release_command_immutable
        BEFORE UPDATE OF case_id,transfer_id,created_at
        ON med_psp_release_outbox
        BEGIN SELECT RAISE(ABORT,'MED_PSP_RELEASE_COMMAND_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_psp_release_ack_immutable
        BEFORE UPDATE OF acknowledged_at ON med_psp_release_outbox
        WHEN OLD.acknowledged_at IS NOT NULL OR NEW.acknowledged_at IS NULL
        BEGIN SELECT RAISE(ABORT,'MED_PSP_RELEASE_ACK_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_psp_release_no_delete
        BEFORE DELETE ON med_psp_release_outbox
        BEGIN SELECT RAISE(ABORT,'MED_PSP_RELEASE_COMMAND_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS med_psp_settlement_outbox (
        case_id TEXT PRIMARY KEY REFERENCES med_cases(id),
        transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        end_to_end_id TEXT NOT NULL,
        claim_amount_cents INTEGER NOT NULL CHECK(claim_amount_cents>0),
        created_at TEXT NOT NULL, acknowledged_at TEXT,
        requires_timeline INTEGER NOT NULL DEFAULT 1 CHECK(requires_timeline IN (0,1))
      );
      CREATE INDEX IF NOT EXISTS med_psp_settlement_pending
        ON med_psp_settlement_outbox(acknowledged_at,created_at);
      CREATE TRIGGER IF NOT EXISTS med_psp_settlement_command_immutable
        BEFORE UPDATE OF case_id,transfer_id,end_to_end_id,claim_amount_cents,created_at
        ON med_psp_settlement_outbox
        BEGIN SELECT RAISE(ABORT,'MED_PSP_SETTLEMENT_COMMAND_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_psp_settlement_ack_immutable
        BEFORE UPDATE OF acknowledged_at ON med_psp_settlement_outbox
        WHEN OLD.acknowledged_at IS NOT NULL OR NEW.acknowledged_at IS NULL
        BEGIN SELECT RAISE(ABORT,'MED_PSP_SETTLEMENT_ACK_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_psp_settlement_no_delete
        BEFORE DELETE ON med_psp_settlement_outbox
        BEGIN SELECT RAISE(ABORT,'MED_PSP_SETTLEMENT_COMMAND_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS med_dict_analyses (
        case_id TEXT PRIMARY KEY REFERENCES med_cases(id),
        analysed_at TEXT NOT NULL,
        recorded_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS med_dict_analysis_outbox (
        case_id TEXT PRIMARY KEY REFERENCES med_cases(id),
        transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        approved_at TEXT NOT NULL,
        acknowledged_at TEXT
      );
      CREATE TRIGGER IF NOT EXISTS med_dict_analysis_command_immutable
        BEFORE UPDATE OF case_id,transfer_id,approved_at
        ON med_dict_analysis_outbox
        BEGIN SELECT RAISE(ABORT,'MED_DICT_ANALYSIS_COMMAND_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_dict_analysis_no_delete
        BEFORE DELETE ON med_dict_analysis_outbox
        BEGIN SELECT RAISE(ABORT,'MED_DICT_ANALYSIS_COMMAND_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_dict_analysis_ack_immutable
        BEFORE UPDATE OF acknowledged_at ON med_dict_analysis_outbox
        WHEN OLD.acknowledged_at IS NOT NULL OR NEW.acknowledged_at IS NULL
        BEGIN SELECT RAISE(ABORT,'MED_DICT_ANALYSIS_ACK_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_dict_analyses_no_update
        BEFORE UPDATE ON med_dict_analyses
        BEGIN SELECT RAISE(ABORT,'MED_DICT_ANALYSIS_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_dict_analyses_no_delete
        BEFORE DELETE ON med_dict_analyses
        BEGIN SELECT RAISE(ABORT,'MED_DICT_ANALYSIS_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS med_psp_refund_steps (
        case_id TEXT NOT NULL REFERENCES med_cases(id),
        ispb TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>0),
        requested_at TEXT NOT NULL, deadline_at TEXT NOT NULL,
        processed_at TEXT NOT NULL,
        refunded_cents INTEGER NOT NULL CHECK(refunded_cents>=0),
        PRIMARY KEY(case_id,ispb), UNIQUE(case_id,sequence)
      );
      CREATE TRIGGER IF NOT EXISTS med_psp_refund_steps_no_update
        BEFORE UPDATE ON med_psp_refund_steps
        BEGIN SELECT RAISE(ABORT,'MED_PSP_REFUND_STEP_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_psp_refund_steps_no_delete
        BEFORE DELETE ON med_psp_refund_steps
        BEGIN SELECT RAISE(ABORT,'MED_PSP_REFUND_STEP_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS med_decisions (
        case_id TEXT PRIMARY KEY REFERENCES med_cases(id),
        decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
        maker_id TEXT NOT NULL, checker_id TEXT NOT NULL,
        evidence_ref TEXT NOT NULL, decided_at TEXT NOT NULL,
        CHECK(maker_id<>checker_id)
      );
      CREATE TRIGGER IF NOT EXISTS med_decisions_no_update BEFORE UPDATE ON med_decisions
      BEGIN SELECT RAISE(ABORT,'MED_DECISION_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS med_decisions_no_delete BEFORE DELETE ON med_decisions
      BEGIN SELECT RAISE(ABORT,'MED_DECISION_IMMUTABLE'); END;
      CREATE TABLE IF NOT EXISTS med_replay_outbox (
        case_id TEXT PRIMARY KEY REFERENCES med_cases(id),
        enqueued_at TEXT NOT NULL, published_at TEXT
      );
      CREATE TABLE IF NOT EXISTS med_hops (
        id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES med_cases(id),
        root_transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        account_id TEXT NOT NULL,
        blocked_cents INTEGER NOT NULL CHECK(blocked_cents>0),
        refunded_cents INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL, released_at TEXT
      );
      CREATE INDEX IF NOT EXISTS med_hops_active ON med_hops(account_id,root_transfer_id,released_at);
      CREATE TABLE IF NOT EXISTS period_closes (
        brt_date TEXT PRIMARY KEY, closed_at TEXT NOT NULL,
        ledger_entries_count INTEGER NOT NULL, ledger_sum INTEGER NOT NULL, integrity_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS blue_containments (
        id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, actor_id TEXT NOT NULL,
        kind TEXT NOT NULL, target TEXT NOT NULL, direction TEXT,
        reason TEXT NOT NULL, evidence_json TEXT NOT NULL, created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL, lifted_at TEXT
      );
      CREATE INDEX IF NOT EXISTS blue_containments_active ON blue_containments(kind,target,expires_at);
    `);
        const closeColumns = this.db.prepare("PRAGMA table_info(period_closes)").all() as {
            name: string;
        }[];
        if (!closeColumns.some((column) => column.name === "chart_version"))
            this.db.exec("ALTER TABLE period_closes ADD COLUMN chart_version INTEGER NOT NULL DEFAULT 1");
        if (!closeColumns.some((column) => column.name === "calendar_version"))
            this.db.exec("ALTER TABLE period_closes ADD COLUMN calendar_version INTEGER NOT NULL DEFAULT 0");
        if (!closeColumns.some((column) => column.name === "cutoff_policy_version"))
            this.db.exec("ALTER TABLE period_closes ADD COLUMN cutoff_policy_version INTEGER NOT NULL DEFAULT 1");
        const pixColumns = this.db.prepare("PRAGMA table_info(pix_transfers)").all() as {
            name: string;
        }[];
        if (!pixColumns.some((column) => column.name === "end_to_end_id"))
            this.db.exec("ALTER TABLE pix_transfers ADD COLUMN end_to_end_id TEXT");
        if (!pixColumns.some((column) => column.name === "initiating_device_id"))
            this.db.exec("ALTER TABLE pix_transfers ADD COLUMN initiating_device_id TEXT");
        if (!pixColumns.some((column) => column.name === "risk_decision_id"))
            this.db.exec("ALTER TABLE pix_transfers ADD COLUMN risk_decision_id TEXT REFERENCES risk_decisions(id)");
        if (!pixColumns.some((column) => column.name === "product"))
            this.db.exec("ALTER TABLE pix_transfers ADD COLUMN product TEXT NOT NULL DEFAULT 'standard'");
        if (!pixColumns.some((column) => column.name === "spi_command_version"))
            this.db.exec("ALTER TABLE pix_transfers ADD COLUMN spi_command_version INTEGER NOT NULL DEFAULT 0");
        if (!(this.db.prepare("PRAGMA table_info(pix_spi_outbox)").all() as {
            name: string;
        }[])
            .some((column) => column.name === "trace_id"))
            this.db.exec("ALTER TABLE pix_spi_outbox ADD COLUMN trace_id TEXT");
        this.db.exec(`CREATE INDEX IF NOT EXISTS pix_spi_outbox_trace
      ON pix_spi_outbox(trace_id) WHERE trace_id IS NOT NULL`);
        const outboxColumns = this.db.prepare("PRAGMA table_info(pix_spi_outbox)").all() as {
            name: string;
        }[];
        if (!outboxColumns.some((column) => column.name === "eligible_at_real"))
            this.db.exec("ALTER TABLE pix_spi_outbox ADD COLUMN eligible_at_real TEXT");
        if (!outboxColumns.some((column) => column.name === "queued_at_real"))
            this.db.exec("ALTER TABLE pix_spi_outbox ADD COLUMN queued_at_real TEXT");
        if (!outboxColumns.some((column) => column.name === "deadline_at_real"))
            this.db.exec("ALTER TABLE pix_spi_outbox ADD COLUMN deadline_at_real TEXT");
        if (!outboxColumns.some((column) => column.name === "responded_at_real"))
            this.db.exec("ALTER TABLE pix_spi_outbox ADD COLUMN responded_at_real TEXT");
        if (!outboxColumns.some((column) => column.name === "latency_policy_version"))
            this.db.exec("ALTER TABLE pix_spi_outbox ADD COLUMN latency_policy_version INTEGER");
        this.db.exec(`CREATE TRIGGER IF NOT EXISTS pix_spi_outbox_trace_immutable
      BEFORE UPDATE OF trace_id ON pix_spi_outbox
      BEGIN SELECT RAISE(ABORT,'PIX_SPI_COMMAND_IMMUTABLE'); END`);
        this.db.exec(`CREATE TRIGGER IF NOT EXISTS pix_spi_outbox_eligibility_immutable
      BEFORE UPDATE OF eligible_at_real,deadline_at_real,latency_policy_version ON pix_spi_outbox
      BEGIN SELECT RAISE(ABORT,'PIX_SPI_COMMAND_IMMUTABLE'); END`);
        this.db.exec(`CREATE TRIGGER IF NOT EXISTS pix_spi_outbox_deadline_immutable
      BEFORE UPDATE OF deadline_at_real ON pix_spi_outbox
      BEGIN SELECT RAISE(ABORT,'PIX_SPI_COMMAND_IMMUTABLE'); END`);
        this.db.exec(`CREATE TRIGGER IF NOT EXISTS pix_spi_outbox_queued_real_immutable
      BEFORE UPDATE OF queued_at_real ON pix_spi_outbox
      BEGIN SELECT RAISE(ABORT,'PIX_SPI_COMMAND_IMMUTABLE'); END`);
        this.db.exec(`CREATE TRIGGER IF NOT EXISTS pix_spi_outbox_responded_real_immutable
      BEFORE UPDATE OF responded_at_real ON pix_spi_outbox
      WHEN OLD.response_status IS NOT NULL
      BEGIN SELECT RAISE(ABORT,'PIX_SPI_RESPONSE_IMMUTABLE'); END`);
        const pspOutboxColumns = this.db.prepare("PRAGMA table_info(pix_psp_inbound_outbox)")
            .all() as {
            name: string;
        }[];
        if (!pspOutboxColumns.some((column) => column.name === "from_account"))
            this.db.exec("ALTER TABLE pix_psp_inbound_outbox ADD COLUMN from_account TEXT");
        if (!pspOutboxColumns.some((column) => column.name === "settled_at"))
            this.db.exec("ALTER TABLE pix_psp_inbound_outbox ADD COLUMN settled_at TEXT");
        this.db.exec(`UPDATE pix_psp_inbound_outbox SET
      from_account=COALESCE(from_account,
        (SELECT p.from_account FROM pix_transfers p WHERE p.id=transfer_id)),
      settled_at=COALESCE(settled_at,
        (SELECT p.settled_at FROM pix_transfers p WHERE p.id=transfer_id))
      WHERE from_account IS NULL OR settled_at IS NULL`);
        if (this.db.prepare(`SELECT 1 FROM pix_psp_inbound_outbox
      WHERE from_account IS NULL OR settled_at IS NULL LIMIT 1`).get())
            throw new BankError("INTEGRITY_PIX_PSP_COMMAND");
        this.db.exec(`CREATE TRIGGER IF NOT EXISTS pix_psp_inbound_sender_immutable
      BEFORE UPDATE OF from_account,settled_at ON pix_psp_inbound_outbox
      BEGIN SELECT RAISE(ABORT,'PIX_PSP_COMMAND_IMMUTABLE'); END`);
        const riskHoldColumns = this.db.prepare("PRAGMA table_info(risk_pix_holds)").all() as {
            name: string;
        }[];
        if (!riskHoldColumns.some((column) => column.name === "product"))
            this.db.exec("ALTER TABLE risk_pix_holds ADD COLUMN product TEXT NOT NULL DEFAULT 'standard'");
        if (!riskHoldColumns.some((column) => column.name === "channel")) {
            this.db.exec("ALTER TABLE risk_pix_holds ADD COLUMN channel TEXT NOT NULL DEFAULT 'app'");
            this.db.exec(`UPDATE risk_pix_holds SET channel='automatic'
        WHERE product='automatic'`);
        }
        const transferColumns = this.db.prepare("PRAGMA table_info(pix_transfers)")
            .all() as {
            name: string;
        }[];
        if (!transferColumns.some((column) => column.name === "channel")) {
            this.db.exec("ALTER TABLE pix_transfers ADD COLUMN channel TEXT NOT NULL DEFAULT 'app'");
            this.db.exec(`UPDATE pix_transfers SET channel='automatic'
        WHERE product='automatic';
        UPDATE pix_transfers SET channel='scheduled'
        WHERE product='standard' AND idempotency_key LIKE 'scheduled:%'`);
        }
        this.db.exec(`CREATE INDEX IF NOT EXISTS pix_channel_window
      ON pix_transfers(from_account,channel,initiated_at);
      CREATE TRIGGER IF NOT EXISTS pix_channel_valid_insert
      BEFORE INSERT ON pix_transfers WHEN NEW.channel NOT IN ('app','scheduled','automatic')
      BEGIN SELECT RAISE(ABORT,'PIX_CHANNEL_INVALID'); END;
      CREATE TRIGGER IF NOT EXISTS pix_channel_immutable
      BEFORE UPDATE OF channel ON pix_transfers
      BEGIN SELECT RAISE(ABORT,'PIX_CHANNEL_IMMUTABLE'); END;`);
        const keyColumns = this.db.prepare("PRAGMA table_info(pix_keys)").all() as {
            name: string;
        }[];
        if (!keyColumns.some((column) => column.name === "key_type"))
            this.db.exec("ALTER TABLE pix_keys ADD COLUMN key_type TEXT NOT NULL DEFAULT 'legacy'");
        if (!keyColumns.some((column) => column.name === "status"))
            this.db.exec("ALTER TABLE pix_keys ADD COLUMN status TEXT NOT NULL DEFAULT 'active'");
        if (!keyColumns.some((column) => column.name === "fraud_flag"))
            this.db.exec("ALTER TABLE pix_keys ADD COLUMN fraud_flag INTEGER NOT NULL DEFAULT 0");
        this.db.exec("CREATE INDEX IF NOT EXISTS pix_keys_account ON pix_keys(account_id,status)");
        const claimColumns = this.db.prepare("PRAGMA table_info(pix_key_claims)").all() as {
            name: string;
        }[];
        if (!claimColumns.some((column) => column.name === "proof_issues"))
            this.db.exec("ALTER TABLE pix_key_claims ADD COLUMN proof_issues INTEGER NOT NULL DEFAULT 0");
        const medColumns = this.db.prepare("PRAGMA table_info(med_cases)").all() as {
            name: string;
        }[];
        if (!medColumns.some((column) => column.name === "unrecovered_cents"))
            this.db.exec("ALTER TABLE med_cases ADD COLUMN unrecovered_cents INTEGER NOT NULL DEFAULT 0");
        if (!medColumns.some((column) => column.name === "claim_amount_cents"))
            this.db.exec("ALTER TABLE med_cases ADD COLUMN claim_amount_cents INTEGER CHECK(claim_amount_cents>0)");
        if (!medColumns.some((column) => column.name === "timing_policy_version"))
            this.db.exec("ALTER TABLE med_cases ADD COLUMN timing_policy_version INTEGER NOT NULL DEFAULT 1");
        if (!medColumns.some((column) => column.name === "recovery_initiated_at"))
            this.db.exec("ALTER TABLE med_cases ADD COLUMN recovery_initiated_at TEXT");
        const medSettlementColumns = this.db.prepare("PRAGMA table_info(med_psp_settlement_outbox)")
            .all() as {
            name: string;
        }[];
        if (!medSettlementColumns.some((column) => column.name === "requires_timeline")) {
            this.db.exec(`ALTER TABLE med_psp_settlement_outbox ADD COLUMN requires_timeline
        INTEGER NOT NULL DEFAULT 1 CHECK(requires_timeline IN (0,1))`);
            this.db.exec("UPDATE med_psp_settlement_outbox SET requires_timeline=0");
        }
        this.db.exec(`CREATE TRIGGER IF NOT EXISTS med_psp_settlement_timeline_immutable
      BEFORE UPDATE OF requires_timeline ON med_psp_settlement_outbox
      BEGIN SELECT RAISE(ABORT,'MED_PSP_SETTLEMENT_COMMAND_IMMUTABLE'); END`);
        this.db.exec(`UPDATE med_cases SET recovery_initiated_at=(
      SELECT created_at FROM med_psp_settlement_outbox o WHERE o.case_id=med_cases.id)
      WHERE recovery_initiated_at IS NULL AND EXISTS(
        SELECT 1 FROM med_psp_settlement_outbox o WHERE o.case_id=med_cases.id)`);
        if (this.separatedEcosystem)
            this.db.exec(`INSERT OR IGNORE INTO med_dict_analysis_outbox
      (case_id,transfer_id,approved_at)
      SELECT m.id,m.transfer_id,d.decided_at FROM med_cases m
      JOIN med_decisions d ON d.case_id=m.id AND d.decision='approved'
      JOIN pix_spi_outbox p ON p.transfer_id=m.transfer_id
      WHERE m.status IN ('open','settlement_pending_psp')`);
        this.transaction(() => {
            const legacy = this.db.prepare(`SELECT m.id,m.opened_at,m.resolve_after,
        EXISTS(SELECT 1 FROM med_refunds r WHERE r.case_id=m.id) reopened
        FROM med_cases m WHERE m.status='open' AND m.timing_policy_version=1`).all() as {
                id: string;
                opened_at: string;
                resolve_after: string;
                reopened: number;
            }[];
            const update = this.db.prepare(`UPDATE med_cases SET resolve_after=?,timing_policy_version=2
        WHERE id=?`);
            const now = this.now().getTime();
            for (const row of legacy) {
                const opened = Date.parse(row.opened_at);
                const due = Date.parse(row.resolve_after);
                if (!Number.isFinite(opened) || !Number.isFinite(due))
                    throw new Error("MED_TIMING_DATE_INVALID");
                const effective = row.reopened ? Math.max(due, now + 7 * 86400000) :
                    Math.max(due, opened + 7 * 86400000, now);
                update.run(new Date(effective).toISOString(), row.id);
            }
        });
        this.transaction(() => {
            const legacy = this.db.prepare(`SELECT id,initiated_at,status,settled_at FROM pix_transfers
        WHERE end_to_end_id IS NULL`).all() as {
                id: string;
                initiated_at: string;
                status: string;
                settled_at: string | null;
            }[];
            const update = this.db.prepare("UPDATE pix_transfers SET end_to_end_id=? WHERE id=?");
            const history = this.db.prepare(`INSERT INTO pix_status_history
        (transfer_id,status,changed_at) VALUES (?,?,?)`);
            const hasHistory = this.db.prepare(`SELECT 1 FROM pix_status_history WHERE transfer_id=? LIMIT 1`);
            for (const row of legacy) {
                update.run(pixEndToEndId(row.id, new Date(row.initiated_at)), row.id);
                if (!hasHistory.get(row.id)) {
                    history.run(row.id, "created", row.initiated_at);
                    if (row.status !== "created")
                        history.run(row.id, row.status, row.settled_at ?? row.initiated_at);
                }
            }
        });
        this.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS pix_end_to_end_id
      ON pix_transfers(end_to_end_id);
      CREATE TRIGGER IF NOT EXISTS pix_history_no_update BEFORE UPDATE ON pix_status_history
      BEGIN SELECT RAISE(ABORT, 'PIX_HISTORY_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS pix_history_no_delete BEFORE DELETE ON pix_status_history
      BEGIN SELECT RAISE(ABORT, 'PIX_HISTORY_IMMUTABLE'); END;`);
        if (!(this.db.prepare("PRAGMA table_info(accounts)").all() as {
            name: string;
        }[])
            .some((column) => column.name === "frozen_reason"))
            this.db.exec("ALTER TABLE accounts ADD COLUMN frozen_reason TEXT");
        const accountColumns = this.db.prepare("PRAGMA table_info(accounts)").all() as {
            name: string;
        }[];
        for (const column of ["branch_code", "account_number", "account_digit"])
            if (!accountColumns.some((existing) => existing.name === column))
                this.db.exec(`ALTER TABLE accounts ADD COLUMN ${column} TEXT`);
        this.transaction(() => {
            const max = this.db.prepare("SELECT MAX(account_number) number FROM accounts")
                .get() as {
                number: string | null;
            };
            let next = max.number ? Number(max.number) + 1 : 1;
            const missing = this.db.prepare(`SELECT id FROM accounts WHERE customer_id IS NOT NULL
        AND account_number IS NULL ORDER BY opened_at,id`).all() as {
                id: string;
            }[];
            const update = this.db.prepare(`UPDATE accounts SET branch_code=?,account_number=?,account_digit=? WHERE id=?`);
            for (const row of missing) {
                const identifier = accountIdentifier(next++);
                update.run(identifier.branch_code, identifier.account_number, identifier.account_digit, row.id);
            }
        });
        this.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS account_branch_number
      ON accounts(branch_code,account_number) WHERE account_number IS NOT NULL;
      CREATE TRIGGER IF NOT EXISTS account_identifier_required BEFORE INSERT ON accounts
      WHEN NEW.customer_id IS NOT NULL AND (NEW.branch_code IS NULL OR NEW.account_number IS NULL
        OR NEW.account_digit IS NULL OR NEW.branch_code NOT GLOB '[0-9][0-9][0-9][0-9]'
        OR NEW.account_number NOT GLOB '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]'
        OR NEW.account_digit NOT GLOB '[0-9]')
      BEGIN SELECT RAISE(ABORT, 'ACCOUNT_IDENTIFIER_REQUIRED'); END;
      CREATE TRIGGER IF NOT EXISTS account_identifier_immutable
      BEFORE UPDATE OF branch_code,account_number,account_digit ON accounts
      WHEN OLD.account_number IS NOT NULL
      BEGIN SELECT RAISE(ABORT, 'ACCOUNT_IDENTIFIER_IMMUTABLE'); END;`);
        this.transaction(() => {
            const legacySeedBusinesses = this.db.prepare(`SELECT a.id,a.customer_id,
        a.account_number,a.opened_at FROM accounts a
        LEFT JOIN business_account_identity b ON b.account_id=a.id
        WHERE a.kind='merchant' AND a.customer_id IS NOT NULL
          AND a.account_number IS NOT NULL AND b.account_id IS NULL`).all() as {
                id: string;
                customer_id: string;
                account_number: string;
                opened_at: string;
            }[];
            const insert = this.db.prepare(`INSERT INTO business_account_identity
        (account_id,cnpj,legal_name,representative_customer_id,verified_at,verified_by)
        VALUES (?,?,?,?,?,'synthetic_seed_migration')`);
            for (const row of legacySeedBusinesses) {
                const index = Number(row.account_number);
                if (!Number.isSafeInteger(index) || row.id !== seedAccountId(index))
                    continue;
                insert.run(row.id, syntheticCnpj(index), `Synthetic Business ${index} Ltda`, row.customer_id, row.opened_at);
            }
        });
        installLedgerIntegrity(this.db);
        installAccountingDates(this.db);
        installChartOfAccounts(this.db);
        installPeriodCloseSeals(this.db);
        installPeriodResultTransfers(this.db);
        if (this.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='loan_installments'`).get())
            installLoanInterestAccruals(this.db);
        if (this.db.prepare("SELECT 1 FROM customers LIMIT 1").get()) {
            const insert = this.db.prepare(`INSERT OR IGNORE INTO accounts
        (id,customer_id,kind,system_role,balance_cached,overdraft_limit,status,opened_at,
         branch_code,account_number,account_digit) VALUES (?,NULL,'system',?,0,0,'active',?,NULL,NULL,NULL)`);
            for (const role of ["loan_loss_allowance", "loan_provision_expense",
                "loan_interest_receivable", "loan_interest_revenue", "equity_capital",
                "retained_earnings"] as const)
                insert.run(seedSystemAccountId(role), role, this.now().toISOString());
        }
        if (!reconcilePeriodResultTransfers(this.db))
            throw new BankError("INTEGRITY_PERIOD_RESULT");
        installDictRateBuckets(this.db, this.separatedEcosystem ? "bank" : "embedded");
        this.telemetry = new TelemetryStore(this.db, this.now, this.realNow);
        if (this.separatedEcosystem)
            this.migrateMedHopSchema();
        if (!this.separatedEcosystem) {
            this.embeddedSpi = new SpiNetwork(this.db, this.now, this.telemetry, this.realNow);
            this.embeddedPsp = new PspNetwork(this.db, this.spi, this.now);
            this.migrateMedHopSchema();
            const pspHistory = this.reconcilePsp();
            if (pspHistory.med_hold_drift)
                throw new BankError("PSP_MED_HISTORY_INVALID");
            if (pspHistory.root_fact_drift)
                throw new BankError("PSP_ROOT_HISTORY_INVALID");
            if (pspHistory.inbound_receipt_drift || pspHistory.inbound_sender_drift)
                throw new BankError("PSP_INBOUND_HISTORY_INVALID");
            if (pspHistory.inbound_spi_drift)
                throw new BankError("PSP_INBOUND_SPI_HISTORY_INVALID");
        }
        this.risk = new RiskEngine(this.db, this.now, this.telemetry, (accountId, at) => {
            if (this.separatedEcosystem)
                throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
            const local = Boolean(this.db.prepare(`SELECT 1 FROM accounts
        WHERE id=? AND customer_id IS NOT NULL`).get(accountId));
            const external = this.spi.account(accountId);
            const flaggedLocal = Boolean(this.db.prepare(`SELECT 1 FROM pix_keys
        WHERE account_id=? AND status='active' AND fraud_flag=1 LIMIT 1`).get(accountId));
            const exists = local || Boolean(external);
            return { exists, flagged: flaggedLocal || Boolean(external?.fraud_flag),
                fraudHistory: dictFraudCounter(this.db, at, "account_id", exists ? accountId : undefined) };
        });
    }
    private migrateMedHopSchema(): void {
        const references = this.db.prepare("PRAGMA foreign_key_list(med_hops)")
            .all() as {
            table: string;
        }[];
        const schema = (this.db.prepare(`SELECT sql FROM sqlite_master
      WHERE type='table' AND name='med_hops'`).get() as {
            sql: string;
        }).sql;
        if (!references.some((reference) => reference.table === "psp_accounts") &&
            !schema.replace(/\s+/g, "").includes("UNIQUE(case_id,account_id)"))
            return;
        this.db.exec("BEGIN IMMEDIATE");
        try {
            this.db.exec(`CREATE TABLE med_hops_v2 (
        id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES med_cases(id),
        root_transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
        account_id TEXT NOT NULL,
        blocked_cents INTEGER NOT NULL CHECK(blocked_cents>0),
        refunded_cents INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL, released_at TEXT
      );
      INSERT INTO med_hops_v2
        (id,case_id,root_transfer_id,account_id,blocked_cents,refunded_cents,created_at,released_at)
        SELECT id,case_id,root_transfer_id,account_id,blocked_cents,refunded_cents,created_at,released_at
        FROM med_hops;
      DROP TABLE med_hops;
      ALTER TABLE med_hops_v2 RENAME TO med_hops;
      CREATE INDEX med_hops_active ON med_hops(account_id,root_transfer_id,released_at);`);
            this.db.exec("COMMIT");
        }
        catch (error) {
            this.db.exec("ROLLBACK");
            throw error;
        }
    }
    heartbeatPix(): void {
        this.db.prepare("SELECT 1 FROM pix_transfers LIMIT 1").get();
        this.telemetry.emit({ source: "pix", category: "health", action: "heartbeat",
            outcome: "success", message: "Pix telemetry heartbeat" });
    }
    heartbeatDict(): void {
        this.db.prepare("SELECT 1 FROM pix_keys LIMIT 1").get();
        this.telemetry.emit({ source: "dict", category: "health", action: "heartbeat",
            outcome: "success", message: "DICT telemetry heartbeat" });
    }
    heartbeatLedger(): void {
        this.db.prepare("SELECT 1 FROM ledger_entries LIMIT 1").get();
        this.telemetry.emit({ source: "ledger", category: "health", action: "heartbeat",
            outcome: "success", message: "Ledger telemetry heartbeat" });
    }
    transaction<T>(work: () => T): T {
        if (this.db.isTransaction)
            return work();
        this.db.exec("BEGIN IMMEDIATE");
        try {
            const result = work();
            this.db.exec("COMMIT");
            return result;
        }
        catch (error) {
            this.db.exec("ROLLBACK");
            throw error;
        }
    }
    isWeaknessOpen(id: string): boolean {
        const row = this.db.prepare("SELECT open FROM weakness_state WHERE id=?").get(id) as {
            open: number;
        } | undefined;
        return row?.open === 1;
    }
    setWeaknessOpen(id: string, open: boolean, by: string): void {
        if (open)
            throw new BankError("SIMULATION_UNSAFE_MODE_DISABLED");
        if (!WEAKNESSES.some((item) => item.id === id))
            throw new BankError("BIZ_UNKNOWN_WEAKNESS");
        const result = this.db.prepare("UPDATE weakness_state SET open=?,changed_at=?,changed_by=? WHERE id=?")
            .run(Number(open), this.now().toISOString(), by, id);
        if (result.changes !== 1)
            throw new BankError("BIZ_UNKNOWN_WEAKNESS");
    }
    addCustomer(customer: Customer): void {
        if (!validCpf(customer.cpf))
            throw new BankError("BIZ_INVALID_CPF");
        this.db.prepare("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)").run(customer.id, customer.cpf, customer.name, customer.persona, customer.kyc_tier, customer.kyc_status, customer.risk_score, Number(customer.is_attacker_owned), customer.status, this.now().toISOString());
    }
    addAccount(account: Omit<Account, "balance_cached" | "branch_code" | "account_number" | "account_digit">): void {
        if ((account.kind === "payment" || account.kind === "salary") &&
            (account.customer_id === null || account.overdraft_limit !== 0 ||
                account.system_role !== null))
            throw new BankError("BIZ_ACCOUNT_KIND_INVALID");
        if (account.status === "under_review" && (account.customer_id === null ||
            account.kind !== "checking" || account.overdraft_limit !== 0))
            throw new BankError("BIZ_ACCOUNT_STATUS_INVALID");
        if (account.status === "frozen" ?
            !account.frozen_reason || !["fraud_suspect", "med", "judicial", "kyc"].includes(account.frozen_reason) :
            account.frozen_reason != null)
            throw new BankError("BIZ_ACCOUNT_STATUS_INVALID");
        this.transaction(() => {
            const identifier = account.customer_id ? accountIdentifier(Number((this.db.prepare("SELECT MAX(account_number) number FROM accounts").get() as {
                number: string | null;
            }).number ?? 0) + 1) : null;
            this.db.prepare(`INSERT INTO accounts
        (id,customer_id,kind,system_role,balance_cached,overdraft_limit,status,opened_at,
         frozen_reason,branch_code,account_number,account_digit)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(account.id, account.customer_id, account.kind, account.system_role, 0, account.overdraft_limit, account.status, this.now().toISOString(), account.frozen_reason ?? null, identifier?.branch_code ?? null, identifier?.account_number ?? null, identifier?.account_digit ?? null);
        });
    }
    account(id: string): Account {
        const row = this.db.prepare(`SELECT id,customer_id,kind,system_role,balance_cached,
      overdraft_limit,status,frozen_reason,branch_code,account_number,account_digit FROM accounts WHERE id=?`)
            .get(id) as Account | undefined;
        if (!row)
            throw new BankError("BIZ_ACCOUNT_NOT_FOUND");
        return row;
    }
    changeAccountStatus(accountId: string, status: Account["status"], actor: string, reason: AccountFrozenReason | null = null): Account {
        if (!/^[a-zA-Z0-9_-]{1,80}$/.test(actor) ||
            !["active", "frozen", "closed"].includes(status) ||
            (status === "frozen" ? !reason || !["fraud_suspect", "med", "judicial", "kyc"].includes(reason) : reason !== null))
            throw new BankError("BIZ_ACCOUNT_STATUS_INVALID");
        return this.transaction(() => {
            const current = this.account(accountId);
            if (current.kind === "system" || current.status === "closed" && status !== "closed")
                throw new BankError("BIZ_ACCOUNT_STATUS_INVALID");
            if (current.status === "under_review") {
                const review = this.db.prepare(`SELECT status FROM onboarding_applications
          WHERE account_id=?`).get(accountId) as {
                    status: string;
                } | undefined;
                if (status === "active" ? review?.status !== "approved" :
                    status === "frozen" && reason === "kyc" ? review?.status !== "rejected" : true)
                    throw new BankError("DEF_ONBOARDING_REVIEW_REQUIRED");
            }
            if (current.status === "frozen" && current.frozen_reason === "kyc" &&
                status === "active" && this.db.prepare(`SELECT 1 FROM onboarding_applications
          WHERE account_id=? AND status<>'approved'`).get(accountId))
                throw new BankError("DEF_ONBOARDING_REVIEW_REQUIRED");
            if (status === "closed" && current.balance_cached !== 0)
                throw new BankError("BIZ_ACCOUNT_CLOSE_BALANCE");
            if (current.status === status && (current.frozen_reason ?? null) === reason)
                return current;
            this.db.prepare("UPDATE accounts SET status=?,frozen_reason=? WHERE id=?")
                .run(status, reason, accountId);
            this.db.prepare(`INSERT INTO account_status_changes
        (id,account_id,from_status,to_status,reason,actor,changed_at)
        VALUES (?,?,?,?,?,?,?)`).run(newId("astatus", this.now().getTime()), accountId, current.status, status, reason, actor, this.now().toISOString());
            this.telemetry.emit({ source: "ledger", category: "account", action: "status_change",
                outcome: "success", accountId, message: `Account status changed to ${status}` });
            return this.account(accountId);
        });
    }
    availableBalance(accountId: string): number {
        const account = this.account(accountId);
        if (account.status === "under_review")
            return 0;
        const held = this.db.prepare(`SELECT COALESCE(SUM(h.amount),0) amount FROM balance_holds h
      WHERE h.account_id=? AND h.released_at IS NULL AND
        (h.expires_at>? OR (h.kind='pix_cautelar' AND EXISTS (
          SELECT 1 FROM pix_transfers p WHERE p.id=h.ref AND p.status='in_processing')))`)
            .get(accountId, this.now().toISOString()) as {
            amount: number;
        };
        return account.balance_cached + account.overdraft_limit - held.amount;
    }
    createHold(input: {
        accountId: string;
        amount: number;
        kind: HoldKind;
        ref: string;
        actor: string;
        expiresAt: Date;
    }): string {
        if (!Number.isSafeInteger(input.amount) || input.amount <= 0 ||
            !Number.isFinite(input.expiresAt.getTime()) || input.expiresAt.getTime() <= this.now().getTime() ||
            !input.ref || input.ref.length > 128 || !input.actor || input.actor.length > 128)
            throw new BankError("BIZ_INVALID_HOLD");
        return this.transaction(() => {
            const account = this.account(input.accountId);
            if (account.kind === "system" || account.status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            if (this.availableBalance(input.accountId) < input.amount)
                throw new BankError("BIZ_INSUFFICIENT_FUNDS");
            const id = newId("hold", this.now().getTime());
            this.db.prepare(`INSERT INTO balance_holds
        (id,account_id,amount,kind,ref,actor,created_at,expires_at)
        VALUES (?,?,?,?,?,?,?,?)`).run(id, input.accountId, input.amount, input.kind, input.ref, input.actor, this.now().toISOString(), input.expiresAt.toISOString());
            return id;
        });
    }
    releaseHold(id: string, actor: string): boolean {
        if (!actor || actor.length > 128)
            throw new BankError("BIZ_INVALID_HOLD");
        if (this.db.prepare(`SELECT 1 FROM balance_holds h JOIN pix_transfers p ON p.id=h.ref
      WHERE h.id=? AND h.kind='pix_cautelar' AND p.status='in_processing'
        AND h.released_at IS NULL`).get(id))
            throw new BankError("DEF_PIX_PROCESSING_HOLD");
        if (this.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='judicial_orders'").get() &&
            this.db.prepare(`SELECT 1 FROM judicial_orders WHERE hold_id=?
        AND status IN ('active','release_pending') LIMIT 1`).get(id))
            throw new BankError("DEF_JUDICIAL_ORDER_PROTECTED");
        const changed = this.db.prepare(`UPDATE balance_holds SET released_at=?,release_actor=?
      WHERE id=? AND released_at IS NULL`).run(this.now().toISOString(), actor, id);
        return changed.changes === 1;
    }
    riskPixHold(id: string): RiskPixHold | undefined {
        return this.db.prepare("SELECT * FROM risk_pix_holds WHERE id=?")
            .get(id) as RiskPixHold | undefined;
    }
    acknowledgeRiskPixHold(id: string, reviewer: string): RiskPixReviewAcknowledgement {
        if (!/^[a-zA-Z0-9_-]{1,80}$/.test(reviewer))
            throw new BankError("BIZ_RISK_REVIEW_ACK_INVALID");
        this.expireRiskPixHolds();
        return this.transaction(() => {
            const hold = this.riskPixHold(id);
            if (!hold)
                throw new BankError("DEF_NOT_FOUND");
            if (hold.status !== "pending" || hold.expires_at <= this.now().toISOString() ||
                hold.actor === reviewer)
                throw new BankError("BIZ_RISK_REVIEW_ACK_INVALID");
            const existing = this.db.prepare(`SELECT hold_id,reviewer,acknowledged_at
        FROM risk_pix_review_acknowledgements WHERE hold_id=?`).get(id) as RiskPixReviewAcknowledgement | undefined;
            if (existing)
                return { ...existing };
            const acknowledgedAt = this.now().toISOString();
            this.db.prepare(`INSERT INTO risk_pix_review_acknowledgements
        (hold_id,reviewer,acknowledged_at) VALUES (?,?,?)`).run(id, reviewer, acknowledgedAt);
            this.telemetry.emit({ source: "siem", category: "pix", action: "review_acknowledged",
                outcome: "success", message: "Pix risk review acknowledged" });
            return { hold_id: id, reviewer, acknowledged_at: acknowledgedAt };
        });
    }
    private placeRiskPixHold(input: PixTransferInput, decision: RiskDecision, externalRecipient?: ExternalPixRecipient): RiskPixHold {
        return this.transaction(() => {
            const existing = this.db.prepare(`SELECT id FROM risk_pix_holds
        WHERE from_account=? AND idempotency_key=?`).get(input.from, input.idempotencyKey) as {
                id: string;
            } | undefined;
            if (existing)
                return this.riskPixHold(existing.id)!;
            const recipient = externalRecipient ??
                (this.separatedEcosystem ? undefined : this.spi.account(input.to));
            const localRecipient = recipient ? undefined : this.account(input.to);
            if (input.from === input.to || localRecipient?.kind === "system" ||
                (localRecipient?.status ?? recipient?.status) !== "active")
                throw new BankError("BIZ_INVALID_PIX_ACCOUNT");
            this.db.exec("SAVEPOINT risk_pix_preflight");
            try {
                const trial = this.transferPixCore(input, false, false, undefined, undefined, this.separatedEcosystem && Boolean(externalRecipient), externalRecipient);
                if (trial.status !== (this.separatedEcosystem && externalRecipient ?
                    "in_processing" : "settled"))
                    throw new BankError("BIZ_RISK_SETTLEMENT_REJECTED");
            }
            finally {
                this.db.exec("ROLLBACK TO risk_pix_preflight");
                this.db.exec("RELEASE risk_pix_preflight");
            }
            const id = newId("riskhold", this.now().getTime());
            const expiresAt = new Date(this.now().getTime() + 24 * 3600000);
            const balanceHoldId = this.createHold({ accountId: input.from, amount: input.amount,
                kind: "pix_cautelar", ref: id, actor: "risk", expiresAt });
            this.db.prepare(`INSERT INTO risk_pix_holds
        (id,from_account,to_account,amount_cents,idempotency_key,actor,device_id,
        step_up_verified,balance_hold_id,risk_decision_id,product,channel,status,created_at,expires_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)`).run(id, input.from, input.to, input.amount, input.idempotencyKey, input.actor, input.deviceId ?? null, Number(input.stepUpVerified ?? false), balanceHoldId, decision.id, input.product ?? "standard", input.product === "automatic" ? "automatic" : input.channel ?? "app", this.now().toISOString(), expiresAt.toISOString());
            this.telemetry.emit({ source: "risk", category: "pix", action: "payment_held",
                outcome: "failure", severity: "warn", accountId: input.from,
                amountCents: input.amount, counterparty: input.to,
                riskScore: decision.score, reasonCodes: decision.reason_codes,
                message: "Pix retained for operator review" });
            return this.riskPixHold(id)!;
        });
    }
    resolveRiskPixHold(id: string, decision: "approve" | "reject", reviewer: string, externalSnapshot?: {
        account: ExternalPixRecipient | null;
        evidence: PixRecipientEvidence | null;
    }): {
        hold: RiskPixHold;
        transfer?: PixResult;
    } {
        if (!/^[a-zA-Z0-9_-]{1,80}$/.test(reviewer) ||
            (decision !== "approve" && decision !== "reject"))
            throw new BankError("BIZ_RISK_REVIEW_INVALID");
        this.expireRiskPixHolds();
        return this.transaction(() => {
            const hold = this.riskPixHold(id);
            if (!hold)
                throw new BankError("DEF_NOT_FOUND");
            if (reviewer === hold.actor || hold.status !== "pending" ||
                hold.expires_at <= this.now().toISOString())
                throw new BankError("BIZ_RISK_REVIEW_INVALID");
            const localRecipient = this.db.prepare(`SELECT 1 FROM accounts
        WHERE id=? AND customer_id IS NOT NULL`).get(hold.to_account);
            const externalRecipient = this.separatedEcosystem && decision === "approve" &&
                !localRecipient ? externalSnapshot?.account : undefined;
            if (this.separatedEcosystem && decision === "approve" && !localRecipient &&
                (!externalRecipient || !externalSnapshot?.evidence ||
                    !this.validExternalPixEvidence({ to: hold.to_account }, externalRecipient, externalSnapshot.evidence)))
                throw new BankError("INTEGRITY_PIX_RECIPIENT_EVIDENCE");
            if (externalSnapshot && (!this.separatedEcosystem || localRecipient))
                throw new BankError("INTEGRITY_PIX_RECIPIENT_EVIDENCE");
            if (!this.releaseHold(hold.balance_hold_id, reviewer))
                throw new BankError("INTEGRITY_RISK_HOLD_MISSING");
            const transfer = decision === "approve" ? this.transferPixCore({
                from: hold.from_account, to: hold.to_account, amount: hold.amount_cents,
                idempotencyKey: hold.idempotency_key, actor: hold.actor,
                ...(hold.device_id ? { deviceId: hold.device_id } : {}),
                stepUpVerified: Boolean(hold.step_up_verified),
                ...(hold.product === "automatic" ? { product: "automatic" as const } : {}),
                ...(hold.channel === "scheduled" ? { channel: "scheduled" as const } : {}),
            }, false, false, undefined, hold.risk_decision_id, Boolean(externalRecipient), externalRecipient ?? undefined) : undefined;
            if (transfer?.status === "rejected")
                throw new BankError("BIZ_RISK_SETTLEMENT_REJECTED");
            if (transfer && hold.proximity_token_id) {
                const token = this.db.prepare(`SELECT id,to_account,amount_cents,used_at
          FROM proximity_tokens WHERE id=?`).get(hold.proximity_token_id) as {
                    id: string;
                    to_account: string;
                    amount_cents: number;
                    used_at: string | null;
                } | undefined;
                if (!token || token.used_at || token.to_account !== hold.to_account ||
                    token.amount_cents !== hold.amount_cents)
                    throw new BankError("INTEGRITY_RISK_PROXIMITY_TOKEN");
                this.db.prepare("UPDATE proximity_tokens SET used_at=? WHERE id=?")
                    .run(this.now().toISOString(), token.id);
                this.db.prepare(`INSERT INTO proximity_uses
          (id,token_id,transfer_id,requested_to,requested_amount_cents,used_at)
          VALUES (?,?,?,?,?,?)`).run(newId("use", this.now().getTime()), token.id, transfer.id, hold.to_account, hold.amount_cents, this.now().toISOString());
            }
            this.db.prepare(`UPDATE risk_pix_holds SET status=?,resolved_at=?,reviewer=?,transfer_id=?
        WHERE id=?`).run(decision === "approve" ? "approved" : "rejected", this.now().toISOString(), reviewer, transfer?.id ?? null, id);
            this.telemetry.emit({ source: "risk", category: "pix", action: "payment_reviewed",
                outcome: decision === "approve" ? "success" : "failure", accountId: hold.from_account,
                amountCents: hold.amount_cents, counterparty: hold.to_account,
                message: `Held Pix ${decision === "approve" ? "approved" : "rejected"}` });
            return { hold: this.riskPixHold(id)!, ...(transfer ? { transfer } : {}) };
        });
    }
    expireRiskPixHolds(): number {
        return this.transaction(() => {
            const expired = this.db.prepare(`SELECT id,balance_hold_id FROM risk_pix_holds
        WHERE status='pending' AND expires_at<=?`).all(this.now().toISOString()) as {
                id: string;
                balance_hold_id: string;
            }[];
            for (const hold of expired) {
                this.releaseHold(hold.balance_hold_id, "risk_expiry");
                this.db.prepare(`UPDATE risk_pix_holds SET status='expired',resolved_at=? WHERE id=?`)
                    .run(this.now().toISOString(), hold.id);
            }
            return expired.length;
        });
    }
    customer(id: string): Customer {
        const row = this.db.prepare("SELECT id,cpf,name,persona,kyc_tier,kyc_status,risk_score,is_attacker_owned,status FROM customers WHERE id=?")
            .get(id) as Customer | undefined;
        if (!row)
            throw new BankError("BIZ_CUSTOMER_NOT_FOUND");
        return { ...row, is_attacker_owned: Boolean(row.is_attacker_owned) };
    }
    ownAccount(customerId: string, accountId: string): Account {
        const account = this.db.prepare(`SELECT id,customer_id,kind,system_role,balance_cached,overdraft_limit,status,
      branch_code,account_number,account_digit
      FROM accounts WHERE id=? AND customer_id=?`).get(accountId, customerId) as Account | undefined;
        if (!account)
            throw new BankError("DEF_NOT_FOUND");
        return account;
    }
    systemAccountId(role: SystemRole): string {
        const cached = this.systemIds.get(role);
        if (cached)
            return cached;
        const row = this.db.prepare("SELECT id FROM accounts WHERE kind='system' AND system_role=? LIMIT 1")
            .get(role) as {
            id: string;
        } | undefined;
        if (!row)
            throw new BankError("INTEGRITY_SYSTEM_ACCOUNT_MISSING");
        this.systemIds.set(role, row.id);
        return row.id;
    }
    post(postings: Posting[], reversesTxId?: string, valueDate?: string): string {
        if (postings.length < 2 || postings.some((item) => !Number.isSafeInteger(item.amount)) ||
            postings.reduce((sum, item) => sum + item.amount, 0) !== 0)
            throw new BankError("INTEGRITY_UNBALANCED_POSTING");
        const txId = newId("tx", this.now().getTime());
        const timestamp = this.now().toISOString();
        const execute = () => this.transaction(() => {
            const activeFreezes = this.db.prepare(`SELECT target,direction FROM blue_containments
        WHERE kind='freeze_account' AND lifted_at IS NULL AND expires_at>?
          AND target IN (SELECT value FROM json_each(?))`).all(this.realNow().toISOString(), JSON.stringify([...new Set(postings.map((posting) => posting.accountId))])) as {
                target: string;
                direction: string;
            }[];
            const freezes = new Map<string, Set<string>>();
            for (const row of activeFreezes) {
                const directions = freezes.get(row.target) ?? new Set<string>();
                directions.add(row.direction);
                freezes.set(row.target, directions);
            }
            for (const posting of postings) {
                const account = this.account(posting.accountId);
                if (account.kind === "salary") {
                    const employer = this.db.prepare(`SELECT employer_account_id,employee_customer_id
            FROM salary_account_employers WHERE account_id=?`).get(account.id) as {
                        employer_account_id: string;
                        employee_customer_id: string;
                    } | undefined;
                    const counterpart = postings.find((line) => line.accountId !== account.id);
                    if (!employer || account.status !== "active" || postings.length !== 2 ||
                        !counterpart || counterpart.amount !== -posting.amount ||
                        (posting.amount > 0 ? posting.kind !== "salary_payment" ||
                            counterpart.accountId !== employer.employer_account_id ||
                            posting.refType !== "salary_payment" ||
                            counterpart.refType !== "salary_payment" :
                            posting.kind !== "salary_portability" ||
                                posting.refType !== "salary_portability" ||
                                counterpart.refType !== "salary_portability" ||
                                !this.db.prepare(`SELECT 1 FROM accounts WHERE id=?
                AND customer_id=? AND kind IN ('checking','payment') AND status='active'`)
                                    .get(counterpart.accountId, employer.employee_customer_id)))
                        throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
                }
                const directions = freezes.get(posting.accountId);
                if (directions?.has("both") || directions?.has(posting.amount < 0 ? "outbound" : "inbound"))
                    throw new BankError("DEF_ACCOUNT_FROZEN");
                this.db.prepare("INSERT INTO ledger_entries VALUES (?,?,?,?,?,?,?,?,?,?)").run(newId("le", this.now().getTime()), txId, posting.accountId, posting.amount, posting.kind, posting.actor, posting.refType, posting.refId, timestamp, reversesTxId ?? null);
                this.db.prepare("UPDATE accounts SET balance_cached=balance_cached+? WHERE id=?").run(posting.amount, posting.accountId);
            }
            this.telemetry.emit({ source: "ledger", category: "transaction", action: "post",
                outcome: "success", amountCents: postings.reduce((sum, posting) => sum + Math.max(0, posting.amount), 0), counterparty: txId,
                message: "Balanced ledger transaction posted" });
            return txId;
        });
        return valueDate === undefined ? execute() :
            withAccountingValueDate(this.db, valueDate, execute);
    }
    manualPostingRequest(id: string): ManualPostingRequest {
        const request = this.db.prepare("SELECT * FROM manual_posting_requests WHERE id=?")
            .get(id) as ManualPostingRequest | undefined;
        if (!request)
            throw new BankError("DEF_NOT_FOUND");
        return request;
    }
    requestManualPosting(makerId: string, reason: string, lines: ManualPostingLine[]): ManualPostingRequest {
        if (!/^[a-zA-Z0-9_-]{1,80}$/.test(makerId) || typeof reason !== "string" ||
            reason.trim().length < 10 || reason.length > 500 || !Array.isArray(lines) ||
            lines.length < 2 || lines.length > 20 ||
            lines.some((line) => typeof line?.accountId !== "string" || !line.accountId ||
                line.accountId.length > 128 || !Number.isSafeInteger(line.amount) || line.amount === 0) ||
            new Set(lines.map((line) => line.accountId)).size !== lines.length ||
            !Number.isSafeInteger(lines.reduce((sum, line) => sum + line.amount, 0)) ||
            lines.reduce((sum, line) => sum + line.amount, 0) !== 0 ||
            lines.reduce((sum, line) => sum + Math.max(0, line.amount), 0) > 5000000)
            throw new BankError("BIZ_MANUAL_POSTING_INVALID");
        return this.transaction(() => {
            for (const line of lines)
                this.account(line.accountId);
            const id = newId("manual", this.now().getTime());
            this.db.prepare(`INSERT INTO manual_posting_requests
        (id,maker_id,reason,lines_json,status,created_at) VALUES (?,?,?,?,'pending',?)`)
                .run(id, makerId, reason.trim(), JSON.stringify(lines), this.now().toISOString());
            this.telemetry.emit({ source: "ledger", category: "manual_posting", action: "requested",
                outcome: "success", message: "Manual posting awaits independent approval" });
            return this.manualPostingRequest(id);
        });
    }
    resolveManualPosting(id: string, checkerId: string, decision: "approve" | "reject"): ManualPostingRequest {
        if (!/^[a-zA-Z0-9_-]{1,80}$/.test(checkerId) ||
            (decision !== "approve" && decision !== "reject"))
            throw new BankError("BIZ_MANUAL_POSTING_INVALID");
        return this.transaction(() => {
            const request = this.manualPostingRequest(id);
            if (request.status !== "pending" || checkerId === request.maker_id)
                throw new BankError("DEF_MANUAL_POSTING_APPROVAL");
            let txId: string | null = null;
            if (decision === "approve") {
                const lines = JSON.parse(request.lines_json) as ManualPostingLine[];
                const netByAccount = new Map<string, number>();
                for (const line of lines)
                    netByAccount.set(line.accountId, (netByAccount.get(line.accountId) ?? 0) + line.amount);
                for (const [accountId, netAmount] of netByAccount) {
                    const account = this.account(accountId);
                    if (account.kind === "system" &&
                        (account.system_role === "pix_settlement" || account.system_role === "card_settlement"))
                        throw new BankError("DEF_MANUAL_POSTING_EXTERNAL_BOOK");
                    if (account.status !== "active" || account.customer_id &&
                        this.customer(account.customer_id).status !== "active")
                        throw new BankError("DEF_ACCOUNT_FROZEN");
                    if (account.kind !== "system" && netAmount < 0 &&
                        this.availableBalance(accountId) < -netAmount)
                        throw new BankError("BIZ_INSUFFICIENT_FUNDS");
                }
                txId = this.post(lines.map((line) => ({ ...line, kind: "manual_adjustment",
                    actor: request.maker_id, refType: "manual_posting", refId: id })));
            }
            this.db.prepare(`UPDATE manual_posting_requests SET status=?,checker_id=?,
        resolved_at=?,ledger_tx_id=? WHERE id=? AND status='pending'`)
                .run(decision === "approve" ? "approved" : "rejected", checkerId, this.now().toISOString(), txId, id);
            this.telemetry.emit({ source: "ledger", category: "manual_posting", action: decision,
                outcome: "success", message: `Manual posting ${decision === "approve" ? "approved" : "rejected"} by independent checker` });
            return this.manualPostingRequest(id);
        });
    }
    fund(accountId: string, amount: number, sourceAccountId = this.systemAccountId("cash_in")): string {
        if (!Number.isSafeInteger(amount) || amount <= 0)
            throw new BankError("BIZ_INVALID_AMOUNT");
        const target = this.account(accountId);
        if (target.kind === "salary")
            throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
        if (target.status === "closed")
            throw new BankError("BIZ_ACCOUNT_CLOSED");
        if (target.customer_id && this.customer(target.customer_id).status !== "active")
            throw new BankError("DEF_ACCOUNT_FROZEN");
        return this.post([
            { accountId: sourceAccountId, amount: -amount, kind: "funding", actor: "seed", refType: "funding", refId: accountId },
            { accountId, amount, kind: "funding", actor: "seed", refType: "funding", refId: accountId },
        ]);
    }
    fundPiLiquidity(amount: number): string {
        if (!Number.isSafeInteger(amount) || amount <= 0)
            throw new BankError("BIZ_INVALID_AMOUNT");
        return this.transaction(() => {
            const txId = this.post([
                { accountId: this.systemAccountId("cash_in"), amount, kind: "pi_funding",
                    actor: "bank", refType: "spi", refId: "liquidity" },
                { accountId: this.systemAccountId("pix_settlement"), amount: -amount,
                    kind: "pi_funding", actor: "bank", refType: "spi", refId: "liquidity" },
            ]);
            this.spi.fund(JACARANDA_ISPB, amount);
            return txId;
        });
    }
    submitKyc(customerId: string, tier: 2 | 3): void {
        if (tier !== 2 && tier !== 3)
            throw new BankError("BIZ_KYC_TIER_INVALID");
        this.transaction(() => {
            const customer = this.customer(customerId);
            if (this.db.prepare(`SELECT 1 FROM onboarding_applications
        WHERE customer_id=? AND status<>'approved'`).get(customerId))
                throw new BankError("DEF_ONBOARDING_REVIEW_REQUIRED");
            if (customer.kyc_tier >= tier)
                throw new BankError("BIZ_KYC_TIER_ALREADY_SET");
            const pending = this.db.prepare(`SELECT requested_tier FROM kyc_requests
        WHERE customer_id=? AND status='submitted'`).get(customerId) as {
                requested_tier: number;
            } | undefined;
            if (pending) {
                if (pending.requested_tier !== tier)
                    throw new BankError("BIZ_KYC_REQUEST_PENDING");
                return;
            }
            const twinAt = this.now().toISOString();
            this.db.prepare(`INSERT INTO kyc_requests VALUES (?,?,?, ?,NULL) ON CONFLICT(customer_id) DO UPDATE SET
        requested_tier=excluded.requested_tier,status='submitted',submitted_at=excluded.submitted_at,approved_at=NULL`)
                .run(customerId, tier, "submitted", twinAt);
            this.db.prepare("UPDATE customers SET kyc_status='submitted' WHERE id=?").run(customerId);
            this.db.prepare(`INSERT INTO kyc_history
        (customer_id,event,previous_tier,requested_tier,twin_at,recorded_at,reviewer)
        VALUES (?,'submitted',?,?,?,?,NULL)`)
                .run(customerId, customer.kyc_tier, tier, twinAt, this.realNow().toISOString());
        });
    }
    approveKyc(customerId: string, reviewer?: string): void {
        if (reviewer !== undefined && !/^[a-zA-Z0-9_-]{1,80}$/.test(reviewer))
            throw new BankError("BIZ_KYC_REVIEWER_INVALID");
        this.transaction(() => {
            const customer = this.customer(customerId);
            if (this.db.prepare(`SELECT 1 FROM onboarding_applications
        WHERE customer_id=? AND status<>'approved'`).get(customerId))
                throw new BankError("DEF_ONBOARDING_REVIEW_REQUIRED");
            const request = this.db.prepare(`SELECT requested_tier FROM kyc_requests
        WHERE customer_id=? AND status='submitted'`).get(customerId) as {
                requested_tier: number;
            } | undefined;
            if (!request)
                throw new BankError("BIZ_KYC_REQUEST_NOT_FOUND");
            if ((request.requested_tier !== 2 && request.requested_tier !== 3) ||
                request.requested_tier <= customer.kyc_tier)
                throw new BankError("BIZ_KYC_TIER_INVALID");
            const twinAt = this.now().toISOString();
            this.db.prepare("UPDATE kyc_requests SET status='approved',approved_at=? WHERE customer_id=?")
                .run(twinAt, customerId);
            this.db.prepare("UPDATE customers SET kyc_tier=?,kyc_status='approved' WHERE id=?")
                .run(request.requested_tier, customerId);
            this.db.prepare(`INSERT INTO kyc_history
        (customer_id,event,previous_tier,requested_tier,twin_at,recorded_at,reviewer)
        VALUES (?,'approved',?,?,?,?,?)`)
                .run(customerId, customer.kyc_tier, request.requested_tier, twinAt, this.realNow().toISOString(), reviewer ?? null);
        });
    }
    effectiveTier(customerId: string): number {
        return effectiveKycTier(this, this.customer(customerId));
    }
    pixDailyLimit(customerId: string): number {
        const tier = this.effectiveTier(customerId);
        const base = this.pixLimits.daily_by_tier_cents[tier] ?? 0;
        const feature = this.db.prepare(`SELECT f.enabled FROM feature_flags f WHERE f.id='limite_dinamico'
      AND NOT EXISTS (SELECT 1 FROM blue_containments c WHERE c.kind='disable_flag' AND c.target=f.id
      AND c.lifted_at IS NULL AND c.expires_at>?)`)
            .get(this.realNow().toISOString()) as {
            enabled: number;
        } | undefined;
        if (!feature?.enabled)
            return base;
        const row = this.db.prepare("SELECT extra_cents,verified FROM dynamic_limits WHERE customer_id=?")
            .get(customerId) as {
            extra_cents: number;
            verified: number;
        } | undefined;
        if (row?.verified === 0 && this.db.prepare(`SELECT 1 FROM blue_containments
      WHERE kind='disable_flag' AND target='limite_dinamico'
        AND lifted_at IS NULL LIMIT 1`).get())
            return base;
        return base + (row?.extra_cents ?? 0);
    }
    pixChannelLimit(customerId: string, channel: "app" | "scheduled"): PixChannelLimit {
        this.customer(customerId);
        const row = this.db.prepare(`SELECT daily_limit_cents,pending_limit_cents,
      pending_effective_at,policy_version FROM pix_channel_limits
      WHERE customer_id=? AND channel=?`).get(customerId, channel) as {
            daily_limit_cents: number;
            pending_limit_cents: number | null;
            pending_effective_at: string | null;
            policy_version: number;
        } | undefined;
        const effective = row?.pending_limit_cents !== null &&
            row?.pending_limit_cents !== undefined && row.pending_effective_at &&
            row.pending_effective_at <= this.now().toISOString();
        return { channel, daily_limit_cents: effective ? row!.pending_limit_cents! :
                row?.daily_limit_cents ?? this.pixDailyLimit(customerId),
            pending: !effective && row?.pending_limit_cents !== null &&
                row?.pending_limit_cents !== undefined && row.pending_effective_at ?
                { value: row.pending_limit_cents, effective_at: row.pending_effective_at } : null,
            policy_version: row?.policy_version ?? 1 };
    }
    requestPixChannelLimit(customerId: string, channel: "app" | "scheduled", value: number): PixChannelLimit {
        if ((channel !== "app" && channel !== "scheduled") ||
            !Number.isSafeInteger(value) || value < 0 ||
            value > this.pixLimits.max_setting_cents)
            throw new BankError("BIZ_PIX_LIMIT_INVALID");
        return this.transaction(() => {
            if (this.customer(customerId).status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            const current = this.pixChannelLimit(customerId, channel);
            const increase = value > current.daily_limit_cents;
            this.db.prepare(`INSERT INTO pix_channel_limits
        (customer_id,channel,daily_limit_cents,pending_limit_cents,
          pending_effective_at,policy_version) VALUES (?,?,?,?,?,1)
        ON CONFLICT(customer_id,channel) DO UPDATE SET
          daily_limit_cents=excluded.daily_limit_cents,
          pending_limit_cents=excluded.pending_limit_cents,
          pending_effective_at=excluded.pending_effective_at,
          policy_version=excluded.policy_version`).run(customerId, channel, increase ? current.daily_limit_cents : value, increase ? value : null, increase ? new Date(this.now().getTime() + 86400000).toISOString() : null);
            this.telemetry.emit({ source: "pix", category: "limits",
                action: "daily_limit_changed", outcome: "success", userId: customerId,
                message: increase ? "Pix channel limit increase scheduled" :
                    "Pix channel limit reduced" });
            return this.pixChannelLimit(customerId, channel);
        });
    }
    pixAutomaticLimit(customerId: string, accountId: string): PixAutomaticLimit {
        this.ownAccount(customerId, accountId);
        const row = this.db.prepare(`SELECT daily_limit_cents,pending_limit_cents,
      pending_effective_at FROM pix_automatic_limits WHERE account_id=?`)
            .get(accountId) as {
            daily_limit_cents: number;
            pending_limit_cents: number | null;
            pending_effective_at: string | null;
        } | undefined;
        const effective = row?.pending_limit_cents !== null &&
            row?.pending_limit_cents !== undefined && row.pending_effective_at &&
            row.pending_effective_at <= this.now().toISOString();
        return { account_id: accountId,
            daily_limit_cents: effective ? row!.pending_limit_cents! :
                row?.daily_limit_cents ?? this.pixDailyLimit(customerId),
            pending: !effective && row?.pending_limit_cents !== null &&
                row?.pending_limit_cents !== undefined && row.pending_effective_at
                ? { value: row.pending_limit_cents, effective_at: row.pending_effective_at } : null };
    }
    requestPixAutomaticLimit(customerId: string, accountId: string, value: number): PixAutomaticLimit {
        if (!Number.isSafeInteger(value) || value < 0 || value > this.pixLimits.max_setting_cents)
            throw new BankError("BIZ_AUTOMATIC_LIMIT");
        return this.transaction(() => {
            const current = this.pixAutomaticLimit(customerId, accountId);
            const increase = value > current.daily_limit_cents;
            this.db.prepare(`INSERT INTO pix_automatic_limits
        (account_id,daily_limit_cents,pending_limit_cents,pending_effective_at)
        VALUES (?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
        daily_limit_cents=excluded.daily_limit_cents,
        pending_limit_cents=excluded.pending_limit_cents,
        pending_effective_at=excluded.pending_effective_at`)
                .run(accountId, increase ? current.daily_limit_cents : value, increase ? value : null, increase ? new Date(this.now().getTime() + 8 * 3600000).toISOString() : null);
            this.telemetry.emit({ source: "pix", category: "automatic",
                action: "daily_limit_changed", outcome: "success", userId: customerId,
                accountId, message: increase ? "Automatic Pix limit increase scheduled" :
                    "Automatic Pix limit reduced" });
            return this.pixAutomaticLimit(customerId, accountId);
        });
    }
    pixNightSettings(customerId: string): PixNightSettings {
        this.customer(customerId);
        const now = this.now().toISOString();
        const active = this.db.prepare(`SELECT value FROM pix_limits WHERE customer_id=? AND setting=?
      AND superseded_at IS NULL AND effective_at<=? ORDER BY effective_at DESC,id DESC LIMIT 1`);
        const pending = this.db.prepare(`SELECT value,effective_at FROM pix_limits WHERE customer_id=? AND setting=?
      AND superseded_at IS NULL AND effective_at>? ORDER BY id DESC LIMIT 1`);
        const limit = active.get(customerId, "night_limit_cents", now) as {
            value: number;
        } | undefined;
        const start = active.get(customerId, "night_start_hour", now) as {
            value: 20 | 22;
        } | undefined;
        const pendingLimit = pending.get(customerId, "night_limit_cents", now) as {
            value: number;
            effective_at: string;
        } | undefined;
        const pendingStart = pending.get(customerId, "night_start_hour", now) as {
            value: 20 | 22;
            effective_at: string;
        } | undefined;
        return { night_limit_cents: limit?.value ?? this.pixLimits.night_limit_cents, night_start_hour: start?.value ?? this.pixLimits.night_start_hour,
            pending_limit: pendingLimit ?? null, pending_start_hour: pendingStart ?? null };
    }
    requestPixNightSetting(customerId: string, setting: "night_limit_cents" | "night_start_hour", value: number): PixNightSettings {
        if (setting === "night_limit_cents" ? !Number.isSafeInteger(value) || value < 0 || value > this.pixLimits.max_setting_cents :
            value !== 20 && value !== 22)
            throw new BankError("BIZ_PIX_LIMIT_INVALID");
        return this.transaction(() => {
            if (this.customer(customerId).status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            const current = this.pixNightSettings(customerId);
            const active = setting === "night_limit_cents" ? current.night_limit_cents : current.night_start_hour;
            const now = this.now();
            const requestedAt = now.toISOString();
            this.db.prepare(`UPDATE pix_limits SET superseded_at=? WHERE customer_id=? AND setting=?
        AND effective_at>? AND superseded_at IS NULL`).run(requestedAt, customerId, setting, requestedAt);
            if (value !== active) {
                const effectiveAt = value > active ? new Date(now.getTime() + 86400000).toISOString() : requestedAt;
                this.db.prepare(`INSERT INTO pix_limits
          (customer_id,setting,value,requested_at,effective_at) VALUES (?,?,?,?,?)`)
                    .run(customerId, setting, value, requestedAt, effectiveAt);
            }
            this.telemetry.emit({ source: "pix", category: "limits", action: "night_setting_requested",
                outcome: "success", userId: customerId,
                message: value > active ? "Pix night setting change scheduled" : "Pix night setting changed" });
            return this.pixNightSettings(customerId);
        });
    }
    requiresPixStepUp(fromAccount: string, toAccount: string, amount: number): boolean {
        if (amount > 100000)
            return true;
        if (amount <= 50000)
            return false;
        return !this.db.prepare(`SELECT 1 FROM pix_transfers
      WHERE from_account=? AND to_account=? LIMIT 1`).get(fromAccount, toAccount);
    }
    private activePixKeyCount(accountId: string): number {
        const row = this.db.prepare(`SELECT COUNT(*) n FROM pix_keys
      WHERE account_id=? AND status='active'`).get(accountId) as {
            n: number;
        };
        return row.n;
    }
    private pixKeyCapacity(account: Account): number {
        return account.kind === "merchant" && this.db.prepare(`SELECT 1
      FROM business_account_identity WHERE account_id=?`).get(account.id) ? 20 : 5;
    }
    private assertPixKeyDocument(customerId: string, accountId: string, parsed: {
        type: string;
        value: string;
    }): void {
        if (parsed.type !== "cpf" && parsed.type !== "cnpj")
            return;
        const business = this.db.prepare(`SELECT cnpj FROM business_account_identity
      WHERE account_id=?`).get(accountId) as {
            cnpj: string;
        } | undefined;
        if (parsed.type === "cpf" && (business || parsed.value !== this.customer(customerId).cpf) ||
            parsed.type === "cnpj" && parsed.value !== business?.cnpj)
            throw new BankError("DEF_PIX_KEY_DOCUMENT_MISMATCH");
    }
    registerPixKey(customerId: string, accountId: string, key: string): {
        id: string;
        key: string;
    } {
        const parsed = parsePixKey(key);
        if (!parsed || key.length > 255)
            throw new BankError("BIZ_INVALID_KEY");
        return this.transaction(() => {
            const customer = this.customer(customerId);
            if (customer.status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            const account = this.ownAccount(customerId, accountId);
            if (account.status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            if (account.kind === "salary")
                throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
            this.assertPixKeyDocument(customerId, accountId, parsed);
            const capacity = this.pixKeyCapacity(account);
            if (this.activePixKeyCount(accountId) >= capacity)
                throw new BankError("BIZ_KEY_LIMIT");
            if (this.spi.lookup(parsed.value))
                throw new BankError("BIZ_KEY_ALREADY_EXISTS");
            const inactive = this.db.prepare(`SELECT k.id,a.customer_id FROM pix_keys k
        JOIN accounts a ON a.id=k.account_id WHERE k.key_value=? AND k.status='inactive'`)
                .get(parsed.value) as {
                id: string;
                customer_id: string;
            } | undefined;
            if (inactive) {
                if (inactive.customer_id !== customerId)
                    throw new BankError("BIZ_KEY_ALREADY_EXISTS");
                if (this.db.prepare(`SELECT 1 FROM pix_key_claims WHERE key_id=?
          AND status IN ('pending','verified') LIMIT 1`).get(inactive.id))
                    throw new BankError("BIZ_CLAIM_ALREADY_ACTIVE");
                this.db.prepare(`UPDATE pix_keys SET account_id=?,created_at=?,key_type=?,status='active'
          WHERE id=?`).run(accountId, this.now().toISOString(), parsed.type, inactive.id);
                return { id: inactive.id, key: parsed.value };
            }
            const id = newId("key", this.now().getTime());
            try {
                this.db.prepare(`INSERT INTO pix_keys
          (id,key_value,account_id,created_at,key_type,status,fraud_flag)
          VALUES (?,?,?,?,?,'active',0)`).run(id, parsed.value, accountId, this.now().toISOString(), parsed.type);
            }
            catch {
                throw new BankError("BIZ_KEY_ALREADY_EXISTS");
            }
            return { id, key: parsed.value };
        });
    }
    deregisterPixKey(customerId: string, keyId: string): {
        id: string;
        status: "inactive";
    } {
        return this.transaction(() => {
            const key = this.db.prepare(`SELECT k.account_id,k.status FROM pix_keys k
        JOIN accounts a ON a.id=k.account_id WHERE k.id=? AND a.customer_id=?`)
                .get(keyId, customerId) as {
                account_id: string;
                status: string;
            } | undefined;
            if (!key)
                throw new BankError("DEF_NOT_FOUND");
            if (key.status !== "active")
                throw new BankError("BIZ_KEY_NOT_ACTIVE");
            if (this.db.prepare(`SELECT 1 FROM pix_key_claims WHERE key_id=?
        AND status IN ('pending','verified') LIMIT 1`).get(keyId))
                throw new BankError("BIZ_CLAIM_ALREADY_ACTIVE");
            this.db.prepare("UPDATE pix_keys SET status='inactive' WHERE id=?").run(keyId);
            this.telemetry.emit({ source: "dict", category: "identity", action: "key_deregister",
                outcome: "success", userId: customerId, accountId: key.account_id,
                message: "Pix key deregistered" });
            return { id: keyId, status: "inactive" };
        });
    }
    pixFraudHistory(input: {
        key?: string;
        accountId?: string;
        cpf?: string;
    }) {
        const parsed = input.key === undefined ? null : parsePixKey(input.key);
        const normalized = parsed?.value ?? input.key;
        const knownKey = normalized && (this.db.prepare("SELECT 1 FROM pix_keys WHERE key_value=?").get(normalized) ||
            this.spi.lookup(normalized));
        if (input.key !== undefined && !parsed && !knownKey)
            throw new BankError("BIZ_INVALID_KEY");
        const knownAccount = input.accountId && (this.db.prepare("SELECT 1 FROM accounts WHERE id=? AND customer_id IS NOT NULL")
            .get(input.accountId) || this.spi.account(input.accountId));
        const knownCpf = input.cpf && this.db.prepare("SELECT 1 FROM customers WHERE cpf=?").get(input.cpf);
        const at = this.now();
        return { key: dictFraudCounter(this.db, at, "key_value", knownKey ? normalized : undefined),
            account: dictFraudCounter(this.db, at, "account_id", knownAccount ? input.accountId : undefined),
            cpf: dictFraudCounter(this.db, at, "cpf", knownCpf ? input.cpf : undefined) };
    }
    flagPixKeyFraud(key: string, flagged: boolean, actor: string, operationId?: string): void {
        if (typeof key !== "string" || !key)
            throw new BankError("BIZ_INVALID_KEY");
        if (typeof flagged !== "boolean")
            throw new BankError("BIZ_INVALID_FRAUD_FLAG");
        if (typeof actor !== "string" || !actor.trim() || actor.length > 128 ||
            (operationId !== undefined && (typeof operationId !== "string" ||
                !/^[a-zA-Z0-9._:-]{1,128}$/.test(operationId))))
            throw new BankError("BIZ_INVALID_ACTOR");
        const normalized = parsePixKey(key)?.value ?? key;
        this.transaction(() => {
            const prior = operationId && this.db.prepare(`SELECT key_value,action,actor FROM dict_fraud_operations
        WHERE operation_id=?`).get(operationId) as {
                key_value: string;
                action: string;
                actor: string;
            } | undefined;
            if (prior) {
                if (prior.key_value !== normalized || prior.action !== (flagged ? "marked" : "cleared") || prior.actor !== actor)
                    throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
                return;
            }
            const local = this.db.prepare(`SELECT k.account_id,k.fraud_flag,a.customer_id,c.cpf
        FROM pix_keys k JOIN accounts a ON a.id=k.account_id LEFT JOIN customers c ON c.id=a.customer_id
        WHERE k.key_value=?`).get(normalized) as {
                account_id: string;
                fraud_flag: number;
                customer_id: string | null;
                cpf: string | null;
            } | undefined;
            const pspAccount = local ? undefined : this.spi.lookup(normalized);
            const external = pspAccount ? { account_id: pspAccount.id,
                fraud_flag: pspAccount.fraud_flag } : undefined;
            const target = local ?? external;
            if (!target)
                throw new BankError("DEF_NOT_FOUND");
            if (operationId)
                this.db.prepare("INSERT INTO dict_fraud_operations VALUES (?,?,?,?)")
                    .run(operationId, normalized, flagged ? "marked" : "cleared", actor);
            if (Boolean(target.fraud_flag) === flagged)
                return;
            if (local)
                this.db.prepare("UPDATE pix_keys SET fraud_flag=? WHERE key_value=?").run(Number(flagged), normalized);
            else
                this.psp.setFraudFlagByKey(normalized, flagged);
            this.db.prepare(`INSERT INTO dict_fraud_events
        (id,operation_id,source,key_value,account_id,customer_id,cpf,action,actor,occurred_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)`).run(newId("dict_fraud", this.now().getTime()), operationId ?? null, local ? "local" : "synthetic_psp", normalized, target.account_id, local?.customer_id ?? null, local?.cpf ?? null, flagged ? "marked" : "cleared", actor, this.now().toISOString());
            this.log({ actor, kind: "pix_key_fraud_flag", route: "dict.fraud_flag", status: 200 });
            this.telemetry.emit({ source: "dict", category: "security", action: "fraud_flag",
                outcome: "success", message: flagged ? "Pix key marked for fraud" : "Pix key fraud marker cleared" });
        });
    }
    requestPixKeyClaim(customerId: string, toAccount: string, key: string, kind: "portability" | "ownership"): PixKeyClaim {
        const parsed = parsePixKey(key);
        if (!parsed)
            throw new BankError("BIZ_INVALID_KEY");
        const proof = kind === "ownership" ? String(randomInt(0, 1000000)).padStart(6, "0") : null;
        const claim = this.transaction(() => {
            if (this.customer(customerId).status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            const target = this.ownAccount(customerId, toAccount);
            if (target.status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            if (target.kind === "salary")
                throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
            this.assertPixKeyDocument(customerId, toAccount, parsed);
            const source = this.db.prepare(`SELECT k.id,k.account_id,k.key_type,a.customer_id
        FROM pix_keys k JOIN accounts a ON a.id=k.account_id
        WHERE k.key_value=? AND (k.status='active' OR
          (k.status='inactive' AND ?='ownership'))`).get(parsed.value, kind) as {
                id: string;
                account_id: string;
                key_type: string;
                customer_id: string;
            } | undefined;
            if (!source)
                throw new BankError("DEF_NOT_FOUND");
            if (source.account_id === toAccount)
                throw new BankError("BIZ_CLAIM_SAME_ACCOUNT");
            if (kind === "portability" && source.customer_id !== customerId)
                throw new BankError("BIZ_CLAIM_OWNER_MISMATCH");
            if (kind === "ownership" && (source.customer_id === customerId ||
                !["email", "phone"].includes(source.key_type)))
                throw new BankError("BIZ_CLAIM_PROOF_UNAVAILABLE");
            const now = this.now();
            const recent = this.db.prepare(`SELECT COUNT(*) n FROM pix_key_claims
        WHERE key_id=? AND requester_customer_id=? AND requested_at>=?`)
                .get(source.id, customerId, new Date(now.getTime() - 24 * 60 * 60000).toISOString()) as {
                n: number;
            };
            if (recent.n >= 3)
                throw new BankError("BIZ_CLAIM_RATE_LIMIT");
            const id = newId("claim", now.getTime());
            const status = kind === "portability" ? "verified" : "pending";
            const readyAt = new Date(now.getTime() + (kind === "portability" ? 24 : 7 * 24) * 60 * 60000).toISOString();
            try {
                this.db.prepare(`INSERT INTO pix_key_claims
          (id,key_id,kind,from_account,to_account,requester_customer_id,status,
           requested_at,ready_at,verified_at,proof_hash,proof_expires_at,proof_issues)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, source.id, kind, source.account_id, toAccount, customerId, status, now.toISOString(), readyAt, kind === "portability" ? now.toISOString() : null, proof ? createHash("sha256").update(proof).digest("hex") : null, proof ? new Date(now.getTime() + 24 * 60 * 60000).toISOString() : null, proof ? 1 : 0);
            }
            catch {
                throw new BankError("BIZ_CLAIM_ALREADY_ACTIVE");
            }
            return { id, key: parsed.value, kind, status, ready_at: readyAt,
                verified_at: kind === "portability" ? now.toISOString() : null,
                completed_at: null } as PixKeyClaim;
        });
        if (proof)
            this.pixClaimProofs.set(claim.id, proof);
        return claim;
    }
    simulatedPixKeyClaimProof(claimId: string, customerId: string): string {
        const claim = this.db.prepare(`SELECT requester_customer_id,status FROM pix_key_claims WHERE id=?`)
            .get(claimId) as {
            requester_customer_id: string;
            status: string;
        } | undefined;
        const proof = this.pixClaimProofs.get(claimId);
        if (!claim || claim.requester_customer_id !== customerId || claim.status !== "pending" || !proof)
            throw new BankError("DEF_NOT_FOUND");
        return proof;
    }
    reissuePixKeyClaimProof(customerId: string, claimId: string): PixKeyClaim {
        const proof = String(randomInt(0, 1000000)).padStart(6, "0");
        const claim = this.transaction(() => {
            const row = this.db.prepare(`SELECT proof_issues FROM pix_key_claims WHERE id=?
        AND requester_customer_id=? AND kind='ownership' AND status='pending'`)
                .get(claimId, customerId) as {
                proof_issues: number;
            } | undefined;
            if (!row)
                throw new BankError("DEF_NOT_FOUND");
            if (row.proof_issues >= 5)
                throw new BankError("BIZ_CLAIM_PROOF_LIMIT");
            this.db.prepare(`UPDATE pix_key_claims SET proof_hash=?,proof_expires_at=?,
        proof_issues=proof_issues+1,attempts=0 WHERE id=?`).run(createHash("sha256").update(proof).digest("hex"), new Date(this.now().getTime() + 24 * 60 * 60000).toISOString(), claimId);
            return this.pixKeyClaim(customerId, claimId);
        });
        this.pixClaimProofs.set(claimId, proof);
        return claim;
    }
    verifyPixKeyClaim(customerId: string, claimId: string, code: string): PixKeyClaim {
        if (!/^\d{6}$/.test(code))
            throw new BankError("BIZ_CLAIM_PROOF_INVALID");
        const valid = this.transaction(() => {
            const row = this.db.prepare(`SELECT proof_hash,proof_expires_at,attempts FROM pix_key_claims
        WHERE id=? AND requester_customer_id=? AND status='pending'`)
                .get(claimId, customerId) as {
                proof_hash: string;
                proof_expires_at: string;
                attempts: number;
            } | undefined;
            if (!row)
                throw new BankError("DEF_NOT_FOUND");
            if (row.attempts >= 5 || row.proof_expires_at < this.now().toISOString())
                throw new BankError("BIZ_CLAIM_PROOF_EXPIRED");
            const digest = createHash("sha256").update(code).digest();
            const expected = Buffer.from(row.proof_hash, "hex");
            const matches = expected.length === digest.length && timingSafeEqual(digest, expected);
            this.db.prepare(`UPDATE pix_key_claims SET attempts=attempts+1,
        status=CASE WHEN ? THEN 'verified' WHEN attempts+1>=5 THEN 'rejected' ELSE status END,
        verified_at=CASE WHEN ? THEN ? ELSE verified_at END WHERE id=?`)
                .run(Number(matches), Number(matches), this.now().toISOString(), claimId);
            return matches;
        });
        if (!valid)
            throw new BankError("BIZ_CLAIM_PROOF_INVALID");
        this.pixClaimProofs.delete(claimId);
        return this.pixKeyClaim(customerId, claimId);
    }
    pixKeyClaim(customerId: string, claimId: string): PixKeyClaim {
        const row = this.db.prepare(`SELECT c.id,k.key_value key,c.kind,c.status,c.ready_at,
      c.verified_at,c.completed_at,c.requester_customer_id,a.customer_id source_customer_id
      FROM pix_key_claims c JOIN pix_keys k ON k.id=c.key_id
      JOIN accounts a ON a.id=c.from_account WHERE c.id=?`).get(claimId) as (PixKeyClaim & {
            key_value: string;
            requester_customer_id: string;
            source_customer_id: string;
        }) | undefined;
        if (!row || (row.requester_customer_id !== customerId && row.source_customer_id !== customerId))
            throw new BankError("DEF_NOT_FOUND");
        return { id: row.id, key: row.key_value, kind: row.kind, status: row.status,
            ready_at: row.ready_at, verified_at: row.verified_at, completed_at: row.completed_at };
    }
    completePixKeyClaim(customerId: string, claimId: string): PixKeyClaim {
        return this.transaction(() => {
            const row = this.db.prepare(`SELECT c.key_id,c.from_account,c.to_account,c.kind,c.status,c.ready_at,
        c.requester_customer_id,k.account_id current_account,k.key_value
        FROM pix_key_claims c JOIN pix_keys k ON k.id=c.key_id WHERE c.id=?`)
                .get(claimId) as {
                key_id: string;
                from_account: string;
                to_account: string;
                kind: string;
                status: string;
                ready_at: string;
                requester_customer_id: string;
                current_account: string;
                key_value: string;
            } | undefined;
            if (!row || row.requester_customer_id !== customerId)
                throw new BankError("DEF_NOT_FOUND");
            if (row.status !== "verified" || row.ready_at > this.now().toISOString())
                throw new BankError("BIZ_CLAIM_NOT_READY");
            if (row.current_account !== row.from_account)
                throw new BankError("BIZ_CLAIM_SOURCE_CHANGED");
            if (this.customer(customerId).status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            const target = this.ownAccount(customerId, row.to_account);
            if (target.status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            if (target.kind === "salary")
                throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
            const parsed = parsePixKey(row.key_value);
            if (!parsed)
                throw new BankError("INTEGRITY_PIX_KEY_INVALID");
            this.assertPixKeyDocument(customerId, row.to_account, parsed);
            if (this.activePixKeyCount(row.to_account) >= this.pixKeyCapacity(target))
                throw new BankError("BIZ_KEY_LIMIT");
            this.db.prepare("UPDATE pix_keys SET account_id=?,status='active' WHERE id=?")
                .run(row.to_account, row.key_id);
            this.db.prepare("UPDATE pix_key_claims SET status='completed',completed_at=? WHERE id=?")
                .run(this.now().toISOString(), claimId);
            this.telemetry.emit({ source: "dict", category: "identity", action: "claim_complete",
                outcome: "success", userId: customerId, message: "Pix key claim completed" });
            return this.pixKeyClaim(customerId, claimId);
        });
    }
    closePixKeyClaim(customerId: string, claimId: string): PixKeyClaim {
        return this.transaction(() => {
            const row = this.db.prepare(`SELECT c.requester_customer_id,c.status,a.customer_id source_customer_id
        FROM pix_key_claims c JOIN accounts a ON a.id=c.from_account WHERE c.id=?`)
                .get(claimId) as {
                requester_customer_id: string;
                status: string;
                source_customer_id: string;
            } | undefined;
            if (!row || (row.requester_customer_id !== customerId && row.source_customer_id !== customerId))
                throw new BankError("DEF_NOT_FOUND");
            if (row.status !== "pending" && row.status !== "verified")
                throw new BankError("BIZ_CLAIM_NOT_ACTIVE");
            this.db.prepare("UPDATE pix_key_claims SET status=? WHERE id=?")
                .run(row.source_customer_id === customerId ? "contested" : "rejected", claimId);
            this.pixClaimProofs.delete(claimId);
            return this.pixKeyClaim(customerId, claimId);
        });
    }
    lookupPixKey(key: string, session = "direct", userId?: string, externalLookup?: ExternalPixKeyLookup | null): {
        holder_name: string;
        cpf: string;
        account_id: string;
        fraud_flag: boolean;
        registered_at: string | null;
        security: ReturnType<Bank["pixFraudHistory"]>;
    } {
        const normalized = parsePixKey(key)?.value ?? key;
        if ((!this.separatedEcosystem && externalLookup !== undefined) ||
            (externalLookup && externalLookup.key !== normalized))
            throw new BankError("ECOSYSTEM_MESSAGE_INVALID");
        const sessionHash = createHash("sha256").update(session).digest("hex");
        const userHash = createHash("sha256").update(userId ?? session).digest("hex");
        const participantHash = createHash("sha256").update(JACARANDA_ISPB).digest("hex");
        const result = this.transaction(() => {
            const nowMs = this.now().getTime();
            const since = new Date(nowMs - 60000).toISOString();
            const count = (this.db.prepare("SELECT COUNT(*) n FROM pix_lookup_attempts WHERE session_hash=? AND ts>=?")
                .get(sessionHash, since) as {
                n: number;
            }).n;
            if (!lookupRateAllowed(this, count))
                throw new BankError("BIZ_RATE_LIMIT");
            if ((!consumeDictToken(this.db, "user", userHash, 30, 0.5, nowMs, this.separatedEcosystem ? "bank" : "embedded") ||
                !consumeDictToken(this.db, "participant", participantHash, 300, 5, nowMs, this.separatedEcosystem ? "bank" : "embedded")))
                throw new BankError("BIZ_RATE_LIMIT");
            this.db.prepare("INSERT INTO pix_lookup_attempts VALUES (?,?,?,?)").run(newId("lookup", nowMs), sessionHash, createHash("sha256").update(normalized).digest("hex"), this.now().toISOString());
            const row = this.db.prepare(`SELECT c.name holder_name,c.cpf,a.id account_id,k.fraud_flag,k.created_at FROM pix_keys k
        JOIN accounts a ON a.id=k.account_id JOIN customers c ON c.id=a.customer_id
        WHERE k.key_value=? AND k.status='active'`)
                .get(normalized) as {
                holder_name: string;
                cpf: string;
                account_id: string;
                fraud_flag: number;
                created_at: string;
            } | undefined;
            if (!row) {
                if (this.separatedEcosystem && externalLookup === undefined)
                    throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
                const external = externalLookup === undefined ? this.spi.lookup(normalized) : externalLookup;
                if (!external || external.status !== "active")
                    return undefined;
                const holderName = external.holder_name.split(/\s+/).map((part) => `${part[0] ?? "*"}${"*".repeat(Math.max(part.length - 1, 1))}`).join(" ");
                return { holder_name: holderName, cpf: "***.***.***-**", account_id: external.id,
                    fraud_flag: Boolean(external.fraud_flag), registered_at: null,
                    security: externalLookup?.security ??
                        this.pixFraudHistory({ key: normalized, accountId: external.id }) };
            }
            return { ...pixKeyResult(this, { holder_name: row.holder_name, cpf: row.cpf,
                    account_id: row.account_id }), fraud_flag: Boolean(row.fraud_flag), registered_at: row.created_at,
                security: this.pixFraudHistory({ key: normalized, accountId: row.account_id, cpf: row.cpf }) };
        });
        if (!result)
            throw new BankError("DEF_NOT_FOUND");
        this.telemetry.emit({ source: "dict", category: "lookup", action: "resolve_key",
            outcome: "success", counterparty: result.account_id,
            sessionId: sessionHash, ...(userId ? { userId } : {}),
            message: "Pix key resolved" });
        return result;
    }
    async transferPixWithRace(input: PixTransferInput): Promise<PixResult> {
        if (!pixRaceEnabled(this))
            return this.transferPix(input);
        if (this.availableBalance(input.from) < input.amount)
            throw new BankError("BIZ_INSUFFICIENT_FUNDS");
        await new Promise<void>((resolve) => setImmediate(resolve));
        try {
            return this.transferPixInternal(input, true);
        }
        catch (error) {
            this.logPixHold(input, error);
            throw error;
        }
    }
    transferPix(input: PixTransferInput): PixResult {
        try {
            return this.transferPixInternal(input, false);
        }
        catch (error) {
            this.logPixHold(input, error);
            throw error;
        }
    }
    enqueueExternalPix(input: PixTransferInput): PixResult {
        if (!this.spi.account(input.to))
            throw new BankError("BIZ_PIX_EXTERNAL_REQUIRED");
        try {
            return this.transferPixInternal(input, false, false, undefined, true);
        }
        catch (error) {
            this.logPixHold(input, error);
            throw error;
        }
    }
    enqueueExternalPixWithEvidence(input: PixTransferInput, recipient: ExternalPixRecipient | null, evidence: PixRecipientEvidence | null): PixResult {
        if (!this.separatedEcosystem || !recipient || !evidence ||
            !this.validExternalPixEvidence(input, recipient, evidence))
            throw new BankError("INTEGRITY_PIX_RECIPIENT_EVIDENCE");
        try {
            return this.transferPixInternal(input, false, false, undefined, true, recipient, evidence);
        }
        catch (error) {
            this.logPixHold(input, error);
            throw error;
        }
    }
    private validExternalPixEvidence(input: {
        to: string;
    }, recipient: ExternalPixRecipient, evidence: PixRecipientEvidence): boolean {
        const history = evidence.fraudHistory;
        return recipient.id === input.to && /^\d{8}$/.test(recipient.ispb) &&
            recipient.ispb !== JACARANDA_ISPB && recipient.status === "active" &&
            (recipient.fraud_flag === 0 || recipient.fraud_flag === 1) &&
            evidence.exists === true && evidence.flagged === Boolean(recipient.fraud_flag) &&
            history?.known === true &&
            typeof history.history_complete_90d === "boolean" &&
            typeof history.history_complete_12m === "boolean" &&
            Number.isSafeInteger(history.marks_90d) && history.marks_90d! >= 0 &&
            Number.isSafeInteger(history.marks_12m) && history.marks_12m! >= 0;
    }
    transferInternalPixWithHistory(input: PixTransferInput, fraudHistory: DictFraudCounter): PixResult {
        if (!this.separatedEcosystem || !fraudHistory || fraudHistory.known !== true ||
            typeof fraudHistory.history_complete_90d !== "boolean" ||
            typeof fraudHistory.history_complete_12m !== "boolean" ||
            !Number.isSafeInteger(fraudHistory.marks_90d) || fraudHistory.marks_90d! < 0 ||
            !Number.isSafeInteger(fraudHistory.marks_12m) || fraudHistory.marks_12m! < 0)
            throw new BankError("INTEGRITY_PIX_RECIPIENT_EVIDENCE");
        const recipient = this.account(input.to);
        if (!recipient.customer_id || recipient.kind === "system")
            throw new BankError("BIZ_INVALID_PIX_ACCOUNT");
        const flagged = Boolean(this.db.prepare(`SELECT 1 FROM pix_keys
      WHERE account_id=? AND status='active' AND fraud_flag=1 LIMIT 1`)
            .get(input.to));
        const evidence: PixRecipientEvidence = { exists: true, flagged, fraudHistory };
        try {
            return this.transferPixInternal(input, false, false, undefined, false, undefined, evidence);
        }
        catch (error) {
            this.logPixHold(input, error);
            throw error;
        }
    }
    transferPixScheduledUnchecked(input: PixTransferInput, scheduledNightMode: boolean): PixResult {
        try {
            return this.transferPixInternal(input, false, true, scheduledNightMode);
        }
        catch (error) {
            this.logPixHold(input, error);
            throw error;
        }
    }
    private logPixHold(input: {
        from: string;
        actor: string;
    }, error: unknown): void {
        if (error instanceof BankError && error.code === "BIZ_MULE_HOLD")
            this.log({ actor: input.actor, kind: "mule_hold", accountId: input.from, route: "pix.transfers", status: 409 });
    }
    private transferPixInternal(input: PixTransferInput, precheckedBalance: boolean, skipPolicy = false, scheduledNightMode?: boolean, deferExternal = false, externalRecipient?: ExternalPixRecipient, recipientEvidence?: PixRecipientEvidence): PixResult {
        return withTrace(currentTrace() ?? newId("trace", this.now().getTime()), () => {
            const result = this.transaction((): {
                payment: PixResult;
            } | {
                error: BankError;
            } => {
                let riskDecisionId: string | undefined;
                if (Number.isSafeInteger(input.amount) && input.amount > this.pixLimits.max_transaction_cents)
                    throw new BankError("BIZ_INVALID_AMOUNT");
                if (Number.isSafeInteger(input.amount) && input.amount > 0 && input.idempotencyKey &&
                    !this.db.prepare(`SELECT 1 FROM pix_transfers WHERE from_account=? AND idempotency_key=?`)
                        .get(input.from, input.idempotencyKey)) {
                    const existingHold = this.db.prepare(`SELECT h.id,h.to_account,h.amount_cents,h.status,
            h.product,h.channel,
            h.expires_at,
            d.score,d.reason_codes_json FROM risk_pix_holds h JOIN risk_decisions d
            ON d.id=h.risk_decision_id WHERE h.from_account=? AND h.idempotency_key=?`)
                        .get(input.from, input.idempotencyKey) as {
                        id: string;
                        to_account: string;
                        amount_cents: number;
                        status: string;
                        product: string;
                        channel: string;
                        expires_at: string;
                        score: number;
                        reason_codes_json: string;
                    } | undefined;
                    if (existingHold) {
                        if (existingHold.to_account !== input.to || existingHold.amount_cents !== input.amount ||
                            existingHold.product !== (input.product ?? "standard") ||
                            existingHold.channel !== (input.product === "automatic" ? "automatic" :
                                input.channel ?? "app"))
                            throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
                        if (existingHold.status === "pending" &&
                            existingHold.expires_at <= this.now().toISOString())
                            this.expireRiskPixHolds();
                        if (existingHold.status !== "pending")
                            return { error: new BankError("BIZ_RISK_REVIEW_CLOSED") };
                        if (existingHold.expires_at <= this.now().toISOString())
                            return { error: new BankError("BIZ_RISK_REVIEW_CLOSED") };
                        return { error: new BankError("BIZ_RISK_HOLD", { score: existingHold.score,
                                reasonCodes: JSON.parse(existingHold.reason_codes_json) as string[],
                                holdId: existingHold.id }) };
                    }
                    const from = this.account(input.from);
                    if (from.customer_id) {
                        const decision = this.risk.evaluatePix({ customerId: from.customer_id,
                            accountId: input.from, toAccount: input.to, amountCents: input.amount,
                            ...(input.idempotencyKey ? { labProbeKey: input.idempotencyKey } : {}),
                            ...(input.deviceId ? { deviceId: input.deviceId } : {}),
                            ...(recipientEvidence ? { recipientEvidence } : {}) });
                        riskDecisionId = decision.id;
                        const risk = { score: decision.score, reasonCodes: decision.reason_codes };
                        if (decision.outcome === "decline")
                            return { error: new BankError(decision.reason_codes.includes("DESTINATION_FRAUD_FLAG") ? "BIZ_FRAUD_DESTINATION" : "BIZ_RISK_DECLINE", risk) };
                        if (decision.outcome === "hold") {
                            const hold = this.placeRiskPixHold(input, decision, externalRecipient);
                            return { error: new BankError("BIZ_RISK_HOLD", { ...risk, holdId: hold.id }) };
                        }
                        if (decision.outcome === "step_up" && !input.stepUpVerified)
                            return { error: new BankError("DEF_STEP_UP_REQUIRED", risk) };
                    }
                }
                return { payment: this.transferPixCore(input, precheckedBalance, skipPolicy, scheduledNightMode, riskDecisionId, deferExternal, externalRecipient) };
            });
            if ("error" in result)
                throw result.error;
            return result.payment;
        });
    }
    private transferPixCore(input: PixTransferInput, precheckedBalance: boolean, skipPolicy: boolean, scheduledNightMode?: boolean, riskDecisionId?: string, deferExternal = false, externalRecipient?: ExternalPixRecipient): PixResult {
        if (!Number.isSafeInteger(input.amount) || input.amount <= 0 || input.amount > this.pixLimits.max_transaction_cents)
            throw new BankError("BIZ_INVALID_AMOUNT");
        if (!input.idempotencyKey || input.idempotencyKey.length > 128)
            throw new BankError("BIZ_IDEMPOTENCY_REQUIRED");
        if ((input.channel !== undefined && input.channel !== "scheduled") ||
            (input.product === "automatic" && input.channel !== undefined))
            throw new BankError("BIZ_PIX_LIMIT_INVALID");
        const channel = input.product === "automatic" ? "automatic" : input.channel ?? "app";
        return this.transaction(() => {
            const existing = this.db.prepare(`SELECT id,end_to_end_id,from_account,to_account,amount,
        status,ledger_tx_id,product,channel
        FROM pix_transfers WHERE from_account=? AND idempotency_key=?`)
                .get(input.from, input.idempotencyKey) as (PixResult & {
                product: string;
                channel: string;
            }) | undefined;
            if (existing) {
                if (existing.amount !== input.amount || existing.to_account !== input.to ||
                    existing.product !== (input.product ?? "standard") ||
                    existing.channel !== channel)
                    throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
                return { id: existing.id, end_to_end_id: existing.end_to_end_id,
                    from_account: existing.from_account, to_account: existing.to_account,
                    amount: existing.amount, status: existing.status,
                    ledger_tx_id: existing.ledger_tx_id };
            }
            const from = this.account(input.from);
            const external = externalRecipient ??
                (this.separatedEcosystem ? undefined : this.spi.account(input.to));
            const to = external ? undefined : this.account(input.to);
            if (from.kind === "system" || to?.kind === "system")
                throw new BankError("BIZ_INVALID_PIX_ACCOUNT");
            if (from.kind === "salary" || to?.kind === "salary")
                throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
            if (from.status !== "active" || (to?.status ?? external?.status) !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            if ((from.customer_id && this.customer(from.customer_id).status !== "active") ||
                (to?.customer_id && this.customer(to.customer_id).status !== "active"))
                throw new BankError("DEF_ACCOUNT_FROZEN");
            const markedLocal = to && this.db.prepare(`SELECT 1 FROM pix_keys
        WHERE account_id=? AND status='active' AND fraud_flag=1 LIMIT 1`).get(to.id);
            if (external?.fraud_flag || markedLocal)
                throw new BankError("BIZ_FRAUD_DESTINATION");
            if (input.deviceId) {
                const device = from.customer_id && deviceQuarantine(this.db, from.customer_id, input.deviceId, this.now());
                if (!device)
                    throw new BankError("DEF_UNAUTHORIZED");
                if (device.quarantined || !device.pixRegistered) {
                    if (input.amount > this.pixLimits.new_device_transaction_cents)
                        throw new BankError("BIZ_NEW_DEVICE_LIMIT");
                    const since = new Date(this.now().getTime() - 86400000).toISOString();
                    const used = this.db.prepare(`SELECT COALESCE(SUM(amount),0) n FROM pix_transfers
            WHERE initiating_device_id=? AND status IN
              ('in_processing','settled','returned_partial','returned_full')
            AND COALESCE(settled_at,initiated_at)>=?`)
                        .get(input.deviceId, since) as {
                        n: number;
                    };
                    if (used.n + input.amount > this.pixLimits.new_device_daily_cents)
                        throw new BankError("BIZ_NEW_DEVICE_LIMIT");
                }
            }
            const hour = pixNightHour(this);
            const nightSettings = from.customer_id ? this.pixNightSettings(from.customer_id) : null;
            const automatic = input.product === "automatic";
            const night = automatic ? false : scheduledNightMode ??
                (hour >= (nightSettings?.night_start_hour ?? this.pixLimits.night_start_hour) ||
                    hour < 6);
            const nightLimit = nightSettings?.night_limit_cents ?? this.pixLimits.night_limit_cents;
            if (!skipPolicy && night && input.amount > nightLimit)
                throw new BankError("BIZ_NIGHT_LIMIT");
            if (!skipPolicy && night && from.customer_id) {
                const recent = this.db.prepare(`SELECT p.amount,
          COALESCE(p.settled_at,p.initiated_at) effective_at FROM pix_transfers p
          JOIN accounts a ON a.id=p.from_account WHERE a.customer_id=?
          AND p.status IN ('in_processing','settled','returned_partial','returned_full')
          AND p.night_mode=1 AND COALESCE(p.settled_at,p.initiated_at)>=?`).all(from.customer_id, new Date(this.now().getTime() - 12 * 60 * 60000).toISOString()) as {
                    amount: number;
                    effective_at: string;
                }[];
                const key = brtNightKey(this.now());
                const used = recent.filter((transfer) => brtNightKey(new Date(transfer.effective_at)) === key)
                    .reduce((sum, transfer) => sum + transfer.amount, 0);
                if (used + input.amount > nightLimit)
                    throw new BankError("BIZ_NIGHT_LIMIT");
            }
            if (!skipPolicy && from.customer_id) {
                const limit = automatic ? this.pixAutomaticLimit(from.customer_id, input.from)
                    .daily_limit_cents : this.pixDailyLimit(from.customer_id);
                const since = new Date(this.now().getTime() - 86400000).toISOString();
                const used = (this.db.prepare(`SELECT COALESCE(SUM(amount),0) n FROM pix_transfers
          WHERE from_account=? AND status IN
            ('in_processing','settled','returned_partial','returned_full')
          AND COALESCE(settled_at,initiated_at)>=? AND product=?`)
                    .get(input.from, since, automatic ? "automatic" : "standard") as {
                    n: number;
                }).n;
                if (used + input.amount > limit)
                    throw new BankError("BIZ_DAILY_LIMIT");
                if (channel !== "automatic") {
                    const channelLimit = this.pixChannelLimit(from.customer_id, channel)
                        .daily_limit_cents;
                    const channelUsed = (this.db.prepare(`SELECT COALESCE(SUM(p.amount),0) n
            FROM pix_transfers p JOIN accounts a ON a.id=p.from_account
            WHERE a.customer_id=? AND p.channel=? AND p.status IN
              ('in_processing','settled','returned_partial','returned_full')
            AND COALESCE(p.settled_at,p.initiated_at)>=?`)
                        .get(from.customer_id, channel, since) as {
                        n: number;
                    }).n;
                    if (channelUsed + input.amount > channelLimit)
                        throw new BankError("BIZ_CHANNEL_LIMIT");
                }
            }
            if (muleHoldEnabled(this)) {
                const opened = this.db.prepare("SELECT opened_at FROM accounts WHERE id=?").get(input.from) as {
                    opened_at: string;
                };
                if (this.now().getTime() - Date.parse(opened.opened_at) < 7 * 86400000) {
                    const since = new Date(this.now().getTime() - 15 * 60000).toISOString();
                    const inflow = this.db.prepare(`SELECT COUNT(DISTINCT from_account) senders,COALESCE(SUM(amount),0) total
            FROM pix_transfers WHERE to_account=? AND status='settled' AND settled_at>=?`)
                        .get(input.from, since) as {
                        senders: number;
                        total: number;
                    };
                    if (inflow.senders >= 5 && input.amount * 100 >= inflow.total * 80) {
                        throw new BankError("BIZ_MULE_HOLD");
                    }
                }
            }
            if (!precheckedBalance && this.availableBalance(input.from) < input.amount)
                throw new BankError("BIZ_INSUFFICIENT_FUNDS");
            const id = newId("pix", this.now().getTime());
            const ts = this.now().toISOString();
            const endToEndId = pixEndToEndId(id, new Date(ts));
            const history = this.db.prepare(`INSERT INTO pix_status_history
        (transfer_id,status,changed_at) VALUES (?,?,?)`);
            if (external) {
                const holdId = newId("hold", this.now().getTime());
                this.db.prepare(`INSERT INTO balance_holds
          (id,account_id,amount,kind,ref,actor,created_at,expires_at)
          VALUES (?,?,?,'pix_cautelar',?,?,?,?)`).run(holdId, input.from, input.amount, id, input.actor, ts, new Date(this.now().getTime() + 5 * 60000).toISOString());
                this.db.prepare(`INSERT INTO pix_transfers (id,idempotency_key,from_account,to_account,amount,
          status,initiated_at,settled_at,ledger_tx_id,night_mode,actor,end_to_end_id,initiating_device_id,
          risk_decision_id,product,channel,spi_command_version)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, input.idempotencyKey, input.from, input.to, input.amount, "created", ts, null, null, Number(night), input.actor, endToEndId, input.deviceId ?? null, riskDecisionId ?? null, input.product ?? "standard", channel, deferExternal ? 2 : 1);
                for (const status of ["created", "risk_review", "held"])
                    history.run(id, status, ts);
                const queuedAtReal = deferExternal ? this.realNow() : null;
                const eligibleAtReal = queuedAtReal ? new Date(queuedAtReal.getTime() +
                    spiLatencyMs(endToEndId, this.spiLatencyPolicy)).toISOString() : null;
                const deadlineAtReal = queuedAtReal && this.spiLatencyPolicy.version !== 1 ?
                    new Date(queuedAtReal.getTime() + this.spiLatencyPolicy.timeout_ms).toISOString() : null;
                this.db.prepare(`INSERT INTO pix_spi_outbox
          (transfer_id,end_to_end_id,from_ispb,to_ispb,amount_cents,trace_id,
            queued_at_real,eligible_at_real,deadline_at_real,latency_policy_version,created_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(id, endToEndId, JACARANDA_ISPB, external.ispb, input.amount, currentTrace() ?? null, queuedAtReal?.toISOString() ?? null, eligibleAtReal, deadlineAtReal, deferExternal ? this.spiLatencyPolicy.version : null, ts);
                if (deferExternal) {
                    this.db.prepare("UPDATE pix_transfers SET status='in_processing' WHERE id=?").run(id);
                    history.run(id, "in_processing", ts);
                    return { id, end_to_end_id: endToEndId, from_account: input.from,
                        to_account: input.to, amount: input.amount, status: "in_processing", ledger_tx_id: null };
                }
                history.run(id, "sent_to_spi", ts);
                let accepted: boolean;
                try {
                    const response = this.spi.submitPayment(endToEndId, JACARANDA_ISPB, external.ispb, input.amount, input.from, id, undefined, external.id);
                    this.db.prepare(`UPDATE pix_spi_outbox SET response_status=?,response_reason=?,
            responded_at=? WHERE transfer_id=? AND response_status IS NULL`)
                        .run(response.status, response.reason ?? null, this.now().toISOString(), id);
                    accepted = response.status === "ACSC";
                }
                catch (error) {
                    if (error instanceof Error && error.message === "SPI_UNAVAILABLE")
                        throw new BankError("BIZ_SPI_UNAVAILABLE");
                    throw error;
                }
                this.telemetry.emit({ source: "spi", category: "payment", action: "pacs.008",
                    outcome: "success", accountId: input.from, counterparty: input.to,
                    amountCents: input.amount, e2eId: endToEndId,
                    message: "Interbank Pix instruction sent" });
                this.telemetry.emit({ source: "spi", category: "payment", action: "pacs.002",
                    outcome: accepted ? "success" : "failure", accountId: input.from,
                    counterparty: input.to, amountCents: input.amount, e2eId: endToEndId,
                    message: accepted ? "Interbank Pix settlement confirmed" :
                        "Interbank Pix settlement rejected" });
                this.db.prepare("UPDATE balance_holds SET released_at=?,release_actor='spi' WHERE id=?")
                    .run(ts, holdId);
                if (!accepted) {
                    this.db.prepare("UPDATE pix_transfers SET status='rejected' WHERE id=?").run(id);
                    history.run(id, "rejected", ts);
                    return { id, end_to_end_id: endToEndId, from_account: input.from, to_account: input.to,
                        amount: input.amount, status: "rejected", ledger_tx_id: null };
                }
                const ledgerTxId = this.post([
                    { accountId: input.from, amount: -input.amount, kind: "pix", actor: input.actor,
                        refType: "pix", refId: id },
                    { accountId: this.systemAccountId("pix_settlement"), amount: input.amount,
                        kind: "pix", actor: input.actor, refType: "pix", refId: id },
                ]);
                this.psp.creditInbound(external.id, id, endToEndId, input.amount, input.from, ts);
                this.db.prepare(`UPDATE pix_transfers SET status='settled',settled_at=?,ledger_tx_id=?
          WHERE id=?`).run(ts, ledgerTxId, id);
                history.run(id, "settled", ts);
                const cautelar = this.psp.reviewIncoming(external.id, id, input.amount);
                if (cautelar)
                    this.telemetry.emit({ source: "risk", category: "pix",
                        action: "psp_cautelar", outcome: "failure", severity: "warn",
                        accountId: external.id, amountCents: input.amount, e2eId: endToEndId,
                        reasonCodes: [cautelar.reason], message: "Receiving PSP held unusual inbound Pix" });
                this.telemetry.emit({ source: "pix", category: "payment", action: "settle",
                    outcome: "success", ...(from.customer_id ? { userId: from.customer_id } : {}),
                    accountId: input.from, counterparty: input.to, amountCents: input.amount,
                    e2eId: endToEndId, message: "External Pix transfer settled" });
                return { id, end_to_end_id: endToEndId, from_account: input.from,
                    to_account: input.to, amount: input.amount, status: "settled", ledger_tx_id: ledgerTxId };
            }
            const ledgerTxId = this.post([
                { accountId: input.from, amount: -input.amount, kind: "pix", actor: input.actor, refType: "pix", refId: id },
                { accountId: to!.id, amount: input.amount, kind: "pix", actor: input.actor, refType: "pix", refId: id },
            ]);
            this.db.prepare(`INSERT INTO pix_transfers (id,idempotency_key,from_account,to_account,amount,
        status,initiated_at,settled_at,ledger_tx_id,night_mode,actor,end_to_end_id,initiating_device_id,
        risk_decision_id,product,channel)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, input.idempotencyKey, input.from, input.to, input.amount, "settled", ts, ts, ledgerTxId, Number(night), input.actor, endToEndId, input.deviceId ?? null, riskDecisionId ?? null, input.product ?? "standard", channel);
            history.run(id, "created", ts);
            history.run(id, "settled", ts);
            this.telemetry.emit({ source: "pix", category: "payment", action: "settle",
                outcome: "success", ...(from.customer_id ? { userId: from.customer_id } : {}),
                accountId: input.from, counterparty: input.to, amountCents: input.amount,
                e2eId: endToEndId, message: "Pix transfer settled" });
            return { id, end_to_end_id: endToEndId, from_account: input.from, to_account: input.to,
                amount: input.amount, status: "settled", ledger_tx_id: ledgerTxId };
        });
    }
    pixLatencyMetrics(): {
        count: number;
        p50_ms: number | null;
        p99_ms: number | null;
        max_ms: number | null;
    } {
        const rows = this.db.prepare(`SELECT queued_at_real,responded_at_real
      FROM pix_spi_outbox WHERE queued_at_real IS NOT NULL
        AND responded_at_real IS NOT NULL`).all() as {
            queued_at_real: string;
            responded_at_real: string;
        }[];
        const elapsed = rows.map((row) => Date.parse(row.responded_at_real) -
            Date.parse(row.queued_at_real));
        if (elapsed.some((ms) => !Number.isSafeInteger(ms) || ms < 0))
            throw new BankError("INTEGRITY_PIX_LATENCY");
        elapsed.sort((a, b) => a - b);
        const percentile = (fraction: number): number | null => elapsed.length > 0
            ? elapsed[Math.ceil(fraction * elapsed.length) - 1]! : null;
        return { count: elapsed.length, p50_ms: percentile(0.5),
            p99_ms: percentile(0.99), max_ms: elapsed.at(-1) ?? null };
    }
    dispatchPendingPspCredits(limit = 100): number {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
            throw new BankError("BIZ_INVALID_LIMIT");
        const pending = readPendingPspCredits(this.db, limit);
        let processed = 0;
        for (const row of pending) {
            withTrace(row.trace_id ?? newId("trace", this.now().getTime()), () => {
                this.psp.creditInbound(row.to_account, row.transfer_id, row.end_to_end_id, row.amount_cents, row.from_account, row.settled_at);
                const cautelar = this.psp.reviewIncoming(row.to_account, row.transfer_id, row.amount_cents);
                this.acknowledgePspCredit(row.transfer_id, cautelar?.reason ?? null);
            });
            processed++;
        }
        return processed;
    }
    acknowledgePspCredit(transferId: string, cautelarReason: string | null): void {
        if (cautelarReason !== null && !/^[A-Z0-9_]{1,64}$/.test(cautelarReason))
            throw new BankError("INTEGRITY_PIX_PSP_ACK");
        this.transaction(() => {
            const row = readPendingPspCredit(this.db, transferId);
            if (!row)
                throw new BankError("INTEGRITY_PIX_PSP_ACK");
            withTrace(row.trace_id ?? newId("trace", this.now().getTime()), () => {
                const ack = this.db.prepare(`UPDATE pix_psp_inbound_outbox
          SET acknowledged_at=? WHERE transfer_id=? AND acknowledged_at IS NULL`)
                    .run(this.now().toISOString(), transferId);
                if (ack.changes !== 1)
                    throw new BankError("INTEGRITY_PIX_PSP_ACK");
                if (cautelarReason)
                    this.telemetry.emit({ source: "risk", category: "pix",
                        action: "psp_cautelar", outcome: "failure", severity: "warn",
                        accountId: row.to_account, amountCents: row.amount_cents,
                        e2eId: row.end_to_end_id, reasonCodes: [cautelarReason],
                        message: "Receiving PSP held unusual inbound Pix" });
            });
        });
    }
    dispatchPendingPix(limit = 100): {
        processed: number;
        deferred: number;
    } {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
            throw new BankError("BIZ_INVALID_LIMIT");
        const pending = readDuePixCommands(this.db, this.realNow(), limit);
        let processed = 0, deferred = 0;
        for (const row of pending) {
            if (this.spi.account(row.to_account)?.ispb !== row.to_ispb)
                throw new BankError("INTEGRITY_PIX_SPI_COMMAND");
            let response: ReturnType<SpiNetwork["submitPayment"]>;
            try {
                response = withTrace(row.trace_id ?? newId("trace", this.now().getTime()), () => this.spi.submitPayment(row.end_to_end_id, row.from_ispb, row.to_ispb, row.amount, row.from_account, row.id, row.deadline_at_real ?? undefined, row.to_account));
            }
            catch (error) {
                if (error instanceof Error && error.message === "SPI_UNAVAILABLE") {
                    deferred++;
                    continue;
                }
                throw error;
            }
            this.applyQueuedSpiResponse(row.id, response);
            processed++;
        }
        this.dispatchPendingPspCredits(limit);
        return { processed, deferred };
    }
    applyQueuedSpiResponse(transferId: string, response: ReturnType<SpiNetwork["submitPayment"]>): void {
        this.transaction(() => {
            const row = this.db.prepare(`SELECT p.id,p.end_to_end_id,p.from_account,p.to_account,
        p.amount,p.actor,p.status,o.end_to_end_id command_end_to_end_id,
        o.from_ispb,o.to_ispb,o.amount_cents,o.trace_id,o.response_status
        FROM pix_transfers p JOIN pix_spi_outbox o ON o.transfer_id=p.id
        WHERE p.id=?`).get(transferId) as {
                id: string;
                end_to_end_id: string;
                from_account: string;
                to_account: string;
                amount: number;
                actor: string;
                status: string;
                command_end_to_end_id: string;
                from_ispb: string;
                to_ispb: string;
                amount_cents: number;
                trace_id: string | null;
                response_status: string | null;
            } | undefined;
            if (!row || row.end_to_end_id !== row.command_end_to_end_id ||
                row.amount !== row.amount_cents || row.from_ispb !== JACARANDA_ISPB ||
                response.type !== "pacs.002" ||
                (response.status !== "ACSC" && response.status !== "RJCT") ||
                response.end_to_end_id !== row.end_to_end_id ||
                response.from_ispb !== row.from_ispb || response.to_ispb !== row.to_ispb ||
                response.amount_cents !== row.amount_cents)
                throw new BankError("INTEGRITY_PIX_SPI_RESPONSE");
            if (row.status !== "in_processing") {
                if (row.response_status !== response.status)
                    throw new BankError("INTEGRITY_PIX_SPI_RESPONSE");
                return;
            }
            withTrace(row.trace_id ?? newId("trace", this.now().getTime()), () => {
                const current = this.db.prepare(`SELECT status FROM pix_transfers WHERE id=?`)
                    .get(row.id) as {
                    status: string;
                } | undefined;
                if (current?.status !== "in_processing")
                    return;
                const existing = this.db.prepare(`SELECT response_status FROM pix_spi_outbox
          WHERE transfer_id=?`).get(row.id) as {
                    response_status: string | null;
                } | undefined;
                if (!existing || existing.response_status !== null)
                    throw new BankError("INTEGRITY_PIX_SPI_RESPONSE");
                this.db.prepare(`UPDATE pix_spi_outbox SET response_status=?,response_reason=?,
          responded_at=?,responded_at_real=? WHERE transfer_id=? AND response_status IS NULL`)
                    .run(response.status, response.reason ?? null, this.now().toISOString(), this.realNow().toISOString(), row.id);
                const ts = this.now().toISOString();
                const hold = this.db.prepare(`UPDATE balance_holds SET released_at=?,release_actor='spi'
          WHERE kind='pix_cautelar' AND ref=? AND released_at IS NULL`)
                    .run(ts, row.id);
                if (hold.changes !== 1)
                    throw new BankError("INTEGRITY_PIX_RESERVATION");
                this.telemetry.emit({ source: "spi", category: "payment", action: "pacs.008",
                    outcome: "success", accountId: row.from_account, counterparty: row.to_account,
                    amountCents: row.amount, e2eId: row.end_to_end_id,
                    message: "Interbank Pix instruction sent" });
                this.telemetry.emit({ source: "spi", category: "payment", action: "pacs.002",
                    outcome: response.status === "ACSC" ? "success" : "failure",
                    accountId: row.from_account, counterparty: row.to_account,
                    amountCents: row.amount, e2eId: row.end_to_end_id,
                    message: "Interbank Pix response received" });
                this.db.prepare(`INSERT INTO pix_status_history (transfer_id,status,changed_at)
          VALUES (?,'sent_to_spi',?)`).run(row.id, ts);
                if (response.status === "RJCT") {
                    this.db.prepare("UPDATE pix_transfers SET status='rejected' WHERE id=?").run(row.id);
                    this.db.prepare(`INSERT INTO pix_status_history (transfer_id,status,changed_at)
            VALUES (?,'rejected',?)`).run(row.id, ts);
                    return;
                }
                const ledgerTxId = this.post([
                    { accountId: row.from_account, amount: -row.amount, kind: "pix", actor: row.actor,
                        refType: "pix", refId: row.id },
                    { accountId: this.systemAccountId("pix_settlement"), amount: row.amount,
                        kind: "pix", actor: row.actor, refType: "pix", refId: row.id },
                ]);
                this.db.prepare(`INSERT INTO pix_psp_inbound_outbox
          (transfer_id,end_to_end_id,to_account,amount_cents,from_account,settled_at,
            trace_id,created_at)
          VALUES (?,?,?,?,?,?,?,?)`).run(row.id, row.end_to_end_id, row.to_account, row.amount, row.from_account, ts, row.trace_id, ts);
                this.db.prepare(`UPDATE pix_transfers SET status='settled',settled_at=?,ledger_tx_id=?
          WHERE id=?`).run(ts, ledgerTxId, row.id);
                this.db.prepare(`INSERT INTO pix_status_history (transfer_id,status,changed_at)
          VALUES (?,'settled',?)`).run(row.id, ts);
                const from = this.account(row.from_account);
                this.telemetry.emit({ source: "pix", category: "payment", action: "settle",
                    outcome: "success", ...(from.customer_id ? { userId: from.customer_id } : {}),
                    accountId: row.from_account, counterparty: row.to_account, amountCents: row.amount,
                    e2eId: row.end_to_end_id, message: "External Pix transfer settled" });
            });
        });
    }
    placePspCautelar(accountId: string, transferId: string, amount: number, reason: string): PspCautelarHold {
        if (this.isSeparatedEcosystem)
            throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
        return this.transaction(() => {
            const transfer = this.db.prepare(`SELECT to_account,status FROM pix_transfers WHERE id=?`)
                .get(transferId) as {
                to_account: string;
                status: string;
            } | undefined;
            if (!transfer || transfer.to_account !== accountId || !this.spi.account(accountId) ||
                (transfer.status !== "settled" && transfer.status !== "returned_partial"))
                throw new BankError("BIZ_CAUTELAR_NOT_ELIGIBLE");
            const hold = this.psp.placeCautelar(accountId, transferId, amount, reason);
            this.telemetry.emit({ source: "pix", category: "cautelar", action: "hold",
                outcome: "success", accountId, amountCents: amount, message: "PSP credit held for review" });
            return hold;
        });
    }
    resolvePspCautelar(id: string, resolution: "release" | "return", actor: string): {
        hold: PspCautelarHold;
        returned?: PixReturnResult;
    } {
        if (this.isSeparatedEcosystem)
            throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(actor))
            throw new BankError("BIZ_CAUTELAR_ACTOR_REQUIRED");
        return this.transaction(() => {
            const hold = this.psp.cautelarHold(id);
            if (!hold)
                throw new BankError("DEF_NOT_FOUND");
            if (resolution !== "release" && resolution !== "return")
                throw new BankError("BIZ_CAUTELAR_RESOLUTION_INVALID");
            if (hold.status !== "active" || hold.expires_at <= this.now().toISOString())
                throw new BankError("BIZ_CAUTELAR_NOT_ACTIVE");
            const resolved = this.psp.resolveCautelar(id, resolution === "release" ? "released" : "returned", actor);
            const returned = resolution === "return" ? this.returnExternalPix(hold.root_transfer_id, hold.amount_cents, `cautelar:${id}`, "cautelar") : undefined;
            this.telemetry.emit({ source: "pix", category: "cautelar", action: resolution,
                outcome: "success", accountId: hold.account_id, amountCents: hold.amount_cents,
                message: `PSP credit review resolved by ${actor}` });
            return { hold: resolved, ...(returned ? { returned } : {}) };
        });
    }
    private recordClosedAccountCredit(sourceAccount: string, sourceKind: ClosedAccountCredit["source_kind"], sourceId: string, amount: number, ledgerTxId: string): void {
        const account = this.account(sourceAccount);
        if (account.status !== "closed" || !account.customer_id || amount <= 0)
            throw new BankError("INTEGRITY_CLOSED_CREDIT_SOURCE");
        this.db.prepare(`INSERT INTO closed_account_credits
      (id,customer_id,source_account,source_kind,source_id,amount_cents,status,
       ledger_tx_id,created_at) VALUES (?,?,?,?,?,?,'pending',?,?)`)
            .run(newId("credit", this.now().getTime()), account.customer_id, sourceAccount, sourceKind, sourceId, amount, ledgerTxId, this.now().toISOString());
    }
    closedAccountCredits(customerId: string, after = 0): {
        items: ClosedAccountCredit[];
        next_cursor: number | null;
    } {
        this.customer(customerId);
        if (!Number.isSafeInteger(after) || after < 0)
            throw new BankError("BIZ_INVALID_CURSOR");
        const rows = this.db.prepare(`SELECT rowid cursor,* FROM closed_account_credits
      WHERE customer_id=? AND status='pending' AND rowid>? ORDER BY rowid LIMIT 101`)
            .all(customerId, after) as unknown as (ClosedAccountCredit & {
            cursor: number;
        })[];
        const visible = rows.slice(0, 100);
        return { items: visible.map(({ cursor: _cursor, ...credit }) => credit),
            next_cursor: rows.length > 100 ? visible.at(-1)!.cursor : null };
    }
    closedCreditReconciliation(): {
        ok: boolean;
        pending_cents: number;
        suspense_cents: number;
        mismatches: number;
    } {
        const suspenseId = this.systemAccountId("suspense");
        const pending = this.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) cents
      FROM closed_account_credits WHERE status='pending'`).get() as {
            cents: number;
        };
        const mismatches = this.db.prepare(`SELECT COUNT(*) n FROM closed_account_credits c
      JOIN accounts source ON source.id=c.source_account
      LEFT JOIN accounts destination ON destination.id=c.destination_account
      WHERE source.customer_id<>c.customer_id OR source.status<>'closed' OR
        (SELECT COALESCE(SUM(amount),0) FROM ledger_entries
         WHERE tx_id=c.ledger_tx_id AND account_id=?)<>c.amount_cents OR
        (c.status='paid' AND (destination.id IS NULL OR destination.customer_id<>c.customer_id OR
          (SELECT COALESCE(SUM(amount),0) FROM ledger_entries
           WHERE tx_id=c.payout_tx_id AND account_id=?)<>-c.amount_cents OR
          (SELECT COALESCE(SUM(amount),0) FROM ledger_entries
           WHERE tx_id=c.payout_tx_id AND account_id=c.destination_account)<>c.amount_cents))`)
            .get(suspenseId, suspenseId) as {
            n: number;
        };
        const suspense = this.account(suspenseId).balance_cached;
        return { ok: pending.cents === suspense && mismatches.n === 0,
            pending_cents: pending.cents, suspense_cents: suspense,
            mismatches: mismatches.n };
    }
    claimClosedAccountCredit(customerId: string, creditId: string, destinationAccountId: string): ClosedAccountCredit {
        return this.transaction(() => {
            const credit = this.db.prepare(`SELECT * FROM closed_account_credits
        WHERE id=? AND customer_id=?`).get(creditId, customerId) as ClosedAccountCredit | undefined;
            if (!credit)
                throw new BankError("DEF_NOT_FOUND");
            if (credit.status === "paid") {
                if (credit.destination_account !== destinationAccountId)
                    throw new BankError("BIZ_CLOSED_CREDIT_ALREADY_PAID");
                return credit;
            }
            const destination = this.ownAccount(customerId, destinationAccountId);
            if (destination.status !== "active" || this.customer(customerId).status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            if (destination.kind === "salary")
                throw new BankError("DEF_SALARY_ACCOUNT_RESTRICTED");
            if (!this.closedCreditReconciliation().ok)
                throw new BankError("INTEGRITY_CLOSED_CREDIT_DRIFT");
            const payoutTxId = this.post([
                { accountId: this.systemAccountId("suspense"), amount: -credit.amount_cents,
                    kind: "closed_credit_payout", actor: customerId,
                    refType: "closed_credit", refId: credit.id },
                { accountId: destinationAccountId, amount: credit.amount_cents,
                    kind: "closed_credit_payout", actor: customerId,
                    refType: "closed_credit", refId: credit.id },
            ]);
            this.db.prepare(`UPDATE closed_account_credits SET status='paid',destination_account=?,
        payout_tx_id=?,paid_at=? WHERE id=? AND status='pending'`)
                .run(destinationAccountId, payoutTxId, this.now().toISOString(), creditId);
            if (!this.closedCreditReconciliation().ok)
                throw new BankError("INTEGRITY_CLOSED_CREDIT_DRIFT");
            this.telemetry.emit({ source: "ledger", category: "account", action: "closed_credit_payout",
                outcome: "success", userId: customerId, accountId: destinationAccountId,
                amountCents: credit.amount_cents, message: "Closed-account credit paid to active account" });
            return this.db.prepare("SELECT * FROM closed_account_credits WHERE id=?")
                .get(creditId) as unknown as ClosedAccountCredit;
        });
    }
    requestExternalPixReturn(transferId: string, amount: number, idempotencyKey: string): ExternalPixReturnIntent {
        if (!this.separatedEcosystem)
            throw new BankError("ECOSYSTEM_MODE_INVALID");
        if (!Number.isSafeInteger(amount) || amount <= 0)
            throw new BankError("BIZ_INVALID_AMOUNT");
        if (!idempotencyKey || idempotencyKey.length > 128)
            throw new BankError("BIZ_IDEMPOTENCY_REQUIRED");
        return this.transaction(() => {
            const transfer = this.db.prepare(`SELECT id,end_to_end_id,to_account,amount,status
        FROM pix_transfers WHERE id=?`).get(transferId) as {
                id: string;
                end_to_end_id: string;
                to_account: string;
                amount: number;
                status: string;
            } | undefined;
            if (!transfer)
                throw new BankError("DEF_NOT_FOUND");
            if (this.db.prepare("SELECT 1 FROM accounts WHERE id=?").get(transfer.to_account))
                throw new BankError("BIZ_RETURN_NOT_EXTERNAL");
            const existing = this.db.prepare(`SELECT o.id,o.transfer_id,o.amount_cents amount,
        CASE WHEN o.rejected_at IS NOT NULL THEN 'failed'
          WHEN o.acknowledged_at IS NULL THEN 'pending_psp' ELSE r.status END status,
        r.ledger_tx_id,o.failure_reason
        FROM pix_psp_return_outbox o LEFT JOIN pix_returns r ON r.id=o.id
        WHERE o.transfer_id=? AND o.idempotency_key=?`)
                .get(transferId, idempotencyKey) as ExternalPixReturnIntent | undefined;
            if (existing) {
                if (existing.amount !== amount)
                    throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
                return existing;
            }
            if (this.db.prepare(`SELECT 1 FROM med_cases WHERE transfer_id=?
        AND status<>'rejected' LIMIT 1`).get(transferId))
                throw new BankError("BIZ_RETURN_MED_ACTIVE");
            if (!["settled", "returned_partial"].includes(transfer.status))
                throw new BankError("BIZ_RETURN_NOT_SETTLED");
            if (this.db.prepare(`SELECT 1 FROM pix_psp_return_outbox
        WHERE transfer_id=? AND acknowledged_at IS NULL AND rejected_at IS NULL`)
                .get(transferId))
                throw new BankError("BIZ_RETURN_PENDING");
            if (this.db.prepare(`SELECT 1 FROM pix_psp_cautelar_return_outbox
        WHERE transfer_id=? AND acknowledged_at IS NULL AND rejected_at IS NULL`)
                .get(transferId))
                throw new BankError("BIZ_RETURN_PENDING");
            const returned = (this.db.prepare(`SELECT COALESCE(SUM(amount),0) n
        FROM pix_returns WHERE transfer_id=?`).get(transferId) as {
                n: number;
            }).n;
            if (returned + amount > transfer.amount)
                throw new BankError("BIZ_RETURN_EXCEEDS_PAYMENT");
            const id = newId("return", this.now().getTime());
            this.db.prepare(`INSERT INTO pix_psp_return_outbox
        (id,transfer_id,end_to_end_id,recipient_account,idempotency_key,
          amount_cents,reason,created_at) VALUES (?,?,?,?,?,?,'ordinary',?)`)
                .run(id, transferId, transfer.end_to_end_id, transfer.to_account, idempotencyKey, amount, this.now().toISOString());
            return { id, transfer_id: transferId, amount, status: "pending_psp",
                ledger_tx_id: null, failure_reason: null };
        });
    }
    pendingExternalPixReturns(limit = 100): {
        id: string;
        transfer_id: string;
        end_to_end_id: string;
        recipient_account: string;
        amount_cents: number;
        reason: "ordinary";
        created_at: string;
    }[] {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
            throw new BankError("BIZ_INVALID_LIMIT");
        const commands = this.db.prepare(`SELECT o.id,o.transfer_id,o.end_to_end_id,
      o.recipient_account,o.amount_cents,o.reason,o.created_at,
      p.end_to_end_id payment_e2e,p.to_account,p.status payment_status
      FROM pix_psp_return_outbox o
      LEFT JOIN pix_transfers p ON p.id=o.transfer_id
      WHERE o.acknowledged_at IS NULL AND o.rejected_at IS NULL
      ORDER BY o.created_at,o.id LIMIT ?`).all(limit) as {
            id: string;
            transfer_id: string;
            end_to_end_id: string;
            recipient_account: string;
            amount_cents: number;
            reason: "ordinary";
            created_at: string;
            payment_e2e: string;
            to_account: string;
            payment_status: string;
        }[];
        return commands.map(({ payment_e2e, to_account, payment_status, ...command }) => {
            if (payment_e2e !== command.end_to_end_id ||
                to_account !== command.recipient_account ||
                !["settled", "returned_partial"].includes(payment_status) ||
                this.db.prepare("SELECT 1 FROM accounts WHERE id=?")
                    .get(command.recipient_account) ||
                this.db.prepare(`SELECT 1 FROM med_cases WHERE transfer_id=?
          AND status<>'rejected'`).get(command.transfer_id))
                throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
            return command;
        });
    }
    requestExternalCautelarReturn(hold: PspCautelarHold, actor: string): ExternalPixReturnIntent {
        if (!this.separatedEcosystem)
            throw new BankError("ECOSYSTEM_MODE_INVALID");
        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(actor))
            throw new BankError("BIZ_CAUTELAR_ACTOR_REQUIRED");
        return this.transaction(() => {
            const existing = this.db.prepare(`SELECT o.id,o.transfer_id,o.amount_cents amount,
        CASE WHEN o.rejected_at IS NOT NULL THEN 'failed'
          WHEN o.acknowledged_at IS NULL THEN 'pending_psp' ELSE r.status END status,
        r.ledger_tx_id,r.reason return_reason,o.failure_reason,o.actor,
        o.recipient_account,o.acknowledged_at,o.rejected_at
        FROM pix_psp_cautelar_return_outbox o
        LEFT JOIN pix_returns r ON r.id=o.id WHERE o.hold_id=?`)
                .get(hold.id) as (ExternalPixReturnIntent & {
                actor: string;
                recipient_account: string;
                return_reason: string | null;
                acknowledged_at: string | null;
                rejected_at: string | null;
            }) | undefined;
            if (existing) {
                if (existing.actor !== actor || existing.transfer_id !== hold.root_transfer_id ||
                    existing.recipient_account !== hold.account_id ||
                    existing.amount !== hold.amount_cents)
                    throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
                if (existing.acknowledged_at ?
                    !existing.ledger_tx_id || existing.return_reason !== "cautelar" ||
                        !["returned_partial", "returned_full"].includes(existing.status) :
                    Boolean(existing.ledger_tx_id || existing.return_reason))
                    throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
                return { id: existing.id, transfer_id: existing.transfer_id,
                    amount: existing.amount, status: existing.status,
                    ledger_tx_id: existing.ledger_tx_id,
                    failure_reason: existing.failure_reason };
            }
            if (hold.status !== "active" || hold.expires_at <= this.now().toISOString())
                throw new BankError("BIZ_CAUTELAR_NOT_ACTIVE");
            const transfer = this.db.prepare(`SELECT id,end_to_end_id,to_account,amount,status
        FROM pix_transfers WHERE id=?`).get(hold.root_transfer_id) as {
                id: string;
                end_to_end_id: string;
                to_account: string;
                amount: number;
                status: string;
            } | undefined;
            if (!transfer || transfer.to_account !== hold.account_id ||
                this.db.prepare("SELECT 1 FROM accounts WHERE id=?")
                    .get(hold.account_id))
                throw new BankError("BIZ_CAUTELAR_NOT_ELIGIBLE");
            if (!["settled", "returned_partial"].includes(transfer.status))
                throw new BankError("BIZ_RETURN_NOT_SETTLED");
            if (this.db.prepare(`SELECT 1 FROM med_cases WHERE transfer_id=?
        AND status<>'rejected'`).get(transfer.id))
                throw new BankError("BIZ_RETURN_MED_ACTIVE");
            if (this.db.prepare(`SELECT 1 FROM pix_psp_return_outbox
        WHERE transfer_id=? AND acknowledged_at IS NULL AND rejected_at IS NULL`)
                .get(transfer.id) || this.db.prepare(`SELECT 1 FROM pix_psp_cautelar_return_outbox
        WHERE transfer_id=? AND acknowledged_at IS NULL AND rejected_at IS NULL`)
                .get(transfer.id))
                throw new BankError("BIZ_RETURN_PENDING");
            const returned = (this.db.prepare(`SELECT COALESCE(SUM(amount),0) n
        FROM pix_returns WHERE transfer_id=?`).get(transfer.id) as {
                n: number;
            }).n;
            if (returned + hold.amount_cents > transfer.amount)
                throw new BankError("BIZ_RETURN_EXCEEDS_PAYMENT");
            const id = newId("return", this.now().getTime());
            this.db.prepare(`INSERT INTO pix_psp_cautelar_return_outbox
        (id,hold_id,transfer_id,end_to_end_id,recipient_account,amount_cents,
          actor,created_at) VALUES (?,?,?,?,?,?,?,?)`)
                .run(id, hold.id, transfer.id, transfer.end_to_end_id, hold.account_id, hold.amount_cents, actor, this.now().toISOString());
            return { id, transfer_id: transfer.id, amount: hold.amount_cents,
                status: "pending_psp", ledger_tx_id: null, failure_reason: null };
        });
    }
    pendingExternalCautelarReturns(limit = 100): {
        id: string;
        hold_id: string;
        transfer_id: string;
        end_to_end_id: string;
        recipient_account: string;
        amount_cents: number;
        actor: string;
        created_at: string;
    }[] {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
            throw new BankError("BIZ_INVALID_LIMIT");
        const commands = this.db.prepare(`SELECT o.id,o.hold_id,o.transfer_id,
      o.end_to_end_id,o.recipient_account,o.amount_cents,o.actor,o.created_at,
      p.end_to_end_id payment_e2e,p.to_account,p.status payment_status
      FROM pix_psp_cautelar_return_outbox o
      LEFT JOIN pix_transfers p ON p.id=o.transfer_id
      WHERE o.acknowledged_at IS NULL AND o.rejected_at IS NULL
      ORDER BY o.created_at,o.id LIMIT ?`).all(limit) as {
            id: string;
            hold_id: string;
            transfer_id: string;
            end_to_end_id: string;
            recipient_account: string;
            amount_cents: number;
            actor: string;
            created_at: string;
            payment_e2e: string;
            to_account: string;
            payment_status: string;
        }[];
        return commands.map(({ payment_e2e, to_account, payment_status, ...command }) => {
            if (payment_e2e !== command.end_to_end_id ||
                to_account !== command.recipient_account ||
                !["settled", "returned_partial"].includes(payment_status) ||
                this.db.prepare("SELECT 1 FROM accounts WHERE id=?")
                    .get(command.recipient_account) ||
                this.db.prepare(`SELECT 1 FROM med_cases WHERE transfer_id=?
          AND status<>'rejected'`).get(command.transfer_id))
                throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
            return command;
        });
    }
    private postSeparatedExternalReturn(input: {
        id: string;
        transferId: string;
        endToEndId: string;
        fromAccount: string;
        toAccount: string;
        amount: number;
        paymentAmount: number;
        idempotencyKey: string;
        reason: "ordinary" | "cautelar";
        createdAt: string;
        fromIspb: string;
    }): PixReturnResult {
        const returned = (this.db.prepare(`SELECT COALESCE(SUM(amount),0) n
      FROM pix_returns WHERE transfer_id=?`).get(input.transferId) as {
            n: number;
        }).n;
        if (returned + input.amount > input.paymentAmount)
            throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
        const compensationTable = this.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='blue_external_compensations'`).get();
        const bankAlreadyCompensated = compensationTable && this.db.prepare(`SELECT 1
      FROM blue_external_compensations WHERE transfer_id=?`).get(input.transferId);
        const closedSource = !bankAlreadyCompensated &&
            this.account(input.fromAccount).status === "closed";
        const ledgerTxId = this.post([
            { accountId: this.systemAccountId("pix_settlement"),
                amount: -input.amount, kind: "pix_return", actor: input.fromIspb,
                refType: "pix", refId: input.transferId },
            { accountId: bankAlreadyCompensated ? this.systemAccountId("bank_loss") :
                    closedSource ? this.systemAccountId("suspense") : input.fromAccount,
                amount: input.amount, kind: bankAlreadyCompensated ?
                    "pix_return_bank_recovery" : "pix_return", actor: input.fromIspb,
                refType: "pix", refId: input.transferId },
        ]);
        const status = returned + input.amount === input.paymentAmount ?
            "returned_full" : "returned_partial";
        this.db.prepare(`INSERT INTO pix_returns
      (id,transfer_id,idempotency_key,amount,reason,status,ledger_tx_id,created_at)
      VALUES (?,?,?,?,?,?,?,?)`).run(input.id, input.transferId, input.idempotencyKey, input.amount, input.reason, status, ledgerTxId, input.createdAt);
        if (closedSource)
            this.recordClosedAccountCredit(input.fromAccount, "pix_return", input.id, input.amount, ledgerTxId);
        this.db.prepare("UPDATE pix_transfers SET status=? WHERE id=?")
            .run(status, input.transferId);
        this.db.prepare(`INSERT INTO pix_status_history
      (transfer_id,status,changed_at,reason) VALUES (?,?,?,?)`)
            .run(input.transferId, status, input.createdAt, `${input.reason}_return`);
        this.telemetry.emit({ source: "pix", category: "payment", action: "return",
            outcome: "success", accountId: input.fromAccount,
            counterparty: input.toAccount, amountCents: input.amount,
            e2eId: input.endToEndId, message: "External Pix returned" });
        return { id: input.id, transfer_id: input.transferId,
            amount: input.amount, status, ledger_tx_id: ledgerTxId };
    }
    applyExternalPixReturn(returnId: string, result: {
        outcome: "accepted" | "rejected";
        failureReason: string | null;
        fromIspb: string;
    }): ExternalPixReturnIntent {
        return this.transaction(() => {
            const row = this.db.prepare(`SELECT o.id,o.transfer_id,o.end_to_end_id,
        o.recipient_account,o.idempotency_key,o.amount_cents,o.reason,
        o.created_at,o.acknowledged_at,o.rejected_at,o.failure_reason,
        p.from_account,p.to_account,p.end_to_end_id payment_e2e,
        p.amount payment_amount,p.status payment_status
        FROM pix_psp_return_outbox o JOIN pix_transfers p ON p.id=o.transfer_id
        WHERE o.id=?`).get(returnId) as {
                id: string;
                transfer_id: string;
                end_to_end_id: string;
                recipient_account: string;
                idempotency_key: string;
                amount_cents: number;
                reason: string;
                created_at: string;
                acknowledged_at: string | null;
                rejected_at: string | null;
                failure_reason: string | null;
                from_account: string;
                to_account: string;
                payment_e2e: string;
                payment_amount: number;
                payment_status: string;
            } | undefined;
            if (!row || row.recipient_account !== row.to_account ||
                row.end_to_end_id !== row.payment_e2e || row.reason !== "ordinary" ||
                !/^\d{8}$/.test(result.fromIspb) || result.fromIspb === JACARANDA_ISPB)
                throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
            if (row.acknowledged_at) {
                const settled = this.db.prepare(`SELECT id,transfer_id,amount,status,
          ledger_tx_id FROM pix_returns WHERE id=?`).get(returnId) as PixReturnResult | undefined;
                if (!settled || result.outcome !== "accepted" || result.failureReason !== null)
                    throw new BankError("INTEGRITY_PIX_RETURN_REPLY");
                return { ...settled, failure_reason: null };
            }
            if (row.rejected_at) {
                if (result.outcome !== "rejected" ||
                    result.failureReason !== row.failure_reason)
                    throw new BankError("INTEGRITY_PIX_RETURN_REPLY");
                return { id: row.id, transfer_id: row.transfer_id,
                    amount: row.amount_cents, status: "failed", ledger_tx_id: null,
                    failure_reason: row.failure_reason };
            }
            if (!["settled", "returned_partial"].includes(row.payment_status) ||
                this.db.prepare(`SELECT 1 FROM med_cases WHERE transfer_id=?
          AND status<>'rejected'`).get(row.transfer_id))
                throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
            const returned = (this.db.prepare(`SELECT COALESCE(SUM(amount),0) n
        FROM pix_returns WHERE transfer_id=?`).get(row.transfer_id) as {
                n: number;
            }).n;
            if (returned + row.amount_cents > row.payment_amount)
                throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
            if (result.outcome === "rejected") {
                if (!result.failureReason || !["PSP_FUNDS_UNAVAILABLE",
                    "SPI_INSUFFICIENT_LIQUIDITY"].includes(result.failureReason))
                    throw new BankError("INTEGRITY_PIX_RETURN_REPLY");
                this.db.prepare(`UPDATE pix_psp_return_outbox SET rejected_at=?,
          failure_reason=? WHERE id=? AND rejected_at IS NULL`)
                    .run(this.now().toISOString(), result.failureReason, returnId);
                return { id: row.id, transfer_id: row.transfer_id,
                    amount: row.amount_cents, status: "failed", ledger_tx_id: null,
                    failure_reason: result.failureReason };
            }
            if (result.outcome !== "accepted" || result.failureReason !== null)
                throw new BankError("INTEGRITY_PIX_RETURN_REPLY");
            const settled = this.postSeparatedExternalReturn({ id: row.id,
                transferId: row.transfer_id, endToEndId: row.end_to_end_id,
                fromAccount: row.from_account, toAccount: row.to_account,
                amount: row.amount_cents, paymentAmount: row.payment_amount,
                idempotencyKey: row.idempotency_key, reason: "ordinary",
                createdAt: row.created_at, fromIspb: result.fromIspb });
            this.db.prepare(`UPDATE pix_psp_return_outbox SET acknowledged_at=?
        WHERE id=? AND acknowledged_at IS NULL`).run(this.now().toISOString(), row.id);
            return { ...settled, failure_reason: null };
        });
    }
    applyExternalCautelarReturn(returnId: string, result: {
        outcome: "accepted" | "rejected";
        failureReason: string | null;
        fromIspb: string;
    }): ExternalPixReturnIntent {
        return this.transaction(() => {
            const row = this.db.prepare(`SELECT o.id,o.hold_id,o.transfer_id,
        o.end_to_end_id,o.recipient_account,o.amount_cents,o.actor,o.created_at,
        o.acknowledged_at,o.rejected_at,o.failure_reason,
        p.from_account,p.to_account,p.end_to_end_id payment_e2e,
        p.amount payment_amount,p.status payment_status
        FROM pix_psp_cautelar_return_outbox o
        JOIN pix_transfers p ON p.id=o.transfer_id WHERE o.id=?`)
                .get(returnId) as {
                id: string;
                hold_id: string;
                transfer_id: string;
                end_to_end_id: string;
                recipient_account: string;
                amount_cents: number;
                actor: string;
                created_at: string;
                acknowledged_at: string | null;
                rejected_at: string | null;
                failure_reason: string | null;
                from_account: string;
                to_account: string;
                payment_e2e: string;
                payment_amount: number;
                payment_status: string;
            } | undefined;
            if (!row || row.recipient_account !== row.to_account ||
                row.end_to_end_id !== row.payment_e2e ||
                !/^\d{8}$/.test(result.fromIspb) || result.fromIspb === JACARANDA_ISPB)
                throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
            if (row.acknowledged_at) {
                const settled = this.db.prepare(`SELECT id,transfer_id,amount,status,
          ledger_tx_id FROM pix_returns WHERE id=? AND reason='cautelar'`)
                    .get(returnId) as PixReturnResult | undefined;
                if (!settled || result.outcome !== "accepted" || result.failureReason !== null)
                    throw new BankError("INTEGRITY_PIX_RETURN_REPLY");
                return { ...settled, failure_reason: null };
            }
            if (row.rejected_at) {
                if (result.outcome !== "rejected" ||
                    result.failureReason !== row.failure_reason)
                    throw new BankError("INTEGRITY_PIX_RETURN_REPLY");
                return { id: row.id, transfer_id: row.transfer_id,
                    amount: row.amount_cents, status: "failed", ledger_tx_id: null,
                    failure_reason: row.failure_reason };
            }
            if (!["settled", "returned_partial"].includes(row.payment_status) ||
                this.db.prepare(`SELECT 1 FROM med_cases WHERE transfer_id=?
          AND status<>'rejected'`).get(row.transfer_id))
                throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
            if (result.outcome === "rejected") {
                if (result.failureReason !== "PSP_CAUTELAR_NOT_ACTIVE")
                    throw new BankError("INTEGRITY_PIX_RETURN_REPLY");
                this.db.prepare(`UPDATE pix_psp_cautelar_return_outbox
          SET rejected_at=?,failure_reason=? WHERE id=? AND rejected_at IS NULL`)
                    .run(this.now().toISOString(), result.failureReason, returnId);
                return { id: row.id, transfer_id: row.transfer_id,
                    amount: row.amount_cents, status: "failed", ledger_tx_id: null,
                    failure_reason: result.failureReason };
            }
            if (result.outcome !== "accepted" || result.failureReason !== null)
                throw new BankError("INTEGRITY_PIX_RETURN_REPLY");
            const settled = this.postSeparatedExternalReturn({ id: row.id,
                transferId: row.transfer_id, endToEndId: row.end_to_end_id,
                fromAccount: row.from_account, toAccount: row.to_account,
                amount: row.amount_cents, paymentAmount: row.payment_amount,
                idempotencyKey: `cautelar:${row.hold_id}`, reason: "cautelar",
                createdAt: row.created_at, fromIspb: result.fromIspb });
            this.db.prepare(`UPDATE pix_psp_cautelar_return_outbox
        SET acknowledged_at=? WHERE id=? AND acknowledged_at IS NULL`)
                .run(this.now().toISOString(), returnId);
            this.telemetry.emit({ source: "pix", category: "cautelar", action: "return",
                outcome: "success", accountId: row.recipient_account,
                amountCents: row.amount_cents,
                message: `PSP credit review resolved by ${row.actor}` });
            return { ...settled, failure_reason: null };
        });
    }
    returnExternalPix(transferId: string, amount: number, idempotencyKey: string, reason: "ordinary" | "cautelar" = "ordinary"): PixReturnResult {
        if (this.separatedEcosystem)
            throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
        if (!Number.isSafeInteger(amount) || amount <= 0)
            throw new BankError("BIZ_INVALID_AMOUNT");
        if (!idempotencyKey || idempotencyKey.length > 128)
            throw new BankError("BIZ_IDEMPOTENCY_REQUIRED");
        return this.transaction(() => {
            const transfer = this.db.prepare(`SELECT id,end_to_end_id,from_account,to_account,amount,status
        FROM pix_transfers WHERE id=?`).get(transferId) as {
                id: string;
                end_to_end_id: string;
                from_account: string;
                to_account: string;
                amount: number;
                status: string;
            } | undefined;
            if (!transfer)
                throw new BankError("DEF_NOT_FOUND");
            const external = this.spi.account(transfer.to_account);
            if (!external)
                throw new BankError("BIZ_RETURN_NOT_EXTERNAL");
            const existing = this.db.prepare(`SELECT id,transfer_id,amount,status,ledger_tx_id
        FROM pix_returns WHERE transfer_id=? AND idempotency_key=?`)
                .get(transferId, idempotencyKey) as PixReturnResult | undefined;
            if (existing) {
                if (existing.amount !== amount)
                    throw new BankError("BIZ_IDEMPOTENCY_CONFLICT");
                return existing;
            }
            if (this.db.prepare(`SELECT 1 FROM med_cases WHERE transfer_id=?
        AND status<>'rejected' LIMIT 1`).get(transferId))
                throw new BankError("BIZ_RETURN_MED_ACTIVE");
            if (transfer.status !== "settled" && transfer.status !== "returned_partial")
                throw new BankError("BIZ_RETURN_NOT_SETTLED");
            const returned = (this.db.prepare("SELECT COALESCE(SUM(amount),0) n FROM pix_returns WHERE transfer_id=?")
                .get(transferId) as {
                n: number;
            }).n;
            if (returned + amount > transfer.amount)
                throw new BankError("BIZ_RETURN_EXCEEDS_PAYMENT");
            if (external.balance_cents < amount)
                throw new BankError("BIZ_PSP_INSUFFICIENT_FUNDS");
            if (this.psp.availableRoot(external.id, transferId) < amount)
                throw new BankError("BIZ_PSP_FUNDS_UNAVAILABLE");
            const id = newId("return", this.now().getTime());
            try {
                this.spi.returnPayment(transfer.end_to_end_id, id, external.ispb, JACARANDA_ISPB, amount, reason);
            }
            catch (error) {
                if (error instanceof Error && error.message === "SPI_UNAVAILABLE")
                    throw new BankError("BIZ_SPI_UNAVAILABLE");
                if (error instanceof Error && error.message === "SPI_INSUFFICIENT_LIQUIDITY")
                    throw new BankError("BIZ_SPI_INSUFFICIENT_LIQUIDITY");
                throw error;
            }
            this.psp.debitAccountRoot(external.id, transferId, amount);
            const compensationTable = this.db.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='blue_external_compensations'`).get();
            const bankAlreadyCompensated = compensationTable && this.db.prepare(`SELECT 1
        FROM blue_external_compensations WHERE transfer_id=?`).get(transferId);
            const closedSource = !bankAlreadyCompensated &&
                this.account(transfer.from_account).status === "closed";
            const ledgerTxId = this.post([
                { accountId: this.systemAccountId("pix_settlement"), amount: -amount,
                    kind: "pix_return", actor: external.ispb, refType: "pix", refId: transferId },
                { accountId: bankAlreadyCompensated ? this.systemAccountId("bank_loss") :
                        closedSource ? this.systemAccountId("suspense") : transfer.from_account,
                    amount, kind: bankAlreadyCompensated ?
                        "pix_return_bank_recovery" : "pix_return",
                    actor: external.ispb, refType: "pix", refId: transferId },
            ]);
            const status = returned + amount === transfer.amount ? "returned_full" : "returned_partial";
            const ts = this.now().toISOString();
            this.db.prepare(`INSERT INTO pix_returns
        (id,transfer_id,idempotency_key,amount,reason,status,ledger_tx_id,created_at)
        VALUES (?,?,?,?,?,?,?,?)`).run(id, transferId, idempotencyKey, amount, reason, status, ledgerTxId, ts);
            if (closedSource)
                this.recordClosedAccountCredit(transfer.from_account, "pix_return", id, amount, ledgerTxId);
            this.db.prepare("UPDATE pix_transfers SET status=? WHERE id=?").run(status, transferId);
            this.db.prepare(`INSERT INTO pix_status_history
        (transfer_id,status,changed_at,reason) VALUES (?,?,?,?)`)
                .run(transferId, status, ts, `${reason}_return`);
            this.telemetry.emit({ source: "pix", category: "payment", action: "return",
                outcome: "success", accountId: transfer.from_account, counterparty: transfer.to_account,
                amountCents: amount, e2eId: transfer.end_to_end_id,
                message: "External Pix returned" });
            return { id, transfer_id: transferId, amount, status, ledger_tx_id: ledgerTxId };
        });
    }
    requestExternalMed(customerId: string, transferId: string): {
        id: string;
        status: string;
        refunded_cents: number;
    } {
        if (!this.separatedEcosystem)
            throw new BankError("ECOSYSTEM_MODE_INVALID");
        return this.transaction(() => {
            const transfer = this.db.prepare(`SELECT from_account,to_account,amount,status,initiated_at
        FROM pix_transfers WHERE id=?`).get(transferId) as {
                from_account: string;
                to_account: string;
                amount: number;
                status: string;
                initiated_at: string;
            } | undefined;
            if (!transfer || this.account(transfer.from_account).customer_id !== customerId)
                throw new BankError("DEF_NOT_FOUND");
            if (this.db.prepare("SELECT 1 FROM accounts WHERE id=?").get(transfer.to_account))
                throw new BankError("BIZ_MED_EXTERNAL_REQUIRED");
            if (this.db.prepare(`SELECT 1 FROM pix_psp_return_outbox WHERE transfer_id=?
        AND acknowledged_at IS NULL AND rejected_at IS NULL`).get(transferId))
                throw new BankError("BIZ_RETURN_PENDING");
            if (this.db.prepare(`SELECT 1 FROM pix_psp_cautelar_return_outbox
        WHERE transfer_id=? AND acknowledged_at IS NULL AND rejected_at IS NULL`)
                .get(transferId))
                throw new BankError("BIZ_RETURN_PENDING");
            const transferAgeMs = this.now().getTime() - Date.parse(transfer.initiated_at);
            if (!Number.isFinite(transferAgeMs) || transferAgeMs < 0 ||
                transferAgeMs > 80 * 86400000)
                throw new BankError("BIZ_MED_EXPIRED");
            const existing = this.db.prepare(`SELECT id,status,refunded_cents FROM med_cases
        WHERE transfer_id=?`).get(transferId) as {
                id: string;
                status: string;
                refunded_cents: number;
            } | undefined;
            if (existing)
                return existing;
            if (!["settled", "returned_partial"].includes(transfer.status))
                throw new BankError("BIZ_MED_NOT_SETTLED");
            const ordinaryReturned = (this.db.prepare(`SELECT COALESCE(SUM(amount),0) n
        FROM pix_returns WHERE transfer_id=?`).get(transferId) as {
                n: number;
            }).n;
            const claimAmount = transfer.amount - ordinaryReturned;
            if (claimAmount <= 0)
                throw new BankError("BIZ_MED_NOT_SETTLED");
            const id = newId("med", this.now().getTime());
            const openedAt = this.now().toISOString();
            const resolveAfter = new Date(this.now().getTime() + 7 * 86400000).toISOString();
            this.db.prepare(`INSERT INTO med_cases
        (id,transfer_id,customer_id,status,opened_at,resolve_after,claim_amount_cents)
        VALUES (?,?,?,'opening',?,?,?)`)
                .run(id, transferId, customerId, openedAt, resolveAfter, claimAmount);
            this.db.prepare(`INSERT INTO med_psp_open_outbox
        (case_id,transfer_id,claim_amount_cents,created_at) VALUES (?,?,?,?)`)
                .run(id, transferId, claimAmount, openedAt);
            return { id, status: "opening", refunded_cents: 0 };
        });
    }
    pendingExternalMedOpenings(limit = 100): {
        case_id: string;
        transfer_id: string;
        claim_amount_cents: number;
        created_at: string;
    }[] {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
            throw new BankError("BIZ_INVALID_LIMIT");
        const commands = this.db.prepare(`SELECT o.case_id,o.transfer_id,
      o.claim_amount_cents,o.created_at,m.status case_status,
      m.transfer_id case_transfer,m.claim_amount_cents case_claim,
      m.opened_at case_opened,p.amount payment_amount,
      p.status payment_status,p.to_account,
      (SELECT COALESCE(SUM(amount),0) FROM pix_returns
        WHERE transfer_id=o.transfer_id) returned_cents
      FROM med_psp_open_outbox o LEFT JOIN med_cases m ON m.id=o.case_id
      LEFT JOIN pix_transfers p ON p.id=o.transfer_id
      WHERE o.acknowledged_at IS NULL
      ORDER BY o.created_at,o.case_id LIMIT ?`).all(limit) as {
            case_id: string;
            transfer_id: string;
            claim_amount_cents: number;
            created_at: string;
            case_status: string;
            case_transfer: string;
            case_claim: number;
            case_opened: string;
            payment_amount: number;
            payment_status: string;
            to_account: string;
            returned_cents: number;
        }[];
        return commands.map(({ case_status, case_transfer, case_claim, case_opened, payment_amount, payment_status, to_account, returned_cents, ...command }) => {
            if (case_status !== "opening" || case_transfer !== command.transfer_id ||
                case_claim !== command.claim_amount_cents || case_opened !== command.created_at ||
                !["settled", "returned_partial"].includes(payment_status) ||
                payment_amount - returned_cents !== command.claim_amount_cents ||
                this.db.prepare("SELECT 1 FROM accounts WHERE id=?").get(to_account))
                throw new BankError("INTEGRITY_MED_OPEN_COMMAND");
            return command;
        });
    }
    applyExternalMedOpening(caseId: string, hops: {
        id: string;
        case_id: string;
        root_transfer_id: string;
        account_id: string;
        blocked_cents: number;
        refunded_cents: number;
        created_at: string;
        released_at: string | null;
    }[]): void {
        this.transaction(() => {
            const command = this.db.prepare(`SELECT o.transfer_id,o.claim_amount_cents,
        o.created_at command_created_at,o.acknowledged_at,m.status,
        m.claim_amount_cents case_claim FROM med_psp_open_outbox o
        JOIN med_cases m ON m.id=o.case_id WHERE o.case_id=?`).get(caseId) as {
                transfer_id: string;
                claim_amount_cents: number;
                status: string;
                acknowledged_at: string | null;
                command_created_at: string;
                case_claim: number;
            } | undefined;
            if (!command || command.claim_amount_cents !== command.case_claim)
                throw new BankError("INTEGRITY_MED_OPEN_COMMAND");
            if (command.status === "open" && command.acknowledged_at)
                return;
            if (command.status !== "opening")
                throw new BankError("INTEGRITY_MED_OPEN_COMMAND");
            const accounts = new Set<string>();
            let blocked = 0;
            for (const hop of hops) {
                if (!hop.id || hop.case_id !== caseId ||
                    hop.root_transfer_id !== command.transfer_id ||
                    !hop.account_id || !Number.isSafeInteger(hop.blocked_cents) ||
                    hop.blocked_cents <= 0 || hop.refunded_cents !== 0 ||
                    hop.released_at !== null ||
                    hop.created_at !== command.command_created_at ||
                    accounts.has(hop.account_id))
                    throw new BankError("INTEGRITY_MED_OPEN_REPLY");
                accounts.add(hop.account_id);
                blocked += hop.blocked_cents;
                this.db.prepare(`INSERT INTO med_hops
          (id,case_id,root_transfer_id,account_id,blocked_cents,created_at)
          VALUES (?,?,?,?,?,?)`).run(hop.id, caseId, command.transfer_id, hop.account_id, hop.blocked_cents, hop.created_at);
            }
            if (blocked > command.claim_amount_cents)
                throw new BankError("INTEGRITY_MED_OPEN_REPLY");
            this.db.prepare("UPDATE med_cases SET status='open' WHERE id=?").run(caseId);
            this.db.prepare(`UPDATE med_psp_open_outbox SET acknowledged_at=?
        WHERE case_id=? AND acknowledged_at IS NULL`).run(this.now().toISOString(), caseId);
        });
    }
    applyExternalMedHoldAdditions(caseId: string, hops: {
        id: string;
        case_id: string;
        root_transfer_id: string;
        account_id: string;
        blocked_cents: number;
        refunded_cents: number;
        created_at: string;
        released_at: string | null;
    }[]): number {
        return this.transaction(() => {
            const med = this.db.prepare(`SELECT m.transfer_id,m.claim_amount_cents,m.opened_at,
        m.status FROM med_cases m WHERE m.id=?`).get(caseId) as {
                transfer_id: string;
                claim_amount_cents: number;
                opened_at: string;
                status: string;
            } | undefined;
            if (!med || !["open", "rejection_pending_psp", "settlement_pending_psp"]
                .includes(med.status) || !Number.isSafeInteger(med.claim_amount_cents))
                throw new BankError("INTEGRITY_MED_HOLD_ADDITION");
            let held = (this.db.prepare(`SELECT COALESCE(SUM(blocked_cents),0) n
        FROM med_hops WHERE case_id=?`).get(caseId) as {
                n: number;
            }).n;
            let added = 0;
            for (const hop of hops) {
                if (hop.case_id !== caseId ||
                    !hop.id || !hop.account_id ||
                    !this.db.prepare(`SELECT 1 FROM pix_transfers WHERE id=?
            AND status IN ('settled','returned_partial')`).get(hop.root_transfer_id) ||
                    !Number.isSafeInteger(hop.blocked_cents) || hop.blocked_cents <= 0 ||
                    !Number.isSafeInteger(hop.refunded_cents) || hop.refunded_cents < 0 ||
                    hop.refunded_cents > hop.blocked_cents ||
                    (hop.released_at !== null && (!Number.isFinite(Date.parse(hop.released_at)) ||
                        hop.released_at < hop.created_at ||
                        hop.released_at > this.now().toISOString() || med.status === "open")) ||
                    !Number.isFinite(Date.parse(hop.created_at)) ||
                    hop.created_at < med.opened_at || hop.created_at > this.now().toISOString())
                    throw new BankError("INTEGRITY_MED_HOLD_ADDITION");
                const prior = this.db.prepare(`SELECT case_id,root_transfer_id,account_id,
          blocked_cents,refunded_cents,created_at,released_at FROM med_hops
          WHERE id=?`).get(hop.id) as Omit<typeof hop, "id"> | undefined;
                if (prior) {
                    if (prior.case_id !== hop.case_id ||
                        prior.root_transfer_id !== hop.root_transfer_id ||
                        prior.account_id !== hop.account_id ||
                        prior.blocked_cents !== hop.blocked_cents ||
                        prior.created_at !== hop.created_at ||
                        (prior.released_at !== null && prior.released_at !== hop.released_at) ||
                        (prior.refunded_cents !== 0 && prior.refunded_cents !== hop.refunded_cents))
                        throw new BankError("INTEGRITY_MED_HOLD_ADDITION");
                    continue;
                }
                held += hop.blocked_cents;
                if (!Number.isSafeInteger(held) || held > med.claim_amount_cents)
                    throw new BankError("INTEGRITY_MED_HOLD_ADDITION");
                this.db.prepare(`INSERT INTO med_hops
          (id,case_id,root_transfer_id,account_id,blocked_cents,created_at)
          VALUES (?,?,?,?,?,?)`).run(hop.id, caseId, hop.root_transfer_id, hop.account_id, hop.blocked_cents, hop.created_at);
                added++;
            }
            return added;
        });
    }
    pendingExternalMedReleases(limit = 100): {
        case_id: string;
        transfer_id: string;
        created_at: string;
    }[] {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
            throw new BankError("BIZ_INVALID_LIMIT");
        const commands = this.db.prepare(`SELECT o.case_id,o.transfer_id,o.created_at,
      m.status case_status,m.transfer_id case_transfer,d.decision,
      opened.acknowledged_at opened_at
      FROM med_psp_release_outbox o
      LEFT JOIN med_cases m ON m.id=o.case_id
      LEFT JOIN med_decisions d ON d.case_id=o.case_id
      LEFT JOIN med_psp_open_outbox opened ON opened.case_id=o.case_id
      WHERE o.acknowledged_at IS NULL
      ORDER BY o.created_at,o.case_id LIMIT ?`).all(limit) as {
            case_id: string;
            transfer_id: string;
            created_at: string;
            case_status: string;
            case_transfer: string;
            decision: string;
            opened_at: string | null;
        }[];
        return commands.map(({ case_status, case_transfer, decision, opened_at, ...command }) => {
            if (case_status !== "rejection_pending_psp" ||
                case_transfer !== command.transfer_id || decision !== "rejected" ||
                !opened_at)
                throw new BankError("INTEGRITY_MED_RELEASE_COMMAND");
            return command;
        });
    }
    applyExternalMedRelease(caseId: string, hops: {
        id: string;
        case_id: string;
        root_transfer_id: string;
        account_id: string;
        ispb: string;
        blocked_cents: number;
        refunded_cents: number;
        created_at: string;
        released_at: string | null;
    }[]): void {
        this.transaction(() => {
            const command = this.db.prepare(`SELECT o.transfer_id,o.created_at,
        o.acknowledged_at,m.status,d.decision
        FROM med_psp_release_outbox o
        JOIN med_cases m ON m.id=o.case_id
        JOIN med_decisions d ON d.case_id=o.case_id
        WHERE o.case_id=?`).get(caseId) as {
                transfer_id: string;
                created_at: string;
                acknowledged_at: string | null;
                status: string;
                decision: string;
            } | undefined;
            if (!command || command.decision !== "rejected")
                throw new BankError("INTEGRITY_MED_RELEASE_COMMAND");
            if (command.status === "rejected" && command.acknowledged_at)
                return;
            if (command.status !== "rejection_pending_psp" || command.acknowledged_at)
                throw new BankError("INTEGRITY_MED_RELEASE_COMMAND");
            const bankHops = this.db.prepare(`SELECT id,case_id,root_transfer_id,
        account_id,blocked_cents,refunded_cents,created_at,released_at
        FROM med_hops WHERE case_id=? ORDER BY id`).all(caseId) as {
                id: string;
                case_id: string;
                root_transfer_id: string;
                account_id: string;
                blocked_cents: number;
                refunded_cents: number;
                created_at: string;
                released_at: string | null;
            }[];
            if (bankHops.length !== hops.length)
                throw new BankError("INTEGRITY_MED_RELEASE_REPLY");
            const releasedAt = hops[0]?.released_at ?? this.now().toISOString();
            const releaseTime = Date.parse(releasedAt);
            if (!Number.isFinite(releaseTime) ||
                releaseTime < Date.parse(command.created_at) ||
                releaseTime > this.now().getTime())
                throw new BankError("INTEGRITY_MED_RELEASE_REPLY");
            for (let i = 0; i < hops.length; i++) {
                const hop = hops[i]!;
                const mirror = bankHops[i]!;
                if (hop.released_at !== releasedAt ||
                    mirror.released_at !== null ||
                    hop.id !== mirror.id || hop.case_id !== mirror.case_id ||
                    hop.root_transfer_id !== mirror.root_transfer_id ||
                    hop.account_id !== mirror.account_id ||
                    hop.blocked_cents !== mirror.blocked_cents ||
                    hop.refunded_cents !== mirror.refunded_cents ||
                    hop.created_at !== mirror.created_at)
                    throw new BankError("INTEGRITY_MED_RELEASE_REPLY");
            }
            this.db.prepare(`UPDATE med_hops SET released_at=?
        WHERE case_id=? AND released_at IS NULL`).run(releasedAt, caseId);
            this.db.prepare("UPDATE med_cases SET status='rejected' WHERE id=?").run(caseId);
            this.db.prepare(`UPDATE med_psp_release_outbox SET acknowledged_at=?
        WHERE case_id=? AND acknowledged_at IS NULL`)
                .run(this.now().toISOString(), caseId);
            this.enqueueMedReplay(caseId);
        });
    }
    pendingExternalMedSettlements(limit = 100): {
        case_id: string;
        transfer_id: string;
        end_to_end_id: string;
        claim_amount_cents: number;
        created_at: string;
    }[] {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
            throw new BankError("BIZ_INVALID_LIMIT");
        const commands = this.db.prepare(`SELECT o.case_id,o.transfer_id,
      o.end_to_end_id,o.claim_amount_cents,o.created_at,
      m.status case_status,m.transfer_id case_transfer,
      m.claim_amount_cents case_claim,d.decision,
      p.end_to_end_id payment_e2e,p.status payment_status,
      opened.acknowledged_at opened_at
      FROM med_psp_settlement_outbox o
      LEFT JOIN med_cases m ON m.id=o.case_id
      LEFT JOIN med_decisions d ON d.case_id=o.case_id
      LEFT JOIN pix_transfers p ON p.id=o.transfer_id
      LEFT JOIN med_psp_open_outbox opened ON opened.case_id=o.case_id
      WHERE o.acknowledged_at IS NULL
      ORDER BY o.created_at,o.case_id LIMIT ?`).all(limit) as {
            case_id: string;
            transfer_id: string;
            end_to_end_id: string;
            claim_amount_cents: number;
            created_at: string;
            case_status: string;
            case_transfer: string;
            case_claim: number;
            decision: string;
            payment_e2e: string;
            payment_status: string;
            opened_at: string | null;
        }[];
        return commands.map(({ case_status, case_transfer, case_claim, decision, payment_e2e, payment_status, opened_at, ...command }) => {
            if (case_status !== "settlement_pending_psp" ||
                case_transfer !== command.transfer_id ||
                case_claim !== command.claim_amount_cents ||
                decision !== "approved" || payment_e2e !== command.end_to_end_id ||
                !["settled", "returned_partial"].includes(payment_status) ||
                !opened_at)
                throw new BankError("INTEGRITY_MED_SETTLEMENT_COMMAND");
            return command;
        });
    }
    pendingExternalMedAnalyses(limit = 100): {
        case_id: string;
        transfer_id: string;
        approved_at: string;
    }[] {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
            throw new BankError("BIZ_INVALID_LIMIT");
        return this.db.prepare(`SELECT o.case_id,o.transfer_id,o.approved_at
      FROM med_dict_analysis_outbox o
      WHERE o.acknowledged_at IS NULL
      ORDER BY o.approved_at,o.case_id LIMIT ?`).all(limit) as {
            case_id: string;
            transfer_id: string;
            approved_at: string;
        }[];
    }
    applyExternalMedAnalysis(caseId: string, reply: {
        case_id: string;
        root_transfer_id: string;
        analysed_at: string;
    }): void {
        this.transaction(() => {
            const command = this.db.prepare(`SELECT o.transfer_id,
        o.acknowledged_at,o.approved_at FROM med_dict_analysis_outbox o
        WHERE o.case_id=?`).get(caseId) as {
                transfer_id: string;
                acknowledged_at: string | null;
                approved_at: string;
            } | undefined;
            const analysed = Date.parse(reply.analysed_at);
            if (!command || reply.case_id !== caseId ||
                reply.root_transfer_id !== command.transfer_id ||
                !Number.isFinite(analysed) ||
                new Date(analysed).toISOString() !== reply.analysed_at ||
                analysed < Date.parse(command.approved_at) ||
                analysed > this.now().getTime())
                throw new BankError("INTEGRITY_MED_ANALYSIS_REPLY");
            const existing = this.db.prepare(`SELECT analysed_at FROM med_dict_analyses
        WHERE case_id=?`).get(caseId) as {
                analysed_at: string;
            } | undefined;
            if (existing) {
                if (existing.analysed_at !== reply.analysed_at)
                    throw new BankError("INTEGRITY_MED_ANALYSIS_REPLY");
                return;
            }
            if (command.acknowledged_at)
                throw new BankError("INTEGRITY_MED_ANALYSIS_REPLY");
            this.db.prepare(`INSERT INTO med_dict_analyses
        (case_id,analysed_at,recorded_at) VALUES (?,?,?)`)
                .run(caseId, reply.analysed_at, this.now().toISOString());
            this.db.prepare(`UPDATE med_dict_analysis_outbox SET acknowledged_at=?
        WHERE case_id=? AND acknowledged_at IS NULL`)
                .run(this.now().toISOString(), caseId);
        });
    }
    applyExternalMedSettlement(caseId: string, hops: {
        id: string;
        case_id: string;
        root_transfer_id: string;
        account_id: string;
        ispb: string;
        blocked_cents: number;
        refunded_cents: number;
        created_at: string;
        released_at: string | null;
    }[], timeline: {
        case_id: string;
        ispb: string;
        sequence: number;
        requested_at: string;
        deadline_at: string;
        processed_at: string | null;
        refunded_cents: number | null;
    }[]): {
        id: string;
        status: string;
        refunded_cents: number;
    } {
        return this.transaction(() => {
            const command = this.db.prepare(`SELECT o.transfer_id,o.end_to_end_id,
        o.claim_amount_cents,o.created_at,o.acknowledged_at,o.requires_timeline,
        m.status,m.refunded_cents,m.claim_amount_cents case_claim,
        p.from_account,p.amount,p.status payment_status,d.decision
        FROM med_psp_settlement_outbox o
        JOIN med_cases m ON m.id=o.case_id
        JOIN pix_transfers p ON p.id=o.transfer_id
        JOIN med_decisions d ON d.case_id=o.case_id WHERE o.case_id=?`)
                .get(caseId) as {
                transfer_id: string;
                end_to_end_id: string;
                claim_amount_cents: number;
                created_at: string;
                acknowledged_at: string | null;
                requires_timeline: number;
                status: string;
                refunded_cents: number;
                case_claim: number;
                from_account: string;
                amount: number;
                payment_status: string;
                decision: string;
            } | undefined;
            if (!command || command.decision !== "approved" ||
                command.claim_amount_cents !== command.case_claim)
                throw new BankError("INTEGRITY_MED_SETTLEMENT_COMMAND");
            if (command.status === "resolved" && command.acknowledged_at)
                return { id: caseId, status: "resolved", refunded_cents: command.refunded_cents };
            if (command.status !== "settlement_pending_psp" || command.acknowledged_at ||
                !["settled", "returned_partial"].includes(command.payment_status))
                throw new BankError("INTEGRITY_MED_SETTLEMENT_COMMAND");
            if (!this.db.prepare(`SELECT 1 FROM med_dict_analyses
        WHERE case_id=? AND analysed_at<=?`).get(caseId, this.now().toISOString()))
                throw new BankError("INTEGRITY_MED_ANALYSIS_REQUIRED");
            const analysed = this.db.prepare(`SELECT analysed_at FROM med_dict_analyses
        WHERE case_id=?`).get(caseId) as {
                analysed_at: string;
            };
            const participants = [...new Set(hops.map((hop) => hop.ispb))].sort();
            if (timeline.length !== participants.length &&
                !(command.requires_timeline === 0 && timeline.length === 0))
                throw new BankError("INTEGRITY_MED_REFUND_TIMELINE");
            let previousProcessed = analysed.analysed_at;
            for (let index = 0; index < timeline.length; index++) {
                const step = timeline[index]!;
                const requested = Date.parse(step.requested_at);
                const deadline = Date.parse(step.deadline_at);
                const processed = Date.parse(step.processed_at ?? "");
                const group = hops.filter((hop) => hop.ispb === step.ispb);
                if (step.case_id !== caseId || step.ispb !== participants[index] ||
                    step.sequence !== index + 1 ||
                    !Number.isFinite(requested) || !Number.isFinite(deadline) ||
                    !Number.isFinite(processed) ||
                    requested < Date.parse(previousProcessed) ||
                    deadline - requested !== 6 * 3600000 ||
                    processed < requested || processed > this.now().getTime() ||
                    group.some((hop) => hop.released_at !== step.processed_at) ||
                    step.refunded_cents !== group.reduce((sum, hop) => sum + hop.refunded_cents, 0))
                    throw new BankError("INTEGRITY_MED_REFUND_TIMELINE");
                previousProcessed = step.processed_at!;
            }
            const mirror = this.db.prepare(`SELECT id,case_id,root_transfer_id,
        account_id,blocked_cents,refunded_cents,created_at,released_at
        FROM med_hops WHERE case_id=? ORDER BY id`).all(caseId) as {
                id: string;
                case_id: string;
                root_transfer_id: string;
                account_id: string;
                blocked_cents: number;
                refunded_cents: number;
                created_at: string;
                released_at: string | null;
            }[];
            if (mirror.length !== hops.length)
                throw new BankError("INTEGRITY_MED_SETTLEMENT_REPLY");
            const settlementAt = hops.length ? hops.reduce((latest, hop) => hop.released_at && hop.released_at > latest ? hop.released_at : latest, command.created_at) : this.now().toISOString();
            const settlementTime = Date.parse(settlementAt);
            if (!Number.isFinite(settlementTime) ||
                settlementTime < Date.parse(command.created_at) ||
                settlementTime > this.now().getTime())
                throw new BankError("INTEGRITY_MED_SETTLEMENT_REPLY");
            let recovered = 0;
            for (let i = 0; i < hops.length; i++) {
                const hop = hops[i]!;
                const prior = mirror[i]!;
                if (hop.id !== prior.id || hop.case_id !== prior.case_id ||
                    hop.root_transfer_id !== prior.root_transfer_id ||
                    hop.account_id !== prior.account_id ||
                    hop.blocked_cents !== prior.blocked_cents ||
                    hop.created_at !== prior.created_at || prior.refunded_cents !== 0 ||
                    prior.released_at !== null || hop.released_at === null ||
                    !Number.isFinite(Date.parse(hop.released_at)) ||
                    Date.parse(hop.released_at) < Date.parse(command.created_at) ||
                    Date.parse(hop.released_at) > this.now().getTime() ||
                    !Number.isSafeInteger(hop.refunded_cents) ||
                    hop.refunded_cents < 0 || hop.refunded_cents > hop.blocked_cents)
                    throw new BankError("INTEGRITY_MED_SETTLEMENT_REPLY");
                recovered += hop.refunded_cents;
                if (!Number.isSafeInteger(recovered) || recovered > command.claim_amount_cents)
                    throw new BankError("INTEGRITY_MED_SETTLEMENT_REPLY");
            }
            for (const hop of hops)
                this.db.prepare(`UPDATE med_hops SET released_at=?,refunded_cents=?
          WHERE id=? AND released_at IS NULL`).run(hop.released_at, hop.refunded_cents, hop.id);
            for (const step of timeline)
                this.db.prepare(`INSERT INTO med_psp_refund_steps
        (case_id,ispb,sequence,requested_at,deadline_at,processed_at,refunded_cents)
        VALUES (?,?,?,?,?,?,?)`).run(caseId, step.ispb, step.sequence, step.requested_at, step.deadline_at, step.processed_at!, step.refunded_cents!);
            const loss = command.claim_amount_cents - recovered;
            const closedSource = this.account(command.from_account).status === "closed";
            const postings: Posting[] = [{
                    accountId: closedSource ? this.systemAccountId("suspense") : command.from_account,
                    amount: command.claim_amount_cents, kind: "med_recovery", actor: "med",
                    refType: "pix", refId: command.transfer_id,
                }];
            if (recovered)
                postings.push({ accountId: this.systemAccountId("pix_settlement"),
                    amount: -recovered, kind: "med_recovery", actor: "med", refType: "pix",
                    refId: command.transfer_id });
            if (loss)
                postings.push({ accountId: this.systemAccountId("bank_loss"),
                    amount: -loss, kind: "med_loss", actor: "med", refType: "pix",
                    refId: command.transfer_id });
            const ledgerTxId = this.post(postings);
            if (closedSource)
                this.recordClosedAccountCredit(command.from_account, "med_recovery", caseId, command.claim_amount_cents, ledgerTxId);
            if (recovered)
                this.db.prepare("INSERT INTO med_refunds VALUES (?,?,?,?,?)")
                    .run(newId("refund", this.now().getTime()), caseId, recovered, ledgerTxId, settlementAt);
            this.db.prepare(`UPDATE med_cases SET status='resolved',refunded_cents=?,
        unrecovered_cents=? WHERE id=?`).run(recovered, loss, caseId);
            this.enqueueMedReplay(caseId);
            if (recovered) {
                const ordinaryReturned = (this.db.prepare(`SELECT COALESCE(SUM(amount),0) n
          FROM pix_returns WHERE transfer_id=?`).get(command.transfer_id) as {
                    n: number;
                }).n;
                const status = ordinaryReturned + recovered === command.amount ?
                    "returned_full" : "returned_partial";
                this.db.prepare("UPDATE pix_transfers SET status=? WHERE id=?")
                    .run(status, command.transfer_id);
                this.db.prepare(`INSERT INTO pix_status_history
          (transfer_id,status,changed_at,reason) VALUES (?,?,?,?)`)
                    .run(command.transfer_id, status, settlementAt, "med_return");
            }
            this.db.prepare(`UPDATE med_psp_settlement_outbox SET acknowledged_at=?
        WHERE case_id=? AND acknowledged_at IS NULL`)
                .run(this.now().toISOString(), caseId);
            this.telemetry.emit({ source: "pix", category: "recovery", action: "med_resolve",
                outcome: "success", accountId: command.from_account,
                amountCents: command.claim_amount_cents, e2eId: command.end_to_end_id,
                message: "External MED case resolved" });
            return { id: caseId, status: "resolved", refunded_cents: recovered };
        });
    }
    requestMed(customerId: string, transferId: string): {
        id: string;
        status: string;
        refunded_cents: number;
    } {
        return this.transaction(() => {
            const transfer = this.db.prepare("SELECT from_account,to_account,amount,status,initiated_at FROM pix_transfers WHERE id=?")
                .get(transferId) as {
                from_account: string;
                to_account: string;
                amount: number;
                status: string;
                initiated_at: string;
            } | undefined;
            if (!transfer || this.account(transfer.from_account).customer_id !== customerId)
                throw new BankError("DEF_NOT_FOUND");
            const transferAgeMs = this.now().getTime() - Date.parse(transfer.initiated_at);
            if (!Number.isFinite(transferAgeMs) || transferAgeMs < 0 ||
                transferAgeMs > 80 * 86400000)
                throw new BankError("BIZ_MED_EXPIRED");
            if (this.separatedEcosystem &&
                !this.db.prepare("SELECT 1 FROM accounts WHERE id=?").get(transfer.to_account))
                throw new BankError("ECOSYSTEM_PROCESS_REQUIRED");
            const existing = this.db.prepare("SELECT id,status,refunded_cents FROM med_cases WHERE transfer_id=?")
                .get(transferId) as {
                id: string;
                status: string;
                refunded_cents: number;
            } | undefined;
            if (existing) {
                const decided = this.db.prepare("SELECT 1 FROM med_decisions WHERE case_id=?")
                    .get(existing.id);
                if (!decided && medMayReopen(this, existing.status)) {
                    this.db.prepare(`UPDATE med_cases SET status='open',resolve_after=?,
            timing_policy_version=2,recovery_initiated_at=NULL WHERE id=?`)
                        .run(new Date(this.now().getTime() + 7 * 86400000).toISOString(), existing.id);
                    return { ...existing, status: "open" };
                }
                return existing;
            }
            const external = this.separatedEcosystem ? undefined : this.spi.account(transfer.to_account);
            if (transfer.status !== "settled" &&
                !(external && transfer.status === "returned_partial"))
                throw new BankError("BIZ_MED_NOT_SETTLED");
            const ordinaryReturned = external ? (this.db.prepare(`SELECT COALESCE(SUM(amount),0) n
        FROM pix_returns WHERE transfer_id=?`).get(transferId) as {
                n: number;
            }).n : 0;
            const claimAmount = transfer.amount - ordinaryReturned;
            if (claimAmount <= 0)
                throw new BankError("BIZ_MED_NOT_SETTLED");
            const id = newId("med", this.now().getTime());
            const now = this.now();
            const resolveAfter = new Date(now.getTime() + 7 * 86400000);
            this.db.prepare(`INSERT INTO med_cases
        (id,transfer_id,customer_id,status,opened_at,resolve_after,claim_amount_cents)
        VALUES (?,?,?,?,?,?,?)`).run(id, transferId, customerId, "open", now.toISOString(), resolveAfter.toISOString(), claimAmount);
            if (external) {
                this.psp.supersedeCautelarForMed(transferId);
                for (const hop of this.psp.trace(transferId)) {
                    const available = this.psp.availableRoot(hop.account_id, transferId);
                    if (available <= 0)
                        continue;
                    const hopId = newId("medhop", now.getTime());
                    this.db.prepare(`INSERT INTO med_hops
            (id,case_id,root_transfer_id,account_id,blocked_cents,created_at)
            VALUES (?,?,?,?,?,?)`).run(hopId, id, transferId, hop.account_id, available, now.toISOString());
                    this.psp.recordMedHold({ id: hopId, case_id: id, root_transfer_id: transferId,
                        account_id: hop.account_id, blocked_cents: available,
                        created_at: now.toISOString() });
                    this.psp.notifyMedHop(hopId, "blocked", available);
                }
            }
            return { id, status: "open", refunded_cents: 0 };
        });
    }
    recordMedDecision(caseId: string, decision: "approved" | "rejected", makerId: string, checkerId: string, evidenceRef: string): void {
        if (!/^[A-Za-z][A-Za-z0-9_-]{2,79}$/.test(makerId) ||
            !/^[A-Za-z][A-Za-z0-9_-]{2,79}$/.test(checkerId) || makerId === checkerId ||
            !/^[A-Za-z0-9:_-]{1,128}$/.test(evidenceRef))
            throw new BankError("DEF_MED_DECISION_INVALID");
        this.transaction(() => {
            const row = this.db.prepare(`SELECT m.transfer_id,m.status,p.to_account
        FROM med_cases m JOIN pix_transfers p ON p.id=m.transfer_id
        WHERE m.id=?`).get(caseId) as {
                transfer_id: string;
                status: string;
                to_account: string;
            } | undefined;
            if (!row || row.status !== "open")
                throw new BankError("DEF_MED_DECISION_INVALID");
            const evidenceTable = this.db.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='sentinel_incident_transfer_evidence'`).get();
            const evidence = evidenceTable && this.db.prepare(`SELECT 1 FROM
        sentinel_incident_transfer_evidence WHERE transfer_id=? AND evidence_ref=?`)
                .get(row.transfer_id, evidenceRef);
            let authorizedOperators = false;
            if (this.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
        AND name='operator_accounts'`).get()) {
                const maker = this.db.prepare(`SELECT role,disabled_at FROM operator_accounts
          WHERE id=?`).get(makerId) as {
                    role: string;
                    disabled_at: string | null;
                } | undefined;
                const checker = this.db.prepare(`SELECT role,disabled_at FROM operator_accounts
          WHERE id=?`).get(checkerId) as {
                    role: string;
                    disabled_at: string | null;
                } | undefined;
                authorizedOperators = Boolean(maker && !maker.disabled_at &&
                    ["maker", "admin"].includes(maker.role) && checker && !checker.disabled_at &&
                    ["reviewer", "admin"].includes(checker.role));
            }
            const approvalTable = this.db.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='blue_med_approvals'`).get();
            const blueApproval = evidence && approvalTable && this.db.prepare(`SELECT 1 FROM blue_med_approvals a
        JOIN sentinel_incident_transfer_evidence e ON e.incident_id=a.incident_id
          AND e.transfer_id=a.transfer_id
        WHERE a.transfer_id=? AND a.maker_id=? AND a.checker_id=?
          AND a.consumed_at IS NOT NULL AND e.evidence_ref=?`)
                .get(row.transfer_id, makerId, checkerId, evidenceRef);
            const operatorReviewTables = this.db.prepare(`SELECT COUNT(*) n FROM sqlite_master
        WHERE type='table' AND name IN ('med_operator_review_proposals',
          'med_operator_review_confirmations')`).get() as {
                n: number;
            };
            const operatorReview = authorizedOperators && operatorReviewTables.n === 2 &&
                this.db.prepare(`SELECT 1 FROM med_operator_review_proposals p
          JOIN med_operator_review_confirmations c ON c.proposal_id=p.id
          WHERE p.case_id=? AND p.transfer_id=? AND p.decision=?
            AND p.evidence_ref=? AND p.maker_id=? AND c.checker_id=?`)
                    .get(caseId, row.transfer_id, decision, evidenceRef, makerId, checkerId);
            if (!operatorReview && !blueApproval)
                throw new BankError("DEF_MED_DECISION_INVALID");
            this.db.prepare(`INSERT INTO med_decisions
        (case_id,decision,maker_id,checker_id,evidence_ref,decided_at)
        VALUES (?,?,?,?,?,?)`).run(caseId, decision, makerId, checkerId, evidenceRef, this.now().toISOString());
            if (decision === "approved" && this.separatedEcosystem &&
                !this.db.prepare("SELECT 1 FROM accounts WHERE id=?").get(row.to_account))
                this.db.prepare(`INSERT INTO med_dict_analysis_outbox
          (case_id,transfer_id,approved_at) VALUES (?,?,?)`)
                    .run(caseId, row.transfer_id, this.now().toISOString());
            if (decision === "rejected") {
                if (this.separatedEcosystem &&
                    !this.db.prepare("SELECT 1 FROM accounts WHERE id=?").get(row.to_account)) {
                    this.db.prepare(`INSERT INTO med_psp_release_outbox
            (case_id,transfer_id,created_at) VALUES (?,?,?)`)
                        .run(caseId, row.transfer_id, this.now().toISOString());
                    this.db.prepare(`UPDATE med_cases SET status='rejection_pending_psp'
            WHERE id=?`).run(caseId);
                    return;
                }
                const hops = this.db.prepare(`SELECT id,account_id,root_transfer_id,
          blocked_cents FROM med_hops
          WHERE case_id=? AND released_at IS NULL`).all(caseId) as {
                    id: string;
                    account_id: string;
                    root_transfer_id: string;
                    blocked_cents: number;
                }[];
                for (const hop of hops) {
                    const releasedAt = this.now().toISOString();
                    this.db.prepare("UPDATE med_hops SET released_at=? WHERE id=?")
                        .run(releasedAt, hop.id);
                    this.psp.releaseMedHold(hop.id, releasedAt);
                    this.psp.notifyMedHop(hop.id, "released", hop.blocked_cents);
                }
                for (const hop of hops)
                    this.psp.reserveAvailableMedFunds(hop.account_id, hop.root_transfer_id);
                this.db.prepare("UPDATE med_cases SET status='rejected' WHERE id=?").run(caseId);
                this.enqueueMedReplay(caseId);
            }
        });
    }
    private enqueueMedReplay(caseId: string): void {
        this.db.prepare(`INSERT OR IGNORE INTO med_replay_outbox
      (case_id,enqueued_at) VALUES (?,?)`).run(caseId, this.now().toISOString());
    }
    resolvePendingMed(): number {
        const pending = this.db.prepare(`SELECT m.id FROM med_cases m
      JOIN med_decisions d ON d.case_id=m.id AND d.decision='approved'
      WHERE m.status='open' ORDER BY d.decided_at,m.id`)
            .all() as {
            id: string;
        }[];
        let resolved = 0;
        for (const row of pending) {
            try {
                if (this.resolveMed(row.id).status !== "analysis_pending_dict")
                    resolved++;
            }
            catch (error) {
                if (error instanceof Error && error.message === "SPI_UNAVAILABLE")
                    continue;
                throw error;
            }
        }
        return resolved;
    }
    medOpeningSla(): {
        target_seconds: number;
        completed: number;
        pending: number;
        overdue_pending: number;
        p95_seconds: number | null;
        target_met: boolean | null;
        cases: {
            case_id: string;
            requested_at: string;
            opened_at: string | null;
            elapsed_seconds: number;
            state: "pending" | "overdue" | "on_time" | "late";
        }[];
    } {
        const rows = this.db.prepare(`SELECT m.id case_id,m.opened_at requested_at,
      m.status,o.case_id opening_command,o.acknowledged_at
      FROM med_cases m LEFT JOIN med_psp_open_outbox o ON o.case_id=m.id
      ORDER BY m.opened_at,m.id`).all() as {
            case_id: string;
            requested_at: string;
            status: string;
            opening_command: string | null;
            acknowledged_at: string | null;
        }[];
        const now = this.now().getTime();
        const targetSeconds = 30 * 60;
        const cases = rows.map((row) => {
            if ((row.status === "opening") !==
                (row.opening_command !== null && row.acknowledged_at === null))
                throw new BankError("INTEGRITY_MED_OPENING_TIME");
            const requested = Date.parse(row.requested_at);
            const openedAt = row.status === "opening" && row.acknowledged_at === null ?
                null : row.acknowledged_at ?? row.requested_at;
            const opened = openedAt === null ? now : Date.parse(openedAt);
            if (!Number.isFinite(requested) || !Number.isFinite(opened) ||
                opened < requested || (openedAt !== null && opened > now))
                throw new BankError("INTEGRITY_MED_OPENING_TIME");
            const elapsedSeconds = Math.floor((opened - requested) / 1000);
            return { case_id: row.case_id, requested_at: row.requested_at,
                opened_at: openedAt, elapsed_seconds: elapsedSeconds,
                state: openedAt === null ? elapsedSeconds > targetSeconds ?
                    "overdue" as const : "pending" as const :
                    elapsedSeconds > targetSeconds ? "late" as const : "on_time" as const };
        });
        const durations = cases.filter((row) => row.opened_at !== null)
            .map((row) => row.elapsed_seconds).sort((a, b) => a - b);
        const p95Seconds = durations.at(Math.ceil(durations.length * 0.95) - 1) ?? null;
        const overduePending = cases.filter((row) => row.state === "overdue").length;
        return { target_seconds: targetSeconds, completed: durations.length,
            pending: cases.filter((row) => row.opened_at === null).length,
            overdue_pending: overduePending, p95_seconds: p95Seconds,
            target_met: overduePending > 0 ? false : p95Seconds === null ? null :
                p95Seconds <= targetSeconds, cases };
    }
    medInitiationSla(): {
        case_id: string;
        decided_at: string;
        analysed_at: string | null;
        deadline_at: string | null;
        initiated_at: string | null;
        state: "awaiting_analysis" | "pending" | "on_time" | "late" | "overdue" | "unknown";
    }[] {
        const rows = this.db.prepare(`SELECT m.id case_id,m.status,d.decided_at,
      m.recovery_initiated_at,a.analysed_at,
      EXISTS(SELECT 1 FROM med_dict_analysis_outbox o WHERE o.case_id=m.id)
        analysis_required
      FROM med_cases m JOIN med_decisions d ON d.case_id=m.id
      JOIN pix_spi_outbox p ON p.transfer_id=m.transfer_id
      LEFT JOIN med_dict_analyses a ON a.case_id=m.id
      WHERE d.decision='approved' ORDER BY d.decided_at,m.id`).all() as {
            case_id: string;
            status: string;
            decided_at: string;
            recovery_initiated_at: string | null;
            analysed_at: string | null;
            analysis_required: number;
        }[];
        const now = this.now().getTime();
        return rows.map((row) => {
            const decided = Date.parse(row.decided_at);
            const initiated = row.recovery_initiated_at === null ? null :
                Date.parse(row.recovery_initiated_at);
            if (row.analysis_required === 1 && row.analysed_at === null &&
                initiated === null && row.status === "open")
                return { case_id: row.case_id, decided_at: row.decided_at,
                    analysed_at: null, deadline_at: null, initiated_at: null,
                    state: "awaiting_analysis" as const };
            const clockStart = row.analysed_at ?? row.decided_at;
            const start = Date.parse(clockStart);
            if (!Number.isFinite(decided) || (initiated !== null &&
                (!Number.isFinite(initiated) || initiated < start)) ||
                !Number.isFinite(start) || start < decided)
                throw new BankError("INTEGRITY_MED_INITIATION_TIME");
            const deadline = start + 72 * 3600000;
            return { case_id: row.case_id, decided_at: row.decided_at,
                analysed_at: row.analysed_at,
                deadline_at: new Date(deadline).toISOString(),
                initiated_at: row.recovery_initiated_at,
                state: initiated === null ? row.status !== "open" ? "unknown" :
                    now > deadline ? "overdue" : "pending" :
                    initiated > deadline ? "late" : "on_time" };
        });
    }
    compensateIncidentMed(caseId: string, incidentId: string): {
        txId: string;
        amount: number;
    } | undefined {
        return this.transaction(() => {
            const row = this.db.prepare(`SELECT p.id transfer_id,p.from_account,m.refunded_cents,
        m.unrecovered_cents FROM med_cases m
        JOIN pix_transfers p ON p.id=m.transfer_id
        JOIN accounts source ON source.id=p.from_account AND source.customer_id=m.customer_id
        JOIN accounts recipient ON recipient.id=p.to_account AND recipient.customer_id IS NOT NULL
        JOIN med_decisions d ON d.case_id=m.id AND d.decision='approved' AND d.maker_id<>d.checker_id
        JOIN sentinel_incident_transfer_evidence e ON e.transfer_id=p.id AND e.evidence_ref=d.evidence_ref
        JOIN sentinel_incidents i ON i.id=e.incident_id AND i.entity_key=m.customer_id AND i.area='pix'
        JOIN sentinel_alerts a ON e.evidence_ref='sentinel_alerts:' || a.id
          AND a.rule_id='S-PIX-02' AND a.entity=p.from_account
        JOIN fraud_incident_notices n ON n.incident_id=i.id AND n.alert_id=a.id
          AND n.transfer_id=p.id AND n.customer_id=m.customer_id
          AND n.kind='suspicious_pix_review'
        WHERE m.id=? AND i.id=? AND m.status='resolved' AND p.status='settled'
          AND p.ledger_tx_id IS NOT NULL AND m.claim_amount_cents=p.amount AND m.unrecovered_cents>0
          AND m.refunded_cents>=0 AND m.refunded_cents+m.unrecovered_cents=p.amount`)
                .get(caseId, incidentId) as {
                transfer_id: string;
                from_account: string;
                refunded_cents: number;
                unrecovered_cents: number;
            } | undefined;
            if (!row)
                return undefined;
            const proof = { caseId, sourceAccount: row.from_account, amount: row.unrecovered_cents };
            const existing = readMedIncidentCompensation(this.db, proof);
            if (existing)
                return existing;
            const refund = this.db.prepare(`SELECT amount,ledger_tx_id FROM med_refunds WHERE case_id=?`)
                .all(caseId) as {
                amount: number;
                ledger_tx_id: string;
            }[];
            if (refund.length !== Number(row.refunded_cents > 0) ||
                (refund.length && (refund[0]!.amount !== row.refunded_cents ||
                    !hasMedCustomerCredit(this.db, { sourceAccount: row.from_account, sourceId: caseId,
                        txId: refund[0]!.ledger_tx_id, amount: row.refunded_cents,
                        kind: "med_refund", refType: "pix", refId: row.transfer_id }))))
                return undefined;
            const closed = this.account(row.from_account).status === "closed";
            const reference = { actor: "med", refType: "med_case", refId: caseId };
            const txId = this.post([
                { ...reference, accountId: this.systemAccountId("bank_loss"),
                    amount: -proof.amount, kind: "med_incident_loss" },
                { ...reference, accountId: closed ? this.systemAccountId("suspense") : row.from_account,
                    amount: proof.amount, kind: "med_incident_compensation" },
            ]);
            if (closed)
                this.recordClosedAccountCredit(row.from_account, "med_recovery", `${caseId}:compensation`, proof.amount, txId);
            return { txId, amount: proof.amount };
        });
    }
    resolveMed(caseId: string): {
        id: string;
        status: string;
        refunded_cents: number;
    } {
        return this.transaction(() => {
            const row = this.db.prepare(`SELECT m.id,m.status,m.refunded_cents,
        p.id transfer_id,p.end_to_end_id,p.from_account,p.to_account,p.amount,
        COALESCE(m.claim_amount_cents,p.amount) claim_amount_cents
        FROM med_cases m JOIN pix_transfers p ON p.id=m.transfer_id WHERE m.id=?`)
                .get(caseId) as {
                id: string;
                status: string;
                refunded_cents: number;
                transfer_id: string;
                end_to_end_id: string;
                from_account: string;
                to_account: string;
                amount: number;
                claim_amount_cents: number;
            } | undefined;
            if (!row)
                throw new BankError("BIZ_MED_NOT_FOUND");
            if (row.status !== "open")
                return { id: row.id, status: row.status, refunded_cents: row.refunded_cents };
            if (!this.db.prepare(`SELECT 1 FROM med_decisions WHERE case_id=?
        AND decision='approved'`).get(row.id))
                throw new BankError("DEF_MED_DECISION_REQUIRED");
            if (this.separatedEcosystem &&
                !this.db.prepare("SELECT 1 FROM accounts WHERE id=?").get(row.to_account) &&
                !this.db.prepare(`SELECT 1 FROM med_dict_analyses WHERE case_id=?`)
                    .get(row.id))
                return { id: row.id, status: "analysis_pending_dict",
                    refunded_cents: row.refunded_cents };
            const initiatedAt = this.now().toISOString();
            this.db.prepare(`UPDATE med_cases SET recovery_initiated_at=?
        WHERE id=? AND recovery_initiated_at IS NULL`).run(initiatedAt, row.id);
            if (this.separatedEcosystem &&
                !this.db.prepare("SELECT 1 FROM accounts WHERE id=?").get(row.to_account)) {
                const createdAt = initiatedAt;
                this.db.prepare(`INSERT INTO med_psp_settlement_outbox
          (case_id,transfer_id,end_to_end_id,claim_amount_cents,created_at)
          VALUES (?,?,?,?,?)`).run(row.id, row.transfer_id, row.end_to_end_id, row.claim_amount_cents, createdAt);
                this.db.prepare(`UPDATE med_cases SET status='settlement_pending_psp'
          WHERE id=?`).run(row.id);
                return { id: row.id, status: "settlement_pending_psp",
                    refunded_cents: row.refunded_cents };
            }
            if (!this.separatedEcosystem && this.spi.account(row.to_account))
                return this.resolveExternalMed(row);
            const amount = Math.min(row.amount, Math.max(0, this.account(row.to_account).balance_cached));
            if (amount > 0) {
                const closedSource = this.account(row.from_account).status === "closed";
                const ledgerTxId = this.post([
                    { accountId: row.to_account, amount: -amount, kind: "med_refund", actor: "med", refType: "pix", refId: row.transfer_id },
                    { accountId: closedSource ? this.systemAccountId("suspense") : row.from_account,
                        amount, kind: "med_refund", actor: "med", refType: "pix", refId: row.transfer_id },
                ]);
                this.db.prepare("INSERT INTO med_refunds VALUES (?,?,?,?,?)").run(newId("refund", this.now().getTime()), row.id, amount, ledgerTxId, this.now().toISOString());
                if (closedSource)
                    this.recordClosedAccountCredit(row.from_account, "med_recovery", row.id, amount, ledgerTxId);
            }
            const refunded = row.refunded_cents + amount;
            const unrecovered = row.claim_amount_cents - refunded;
            const status = unrecovered === 0 ? "refunded" : "resolved";
            this.db.prepare(`UPDATE med_cases SET status=?,refunded_cents=?,
        unrecovered_cents=? WHERE id=?`).run(status, refunded, unrecovered, row.id);
            this.enqueueMedReplay(row.id);
            return { id: row.id, status, refunded_cents: refunded };
        });
    }
    private resolveExternalMed(row: {
        id: string;
        transfer_id: string;
        end_to_end_id: string;
        from_account: string;
        amount: number;
        claim_amount_cents: number;
    }): {
        id: string;
        status: string;
        refunded_cents: number;
    } {
        const hops = this.db.prepare(`SELECT id,root_transfer_id,account_id,blocked_cents FROM med_hops
      WHERE case_id=? AND released_at IS NULL ORDER BY id`).all(row.id) as {
            id: string;
            root_transfer_id: string;
            account_id: string;
            blocked_cents: number;
        }[];
        let recovered = 0;
        const ts = this.now().toISOString();
        for (const hop of hops) {
            const account = this.spi.account(hop.account_id);
            if (!account)
                throw new BankError("INTEGRITY_MED_HOP_MISSING");
            this.db.prepare("UPDATE med_hops SET released_at=? WHERE id=?").run(ts, hop.id);
            this.psp.releaseMedHold(hop.id, ts);
            const amount = Math.min(hop.blocked_cents, this.psp.availableRoot(hop.account_id, hop.root_transfer_id), account.balance_cents, this.spi.balance(account.ispb), row.claim_amount_cents - recovered);
            if (amount > 0) {
                this.psp.debitAccountRoot(hop.account_id, hop.root_transfer_id, amount);
                const returnId = `medreturn_${createHash("sha256")
                    .update(`banco-vivo:med-return:v1:${hop.id}`).digest("base64url")}`;
                this.spi.returnPayment(row.end_to_end_id, returnId, account.ispb, JACARANDA_ISPB, amount, "MED");
                this.db.prepare("UPDATE med_hops SET refunded_cents=? WHERE id=?").run(amount, hop.id);
                this.psp.recordMedRefund(hop.id, amount);
                this.psp.notifyMedHop(hop.id, "recovered", amount);
            }
            if (hop.blocked_cents > amount)
                this.psp.notifyMedHop(hop.id, "released", hop.blocked_cents - amount);
            recovered += amount;
        }
        for (const hop of hops)
            this.psp.reserveAvailableMedFunds(hop.account_id, hop.root_transfer_id);
        const loss = row.claim_amount_cents - recovered;
        const closedSource = this.account(row.from_account).status === "closed";
        const postings: Posting[] = [
            { accountId: closedSource ? this.systemAccountId("suspense") : row.from_account,
                amount: row.claim_amount_cents, kind: "med_recovery",
                actor: "med", refType: "pix", refId: row.transfer_id },
        ];
        if (recovered)
            postings.push({ accountId: this.systemAccountId("pix_settlement"),
                amount: -recovered, kind: "med_recovery", actor: "med", refType: "pix",
                refId: row.transfer_id });
        if (loss)
            postings.push({ accountId: this.systemAccountId("bank_loss"),
                amount: -loss, kind: "med_loss", actor: "med", refType: "pix",
                refId: row.transfer_id });
        const ledgerTxId = this.post(postings);
        if (closedSource)
            this.recordClosedAccountCredit(row.from_account, "med_recovery", row.id, row.claim_amount_cents, ledgerTxId);
        if (recovered)
            this.db.prepare("INSERT INTO med_refunds VALUES (?,?,?,?,?)")
                .run(newId("refund", this.now().getTime()), row.id, recovered, ledgerTxId, ts);
        this.db.prepare(`UPDATE med_cases SET status='resolved',refunded_cents=?,unrecovered_cents=?
      WHERE id=?`).run(recovered, loss, row.id);
        this.enqueueMedReplay(row.id);
        if (recovered) {
            const ordinaryReturned = (this.db.prepare(`SELECT COALESCE(SUM(amount),0) n
        FROM pix_returns WHERE transfer_id=?`).get(row.transfer_id) as {
                n: number;
            }).n;
            const status = ordinaryReturned + recovered === row.amount ? "returned_full" : "returned_partial";
            this.db.prepare("UPDATE pix_transfers SET status=? WHERE id=?").run(status, row.transfer_id);
            this.db.prepare(`INSERT INTO pix_status_history
        (transfer_id,status,changed_at,reason) VALUES (?,?,?,?)`)
                .run(row.transfer_id, status, ts, "med_return");
        }
        this.telemetry.emit({ source: "pix", category: "recovery", action: "med_resolve",
            outcome: "success", accountId: row.from_account, amountCents: row.claim_amount_cents,
            e2eId: row.end_to_end_id, message: "External MED case resolved" });
        return { id: row.id, status: "resolved", refunded_cents: recovered };
    }
    statement(accountId: string, customerId: string, limit = 20, from?: string, to?: string): {
        tx_id: string;
        amount: number;
        kind: string;
        created_at: string;
    }[] {
        const account = this.db.prepare(`SELECT id,customer_id,kind,system_role,balance_cached,overdraft_limit,status
      FROM accounts WHERE id=?`).get(accountId) as Account | undefined;
        if (!account)
            throw new BankError("DEF_NOT_FOUND");
        if (account.customer_id !== customerId) {
            const exposed = canReadStatement(this, account.customer_id, customerId);
            this.log({ actor: customerId, kind: "statement_foreign", customerId, accountId, route: "statement", status: exposed ? 200 : 404 });
            if (!exposed)
                throw new BankError("DEF_NOT_FOUND");
        }
        const toMs = to === undefined ? this.now().getTime() : Date.parse(to);
        const fromMs = from === undefined ? toMs - 90 * 86400000 : Date.parse(from);
        if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || fromMs > toMs ||
            toMs - fromMs > 90 * 86400000 || toMs > this.now().getTime())
            throw new BankError("BIZ_STATEMENT_WINDOW");
        this.log({ actor: customerId, kind: "statement_own", customerId, accountId, route: "statement", status: 200 });
        return this.db.prepare(`SELECT tx_id,amount,kind,created_at FROM ledger_entries
      WHERE account_id=? AND created_at>=? AND created_at<=? ORDER BY created_at DESC LIMIT ?`)
            .all(accountId, new Date(fromMs).toISOString(), new Date(toMs).toISOString(), Math.min(Math.max(limit, 1), 100)) as {
            tx_id: string;
            amount: number;
            kind: string;
            created_at: string;
        }[];
    }
    log(input: {
        actor: string;
        kind: BankAuditKind;
        customerId?: string;
        accountId?: string;
        cardId?: string;
        deviceId?: string;
        sessionId?: string;
        route?: string;
        status: number;
        peerIp?: string;
    }): void {
        if (!Object.hasOwn(AUDIT_SOURCE_BY_KIND, input.kind))
            throw new BankError("BIZ_UNKNOWN_AUDIT_KIND");
        this.db.prepare("INSERT INTO access_log VALUES (?,?,?,?,?,?,?,?,?)").run(newId("log", this.now().getTime()), this.now().toISOString(), input.actor, input.kind, input.customerId ?? null, input.accountId ?? null, input.route ?? null, input.status, input.peerIp ?? null);
        const source = AUDIT_SOURCE_BY_KIND[input.kind];
        if (source === null)
            return;
        this.telemetry.emit({ source, category: "audit", action: input.kind,
            outcome: input.status === 0 ? "unknown" : input.status >= 400 ? "failure" : "success",
            severity: input.status >= 500 ? "error" : input.status >= 400 ? "warn" : "info",
            ...(input.customerId ? { userId: input.customerId } : {}),
            ...(input.accountId ? { accountId: input.accountId } : {}),
            ...(input.cardId ? { cardToken: input.cardId } : {}),
            ...(input.deviceId ? { deviceId: input.deviceId } : {}),
            ...(input.sessionId ? { sessionId: input.sessionId } : {}),
            ...(input.peerIp ? { sourceIp: input.peerIp } : {}),
            message: "Application action recorded" });
    }
    balanceDriftCents(): number {
        return (this.db.prepare(`SELECT COALESCE(SUM(ABS(a.balance_cached-
      COALESCE(l.total,0))),0) cents FROM accounts a LEFT JOIN
      (SELECT account_id,SUM(amount) total FROM ledger_entries GROUP BY account_id) l
      ON l.account_id=a.id`).get() as {
            cents: number;
        }).cents;
    }
    verifyLedgerChain(): boolean { return verifyLedgerChain(this.db); }
    trialBalance(): TrialBalanceLine[] { return trialBalance(this.db); }
    reconcileSpi(): {
        ok: boolean;
        ledger_pi_cents: number;
        spi_pi_cents: number;
        command_drift: number;
    } {
        const ledgerPi = -this.account(this.systemAccountId("pix_settlement")).balance_cached;
        const spiPi = this.spi.balance(JACARANDA_ISPB);
        const acceptedPending = (this.db.prepare(`SELECT COALESCE(SUM(p.amount),0) cents
      FROM pix_transfers p JOIN pix_spi_outbox o ON o.transfer_id=p.id
      JOIN spi_messages res ON res.end_to_end_id=o.end_to_end_id
        AND res.message_type='pacs.002'
      WHERE p.status='in_processing' AND
        json_extract(res.payload_json,'$.status')='ACSC'`)
            .get() as {
            cents: number;
        }).cents;
        const commandDrift = (this.db.prepare(`SELECT COUNT(*) n FROM pix_spi_outbox o
      LEFT JOIN pix_transfers p ON p.id=o.transfer_id
      LEFT JOIN spi_messages req ON req.end_to_end_id=o.end_to_end_id
        AND req.message_type='pacs.008'
      LEFT JOIN spi_messages res ON res.end_to_end_id=o.end_to_end_id
        AND res.message_type='pacs.002'
      WHERE p.id IS NULL OR o.end_to_end_id<>p.end_to_end_id OR o.amount_cents<>p.amount OR
        o.from_ispb<>? OR
        (o.latency_policy_version IN (2,3) AND (o.deadline_at_real IS NULL OR
          o.queued_at_real IS NULL OR o.eligible_at_real IS NULL OR
          o.deadline_at_real<=o.eligible_at_real)) OR
        (o.latency_policy_version=1 AND o.deadline_at_real IS NOT NULL) OR
        (res.id IS NOT NULL AND req.id IS NULL) OR
        (p.status<>'in_processing' AND (req.id IS NULL OR res.id IS NULL)) OR
        (p.status<>'in_processing' AND o.response_status IS NULL) OR
        (p.status='in_processing' AND o.response_status IS NOT NULL) OR
        (req.id IS NOT NULL AND (
          json_extract(req.payload_json,'$.from_ispb') IS NOT o.from_ispb OR
          json_extract(req.payload_json,'$.to_ispb') IS NOT o.to_ispb OR
          json_extract(req.payload_json,'$.amount_cents') IS NOT o.amount_cents OR
          json_extract(req.payload_json,'$.deadline_at_real') IS NOT o.deadline_at_real OR
          (json_type(req.payload_json,'$.sender_account') IS NOT NULL AND
           json_extract(req.payload_json,'$.sender_account') IS NOT p.from_account) OR
          (json_type(req.payload_json,'$.root_transfer_id') IS NOT NULL AND
           json_extract(req.payload_json,'$.root_transfer_id') IS NOT p.id) OR
          (json_type(req.payload_json,'$.recipient_account') IS NOT NULL AND
           json_extract(req.payload_json,'$.recipient_account') IS NOT p.to_account))) OR
        (res.id IS NOT NULL AND (
          json_extract(res.payload_json,'$.from_ispb') IS NOT o.from_ispb OR
          json_extract(res.payload_json,'$.to_ispb') IS NOT o.to_ispb OR
          json_extract(res.payload_json,'$.amount_cents') IS NOT o.amount_cents)) OR
        (o.response_status IS NOT NULL AND (
          json_extract(res.payload_json,'$.status') IS NOT o.response_status OR
          json_extract(res.payload_json,'$.reason') IS NOT o.response_reason)) OR
        (o.response_status='ACSC' AND p.status NOT IN
          ('settled','returned_partial','returned_full')) OR
        (o.response_reason='AB03' AND (o.response_status<>'RJCT' OR
          o.deadline_at_real IS NULL OR o.responded_at_real IS NULL OR
          o.responded_at_real<o.deadline_at_real)) OR
        (o.response_status='RJCT' AND p.status<>'rejected')`)
            .get(JACARANDA_ISPB) as {
            n: number;
        }).n +
            (this.db.prepare(`SELECT COUNT(*) n FROM pix_transfers p
        LEFT JOIN pix_spi_outbox o ON o.transfer_id=p.id
        WHERE p.spi_command_version IN (1,2) AND o.transfer_id IS NULL`)
                .get() as {
                n: number;
            }).n +
            (this.db.prepare(`SELECT COUNT(*) n FROM pix_transfers p
        LEFT JOIN pix_psp_inbound_outbox o ON o.transfer_id=p.id
        WHERE p.spi_command_version=2 AND p.status IN
          ('settled','returned_partial','returned_full') AND
          (o.transfer_id IS NULL OR o.end_to_end_id<>p.end_to_end_id OR
           o.to_account<>p.to_account OR o.amount_cents<>p.amount OR
           o.from_account IS NOT p.from_account OR o.settled_at IS NOT p.settled_at)`)
                .get() as {
                n: number;
            }).n +
            (this.db.prepare(`SELECT COUNT(*) n FROM pix_psp_inbound_outbox o
        LEFT JOIN pix_transfers p ON p.id=o.transfer_id
        WHERE p.id IS NULL OR p.spi_command_version<>2 OR p.status NOT IN
          ('settled','returned_partial','returned_full')`)
                .get() as {
                n: number;
            }).n;
        return { ok: ledgerPi - acceptedPending === spiPi && commandDrift === 0,
            ledger_pi_cents: ledgerPi, spi_pi_cents: spiPi, command_drift: commandDrift };
    }
    reconcilePsp(): ReturnType<PspNetwork["reconcile"]> & {
        med_hold_drift: number;
        inbound_pending: number;
        inbound_receipt_drift: number;
    } {
        const local = this.psp.reconcile();
        const medHoldDrift = (this.db.prepare(`SELECT COUNT(*) n FROM med_hops h
      LEFT JOIN psp_med_holds p ON p.hop_id=h.id
      WHERE p.hop_id IS NULL OR p.case_id<>h.case_id OR
        p.root_transfer_id<>h.root_transfer_id OR p.account_id<>h.account_id OR
        p.blocked_cents<>h.blocked_cents OR p.refunded_cents<>h.refunded_cents OR
        p.created_at<>h.created_at OR p.released_at IS NOT h.released_at`)
            .get() as {
            n: number;
        }).n +
            (this.db.prepare(`SELECT COUNT(*) n FROM psp_med_holds p
        LEFT JOIN med_hops h ON h.id=p.hop_id WHERE h.id IS NULL`)
                .get() as {
                n: number;
            }).n;
        const legacyRootDrift = (this.db.prepare(`SELECT COUNT(*) n FROM psp_roots r
      LEFT JOIN pix_transfers p ON p.id=r.root_transfer_id
      WHERE r.source='legacy' AND (p.id IS NULL OR
        p.end_to_end_id<>r.end_to_end_id OR p.to_account<>r.account_id OR
        p.amount<>r.amount_cents OR p.spi_command_version=2 OR
        p.status NOT IN ('settled','returned_partial','returned_full'))`)
            .get() as {
            n: number;
        }).n;
        const inboundPending = (this.db.prepare(`SELECT COUNT(*) n FROM pix_psp_inbound_outbox
      WHERE acknowledged_at IS NULL`).get() as {
            n: number;
        }).n;
        const inboundReceiptDrift = (this.db.prepare(`SELECT COUNT(*) n
      FROM pix_psp_inbound_outbox o LEFT JOIN psp_inbound_receipts i
      ON i.root_transfer_id=o.transfer_id
      LEFT JOIN psp_inbound_sender_facts f ON f.root_transfer_id=o.transfer_id
      WHERE o.acknowledged_at IS NOT NULL
      AND (i.root_transfer_id IS NULL OR i.end_to_end_id<>o.end_to_end_id OR
        i.account_id<>o.to_account OR i.amount_cents<>o.amount_cents OR
        f.root_transfer_id IS NULL OR f.sender_account<>o.from_account OR
        f.settled_at<>o.settled_at)`)
            .get() as {
            n: number;
        }).n +
            (this.db.prepare(`SELECT COUNT(*) n FROM psp_inbound_receipts r
        LEFT JOIN pix_transfers p ON p.id=r.root_transfer_id
        WHERE p.id IS NULL OR p.end_to_end_id<>r.end_to_end_id OR
          p.to_account<>r.account_id OR p.amount<>r.amount_cents OR
          p.status NOT IN ('settled','returned_partial','returned_full')`)
                .get() as {
                n: number;
            }).n;
        const inboundSenderDrift = local.inbound_sender_drift +
            (this.db.prepare(`SELECT COUNT(*) n FROM psp_inbound_receipts r
        JOIN pix_transfers p ON p.id=r.root_transfer_id
        LEFT JOIN psp_inbound_sender_facts f ON f.root_transfer_id=r.root_transfer_id
        WHERE f.root_transfer_id IS NULL OR f.sender_account<>p.from_account OR
          f.settled_at<>p.settled_at`)
                .get() as {
                n: number;
            }).n;
        const rootFactDrift = local.root_fact_drift + legacyRootDrift;
        return { ...local, ok: local.ok && medHoldDrift === 0 && legacyRootDrift === 0 &&
                inboundPending === 0 && inboundReceiptDrift === 0 && inboundSenderDrift === 0,
            root_fact_drift: rootFactDrift, med_hold_drift: medHoldDrift,
            inbound_pending: inboundPending, inbound_receipt_drift: inboundReceiptDrift,
            inbound_sender_drift: inboundSenderDrift };
    }
    reconcileCardSettlement(): {
        ok: boolean;
        mismatches: number;
    } {
        const exists = this.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='card_settlement_file'`).get();
        if (!exists) {
            const networkExists = this.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
        AND name='card_network_authorizations'`).get();
            return { ok: !networkExists, mismatches: networkExists ? 1 : 0 };
        }
        const row = this.db.prepare(`WITH expected AS (
        SELECT ref_type,ref_id,amount_cents amount,COUNT(*) items FROM card_settlement_file
        GROUP BY ref_type,ref_id,amount_cents
      ), actual AS (
        SELECT l.ref_type,l.ref_id,l.amount,COUNT(*) items FROM ledger_entries l
        WHERE l.account_id=? AND ((l.ref_type='card_auth' AND l.ref_id IN
          (SELECT id FROM card_network_authorizations)) OR
          (l.ref_type='card_dispute' AND l.ref_id IN (SELECT id FROM card_disputes)))
        GROUP BY l.ref_type,l.ref_id,l.amount
      ), refs AS (
        SELECT ref_type,ref_id,amount FROM expected
        UNION SELECT ref_type,ref_id,amount FROM actual
      ) SELECT COUNT(*) mismatches FROM refs r
      LEFT JOIN expected e ON e.ref_type=r.ref_type AND e.ref_id=r.ref_id
        AND e.amount=r.amount
      LEFT JOIN actual a ON a.ref_type=r.ref_type AND a.ref_id=r.ref_id
        AND a.amount=r.amount
      WHERE COALESCE(e.items,0)<>COALESCE(a.items,0)`).get(this.systemAccountId("card_settlement")) as {
            mismatches: number;
        };
        const acquirerExists = this.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name='card_acquirer_balances'`).get();
        if (!acquirerExists)
            return { ok: false, mismatches: row.mismatches + 1 };
        const acquirer = this.db.prepare(`WITH items AS (
        SELECT a.merchant_id,f.amount_cents amount FROM card_settlement_file f
          JOIN card_network_authorizations a ON f.ref_type='card_auth' AND f.ref_id=a.id
        UNION ALL
        SELECT a.merchant_id,f.amount_cents amount FROM card_settlement_file f
          JOIN card_disputes d ON f.ref_type='card_dispute' AND f.ref_id=d.id
          JOIN card_network_authorizations a ON a.id=d.authorization_id
      ), totals AS (
        SELECT merchant_id,SUM(amount) amount FROM items GROUP BY merchant_id
      ) SELECT COUNT(*) mismatches FROM card_merchants m
      LEFT JOIN card_acquirer_balances b ON b.merchant_id=m.id
      LEFT JOIN totals t ON t.merchant_id=m.id
      WHERE b.merchant_id IS NULL OR b.balance_cents<>COALESCE(t.amount,0)`)
            .get() as {
            mismatches: number;
        };
        const mismatches = row.mismatches + acquirer.mismatches;
        return { ok: mismatches === 0, mismatches };
    }
    reconcile(): {
        ok: boolean;
        unbalancedTx: number;
        accountDrift: number;
        belowFloor: number;
        medDrift: number;
        roundingDrift: number;
    } {
        const unbalancedTx = (this.db.prepare("SELECT COUNT(*) n FROM (SELECT tx_id FROM ledger_entries GROUP BY tx_id HAVING SUM(amount)<>0)").get() as {
            n: number;
        }).n;
        const accountDrift = (this.db.prepare(`SELECT COUNT(*) n FROM accounts a LEFT JOIN
      (SELECT account_id,SUM(amount) total FROM ledger_entries GROUP BY account_id) l ON l.account_id=a.id
      WHERE a.balance_cached<>COALESCE(l.total,0)`).get() as {
            n: number;
        }).n;
        const belowFloor = (this.db.prepare("SELECT COUNT(*) n FROM accounts WHERE kind<>'system' AND balance_cached < -overdraft_limit").get() as {
            n: number;
        }).n;
        const medDrift = (this.db.prepare(`SELECT COUNT(*) n FROM med_cases m
      JOIN pix_transfers p ON p.id=m.transfer_id LEFT JOIN
      (SELECT case_id,SUM(amount) total,COUNT(*) refunds FROM med_refunds GROUP BY case_id) r ON r.case_id=m.id
      LEFT JOIN (SELECT transfer_id,SUM(amount) total FROM pix_returns GROUP BY transfer_id) o
        ON o.transfer_id=p.id
      WHERE m.refunded_cents<>COALESCE(r.total,0) OR
      COALESCE(r.total,0)>COALESCE(m.claim_amount_cents,p.amount) OR
      (m.status<>'rejected' AND
        COALESCE(m.claim_amount_cents,p.amount)+COALESCE(o.total,0)<>p.amount) OR
      COALESCE(r.refunds,0)>1 OR
      (m.status='rejected' AND (m.refunded_cents<>0 OR
        m.unrecovered_cents<>0 OR COALESCE(r.refunds,0)<>0)) OR
      (m.status='refunded' AND m.refunded_cents<>
        COALESCE(m.claim_amount_cents,p.amount)) OR
      (m.status='resolved' AND m.refunded_cents+m.unrecovered_cents<>
        COALESCE(m.claim_amount_cents,p.amount))`)
            .get() as {
            n: number;
        }).n;
        const roundingDrift = (this.db.prepare("SELECT ABS(balance_cached) amount FROM accounts WHERE kind='system' AND system_role='rounding'")
            .get() as {
            amount: number;
        } | undefined)?.amount ?? 0;
        return { ok: unbalancedTx === 0 && accountDrift === 0 && belowFloor === 0 && medDrift === 0 && roundingDrift < 500,
            unbalancedTx, accountDrift, belowFloor, medDrift, roundingDrift };
    }
    periodClose(): {
        brt_date: string;
        ledger_entries_count: number;
        ledger_sum: number;
    } {
        if (brtHour(this.now()) !== 3)
            throw new BankError("BIZ_PERIOD_CLOSE_WINDOW");
        if (!this.periodCloseAnchor && this.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='period_close_anchor_registry'`).get() &&
            this.db.prepare("SELECT 1 FROM period_close_anchor_registry WHERE id=1").get())
            throw new BankError("INTEGRITY_PERIOD_CLOSE_ANCHOR_REQUIRED");
        this.periodCloseAnchor?.verify();
        if (this.periodCloseAnchor && this.db.isTransaction)
            throw new BankError("INTEGRITY_PERIOD_CLOSE_ANCHOR_TRANSACTION");
        const date = brtNightKey(this.now());
        const creditCardsOk = (): boolean => !this.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
        AND name='credit_card_accounts'`).get() ||
            new CreditCardsEngine(this, SYNTHETIC_CREDIT_CARD_POLICY_V1).reconcileAll().ok;
        let prepared: {
            date: string;
            sha256: string;
        } | undefined;
        const result = this.transaction(() => {
            const existing = this.db.prepare(`SELECT brt_date,ledger_entries_count,ledger_sum,
        chart_version,cutoff_policy_version FROM period_closes WHERE brt_date=?`)
                .get(date) as {
                brt_date: string;
                ledger_entries_count: number;
                ledger_sum: number;
                chart_version: number;
                cutoff_policy_version: number;
            } | undefined;
            if (existing) {
                const seal = verifyPeriodCloseSeal(this.db, date);
                if (!seal || seal === "legacy_missing")
                    throw new BankError("INTEGRITY_PERIOD_CLOSE_BLOCKED");
                if (!this.reconcile().ok || !this.reconcileSpi().ok || !this.reconcilePsp().ok ||
                    !this.verifyLedgerChain() || !verifyAccountingDates(this.db) || !this.reconcileCardSettlement().ok ||
                    !this.closedCreditReconciliation().ok || !creditCardsOk() ||
                    !reconcileLoanContracts(this.db) || !reconcileLoanProvisions(this.db) ||
                    !reconcileLoanInterestAccruals(this.db) ||
                    !reconcilePeriodResultTransfers(this.db))
                    throw new BankError("INTEGRITY_PERIOD_CLOSE_BLOCKED");
                if (existing.cutoff_policy_version === PERIOD_CUTOFF_POLICY_VERSION &&
                    existing.chart_version === CHART_VERSION) {
                    const stored = this.db.prepare(`SELECT lines_json,debit_cents,credit_cents
            FROM period_trial_balances WHERE brt_date=?`).get(date) as {
                        lines_json: string;
                        debit_cents: number;
                        credit_cents: number;
                    } | undefined;
                    const projected = trialBalanceAtDate(this.db, date);
                    const debit = projected.lines.reduce((sum, line) => sum + line.debit_cents, 0);
                    const credit = projected.lines.reduce((sum, line) => sum + line.credit_cents, 0);
                    if (!stored || stored.lines_json !== JSON.stringify(projected.lines) ||
                        stored.debit_cents !== debit || stored.credit_cents !== credit ||
                        existing.ledger_entries_count !== projected.ledger_entries_count ||
                        existing.ledger_sum !== projected.ledger_sum)
                        throw new BankError("INTEGRITY_PERIOD_CLOSE_BLOCKED");
                }
                return { brt_date: existing.brt_date,
                    ledger_entries_count: existing.ledger_entries_count,
                    ledger_sum: existing.ledger_sum };
            }
            if (!reconcileLoanContracts(this.db) || !reconcileLoanProvisions(this.db) ||
                !reconcileLoanInterestAccruals(this.db) ||
                !reconcilePeriodResultTransfers(this.db))
                throw new BankError("INTEGRITY_PERIOD_CLOSE_BLOCKED");
            bookLoanInterestAccruals(this, date);
            bookLoanProvisions(this, date);
            const integrity = this.reconcile();
            if (!integrity.ok || !this.reconcileSpi().ok || !this.reconcilePsp().ok ||
                !this.reconcileCardSettlement().ok ||
                !this.verifyLedgerChain() || !verifyAccountingDates(this.db) ||
                !this.closedCreditReconciliation().ok || !creditCardsOk() ||
                !reconcileLoanContracts(this.db) || !reconcileLoanProvisions(this.db) ||
                !reconcileLoanInterestAccruals(this.db) ||
                !reconcilePeriodResultTransfers(this.db))
                throw new BankError("INTEGRITY_PERIOD_CLOSE_BLOCKED");
            const { lines, ledger_entries_count, ledger_sum } = trialBalanceAtDate(this.db, date);
            const debit = lines.reduce((sum, line) => sum + line.debit_cents, 0);
            const credit = lines.reduce((sum, line) => sum + line.credit_cents, 0);
            if (debit !== credit || !Number.isSafeInteger(debit))
                throw new BankError("INTEGRITY_TRIAL_BALANCE_BLOCKED");
            this.db.prepare(`INSERT INTO period_closes
        (brt_date,closed_at,ledger_entries_count,ledger_sum,integrity_json,chart_version,
          calendar_version,cutoff_policy_version) VALUES (?,?,?,?,?,?,?,?)`)
                .run(date, this.now().toISOString(), ledger_entries_count, ledger_sum, JSON.stringify(integrity), CHART_VERSION, ACCOUNTING_CALENDAR_VERSION, PERIOD_CUTOFF_POLICY_VERSION);
            this.db.prepare("INSERT INTO period_trial_balances VALUES (?,?,?,?)")
                .run(date, JSON.stringify(lines), debit, credit);
            recordPeriodResultTransfer(this, date, lines);
            if (!reconcilePeriodResultTransfers(this.db))
                throw new BankError("INTEGRITY_PERIOD_CLOSE_BLOCKED");
            const sha256 = recordPeriodCloseSeal(this.db, date, this.now().toISOString());
            this.periodCloseAnchor?.prepare(date, sha256);
            prepared = { date, sha256 };
            return { brt_date: date, ledger_entries_count, ledger_sum };
        });
        if (prepared)
            this.periodCloseAnchor?.confirm(prepared.date, prepared.sha256);
        return result;
    }
    configurePeriodCloseAnchor(anchor: {
        verify: () => void;
        prepare: (date: string, sha256: string) => void;
        confirm: (date: string, sha256: string) => void;
    }): void {
        if (this.periodCloseAnchor)
            throw new BankError("INTEGRITY_PERIOD_CLOSE_ANCHOR_CONFIGURED");
        this.periodCloseAnchor = anchor;
    }
    close(): void { this.db.close(); }
}
function validCpf(value: unknown): value is string {
    if (typeof value !== "string" || !/^\d{11}$/.test(value) || /^(\d)\1{10}$/.test(value))
        return false;
    const digits = Array.from(value, Number);
    for (let length = 9; length <= 10; length++) {
        const weighted = digits.slice(0, length).reduce((sum, digit, position) => sum + digit * (length + 1 - position), 0);
        const check = (weighted * 10) % 11;
        if (digits[length] !== (check === 10 ? 0 : check))
            return false;
    }
    return true;
}
export function syntheticCpf(index: number): string {
    if (!Number.isSafeInteger(index) || index < 0 || index >= 100000000)
        throw new Error("CPF seed out of range");
    const digits = String(index + 100000000).slice(0, 9).split("").map(Number);
    for (let length = 9; length <= 10; length++) {
        const weighted = digits.reduce((sum, digit, position) => sum + digit * (length + 1 - position), 0);
        const check = (weighted * 10) % 11;
        digits.push(check === 10 ? 0 : check);
    }
    return digits.join("");
}
