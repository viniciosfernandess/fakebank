import { newId } from "./id.ts";
import { Bank, BankError } from "./bank.ts";
import { FeatureRegistry } from "./features.ts";
import { CashbackEngine } from "./cashback.ts";
import { CardVault } from "./ecosystem/card-vault.ts";
import { CreditCardsEngine, SYNTHETIC_CREDIT_CARD_POLICY_V1 } from "./credit-cards.ts";
import { DEVICE_QUARANTINE_V1, deviceQuarantine } from "./device-quarantine.ts";
export interface Card {
    id: string;
    customer_id: string;
    account_id: string;
    parent_id: string | null;
    kind: "debit" | "virtual" | "credit";
    status: "active" | "blocked" | "lost" | "stolen";
    online_enabled: number;
    international_enabled: number;
    limit_cents: number;
    used_cents: number;
    expires_at: string | null;
    effective_limit_cents: number;
    last4: string;
}
export interface CardAuthorization {
    id: string;
    card_id: string;
    amount_cents: number;
    merchant_id: string;
    status: "approved" | "declined";
    ledger_tx_id: string | null;
}
export class CardsEngine {
    readonly bank: Bank;
    readonly features: FeatureRegistry;
    readonly cashback: CashbackEngine;
    readonly vault: CardVault;
    constructor(bank: Bank) {
        this.bank = bank;
        this.features = new FeatureRegistry(bank);
        new CreditCardsEngine(bank, SYNTHETIC_CREDIT_CARD_POLICY_V1);
        bank.db.exec(`CREATE TABLE IF NOT EXISTS cards (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      account_id TEXT NOT NULL REFERENCES accounts(id), parent_id TEXT REFERENCES cards(id),
      kind TEXT NOT NULL, status TEXT NOT NULL, online_enabled INTEGER NOT NULL,
      international_enabled INTEGER NOT NULL, limit_cents INTEGER NOT NULL,
      used_cents INTEGER NOT NULL DEFAULT 0, expires_at TEXT, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS cards_customer ON cards(customer_id);
    CREATE TABLE IF NOT EXISTS card_authorizations (
      id TEXT PRIMARY KEY, card_id TEXT NOT NULL REFERENCES cards(id), amount_cents INTEGER NOT NULL,
      merchant_id TEXT NOT NULL, status TEXT NOT NULL, ledger_tx_id TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS card_auth_card_time ON card_authorizations(card_id,created_at);
    CREATE TABLE IF NOT EXISTS card_refunds (
      id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL REFERENCES card_authorizations(id),
      target_card_id TEXT NOT NULL REFERENCES cards(id), amount_cents INTEGER NOT NULL,
      ledger_tx_id TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS card_changes (
      id TEXT PRIMARY KEY, card_id TEXT NOT NULL REFERENCES cards(id), field TEXT NOT NULL,
      old_value TEXT, new_value TEXT NOT NULL, approved_request_id TEXT, changed_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS card_reactivation_caps (
      id TEXT PRIMARY KEY, card_id TEXT NOT NULL REFERENCES cards(id),
      device_id TEXT NOT NULL REFERENCES auth_devices(id),
      cap_cents INTEGER NOT NULL CHECK(cap_cents>0),
      baseline_used_cents INTEGER NOT NULL CHECK(baseline_used_cents>=0),
      expires_at TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS card_reactivation_caps_active
      ON card_reactivation_caps(card_id,expires_at,cap_cents);
    CREATE TRIGGER IF NOT EXISTS card_reactivation_caps_no_update
      BEFORE UPDATE ON card_reactivation_caps BEGIN
        SELECT RAISE(ABORT, 'CARD_REACTIVATION_CAP_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS card_reactivation_caps_no_delete
      BEFORE DELETE ON card_reactivation_caps BEGIN
        SELECT RAISE(ABORT, 'CARD_REACTIVATION_CAP_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS temporary_cards (
      card_id TEXT PRIMARY KEY REFERENCES cards(id), expires_at TEXT NOT NULL,
      grace_until TEXT NOT NULL, capture_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS credit_card_links (
      card_id TEXT PRIMARY KEY REFERENCES cards(id),
      credit_id TEXT NOT NULL UNIQUE REFERENCES credit_card_accounts(id)
    );`);
        this.vault = new CardVault(bank);
        this.cashback = new CashbackEngine(bank);
    }
    card(id: string): Card {
        const row = this.bank.db.prepare(`SELECT id,customer_id,account_id,parent_id,kind,status,online_enabled,
      international_enabled,limit_cents,used_cents,expires_at FROM cards WHERE id=?`).get(id) as Omit<Card, "last4" | "effective_limit_cents"> | undefined;
        if (!row)
            throw new BankError("DEF_NOT_FOUND");
        return { ...row, effective_limit_cents: this.effectiveLimit(row), last4: this.vault.last4(id) };
    }
    ownCard(customerId: string, cardId: string): Card {
        const card = this.card(cardId);
        if (card.customer_id !== customerId)
            throw new BankError("DEF_NOT_FOUND");
        return card;
    }
    list(customerId: string): Card[] {
        const rows = this.bank.db.prepare(`SELECT id,customer_id,account_id,parent_id,kind,status,online_enabled,
      international_enabled,limit_cents,used_cents,expires_at FROM cards WHERE customer_id=? ORDER BY created_at,id`)
            .all(customerId) as unknown as Omit<Card, "last4" | "effective_limit_cents">[];
        return rows.map((row) => ({ ...row, effective_limit_cents: this.effectiveLimit(row),
            last4: this.vault.last4(row.id) }));
    }
    effectiveLimit(card: Pick<Card, "id" | "limit_cents">): number {
        const cap = this.bank.db.prepare(`SELECT MIN(baseline_used_cents+cap_cents) cap
      FROM card_reactivation_caps
      WHERE card_id=? AND expires_at>?`).get(card.id, this.bank.now().toISOString()) as {
            cap: number | null;
        };
        return Math.min(card.limit_cents, cap.cap ?? card.limit_cents);
    }
    private checkDevice(customerId: string, deviceId: string | undefined, limitCents: number): void {
        if (deviceId === undefined)
            return;
        const device = deviceQuarantine(this.bank.db, customerId, deviceId, this.bank.now());
        if (!device)
            throw new BankError("DEF_UNAUTHORIZED");
        if (device.quarantined && limitCents > DEVICE_QUARANTINE_V1.card_limit_cents)
            throw new BankError("BIZ_NEW_DEVICE_LIMIT");
    }
    issueDebit(customerId: string, accountId: string, limitCents = 500000, deviceId?: string): Card {
        if (!Number.isSafeInteger(limitCents) || limitCents <= 0 || limitCents > 2000000)
            throw new BankError("BIZ_INVALID_LIMIT");
        return this.bank.transaction(() => {
            this.checkDevice(customerId, deviceId, limitCents);
            const account = this.bank.ownAccount(customerId, accountId);
            if (account.status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            if (!["checking", "merchant", "payment"].includes(account.kind))
                throw new BankError("BIZ_CARD_ACCOUNT_INVALID");
            const id = newId("card", this.bank.now().getTime());
            this.bank.db.prepare("INSERT INTO cards VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
                .run(id, customerId, accountId, null, "debit", "active", 1, 0, limitCents, 0, null, this.bank.now().toISOString());
            this.vault.ensureCard(id);
            return this.card(id);
        });
    }
    issueCredit(customerId: string, accountId: string, creditId: string): Card {
        return this.bank.transaction(() => {
            const deposit = this.bank.ownAccount(customerId, accountId);
            if (deposit.kind !== "checking" || deposit.status !== "active")
                throw new BankError("BIZ_CREDIT_ACCOUNT_INVALID");
            const credit = this.bank.db.prepare(`SELECT limit_cents,status FROM credit_card_accounts
        WHERE id=? AND customer_id=?`).get(creditId, customerId) as {
                limit_cents: number;
                status: string;
            } | undefined;
            if (!credit || credit.status !== "active")
                throw new BankError("DEF_NOT_FOUND");
            if (this.bank.db.prepare("SELECT 1 FROM credit_card_links WHERE credit_id=?").get(creditId))
                throw new BankError("BIZ_CREDIT_CARD_EXISTS");
            const id = newId("card", this.bank.now().getTime());
            this.bank.db.prepare("INSERT INTO cards VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
                .run(id, customerId, accountId, null, "credit", "active", 1, 0, credit.limit_cents, 0, null, this.bank.now().toISOString());
            this.bank.db.prepare("INSERT INTO credit_card_links VALUES (?,?)").run(id, creditId);
            this.vault.ensureCard(id);
            return this.card(id);
        });
    }
    creditAccountId(cardId: string): string | null {
        return (this.bank.db.prepare("SELECT credit_id FROM credit_card_links WHERE card_id=?")
            .get(cardId) as {
            credit_id: string;
        } | undefined)?.credit_id ?? null;
    }
    createVirtual(customerId: string, parentId: string, limitCents: number, expiresAt?: string, deviceId?: string): Card {
        if (!Number.isSafeInteger(limitCents) || limitCents <= 0)
            throw new BankError("BIZ_INVALID_LIMIT");
        return this.bank.transaction(() => {
            this.checkDevice(customerId, deviceId, limitCents);
            const parent = this.ownCard(customerId, parentId);
            if (parent.kind !== "debit" || parent.status !== "active")
                throw new BankError("BIZ_PARENT_CARD_INACTIVE");
            if (this.bank.account(parent.account_id).status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            const allocated = this.bank.db.prepare(`SELECT COALESCE(SUM(limit_cents),0) amount,COUNT(*) count FROM cards
        WHERE parent_id=? AND status='active'`).get(parentId) as {
                amount: number;
                count: number;
            };
            if (allocated.count >= 5)
                throw new BankError("BIZ_VIRTUAL_CARD_LIMIT");
            if (allocated.amount + limitCents > this.effectiveLimit(parent) - parent.used_cents)
                throw new BankError("BIZ_PARENT_LIMIT");
            const id = newId("card", this.bank.now().getTime());
            const expiry = expiresAt === undefined ? null : new Date(expiresAt).toISOString();
            this.bank.db.prepare("INSERT INTO cards VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
                .run(id, customerId, parent.account_id, parentId, "virtual", "active", 1, 0, limitCents, 0, expiry, this.bank.now().toISOString());
            this.vault.ensureCard(id);
            return this.card(id);
        });
    }
    createTemporaryVirtual(customerId: string, parentId: string, limitCents: number, deviceId?: string): Card {
        if (!this.features.isEnabled("cartao_virtual_temporario"))
            throw new BankError("DEF_NOT_FOUND");
        const expires = new Date(this.bank.now().getTime() + 24 * 60 * 60000);
        return this.bank.transaction(() => {
            const card = this.createVirtual(customerId, parentId, limitCents, expires.toISOString(), deviceId);
            this.bank.db.prepare("INSERT INTO temporary_cards VALUES (?,?,?,0)")
                .run(card.id, expires.toISOString(), new Date(expires.getTime() + 10 * 60000).toISOString());
            return card;
        });
    }
    update(customerId: string, cardId: string, patch: Record<string, unknown>, deviceId?: string): Card {
        const card = this.ownCard(customerId, cardId);
        const allowed = new Set(["status", "online_enabled", "international_enabled"]);
        if (!Object.keys(patch).length || Object.keys(patch).some((key) => !allowed.has(key)))
            throw new BankError("BIZ_INVALID_CARD_PATCH");
        for (const [key, value] of Object.entries(patch)) {
            if (key === "status" && value !== "active" && value !== "blocked" &&
                value !== "lost" && value !== "stolen")
                throw new BankError("BIZ_INVALID_CARD_PATCH");
            if ((key === "online_enabled" || key === "international_enabled") && typeof value !== "boolean")
                throw new BankError("BIZ_INVALID_CARD_PATCH");
            if (key === "limit_cents" && (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > 20000000))
                throw new BankError("BIZ_INVALID_CARD_PATCH");
        }
        this.bank.transaction(() => {
            const current = this.ownCard(customerId, cardId);
            if ((current.status === "lost" || current.status === "stolen") &&
                patch.status !== undefined && patch.status !== current.status)
                throw new BankError("BIZ_CARD_REPLACEMENT_REQUIRED");
            if (typeof patch.limit_cents === "number")
                this.checkDevice(customerId, deviceId, patch.limit_cents);
            if (patch.status === "active" && current.status === "blocked" && deviceId !== undefined) {
                const device = deviceQuarantine(this.bank.db, customerId, deviceId, this.bank.now());
                if (!device)
                    throw new BankError("DEF_UNAUTHORIZED");
                if (device.quarantined && current.limit_cents > DEVICE_QUARANTINE_V1.card_limit_cents)
                    this.bank.db.prepare(`INSERT INTO card_reactivation_caps
            (id,card_id,device_id,cap_cents,baseline_used_cents,expires_at,created_at)
            VALUES (?,?,?,?,?,?,?)`)
                        .run(newId("cardcap", this.bank.now().getTime()), cardId, deviceId, DEVICE_QUARANTINE_V1.card_limit_cents, current.used_cents, device.quarantineEndsAt, this.bank.now().toISOString());
            }
            if (patch.status === "active" && this.bank.account(current.account_id).status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            for (const [key, value] of Object.entries(patch)) {
                const stored = typeof value === "boolean" ? Number(value) : value;
                this.bank.db.prepare(`UPDATE cards SET ${key}=? WHERE id=?`).run(stored as string | number, cardId);
                const old = current[key as keyof Card];
                this.bank.db.prepare("INSERT INTO card_changes VALUES (?,?,?,?,?,NULL,?)")
                    .run(newId("change", this.bank.now().getTime()), cardId, key, old === null ? null : String(old), String(stored), this.bank.now().toISOString());
            }
            this.bank.log({ actor: customerId, kind: "card_updated", customerId,
                accountId: card.account_id, cardId, route: "cards.update", status: 200 });
        });
        return this.card(cardId);
    }
    authorize(cardId: string, merchantId: string, amountCents: number): CardAuthorization {
        if (!Number.isSafeInteger(amountCents) || amountCents <= 0)
            throw new BankError("BIZ_INVALID_AMOUNT");
        if (!merchantId || merchantId.length > 128)
            throw new BankError("BIZ_INVALID_MERCHANT");
        const owner = this.card(cardId);
        if (owner.kind === "credit")
            throw new BankError("BIZ_CREDIT_NETWORK_REQUIRED");
        this.bank.log({ actor: merchantId, kind: "card_authorize_attempt", customerId: owner.customer_id,
            accountId: owner.account_id, cardId, route: cardId, status: 0 });
        return this.bank.transaction(() => {
            const card = this.card(cardId);
            const root = card.parent_id ? this.card(card.parent_id) : card;
            if (this.bank.account(card.account_id).status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            const temporary = this.bank.db.prepare("SELECT expires_at,grace_until,capture_count FROM temporary_cards WHERE card_id=?")
                .get(cardId) as {
                expires_at: string;
                grace_until: string;
                capture_count: number;
            } | undefined;
            if (card.status !== "active" || root.status !== "active" || !card.online_enabled)
                throw new BankError("BIZ_CARD_BLOCKED");
            if (temporary && !this.features.isEnabled("cartao_virtual_temporario"))
                throw new BankError("BIZ_CARD_BLOCKED");
            if (card.expires_at && Date.parse(card.expires_at) <= this.bank.now().getTime())
                throw new BankError("BIZ_CARD_EXPIRED");
            if (temporary && temporary.capture_count >= 1)
                throw new BankError("BIZ_SINGLE_USE_CARD");
            const since = new Date(this.bank.now().getTime() - 60000).toISOString();
            const count = (this.bank.db.prepare("SELECT COUNT(*) n FROM card_authorizations WHERE card_id=? AND created_at>=?")
                .get(cardId, since) as {
                n: number;
            }).n;
            if (count >= 10)
                throw new BankError("BIZ_CARD_VELOCITY");
            if (card.used_cents + amountCents > this.effectiveLimit(card) ||
                root.used_cents + amountCents > this.effectiveLimit(root))
                throw new BankError("BIZ_CARD_LIMIT");
            if (this.bank.availableBalance(card.account_id) < amountCents)
                throw new BankError("BIZ_INSUFFICIENT_FUNDS");
            const id = newId("auth", this.bank.now().getTime());
            const ledgerTxId = this.bank.post([
                { accountId: card.account_id, amount: -amountCents, kind: "card_purchase", actor: card.customer_id, refType: "card_auth", refId: id },
                { accountId: this.bank.systemAccountId("card_settlement"), amount: amountCents, kind: "card_purchase", actor: card.customer_id, refType: "card_auth", refId: id },
            ]);
            this.bank.db.prepare("INSERT INTO card_authorizations VALUES (?,?,?,?,?,?,?)")
                .run(id, cardId, amountCents, merchantId, "approved", ledgerTxId, this.bank.now().toISOString());
            this.bank.db.prepare("UPDATE cards SET used_cents=used_cents+? WHERE id=?").run(amountCents, cardId);
            if (card.parent_id)
                this.bank.db.prepare("UPDATE cards SET used_cents=used_cents+? WHERE id=?").run(amountCents, root.id);
            if (temporary)
                this.bank.db.prepare("UPDATE temporary_cards SET capture_count=capture_count+1 WHERE card_id=?").run(cardId);
            this.cashback.onPurchase(id, card.customer_id, card.account_id, amountCents);
            return { id, card_id: cardId, amount_cents: amountCents, merchant_id: merchantId,
                status: "approved", ledger_tx_id: ledgerTxId };
        });
    }
    refund(authorizationId: string, targetCardId: string, amountCents: number): {
        id: string;
        ledger_tx_id: string;
    } {
        if (!Number.isSafeInteger(amountCents) || amountCents <= 0)
            throw new BankError("BIZ_INVALID_AMOUNT");
        return this.bank.transaction(() => {
            const auth = this.bank.db.prepare("SELECT card_id,amount_cents,status FROM card_authorizations WHERE id=?")
                .get(authorizationId) as {
                card_id: string;
                amount_cents: number;
                status: string;
            } | undefined;
            if (!auth || auth.status !== "approved")
                throw new BankError("DEF_NOT_FOUND");
            const disputesExist = this.bank.db.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='card_disputes'`).get();
            const dispute = disputesExist ? this.bank.db.prepare(`SELECT status,amount_cents
        FROM card_disputes WHERE authorization_id=?`).get(authorizationId) as {
                status: string;
                amount_cents: number;
            } | undefined : undefined;
            if (dispute && dispute.status !== "merchant_won" && dispute.status !== "customer_won")
                throw new BankError("BIZ_DISPUTE_REFUND_CONFLICT");
            const original = this.card(auth.card_id);
            const target = this.card(targetCardId);
            if (target.customer_id !== original.customer_id)
                throw new BankError("DEF_NOT_FOUND");
            if (original.kind === "credit") {
                if (target.id !== original.id)
                    throw new BankError("BIZ_REFUND_CARD_MISMATCH");
                const creditId = this.creditAccountId(original.id);
                const purchase = creditId ? this.bank.db.prepare(`SELECT id FROM credit_card_purchases
          WHERE network_authorization_id=? AND credit_id=?`).get(authorizationId, creditId) as {
                    id: string;
                } | undefined : undefined;
                const networkAuth = this.bank.db.prepare(`SELECT merchant_id FROM card_network_authorizations
          WHERE id=? AND status='captured'`).get(authorizationId) as {
                    merchant_id: string;
                } | undefined;
                if (!creditId || !purchase || !networkAuth)
                    throw new BankError("INTEGRITY_CREDIT_CARD_NETWORK");
                const refunded = (this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) n
          FROM card_refunds WHERE authorization_id=?`).get(authorizationId) as {
                    n: number;
                }).n;
                const won = dispute?.status === "customer_won" ? dispute.amount_cents : 0;
                if (refunded + amountCents > auth.amount_cents - won)
                    throw new BankError("BIZ_REFUND_EXCEEDS_AUTH");
                new CreditCardsEngine(this.bank, SYNTHETIC_CREDIT_CARD_POLICY_V1)
                    .refund(original.customer_id, creditId, purchase.id, amountCents);
                const ledgerTxId = this.bank.post([
                    { accountId: this.bank.systemAccountId("card_settlement"), amount: -amountCents,
                        kind: "card_network_credit_refund", actor: "merchant",
                        refType: "card_auth", refId: authorizationId },
                    { accountId: this.bank.systemAccountId("cash_out"), amount: amountCents,
                        kind: "card_network_credit_refund", actor: "merchant",
                        refType: "card_auth", refId: authorizationId },
                ]);
                this.bank.db.prepare(`INSERT INTO card_settlement_file
          (id,ref_type,ref_id,amount_cents,created_at) VALUES (?,?,?,?,?)`)
                    .run(newId("clearing", this.bank.now().getTime()), "card_auth", authorizationId, -amountCents, this.bank.now().toISOString());
                this.bank.db.prepare(`UPDATE card_acquirer_balances
          SET balance_cents=balance_cents-? WHERE merchant_id=?`)
                    .run(amountCents, networkAuth.merchant_id);
                const id = newId("refund", this.bank.now().getTime());
                this.bank.db.prepare("INSERT INTO card_refunds VALUES (?,?,?,?,?,?)")
                    .run(id, authorizationId, targetCardId, amountCents, ledgerTxId, this.bank.now().toISOString());
                return { id, ledger_tx_id: ledgerTxId };
            }
            if (target.id !== original.id)
                throw new BankError("BIZ_REFUND_CARD_MISMATCH");
            const refunded = (this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) n FROM card_refunds
        WHERE authorization_id=? `)
                .get(...([authorizationId])) as {
                n: number;
            }).n;
            const won = dispute?.status === "customer_won" ? dispute.amount_cents : 0;
            if (refunded + amountCents > auth.amount_cents - won)
                throw new BankError("BIZ_REFUND_EXCEEDS_AUTH");
            const id = newId("refund", this.bank.now().getTime());
            const ledgerTxId = this.bank.post([
                { accountId: this.bank.systemAccountId("card_settlement"), amount: -amountCents, kind: "card_refund", actor: "merchant", refType: "card_auth", refId: authorizationId },
                { accountId: target.account_id, amount: amountCents, kind: "card_refund", actor: "merchant", refType: "card_auth", refId: authorizationId },
            ]);
            const networkAuth = this.bank.db.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='card_network_authorizations'`).get()
                ? this.bank.db.prepare(`SELECT merchant_id FROM card_network_authorizations
          WHERE id=?`).get(authorizationId) as {
                    merchant_id: string;
                } | undefined
                : undefined;
            if (networkAuth) {
                this.bank.db.prepare(`INSERT INTO card_settlement_file
          (id,ref_type,ref_id,amount_cents,created_at) VALUES (?,?,?,?,?)`)
                    .run(newId("clearing", this.bank.now().getTime()), "card_auth", authorizationId, -amountCents, this.bank.now().toISOString());
                this.bank.db.prepare(`UPDATE card_acquirer_balances
          SET balance_cents=balance_cents-? WHERE merchant_id=?`)
                    .run(amountCents, networkAuth.merchant_id);
            }
            this.bank.db.prepare("INSERT INTO card_refunds VALUES (?,?,?,?,?,?)")
                .run(id, authorizationId, targetCardId, amountCents, ledgerTxId, this.bank.now().toISOString());
            this.bank.db.prepare("UPDATE cards SET used_cents=MAX(0,used_cents-?) WHERE id=?").run(amountCents, target.id);
            if (target.parent_id)
                this.bank.db.prepare("UPDATE cards SET used_cents=MAX(0,used_cents-?) WHERE id=?")
                    .run(amountCents, target.parent_id);
            this.cashback.onRefund(authorizationId, amountCents);
            return { id, ledger_tx_id: ledgerTxId };
        });
    }
    refundDrift(): number {
        return (this.bank.db.prepare(`SELECT COUNT(*) n FROM card_authorizations a LEFT JOIN
      (SELECT r.authorization_id,SUM(r.amount_cents) total,MAX(r.target_card_id<>a.card_id) mismatch
       FROM card_refunds r JOIN card_authorizations a ON a.id=r.authorization_id GROUP BY authorization_id) r
      ON r.authorization_id=a.id WHERE COALESCE(r.total,0)>a.amount_cents OR COALESCE(r.mismatch,0)>0`)
            .get() as {
            n: number;
        }).n;
    }
}
