import { newId } from "./id.ts";
import { Bank, BankError } from "./bank.ts";
import { FeatureRegistry } from "./features.ts";
export class DynamicLimits {
    readonly bank: Bank;
    readonly features: FeatureRegistry;
    constructor(bank: Bank, features: FeatureRegistry) {
        this.bank = bank;
        this.features = features;
        bank.db.exec(`CREATE TABLE IF NOT EXISTS verified_income_events (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      account_id TEXT NOT NULL REFERENCES accounts(id), amount_cents INTEGER NOT NULL,
      source TEXT NOT NULL, ledger_tx_id TEXT NOT NULL, occurred_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS verified_income_customer_time ON verified_income_events(customer_id,occurred_at);
    CREATE TABLE IF NOT EXISTS dynamic_limits (
      customer_id TEXT PRIMARY KEY REFERENCES customers(id), extra_cents INTEGER NOT NULL,
      source_count INTEGER NOT NULL, verified INTEGER NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS dynamic_limit_changes (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      old_extra_cents INTEGER NOT NULL, new_extra_cents INTEGER NOT NULL,
      source_count INTEGER NOT NULL, from_verified INTEGER NOT NULL, changed_at TEXT NOT NULL
    );`);
    }
    recordVerifiedIncome(customerId: string, accountId: string, amountCents: number, source: string): void {
        this.bank.ownAccount(customerId, accountId);
        if (!Number.isSafeInteger(amountCents) || amountCents <= 0 || !/^[a-z0-9_-]{3,64}$/.test(source))
            throw new BankError("BIZ_INVALID_INCOME");
        this.bank.transaction(() => {
            const id = newId("income", this.bank.now().getTime());
            const txId = this.bank.post([
                { accountId: this.bank.systemAccountId("cash_in"), amount: -amountCents, kind: "verified_income", actor: source, refType: "income", refId: id },
                { accountId, amount: amountCents, kind: "verified_income", actor: source, refType: "income", refId: id },
            ]);
            this.bank.db.prepare("INSERT INTO verified_income_events VALUES (?,?,?,?,?,?,?)")
                .run(id, customerId, accountId, amountCents, source, txId, this.bank.now().toISOString());
        });
    }
    recompute(customerId: string): {
        extra_cents: number;
        source_count: number;
        verified: boolean;
    } {
        if (!this.features.isEnabled("limite_dinamico"))
            throw new BankError("DEF_NOT_FOUND");
        this.bank.customer(customerId);
        const since = new Date(this.bank.now().getTime() - 30 * 86400000).toISOString();
        const weak = false;
        const verifiedCount = (this.bank.db.prepare(`SELECT COUNT(*) n FROM verified_income_events
      WHERE customer_id=? AND occurred_at>=?`).get(customerId, since) as {
            n: number;
        }).n;
        const selfTransferCount = weak ? (this.bank.db.prepare(`SELECT COUNT(*) n FROM pix_transfers p
      JOIN accounts src ON src.id=p.from_account JOIN accounts dst ON dst.id=p.to_account
      WHERE src.customer_id=? AND dst.customer_id=? AND p.status='settled' AND p.settled_at>=?`)
            .get(customerId, customerId, since) as {
            n: number;
        }).n : 0;
        const count = verifiedCount + selfTransferCount;
        const verified = !weak || verifiedCount >= 3;
        const extra = count >= 3 ? 100000 : 0;
        const old = this.bank.db.prepare("SELECT extra_cents FROM dynamic_limits WHERE customer_id=?")
            .get(customerId) as {
            extra_cents: number;
        } | undefined;
        this.bank.transaction(() => {
            this.bank.db.prepare(`INSERT INTO dynamic_limits VALUES (?,?,?,?,?) ON CONFLICT(customer_id)
        DO UPDATE SET extra_cents=excluded.extra_cents,source_count=excluded.source_count,
        verified=excluded.verified,updated_at=excluded.updated_at`)
                .run(customerId, extra, count, Number(verified), this.bank.now().toISOString());
            if ((old?.extra_cents ?? 0) !== extra)
                this.bank.db.prepare("INSERT INTO dynamic_limit_changes VALUES (?,?,?,?,?,?,?)")
                    .run(newId("limit", this.bank.now().getTime()), customerId, old?.extra_cents ?? 0, extra, count, Number(verified), this.bank.now().toISOString());
        });
        return { extra_cents: extra, source_count: count, verified };
    }
}
