import { newId } from "./id.ts";
import { Bank } from "./bank.ts";
import { FeatureRegistry } from "./features.ts";
import { bankersRound } from "./fees.ts";
export class CashbackEngine {
    readonly bank: Bank;
    readonly features: FeatureRegistry;
    constructor(bank: Bank) {
        this.bank = bank;
        this.features = new FeatureRegistry(bank);
        bank.db.exec(`CREATE TABLE IF NOT EXISTS cashback_records (
      id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE REFERENCES card_authorizations(id),
      customer_id TEXT NOT NULL REFERENCES customers(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      purchase_cents INTEGER NOT NULL, rate_bps INTEGER NOT NULL, credited_cents INTEGER NOT NULL,
      clawed_back_cents INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS cashback_customer_time ON cashback_records(customer_id,created_at);`);
    }
    onPurchase(authorizationId: string, customerId: string, accountId: string, purchaseCents: number): void {
        if (!this.features.isEnabled("cashback"))
            return;
        const rateBps = 100 + this.bank.customer(customerId).risk_score % 3 * 100;
        const nominalCredit = bankersRound(purchaseCents * rateBps, 10000);
        if (nominalCredit <= 0)
            return;
        const month = this.bank.now().toISOString().slice(0, 7);
        const creditedThisMonth = (this.bank.db.prepare(`SELECT COALESCE(SUM(credited_cents),0) total FROM cashback_records
      WHERE customer_id=? AND substr(created_at,1,7)=?`).get(customerId, month) as {
            total: number;
        }).total;
        const merchantWeak = false;
        const credit = Math.min(nominalCredit, merchantWeak ? nominalCredit : Math.max(0, 5000 - creditedThisMonth), Math.max(0, this.bank.account(this.bank.systemAccountId("cashback_pool")).balance_cached));
        if (credit <= 0)
            return;
        this.bank.post([
            { accountId: this.bank.systemAccountId("cashback_pool"), amount: -credit, kind: "cashback", actor: "cashback", refType: "card_auth", refId: authorizationId },
            { accountId, amount: credit, kind: "cashback", actor: "cashback", refType: "card_auth", refId: authorizationId },
        ]);
        this.bank.db.prepare("INSERT INTO cashback_records VALUES (?,?,?,?,?,?,?,0,?)")
            .run(newId("cashback", this.bank.now().getTime()), authorizationId, customerId, accountId, purchaseCents, rateBps, credit, this.bank.now().toISOString());
    }
    onRefund(authorizationId: string, refundCents: number): void {
        if (!this.features.isEnabled("cashback"))
            return;
        const row = this.bank.db.prepare(`SELECT id,account_id,purchase_cents,credited_cents,clawed_back_cents
      FROM cashback_records WHERE authorization_id=?`).get(authorizationId) as {
            id: string;
            account_id: string;
            purchase_cents: number;
            credited_cents: number;
            clawed_back_cents: number;
        } | undefined;
        if (!row)
            return;
        const toClaw = Math.min(row.credited_cents - row.clawed_back_cents, bankersRound(row.credited_cents * refundCents, row.purchase_cents));
        if (toClaw <= 0)
            return;
        const recovered = Math.min(toClaw, Math.max(0, this.bank.availableBalance(row.account_id)));
        const loss = toClaw - recovered;
        this.bank.post([
            ...(recovered ? [{ accountId: row.account_id, amount: -recovered,
                    kind: "cashback_clawback", actor: "cashback", refType: "card_auth", refId: authorizationId }] : []),
            ...(loss ? [{ accountId: this.bank.systemAccountId("bank_loss"), amount: -loss,
                    kind: "cashback_clawback_loss", actor: "cashback", refType: "card_auth", refId: authorizationId }] : []),
            { accountId: this.bank.systemAccountId("cashback_pool"), amount: toClaw, kind: "cashback_clawback", actor: "cashback", refType: "card_auth", refId: authorizationId },
        ]);
        this.bank.db.prepare("UPDATE cashback_records SET clawed_back_cents=clawed_back_cents+? WHERE id=?")
            .run(toClaw, row.id);
    }
    drift(): number {
        return (this.bank.db.prepare(`SELECT COUNT(*) n FROM cashback_records c JOIN card_authorizations a
      ON a.id=c.authorization_id LEFT JOIN
      (SELECT authorization_id,COALESCE(SUM(amount_cents),0) refunded FROM card_refunds GROUP BY authorization_id) r
      ON r.authorization_id=a.id WHERE c.credited_cents-c.clawed_back_cents >
      (a.amount_cents-COALESCE(r.refunded,0))*c.rate_bps/10000.0 + 1`).get() as {
            n: number;
        }).n;
    }
}
