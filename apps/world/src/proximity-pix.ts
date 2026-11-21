import { newId } from "./id.ts";
import { randomBytes, createHash } from "node:crypto";
import { Bank, BankError, type PixResult } from "./bank.ts";
import { FeatureRegistry } from "./features.ts";
function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
export class ProximityPix {
    readonly bank: Bank;
    readonly features: FeatureRegistry;
    constructor(bank: Bank, features: FeatureRegistry) {
        this.bank = bank;
        this.features = features;
        bank.db.exec(`CREATE TABLE IF NOT EXISTS proximity_tokens (
      id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, customer_id TEXT NOT NULL REFERENCES customers(id),
      from_account TEXT NOT NULL REFERENCES accounts(id), to_account TEXT NOT NULL REFERENCES accounts(id),
      amount_cents INTEGER NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS proximity_uses (
      id TEXT PRIMARY KEY, token_id TEXT NOT NULL REFERENCES proximity_tokens(id),
      transfer_id TEXT NOT NULL REFERENCES pix_transfers(id),
      requested_to TEXT NOT NULL, requested_amount_cents INTEGER NOT NULL, used_at TEXT NOT NULL
    );`);
    }
    issue(customerId: string, from: string, to: string, amountCents: number): {
        token: string;
        token_id: string;
        expires_at: string;
    } {
        if (!this.features.isEnabled("pix_aproximacao"))
            throw new BankError("DEF_NOT_FOUND");
        this.bank.ownAccount(customerId, from);
        this.bank.account(to);
        if (!Number.isSafeInteger(amountCents) || amountCents <= 0 || amountCents > 2000000)
            throw new BankError("BIZ_INVALID_AMOUNT");
        const token = randomBytes(24).toString("base64url");
        const id = newId("proximity", this.bank.now().getTime());
        const expiresAt = new Date(this.bank.now().getTime() + 2 * 60000).toISOString();
        this.bank.db.prepare("INSERT INTO proximity_tokens VALUES (?,?,?,?,?,?,?,NULL,?)")
            .run(id, hash(token), customerId, from, to, amountCents, expiresAt, this.bank.now().toISOString());
        return { token, token_id: id, expires_at: expiresAt };
    }
    redeem(customerId: string, token: string, to: string, amountCents: number, session: {
        deviceId?: string;
        stepUpVerified?: boolean;
    } = {}): PixResult {
        if (!this.features.isEnabled("pix_aproximacao"))
            throw new BankError("DEF_NOT_FOUND");
        if (!Number.isSafeInteger(amountCents) || amountCents <= 0)
            throw new BankError("BIZ_INVALID_AMOUNT");
        let riskError: BankError | undefined;
        let result: PixResult | undefined;
        result = this.bank.transaction(() => {
            const row = this.bank.db.prepare(`SELECT id,customer_id,from_account,to_account,amount_cents,
        expires_at,used_at FROM proximity_tokens WHERE token_hash=?`).get(hash(token)) as {
                id: string;
                customer_id: string;
                from_account: string;
                to_account: string;
                amount_cents: number;
                expires_at: string;
                used_at: string | null;
            } | undefined;
            if (!row || row.customer_id !== customerId)
                throw new BankError("DEF_NOT_FOUND");
            if (Date.parse(row.expires_at) <= this.bank.now().getTime())
                throw new BankError("BIZ_PROXIMITY_EXPIRED");
            {
                const uses = (this.bank.db.prepare("SELECT COUNT(*) n FROM proximity_uses WHERE token_id=?")
                    .get(row.id) as {
                    n: number;
                }).n;
                if (row.used_at || uses)
                    throw new BankError("BIZ_PROXIMITY_USED");
                if (row.to_account !== to || row.amount_cents !== amountCents)
                    throw new BankError("BIZ_PROXIMITY_MISMATCH");
            }
            const pending = this.bank.db.prepare(`SELECT h.id,d.score,d.reason_codes_json
        FROM risk_pix_holds h JOIN risk_decisions d ON d.id=h.risk_decision_id
        WHERE h.proximity_token_id=? AND h.status='pending' LIMIT 1`).get(row.id) as {
                id: string;
                score: number;
                reason_codes_json: string;
            } | undefined;
            if (pending)
                throw new BankError("BIZ_RISK_HOLD", { score: pending.score,
                    reasonCodes: JSON.parse(pending.reason_codes_json) as string[], holdId: pending.id });
            let transfer: PixResult;
            try {
                transfer = this.bank.transferPix({ from: row.from_account, to, amount: amountCents,
                    idempotencyKey: `proximity:${row.id}`,
                    actor: customerId, ...session });
            }
            catch (error) {
                if (error instanceof BankError && error.code === "BIZ_RISK_HOLD" && error.risk?.holdId) {
                    this.bank.db.prepare("UPDATE risk_pix_holds SET proximity_token_id=? WHERE id=?")
                        .run(row.id, error.risk.holdId);
                    riskError = error;
                    return undefined;
                }
                if (error instanceof BankError && error.risk &&
                    ["BIZ_FRAUD_DESTINATION", "BIZ_RISK_DECLINE", "DEF_STEP_UP_REQUIRED"].includes(error.code)) {
                    riskError = error;
                    return undefined;
                }
                throw error;
            }
            this.bank.db.prepare("INSERT INTO proximity_uses VALUES (?,?,?,?,?,?)")
                .run(newId("use", this.bank.now().getTime()), row.id, transfer.id, to, amountCents, this.bank.now().toISOString());
            this.bank.db.prepare("UPDATE proximity_tokens SET used_at=? WHERE id=?").run(this.bank.now().toISOString(), row.id);
            return transfer;
        });
        if (riskError)
            throw riskError;
        return result!;
    }
}
