import { newId } from "./id.ts";
import { createHash, randomBytes } from "node:crypto";
import { Bank, BankError } from "./bank.ts";
import { FeatureRegistry } from "./features.ts";
export type DataScope = "balance" | "statement";
function tokenHash(token: string): string { return createHash("sha256").update(token).digest("hex"); }
export class DataSharing {
    readonly bank: Bank;
    readonly features: FeatureRegistry;
    constructor(bank: Bank, features: FeatureRegistry) {
        this.bank = bank;
        this.features = features;
        bank.db.exec(`CREATE TABLE IF NOT EXISTS data_consents (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id), partner_id TEXT NOT NULL,
      scopes_json TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
      revoked_at TEXT, granted_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS data_share_reads (
      id TEXT PRIMARY KEY, consent_id TEXT NOT NULL REFERENCES data_consents(id),
      scope TEXT NOT NULL, read_at TEXT NOT NULL, was_revoked INTEGER NOT NULL,
      scope_granted INTEGER NOT NULL
    );`);
    }
    grant(customerId: string, partnerId: string, scopes: DataScope[]): {
        consent_id: string;
        token: string;
        expires_at: string;
    } {
        if (!this.features.isEnabled("compartilhar_dados"))
            throw new BankError("DEF_NOT_FOUND");
        this.bank.customer(customerId);
        if (!/^[a-zA-Z0-9_-]{3,64}$/.test(partnerId) || !scopes.length ||
            scopes.some((scope) => scope !== "balance" && scope !== "statement") || new Set(scopes).size !== scopes.length)
            throw new BankError("BIZ_INVALID_CONSENT");
        const id = newId("consent", this.bank.now().getTime());
        const token = randomBytes(32).toString("base64url");
        const expires = new Date(this.bank.now().getTime() + 24 * 60 * 60000).toISOString();
        this.bank.db.prepare("INSERT INTO data_consents VALUES (?,?,?,?,?,?,NULL,?)")
            .run(id, customerId, partnerId, JSON.stringify(scopes), tokenHash(token), expires, this.bank.now().toISOString());
        return { consent_id: id, token, expires_at: expires };
    }
    revoke(customerId: string, consentId: string): void {
        const result = this.bank.db.prepare("UPDATE data_consents SET revoked_at=? WHERE id=? AND customer_id=? AND revoked_at IS NULL")
            .run(this.bank.now().toISOString(), consentId, customerId);
        if (result.changes !== 1)
            throw new BankError("DEF_NOT_FOUND");
    }
    read(token: string, scope: DataScope): {
        customer_id: string;
        scope: DataScope;
        data: unknown;
    } {
        if (!this.features.isEnabled("compartilhar_dados"))
            throw new BankError("DEF_NOT_FOUND");
        if (scope !== "balance" && scope !== "statement")
            throw new BankError("BIZ_INVALID_SCOPE");
        const row = this.bank.db.prepare(`SELECT id,customer_id,scopes_json,expires_at,revoked_at
      FROM data_consents WHERE token_hash=?`).get(tokenHash(token)) as {
            id: string;
            customer_id: string;
            scopes_json: string;
            expires_at: string;
            revoked_at: string | null;
        } | undefined;
        if (!row || Date.parse(row.expires_at) <= this.bank.now().getTime())
            throw new BankError("DEF_CONSENT_INVALID");
        const granted = (JSON.parse(row.scopes_json) as DataScope[]).includes(scope);
        if ((row.revoked_at || !granted))
            throw new BankError("DEF_CONSENT_INVALID");
        const account = this.bank.db.prepare(`SELECT id,balance_cached FROM accounts WHERE customer_id=?
      ORDER BY id LIMIT 1`).get(row.customer_id) as {
            id: string;
            balance_cached: number;
        } | undefined;
        if (!account)
            throw new BankError("DEF_NOT_FOUND");
        const data = scope === "balance" ? { balance_cents: account.balance_cached }
            : { entries: this.bank.statement(account.id, row.customer_id, 5) };
        this.bank.db.prepare("INSERT INTO data_share_reads VALUES (?,?,?,?,?,?)")
            .run(newId("read", this.bank.now().getTime()), row.id, scope, this.bank.now().toISOString(), Number(Boolean(row.revoked_at)), Number(granted));
        return { customer_id: row.customer_id, scope, data };
    }
}
