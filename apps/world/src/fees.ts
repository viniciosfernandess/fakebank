import { newId } from "./id.ts";
import { Bank, BankError } from "./bank.ts";
export function bankersRound(numerator: number, denominator: number): number {
    if (!Number.isSafeInteger(numerator) || numerator < 0 || !Number.isSafeInteger(denominator) || denominator <= 0)
        throw new BankError("BIZ_INVALID_AMOUNT");
    const floor = Math.floor(numerator / denominator);
    const remainder = numerator % denominator;
    return floor + Number(remainder * 2 > denominator || (remainder * 2 === denominator && floor % 2 === 1));
}
export class FeePolicy {
    readonly bank: Bank;
    constructor(bank: Bank) { this.bank = bank; }
    charge(accountId: string, baseCents: number, basisPoints: number, actor: string): {
        transaction_id: string;
        charged_cents: number;
        nominal_cents: number;
        rounding_cents: number;
    } {
        if (!Number.isSafeInteger(baseCents) || baseCents <= 0 || !Number.isSafeInteger(basisPoints) ||
            basisPoints <= 0 || basisPoints > 10000 || !Number.isSafeInteger(baseCents * basisPoints))
            throw new BankError("BIZ_INVALID_AMOUNT");
        return this.bank.transaction(() => {
            const account = this.bank.account(accountId);
            if (account.status !== "active")
                throw new BankError("DEF_ACCOUNT_FROZEN");
            const nominal = bankersRound(baseCents * basisPoints, 10000);
            if (nominal <= 0)
                throw new BankError("BIZ_INVALID_AMOUNT");
            const charged = nominal;
            const rounding = nominal - charged;
            if (this.bank.availableBalance(accountId) < charged)
                throw new BankError("BIZ_INSUFFICIENT_FUNDS");
            const refId = newId("fee", this.bank.now().getTime());
            const postings = [
                { accountId, amount: -charged, kind: "service_fee", actor, refType: "fee", refId },
                { accountId: this.bank.systemAccountId("fees"), amount: nominal, kind: "service_fee", actor, refType: "fee", refId },
            ];
            if (rounding > 0)
                postings.push({ accountId: this.bank.systemAccountId("rounding"), amount: -rounding,
                    kind: "service_fee", actor, refType: "fee", refId });
            const txId = this.bank.post(postings);
            return { transaction_id: txId, charged_cents: charged, nominal_cents: nominal, rounding_cents: rounding };
        });
    }
}
