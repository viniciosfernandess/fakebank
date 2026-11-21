import type { Bank, Customer } from "./bank.ts";
export function canReadStatement(_bank: Bank, accountCustomerId: string | null, requesterId: string): boolean {
    return accountCustomerId === requesterId;
}
export function effectiveKycTier(_bank: Bank, customer: Customer): number {
    return customer.kyc_tier;
}
