import type { Bank } from "./bank.ts";
import { brtHour } from "./bank.ts";
export function pixNightHour(bank: Bank): number {
    return brtHour(bank.now());
}
export function pixRaceEnabled(_bank: Bank): boolean { return false; }
export function medMayReopen(_bank: Bank, _status: string): boolean {
    return false;
}
export function lookupRateAllowed(_bank: Bank, attempts: number): boolean {
    return attempts < 30;
}
export function pixKeyResult(_bank: Bank, row: {
    holder_name: string;
    cpf: string;
    account_id: string;
}): {
    holder_name: string;
    cpf: string;
    account_id: string;
} {
    return { ...row,
        holder_name: row.holder_name.split(/\s+/).map((part) => `${part[0] ?? "*"}${"*".repeat(Math.max(part.length - 1, 1))}`).join(" "),
        cpf: `***.${row.cpf.slice(3, 6)}.${row.cpf.slice(6, 9)}-**` };
}
export function muleHoldEnabled(_bank: Bank): boolean { return true; }
