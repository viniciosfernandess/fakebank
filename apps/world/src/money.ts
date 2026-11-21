import { BankError } from "./bank.ts";

export function parseDecimalCents(value: string): number {
  if (!/^(0|[1-9]\d{0,5})(?:\.\d{1,2})?$/.test(value)) throw new BankError("BIZ_INVALID_AMOUNT");
  const [whole = "", fractional = ""] = value.split(".");
  const cents = Number(whole) * 100 + Number(fractional.padEnd(2, "0"));
  if (!Number.isSafeInteger(cents) || cents <= 0 || cents > 2_000_000) throw new BankError("BIZ_INVALID_AMOUNT");
  return cents;
}
