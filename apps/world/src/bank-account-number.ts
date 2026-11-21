export const JACARANDA_BRANCH = "0001";

export function accountIdentifier(sequence: number): {
  branch_code: string; account_number: string; account_digit: string;
} {
  if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence > 99_999_999)
    throw new Error("ACCOUNT_NUMBER_EXHAUSTED");
  const accountNumber = String(sequence).padStart(8, "0");
  const digits = `${JACARANDA_BRANCH}${accountNumber}`;
  let sum = 0;
  for (let index = digits.length - 1, weight = 2; index >= 0; index--, weight = weight === 9 ? 2 : weight + 1)
    sum += Number(digits[index]) * weight;
  const remainder = (11 - sum % 11) % 11;
  return { branch_code: JACARANDA_BRANCH, account_number: accountNumber,
    account_digit: String(remainder === 10 ? 0 : remainder) };
}
