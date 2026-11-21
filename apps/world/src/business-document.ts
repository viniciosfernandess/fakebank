export function syntheticCnpj(index: number): string {
  if (!Number.isSafeInteger(index) || index < 1 || index > 89_999_999)
    throw new Error("SYNTHETIC_CNPJ_INDEX_INVALID");
  const root = String(10_000_000 + index);
  const base = `${root}0001`;
  const checkDigit = (digits: string, weights: number[]): number => {
    const sum = [...digits].reduce((total, digit, offset) =>
      total + Number(digit) * weights[offset]!, 0);
    const remainder = sum % 11;
    return remainder < 2 ? 0 : 11 - remainder;
  };
  const first = checkDigit(base, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  const second = checkDigit(`${base}${first}`, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  return `${base}${first}${second}`;
}
