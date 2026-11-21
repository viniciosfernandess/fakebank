export const PUBLIC_TARIFF_SCHEDULE = Object.freeze({
  version: 1,
  effective_from: "2026-11-01",
  currency: "BRL",
  audience: "individual",
  entries: [
    { service: "account_opening", amount_cents: 0 },
    { service: "debit_card_issuance", amount_cents: 0 },
    { service: "credit_card_annual_fee", amount_cents: 0 },
    { service: "pix_send_digital", amount_cents: 0 },
    { service: "pix_receive_digital", amount_cents: 0 },
    { service: "pix_automatic_send_digital", amount_cents: 0 },
  ],
  disclosure: "Loan fees and credit charges are disclosed in each offer or statement.",
});
