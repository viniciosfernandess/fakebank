import type { Area } from "../../../packages/contracts/src/index.ts";
export interface Weakness { id: string; area: Area; tier: "easy" | "medium" | "hard"; kind: "fraud" | "logic" | "api"; sentinel: string; }
export const WEAKNESSES: Weakness[] = [
  { id: "W01", area: "auth", tier: "easy", kind: "api", sentinel: "S-AUTH-02" },
  { id: "W02", area: "auth", tier: "medium", kind: "fraud", sentinel: "S-AUTH-03" },
  { id: "W03", area: "accounts", tier: "easy", kind: "api", sentinel: "S-ACC-01" },
  { id: "W04", area: "accounts", tier: "medium", kind: "logic", sentinel: "S-ACC-02" },
  { id: "W05", area: "pix", tier: "easy", kind: "logic", sentinel: "S-PIX-03" },
  { id: "W06", area: "pix", tier: "hard", kind: "logic", sentinel: "S-PIX-01" },
  { id: "W07", area: "pix", tier: "medium", kind: "fraud", sentinel: "S-PIX-04" },
  { id: "W08", area: "pix", tier: "easy", kind: "api", sentinel: "S-PIX-05" },
  { id: "W09", area: "cards", tier: "easy", kind: "logic", sentinel: "S-CARD-02" },
  { id: "W10", area: "cards", tier: "medium", kind: "api", sentinel: "S-CARD-03" },
  { id: "W11", area: "cards", tier: "hard", kind: "fraud", sentinel: "S-CARD-04" },
  { id: "W12", area: "loans", tier: "medium", kind: "logic", sentinel: "S-LOAN-01" },
  { id: "W13", area: "loans", tier: "hard", kind: "logic", sentinel: "S-LED-02" },
  { id: "W14", area: "api_gateway", tier: "easy", kind: "api", sentinel: "S-GW-01" },
  { id: "W15", area: "api_gateway", tier: "medium", kind: "api", sentinel: "S-GW-02" },
  { id: "W16", area: "ledger", tier: "hard", kind: "logic", sentinel: "S-LED-03" },
  { id: "W17", area: "pix", tier: "medium", kind: "fraud", sentinel: "S-PIX-02" },
];
export const DECOYS = ["D1", "D2", "D3"] as const;
export const FEATURES = [
  { day: 1, id: "pix_agendado_recorrente", area: "pix", sentinel: "S-PIX-03", disableSafe: true },
  { day: 2, id: "cartao_virtual_temporario", area: "cards", sentinel: "S-CARD-05", disableSafe: true },
  { day: 3, id: "emprestimo_relampago", area: "loans", sentinel: "S-LOAN-02", disableSafe: true },
  { day: 4, id: "pix_aproximacao", area: "pix", sentinel: "S-PIX-06", disableSafe: true },
  { day: 5, id: "cashback", area: "ledger", sentinel: "S-LED-04", disableSafe: true },
  { day: 6, id: "compartilhar_dados", area: "api_gateway", sentinel: "S-GW-03", disableSafe: true },
  { day: 7, id: "limite_dinamico", area: "accounts", sentinel: "S-ACC-03", disableSafe: true },
] as const;
