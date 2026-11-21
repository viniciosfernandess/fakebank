import { Bank, syntheticCpf, type Persona } from "./bank.ts";
import { WEAKNESSES } from "./catalog.ts";
import { seedAccountId, seedCustomerId, seedRecordId, seedSystemAccountId, SYSTEM_ROLES } from "./id.ts";
import { PSP_PARTICIPANTS } from "./ecosystem/spi.ts";
import { JACARANDA_ISPB } from "./pix-id.ts";
import { accountIdentifier } from "./bank-account-number.ts";
import { syntheticCnpj } from "./business-document.ts";

const FIRST = ["Ana", "Bruno", "Camila", "Diego", "Elisa", "Felipe", "Gabriela", "Henrique", "Isabela", "João", "Larissa", "Marcos", "Nádia", "Otávio", "Paula", "Rafael", "Sofia", "Tiago", "Valéria", "Yasmin"];
const LAST = ["Almeida", "Barbosa", "Costa", "Dias", "Ferreira", "Gomes", "Lima", "Martins", "Nascimento", "Oliveira", "Pereira", "Ribeiro", "Rocha", "Santos", "Silva", "Souza"];
const PERSONAS: { persona: Persona; share: number }[] = [
  { persona: "salaried", share: 34 }, { persona: "merchant", share: 11 }, { persona: "student", share: 13 },
  { persona: "retiree", share: 12 }, { persona: "gig", share: 14 }, { persona: "saver", share: 8 }, { persona: "night_owl", share: 8 },
];
function random(seed: number): () => number {
  let value = seed >>> 0;
  return () => { value ^= value << 13; value ^= value >>> 17; value ^= value << 5; return (value >>> 0) / 0x1_0000_0000; };
}
function personaAt(index: number, total: number): Persona {
  let sum = 0;
  for (const item of PERSONAS) { sum += Math.round(total * item.share / 100); if (index < sum) return item.persona; }
  return "night_owl";
}
export interface SeedOptions { customers?: number; accounts?: number; historyTransactions?: number; seed?: number; openWeaknesses?: boolean; }
export function ensureSyntheticRecipients(bank: Bank): void {
  const insert = bank.db.prepare(`INSERT INTO psp_accounts
    (id,ispb,holder_name,pix_key) VALUES (?,?,?,?) ON CONFLICT(id) DO NOTHING`);
  for (let index = 0; index < 250; index++)
    insert.run(`psp_sim_${index}`, index % 2 ? "87654321" : "11223344",
      `Synthetic Recipient ${index}`, `recipient-${index}@psp.example`);
}
export function seedBank(bank: Bank, options: SeedOptions = {}): { customers: number; accounts: number; historyTransactions: number } {
  const customers = options.customers ?? 12_000;
  const accounts = options.accounts ?? 14_500;
  const historyTransactions = options.historyTransactions ?? 400_000;
  if (!Number.isSafeInteger(customers) || customers < 2 || !Number.isSafeInteger(accounts) || accounts < customers ||
    !Number.isSafeInteger(historyTransactions) || historyTransactions < 0) throw new Error("Invalid seed dimensions");
  if ((bank.db.prepare("SELECT COUNT(*) n FROM customers").get() as { n: number }).n) throw new Error("Bank already seeded");
  const next = random(options.seed ?? 20_261_111);
  const now = bank.now().getTime();
  const openingAt = now - 30 * 86_400_000;
  const openingTs = new Date(openingAt).toISOString();
  const cashIn = seedSystemAccountId("cash_in");
  const customerInsert = bank.db.prepare("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)");
  const accountInsert = bank.db.prepare(`INSERT INTO accounts
    (id,customer_id,kind,system_role,balance_cached,overdraft_limit,status,opened_at,
     branch_code,account_number,account_digit)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
  const businessInsert = bank.db.prepare(`INSERT INTO business_account_identity
    (account_id,cnpj,legal_name,representative_customer_id,verified_at,verified_by)
    VALUES (?,?,?,?,?,'synthetic_seed')`);
  const ledgerInsert = bank.db.prepare("INSERT INTO ledger_entries VALUES (?,?,?,?,?,?,?,?,?,?)");
  const balanceUpdate = bank.db.prepare("UPDATE accounts SET balance_cached=balance_cached+? WHERE id=?");
  const balances = new Int32Array(accounts);
  const customerIds = Array.from({ length: customers }, (_, index) => seedCustomerId(index + 1));
  const accountIds = Array.from({ length: accounts }, (_, index) => seedAccountId(index + 1));
  let historyAdded = 0;
  bank.transaction(() => {
    for (const role of SYSTEM_ROLES) bank.db.prepare(`INSERT OR IGNORE INTO accounts
      (id,customer_id,kind,system_role,balance_cached,overdraft_limit,status,opened_at,
       branch_code,account_number,account_digit) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .run(seedSystemAccountId(role), null, "system", role, 0, 0, "active", openingTs,
        null, null, null);
    for (const weakness of WEAKNESSES) bank.db.prepare("INSERT INTO weakness_state VALUES (?,?,?,?)")
      .run(weakness.id, 0, new Date(now).toISOString(), "seed");
    for (let index = 0; index < customers; index++) {
      const persona = personaAt(index, customers);
      const name = `${FIRST[index % FIRST.length]} ${LAST[(index * 7 + Math.floor(index / FIRST.length)) % LAST.length]}`;
      customerInsert.run(customerIds[index]!, syntheticCpf(index), name, persona,
        persona === "student" ? 1 : 2, "approved", 5 + Math.floor(next() * 40), 0,
        "active", new Date(now - (30 + Math.floor(next() * 120)) * 86_400_000).toISOString());
    }
    for (let index = 0; index < accounts; index++) {
      const customerIndex = index % customers;
      const customerId = customerIds[customerIndex]!;
      const accountId = accountIds[index]!;
      const identifier = accountIdentifier(index + 1);
      const kind = personaAt(customerIndex, customers) === "merchant" ? "merchant" : "checking";
      accountInsert.run(accountId, customerId, kind,
        null, 0, 0, "active", openingTs, identifier.branch_code,
        identifier.account_number, identifier.account_digit);
      if (kind === "merchant") businessInsert.run(accountId, syntheticCnpj(index + 1),
        `Synthetic Business ${index + 1} Ltda`, customerId, openingTs);
      const amount = 50_000 + Math.floor(next() * 200_000);
      const txId = seedRecordId("tx", `fund:${index}`, openingAt);
      ledgerInsert.run(seedRecordId("le", `fund:${index}:source`, openingAt), txId,
        cashIn, -amount, "seed_funding", "seed", "funding", accountId, openingTs, null);
      ledgerInsert.run(seedRecordId("le", `fund:${index}:account`, openingAt), txId,
        accountId, amount, "seed_funding", "seed", "funding", accountId, openingTs, null);
      balances[index] = amount;
      balanceUpdate.run(amount, accountId); balanceUpdate.run(-amount, cashIn);
    }
    for (const [key, role, amount] of [
      ["recovery", "recovery", 10_000_000],
      ["loan_reserve", "loan_funding", 100_000_000],
      ["cashback", "cashback_pool", 5_000_000],
    ] as const) {
      const txId = seedRecordId("tx", key, openingAt);
      const target = seedSystemAccountId(role);
      ledgerInsert.run(seedRecordId("le", `${key}:source`, openingAt), txId,
        cashIn, -amount, `seed_${key}`, "seed", "funding", target, openingTs, null);
      ledgerInsert.run(seedRecordId("le", `${key}:target`, openingAt), txId,
        target, amount, `seed_${key}`, "seed", "funding", target, openingTs, null);
      balanceUpdate.run(-amount, cashIn);
      balanceUpdate.run(amount, target);
    }
    const piLiquidity = Math.min(1_000_000_000, -bank.account(cashIn).balance_cached);
    const piAccount = seedSystemAccountId("pix_settlement");
    const piTx = seedRecordId("tx", "pi_liquidity", openingAt);
    ledgerInsert.run(seedRecordId("le", "pi_liquidity:source", openingAt), piTx,
      cashIn, piLiquidity, "seed_pi_liquidity", "seed", "funding", piAccount, openingTs, null);
    ledgerInsert.run(seedRecordId("le", "pi_liquidity:pi", openingAt), piTx,
      piAccount, -piLiquidity, "seed_pi_liquidity", "seed", "funding", piAccount, openingTs, null);
    balanceUpdate.run(piLiquidity, cashIn); balanceUpdate.run(-piLiquidity, piAccount);
    bank.spi.fund(JACARANDA_ISPB, piLiquidity);
    for (const participant of PSP_PARTICIPANTS.slice(1)) bank.spi.fund(participant.ispb, 100_000_000);
    const capital = seedSystemAccountId("equity_capital");
    const capitalAmount = 100_000_000;
    const capitalTx = seedRecordId("tx", "paid_in_capital", openingAt);
    ledgerInsert.run(seedRecordId("le", "paid_in_capital:cash", openingAt), capitalTx,
      cashIn, -capitalAmount, "seed_capital", "seed", "capital", capital, openingTs, null);
    ledgerInsert.run(seedRecordId("le", "paid_in_capital:equity", openingAt), capitalTx,
      capital, capitalAmount, "seed_capital", "seed", "capital", capital, openingTs, null);
    balanceUpdate.run(-capitalAmount, cashIn); balanceUpdate.run(capitalAmount, capital);
    bank.db.prepare(`INSERT INTO psp_accounts (id,ispb,holder_name,pix_key)
      VALUES ('psp_ipe_ana','87654321','Ana Oliveira','ana@ipe.example'),
             ('psp_aroeira_bruno','11223344','Bruno Silva','bruno@aroeira.example')`).run();
    ensureSyntheticRecipients(bank);
    for (let index = 0; index < historyTransactions; index++) {
      let from = Math.floor(next() * accounts);
      let attempts = 0;
      while (balances[from]! <= 1_000 && attempts++ < 10) from = Math.floor(next() * accounts);
      if (balances[from]! <= 1_000) continue;
      let to = Math.floor(next() * accounts);
      if (from === to) to = (to + 1) % accounts;
      const amount = Math.min(100 + Math.floor(next() * 9_900), balances[from]! - 1_000);
      const fromId = accountIds[from]!;
      const toId = accountIds[to]!;
      const at = new Date(now - (historyTransactions - index) / historyTransactions * 30 * 86_400_000).getTime();
      const ts = new Date(at).toISOString();
      const txId = seedRecordId("tx", `history:${index}`, at);
      ledgerInsert.run(seedRecordId("le", `history:${index}:debit`, at), txId,
        fromId, -amount, "pix", "sim", "history", txId, ts, null);
      ledgerInsert.run(seedRecordId("le", `history:${index}:credit`, at), txId,
        toId, amount, "pix", "sim", "history", txId, ts, null);
      balanceUpdate.run(-amount, fromId); balanceUpdate.run(amount, toId);
      balances[from] = balances[from]! - amount; balances[to] = balances[to]! + amount;
      historyAdded++;
    }
  });
  if (!bank.db.isTransaction) bank.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  return { customers, accounts, historyTransactions: historyAdded };
}
