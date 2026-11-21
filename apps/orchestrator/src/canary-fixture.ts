import { createHash, randomBytes, randomInt } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { Bank, syntheticCpf } from "../../world/src/bank.ts";
import { AuthEngine } from "../../world/src/auth.ts";
import { CardsEngine } from "../../world/src/cards.ts";
import { newId } from "../../world/src/id.ts";
import { canaryPlanFingerprint } from "./canary-exclusions.ts";

interface CanaryPlan {
  customer_id: string; account_id: string; cpf_index: number;
  card_id: string | null; completed_at: string | null;
}

export function ensureCanaryFixture(bank: Bank, auth: AuthEngine, dataDir: string): void {
  const registry = new DatabaseSync(join(dataDir, "source-health.sqlite"), { timeout: 1000 });
  try {
    registry.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS canary_fixture (
        id INTEGER PRIMARY KEY CHECK(id=1), customer_id TEXT NOT NULL UNIQUE,
        account_id TEXT NOT NULL UNIQUE, cpf_index INTEGER NOT NULL UNIQUE,
        card_id TEXT, completed_at TEXT
      );
      CREATE TABLE IF NOT EXISTS canary_accounts (
        account_id TEXT PRIMARY KEY, active_after_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_cards (
        card_id TEXT PRIMARY KEY, active_after_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_credentials (
        customer_id TEXT PRIMARY KEY, active_after_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_pix_keys (
        key_hash TEXT PRIMARY KEY, active_after_rowid INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_cursor (
        id INTEGER PRIMARY KEY CHECK(id=1), last_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS canary_key_cursor (
        id INTEGER PRIMARY KEY CHECK(id=1), last_rowid INTEGER NOT NULL
      );`);
    let plan = registry.prepare(`SELECT customer_id,account_id,cpf_index,card_id,completed_at
      FROM canary_fixture WHERE id=1`).get() as CanaryPlan | undefined;
    if (!plan) {
      let index = 0;
      for (let attempt = 0; attempt < 100; attempt++) {
        index = randomInt(50_000_000, 100_000_000);
        if (!bank.db.prepare("SELECT 1 FROM customers WHERE cpf=?")
          .get(syntheticCpf(index))) break;
        if (attempt === 99) throw new Error("CANARY_CPF_EXHAUSTED");
      }
      const customerId = newId("cus", bank.now().getTime());
      const accountId = newId("acc", bank.now().getTime());
      registry.prepare(`INSERT INTO canary_fixture
        (id,customer_id,account_id,cpf_index) VALUES (1,?,?,?)`)
        .run(customerId, accountId, index);
      plan = { customer_id: customerId, account_id: accountId,
        cpf_index: index, card_id: null, completed_at: null };
    }
    bank.db.exec(`CREATE TABLE IF NOT EXISTS runtime_external_registry_required (
      id INTEGER PRIMARY KEY CHECK(id=1), plan_hash TEXT
    );`);
    if (!(bank.db.prepare("PRAGMA table_info(runtime_external_registry_required)")
      .all() as { name: string }[]).some((column) => column.name === "plan_hash"))
      bank.db.exec("ALTER TABLE runtime_external_registry_required ADD COLUMN plan_hash TEXT");
    const planHash = canaryPlanFingerprint(plan.customer_id, plan.account_id);
    const existingHash = bank.db.prepare(`SELECT plan_hash
      FROM runtime_external_registry_required WHERE id=1`).get() as
      { plan_hash: string | null } | undefined;
    if (existingHash?.plan_hash && existingHash.plan_hash !== planHash)
      throw new Error("CANARY_REGISTRY_MISMATCH");
    bank.db.prepare(`INSERT INTO runtime_external_registry_required (id,plan_hash)
      VALUES (1,?) ON CONFLICT(id) DO UPDATE SET plan_hash=excluded.plan_hash
      WHERE plan_hash IS NULL`).run(planHash);
    const cpf = syntheticCpf(plan.cpf_index);
    const existingCustomer = bank.db.prepare(`SELECT cpf FROM customers WHERE id=?`)
      .get(plan.customer_id) as { cpf: string } | undefined;
    if (!existingCustomer) bank.addCustomer({ id: plan.customer_id, cpf,
      name: "Marina Pereira", persona: "saver", kyc_tier: 2,
      kyc_status: "approved", risk_score: 10, is_attacker_owned: false,
      status: "active" });
    else if (existingCustomer.cpf !== cpf) throw new Error("CANARY_FIXTURE_DRIFT");
    const existingAccount = bank.db.prepare(`SELECT customer_id FROM accounts WHERE id=?`)
      .get(plan.account_id) as { customer_id: string | null } | undefined;
    if (!existingAccount) bank.addAccount({ id: plan.account_id,
      customer_id: plan.customer_id, kind: "checking", system_role: null,
      overdraft_limit: 0, status: "active" });
    else if (existingAccount.customer_id !== plan.customer_id)
      throw new Error("CANARY_FIXTURE_DRIFT");
    const cards = new CardsEngine(bank);
    let cardId = plan.card_id;
    if (!cardId) {
      const prior = bank.db.prepare(`SELECT id FROM cards WHERE customer_id=? AND account_id=?
        ORDER BY created_at,id LIMIT 1`).get(plan.customer_id, plan.account_id) as
        { id: string } | undefined;
      cardId = prior?.id ?? cards.issueDebit(plan.customer_id, plan.account_id, 10_000).id;
      registry.prepare("UPDATE canary_fixture SET card_id=? WHERE id=1")
        .run(cardId);
    }
    if (!bank.db.prepare("SELECT 1 FROM cards WHERE id=? AND customer_id=? AND account_id=?")
      .get(cardId, plan.customer_id, plan.account_id)) throw new Error("CANARY_FIXTURE_DRIFT");
    if (!bank.db.prepare("SELECT 1 FROM auth_passwords WHERE customer_id=?")
      .get(plan.customer_id))
      auth.setPassword(plan.customer_id, randomBytes(32).toString("base64url"));
    const afterId = (bank.db.prepare(`SELECT COALESCE(MAX(id),0) id FROM telemetry_events`)
      .get() as { id: number }).id;
    const afterLookup = (bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) id FROM pix_lookup_attempts`)
      .get() as { id: number }).id;
    const key = `${plan.customer_id.slice(-16).toLowerCase()}@banco-vivo.test`;
    const keyHash = createHash("sha256").update(key).digest("hex");
    registry.exec("BEGIN IMMEDIATE");
    try {
      registry.prepare("INSERT OR IGNORE INTO canary_accounts VALUES (?,?)")
        .run(plan.account_id, afterId);
      registry.prepare("INSERT OR IGNORE INTO canary_cards VALUES (?,?)")
        .run(cardId, afterId);
      registry.prepare("INSERT OR IGNORE INTO canary_credentials VALUES (?,?)")
        .run(plan.customer_id, afterId);
      registry.prepare("INSERT OR IGNORE INTO canary_pix_keys VALUES (?,?)")
        .run(keyHash, afterLookup);
      registry.prepare("INSERT OR IGNORE INTO canary_cursor VALUES (1,?)").run(afterId);
      registry.prepare("INSERT OR IGNORE INTO canary_key_cursor VALUES (1,?)")
        .run(afterLookup);
      registry.prepare("UPDATE canary_fixture SET completed_at=COALESCE(completed_at,?) WHERE id=1")
        .run(bank.now().toISOString());
      registry.exec("COMMIT");
    } catch (error) { registry.exec("ROLLBACK"); throw error; }
  } finally { registry.close(); }
}
