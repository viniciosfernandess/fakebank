import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { Bank } from "../../world/src/bank.ts";

export function canaryPlanFingerprint(customerId: string, accountId: string): string {
  return createHash("sha256").update(JSON.stringify(["canary-plan-v1", customerId,
    accountId])).digest("hex");
}

export function canaryExcludedCustomers(bank: Pick<Bank, "db">,
  sourceHealthPath: string, requireCompleted = false): Set<string> {
  const excluded = new Set<string>();
  const required = Boolean(bank.db.prepare(`SELECT 1 FROM sqlite_master
    WHERE type='table' AND name='runtime_external_registry_required'`).get());
  const fingerprintColumn = required && (bank.db.prepare(`PRAGMA table_info(
    runtime_external_registry_required)`).all() as { name: string }[])
    .some((column) => column.name === "plan_hash");
  const marker = fingerprintColumn ? bank.db.prepare(`SELECT plan_hash
    FROM runtime_external_registry_required WHERE id=1`).get() as
    { plan_hash: string | null } | undefined : undefined;
  if (fingerprintColumn && !marker) throw new Error("CANARY_REGISTRY_MISSING");
  const expectedFingerprint = marker?.plan_hash ?? null;
  if (!existsSync(sourceHealthPath)) {
    if (required) throw new Error("CANARY_REGISTRY_MISSING");
    return excluded;
  }
  const registry = new DatabaseSync(sourceHealthPath, { readOnly: true, timeout: 1000 });
  try {
    const tables = new Set((registry.prepare(`SELECT name FROM sqlite_master
      WHERE type='table' AND name IN
        ('canary_fixture','canary_accounts','canary_cards','canary_credentials',
          'canary_cursor','canary_pix_keys','canary_key_cursor')`)
      .all() as { name: string }[]).map((row) => row.name));
    const telemetryMax = (bank.db.prepare(`SELECT COALESCE(MAX(id),0) n
      FROM telemetry_events`).get() as { n: number }).n;
    const lookupMax = (bank.db.prepare(`SELECT COALESCE(MAX(rowid),0) n
      FROM pix_lookup_attempts`).get() as { n: number }).n;
    const ahead = (table: string, column: string, maximum: number): boolean =>
      tables.has(table) && (registry.prepare(`SELECT COALESCE(MAX(${column}),0) n
        FROM ${table}`).get() as { n: number }).n > maximum;
    if (ahead("canary_cursor", "last_id", telemetryMax) ||
      ahead("canary_accounts", "active_after_id", telemetryMax) ||
      ahead("canary_cards", "active_after_id", telemetryMax) ||
      ahead("canary_credentials", "active_after_id", telemetryMax) ||
      ahead("canary_key_cursor", "last_rowid", lookupMax) ||
      ahead("canary_pix_keys", "active_after_rowid", lookupMax))
      throw new Error("CANARY_REGISTRY_AHEAD_OF_BANK");
    if (required && !tables.has("canary_fixture"))
      throw new Error("CANARY_REGISTRY_MISSING");
    if (tables.has("canary_fixture")) {
      const planned = registry.prepare(`SELECT customer_id,account_id,card_id,completed_at
        FROM canary_fixture WHERE id=1`)
        .get() as { customer_id: string; account_id: string;
          card_id: string | null; completed_at: string | null } | undefined;
      if (required && !planned) throw new Error("CANARY_REGISTRY_MISSING");
      if (planned && expectedFingerprint &&
        canaryPlanFingerprint(planned.customer_id, planned.account_id) !== expectedFingerprint)
        throw new Error("CANARY_REGISTRY_MISMATCH");
      if (planned) {
        excluded.add(planned.customer_id);
        if (requireCompleted && !planned.completed_at)
          throw new Error("CANARY_REGISTRY_INCOMPLETE");
        if (planned.completed_at) {
          const account = bank.db.prepare(`SELECT customer_id FROM accounts WHERE id=?`)
            .get(planned.account_id) as { customer_id: string | null } | undefined;
          const card = planned.card_id ? bank.db.prepare(`SELECT customer_id,account_id
            FROM cards WHERE id=?`).get(planned.card_id) as
            { customer_id: string; account_id: string } | undefined : undefined;
          const key = `${planned.customer_id.slice(-16).toLowerCase()}@banco-vivo.test`;
          const keyHash = createHash("sha256").update(key).digest("hex");
          if (!bank.db.prepare("SELECT 1 FROM customers WHERE id=?")
            .get(planned.customer_id) || account?.customer_id !== planned.customer_id ||
            !card || card.customer_id !== planned.customer_id ||
            card.account_id !== planned.account_id ||
            !tables.has("canary_accounts") || !tables.has("canary_cards") ||
            !tables.has("canary_credentials") || !tables.has("canary_pix_keys") ||
            !registry.prepare("SELECT 1 FROM canary_accounts WHERE account_id=?")
              .get(planned.account_id) ||
            !registry.prepare("SELECT 1 FROM canary_cards WHERE card_id=?")
              .get(planned.card_id) ||
            !registry.prepare("SELECT 1 FROM canary_credentials WHERE customer_id=?")
              .get(planned.customer_id) ||
            !registry.prepare("SELECT 1 FROM canary_pix_keys WHERE key_hash=?")
              .get(keyHash)) throw new Error("CANARY_REGISTRY_INCOMPLETE");
        }
      }
    }
    if (tables.has("canary_credentials")) for (const row of registry.prepare(`SELECT customer_id
      FROM canary_credentials`).all() as { customer_id: string }[]) {
      if (!bank.db.prepare("SELECT 1 FROM customers WHERE id=?").get(row.customer_id))
        throw new Error("CANARY_REGISTRY_TARGET_MISSING");
      excluded.add(row.customer_id);
    }
    if (tables.has("canary_accounts")) for (const row of registry.prepare(`SELECT account_id
      FROM canary_accounts`).all() as { account_id: string }[]) {
      const owner = bank.db.prepare(`SELECT customer_id FROM accounts WHERE id=?`)
        .get(row.account_id) as { customer_id: string | null } | undefined;
      if (!owner?.customer_id) throw new Error("CANARY_REGISTRY_TARGET_MISSING");
      excluded.add(owner.customer_id);
    }
    if (tables.has("canary_cards")) for (const row of registry.prepare(`SELECT card_id
      FROM canary_cards`).all() as { card_id: string }[]) {
      const owner = bank.db.prepare(`SELECT customer_id FROM cards WHERE id=?`)
        .get(row.card_id) as { customer_id: string } | undefined;
      if (!owner) throw new Error("CANARY_REGISTRY_TARGET_MISSING");
      excluded.add(owner.customer_id);
    }
    return excluded;
  } finally { registry.close(); }
}
