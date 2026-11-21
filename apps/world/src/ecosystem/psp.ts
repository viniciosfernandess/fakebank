import type { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { newId } from "../id.ts";
import { JACARANDA_ISPB, pixEndToEndIdForIspb } from "../pix-id.ts";
import { CASHOUT_ISPB, type SpiNetwork } from "./spi.ts";

export interface PspTransferResult {
  id: string; root_transfer_id: string; from_account: string; to_account: string;
  amount: number; end_to_end_id: string; status: "settled" | "rejected";
}
export interface PspCautelarHold {
  id: string; account_id: string; root_transfer_id: string; amount_cents: number;
  reason: string; status: "active" | "released" | "returned" | "expired" | "superseded_by_med";
  created_at: string; expires_at: string; resolved_at: string | null;
  resolved_by: string | null;
}
export interface PspCautelarNotice {
  id: number; account_id: string; hold_id: string; kind: "held" | "released" |
    "returned" | "expired" | "med_review";
  amount_cents: number; message_pt: string; created_at: string;
}
export interface PspMedNotice {
  id: number; account_id: string; hop_id: string; case_id: string;
  kind: "blocked" | "recovered" | "released";
  amount_cents: number; message_pt: string; created_at: string;
}

export class PspNetwork {
  private readonly db: DatabaseSync;
  private readonly spi: SpiNetwork;
  private readonly now: () => Date;
  constructor(db: DatabaseSync, spi: SpiNetwork, now: () => Date) {
    this.db = db; this.spi = spi; this.now = now;
    const fundsTableExists = Boolean(db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='psp_funds'`).get());
    db.exec(`CREATE TABLE IF NOT EXISTS psp_schema_migrations (
      name TEXT PRIMARY KEY, completed_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS psp_schema_migrations_no_update
      BEFORE UPDATE ON psp_schema_migrations
      BEGIN SELECT RAISE(ABORT,'PSP_MIGRATION_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_schema_migrations_no_delete
      BEFORE DELETE ON psp_schema_migrations
      BEGIN SELECT RAISE(ABORT,'PSP_MIGRATION_IMMUTABLE'); END;`);
    const fundsImportDone = Boolean(db.prepare(`SELECT 1 FROM psp_schema_migrations
      WHERE name='legacy_funds_import'`).get());
    const medHoldsImportDone = Boolean(db.prepare(`SELECT 1 FROM psp_schema_migrations
      WHERE name='legacy_med_holds_import'`).get());
    const medHoldsTableExists = Boolean(db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='psp_med_holds'`).get());
    const rootFactsImportDone = Boolean(db.prepare(`SELECT 1 FROM psp_schema_migrations
      WHERE name='psp_root_facts_import'`).get());
    const rootFactsTableExists = Boolean(db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='psp_roots'`).get());
    const senderFactsImportDone = Boolean(db.prepare(`SELECT 1 FROM psp_schema_migrations
      WHERE name='legacy_sender_facts_import'`).get());
    const senderFactsTableExists = Boolean(db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='psp_inbound_sender_facts'`).get());
    const legacyProofImportDone = Boolean(db.prepare(`SELECT 1 FROM psp_schema_migrations
      WHERE name='legacy_inbound_proofs_import'`).get());
    const legacyProofTableExists = Boolean(db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='psp_legacy_inbound_proofs'`).get());
    const legacyProofSealExists = Boolean(db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='psp_legacy_inbound_proof_seal'`).get());
    if (fundsImportDone && !fundsTableExists) throw new Error("PSP_ROOT_HISTORY_INVALID");
    if (medHoldsImportDone && !medHoldsTableExists) throw new Error("PSP_MED_HISTORY_INVALID");
    if (rootFactsImportDone && !rootFactsTableExists) throw new Error("PSP_ROOT_HISTORY_INVALID");
    if (senderFactsImportDone && !senderFactsTableExists)
      throw new Error("PSP_INBOUND_HISTORY_INVALID");
    if (legacyProofImportDone && (!legacyProofTableExists || !legacyProofSealExists))
      throw new Error("PSP_LEGACY_PROOF_HISTORY_INVALID");
    db.exec(`CREATE TABLE IF NOT EXISTS psp_roots (
      root_transfer_id TEXT PRIMARY KEY, end_to_end_id TEXT NOT NULL UNIQUE,
      account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      source TEXT NOT NULL CHECK(source IN ('receipt','legacy')),
      registered_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS psp_roots_no_update BEFORE UPDATE ON psp_roots
      BEGIN SELECT RAISE(ABORT,'PSP_ROOT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_roots_no_delete BEFORE DELETE ON psp_roots
      BEGIN SELECT RAISE(ABORT,'PSP_ROOT_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_funds (
      account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      root_transfer_id TEXT NOT NULL REFERENCES psp_roots(root_transfer_id),
      available_cents INTEGER NOT NULL CHECK(available_cents>=0),
      PRIMARY KEY(account_id,root_transfer_id)
    );
    CREATE TABLE IF NOT EXISTS psp_inbound_receipts (
      root_transfer_id TEXT PRIMARY KEY,
      end_to_end_id TEXT NOT NULL UNIQUE,
      account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      credited_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS psp_inbound_receipts_no_update
      BEFORE UPDATE ON psp_inbound_receipts
      BEGIN SELECT RAISE(ABORT,'PSP_INBOUND_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_inbound_receipts_no_delete
      BEFORE DELETE ON psp_inbound_receipts
      BEGIN SELECT RAISE(ABORT,'PSP_INBOUND_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_inbound_sender_facts (
      root_transfer_id TEXT PRIMARY KEY REFERENCES psp_inbound_receipts(root_transfer_id),
      sender_account TEXT NOT NULL,
      settled_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS psp_inbound_sender_recent
      ON psp_inbound_sender_facts(settled_at,sender_account);
    CREATE TRIGGER IF NOT EXISTS psp_inbound_sender_no_update
      BEFORE UPDATE ON psp_inbound_sender_facts
      BEGIN SELECT RAISE(ABORT,'PSP_INBOUND_SENDER_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_inbound_sender_no_delete
      BEFORE DELETE ON psp_inbound_sender_facts
      BEGIN SELECT RAISE(ABORT,'PSP_INBOUND_SENDER_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_legacy_inbound_proofs (
      root_transfer_id TEXT PRIMARY KEY, end_to_end_id TEXT NOT NULL UNIQUE,
      account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      sender_account TEXT NOT NULL, settled_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS psp_legacy_inbound_proofs_no_update
      BEFORE UPDATE ON psp_legacy_inbound_proofs
      BEGIN SELECT RAISE(ABORT,'PSP_LEGACY_PROOF_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_legacy_inbound_proofs_no_delete
      BEFORE DELETE ON psp_legacy_inbound_proofs
      BEGIN SELECT RAISE(ABORT,'PSP_LEGACY_PROOF_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_legacy_inbound_proof_seal (
      id INTEGER PRIMARY KEY CHECK(id=1), count INTEGER NOT NULL CHECK(count>=0),
      sha256 TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS psp_legacy_inbound_proof_seal_no_update
      BEFORE UPDATE ON psp_legacy_inbound_proof_seal
      BEGIN SELECT RAISE(ABORT,'PSP_LEGACY_PROOF_SEAL_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_legacy_inbound_proof_seal_no_delete
      BEFORE DELETE ON psp_legacy_inbound_proof_seal
      BEGIN SELECT RAISE(ABORT,'PSP_LEGACY_PROOF_SEAL_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_med_holds (
      hop_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, root_transfer_id TEXT NOT NULL,
      account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      blocked_cents INTEGER NOT NULL CHECK(blocked_cents>0),
      refunded_cents INTEGER NOT NULL DEFAULT 0 CHECK(refunded_cents>=0 AND refunded_cents<=blocked_cents),
      created_at TEXT NOT NULL, released_at TEXT
    );
    CREATE INDEX IF NOT EXISTS psp_med_holds_active
      ON psp_med_holds(account_id,root_transfer_id,released_at);
    CREATE TRIGGER IF NOT EXISTS psp_med_holds_no_delete
      BEFORE DELETE ON psp_med_holds
      BEGIN SELECT RAISE(ABORT,'PSP_MED_HOLD_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_med_holds_identity_immutable
      BEFORE UPDATE OF hop_id,case_id,root_transfer_id,account_id,blocked_cents,created_at
      ON psp_med_holds
      BEGIN SELECT RAISE(ABORT,'PSP_MED_HOLD_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_med_holds_release_once
      BEFORE UPDATE OF released_at ON psp_med_holds
      WHEN OLD.released_at IS NOT NULL OR NEW.released_at IS NULL
      BEGIN SELECT RAISE(ABORT,'PSP_MED_HOLD_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_med_holds_refund_monotonic
      BEFORE UPDATE OF refunded_cents ON psp_med_holds
      WHEN OLD.released_at IS NULL OR NEW.refunded_cents<OLD.refunded_cents
      BEGIN SELECT RAISE(ABORT,'PSP_MED_HOLD_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_transfers (
      id TEXT PRIMARY KEY, root_transfer_id TEXT NOT NULL REFERENCES psp_roots(root_transfer_id),
      from_account TEXT NOT NULL REFERENCES psp_accounts(id),
      to_account TEXT NOT NULL REFERENCES psp_accounts(id),
      idempotency_key TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0),
      end_to_end_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
      created_at TEXT NOT NULL, UNIQUE(from_account,idempotency_key)
    );
    CREATE INDEX IF NOT EXISTS psp_transfers_root ON psp_transfers(root_transfer_id);
    CREATE TABLE IF NOT EXISTS psp_cashouts (
      id TEXT PRIMARY KEY, root_transfer_id TEXT NOT NULL REFERENCES psp_roots(root_transfer_id),
      account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      idempotency_key TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0),
      end_to_end_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
      created_at TEXT NOT NULL, UNIQUE(account_id,idempotency_key)
    );
    CREATE TABLE IF NOT EXISTS psp_cautelar_holds (
      id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      root_transfer_id TEXT NOT NULL REFERENCES psp_roots(root_transfer_id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0), reason TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN
        ('active','released','returned','expired','superseded_by_med')),
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, resolved_at TEXT,
      resolved_by TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS psp_inbound_review_once
      ON psp_cautelar_holds(root_transfer_id) WHERE reason='PSP_FAN_IN_10M';
    CREATE TABLE IF NOT EXISTS psp_cautelar_notices (
      id INTEGER PRIMARY KEY, account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      hold_id TEXT NOT NULL REFERENCES psp_cautelar_holds(id),
      kind TEXT NOT NULL CHECK(kind IN
        ('held','released','returned','expired','med_review')),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      message_pt TEXT NOT NULL, created_at TEXT NOT NULL,
      UNIQUE(hold_id,kind)
    );
    CREATE INDEX IF NOT EXISTS psp_cautelar_notices_account
      ON psp_cautelar_notices(account_id,id);
    CREATE TRIGGER IF NOT EXISTS psp_cautelar_notices_no_update
      BEFORE UPDATE ON psp_cautelar_notices
      BEGIN SELECT RAISE(ABORT,'PSP_CAUTELAR_NOTICE_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_cautelar_notices_no_delete
      BEFORE DELETE ON psp_cautelar_notices
      BEGIN SELECT RAISE(ABORT,'PSP_CAUTELAR_NOTICE_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_med_notices (
      id INTEGER PRIMARY KEY, account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      hop_id TEXT NOT NULL REFERENCES psp_med_holds(hop_id),
      case_id TEXT NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN ('blocked','recovered','released')),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      message_pt TEXT NOT NULL, created_at TEXT NOT NULL,
      UNIQUE(hop_id,kind)
    );
    CREATE INDEX IF NOT EXISTS psp_med_notices_account
      ON psp_med_notices(account_id,id);
    CREATE TRIGGER IF NOT EXISTS psp_med_notices_no_update
      BEFORE UPDATE ON psp_med_notices
      BEGIN SELECT RAISE(ABORT,'PSP_MED_NOTICE_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_med_notices_no_delete
      BEFORE DELETE ON psp_med_notices
      BEGIN SELECT RAISE(ABORT,'PSP_MED_NOTICE_IMMUTABLE'); END;
    `);
    const holdColumns = db.prepare("PRAGMA table_info(psp_cautelar_holds)")
      .all() as { name: string }[];
    if (!holdColumns.some((column) => column.name === "resolved_by"))
      db.exec("ALTER TABLE psp_cautelar_holds ADD COLUMN resolved_by TEXT");
    db.exec(`CREATE INDEX IF NOT EXISTS psp_cautelar_active
      ON psp_cautelar_holds(account_id,root_transfer_id,status,expires_at);`);
    this.transaction(() => {
      if (!medHoldsImportDone) {
        db.exec(`INSERT OR IGNORE INTO psp_med_holds
          (hop_id,case_id,root_transfer_id,account_id,blocked_cents,refunded_cents,created_at,released_at)
          SELECT id,case_id,root_transfer_id,account_id,blocked_cents,refunded_cents,created_at,released_at
          FROM med_hops`);
        if (this.medHoldDrift() !== 0) throw new Error("PSP_MED_HISTORY_INVALID");
        db.prepare(`INSERT INTO psp_schema_migrations
          (name,completed_at) VALUES ('legacy_med_holds_import',?)`).run(this.now().toISOString());
      }
      this.migrateMedNoticeReferences();
      if (!senderFactsImportDone) {
        const invalidHistory = (db.prepare(`SELECT COUNT(*) n FROM psp_inbound_receipts r
          LEFT JOIN pix_transfers p ON p.id=r.root_transfer_id
          WHERE p.id IS NULL OR p.end_to_end_id<>r.end_to_end_id OR
            p.to_account<>r.account_id OR p.amount<>r.amount_cents OR
            p.from_account IS NULL OR p.settled_at IS NULL`)
          .get() as { n: number }).n;
        if (invalidHistory) throw new Error("PSP_INBOUND_HISTORY_INVALID");
        db.exec(`INSERT OR IGNORE INTO psp_inbound_sender_facts
          (root_transfer_id,sender_account,settled_at)
          SELECT r.root_transfer_id,p.from_account,p.settled_at
          FROM psp_inbound_receipts r JOIN pix_transfers p ON p.id=r.root_transfer_id
          JOIN spi_messages s ON s.end_to_end_id=r.end_to_end_id
            AND s.message_type='pacs.008'
          WHERE json_type(s.payload_json,'$.sender_account') IS NULL`);
        const senderDrift = (db.prepare(`SELECT COUNT(*) n FROM psp_inbound_receipts r
          JOIN pix_transfers p ON p.id=r.root_transfer_id
          LEFT JOIN psp_inbound_sender_facts f ON f.root_transfer_id=r.root_transfer_id
          WHERE f.root_transfer_id IS NULL OR f.sender_account<>p.from_account OR
            f.settled_at<>p.settled_at`)
          .get() as { n: number }).n;
        if (senderDrift) throw new Error("PSP_INBOUND_HISTORY_INVALID");
        db.prepare(`INSERT INTO psp_schema_migrations
          (name,completed_at) VALUES ('legacy_sender_facts_import',?)`)
          .run(this.now().toISOString());
      }
      if (this.db.prepare(`SELECT 1 FROM psp_inbound_receipts r
        LEFT JOIN psp_inbound_sender_facts f ON f.root_transfer_id=r.root_transfer_id
        WHERE f.root_transfer_id IS NULL LIMIT 1`).get())
        throw new Error("PSP_INBOUND_HISTORY_INVALID");
      if (!rootFactsImportDone) {
        db.exec(`INSERT OR IGNORE INTO psp_roots
          (root_transfer_id,end_to_end_id,account_id,amount_cents,source,registered_at)
          SELECT root_transfer_id,end_to_end_id,account_id,amount_cents,'receipt',credited_at
          FROM psp_inbound_receipts`);
        db.prepare(`INSERT OR IGNORE INTO psp_roots
          (root_transfer_id,end_to_end_id,account_id,amount_cents,source,registered_at)
          SELECT p.id,p.end_to_end_id,p.to_account,p.amount,'legacy',
            COALESCE(p.settled_at,p.initiated_at)
          FROM pix_transfers p JOIN psp_accounts a ON a.id=p.to_account
          LEFT JOIN psp_inbound_receipts r ON r.root_transfer_id=p.id
          WHERE r.root_transfer_id IS NULL
            AND p.status IN ('settled','returned_partial','returned_full')
            AND p.spi_command_version<>2
            AND (?=1 OR EXISTS (SELECT 1 FROM psp_funds f WHERE f.root_transfer_id=p.id))`)
          .run(Number(!fundsTableExists));
      }
      if (this.rootFactDrift() + (!rootFactsImportDone ? this.legacyRootBankDrift() : 0) !== 0)
        throw new Error("PSP_ROOT_HISTORY_INVALID");
      if (!fundsTableExists) db.exec(`INSERT INTO psp_funds
        (account_id,root_transfer_id,available_cents)
        SELECT p.to_account,p.id,p.amount-COALESCE(r.returned,0)
        FROM pix_transfers p JOIN psp_accounts a ON a.id=p.to_account
        LEFT JOIN (SELECT transfer_id,SUM(amount) returned FROM pix_returns GROUP BY transfer_id) r
          ON r.transfer_id=p.id
        WHERE p.status IN ('settled','returned_partial','returned_full')
          AND p.spi_command_version<>2`);
      const missingRoots = (!fundsImportDone ? (db.prepare(`SELECT COUNT(*) n FROM pix_transfers p
        JOIN psp_accounts a ON a.id=p.to_account
        LEFT JOIN psp_funds f ON f.account_id=p.to_account AND f.root_transfer_id=p.id
        WHERE p.status IN ('settled','returned_partial','returned_full')
          AND p.spi_command_version<>2 AND f.root_transfer_id IS NULL`)
        .get() as { n: number }).n : 0) +
        (db.prepare(`SELECT COUNT(*) n FROM psp_roots r
          LEFT JOIN psp_funds f ON f.account_id=r.account_id
            AND f.root_transfer_id=r.root_transfer_id
          WHERE f.root_transfer_id IS NULL`).get() as { n: number }).n;
      if (missingRoots) throw new Error("PSP_ROOT_HISTORY_INVALID");
      this.migrateFundReferences();
      this.migrateRootBoundTables();
      if (!rootFactsImportDone) db.prepare(`INSERT INTO psp_schema_migrations
        (name,completed_at) VALUES ('psp_root_facts_import',?)`).run(this.now().toISOString());
      if (!fundsImportDone) db.prepare(`INSERT INTO psp_schema_migrations
        (name,completed_at) VALUES ('legacy_funds_import',?)`).run(this.now().toISOString());
      if (!legacyProofImportDone) this.importLegacyInboundProofs();
      const seal = db.prepare(`SELECT count,sha256 FROM psp_legacy_inbound_proof_seal
        WHERE id=1`).get() as { count: number; sha256: string } | undefined;
      const actual = this.legacyInboundProofSeal();
      if (!seal || seal.count !== actual.count || seal.sha256 !== actual.sha256)
        throw new Error("PSP_LEGACY_PROOF_HISTORY_INVALID");
    });
  }

  private legacyInboundProofSeal(): { count: number; sha256: string } {
    const hash = createHash("sha256");
    let count = 0;
    for (const row of this.db.prepare(`SELECT root_transfer_id,end_to_end_id,account_id,
      amount_cents,sender_account,settled_at FROM psp_legacy_inbound_proofs
      ORDER BY root_transfer_id`).iterate() as Iterable<Record<string, unknown>>) {
      hash.update(JSON.stringify([row.root_transfer_id, row.end_to_end_id, row.account_id,
        row.amount_cents, row.sender_account, row.settled_at]));
      hash.update("\n");
      count++;
    }
    return { count, sha256: hash.digest("hex") };
  }

  private importLegacyInboundProofs(): void {
    const rows = this.db.prepare(`SELECT o.transfer_id,o.end_to_end_id,o.to_account,
      o.amount_cents,o.from_account,o.settled_at,
      p.id bank_id,p.end_to_end_id bank_e2e,p.to_account bank_to,
      p.amount bank_amount,p.from_account bank_from,p.settled_at bank_settled,
      p.status bank_status,a.ispb,req.payload_json request_json,
      res.payload_json response_json
      FROM pix_psp_inbound_outbox o
      JOIN spi_messages req ON req.end_to_end_id=o.end_to_end_id
        AND req.message_type='pacs.008'
      LEFT JOIN spi_messages res ON res.end_to_end_id=o.end_to_end_id
        AND res.message_type='pacs.002'
      LEFT JOIN pix_transfers p ON p.id=o.transfer_id
      LEFT JOIN psp_accounts a ON a.id=o.to_account
      WHERE o.acknowledged_at IS NULL
        AND json_type(req.payload_json,'$.root_transfer_id') IS NULL`)
      .all() as Record<string, unknown>[];
    const insert = this.db.prepare(`INSERT INTO psp_legacy_inbound_proofs
      (root_transfer_id,end_to_end_id,account_id,amount_cents,sender_account,settled_at)
      VALUES (?,?,?,?,?,?)`);
    for (const row of rows) {
      let request: Record<string, unknown>, response: Record<string, unknown>;
      try {
        request = JSON.parse(row.request_json as string) as Record<string, unknown>;
        response = JSON.parse(row.response_json as string) as Record<string, unknown>;
      } catch { throw new Error("PSP_LEGACY_PROOF_HISTORY_INVALID"); }
      if (!request || typeof request !== "object" || Array.isArray(request) ||
        !response || typeof response !== "object" || Array.isArray(response))
        throw new Error("PSP_LEGACY_PROOF_HISTORY_INVALID");
      if (row.bank_id !== row.transfer_id || row.bank_e2e !== row.end_to_end_id ||
        row.bank_to !== row.to_account || row.bank_amount !== row.amount_cents ||
        row.bank_from !== row.from_account || row.bank_settled !== row.settled_at ||
        !["settled", "returned_partial", "returned_full"].includes(row.bank_status as string) ||
        typeof row.from_account !== "string" || !row.from_account ||
        typeof row.settled_at !== "string" ||
        request.type !== "pacs.008" || request.end_to_end_id !== row.end_to_end_id ||
        request.from_ispb !== JACARANDA_ISPB || request.to_ispb !== row.ispb ||
        request.amount_cents !== row.amount_cents || request.root_transfer_id !== undefined ||
        (request.sender_account !== undefined && request.sender_account !== row.from_account) ||
        response.type !== "pacs.002" || response.status !== "ACSC" ||
        response.end_to_end_id !== row.end_to_end_id ||
        response.from_ispb !== request.from_ispb || response.to_ispb !== request.to_ispb ||
        response.amount_cents !== row.amount_cents)
        throw new Error("PSP_LEGACY_PROOF_HISTORY_INVALID");
      insert.run(row.transfer_id as string, row.end_to_end_id as string,
        row.to_account as string, row.amount_cents as number,
        row.from_account, row.settled_at);
    }
    const seal = this.legacyInboundProofSeal();
    this.db.prepare(`INSERT INTO psp_legacy_inbound_proof_seal
      (id,count,sha256) VALUES (1,?,?)`).run(seal.count, seal.sha256);
    this.db.prepare(`INSERT INTO psp_schema_migrations
      (name,completed_at) VALUES ('legacy_inbound_proofs_import',?)`)
      .run(this.now().toISOString());
  }

  private transaction<T>(work: () => T): T {
    if (this.db.isTransaction) return work();
    this.db.exec("BEGIN IMMEDIATE");
    try { const result = work(); this.db.exec("COMMIT"); return result; }
    catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  private medHoldDrift(): number {
    const missingOrChanged = (this.db.prepare(`SELECT COUNT(*) n FROM med_hops h
      LEFT JOIN psp_med_holds p ON p.hop_id=h.id
      WHERE p.hop_id IS NULL OR p.case_id<>h.case_id OR
        p.root_transfer_id<>h.root_transfer_id OR p.account_id<>h.account_id OR
        p.blocked_cents<>h.blocked_cents OR p.refunded_cents<>h.refunded_cents OR
        p.created_at<>h.created_at OR p.released_at IS NOT h.released_at`)
      .get() as { n: number }).n;
    const extra = (this.db.prepare(`SELECT COUNT(*) n FROM psp_med_holds p
      LEFT JOIN med_hops h ON h.id=p.hop_id WHERE h.id IS NULL`)
      .get() as { n: number }).n;
    return missingOrChanged + extra;
  }

  private rootFactDrift(): number {
    const receiptDrift = (this.db.prepare(`SELECT COUNT(*) n FROM psp_inbound_receipts i
      LEFT JOIN psp_roots r ON r.root_transfer_id=i.root_transfer_id
      WHERE r.root_transfer_id IS NULL OR r.source<>'receipt' OR
        r.end_to_end_id<>i.end_to_end_id OR r.account_id<>i.account_id OR
        r.amount_cents<>i.amount_cents OR r.registered_at<>i.credited_at`)
      .get() as { n: number }).n;
    const factDrift = (this.db.prepare(`SELECT COUNT(*) n FROM psp_roots r
      LEFT JOIN psp_inbound_receipts i ON i.root_transfer_id=r.root_transfer_id
      WHERE (r.source='receipt' AND i.root_transfer_id IS NULL)
        OR (r.source='legacy' AND i.root_transfer_id IS NOT NULL)`)
      .get() as { n: number }).n;
    const fundsWithoutRoot = (this.db.prepare(`SELECT COUNT(*) n FROM psp_funds f
      LEFT JOIN psp_roots r ON r.root_transfer_id=f.root_transfer_id
      WHERE r.root_transfer_id IS NULL`).get() as { n: number }).n;
    return receiptDrift + factDrift + fundsWithoutRoot;
  }

  private legacyRootBankDrift(): number {
    return (this.db.prepare(`SELECT COUNT(*) n FROM psp_roots r
      LEFT JOIN pix_transfers p ON p.id=r.root_transfer_id
      WHERE r.source='legacy' AND (p.id IS NULL OR
        p.end_to_end_id<>r.end_to_end_id OR p.to_account<>r.account_id OR
        p.amount<>r.amount_cents OR p.spi_command_version=2 OR
        p.status NOT IN ('settled','returned_partial','returned_full'))`)
      .get() as { n: number }).n;
  }

  private migrateFundReferences(): void {
    const references = this.db.prepare("PRAGMA foreign_key_list(psp_funds)")
      .all() as { table: string }[];
    if (this.db.prepare(`SELECT 1 FROM psp_funds f LEFT JOIN psp_roots r
      ON r.root_transfer_id=f.root_transfer_id WHERE r.root_transfer_id IS NULL LIMIT 1`).get())
      throw new Error("PSP_ROOT_HISTORY_INVALID");
    if (references.some((reference) => reference.table === "pix_transfers")) {
      this.db.exec(`CREATE TABLE psp_funds_v2 (
        account_id TEXT NOT NULL REFERENCES psp_accounts(id),
        root_transfer_id TEXT NOT NULL REFERENCES psp_roots(root_transfer_id),
        available_cents INTEGER NOT NULL CHECK(available_cents>=0),
        PRIMARY KEY(account_id,root_transfer_id)
      );
      INSERT INTO psp_funds_v2 (account_id,root_transfer_id,available_cents)
        SELECT account_id,root_transfer_id,available_cents FROM psp_funds;
      DROP TABLE psp_funds;
      ALTER TABLE psp_funds_v2 RENAME TO psp_funds;`);
      return;
    }
    if (!references.some((reference) => reference.table === "psp_roots"))
      throw new Error("PSP_ROOT_SCHEMA_INVALID");
  }

  private migrateRootBoundTables(): void {
    const needsMigration = (table: "psp_transfers" | "psp_cashouts" | "psp_cautelar_holds") => {
      const references = this.db.prepare(`PRAGMA foreign_key_list(${table})`)
        .all() as { table: string }[];
      if (references.some((reference) => reference.table === "psp_roots") &&
        !references.some((reference) => reference.table === "pix_transfers")) return false;
      if (this.db.prepare(`SELECT 1 FROM ${table} t LEFT JOIN psp_roots r
        ON r.root_transfer_id=t.root_transfer_id WHERE r.root_transfer_id IS NULL LIMIT 1`).get())
        throw new Error("PSP_ROOT_HISTORY_INVALID");
      return true;
    };
    if (needsMigration("psp_transfers")) this.db.exec(`CREATE TABLE psp_transfers_v2 (
      id TEXT PRIMARY KEY, root_transfer_id TEXT NOT NULL REFERENCES psp_roots(root_transfer_id),
      from_account TEXT NOT NULL REFERENCES psp_accounts(id),
      to_account TEXT NOT NULL REFERENCES psp_accounts(id),
      idempotency_key TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0),
      end_to_end_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
      created_at TEXT NOT NULL, UNIQUE(from_account,idempotency_key)
    );
    INSERT INTO psp_transfers_v2
      (id,root_transfer_id,from_account,to_account,idempotency_key,amount,end_to_end_id,status,created_at)
      SELECT id,root_transfer_id,from_account,to_account,idempotency_key,amount,end_to_end_id,status,created_at
      FROM psp_transfers;
    DROP TABLE psp_transfers;
    ALTER TABLE psp_transfers_v2 RENAME TO psp_transfers;
    CREATE INDEX psp_transfers_root ON psp_transfers(root_transfer_id);`);
    if (needsMigration("psp_cashouts")) this.db.exec(`CREATE TABLE psp_cashouts_v2 (
      id TEXT PRIMARY KEY, root_transfer_id TEXT NOT NULL REFERENCES psp_roots(root_transfer_id),
      account_id TEXT NOT NULL REFERENCES psp_accounts(id),
      idempotency_key TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0),
      end_to_end_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
      created_at TEXT NOT NULL, UNIQUE(account_id,idempotency_key)
    );
    INSERT INTO psp_cashouts_v2
      (id,root_transfer_id,account_id,idempotency_key,amount,end_to_end_id,status,created_at)
      SELECT id,root_transfer_id,account_id,idempotency_key,amount,end_to_end_id,status,created_at
      FROM psp_cashouts;
    DROP TABLE psp_cashouts;
    ALTER TABLE psp_cashouts_v2 RENAME TO psp_cashouts;`);
    if (needsMigration("psp_cautelar_holds")) {
      this.db.exec(`CREATE TABLE psp_cautelar_holds_v2 (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES psp_accounts(id),
        root_transfer_id TEXT NOT NULL REFERENCES psp_roots(root_transfer_id),
        amount_cents INTEGER NOT NULL CHECK(amount_cents>0), reason TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN
          ('active','released','returned','expired','superseded_by_med')),
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, resolved_at TEXT,
        resolved_by TEXT
      );
      INSERT INTO psp_cautelar_holds_v2
        (id,account_id,root_transfer_id,amount_cents,reason,status,created_at,expires_at,resolved_at,resolved_by)
        SELECT id,account_id,root_transfer_id,amount_cents,reason,status,created_at,expires_at,resolved_at,resolved_by
        FROM psp_cautelar_holds;
      CREATE TABLE psp_cautelar_notices_v2 (
        id INTEGER PRIMARY KEY, account_id TEXT NOT NULL REFERENCES psp_accounts(id),
        hold_id TEXT NOT NULL REFERENCES psp_cautelar_holds_v2(id),
        kind TEXT NOT NULL CHECK(kind IN
          ('held','released','returned','expired','med_review')),
        amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        message_pt TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(hold_id,kind)
      );
      INSERT INTO psp_cautelar_notices_v2
        (id,account_id,hold_id,kind,amount_cents,message_pt,created_at)
        SELECT id,account_id,hold_id,kind,amount_cents,message_pt,created_at
        FROM psp_cautelar_notices;
      DROP TABLE psp_cautelar_notices;
      DROP TABLE psp_cautelar_holds;
      ALTER TABLE psp_cautelar_holds_v2 RENAME TO psp_cautelar_holds;
      ALTER TABLE psp_cautelar_notices_v2 RENAME TO psp_cautelar_notices;
      CREATE UNIQUE INDEX psp_inbound_review_once
        ON psp_cautelar_holds(root_transfer_id) WHERE reason='PSP_FAN_IN_10M';
      CREATE INDEX psp_cautelar_active
        ON psp_cautelar_holds(account_id,root_transfer_id,status,expires_at);
      CREATE INDEX psp_cautelar_notices_account
        ON psp_cautelar_notices(account_id,id);
      CREATE TRIGGER psp_cautelar_notices_no_update
        BEFORE UPDATE ON psp_cautelar_notices
        BEGIN SELECT RAISE(ABORT,'PSP_CAUTELAR_NOTICE_IMMUTABLE'); END;
      CREATE TRIGGER psp_cautelar_notices_no_delete
        BEFORE DELETE ON psp_cautelar_notices
        BEGIN SELECT RAISE(ABORT,'PSP_CAUTELAR_NOTICE_IMMUTABLE'); END;`);
      if (this.db.prepare("PRAGMA foreign_key_check(psp_cautelar_notices)").get())
        throw new Error("PSP_CAUTELAR_HISTORY_INVALID");
    }
  }

  private migrateMedNoticeReferences(): void {
    const references = this.db.prepare("PRAGMA foreign_key_list(psp_med_notices)")
      .all() as { table: string }[];
    if (references.some((reference) => reference.table === "med_hops" ||
      reference.table === "med_cases")) {
      const invalid = (this.db.prepare(`SELECT COUNT(*) n FROM psp_med_notices n
        LEFT JOIN psp_med_holds h ON h.hop_id=n.hop_id
        WHERE h.hop_id IS NULL OR h.account_id<>n.account_id OR h.case_id<>n.case_id`)
        .get() as { n: number }).n;
      if (invalid) throw new Error("PSP_MED_NOTICE_HISTORY_INVALID");
      this.db.exec(`CREATE TABLE psp_med_notices_v2 (
        id INTEGER PRIMARY KEY, account_id TEXT NOT NULL REFERENCES psp_accounts(id),
        hop_id TEXT NOT NULL REFERENCES psp_med_holds(hop_id),
        case_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('blocked','recovered','released')),
        amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
        message_pt TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(hop_id,kind)
      );
      INSERT INTO psp_med_notices_v2
        (id,account_id,hop_id,case_id,kind,amount_cents,message_pt,created_at)
        SELECT id,account_id,hop_id,case_id,kind,amount_cents,message_pt,created_at
        FROM psp_med_notices ORDER BY id;
      DROP TABLE psp_med_notices;
      ALTER TABLE psp_med_notices_v2 RENAME TO psp_med_notices;
      CREATE INDEX psp_med_notices_account ON psp_med_notices(account_id,id);
      CREATE TRIGGER psp_med_notices_no_update BEFORE UPDATE ON psp_med_notices
        BEGIN SELECT RAISE(ABORT,'PSP_MED_NOTICE_IMMUTABLE'); END;
      CREATE TRIGGER psp_med_notices_no_delete BEFORE DELETE ON psp_med_notices
        BEGIN SELECT RAISE(ABORT,'PSP_MED_NOTICE_IMMUTABLE'); END;`);
      return;
    }
    if (!references.some((reference) => reference.table === "psp_med_holds"))
      throw new Error("PSP_MED_NOTICE_SCHEMA_INVALID");
  }

  private creditRoot(accountId: string, rootTransferId: string, amount: number): void {
    if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error("PSP_AMOUNT_INVALID");
    this.db.prepare(`INSERT INTO psp_funds (account_id,root_transfer_id,available_cents)
      VALUES (?,?,?) ON CONFLICT(account_id,root_transfer_id) DO UPDATE SET
      available_cents=available_cents+excluded.available_cents`).run(accountId, rootTransferId, amount);
    this.holdMedNewCredit(accountId, rootTransferId, amount);
  }

  private holdMedNewCredit(accountId: string, rootTransferId: string,
    creditedCents: number): void {
    const embedded = Boolean(this.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='med_cases'`).get());
    // An exported ecosystem snapshot can run PSP transfers before its MED worker
    // schema has been installed. With no case-opening table there are no cases.
    if (!embedded && !this.db.prepare(`SELECT 1 FROM sqlite_master
      WHERE type='table' AND name='psp_med_case_openings'`).get()) return;
    const cases = (embedded ? this.db.prepare(`SELECT m.id case_id,
      m.transfer_id original_root,m.claim_amount_cents claim_amount
      FROM med_cases m WHERE m.status='open' AND NOT EXISTS
        (SELECT 1 FROM med_decisions d WHERE d.case_id=m.id)
      AND ((SELECT account_id FROM psp_roots
        WHERE root_transfer_id=m.transfer_id)=? OR EXISTS
        (SELECT 1 FROM psp_transfers t WHERE t.root_transfer_id=m.transfer_id
          AND t.to_account=? AND t.status='settled'))
      ORDER BY m.opened_at,m.id`) : this.db.prepare(`SELECT o.case_id,
      o.root_transfer_id original_root,o.claim_amount_cents claim_amount
      FROM psp_med_case_openings o WHERE NOT EXISTS
        (SELECT 1 FROM dict_med_analyses a WHERE a.case_id=o.case_id)
      AND NOT EXISTS (SELECT 1 FROM psp_med_case_releases r WHERE r.case_id=o.case_id)
      AND NOT EXISTS (SELECT 1 FROM psp_med_case_settlements s WHERE s.case_id=o.case_id)
      AND ((SELECT account_id FROM psp_roots
        WHERE root_transfer_id=o.root_transfer_id)=? OR EXISTS
        (SELECT 1 FROM psp_transfers t WHERE t.root_transfer_id=o.root_transfer_id
          AND t.to_account=? AND t.status='settled'))
      ORDER BY o.created_at,o.case_id`)).all(accountId, accountId) as
      { case_id: string; original_root: string; claim_amount: number }[];
    for (const item of cases) {
      const alreadyHeld = (this.db.prepare(`SELECT COALESCE(SUM(blocked_cents),0) n
        FROM psp_med_holds WHERE case_id=? AND released_at IS NULL`)
        .get(item.case_id) as { n: number }).n;
      const blocked = Math.min(creditedCents, item.claim_amount - alreadyHeld,
        this.availableRoot(accountId, rootTransferId));
      if (blocked <= 0) continue;
      const createdAt = this.now().toISOString();
      const id = newId("medhop", this.now().getTime());
      this.recordMedHold({ id, case_id: item.case_id, root_transfer_id: rootTransferId,
        account_id: accountId, blocked_cents: blocked, created_at: createdAt });
      if (embedded) this.db.prepare(`INSERT INTO med_hops
        (id,case_id,root_transfer_id,account_id,blocked_cents,created_at)
        VALUES (?,?,?,?,?,?)`).run(id, item.case_id, rootTransferId,
          accountId, blocked, createdAt);
      this.notifyMedHop(id, "blocked", blocked);
    }
  }

  reserveAvailableMedFunds(accountId: string, rootTransferId: string): void {
    if (!this.db.isTransaction) throw new Error("PSP_MED_HOLD_INVALID");
    const available = this.availableRoot(accountId, rootTransferId);
    if (available > 0) this.holdMedNewCredit(accountId, rootTransferId, available);
  }

  creditInbound(accountId: string, rootTransferId: string, endToEndId: string,
    amountCents: number, senderAccount: string, settledAt: string): void {
    if (!accountId || !rootTransferId || !endToEndId ||
      !Number.isSafeInteger(amountCents) || amountCents <= 0 ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(senderAccount) ||
      !Number.isFinite(Date.parse(settledAt)) ||
      new Date(settledAt).toISOString() !== settledAt)
      throw new Error("PSP_INBOUND_INVALID");
    this.transaction(() => {
      const prior = this.db.prepare(`SELECT root_transfer_id,account_id,end_to_end_id,amount_cents
        FROM psp_inbound_receipts WHERE root_transfer_id=? OR end_to_end_id=?`)
        .get(rootTransferId, endToEndId) as { root_transfer_id: string; account_id: string;
          end_to_end_id: string; amount_cents: number } | undefined;
      if (prior) {
        const request = this.spi.messages(endToEndId)
          .find((message) => message.type === "pacs.008");
        if (request?.recipient_account !== undefined &&
          request.recipient_account !== accountId)
          throw new Error("PSP_INBOUND_SPI_PROOF_INVALID");
        const fact = this.db.prepare(`SELECT sender_account,settled_at
          FROM psp_inbound_sender_facts WHERE root_transfer_id=?`)
          .get(rootTransferId) as { sender_account: string; settled_at: string } | undefined;
        const root = this.db.prepare(`SELECT end_to_end_id,account_id,amount_cents,source
          FROM psp_roots WHERE root_transfer_id=?`).get(rootTransferId) as
          { end_to_end_id: string; account_id: string; amount_cents: number; source: string } | undefined;
        if (prior.root_transfer_id !== rootTransferId || prior.account_id !== accountId ||
          prior.end_to_end_id !== endToEndId ||
          prior.amount_cents !== amountCents || fact?.sender_account !== senderAccount ||
          fact?.settled_at !== settledAt || !root || root.source !== "receipt" ||
          root.end_to_end_id !== endToEndId || root.account_id !== accountId ||
          root.amount_cents !== amountCents)
          throw new Error("PSP_INBOUND_IDEMPOTENCY_CONFLICT");
        return;
      }
      const account = this.spi.account(accountId);
      const messages = this.spi.messages(endToEndId);
      const request = messages.find((message) => message.type === "pacs.008");
      const response = messages.find((message) => message.type === "pacs.002");
      const legacyRoot = request?.root_transfer_id === undefined ? this.db.prepare(`SELECT 1
        FROM psp_legacy_inbound_proofs WHERE root_transfer_id=? AND end_to_end_id=?
        AND account_id=? AND amount_cents=? AND sender_account=? AND settled_at=?`)
        .get(rootTransferId, endToEndId, accountId, amountCents, senderAccount, settledAt) : true;
      if (!account || !request || !response ||
        request.from_ispb !== JACARANDA_ISPB || request.to_ispb !== account.ispb ||
        request.amount_cents !== amountCents || response.status !== "ACSC" ||
        (request.root_transfer_id !== undefined && request.root_transfer_id !== rootTransferId) ||
        (request.recipient_account !== undefined && request.recipient_account !== accountId) ||
        !legacyRoot ||
        (request.sender_account !== undefined && request.sender_account !== senderAccount) ||
        response.from_ispb !== request.from_ispb || response.to_ispb !== request.to_ispb ||
        response.amount_cents !== amountCents)
        throw new Error("PSP_INBOUND_SPI_PROOF_INVALID");
      if (this.db.prepare(`SELECT 1 FROM psp_funds WHERE account_id=? AND root_transfer_id=?`)
        .get(accountId, rootTransferId))
        throw new Error("PSP_INBOUND_ROOT_CONFLICT");
      const creditedAt = this.now().toISOString();
      this.db.prepare(`INSERT INTO psp_roots
        (root_transfer_id,end_to_end_id,account_id,amount_cents,source,registered_at)
        VALUES (?,?,?,?, 'receipt', ?)`).run(rootTransferId, endToEndId, accountId,
        amountCents, creditedAt);
      this.db.prepare(`INSERT INTO psp_inbound_receipts
        (root_transfer_id,end_to_end_id,account_id,amount_cents,credited_at)
        VALUES (?,?,?,?,?)`).run(rootTransferId, endToEndId, accountId,
        amountCents, creditedAt);
      this.db.prepare(`INSERT INTO psp_inbound_sender_facts
        (root_transfer_id,sender_account,settled_at) VALUES (?,?,?)`)
        .run(rootTransferId, senderAccount, settledAt);
      this.db.prepare("UPDATE psp_accounts SET balance_cents=balance_cents+? WHERE id=?")
        .run(amountCents, accountId);
      this.creditRoot(accountId, rootTransferId, amountCents);
    });
  }

  rootBalance(accountId: string, rootTransferId: string): number {
    return (this.db.prepare("SELECT available_cents FROM psp_funds WHERE account_id=? AND root_transfer_id=?")
      .get(accountId, rootTransferId) as { available_cents: number } | undefined)?.available_cents ?? 0;
  }

  availableRoot(accountId: string, rootTransferId: string): number {
    const medBlocked = (this.db.prepare(`SELECT COALESCE(SUM(blocked_cents),0) n FROM psp_med_holds
      WHERE account_id=? AND root_transfer_id=? AND released_at IS NULL`)
      .get(accountId, rootTransferId) as { n: number }).n;
    const cautelarBlocked = (this.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) n
      FROM psp_cautelar_holds WHERE account_id=? AND root_transfer_id=?
      AND status='active' AND expires_at>?`)
      .get(accountId, rootTransferId, this.now().toISOString()) as { n: number }).n;
    return Math.max(0, this.rootBalance(accountId, rootTransferId) - medBlocked - cautelarBlocked);
  }

  cautelarHold(id: string): PspCautelarHold | undefined {
    return this.db.prepare(`SELECT id,account_id,root_transfer_id,amount_cents,reason,
      status,created_at,expires_at,resolved_at,resolved_by FROM psp_cautelar_holds WHERE id=?`)
      .get(id) as PspCautelarHold | undefined;
  }

  cautelarNotices(accountId: string, afterId = 0, limit = 100): PspCautelarNotice[] {
    if (!this.spi.account(accountId) || !Number.isSafeInteger(afterId) || afterId < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("PSP_NOTICE_QUERY_INVALID");
    return this.db.prepare(`SELECT id,account_id,hold_id,kind,amount_cents,
      message_pt,created_at FROM psp_cautelar_notices
      WHERE account_id=? AND id>? ORDER BY id LIMIT ?`)
      .all(accountId, afterId, limit) as unknown as PspCautelarNotice[];
  }

  medNotices(accountId: string, afterId = 0, limit = 100): PspMedNotice[] {
    if (!this.spi.account(accountId) || !Number.isSafeInteger(afterId) || afterId < 0 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("PSP_NOTICE_QUERY_INVALID");
    return this.db.prepare(`SELECT id,account_id,hop_id,case_id,kind,amount_cents,
      message_pt,created_at FROM psp_med_notices
      WHERE account_id=? AND id>? ORDER BY id LIMIT ?`)
      .all(accountId, afterId, limit) as unknown as PspMedNotice[];
  }

  recordMedHold(hop: { id: string; case_id: string; root_transfer_id: string;
    account_id: string; blocked_cents: number; created_at: string }): void {
    if (!this.db.isTransaction || !Number.isSafeInteger(hop.blocked_cents) ||
      hop.blocked_cents <= 0 ||
      this.availableRoot(hop.account_id, hop.root_transfer_id) < hop.blocked_cents)
      throw new Error("PSP_MED_HOLD_INVALID");
    this.db.prepare(`INSERT INTO psp_med_holds
      (hop_id,case_id,root_transfer_id,account_id,blocked_cents,created_at)
      VALUES (?,?,?,?,?,?)`).run(hop.id, hop.case_id, hop.root_transfer_id,
        hop.account_id, hop.blocked_cents, hop.created_at);
  }

  releaseMedHold(hopId: string, releasedAt: string): void {
    if (!this.db.isTransaction) throw new Error("PSP_MED_HOLD_INVALID");
    const result = this.db.prepare(`UPDATE psp_med_holds SET released_at=?
      WHERE hop_id=? AND released_at IS NULL`).run(releasedAt, hopId);
    if (result.changes !== 1) throw new Error("PSP_MED_HOLD_INVALID");
  }

  recordMedRefund(hopId: string, amountCents: number): void {
    if (!this.db.isTransaction || !Number.isSafeInteger(amountCents) || amountCents <= 0)
      throw new Error("PSP_MED_HOLD_INVALID");
    const result = this.db.prepare(`UPDATE psp_med_holds SET refunded_cents=?
      WHERE hop_id=? AND released_at IS NOT NULL AND refunded_cents=0
      AND blocked_cents>=?`).run(amountCents, hopId, amountCents);
    if (result.changes !== 1) throw new Error("PSP_MED_HOLD_INVALID");
  }

  notifyMedHop(hopId: string, kind: PspMedNotice["kind"], amountCents: number): void {
    if (!this.db.isTransaction || !Number.isSafeInteger(amountCents) || amountCents <= 0)
      throw new Error("PSP_MED_NOTICE_INVALID");
    const hop = this.db.prepare(`SELECT account_id,case_id,blocked_cents,refunded_cents,released_at
      FROM psp_med_holds WHERE hop_id=?`)
      .get(hopId) as { account_id: string; case_id: string; blocked_cents: number;
        refunded_cents: number; released_at: string | null } | undefined;
    if (!hop || (kind === "blocked" ? hop.released_at !== null || amountCents !== hop.blocked_cents :
      hop.released_at === null || amountCents !==
        (kind === "recovered" ? hop.refunded_cents : hop.blocked_cents - hop.refunded_cents)))
      throw new Error("PSP_MED_NOTICE_INVALID");
    const messages: Record<PspMedNotice["kind"], string> = {
      blocked: "Saldo Pix bloqueado para análise MED.",
      recovered: "Saldo Pix devolvido após análise MED.",
      released: "Saldo Pix liberado após análise MED.",
    };
    this.db.prepare(`INSERT INTO psp_med_notices
      (account_id,hop_id,case_id,kind,amount_cents,message_pt,created_at)
      VALUES (?,?,?,?,?,?,?)`).run(hop.account_id, hopId, hop.case_id, kind,
        amountCents, messages[kind], this.now().toISOString());
  }

  private notifyCautelar(hold: PspCautelarHold,
    kind: PspCautelarNotice["kind"]): void {
    const messages: Record<PspCautelarNotice["kind"], string> = {
      held: "Crédito Pix bloqueado cautelarmente para análise.",
      released: "Crédito Pix liberado após análise cautelar.",
      returned: "Crédito Pix devolvido ao pagador após análise cautelar.",
      expired: "Bloqueio cautelar encerrado pelo prazo; crédito liberado.",
      med_review: "Bloqueio cautelar transferido para análise MED.",
    };
    this.db.prepare(`INSERT INTO psp_cautelar_notices
      (account_id,hold_id,kind,amount_cents,message_pt,created_at)
      VALUES (?,?,?,?,?,?)`).run(hold.account_id, hold.id, kind,
        hold.amount_cents, messages[kind], this.now().toISOString());
  }

  placeCautelar(accountId: string, rootTransferId: string, amountCents: number,
    reason: string): PspCautelarHold {
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0 ||
      !/^[A-Z0-9_-]{1,64}$/.test(reason)) throw new Error("PSP_CAUTELAR_INVALID");
    return this.transaction(() => {
      if (!this.spi.account(accountId) || this.availableRoot(accountId, rootTransferId) < amountCents)
        throw new Error("PSP_CAUTELAR_FUNDS_UNAVAILABLE");
      const id = newId("cautelar", this.now().getTime());
      const createdAt = this.now().toISOString();
      const expiresAt = new Date(this.now().getTime() + 72 * 3_600_000).toISOString();
      this.db.prepare(`INSERT INTO psp_cautelar_holds
        (id,account_id,root_transfer_id,amount_cents,reason,status,created_at,expires_at)
        VALUES (?,?,?,?,?,'active',?,?)`).run(id, accountId, rootTransferId,
          amountCents, reason, createdAt, expiresAt);
      const hold = this.cautelarHold(id)!;
      this.notifyCautelar(hold, "held");
      return hold;
    });
  }

  reviewIncoming(accountId: string, rootTransferId: string, amountCents: number):
    PspCautelarHold | undefined {
    const prior = this.db.prepare(`SELECT id FROM psp_cautelar_holds
      WHERE root_transfer_id=? AND reason='PSP_FAN_IN_10M'`).get(rootTransferId) as
      { id: string } | undefined;
    if (prior) return this.cautelarHold(prior.id);
    const since = new Date(this.now().getTime() - 600_000).toISOString();
    const senders = (this.db.prepare(`SELECT COUNT(DISTINCT f.sender_account) n
      FROM psp_inbound_sender_facts f JOIN psp_inbound_receipts r
      ON r.root_transfer_id=f.root_transfer_id
      WHERE r.account_id=? AND f.settled_at>=?`)
      .get(accountId, since) as { n: number }).n;
    if (senders < 5) return undefined;
    const available = Math.min(amountCents, this.availableRoot(accountId, rootTransferId));
    return available > 0 ? this.placeCautelar(accountId, rootTransferId,
      available, "PSP_FAN_IN_10M") : undefined;
  }

  resolveCautelar(id: string, status: "released" | "returned", actor: string): PspCautelarHold {
    if (status !== "released" && status !== "returned" ||
      !/^[a-zA-Z0-9_-]{1,64}$/.test(actor))
      throw new Error("PSP_CAUTELAR_REVIEW_INVALID");
    return this.transaction(() => {
      const hold = this.cautelarHold(id);
      if (!hold) throw new Error("PSP_CAUTELAR_NOT_FOUND");
      if (hold.status !== "active" || hold.expires_at <= this.now().toISOString())
        throw new Error("PSP_CAUTELAR_NOT_ACTIVE");
      this.db.prepare(`UPDATE psp_cautelar_holds
        SET status=?,resolved_at=?,resolved_by=? WHERE id=?`)
        .run(status, this.now().toISOString(), actor, id);
      const resolved = this.cautelarHold(id)!;
      this.notifyCautelar(resolved, status);
      return resolved;
    });
  }

  supersedeCautelarForMed(rootTransferId: string): number {
    return this.transaction(() => {
      const now = this.now().toISOString();
      const holds = this.db.prepare(`SELECT id FROM psp_cautelar_holds
        WHERE root_transfer_id=? AND status='active' AND expires_at>?`)
        .all(rootTransferId, now) as { id: string }[];
      const update = this.db.prepare(`UPDATE psp_cautelar_holds
        SET status='superseded_by_med',resolved_at=? WHERE id=?`);
      for (const row of holds) {
        update.run(now, row.id);
        this.notifyCautelar(this.cautelarHold(row.id)!, "med_review");
      }
      return holds.length;
    });
  }

  expireCautelar(): number {
    return this.transaction(() => {
      const now = this.now().toISOString();
      const holds = this.db.prepare(`SELECT id FROM psp_cautelar_holds
        WHERE status='active' AND expires_at<=?`).all(now) as { id: string }[];
      const update = this.db.prepare(`UPDATE psp_cautelar_holds
        SET status='expired',resolved_at=? WHERE id=?`);
      for (const row of holds) {
        update.run(now, row.id);
        this.notifyCautelar(this.cautelarHold(row.id)!, "expired");
      }
      return holds.length;
    });
  }

  debitRoot(accountId: string, rootTransferId: string, amount: number): void {
    if (!Number.isSafeInteger(amount) || amount <= 0 ||
      this.availableRoot(accountId, rootTransferId) < amount) throw new Error("PSP_FUNDS_UNAVAILABLE");
    const result = this.db.prepare(`UPDATE psp_funds SET available_cents=available_cents-?
      WHERE account_id=? AND root_transfer_id=? AND available_cents>=?`)
      .run(amount, accountId, rootTransferId, amount);
    if (result.changes !== 1) throw new Error("PSP_FUNDS_UNAVAILABLE");
  }

  debitAccountRoot(accountId: string, rootTransferId: string, amount: number): void {
    this.db.exec("SAVEPOINT psp_account_root_debit");
    try {
      this.debitRoot(accountId, rootTransferId, amount);
      const result = this.db.prepare(`UPDATE psp_accounts
        SET balance_cents=balance_cents-? WHERE id=? AND balance_cents>=?`)
        .run(amount, accountId, amount);
      if (result.changes !== 1) throw new Error("PSP_FUNDS_UNAVAILABLE");
      this.db.exec("RELEASE psp_account_root_debit");
    } catch (error) {
      this.db.exec("ROLLBACK TO psp_account_root_debit");
      this.db.exec("RELEASE psp_account_root_debit");
      throw error;
    }
  }

  setFraudFlagByKey(key: string, flagged: boolean): void {
    const result = this.db.prepare("UPDATE psp_accounts SET fraud_flag=? WHERE pix_key=?")
      .run(Number(flagged), key);
    if (result.changes !== 1) throw new Error("PSP_ACCOUNT_UNAVAILABLE");
  }

  transfer(rootTransferId: string, fromAccount: string, toAccount: string, amount: number,
    idempotencyKey: string): PspTransferResult {
    if (!Number.isSafeInteger(amount) || amount <= 0 || amount > 2_000_000 ||
      !idempotencyKey || idempotencyKey.length > 128) throw new Error("PSP_INPUT_INVALID");
    return this.transaction(() => {
      const existing = this.db.prepare(`SELECT id,root_transfer_id,from_account,to_account,
        amount,end_to_end_id,status FROM psp_transfers WHERE from_account=? AND idempotency_key=?`)
        .get(fromAccount, idempotencyKey) as PspTransferResult | undefined;
      if (existing) {
        if (existing.root_transfer_id !== rootTransferId || existing.to_account !== toAccount ||
          existing.amount !== amount) throw new Error("PSP_IDEMPOTENCY_CONFLICT");
        return existing;
      }
      const from = this.spi.account(fromAccount); const to = this.spi.account(toAccount);
      if (!from || !to || fromAccount === toAccount || from.status !== "active" ||
        to.status !== "active" || to.fraud_flag) throw new Error("PSP_ACCOUNT_UNAVAILABLE");
      if (this.availableRoot(fromAccount, rootTransferId) < amount)
        throw new Error("PSP_FUNDS_UNAVAILABLE");
      const id = newId("pspix", this.now().getTime());
      const endToEndId = pixEndToEndIdForIspb(id, this.now(), from.ispb);
      const accepted = from.ispb === to.ispb || this.spi.settle(endToEndId, from.ispb, to.ispb, amount);
      const status = accepted ? "settled" : "rejected";
      if (accepted) {
        this.debitRoot(fromAccount, rootTransferId, amount);
        this.creditRoot(toAccount, rootTransferId, amount);
        this.db.prepare("UPDATE psp_accounts SET balance_cents=balance_cents-? WHERE id=?")
          .run(amount, fromAccount);
        this.db.prepare("UPDATE psp_accounts SET balance_cents=balance_cents+? WHERE id=?")
          .run(amount, toAccount);
      }
      this.db.prepare(`INSERT INTO psp_transfers
        (id,root_transfer_id,from_account,to_account,idempotency_key,amount,
         end_to_end_id,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(id, rootTransferId, fromAccount, toAccount, idempotencyKey, amount,
          endToEndId, status, this.now().toISOString());
      return { id, root_transfer_id: rootTransferId, from_account: fromAccount,
        to_account: toAccount, amount, end_to_end_id: endToEndId, status };
    });
  }

  cashOut(rootTransferId: string, accountId: string, amount: number,
    idempotencyKey: string): { id: string; amount: number; end_to_end_id: string; status: string } {
    if (!Number.isSafeInteger(amount) || amount <= 0 || amount > 2_000_000 ||
      !idempotencyKey || idempotencyKey.length > 128) throw new Error("PSP_INPUT_INVALID");
    return this.transaction(() => {
      const existing = this.db.prepare(`SELECT id,root_transfer_id,amount,end_to_end_id,status
        FROM psp_cashouts WHERE account_id=? AND idempotency_key=?`)
        .get(accountId, idempotencyKey) as { id: string; root_transfer_id: string;
          amount: number; end_to_end_id: string; status: string } | undefined;
      if (existing) {
        if (existing.root_transfer_id !== rootTransferId || existing.amount !== amount)
          throw new Error("PSP_IDEMPOTENCY_CONFLICT");
        return existing;
      }
      const account = this.spi.account(accountId);
      if (!account || account.status !== "active") throw new Error("PSP_ACCOUNT_UNAVAILABLE");
      if (this.availableRoot(accountId, rootTransferId) < amount)
        throw new Error("PSP_FUNDS_UNAVAILABLE");
      const id = newId("cashout", this.now().getTime());
      const endToEndId = pixEndToEndIdForIspb(id, this.now(), account.ispb);
      const accepted = this.spi.settle(endToEndId, account.ispb, CASHOUT_ISPB, amount);
      const status = accepted ? "settled" : "rejected";
      if (accepted) {
        this.debitRoot(accountId, rootTransferId, amount);
        this.db.prepare("UPDATE psp_accounts SET balance_cents=balance_cents-? WHERE id=?")
          .run(amount, accountId);
      }
      this.db.prepare(`INSERT INTO psp_cashouts
        (id,root_transfer_id,account_id,idempotency_key,amount,end_to_end_id,status,created_at)
        VALUES (?,?,?,?,?,?,?,?)`).run(id, rootTransferId, accountId, idempotencyKey,
          amount, endToEndId, status, this.now().toISOString());
      return { id, amount, end_to_end_id: endToEndId, status };
    });
  }

  trace(rootTransferId: string): { account_id: string; ispb: string; available_cents: number }[] {
    return this.db.prepare(`SELECT f.account_id,a.ispb,f.available_cents FROM psp_funds f
      JOIN psp_accounts a ON a.id=f.account_id
      WHERE f.root_transfer_id=? AND f.available_cents>0 ORDER BY f.account_id`)
      .all(rootTransferId) as { account_id: string; ispb: string; available_cents: number }[];
  }

  path(rootTransferId: string): { kind: "payment" | "transfer" | "cashout";
    from_ispb: string; to_ispb: string; amount_cents: number; end_to_end_id: string }[] {
    const root = this.db.prepare(`SELECT r.amount_cents amount,r.end_to_end_id,a.ispb
      FROM psp_roots r JOIN psp_accounts a ON a.id=r.account_id
      WHERE r.root_transfer_id=?`)
      .get(rootTransferId) as { amount: number; end_to_end_id: string; ispb: string } | undefined;
    if (!root) return [];
    const transfers = this.db.prepare(`SELECT f.ispb from_ispb,t.ispb to_ispb,
      p.amount amount_cents,p.end_to_end_id FROM psp_transfers p
      JOIN psp_accounts f ON f.id=p.from_account JOIN psp_accounts t ON t.id=p.to_account
      WHERE p.root_transfer_id=? AND p.status='settled' ORDER BY p.created_at,p.id`)
      .all(rootTransferId) as { from_ispb: string; to_ispb: string;
        amount_cents: number; end_to_end_id: string }[];
    const cashouts = this.db.prepare(`SELECT a.ispb from_ispb,
      p.amount amount_cents,p.end_to_end_id FROM psp_cashouts p
      JOIN psp_accounts a ON a.id=p.account_id
      WHERE p.root_transfer_id=? AND p.status='settled' ORDER BY p.created_at,p.id`)
      .all(rootTransferId) as { from_ispb: string; amount_cents: number;
        end_to_end_id: string }[];
    return [
      { kind: "payment", from_ispb: JACARANDA_ISPB, to_ispb: root.ispb,
        amount_cents: root.amount, end_to_end_id: root.end_to_end_id },
      ...transfers.map((item) => ({ kind: "transfer" as const, ...item })),
      ...cashouts.map((item) => ({ kind: "cashout" as const, ...item,
        to_ispb: CASHOUT_ISPB })),
    ];
  }

  reconcile(): { ok: boolean; account_drift: number; root_overflow: number;
      root_fact_drift: number; hold_overflow: number;
      inbound_sender_drift: number; inbound_spi_drift: number } {
    const accountDrift = (this.db.prepare(`SELECT COUNT(*) n FROM psp_accounts a LEFT JOIN
      (SELECT account_id,SUM(available_cents) total FROM psp_funds GROUP BY account_id) f
      ON f.account_id=a.id WHERE a.balance_cents<>COALESCE(f.total,0)`)
      .get() as { n: number }).n;
    const rootOverflow = (this.db.prepare(`SELECT COUNT(*) n FROM
      (SELECT root_transfer_id,SUM(available_cents) total FROM psp_funds GROUP BY root_transfer_id) f
      LEFT JOIN psp_roots r ON r.root_transfer_id=f.root_transfer_id
      WHERE r.root_transfer_id IS NULL OR f.total>r.amount_cents`)
      .get() as { n: number }).n;
    const rootFactDrift = this.rootFactDrift();
    const holdOverflow = (this.db.prepare(`SELECT COUNT(*) n FROM psp_funds f JOIN
      (SELECT account_id,root_transfer_id,SUM(amount) total FROM (
         SELECT account_id,root_transfer_id,blocked_cents amount FROM psp_med_holds
           WHERE released_at IS NULL
         UNION ALL
         SELECT account_id,root_transfer_id,amount_cents amount FROM psp_cautelar_holds
           WHERE status='active' AND expires_at>?
       ) GROUP BY account_id,root_transfer_id) h
      ON h.account_id=f.account_id AND h.root_transfer_id=f.root_transfer_id
      WHERE h.total>f.available_cents`)
      .get(this.now().toISOString()) as { n: number }).n;
    const orphanMedHolds = (this.db.prepare(`SELECT COUNT(*) n FROM psp_med_holds h
      LEFT JOIN psp_funds f ON f.account_id=h.account_id
        AND f.root_transfer_id=h.root_transfer_id
      WHERE f.account_id IS NULL`).get() as { n: number }).n;
    const inboundSenderDrift = (this.db.prepare(`SELECT COUNT(*) n
      FROM psp_inbound_receipts r LEFT JOIN psp_inbound_sender_facts f
      ON f.root_transfer_id=r.root_transfer_id WHERE f.root_transfer_id IS NULL`)
      .get() as { n: number }).n;
    const inboundSpiDrift = (this.db.prepare(`SELECT COUNT(*) n
      FROM psp_inbound_receipts r
      LEFT JOIN psp_accounts a ON a.id=r.account_id
      LEFT JOIN psp_inbound_sender_facts f ON f.root_transfer_id=r.root_transfer_id
      LEFT JOIN spi_messages m ON m.end_to_end_id=r.end_to_end_id
        AND m.message_type='pacs.008'
      LEFT JOIN spi_messages s ON s.end_to_end_id=r.end_to_end_id
        AND s.message_type='pacs.002'
      WHERE a.id IS NULL OR f.root_transfer_id IS NULL OR m.id IS NULL OR s.id IS NULL
        OR json_extract(m.payload_json,'$.type') IS NOT 'pacs.008'
        OR json_extract(m.payload_json,'$.end_to_end_id') IS NOT r.end_to_end_id
        OR json_extract(m.payload_json,'$.from_ispb') IS NOT ?
        OR json_extract(m.payload_json,'$.to_ispb') IS NOT a.ispb
        OR json_extract(m.payload_json,'$.amount_cents') IS NOT r.amount_cents
        OR (json_type(m.payload_json,'$.root_transfer_id') IS NOT NULL
          AND json_extract(m.payload_json,'$.root_transfer_id') IS NOT r.root_transfer_id)
        OR (json_type(m.payload_json,'$.sender_account') IS NOT NULL
          AND json_extract(m.payload_json,'$.sender_account') IS NOT f.sender_account)
        OR (json_type(m.payload_json,'$.recipient_account') IS NOT NULL
          AND json_extract(m.payload_json,'$.recipient_account') IS NOT r.account_id)
        OR json_extract(s.payload_json,'$.type') IS NOT 'pacs.002'
        OR json_extract(s.payload_json,'$.end_to_end_id') IS NOT r.end_to_end_id
        OR json_extract(s.payload_json,'$.from_ispb') IS NOT ?
        OR json_extract(s.payload_json,'$.to_ispb') IS NOT a.ispb
        OR json_extract(s.payload_json,'$.amount_cents') IS NOT r.amount_cents
        OR json_extract(s.payload_json,'$.status') IS NOT 'ACSC'`)
      .get(JACARANDA_ISPB, JACARANDA_ISPB) as { n: number }).n;
    return { ok: accountDrift === 0 && rootOverflow === 0 && rootFactDrift === 0 &&
        holdOverflow === 0 && orphanMedHolds === 0 &&
        inboundSenderDrift === 0 && inboundSpiDrift === 0,
      account_drift: accountDrift, root_overflow: rootOverflow,
      root_fact_drift: rootFactDrift, hold_overflow: holdOverflow + orphanMedHolds,
      inbound_sender_drift: inboundSenderDrift, inbound_spi_drift: inboundSpiDrift };
  }
}
