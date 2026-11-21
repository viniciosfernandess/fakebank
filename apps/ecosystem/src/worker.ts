import { chmodSync, existsSync, lstatSync, rmSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync, backup } from "node:sqlite";
import { basename, dirname, resolve } from "node:path";
import { PspNetwork } from "../../world/src/ecosystem/psp.ts";
import { SpiNetwork } from "../../world/src/ecosystem/spi.ts";
import { dictFraudCounter } from "../../world/src/ecosystem/dict-fraud-history.ts";
import { JACARANDA_ISPB } from "../../world/src/pix-id.ts";
import { parsePixKey } from "../../world/src/ecosystem/dict.ts";
import { PspNoticeAccess, type PspNoticeOwner } from
  "../../world/src/ecosystem/psp-notice-access.ts";

type Request = { version: 1; id: number; operation: string; args?: unknown };

function fields(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("ECOSYSTEM_MESSAGE_INVALID");
  return value as Record<string, unknown>;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 256)
    throw new Error("ECOSYSTEM_MESSAGE_INVALID");
  return value;
}

function requiredAmount(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0)
    throw new Error("ECOSYSTEM_MESSAGE_INVALID");
  return value as number;
}

function requiredTimestamp(value: unknown): Date {
  const text = requiredString(value);
  const date = new Date(text);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== text)
    throw new Error("ECOSYSTEM_MESSAGE_INVALID");
  return date;
}

function medReturnId(hopId: string): string {
  return `medreturn_${createHash("sha256")
    .update(`banco-vivo:med-return:v1:${hopId}`).digest("base64url")}`;
}

function bankVisibleAccount(account: ReturnType<SpiNetwork["account"]>,
  includeHolder: boolean) {
  if (!account) return null;
  return { id: account.id, ispb: account.ispb, status: account.status,
    fraud_flag: account.fraud_flag,
    ...(includeHolder ? { holder_name: account.holder_name } : {}) };
}

function recipientEvidence(accountId: string, at: Date,
  account: ReturnType<SpiNetwork["account"]>) {
  return { exists: Boolean(account), flagged: Boolean(account?.fraud_flag),
    fraudHistory: dictFraudCounter(db, at, "account_id",
      account ? accountId : undefined) };
}

const path = process.argv[2];
if (!path || !process.send) throw new Error("ECOSYSTEM_STARTUP_INVALID");
let operationTime = new Date();
function openEcosystem() {
  const stat = lstatSync(path!);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0)
    throw new Error("ECOSYSTEM_FILE_NOT_PRIVATE");
  const db = new DatabaseSync(path!);
  try {
    db.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL");
    if (db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
      AND name IN ('accounts','pix_transfers','ledger_entries') LIMIT 1`).get())
      throw new Error("ECOSYSTEM_FILE_CONTAINS_BANK_TABLES");
    const spi = new SpiNetwork(db, () => operationTime);
    const psp = new PspNetwork(db, spi, () => operationTime);
    if (!psp.reconcile().ok) throw new Error("ECOSYSTEM_PSP_HISTORY_INVALID");
    db.exec(`CREATE TABLE IF NOT EXISTS psp_med_case_openings (
      case_id TEXT PRIMARY KEY, root_transfer_id TEXT NOT NULL UNIQUE
        REFERENCES psp_roots(root_transfer_id),
      claim_amount_cents INTEGER NOT NULL CHECK(claim_amount_cents>0),
      created_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS psp_med_case_openings_no_update
      BEFORE UPDATE ON psp_med_case_openings
      BEGIN SELECT RAISE(ABORT,'PSP_MED_OPEN_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_med_case_openings_no_delete
      BEFORE DELETE ON psp_med_case_openings
      BEGIN SELECT RAISE(ABORT,'PSP_MED_OPEN_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS dict_med_analyses (
      case_id TEXT PRIMARY KEY REFERENCES psp_med_case_openings(case_id),
      root_transfer_id TEXT NOT NULL, approved_at TEXT NOT NULL,
      analysed_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS dict_med_analyses_no_update
      BEFORE UPDATE ON dict_med_analyses
      BEGIN SELECT RAISE(ABORT,'DICT_MED_ANALYSIS_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS dict_med_analyses_no_delete
      BEFORE DELETE ON dict_med_analyses
      BEGIN SELECT RAISE(ABORT,'DICT_MED_ANALYSIS_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_med_case_releases (
      case_id TEXT PRIMARY KEY REFERENCES psp_med_case_openings(case_id),
      root_transfer_id TEXT NOT NULL, released_at TEXT NOT NULL,
      processed_at TEXT
    );
    CREATE TRIGGER IF NOT EXISTS psp_med_case_releases_no_update
      BEFORE UPDATE ON psp_med_case_releases
      BEGIN SELECT RAISE(ABORT,'PSP_MED_RELEASE_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_med_case_releases_no_delete
      BEFORE DELETE ON psp_med_case_releases
      BEGIN SELECT RAISE(ABORT,'PSP_MED_RELEASE_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_med_case_settlements (
      case_id TEXT PRIMARY KEY REFERENCES psp_med_case_openings(case_id),
      root_transfer_id TEXT NOT NULL, end_to_end_id TEXT NOT NULL,
      claim_amount_cents INTEGER NOT NULL CHECK(claim_amount_cents>0),
      settled_at TEXT NOT NULL,
      processed_at TEXT
    );
    CREATE TRIGGER IF NOT EXISTS psp_med_case_settlements_no_update
      BEFORE UPDATE ON psp_med_case_settlements
      BEGIN SELECT RAISE(ABORT,'PSP_MED_SETTLEMENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_med_case_settlements_no_delete
      BEFORE DELETE ON psp_med_case_settlements
      BEGIN SELECT RAISE(ABORT,'PSP_MED_SETTLEMENT_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS dict_med_refund_requests (
      case_id TEXT NOT NULL REFERENCES psp_med_case_settlements(case_id),
      ispb TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>0),
      requested_at TEXT NOT NULL, deadline_at TEXT NOT NULL,
      processed_at TEXT, refunded_cents INTEGER CHECK(refunded_cents>=0),
      PRIMARY KEY(case_id,ispb), UNIQUE(case_id,sequence),
      CHECK((processed_at IS NULL)=(refunded_cents IS NULL))
    );
    CREATE TRIGGER IF NOT EXISTS dict_med_refund_request_immutable
      BEFORE UPDATE OF case_id,ispb,sequence,requested_at,deadline_at
      ON dict_med_refund_requests
      BEGIN SELECT RAISE(ABORT,'DICT_MED_REFUND_REQUEST_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS dict_med_refund_result_immutable
      BEFORE UPDATE OF processed_at,refunded_cents ON dict_med_refund_requests
      WHEN OLD.processed_at IS NOT NULL OR NEW.processed_at IS NULL OR
        NEW.refunded_cents IS NULL
      BEGIN SELECT RAISE(ABORT,'DICT_MED_REFUND_RESULT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS dict_med_refund_request_no_delete
      BEFORE DELETE ON dict_med_refund_requests
      BEGIN SELECT RAISE(ABORT,'DICT_MED_REFUND_REQUEST_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_pix_return_results (
      return_id TEXT PRIMARY KEY, root_transfer_id TEXT NOT NULL
        REFERENCES psp_roots(root_transfer_id),
      end_to_end_id TEXT NOT NULL, account_id TEXT NOT NULL,
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      reason TEXT NOT NULL CHECK(reason='ordinary'), created_at TEXT NOT NULL,
      outcome TEXT NOT NULL CHECK(outcome IN ('accepted','rejected')),
      failure_reason TEXT,
      CHECK((outcome='accepted' AND failure_reason IS NULL) OR
        (outcome='rejected' AND failure_reason IS NOT NULL))
    );
    CREATE TRIGGER IF NOT EXISTS psp_pix_return_results_no_update
      BEFORE UPDATE ON psp_pix_return_results
      BEGIN SELECT RAISE(ABORT,'PSP_PIX_RETURN_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_pix_return_results_no_delete
      BEFORE DELETE ON psp_pix_return_results
      BEGIN SELECT RAISE(ABORT,'PSP_PIX_RETURN_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_cautelar_placements (
      idempotency_key TEXT PRIMARY KEY,
      hold_id TEXT NOT NULL UNIQUE REFERENCES psp_cautelar_holds(id),
      account_id TEXT NOT NULL, root_transfer_id TEXT NOT NULL,
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      reason TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS psp_cautelar_placements_no_update
      BEFORE UPDATE ON psp_cautelar_placements
      BEGIN SELECT RAISE(ABORT,'PSP_CAUTELAR_PLACEMENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_cautelar_placements_no_delete
      BEFORE DELETE ON psp_cautelar_placements
      BEGIN SELECT RAISE(ABORT,'PSP_CAUTELAR_PLACEMENT_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_cautelar_return_results (
      return_id TEXT PRIMARY KEY, hold_id TEXT NOT NULL UNIQUE
        REFERENCES psp_cautelar_holds(id),
      root_transfer_id TEXT NOT NULL, end_to_end_id TEXT NOT NULL,
      account_id TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      actor TEXT NOT NULL, created_at TEXT NOT NULL,
      outcome TEXT NOT NULL CHECK(outcome IN ('accepted','rejected')),
      failure_reason TEXT,
      CHECK((outcome='accepted' AND failure_reason IS NULL) OR
        (outcome='rejected' AND failure_reason='PSP_CAUTELAR_NOT_ACTIVE'))
    );
    CREATE TRIGGER IF NOT EXISTS psp_cautelar_return_results_no_update
      BEFORE UPDATE ON psp_cautelar_return_results
      BEGIN SELECT RAISE(ABORT,'PSP_CAUTELAR_RETURN_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_cautelar_return_results_no_delete
      BEFORE DELETE ON psp_cautelar_return_results
      BEGIN SELECT RAISE(ABORT,'PSP_CAUTELAR_RETURN_IMMUTABLE'); END;`);
    const medReleaseColumns = db.prepare("PRAGMA table_info(psp_med_case_releases)")
      .all() as { name: string }[];
    if (!medReleaseColumns.some((column) => column.name === "processed_at"))
      db.exec("ALTER TABLE psp_med_case_releases ADD COLUMN processed_at TEXT");
    const medSettlementColumns = db.prepare("PRAGMA table_info(psp_med_case_settlements)")
      .all() as { name: string }[];
    if (!medSettlementColumns.some((column) => column.name === "processed_at"))
      db.exec("ALTER TABLE psp_med_case_settlements ADD COLUMN processed_at TEXT");
    if (db.prepare(`SELECT 1 FROM psp_med_holds h
      JOIN psp_med_case_releases r ON r.case_id=h.case_id
      WHERE h.released_at IS NOT COALESCE(r.processed_at,r.released_at)
      LIMIT 1`).get() ||
      db.prepare(`SELECT 1 FROM psp_med_holds h
        JOIN psp_accounts a ON a.id=h.account_id
        JOIN psp_med_case_settlements s ON s.case_id=h.case_id
        LEFT JOIN dict_med_refund_requests r ON r.case_id=h.case_id
          AND r.ispb=a.ispb
        WHERE h.released_at IS NOT CASE WHEN EXISTS(
          SELECT 1 FROM dict_med_refund_requests q WHERE q.case_id=h.case_id)
          THEN r.processed_at ELSE COALESCE(s.processed_at,s.settled_at) END
        LIMIT 1`).get())
      throw new Error("ECOSYSTEM_PSP_MED_HISTORY_INVALID");
    if (db.prepare(`SELECT 1 FROM psp_cautelar_placements p
      LEFT JOIN psp_cautelar_holds h ON h.id=p.hold_id
      WHERE h.id IS NULL OR h.account_id<>p.account_id OR
        h.root_transfer_id<>p.root_transfer_id OR h.amount_cents<>p.amount_cents OR
        h.reason<>p.reason OR h.created_at<>p.created_at LIMIT 1`).get())
      throw new Error("ECOSYSTEM_PSP_CAUTELAR_HISTORY_INVALID");
    if (db.prepare(`SELECT 1 FROM psp_cautelar_return_results r
      LEFT JOIN psp_cautelar_holds h ON h.id=r.hold_id
      LEFT JOIN psp_accounts a ON a.id=r.account_id
      WHERE h.id IS NULL OR a.id IS NULL OR
        h.root_transfer_id<>r.root_transfer_id OR
        h.account_id<>r.account_id OR h.amount_cents<>r.amount_cents OR
        (r.outcome='accepted' AND
          (h.status<>'returned' OR h.resolved_by<>r.actor OR NOT EXISTS (
            SELECT 1 FROM spi_messages m WHERE m.message_type='pacs.004'
              AND m.end_to_end_id=r.end_to_end_id
              AND json_extract(m.payload_json,'$.return_id')=r.return_id
              AND json_extract(m.payload_json,'$.from_ispb')=a.ispb
              AND json_extract(m.payload_json,'$.to_ispb')='12345678'
              AND json_extract(m.payload_json,'$.amount_cents')=r.amount_cents
              AND json_extract(m.payload_json,'$.reason')='cautelar')))
        OR (r.outcome='rejected' AND EXISTS (
          SELECT 1 FROM spi_messages m WHERE m.message_type='pacs.004'
            AND json_extract(m.payload_json,'$.return_id')=r.return_id))
      LIMIT 1`).get())
      throw new Error("ECOSYSTEM_PSP_CAUTELAR_RETURN_HISTORY_INVALID");
    const noticeOwner: PspNoticeOwner = { db, realNow: () => new Date(),
      transaction<T>(work: () => T): T {
        db.exec("SAVEPOINT psp_notice_access");
        try { const result = work(); db.exec("RELEASE psp_notice_access"); return result; }
        catch (error) {
          db.exec("ROLLBACK TO psp_notice_access");
          db.exec("RELEASE psp_notice_access");
          throw error;
        }
      } };
    const notices = new PspNoticeAccess(noticeOwner);
    return { db, spi, psp, notices };
  } catch (error) { db.close(); throw error; }
}
let opened: ReturnType<typeof openEcosystem>;
try { opened = openEcosystem(); }
catch (error) {
  const code = error instanceof Error && /^ECOSYSTEM_[A-Z_]+$/.test(error.message) ?
    error.message : "ECOSYSTEM_STARTUP_FAILED";
  await new Promise<void>((resolve) =>
    process.send?.({ version: 1, startupError: code }, () => resolve()));
  process.exit(1);
}
const { db, spi, psp, notices } = opened;

function medCaseProjection(caseId: string, rootTransferId: string) {
  return { hops: db.prepare(`SELECT h.hop_id id,h.case_id,h.root_transfer_id,
    h.account_id,a.ispb,
    h.blocked_cents,h.refunded_cents,h.created_at,h.released_at FROM psp_med_holds h
    JOIN psp_accounts a ON a.id=h.account_id
    WHERE h.case_id=? ORDER BY h.hop_id`)
    .all(caseId), path: psp.path(rootTransferId) };
}

function handle(request: Request): unknown {
  const args = fields(request.args ?? {});
  operationTime = new Date();
  switch (request.operation) {
    case "account": return bankVisibleAccount(spi.account(requiredString(args.accountId)), false);
    case "recipientEvidence": {
      const accountId = requiredString(args.accountId);
      const at = requiredTimestamp(args.at);
      return recipientEvidence(accountId, at, spi.account(accountId));
    }
    case "accountFraudHistory": {
      const accountId = requiredString(args.accountId);
      const at = requiredTimestamp(args.at);
      return dictFraudCounter(db, at, "account_id", accountId);
    }
    case "recipientSnapshot": {
      const accountId = requiredString(args.accountId);
      const at = requiredTimestamp(args.at);
      const account = spi.account(accountId);
      return { account: bankVisibleAccount(account, false),
        evidence: recipientEvidence(accountId, at, account) };
    }
    case "lookup": return bankVisibleAccount(spi.lookup(requiredString(args.key)), true);
    case "keySnapshot": {
      const rawKey = requiredString(args.key);
      const key = parsePixKey(rawKey)?.value ?? rawKey;
      const at = requiredTimestamp(args.at);
      const account = spi.lookup(key);
      if (!account) return null;
      return { key, id: account.id, ispb: account.ispb, status: account.status,
        fraud_flag: account.fraud_flag, holder_name: account.holder_name,
        security: { key: dictFraudCounter(db, at, "key_value", key),
          account: dictFraudCounter(db, at, "account_id", account.id),
          cpf: dictFraudCounter(db, at, "cpf", undefined) } };
    }
    case "dictHealth": {
      if (!db.prepare("SELECT 1 FROM dict_fraud_history_state WHERE id=1").get())
        throw new Error("ECOSYSTEM_DICT_UNAVAILABLE");
      db.prepare("SELECT 1 FROM dict_fraud_events LIMIT 1").get();
      db.prepare("SELECT 1 FROM psp_accounts LIMIT 1").get();
      return { ready: true };
    }
    case "snapshot": {
      const destination = resolve(requiredString(args.destination));
      const stage = dirname(destination);
      const stageStat = lstatSync(stage);
      if (basename(destination) !== "ecosystem.sqlite" ||
        dirname(stage) !== resolve(dirname(path!), "snapshots") ||
        !/^\.tmp-r\d{2}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(basename(stage)) ||
        !stageStat.isDirectory() || stageStat.isSymbolicLink() ||
        existsSync(destination)) throw new Error("ECOSYSTEM_SNAPSHOT_PATH_INVALID");
      return backup(db, destination).then(() => {
        chmodSync(destination, 0o600);
        return { saved: true };
      }).catch((error: unknown) => {
        rmSync(destination, { force: true });
        throw error;
      });
    }
    case "syntheticRecipients": return (db.prepare(`SELECT id,pix_key
      FROM psp_accounts WHERE id LIKE 'psp_sim_%' AND status='active'
      ORDER BY id LIMIT 250`).all() as { id: string; pix_key: string }[])
      .map((row) => ({ id: row.id, pixKey: row.pix_key }));
    case "activeCautelarSummary": {
      const at = requiredTimestamp(args.at).toISOString();
      return db.prepare(`SELECT account_id,COUNT(*) holds,
        SUM(amount_cents) blocked_cents FROM psp_cautelar_holds
        WHERE status='active' AND expires_at>? GROUP BY account_id`)
        .all(at);
    }
    case "cautelarReviewPage": {
      const at = requiredTimestamp(args.at).toISOString();
      const afterExpiry = args.afterExpiry === "" ? "" :
        requiredTimestamp(args.afterExpiry).toISOString();
      const afterId = args.afterId === "" ? "" : requiredString(args.afterId);
      if (Boolean(afterExpiry) !== Boolean(afterId) ||
        (afterId && !/^[a-zA-Z0-9_-]{1,128}$/.test(afterId)))
        throw new Error("ECOSYSTEM_MESSAGE_INVALID");
      const total = (db.prepare(`SELECT COUNT(*) n FROM psp_cautelar_holds
        WHERE status='active' AND expires_at>?`).get(at) as { n: number }).n;
      const rows = db.prepare(`SELECT id,account_id,root_transfer_id,amount_cents,
        reason,created_at,expires_at FROM psp_cautelar_holds
        WHERE status='active' AND expires_at>?
          AND (expires_at>? OR (expires_at=? AND id>?))
        ORDER BY expires_at,id LIMIT 21`)
        .all(at, afterExpiry, afterExpiry, afterId);
      return { total, rows };
    }
    case "operations": return {
      spi: db.prepare(`SELECT COUNT(*) total,MAX(created_at) last_at
        FROM spi_messages`).get(),
      cautelar: db.prepare(`SELECT COUNT(*) total,MAX(created_at) last_at
        FROM psp_cautelar_holds`).get(),
      pi_accounts: db.prepare(`SELECT ispb,name,pi_balance_cents
        FROM spi_participants ORDER BY ispb`).all(),
      recent_spi: db.prepare(`SELECT id,message_type,
        substr(end_to_end_id,-8) end_to_end_ref,created_at
        FROM spi_messages ORDER BY id DESC LIMIT 12`).all(),
      recent_cautelar: db.prepare(`SELECT substr(id,-8) ref,
        substr(account_id,-8) account_ref,amount_cents,reason,status,
        created_at,resolved_at,resolved_by FROM psp_cautelar_holds
        ORDER BY created_at DESC,id DESC LIMIT 12`).all(),
      recent_notices: db.prepare(`SELECT id,substr(account_id,-8) account_ref,
        kind,amount_cents,message_pt,created_at FROM psp_cautelar_notices
        ORDER BY id DESC LIMIT 12`).all(),
    };
    case "paymentMessages": return spi.messages(requiredString(args.endToEndId));
    case "cautelarHold": return psp.cautelarHold(requiredString(args.holdId)) ?? null;
    case "medCaseProjection": return medCaseProjection(
      requiredString(args.caseId), requiredString(args.rootTransferId));
    case "medRefundTimeline": {
      const caseId = requiredString(args.caseId);
      const rootTransferId = requiredString(args.rootTransferId);
      if (!db.prepare(`SELECT 1 FROM psp_med_case_openings
        WHERE case_id=? AND root_transfer_id=?`).get(caseId, rootTransferId))
        throw new Error("PSP_MED_CASE_NOT_FOUND");
      return db.prepare(`SELECT case_id,ispb,sequence,requested_at,deadline_at,
        processed_at,refunded_cents FROM dict_med_refund_requests
        WHERE case_id=? ORDER BY sequence`).all(caseId);
    }
    case "moneyFlowProjection": {
      const rootTransferId = requiredString(args.rootTransferId);
      const caseId = args.caseId === undefined ? undefined : requiredString(args.caseId);
      const projection = caseId ? medCaseProjection(caseId, rootTransferId) :
        { path: psp.path(rootTransferId), hops: [] };
      const refundSteps = caseId ? db.prepare(`SELECT case_id,ispb,sequence,
        requested_at,deadline_at,processed_at,refunded_cents
        FROM dict_med_refund_requests WHERE case_id=? ORDER BY sequence`)
        .all(caseId) : [];
      return { ...projection, trace: psp.trace(rootTransferId), refundSteps };
    }
    case "openMedCase": {
      const caseId = requiredString(args.caseId);
      const rootTransferId = requiredString(args.rootTransferId);
      const claimAmount = requiredAmount(args.claimAmountCents);
      const createdAt = requiredTimestamp(args.createdAt).toISOString();
      operationTime = requiredTimestamp(args.processedAt);
      db.exec("BEGIN IMMEDIATE");
      try {
        const prior = db.prepare(`SELECT root_transfer_id,claim_amount_cents,created_at
          FROM psp_med_case_openings WHERE case_id=?`).get(caseId) as
          { root_transfer_id: string; claim_amount_cents: number;
            created_at: string } | undefined;
        if (prior) {
          if (prior.root_transfer_id !== rootTransferId ||
            prior.claim_amount_cents !== claimAmount || prior.created_at !== createdAt)
            throw new Error("PSP_MED_OPEN_CONFLICT");
          const result = medCaseProjection(caseId, rootTransferId);
          db.exec("COMMIT");
          return result.hops;
        }
        const root = db.prepare(`SELECT amount_cents FROM psp_roots
          WHERE root_transfer_id=?`).get(rootTransferId) as
          { amount_cents: number } | undefined;
        if (!root || claimAmount > root.amount_cents ||
          db.prepare(`SELECT 1 FROM psp_med_case_openings
            WHERE root_transfer_id=?`).get(rootTransferId))
          throw new Error("PSP_MED_OPEN_INVALID");
        psp.supersedeCautelarForMed(rootTransferId);
        db.prepare(`INSERT INTO psp_med_case_openings
          (case_id,root_transfer_id,claim_amount_cents,created_at)
          VALUES (?,?,?,?)`).run(caseId, rootTransferId, claimAmount, createdAt);
        for (const hop of psp.trace(rootTransferId)) {
          const available = psp.availableRoot(hop.account_id, rootTransferId);
          if (available <= 0) continue;
          const id = `medhop_${randomUUID()}`;
          psp.recordMedHold({ id, case_id: caseId,
            root_transfer_id: rootTransferId, account_id: hop.account_id,
            blocked_cents: available, created_at: createdAt });
          psp.notifyMedHop(id, "blocked", available);
        }
        const result = medCaseProjection(caseId, rootTransferId);
        db.exec("COMMIT");
        return result.hops;
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
    case "releaseMedCase": {
      const caseId = requiredString(args.caseId);
      const rootTransferId = requiredString(args.rootTransferId);
      const releasedAt = requiredTimestamp(args.releasedAt).toISOString();
      operationTime = requiredTimestamp(args.processedAt);
      db.exec("BEGIN IMMEDIATE");
      try {
        const opened = db.prepare(`SELECT root_transfer_id FROM psp_med_case_openings
          WHERE case_id=?`).get(caseId) as { root_transfer_id: string } | undefined;
        if (!opened || opened.root_transfer_id !== rootTransferId)
          throw new Error("PSP_MED_RELEASE_INVALID");
        const prior = db.prepare(`SELECT root_transfer_id,released_at,processed_at
          FROM psp_med_case_releases WHERE case_id=?`).get(caseId) as
          { root_transfer_id: string; released_at: string;
            processed_at: string | null } | undefined;
        if (prior && (prior.root_transfer_id !== rootTransferId ||
          prior.released_at !== releasedAt)) throw new Error("PSP_MED_RELEASE_CONFLICT");
        if (operationTime.getTime() < Date.parse(releasedAt))
          throw new Error("PSP_MED_RELEASE_INVALID");
        const holds = db.prepare(`SELECT hop_id,blocked_cents,refunded_cents,released_at
          FROM psp_med_holds WHERE case_id=?
          ORDER BY hop_id`).all(caseId) as
          { hop_id: string; blocked_cents: number; refunded_cents: number;
            released_at: string | null }[];
        const processedAt = prior?.processed_at ?? releasedAt;
        if (holds.some((hold) => hold.refunded_cents !== 0 ||
          hold.released_at !== (prior ? processedAt : null)))
          throw new Error("PSP_MED_RELEASE_INVALID");
        if (!prior) {
          db.prepare(`INSERT INTO psp_med_case_releases
            (case_id,root_transfer_id,released_at,processed_at) VALUES (?,?,?,?)`)
            .run(caseId, rootTransferId, releasedAt, operationTime.toISOString());
          for (const hold of holds) {
            psp.releaseMedHold(hold.hop_id, operationTime.toISOString());
            psp.notifyMedHop(hold.hop_id, "released", hold.blocked_cents);
          }
          const releasedFunds = db.prepare(`SELECT account_id,root_transfer_id
            FROM psp_med_holds WHERE case_id=?`).all(caseId) as
            { account_id: string; root_transfer_id: string }[];
          for (const fund of releasedFunds)
            psp.reserveAvailableMedFunds(fund.account_id, fund.root_transfer_id);
        }
        const result = medCaseProjection(caseId, rootTransferId);
        db.exec("COMMIT");
        return result.hops;
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
    case "analyseMedCase": {
      const caseId = requiredString(args.caseId);
      const rootTransferId = requiredString(args.rootTransferId);
      const approvedAt = requiredTimestamp(args.approvedAt).toISOString();
      operationTime = requiredTimestamp(args.processedAt);
      if (operationTime.getTime() < Date.parse(approvedAt))
        throw new Error("DICT_MED_ANALYSIS_INVALID");
      db.exec("BEGIN IMMEDIATE");
      try {
        const opened = db.prepare(`SELECT root_transfer_id,created_at
          FROM psp_med_case_openings WHERE case_id=?`).get(caseId) as
          { root_transfer_id: string; created_at: string } | undefined;
        const prior = db.prepare(`SELECT case_id,root_transfer_id,approved_at,analysed_at
          FROM dict_med_analyses WHERE case_id=?`).get(caseId) as
          { case_id: string; root_transfer_id: string; approved_at: string;
            analysed_at: string } | undefined;
        if (!opened || opened.root_transfer_id !== rootTransferId ||
          Date.parse(approvedAt) < Date.parse(opened.created_at) ||
          db.prepare("SELECT 1 FROM psp_med_case_releases WHERE case_id=?").get(caseId) ||
          (prior && (prior.root_transfer_id !== rootTransferId ||
            prior.approved_at !== approvedAt)))
          throw new Error("DICT_MED_ANALYSIS_INVALID");
        if (!prior) db.prepare(`INSERT INTO dict_med_analyses
          (case_id,root_transfer_id,approved_at,analysed_at) VALUES (?,?,?,?)`)
          .run(caseId, rootTransferId, approvedAt, operationTime.toISOString());
        db.exec("COMMIT");
        return { case_id: caseId, root_transfer_id: rootTransferId,
          analysed_at: prior?.analysed_at ?? operationTime.toISOString() };
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
    case "settleMedCase": {
      const caseId = requiredString(args.caseId);
      const rootTransferId = requiredString(args.rootTransferId);
      const endToEndId = requiredString(args.endToEndId);
      const claimAmount = requiredAmount(args.claimAmountCents);
      const settledAt = requiredTimestamp(args.settledAt).toISOString();
      operationTime = requiredTimestamp(args.processedAt);
      if (operationTime.getTime() < Date.parse(settledAt))
        throw new Error("PSP_MED_SETTLEMENT_INVALID");
      db.exec("BEGIN IMMEDIATE");
      try {
        const opened = db.prepare(`SELECT root_transfer_id,claim_amount_cents
          FROM psp_med_case_openings WHERE case_id=?`).get(caseId) as
          { root_transfer_id: string; claim_amount_cents: number } | undefined;
        const root = db.prepare(`SELECT end_to_end_id FROM psp_roots
          WHERE root_transfer_id=?`).get(rootTransferId) as
          { end_to_end_id: string } | undefined;
        if (!opened || opened.root_transfer_id !== rootTransferId ||
          opened.claim_amount_cents !== claimAmount ||
          root?.end_to_end_id !== endToEndId ||
          db.prepare(`SELECT 1 FROM psp_med_case_releases WHERE case_id=?`).get(caseId))
          throw new Error("PSP_MED_SETTLEMENT_INVALID");
        const prior = db.prepare(`SELECT root_transfer_id,end_to_end_id,
          claim_amount_cents,settled_at,processed_at FROM psp_med_case_settlements
          WHERE case_id=?`).get(caseId) as
          { root_transfer_id: string; end_to_end_id: string;
            claim_amount_cents: number; settled_at: string;
            processed_at: string | null } | undefined;
        if (prior && (prior.root_transfer_id !== rootTransferId ||
          prior.end_to_end_id !== endToEndId ||
          prior.claim_amount_cents !== claimAmount ||
          prior.settled_at !== settledAt))
          throw new Error("PSP_MED_SETTLEMENT_CONFLICT");
        if (!prior && !db.prepare(`SELECT 1 FROM dict_med_analyses
          WHERE case_id=? AND root_transfer_id=? AND analysed_at<=?`)
          .get(caseId, rootTransferId, operationTime.toISOString()))
          throw new Error("PSP_MED_ANALYSIS_REQUIRED");
        const holds = db.prepare(`SELECT h.hop_id,h.root_transfer_id,h.account_id,h.blocked_cents,
          h.refunded_cents,h.released_at,a.ispb
          FROM psp_med_holds h JOIN psp_accounts a ON a.id=h.account_id
          WHERE h.case_id=? ORDER BY h.hop_id`)
          .all(caseId) as
          { hop_id: string; root_transfer_id: string; account_id: string; blocked_cents: number;
            refunded_cents: number; released_at: string | null;
            ispb: string }[];
        if (!prior && holds.some((hold) =>
          hold.released_at !== null || hold.refunded_cents !== 0))
          throw new Error("PSP_MED_SETTLEMENT_INVALID");
        if (!prior) {
          db.prepare(`INSERT INTO psp_med_case_settlements
            (case_id,root_transfer_id,end_to_end_id,claim_amount_cents,settled_at,processed_at)
            VALUES (?,?,?,?,?,?)`).run(caseId, rootTransferId, endToEndId,
              claimAmount, settledAt, operationTime.toISOString());
        }
        const requests = db.prepare(`SELECT ispb,sequence,requested_at,deadline_at,
          processed_at,refunded_cents FROM dict_med_refund_requests
          WHERE case_id=? ORDER BY sequence`).all(caseId) as
          { ispb: string; sequence: number; requested_at: string;
            deadline_at: string; processed_at: string | null;
            refunded_cents: number | null }[];
        const participants = [...new Set(holds.map((hold) => hold.ispb))].sort();
        if (!prior && participants.length) {
          db.prepare(`INSERT INTO dict_med_refund_requests
            (case_id,ispb,sequence,requested_at,deadline_at)
            VALUES (?,?,?,?,?)`).run(caseId, participants[0]!, 1,
              operationTime.toISOString(),
              new Date(operationTime.getTime() + 6 * 3_600_000).toISOString());
        } else if (requests.length) {
          const pending = requests.find((request) => request.processed_at === null);
          if (pending) {
            if (requests.at(-1)?.ispb !== pending.ispb ||
              operationTime.getTime() < Date.parse(pending.requested_at))
              throw new Error("PSP_MED_REFUND_SEQUENCE_INVALID");
            let recovered = holds.reduce((total, hold) => total + hold.refunded_cents, 0);
            let participantRefund = 0;
            for (const hold of holds.filter((item) => item.ispb === pending.ispb)) {
              if (hold.released_at !== null || hold.refunded_cents !== 0)
                throw new Error("PSP_MED_REFUND_SEQUENCE_INVALID");
              psp.releaseMedHold(hold.hop_id, operationTime.toISOString());
              const amount = Math.min(hold.blocked_cents,
                psp.availableRoot(hold.account_id, hold.root_transfer_id),
                spi.account(hold.account_id)?.balance_cents ?? 0,
                spi.balance(hold.ispb), claimAmount - recovered);
              if (amount > 0) {
                psp.debitAccountRoot(hold.account_id, hold.root_transfer_id, amount);
                spi.returnPayment(endToEndId, medReturnId(hold.hop_id), hold.ispb,
                  JACARANDA_ISPB, amount, "MED");
                psp.recordMedRefund(hold.hop_id, amount);
                psp.notifyMedHop(hold.hop_id, "recovered", amount);
              }
              if (hold.blocked_cents > amount)
                psp.notifyMedHop(hold.hop_id, "released", hold.blocked_cents - amount);
              recovered += amount;
              participantRefund += amount;
            }
            for (const hold of holds.filter((item) => item.ispb === pending.ispb))
              psp.reserveAvailableMedFunds(hold.account_id, hold.root_transfer_id);
            db.prepare(`UPDATE dict_med_refund_requests
              SET processed_at=?,refunded_cents=?
              WHERE case_id=? AND ispb=? AND processed_at IS NULL`)
              .run(operationTime.toISOString(), participantRefund, caseId, pending.ispb);
            const next = participants.find((ispb) =>
              !requests.some((request) => request.ispb === ispb));
            if (next) db.prepare(`INSERT INTO dict_med_refund_requests
              (case_id,ispb,sequence,requested_at,deadline_at)
              VALUES (?,?,?,?,?)`).run(caseId, next, pending.sequence + 1,
                operationTime.toISOString(),
                new Date(operationTime.getTime() + 6 * 3_600_000).toISOString());
          }
        } else if (prior && holds.some((hold) =>
          hold.released_at !== (prior.processed_at ?? settledAt)))
          throw new Error("PSP_MED_SETTLEMENT_HISTORY_INVALID");
        const persisted = db.prepare(`SELECT h.hop_id,h.refunded_cents,a.ispb
          FROM psp_med_holds h JOIN psp_accounts a ON a.id=h.account_id
          WHERE h.case_id=?`).all(caseId) as
          { hop_id: string; refunded_cents: number; ispb: string }[];
        let returned = 0;
        for (const hold of persisted) {
          const row = db.prepare(`SELECT payload_json FROM spi_messages
            WHERE message_type='pacs.004' AND
            json_extract(payload_json,'$.return_id')=?`)
            .get(medReturnId(hold.hop_id)) as { payload_json: string } | undefined;
          const receipt = row ? JSON.parse(row.payload_json) as Record<string, unknown> : null;
          if (hold.refunded_cents > 0 ?
            !receipt || receipt.type !== "pacs.004" ||
              receipt.end_to_end_id !== endToEndId ||
              receipt.from_ispb !== hold.ispb ||
              receipt.to_ispb !== JACARANDA_ISPB ||
              receipt.amount_cents !== hold.refunded_cents ||
              receipt.reason !== "MED" : Boolean(receipt))
            throw new Error("PSP_MED_SETTLEMENT_HISTORY_INVALID");
          returned += hold.refunded_cents;
        }
        if (returned > claimAmount)
          throw new Error("PSP_MED_SETTLEMENT_HISTORY_INVALID");
        const result = medCaseProjection(caseId, rootTransferId);
        db.exec("COMMIT");
        return result.hops;
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
    case "bankPiBalance": return spi.balance(JACARANDA_ISPB);
    case "spiAvailability": return spi.availability();
    case "spiAvailabilityHistory": {
      const after = args.after;
      if (!Number.isSafeInteger(after) || (after as number) < 0)
        throw new Error("ECOSYSTEM_MESSAGE_INVALID");
      return db.prepare(`SELECT id row_cursor,id,available,changed_at,changed_by
        FROM spi_runtime_history WHERE id>? ORDER BY id LIMIT 101`)
        .all(after as number).map(({ available, ...row }) => ({ ...row,
          available: Boolean(available) }));
    }
    case "spiSetAvailability": {
      const available = args.available;
      if (typeof available !== "boolean") throw new Error("ECOSYSTEM_MESSAGE_INVALID");
      return spi.setAvailability(available, requiredString(args.actor));
    }
    case "submitPayment":
      if (Object.hasOwn(args, "fromIspb")) throw new Error("ECOSYSTEM_OPERATION_DENIED");
      operationTime = args.processedAt === undefined ? new Date() :
        requiredTimestamp(args.processedAt);
      return spi.submitPayment(
      requiredString(args.endToEndId), JACARANDA_ISPB,
      requiredString(args.toIspb), requiredAmount(args.amountCents),
      requiredString(args.senderAccount), requiredString(args.rootTransferId),
      args.deadlineAtReal === undefined ? undefined : requiredString(args.deadlineAtReal),
      requiredString(args.recipientAccount));
    case "returnPix": {
      const returnId = requiredString(args.returnId);
      const rootTransferId = requiredString(args.rootTransferId);
      const endToEndId = requiredString(args.endToEndId);
      const accountId = requiredString(args.accountId);
      const amountCents = requiredAmount(args.amountCents);
      const reason = requiredString(args.reason);
      if (reason !== "ordinary") throw new Error("ECOSYSTEM_MESSAGE_INVALID");
      const createdAt = requiredTimestamp(args.createdAt).toISOString();
      operationTime = requiredTimestamp(args.processedAt);
      db.exec("BEGIN IMMEDIATE");
      try {
        const account = spi.account(accountId);
        const prior = db.prepare(`SELECT root_transfer_id,end_to_end_id,account_id,
          amount_cents,reason,created_at,outcome,failure_reason
          FROM psp_pix_return_results WHERE return_id=?`).get(returnId) as
          { root_transfer_id: string; end_to_end_id: string; account_id: string;
            amount_cents: number; reason: string; created_at: string;
            outcome: "accepted" | "rejected"; failure_reason: string | null } | undefined;
        if (prior && (prior.root_transfer_id !== rootTransferId ||
          prior.end_to_end_id !== endToEndId || prior.account_id !== accountId ||
          prior.amount_cents !== amountCents || prior.reason !== reason ||
          prior.created_at !== createdAt)) throw new Error("PSP_PIX_RETURN_CONFLICT");
        if (prior) {
          if (!account) throw new Error("PSP_PIX_RETURN_HISTORY_INVALID");
          const receipt = spi.messages(endToEndId).find((message) =>
            message.type === "pacs.004" && message.return_id === returnId);
          if (prior.outcome === "accepted" ?
            !receipt || receipt.amount_cents !== amountCents ||
              receipt.from_ispb !== account.ispb ||
              receipt.to_ispb !== JACARANDA_ISPB ||
              receipt.reason !== reason : Boolean(receipt))
            throw new Error("PSP_PIX_RETURN_HISTORY_INVALID");
          db.exec("COMMIT");
          return { outcome: prior.outcome, failureReason: prior.failure_reason,
            fromIspb: account.ispb };
        }
        const root = db.prepare(`SELECT end_to_end_id,account_id,amount_cents
          FROM psp_roots WHERE root_transfer_id=?`).get(rootTransferId) as
          { end_to_end_id: string; account_id: string; amount_cents: number } | undefined;
        const messages = spi.messages(endToEndId);
        const request = messages.find((message) => message.type === "pacs.008");
        const response = messages.find((message) => message.type === "pacs.002");
        if (!root || root.end_to_end_id !== endToEndId ||
          root.account_id !== accountId || amountCents > root.amount_cents ||
          !account || !request || !response || response.status !== "ACSC" ||
          request.to_ispb !== account.ispb ||
          (request.recipient_account !== undefined &&
            request.recipient_account !== accountId))
          throw new Error("PSP_PIX_RETURN_INVALID");
        if (!spi.availability().available) throw new Error("SPI_UNAVAILABLE");
        const failureReason = psp.availableRoot(accountId, rootTransferId) < amountCents ||
          account.balance_cents < amountCents ? "PSP_FUNDS_UNAVAILABLE" :
          spi.balance(account.ispb) < amountCents ? "SPI_INSUFFICIENT_LIQUIDITY" : null;
        const outcome = failureReason ? "rejected" : "accepted";
        if (!failureReason) {
          spi.returnPayment(endToEndId, returnId, account.ispb,
            JACARANDA_ISPB, amountCents, reason);
          psp.debitAccountRoot(accountId, rootTransferId, amountCents);
        }
        db.prepare(`INSERT INTO psp_pix_return_results
          (return_id,root_transfer_id,end_to_end_id,account_id,amount_cents,
            reason,created_at,outcome,failure_reason) VALUES (?,?,?,?,?,?,?,?,?)`)
          .run(returnId, rootTransferId, endToEndId, accountId,
            amountCents, reason, createdAt, outcome, failureReason);
        db.exec("COMMIT");
        return { outcome, failureReason, fromIspb: account.ispb };
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
    case "returnCautelar": {
      const returnId = requiredString(args.returnId);
      const holdId = requiredString(args.holdId);
      const rootTransferId = requiredString(args.rootTransferId);
      const endToEndId = requiredString(args.endToEndId);
      const accountId = requiredString(args.accountId);
      const amountCents = requiredAmount(args.amountCents);
      const actor = requiredString(args.actor);
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(actor))
        throw new Error("ECOSYSTEM_MESSAGE_INVALID");
      const createdAt = requiredTimestamp(args.createdAt).toISOString();
      operationTime = requiredTimestamp(args.processedAt);
      db.exec("BEGIN IMMEDIATE");
      try {
        const account = spi.account(accountId);
        const prior = db.prepare(`SELECT hold_id,root_transfer_id,end_to_end_id,
          account_id,amount_cents,actor,created_at,outcome,failure_reason
          FROM psp_cautelar_return_results WHERE return_id=?`).get(returnId) as
          { hold_id: string; root_transfer_id: string; end_to_end_id: string;
            account_id: string; amount_cents: number; actor: string;
            created_at: string; outcome: "accepted" | "rejected";
            failure_reason: string | null } | undefined;
        if (prior && (prior.hold_id !== holdId ||
          prior.root_transfer_id !== rootTransferId ||
          prior.end_to_end_id !== endToEndId || prior.account_id !== accountId ||
          prior.amount_cents !== amountCents || prior.actor !== actor ||
          prior.created_at !== createdAt))
          throw new Error("PSP_CAUTELAR_RETURN_CONFLICT");
        if (!prior && db.prepare(`SELECT 1 FROM psp_cautelar_return_results
          WHERE hold_id=?`).get(holdId))
          throw new Error("PSP_CAUTELAR_RETURN_CONFLICT");
        if (prior) {
          const hold = psp.cautelarHold(holdId);
          const receipt = spi.messages(endToEndId).find((message) =>
            message.type === "pacs.004" && message.return_id === returnId);
          if (!account || !hold || (prior.outcome === "accepted" ?
            hold.status !== "returned" || hold.resolved_by !== actor ||
              !receipt || receipt.amount_cents !== amountCents ||
              receipt.from_ispb !== account.ispb ||
              receipt.to_ispb !== JACARANDA_ISPB ||
              receipt.reason !== "cautelar" : Boolean(receipt)))
            throw new Error("PSP_CAUTELAR_RETURN_HISTORY_INVALID");
          db.exec("COMMIT");
          return { outcome: prior.outcome, failureReason: prior.failure_reason,
            fromIspb: account.ispb };
        }
        const hold = psp.cautelarHold(holdId);
        const root = db.prepare(`SELECT end_to_end_id,account_id,amount_cents
          FROM psp_roots WHERE root_transfer_id=?`).get(rootTransferId) as
          { end_to_end_id: string; account_id: string;
            amount_cents: number } | undefined;
        const messages = spi.messages(endToEndId);
        const request = messages.find((message) => message.type === "pacs.008");
        const response = messages.find((message) => message.type === "pacs.002");
        if (!hold || hold.root_transfer_id !== rootTransferId ||
          hold.account_id !== accountId || hold.amount_cents !== amountCents ||
          !root || root.end_to_end_id !== endToEndId || root.account_id !== accountId ||
          amountCents > root.amount_cents || !account || !request || !response ||
          response.status !== "ACSC" || request.to_ispb !== account.ispb ||
          (request.recipient_account !== undefined &&
            request.recipient_account !== accountId))
          throw new Error("PSP_CAUTELAR_RETURN_INVALID");
        const inactive = hold.status !== "active" ||
          hold.expires_at <= operationTime.toISOString();
        if (inactive && hold.status === "active") psp.expireCautelar();
        if (!inactive) {
          if (!spi.availability().available) throw new Error("SPI_UNAVAILABLE");
          if (account.balance_cents < amountCents ||
            spi.balance(account.ispb) < amountCents)
            throw new Error("SPI_INSUFFICIENT_LIQUIDITY");
          psp.resolveCautelar(holdId, "returned", actor);
          spi.returnPayment(endToEndId, returnId, account.ispb,
            JACARANDA_ISPB, amountCents, "cautelar");
          psp.debitAccountRoot(accountId, rootTransferId, amountCents);
        }
        db.prepare(`INSERT INTO psp_cautelar_return_results
          (return_id,hold_id,root_transfer_id,end_to_end_id,account_id,
            amount_cents,actor,created_at,outcome,failure_reason)
          VALUES (?,?,?,?,?,?,?,?,?,?)`)
          .run(returnId, holdId, rootTransferId, endToEndId, accountId,
            amountCents, actor, createdAt,
            inactive ? "rejected" : "accepted",
            inactive ? "PSP_CAUTELAR_NOT_ACTIVE" : null);
        db.exec("COMMIT");
        return { outcome: inactive ? "rejected" : "accepted",
          failureReason: inactive ? "PSP_CAUTELAR_NOT_ACTIVE" : null,
          fromIspb: account.ispb };
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
    case "creditInbound": {
      const accountId = requiredString(args.accountId);
      const rootTransferId = requiredString(args.rootTransferId);
      const endToEndId = requiredString(args.endToEndId);
      const amountCents = requiredAmount(args.amountCents);
      const senderAccount = requiredString(args.senderAccount);
      const settledAt = requiredTimestamp(args.settledAt).toISOString();
      operationTime = args.processedAt === undefined ? new Date() :
        requiredTimestamp(args.processedAt);
      db.exec("BEGIN IMMEDIATE");
      try {
        psp.creditInbound(accountId, rootTransferId, endToEndId, amountCents,
          senderAccount, settledAt);
        const hold = psp.reviewIncoming(accountId, rootTransferId, amountCents);
        db.exec("COMMIT");
        return { credited: true,
          cautelar: hold ? { id: hold.id, reason: hold.reason } : null };
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
    case "pspTransfer": {
      operationTime = requiredTimestamp(args.processedAt);
      return psp.transfer(requiredString(args.rootTransferId),
        requiredString(args.fromAccount), requiredString(args.toAccount),
        requiredAmount(args.amountCents), requiredString(args.idempotencyKey));
    }
    case "pspCashOut": {
      operationTime = requiredTimestamp(args.processedAt);
      return psp.cashOut(requiredString(args.rootTransferId),
        requiredString(args.accountId), requiredAmount(args.amountCents),
        requiredString(args.idempotencyKey));
    }
    case "pspPlaceCautelar": {
      const accountId = requiredString(args.accountId);
      const rootTransferId = requiredString(args.rootTransferId);
      const amountCents = requiredAmount(args.amountCents);
      const reason = requiredString(args.reason);
      const idempotencyKey = requiredString(args.idempotencyKey);
      if (idempotencyKey.length > 128) throw new Error("ECOSYSTEM_MESSAGE_INVALID");
      operationTime = requiredTimestamp(args.processedAt);
      db.exec("BEGIN IMMEDIATE");
      try {
        const prior = db.prepare(`SELECT hold_id,account_id,root_transfer_id,
          amount_cents,reason FROM psp_cautelar_placements
          WHERE idempotency_key=?`).get(idempotencyKey) as
          { hold_id: string; account_id: string; root_transfer_id: string;
            amount_cents: number; reason: string } | undefined;
        if (prior && (prior.account_id !== accountId ||
          prior.root_transfer_id !== rootTransferId ||
          prior.amount_cents !== amountCents || prior.reason !== reason))
          throw new Error("PSP_CAUTELAR_IDEMPOTENCY_CONFLICT");
        const hold = prior ? psp.cautelarHold(prior.hold_id) :
          psp.placeCautelar(accountId, rootTransferId, amountCents, reason);
        if (!hold) throw new Error("PSP_CAUTELAR_PLACEMENT_HISTORY_INVALID");
        if (!prior) db.prepare(`INSERT INTO psp_cautelar_placements
          (idempotency_key,hold_id,account_id,root_transfer_id,amount_cents,
            reason,created_at) VALUES (?,?,?,?,?,?,?)`)
          .run(idempotencyKey, hold.id, accountId, rootTransferId,
            amountCents, reason, hold.created_at);
        db.exec("COMMIT");
        return hold;
      } catch (error) { db.exec("ROLLBACK"); throw error; }
    }
    case "pspReleaseCautelar": {
      const holdId = requiredString(args.holdId);
      const actor = requiredString(args.actor);
      operationTime = requiredTimestamp(args.processedAt);
      const prior = psp.cautelarHold(holdId);
      if (prior?.status === "released") {
        if (prior.resolved_by !== actor) throw new Error("PSP_CAUTELAR_REVIEW_CONFLICT");
        return prior;
      }
      return psp.resolveCautelar(holdId, "released", actor);
    }
    case "pspExpireCautelar": {
      operationTime = requiredTimestamp(args.processedAt);
      return psp.expireCautelar();
    }
    case "reconcilePsp":
      if (args.at !== undefined) operationTime = requiredTimestamp(args.at);
      return psp.reconcile();
    case "noticeBeginLogin": return notices.beginLogin(requiredString(args.identityId),
      requiredString(args.clientNonce), requiredString(args.signature));
    case "noticeCompleteLogin": return notices.completeLogin(requiredString(args.identityId),
      requiredString(args.challengeId), requiredString(args.signature));
    case "noticeBeginOperation": {
      const method = requiredString(args.method);
      if (method === "GET") {
        const cursor = args.cursor === null ? null : requiredString(args.cursor);
        const limit = requiredAmount(args.limit);
        return notices.beginOperation(requiredString(args.token), "GET", { cursor, limit });
      }
      if (method === "POST" && args.cursor === undefined && args.limit === undefined)
        return notices.beginOperation(requiredString(args.token), "POST", {});
      throw new Error("ECOSYSTEM_MESSAGE_INVALID");
    }
    case "noticePage": return notices.notices(requiredString(args.token),
      requiredString(args.challengeId), requiredString(args.signature),
      args.cursor === null ? null : requiredString(args.cursor), requiredAmount(args.limit));
    case "noticeLogout":
      notices.logout(requiredString(args.token), requiredString(args.challengeId),
        requiredString(args.signature));
      return { revoked: true };
    case "noticeProvision":
      notices.provision(requiredString(args.identityId), requiredString(args.accountId),
        requiredString(args.publicKey), requiredString(args.actor));
      return { provisioned: true };
    case "noticeRevoke":
      notices.revoke(requiredString(args.identityId), requiredString(args.actor));
      return { revoked: true };
    case "noticeReprovision":
      notices.reprovision(requiredString(args.identityId), requiredString(args.publicKey),
        requiredString(args.actor));
      return { reprovisioned: true };
    case "close": return { closed: true };
    default: throw new Error("ECOSYSTEM_OPERATION_DENIED");
  }
}

// The server owns shutdown, including when the terminal signals the whole group.
process.on("SIGINT", () => {});
process.once("disconnect", () => { db.close(); process.exit(0); });
process.on("message", async (raw: unknown) => {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
  const message = raw as Partial<Request>;
  if (message.version !== 1 || !Number.isSafeInteger(message.id) ||
    (message.id as number) < 1 || typeof message.operation !== "string") return;
  try {
    const value = await handle(message as Request);
    process.send?.({ version: 1, id: message.id, ok: true, value }, () => {
      if (message.operation === "close") { db.close(); process.exit(0); }
    });
  } catch (error) {
    const reason = error instanceof Error && /^[A-Z0-9_]+$/.test(error.message) ?
      error.message : "ECOSYSTEM_REQUEST_FAILED";
    process.send?.({ version: 1, id: message.id, ok: false, code: reason });
  }
});
process.send({ version: 1, ready: true, pid: process.pid });
