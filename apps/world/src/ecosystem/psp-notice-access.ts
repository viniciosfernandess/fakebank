import { createHash, createPublicKey, randomBytes, verify, type KeyObject } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { BankError } from "../bank.ts";
import { newId } from "../id.ts";

const SESSION_MS = 15 * 60_000;
const CHALLENGE_MS = 2 * 60_000;
const CURSOR_MS = 15 * 60_000;
const hash = (value: string): string => createHash("sha256").update(value).digest("hex");
const nonce = (): string => randomBytes(24).toString("base64url");

interface Identity { identity_id: string; account_id: string; public_key: string;
  revoked_at: string | null; account_status: string; }
interface Session { token_hash: string; identity_id: string; account_id: string; public_key: string;
  expires_at: string; revoked_at: string | null; identity_revoked_at: string | null;
  account_status: string; }
interface Cursor { account_id: string; session_hash: string; last_at: string;
  last_source_rank: number; last_notice_id: number; expires_at: string; used_at: string | null; }
type Notice = { source_rank: number; id: number; kind: string; amount_cents: number;
  message_pt: string; created_at: string };
export interface PspNoticePage { items: { type: "cautelar" | "med"; kind: string;
  amount_cents: number; message_pt: string; created_at: string }[]; next_cursor: string | null; }
export interface PspNoticeOwner {
  db: DatabaseSync;
  realNow(): Date;
  transaction<T>(work: () => T): T;
}

function publicKey(encoded: string): KeyObject {
  if (!/^[A-Za-z0-9_-]{40,256}$/.test(encoded)) throw new BankError("BIZ_PSP_NOTICE_KEY_INVALID");
  try {
    const der = Buffer.from(encoded, "base64url");
    if (der.toString("base64url") !== encoded) throw new Error("Noncanonical encoding");
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519" ||
      !key.export({ format: "der", type: "spki" }).equals(der)) throw new Error("Invalid SPKI key");
    return key;
  } catch { throw new BankError("BIZ_PSP_NOTICE_KEY_INVALID"); }
}
function validSignature(key: string, message: string, signature: string): boolean {
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  return verify(null, Buffer.from(message), publicKey(key), Buffer.from(signature, "base64url"));
}
function tokenHash(token: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new BankError("DEF_PSP_NOTICE_ACCESS");
  return hash(token);
}

export class PspNoticeAccess {
  private readonly bank: PspNoticeOwner;
  private readonly db: DatabaseSync;
  constructor(bank: PspNoticeOwner) {
    this.bank = bank;
    this.db = bank.db;
    this.db.exec(`CREATE TABLE IF NOT EXISTS psp_notice_identities (
      identity_id TEXT PRIMARY KEY, account_id TEXT NOT NULL UNIQUE REFERENCES psp_accounts(id),
      public_key TEXT NOT NULL UNIQUE, provisioned_by TEXT NOT NULL,
      created_at TEXT NOT NULL, revoked_at TEXT
    );
    CREATE TABLE IF NOT EXISTS psp_notice_identity_events (
      id INTEGER PRIMARY KEY, identity_id TEXT NOT NULL, account_id TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('provisioned','revoked','reprovisioned')),
      actor TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS psp_notice_identity_events_no_update
      BEFORE UPDATE ON psp_notice_identity_events
      BEGIN SELECT RAISE(ABORT,'PSP_NOTICE_IDENTITY_EVENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS psp_notice_identity_events_no_delete
      BEFORE DELETE ON psp_notice_identity_events
      BEGIN SELECT RAISE(ABORT,'PSP_NOTICE_IDENTITY_EVENT_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS psp_notice_login_challenges (
      id TEXT PRIMARY KEY, identity_id TEXT NOT NULL REFERENCES psp_notice_identities(identity_id),
      nonce TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT
    );
    CREATE TABLE IF NOT EXISTS psp_notice_login_requests (
      nonce_hash TEXT PRIMARY KEY, identity_id TEXT NOT NULL REFERENCES psp_notice_identities(identity_id),
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS psp_notice_login_requests_rate
      ON psp_notice_login_requests(identity_id,created_at);
    CREATE INDEX IF NOT EXISTS psp_notice_login_challenges_rate
      ON psp_notice_login_challenges(identity_id,created_at);
    CREATE TABLE IF NOT EXISTS psp_notice_login_failures (
      id INTEGER PRIMARY KEY, identity_id TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS psp_notice_login_failures_rate
      ON psp_notice_login_failures(identity_id,created_at);
    CREATE TABLE IF NOT EXISTS psp_notice_sessions (
      token_hash TEXT PRIMARY KEY, identity_id TEXT NOT NULL REFERENCES psp_notice_identities(identity_id),
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT
    );
    CREATE INDEX IF NOT EXISTS psp_notice_sessions_identity
      ON psp_notice_sessions(identity_id,expires_at);
    CREATE TABLE IF NOT EXISTS psp_notice_operation_challenges (
      id TEXT PRIMARY KEY, session_hash TEXT NOT NULL REFERENCES psp_notice_sessions(token_hash),
      method TEXT NOT NULL, path TEXT NOT NULL, request_hash TEXT NOT NULL,
      nonce TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT
    );
    CREATE INDEX IF NOT EXISTS psp_notice_operation_pending
      ON psp_notice_operation_challenges(session_hash,expires_at);
    CREATE TABLE IF NOT EXISTS psp_notice_cursors (
      cursor_hash TEXT PRIMARY KEY, session_hash TEXT NOT NULL REFERENCES psp_notice_sessions(token_hash),
      account_id TEXT NOT NULL REFERENCES psp_accounts(id), last_at TEXT NOT NULL,
      last_source_rank INTEGER NOT NULL, last_notice_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL, used_at TEXT
    );`);
  }

  provision(identityId: string, accountId: string, encodedKey: string, actor: string): void {
    if (!/^[A-Za-z0-9_-]{3,80}$/.test(identityId) || !/^[A-Za-z0-9_-]{3,80}$/.test(actor))
      throw new BankError("BIZ_PSP_NOTICE_IDENTITY_INVALID");
    publicKey(encodedKey);
    this.bank.transaction(() => {
      const account = this.db.prepare("SELECT status FROM psp_accounts WHERE id=?")
        .get(accountId) as { status: string } | undefined;
      if (!account || account.status !== "active") throw new BankError("DEF_NOT_FOUND");
      if (this.db.prepare(`SELECT 1 FROM psp_notice_identities
        WHERE identity_id=? OR account_id=? OR public_key=? LIMIT 1`)
        .get(identityId, accountId, encodedKey))
        throw new BankError("BIZ_PSP_NOTICE_IDENTITY_EXISTS");
      this.db.prepare(`INSERT INTO psp_notice_identities
        (identity_id,account_id,public_key,provisioned_by,created_at)
        VALUES (?,?,?,?,?)`).run(identityId, accountId, encodedKey, actor, this.bank.realNow().toISOString());
      this.db.prepare(`INSERT INTO psp_notice_identity_events
        (identity_id,account_id,action,actor,created_at) VALUES (?,?,'provisioned',?,?)`)
        .run(identityId, accountId, actor, this.bank.realNow().toISOString());
    });
  }

  revoke(identityId: string, actor: string): void {
    if (!/^[A-Za-z0-9_-]{3,80}$/.test(actor)) throw new BankError("BIZ_PSP_NOTICE_IDENTITY_INVALID");
    this.bank.transaction(() => {
      const row = this.identity(identityId);
      if (!row) throw new BankError("DEF_NOT_FOUND");
      if (row.revoked_at) return;
      const now = this.bank.realNow().toISOString();
      this.db.prepare("UPDATE psp_notice_identities SET revoked_at=? WHERE identity_id=?")
        .run(now, identityId);
      this.db.prepare("UPDATE psp_notice_sessions SET revoked_at=? WHERE identity_id=? AND revoked_at IS NULL")
        .run(now, identityId);
      this.db.prepare(`UPDATE psp_notice_cursors SET used_at=? WHERE used_at IS NULL
        AND session_hash IN (SELECT token_hash FROM psp_notice_sessions WHERE identity_id=?)`)
        .run(now, identityId);
      this.db.prepare(`INSERT INTO psp_notice_identity_events
        (identity_id,account_id,action,actor,created_at) VALUES (?,?,'revoked',?,?)`)
        .run(identityId, row.account_id, actor, now);
    });
  }

  reprovision(identityId: string, encodedKey: string, actor: string): void {
    if (!/^[A-Za-z0-9_-]{3,80}$/.test(actor)) throw new BankError("BIZ_PSP_NOTICE_IDENTITY_INVALID");
    publicKey(encodedKey);
    this.bank.transaction(() => {
      const row = this.identity(identityId);
      if (!row || !row.revoked_at || row.account_status !== "active")
        throw new BankError("BIZ_PSP_NOTICE_REPROVISION_INVALID");
      if (row.public_key === encodedKey) throw new BankError("BIZ_PSP_NOTICE_KEY_INVALID");
      if (this.db.prepare(`SELECT 1 FROM psp_notice_identities
        WHERE public_key=? AND identity_id<>? LIMIT 1`).get(encodedKey, identityId))
        throw new BankError("BIZ_PSP_NOTICE_IDENTITY_EXISTS");
      const now = this.bank.realNow().toISOString();
      this.db.prepare(`UPDATE psp_notice_identities SET public_key=?,revoked_at=NULL
        WHERE identity_id=? AND revoked_at IS NOT NULL`).run(encodedKey, identityId);
      this.db.prepare(`INSERT INTO psp_notice_identity_events
        (identity_id,account_id,action,actor,created_at) VALUES (?,?,'reprovisioned',?,?)`)
        .run(identityId, row.account_id, actor, now);
    });
  }

  beginLogin(identityId: string, clientNonce: string, signature: string):
    { challenge_id: string; message: string; expires_at: string } {
    return this.bank.transaction(() => {
      const identity = this.identity(identityId);
      if (!identity || identity.revoked_at || identity.account_status !== "active")
        throw new BankError("DEF_PSP_NOTICE_ACCESS");
      if (!/^[A-Za-z0-9_-]{32}$/.test(clientNonce) ||
        !validSignature(identity.public_key,
          `BancoVivo:psp-notice:begin-login:v1:${identityId}:${clientNonce}`, signature))
        throw new BankError("DEF_PSP_NOTICE_ACCESS");
      const nonceHash = hash(`${identityId}:${clientNonce}`);
      if (this.db.prepare("SELECT 1 FROM psp_notice_login_requests WHERE nonce_hash=?").get(nonceHash))
        throw new BankError("DEF_PSP_NOTICE_ACCESS");
      const now = this.bank.realNow();
      this.loginRate(identityId, now);
      const createdAt = now.toISOString();
      const recent = this.db.prepare(`SELECT COUNT(*) n FROM psp_notice_login_requests
        WHERE identity_id=? AND created_at>=?`).get(identityId,
          new Date(now.getTime() - 15 * 60_000).toISOString()) as { n: number };
      if (recent.n >= 30) throw new BankError("BIZ_PSP_NOTICE_RATE_LIMIT");
      this.db.prepare("INSERT INTO psp_notice_login_requests VALUES (?,?,?)")
        .run(nonceHash, identityId, createdAt);
      const id = newId("psplogin", now.getTime()), random = nonce();
      const expiresAt = new Date(now.getTime() + CHALLENGE_MS).toISOString();
      this.db.prepare(`INSERT INTO psp_notice_login_challenges VALUES (?,?,?,?,?,NULL)`)
        .run(id, identityId, random, createdAt, expiresAt);
      return { challenge_id: id, message: this.loginMessage(id, identityId, random), expires_at: expiresAt };
    });
  }

  completeLogin(identityId: string, challengeId: string, signature: string):
    { session_token: string; expires_at: string } {
    const result = this.bank.transaction(() => {
      const identity = this.identity(identityId);
      const now = this.bank.realNow();
      if (!identity || identity.revoked_at || identity.account_status !== "active") return null;
      this.loginRate(identityId, now);
      const row = this.db.prepare(`SELECT nonce,expires_at,used_at FROM psp_notice_login_challenges
        WHERE id=? AND identity_id=?`).get(challengeId, identityId) as
        { nonce: string; expires_at: string; used_at: string | null } | undefined;
      if (!row || row.used_at || row.expires_at <= now.toISOString()) return null;
      this.db.prepare("UPDATE psp_notice_login_challenges SET used_at=? WHERE id=? AND used_at IS NULL")
        .run(now.toISOString(), challengeId);
      if (!validSignature(identity.public_key,
        this.loginMessage(challengeId, identityId, row.nonce), signature)) {
        this.db.prepare("INSERT INTO psp_notice_login_failures (identity_id,created_at) VALUES (?,?)")
          .run(identityId, now.toISOString());
        return null;
      }
      const token = randomBytes(32).toString("base64url");
      const expiresAt = new Date(now.getTime() + SESSION_MS).toISOString();
      this.db.prepare("INSERT INTO psp_notice_sessions VALUES (?,?,?,?,NULL)")
        .run(hash(token), identityId, now.toISOString(), expiresAt);
      return { session_token: token, expires_at: expiresAt };
    });
    if (!result) throw new BankError("DEF_PSP_NOTICE_ACCESS");
    return result;
  }

  beginOperation(token: string, method: "GET" | "POST", request: { cursor: string | null; limit: number } | Record<string, never>):
    { challenge_id: string; message: string; expires_at: string } {
    const path = method === "GET" ? "/psp/notices" : "/psp/notices/logout";
    return this.bank.transaction(() => {
      const session = this.session(token);
      const now = this.bank.realNow();
      const pending = this.db.prepare(`SELECT COUNT(*) n FROM psp_notice_operation_challenges
        WHERE session_hash=? AND expires_at>? AND used_at IS NULL`)
        .get(session.token_hash, now.toISOString()) as { n: number };
      if (pending.n >= 20) throw new BankError("BIZ_PSP_NOTICE_RATE_LIMIT");
      const id = newId("pspop", now.getTime()), random = nonce();
      const expiresAt = new Date(now.getTime() + CHALLENGE_MS).toISOString();
      const requestHash = hash(JSON.stringify(request));
      this.db.prepare(`INSERT INTO psp_notice_operation_challenges VALUES (?,?,?,?,?,?,?,NULL)`)
        .run(id, session.token_hash, method, path, requestHash, random, expiresAt);
      return { challenge_id: id, message: this.operationMessage(id, session.token_hash,
        method, path, requestHash, random), expires_at: expiresAt };
    });
  }

  notices(token: string, challengeId: string, signature: string,
    cursorToken: string | null, limit: number): PspNoticePage {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50 ||
      (cursorToken !== null && !/^[A-Za-z0-9_-]{43}$/.test(cursorToken)))
      throw new BankError("BIZ_PSP_NOTICE_QUERY_INVALID");
    return this.bank.transaction(() => {
      const session = this.session(token);
      this.consumeOperation(session, challengeId, signature, "GET", "/psp/notices",
        { cursor: cursorToken, limit });
      let cursor: Cursor | undefined;
      if (cursorToken !== null) {
        cursor = this.db.prepare(`SELECT account_id,session_hash,last_at,last_source_rank,
          last_notice_id,expires_at,used_at FROM psp_notice_cursors WHERE cursor_hash=?`)
          .get(hash(cursorToken)) as Cursor | undefined;
        if (!cursor || cursor.account_id !== session.account_id ||
          cursor.session_hash !== session.token_hash || cursor.used_at ||
          cursor.expires_at <= this.bank.realNow().toISOString())
          throw new BankError("DEF_PSP_NOTICE_ACCESS");
        const consumed = this.db.prepare(`UPDATE psp_notice_cursors SET used_at=?
          WHERE cursor_hash=? AND used_at IS NULL`)
          .run(this.bank.realNow().toISOString(), hash(cursorToken));
        if (consumed.changes !== 1) throw new BankError("DEF_PSP_NOTICE_ACCESS");
      }
      const rows = this.db.prepare(`WITH notices AS (
        SELECT 1 source_rank,id,kind,amount_cents,message_pt,created_at
          FROM psp_cautelar_notices WHERE account_id=?
        UNION ALL
        SELECT 2 source_rank,id,kind,amount_cents,message_pt,created_at
          FROM psp_med_notices WHERE account_id=?
      ) SELECT source_rank,id,kind,amount_cents,message_pt,created_at FROM notices
      WHERE ? IS NULL OR created_at<? OR (created_at=? AND
        (source_rank<? OR (source_rank=? AND id<?)))
      ORDER BY created_at DESC,source_rank DESC,id DESC LIMIT ?`)
        .all(session.account_id, session.account_id, cursor?.last_at ?? null,
          cursor?.last_at ?? null, cursor?.last_at ?? null,
          cursor?.last_source_rank ?? null, cursor?.last_source_rank ?? null,
          cursor?.last_notice_id ?? null, limit + 1) as Notice[];
      const visible = rows.slice(0, limit);
      let nextCursor: string | null = null;
      if (rows.length > limit) {
        const last = visible.at(-1)!;
        nextCursor = randomBytes(32).toString("base64url");
        this.db.prepare(`INSERT INTO psp_notice_cursors VALUES (?,?,?,?,?,?,?,NULL)`)
          .run(hash(nextCursor), session.token_hash, session.account_id,
            last.created_at, last.source_rank, last.id,
            new Date(this.bank.realNow().getTime() + CURSOR_MS).toISOString());
      }
      return { items: visible.map((row) => ({ type: row.source_rank === 1 ? "cautelar" as const : "med" as const,
        kind: row.kind, amount_cents: row.amount_cents, message_pt: row.message_pt,
        created_at: row.created_at })), next_cursor: nextCursor };
    });
  }

  logout(token: string, challengeId: string, signature: string): void {
    this.bank.transaction(() => {
      const session = this.session(token);
      this.consumeOperation(session, challengeId, signature, "POST", "/psp/notices/logout", {});
      this.db.prepare("UPDATE psp_notice_sessions SET revoked_at=? WHERE token_hash=?")
        .run(this.bank.realNow().toISOString(), session.token_hash);
    });
  }

  private identity(identityId: string): Identity | undefined {
    return this.db.prepare(`SELECT i.identity_id,i.account_id,i.public_key,i.revoked_at,
      a.status account_status FROM psp_notice_identities i
      JOIN psp_accounts a ON a.id=i.account_id WHERE i.identity_id=?`)
      .get(identityId) as Identity | undefined;
  }
  private session(token: string): Session {
    const row = this.db.prepare(`SELECT s.token_hash,s.identity_id,i.account_id,i.public_key,
      s.expires_at,s.revoked_at,i.revoked_at identity_revoked_at,a.status account_status
      FROM psp_notice_sessions s JOIN psp_notice_identities i ON i.identity_id=s.identity_id
      JOIN psp_accounts a ON a.id=i.account_id
      WHERE s.token_hash=?`).get(tokenHash(token)) as Session | undefined;
    if (!row || row.revoked_at || row.identity_revoked_at || row.account_status !== "active" ||
      row.expires_at <= this.bank.realNow().toISOString())
      throw new BankError("DEF_PSP_NOTICE_ACCESS");
    return row;
  }
  private loginRate(identityId: string, now: Date): void {
    const row = this.db.prepare(`SELECT COUNT(*) n,MAX(created_at) last_at FROM psp_notice_login_failures
      WHERE identity_id=? AND created_at>=?`).get(identityId,
        new Date(now.getTime() - 15 * 60_000).toISOString()) as { n: number; last_at: string | null };
    if (row.n >= 5 && row.last_at && now.getTime() < Date.parse(row.last_at) +
      Math.min(60_000, 1_000 * 2 ** Math.min(row.n - 5, 6)))
      throw new BankError("BIZ_PSP_NOTICE_RATE_LIMIT");
  }
  private consumeOperation(session: Session, challengeId: string, signature: string,
    method: "GET" | "POST", path: string, request: object): void {
    const row = this.db.prepare(`SELECT method,path,request_hash,nonce,expires_at,used_at
      FROM psp_notice_operation_challenges WHERE id=? AND session_hash=?`)
      .get(challengeId, session.token_hash) as { method: string; path: string;
        request_hash: string; nonce: string; expires_at: string; used_at: string | null } | undefined;
    const requestHash = hash(JSON.stringify(request));
    if (!row || row.method !== method || row.path !== path || row.request_hash !== requestHash ||
      row.used_at || row.expires_at <= this.bank.realNow().toISOString() ||
      !validSignature(session.public_key, this.operationMessage(challengeId, session.token_hash,
        method, path, requestHash, row.nonce), signature))
      throw new BankError("DEF_PSP_NOTICE_ACCESS");
    const updated = this.db.prepare(`UPDATE psp_notice_operation_challenges SET used_at=?
      WHERE id=? AND used_at IS NULL`).run(this.bank.realNow().toISOString(), challengeId);
    if (updated.changes !== 1) throw new BankError("DEF_PSP_NOTICE_ACCESS");
  }
  private loginMessage(id: string, identityId: string, random: string): string {
    return `BancoVivo:psp-notice:login:v1:${id}:${identityId}:${random}`;
  }
  private operationMessage(id: string, sessionHash: string, method: string,
    path: string, requestHash: string, random: string): string {
    return `BancoVivo:psp-notice:operation:v1:${id}:${sessionHash}:${method}:${path}:${requestHash}:${random}`;
  }
}
