import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import type { Bank } from "./bank.ts";

export type OperatorRole = "admin" | "maker" | "reviewer";
export interface OperatorIdentity { id: string; role: OperatorRole }

const operatorId = /^[a-zA-Z][a-zA-Z0-9_-]{2,79}$/;
const roles: OperatorRole[] = ["admin", "maker", "reviewer"];
const lockMs = 15 * 60_000;
const dummySalt = "00000000000000000000000000000000";

function passwordHash(password: string, salt: string): Buffer {
  return scryptSync(password, Buffer.from(salt, "hex"), 32);
}
function validPassword(password: string): boolean {
  return password.length >= 12 && password.length <= 256 &&
    !/[\u0000-\u001f\u007f]/.test(password);
}

export class OperatorAuth {
  private readonly bank: Bank;
  private readonly now: () => Date;
  constructor(bank: Bank, now: () => Date = () => new Date()) {
    this.bank = bank;
    this.now = now;
    bank.db.exec(`CREATE TABLE IF NOT EXISTS operator_accounts (
      id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('admin','maker','reviewer')),
      salt TEXT NOT NULL, password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL, disabled_at TEXT,
      failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT
    );
    CREATE TABLE IF NOT EXISTS operator_auth_events (
      id INTEGER PRIMARY KEY, operator_id TEXT NOT NULL, outcome TEXT NOT NULL
        CHECK(outcome IN ('success','denied','locked')),
      occurred_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS operator_auth_events_no_update BEFORE UPDATE ON operator_auth_events
      BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS operator_auth_events_no_delete BEFORE DELETE ON operator_auth_events
      BEGIN SELECT RAISE(ABORT, 'OPERATOR_AUTH_HISTORY_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS operator_admin_events (
      id INTEGER PRIMARY KEY, actor_id TEXT NOT NULL, target_id TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('bootstrap','enroll','password_changed','disabled')),
      occurred_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS operator_admin_events_no_update BEFORE UPDATE ON operator_admin_events
      BEGIN SELECT RAISE(ABORT, 'OPERATOR_ADMIN_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS operator_admin_events_no_delete BEFORE DELETE ON operator_admin_events
      BEGIN SELECT RAISE(ABORT, 'OPERATOR_ADMIN_HISTORY_IMMUTABLE'); END;`);
  }

  bootstrap(id: string, password: string): OperatorIdentity {
    this.validateNew(id, "admin", password);
    return this.bank.transaction(() => {
      const count = this.bank.db.prepare("SELECT COUNT(*) n FROM operator_accounts").get() as
        { n: number };
      if (count.n !== 0) throw new Error("OPERATOR_ALREADY_BOOTSTRAPPED");
      this.insert(id, "admin", password);
      this.audit(id, id, "bootstrap");
      return { id, role: "admin" };
    });
  }

  add(adminId: string, id: string, role: OperatorRole, password: string): OperatorIdentity {
    this.validateNew(id, role, password);
    return this.bank.transaction(() => {
      const admin = this.bank.db.prepare(`SELECT role,disabled_at FROM operator_accounts WHERE id=?`)
        .get(adminId) as { role: OperatorRole; disabled_at: string | null } | undefined;
      if (!admin || admin.role !== "admin" || admin.disabled_at)
        throw new Error("OPERATOR_FORBIDDEN");
      this.insert(id, role, password);
      this.audit(adminId, id, "enroll");
      return { id, role };
    });
  }

  changePassword(id: string, currentPassword: string, newPassword: string): void {
    this.authenticate(id, currentPassword);
    if (!validPassword(newPassword) || newPassword === currentPassword)
      throw new Error("OPERATOR_INPUT_INVALID");
    this.bank.transaction(() => {
      const salt = randomBytes(16).toString("hex");
      const changed = this.bank.db.prepare(`UPDATE operator_accounts SET salt=?,password_hash=?,
        failed_attempts=0,locked_until=NULL WHERE id=? AND disabled_at IS NULL`)
        .run(salt, passwordHash(newPassword, salt).toString("hex"), id);
      if (changed.changes !== 1) throw new Error("OPERATOR_FORBIDDEN");
      this.audit(id, id, "password_changed");
    });
  }

  disable(adminId: string, targetId: string): void {
    this.bank.transaction(() => {
      const admin = this.bank.db.prepare(`SELECT role,disabled_at FROM operator_accounts WHERE id=?`)
        .get(adminId) as { role: OperatorRole; disabled_at: string | null } | undefined;
      const target = this.bank.db.prepare(`SELECT role,disabled_at FROM operator_accounts WHERE id=?`)
        .get(targetId) as { role: OperatorRole; disabled_at: string | null } | undefined;
      if (!admin || admin.role !== "admin" || admin.disabled_at || !target || target.disabled_at)
        throw new Error("OPERATOR_FORBIDDEN");
      if (target.role === "admin") {
        const remaining = this.bank.db.prepare(`SELECT COUNT(*) n FROM operator_accounts
          WHERE role='admin' AND disabled_at IS NULL`).get() as { n: number };
        if (remaining.n <= 1) throw new Error("OPERATOR_LAST_ADMIN");
      }
      this.bank.db.prepare("UPDATE operator_accounts SET disabled_at=? WHERE id=?")
        .run(this.now().toISOString(), targetId);
      this.audit(adminId, targetId, "disabled");
    });
  }

  authenticate(id: string, password: string): OperatorIdentity {
    const now = this.now();
    const row = this.bank.db.prepare(`SELECT role,salt,password_hash,disabled_at,
      failed_attempts,locked_until FROM operator_accounts WHERE id=?`).get(id) as
      { role: OperatorRole; salt: string; password_hash: string; disabled_at: string | null;
        failed_attempts: number; locked_until: string | null } | undefined;
    const candidate = passwordHash(validPassword(password) ? password : "", row?.salt ?? dummySalt);
    const expected = Buffer.from(row?.password_hash ?? "0".repeat(64), "hex");
    const matches = timingSafeEqual(candidate, expected);
    const locked = Boolean(row?.locked_until && row.locked_until > now.toISOString());
    const success = Boolean(row && !row.disabled_at && !locked && matches);
    this.bank.transaction(() => {
      this.bank.db.prepare(`INSERT INTO operator_auth_events
        (operator_id,outcome,occurred_at) VALUES (?,?,?)`).run(
          operatorId.test(id) ? id : "invalid", success ? "success" : locked ? "locked" : "denied",
          now.toISOString());
      if (!row) return;
      if (success) {
        this.bank.db.prepare(`UPDATE operator_accounts SET failed_attempts=0,locked_until=NULL
          WHERE id=?`).run(id);
      } else if (!locked && !row.disabled_at) {
        const attempts = row.failed_attempts + 1;
        this.bank.db.prepare(`UPDATE operator_accounts SET failed_attempts=?,locked_until=?
          WHERE id=?`).run(attempts >= 5 ? 0 : attempts,
            attempts >= 5 ? new Date(now.getTime() + lockMs).toISOString() : null, id);
      }
    });
    if (!success) throw new Error("OPERATOR_BAD_CREDENTIALS");
    return { id, role: row!.role };
  }

  require(identity: OperatorIdentity, allowed: readonly OperatorRole[]): void {
    if (!allowed.includes(identity.role)) throw new Error("OPERATOR_FORBIDDEN");
  }

  private validateNew(id: string, role: OperatorRole, password: string): void {
    if (!operatorId.test(id) || !roles.includes(role) || !validPassword(password))
      throw new Error("OPERATOR_INPUT_INVALID");
  }

  private insert(id: string, role: OperatorRole, password: string): void {
    const salt = randomBytes(16).toString("hex");
    this.bank.db.prepare(`INSERT INTO operator_accounts
      (id,role,salt,password_hash,created_at) VALUES (?,?,?,?,?)`).run(
        id, role, salt, passwordHash(password, salt).toString("hex"), this.now().toISOString());
  }

  private audit(actorId: string, targetId: string,
    action: "bootstrap" | "enroll" | "password_changed" | "disabled"): void {
    this.bank.db.prepare(`INSERT INTO operator_admin_events
      (actor_id,target_id,action,occurred_at) VALUES (?,?,?,?)`)
      .run(actorId, targetId, action, this.now().toISOString());
  }
}
