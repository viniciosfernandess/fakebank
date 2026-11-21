import { createHash, randomBytes } from "node:crypto";
import type { Bank } from "../../world/src/bank.ts";
import { OperatorAuth, type OperatorIdentity } from "../../world/src/operator-auth.ts";

const cookieName = "bv_operator_session";
const sessionMs = 15 * 60_000;
const maxSessions = 32;

interface Session {
  operatorId: string;
  passwordHash: string;
  expiresAt: number;
}

function cookieToken(cookie: string | undefined): string | null {
  const value = cookie?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
  return value && /^[0-9a-f]{64}$/.test(value) ? value : null;
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export class OperatorSessions {
  private readonly auth: OperatorAuth;
  private readonly bank: Bank;
  private readonly sessions = new Map<string, Session>();

  constructor(bank: Bank) {
    this.bank = bank;
    this.auth = new OperatorAuth(bank);
  }

  login(id: string, password: string): { token: string; identity: OperatorIdentity } {
    const identity = this.auth.authenticate(id, password);
    this.auth.require(identity, ["admin", "reviewer"]);
    return this.createSession(identity);
  }

  loginMedMaker(id: string, password: string): { token: string; identity: OperatorIdentity } {
    const identity = this.auth.authenticate(id, password);
    this.auth.require(identity, ["maker"]);
    return this.createSession(identity);
  }

  private createSession(identity: OperatorIdentity): { token: string;
    identity: OperatorIdentity } {
    const id = identity.id;
    const row = this.bank.db.prepare("SELECT password_hash FROM operator_accounts WHERE id=?")
      .get(id) as { password_hash: string };
    const token = randomBytes(32).toString("hex");
    for (const [key, session] of this.sessions)
      if (session.expiresAt <= Date.now()) this.sessions.delete(key);
    if (this.sessions.size >= maxSessions) this.sessions.delete(this.sessions.keys().next().value!);
    this.sessions.set(tokenHash(token), { operatorId: id,
      passwordHash: row.password_hash, expiresAt: Date.now() + sessionMs });
    return { token, identity };
  }

  identity(cookie: string | undefined): OperatorIdentity | null {
    const identity = this.medIdentity(cookie);
    return identity && identity.role !== "maker" ? identity : null;
  }

  medIdentity(cookie: string | undefined): OperatorIdentity | null {
    const token = cookieToken(cookie);
    if (!token) return null;
    const key = tokenHash(token);
    const session = this.sessions.get(key);
    if (!session) return null;
    const row = this.bank.db.prepare(`SELECT role,password_hash,disabled_at
      FROM operator_accounts WHERE id=?`).get(session.operatorId) as
      { role: OperatorIdentity["role"]; password_hash: string;
        disabled_at: string | null } | undefined;
    if (session.expiresAt <= Date.now() || !row || row.disabled_at ||
      row.password_hash !== session.passwordHash ||
      !["admin", "reviewer", "maker"].includes(row.role)) {
      this.sessions.delete(key);
      return null;
    }
    return { id: session.operatorId, role: row.role };
  }

  logout(cookie: string | undefined): void {
    const token = cookieToken(cookie);
    if (token) this.sessions.delete(tokenHash(token));
  }

  cookie(token: string, secure: boolean,
    path: "/api/operator" | "/api" = "/api/operator"): string {
    return `${cookieName}=${token}; Path=${path}; HttpOnly; SameSite=Strict; Max-Age=900${
      secure ? "; Secure" : ""}`;
  }

  clearCookie(secure: boolean,
    path: "/api/operator" | "/api" = "/api/operator"): string {
    return `${cookieName}=; Path=${path}; HttpOnly; SameSite=Strict; Max-Age=0${
      secure ? "; Secure" : ""}`;
  }
}
