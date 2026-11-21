import { createHash, createPublicKey, randomBytes, scryptSync, timingSafeEqual, verify, type KeyObject } from "node:crypto";
import { Bank, BankError } from "./bank.ts";
import { newId } from "./id.ts";
import { installDeviceSecurityNotices, listDeviceSecurityNotices, recordDeviceBinding } from "./device-security-notices.ts";
function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function token(): string { return randomBytes(24).toString("base64url"); }
function passwordHash(password: string, salt: string): string { return scryptSync(password, salt, 32).toString("hex"); }
function same(a: string, b: string): boolean {
    const first = Buffer.from(a, "hex");
    const second = Buffer.from(b, "hex");
    return first.length === second.length && timingSafeEqual(first, second);
}
function deviceKey(encoded: string): KeyObject {
    if (!/^[A-Za-z0-9_-]{40,180}$/.test(encoded))
        throw new BankError("BIZ_DEVICE_KEY_INVALID");
    try {
        const key = createPublicKey({ key: Buffer.from(encoded, "base64url"),
            format: "der", type: "spki" });
        if (key.asymmetricKeyType !== "ed25519" ||
            key.export({ format: "der", type: "spki" }).toString("base64url") !== encoded)
            throw new Error("Invalid Ed25519 public key");
        return key;
    }
    catch {
        throw new BankError("BIZ_DEVICE_KEY_INVALID");
    }
}
function signedMessage(purpose: "enroll" | "operation", id: string, deviceId: string, method: string | null, path: string | null, bodyHash: string | null): string {
    return purpose === "enroll" ? `BancoVivo:device:enroll:v1:${id}:${deviceId}` :
        `BancoVivo:device:operation:v1:${id}:${method}:${path}:${bodyHash}`;
}
function requestHash(body: unknown): string {
    return hash(JSON.stringify(body ?? null, (_key, value: unknown) => value && typeof value === "object" && !Array.isArray(value)
        ? Object.fromEntries(Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0))
        : value));
}
interface DeviceChallenge {
    id: string;
    session_id: string;
    device_id: string;
    purpose: "enroll" | "operation";
    method: string | null;
    path: string | null;
    body_hash: string | null;
    expires_at: string;
    used_at: string | null;
}
export class AuthEngine {
    readonly bank: Bank;
    constructor(bank: Bank) {
        this.bank = bank;
        bank.db.exec(`CREATE TABLE IF NOT EXISTS auth_passwords (
      customer_id TEXT PRIMARY KEY REFERENCES customers(id), salt TEXT NOT NULL, password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_password_changes (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      replaced INTEGER NOT NULL CHECK(replaced IN (0,1)), changed_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS auth_password_changes_recent
      ON auth_password_changes(customer_id,changed_at);
    CREATE TRIGGER IF NOT EXISTS auth_password_changes_no_update
      BEFORE UPDATE ON auth_password_changes
      BEGIN SELECT RAISE(ABORT, 'PASSWORD_HISTORY_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS auth_password_changes_no_delete
      BEFORE DELETE ON auth_password_changes
      BEGIN SELECT RAISE(ABORT, 'PASSWORD_HISTORY_IMMUTABLE'); END;
    CREATE TABLE IF NOT EXISTS auth_devices (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id), fingerprint TEXT NOT NULL,
      first_seen_at TEXT NOT NULL,
      first_seen_ip TEXT NOT NULL, trusted_at TEXT, revoked_at TEXT, pix_registered_at TEXT,
      bound_at TEXT,
      synthetic_geo TEXT
    );
    CREATE TABLE IF NOT EXISTS auth_challenges (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id), device_id TEXT NOT NULL,
      otp_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT
    );
    CREATE TABLE IF NOT EXISTS otp_attempts (
      id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL, customer_id TEXT NOT NULL,
      source_ip TEXT NOT NULL, ts TEXT NOT NULL, correct INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS otp_attempt_customer ON otp_attempts(customer_id,ts);
    CREATE INDEX IF NOT EXISTS otp_attempt_source ON otp_attempts(source_ip,ts);
    CREATE INDEX IF NOT EXISTS otp_attempt_challenge ON otp_attempts(challenge_id,ts);
    CREATE TABLE IF NOT EXISTS auth_sessions (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, device_id TEXT NOT NULL,
      access_hash TEXT NOT NULL UNIQUE, access_exp TEXT NOT NULL,
      refresh_hash TEXT NOT NULL UNIQUE, refresh_exp TEXT NOT NULL,
      step_up_until TEXT, revoked_at TEXT
    );
    CREATE INDEX IF NOT EXISTS session_customer ON auth_sessions(customer_id);
    CREATE TABLE IF NOT EXISTS auth_refresh_used (
      refresh_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES auth_sessions(id),
      used_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS auth_refresh_challenges (
      id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES auth_sessions(id),
      refresh_hash TEXT NOT NULL, created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL, used_at TEXT
    );
    CREATE INDEX IF NOT EXISTS auth_refresh_challenges_session
      ON auth_refresh_challenges(session_id,used_at,expires_at);
    CREATE TABLE IF NOT EXISTS auth_device_challenges (
      id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES auth_sessions(id),
      device_id TEXT NOT NULL REFERENCES auth_devices(id),
      purpose TEXT NOT NULL CHECK(purpose IN ('enroll','operation')),
      method TEXT, path TEXT, body_hash TEXT,
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT,
      CHECK((purpose='enroll' AND method IS NULL AND path IS NULL AND body_hash IS NULL)
        OR (purpose='operation' AND method IN ('GET','POST','PATCH','DELETE') AND path IS NOT NULL
          AND body_hash IS NOT NULL))
    );
    CREATE INDEX IF NOT EXISTS auth_device_challenges_session
      ON auth_device_challenges(session_id,used_at,expires_at);
    CREATE TRIGGER IF NOT EXISTS auth_customer_deactivated
      AFTER UPDATE OF status ON customers WHEN NEW.status<>'active'
      BEGIN
        UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP
          WHERE customer_id=NEW.id AND revoked_at IS NULL;
        UPDATE auth_challenges SET used_at=CURRENT_TIMESTAMP
          WHERE customer_id=NEW.id AND used_at IS NULL;
      END;
    `);
        const challengeSchema = bank.db.prepare(`SELECT sql FROM sqlite_master
      WHERE type='table' AND name='auth_device_challenges'`).get() as {
            sql: string;
        } | undefined;
        if (challengeSchema?.sql.includes("method='POST'"))
            bank.transaction(() => {
                bank.db.exec(`CREATE TABLE auth_device_challenges_next (
        id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES auth_sessions(id),
        device_id TEXT NOT NULL REFERENCES auth_devices(id),
        purpose TEXT NOT NULL CHECK(purpose IN ('enroll','operation')),
        method TEXT, path TEXT, body_hash TEXT,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT,
        CHECK((purpose='enroll' AND method IS NULL AND path IS NULL AND body_hash IS NULL)
          OR (purpose='operation' AND method IN ('GET','POST','PATCH') AND path IS NOT NULL
            AND body_hash IS NOT NULL))
      );
      INSERT INTO auth_device_challenges_next SELECT * FROM auth_device_challenges;
      DROP TABLE auth_device_challenges;
      ALTER TABLE auth_device_challenges_next RENAME TO auth_device_challenges;
      CREATE INDEX auth_device_challenges_session
        ON auth_device_challenges(session_id,used_at,expires_at);`);
            });
        const currentChallengeSchema = bank.db.prepare(`SELECT sql FROM sqlite_master
      WHERE type='table' AND name='auth_device_challenges'`).get() as {
            sql: string;
        } | undefined;
        if (currentChallengeSchema && !currentChallengeSchema.sql.includes("'DELETE'"))
            bank.transaction(() => {
                bank.db.exec(`CREATE TABLE auth_device_challenges_next (
        id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES auth_sessions(id),
        device_id TEXT NOT NULL REFERENCES auth_devices(id),
        purpose TEXT NOT NULL CHECK(purpose IN ('enroll','operation')),
        method TEXT, path TEXT, body_hash TEXT,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT,
        CHECK((purpose='enroll' AND method IS NULL AND path IS NULL AND body_hash IS NULL)
          OR (purpose='operation' AND method IN ('GET','POST','PATCH','DELETE') AND path IS NOT NULL
            AND body_hash IS NOT NULL))
      );
      INSERT INTO auth_device_challenges_next SELECT * FROM auth_device_challenges;
      DROP TABLE auth_device_challenges;
      ALTER TABLE auth_device_challenges_next RENAME TO auth_device_challenges;
      CREATE INDEX auth_device_challenges_session
        ON auth_device_challenges(session_id,used_at,expires_at);`);
            });
        const now = bank.now().toISOString();
        bank.db.prepare(`UPDATE auth_sessions SET revoked_at=? WHERE revoked_at IS NULL
      AND customer_id IN (SELECT id FROM customers WHERE status<>'active')`).run(now);
        bank.db.prepare(`UPDATE auth_challenges SET used_at=? WHERE used_at IS NULL
      AND customer_id IN (SELECT id FROM customers WHERE status<>'active')`).run(now);
        const columns = bank.db.prepare("PRAGMA table_info(auth_devices)").all() as {
            name: string;
        }[];
        if (!columns.some((column) => column.name === "fingerprint"))
            bank.db.exec("ALTER TABLE auth_devices ADD COLUMN fingerprint TEXT");
        if (!columns.some((column) => column.name === "pix_registered_at")) {
            bank.db.exec("ALTER TABLE auth_devices ADD COLUMN pix_registered_at TEXT");
            bank.db.exec("UPDATE auth_devices SET pix_registered_at=trusted_at WHERE trusted_at IS NOT NULL");
        }
        if (!columns.some((column) => column.name === "synthetic_geo"))
            bank.db.exec("ALTER TABLE auth_devices ADD COLUMN synthetic_geo TEXT");
        if (!columns.some((column) => column.name === "public_key"))
            bank.db.exec("ALTER TABLE auth_devices ADD COLUMN public_key TEXT");
        if (!columns.some((column) => column.name === "bound_at"))
            bank.transaction(() => {
                bank.db.exec("ALTER TABLE auth_devices ADD COLUMN bound_at TEXT");
                bank.db.exec(`UPDATE auth_devices SET bound_at=first_seen_at
        WHERE public_key IS NOT NULL AND bound_at IS NULL`);
            });
        bank.db.exec("UPDATE auth_devices SET fingerprint=id WHERE fingerprint IS NULL");
        bank.db.exec("CREATE UNIQUE INDEX IF NOT EXISTS auth_device_fingerprint ON auth_devices(customer_id,fingerprint)");
        bank.db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS auth_device_public_key
      ON auth_devices(public_key) WHERE public_key IS NOT NULL`);
        installDeviceSecurityNotices(bank.db);
        bank.db.exec(`CREATE TABLE IF NOT EXISTS auth_clock_migration (
      version INTEGER PRIMARY KEY CHECK(version=1), applied_at TEXT NOT NULL
    )`);
        if (!bank.db.prepare("SELECT 1 FROM auth_clock_migration WHERE version=1").get())
            bank.transaction(() => {
                const appliedAt = bank.realNow().toISOString();
                bank.db.prepare("UPDATE auth_sessions SET revoked_at=? WHERE revoked_at IS NULL")
                    .run(appliedAt);
                bank.db.prepare("UPDATE auth_challenges SET used_at=? WHERE used_at IS NULL")
                    .run(appliedAt);
                bank.db.prepare("UPDATE auth_device_challenges SET used_at=? WHERE used_at IS NULL")
                    .run(appliedAt);
                bank.db.prepare("UPDATE auth_refresh_challenges SET used_at=? WHERE used_at IS NULL")
                    .run(appliedAt);
                bank.db.prepare("INSERT INTO auth_clock_migration VALUES (1,?)").run(appliedAt);
            });
    }
    // Confirms this AuthEngine instance can write through the auth telemetry path.
    heartbeat(): void {
        this.bank.telemetry.emit({ source: "auth", category: "health", action: "heartbeat",
            outcome: "success", message: "Auth telemetry heartbeat" });
    }
    setPassword(customerId: string, password: string): void {
        this.bank.customer(customerId);
        if (password.length < 12)
            throw new BankError("BIZ_WEAK_PASSWORD");
        this.bank.transaction(() => {
            const previous = this.bank.db.prepare("SELECT salt,password_hash FROM auth_passwords WHERE customer_id=?")
                .get(customerId) as {
                salt: string;
                password_hash: string;
            } | undefined;
            if (previous && same(passwordHash(password, previous.salt), previous.password_hash))
                return;
            const salt = token();
            this.bank.db.prepare("INSERT OR REPLACE INTO auth_passwords VALUES (?,?,?)")
                .run(customerId, salt, passwordHash(password, salt));
        });
    }
    changePassword(access: string, currentPassword: string, newPassword: string): void {
        const customerId = this.customerForAccess(access);
        if (!customerId)
            throw new BankError("DEF_UNAUTHORIZED");
        if (newPassword.length < 12 || newPassword.length > 256)
            throw new BankError("BIZ_WEAK_PASSWORD");
        this.bank.transaction(() => {
            const previous = this.bank.db.prepare("SELECT salt,password_hash FROM auth_passwords WHERE customer_id=?")
                .get(customerId) as {
                salt: string;
                password_hash: string;
            } | undefined;
            if (!previous || !same(passwordHash(currentPassword, previous.salt), previous.password_hash))
                throw new BankError("DEF_BAD_CREDENTIALS");
            if (same(passwordHash(newPassword, previous.salt), previous.password_hash))
                throw new BankError("BIZ_PASSWORD_UNCHANGED");
            const salt = token();
            const now = this.bank.now().toISOString();
            this.bank.db.prepare("UPDATE auth_passwords SET salt=?,password_hash=? WHERE customer_id=?")
                .run(salt, passwordHash(newPassword, salt), customerId);
            this.bank.db.prepare("INSERT INTO auth_password_changes VALUES (?,?,1,?)")
                .run(newId("password_change", this.bank.now().getTime()), customerId, now);
            this.bank.db.prepare("UPDATE auth_sessions SET revoked_at=? WHERE customer_id=? AND revoked_at IS NULL")
                .run(now, customerId);
            this.bank.db.prepare("UPDATE auth_challenges SET used_at=? WHERE customer_id=? AND used_at IS NULL")
                .run(now, customerId);
            this.bank.log({ actor: customerId, kind: "password_changed", customerId,
                route: "auth.password", status: 200 });
        });
    }
    beginLogin(cpf: string, password: string, ip: string, fingerprint: string): {
        challenge_id: string;
        expires_at: string;
        device_proof_message: string;
    } {
        const customer = this.bank.db.prepare("SELECT id FROM customers WHERE cpf=? AND status='active'").get(cpf) as {
            id: string;
        } | undefined;
        const credentials = customer ? this.bank.db.prepare("SELECT salt,password_hash FROM auth_passwords WHERE customer_id=?")
            .get(customer.id) as {
            salt: string;
            password_hash: string;
        } | undefined : undefined;
        if (!customer || !credentials || !same(passwordHash(password, credentials.salt), credentials.password_hash)) {
            this.bank.log({ actor: customer?.id ?? "unknown", kind: "login_failed", ...(customer ? { customerId: customer.id } : {}), route: "auth.login", status: 401, peerIp: ip });
            throw new BankError("DEF_BAD_CREDENTIALS");
        }
        const now = this.bank.now();
        let device = this.bank.db.prepare("SELECT id,revoked_at FROM auth_devices WHERE customer_id=? AND id=?")
            .get(customer.id, fingerprint) as {
            id: string;
            revoked_at: string | null;
        } | undefined;
        if (!device)
            device = this.bank.db.prepare("SELECT id,revoked_at FROM auth_devices WHERE customer_id=? AND fingerprint=?")
                .get(customer.id, fingerprint) as {
                id: string;
                revoked_at: string | null;
            } | undefined;
        if (!device) {
            const id = newId("dev", now.getTime());
            this.bank.db.prepare(`INSERT INTO auth_devices
        (id,customer_id,fingerprint,first_seen_at,first_seen_ip,trusted_at,revoked_at)
        VALUES (?,?,?,?,?,NULL,NULL)`).run(id, customer.id, fingerprint, now.toISOString(), ip);
            device = { id, revoked_at: null };
        }
        if (device.revoked_at)
            throw new BankError("DEF_DEVICE_REVOKED");
        const challengeId = newId("ch", now.getTime());
        const otp = String(randomBytes(4).readUInt32BE() % 1000000).padStart(6, "0");
        const expires = new Date(this.bank.realNow().getTime() + 5 * 60000).toISOString();
        this.bank.db.prepare("INSERT INTO auth_challenges VALUES (?,?,?,?,?,NULL)").run(challengeId, customer.id, device.id, hash(otp), expires);
        this.otpVault.set(challengeId, otp);
        this.bank.log({ actor: customer.id, kind: "login_challenge", customerId: customer.id, route: "auth.login", status: 200, peerIp: ip });
        return { challenge_id: challengeId, expires_at: expires,
            device_proof_message: `BancoVivo:device:login:v1:${challengeId}:${device.id}` };
    }
    private readonly otpVault = new Map<string, string>();
    simulatedOtp(challengeId: string, customerId: string): string {
        const challenge = this.bank.db.prepare("SELECT customer_id FROM auth_challenges WHERE id=?")
            .get(challengeId) as {
            customer_id: string;
        } | undefined;
        if (!challenge || challenge.customer_id !== customerId)
            throw new BankError("DEF_NOT_FOUND");
        const otp = this.otpVault.get(challengeId);
        if (!otp)
            throw new BankError("DEF_NOT_FOUND");
        return otp;
    }
    verifyOtp(challengeId: string, otp: string, ip: string, deviceProof?: {
        publicKey: string;
        signature: string;
    }): {
        access_token: string;
        refresh_token: string;
        expires_at: string;
        customer_id: string;
    } {
        const row = this.bank.db.prepare("SELECT customer_id,device_id,otp_hash,expires_at,used_at FROM auth_challenges WHERE id=?")
            .get(challengeId) as {
            customer_id: string;
            device_id: string;
            otp_hash: string;
            expires_at: string;
            used_at: string | null;
        } | undefined;
        if (!row || row.used_at || Date.parse(row.expires_at) < this.bank.realNow().getTime())
            throw new BankError("DEF_OTP_EXPIRED");
        if (this.bank.customer(row.customer_id).status !== "active")
            throw new BankError("DEF_UNAUTHORIZED");
        const since = new Date(this.bank.realNow().getTime() - 15 * 60000).toISOString();
        {
            const attempts = this.bank.db.prepare(`SELECT
        SUM(CASE WHEN a.challenge_id=? THEN 1 ELSE 0 END) challenge_count,
        MAX(CASE WHEN a.challenge_id=? THEN a.ts END) challenge_last,
        SUM(CASE WHEN a.customer_id=? AND c.device_id=? THEN 1 ELSE 0 END) device_count,
        MAX(CASE WHEN a.customer_id=? AND c.device_id=? THEN a.ts END) device_last,
        SUM(CASE WHEN a.customer_id=? AND a.source_ip=? THEN 1 ELSE 0 END) customer_ip_count,
        MAX(CASE WHEN a.customer_id=? AND a.source_ip=? THEN a.ts END) customer_ip_last,
        SUM(CASE WHEN a.source_ip=? THEN 1 ELSE 0 END) ip_count,
        MAX(CASE WHEN a.source_ip=? THEN a.ts END) ip_last
        FROM otp_attempts a JOIN auth_challenges c ON c.id=a.challenge_id
        WHERE a.correct=0 AND a.ts>=? AND (a.customer_id=? OR a.source_ip=?)`)
                .get(challengeId, challengeId, row.customer_id, row.device_id, row.customer_id, row.device_id, row.customer_id, ip, row.customer_id, ip, ip, ip, since, row.customer_id, ip) as {
                challenge_count: number | null;
                challenge_last: string | null;
                device_count: number | null;
                device_last: string | null;
                customer_ip_count: number | null;
                customer_ip_last: string | null;
                ip_count: number | null;
                ip_last: string | null;
            };
            const now = this.bank.realNow().getTime();
            const limited = ([
                [attempts.challenge_count, attempts.challenge_last, 5],
                [attempts.device_count, attempts.device_last, 5],
                [attempts.customer_ip_count, attempts.customer_ip_last, 10],
                [attempts.ip_count, attempts.ip_last, 50],
            ] as const).some(([count, last, threshold]) => count !== null && last !== null &&
                count >= threshold && now < Date.parse(last) +
                Math.min(60000, 1000 * 2 ** Math.min(count - threshold, 6)));
            if (limited)
                throw new BankError("DEF_OTP_LOCKED");
        }
        const correct = same(hash(otp), row.otp_hash);
        this.bank.db.prepare("INSERT INTO otp_attempts VALUES (?,?,?,?,?,?)")
            .run(newId("attempt", this.bank.realNow().getTime()), challengeId, row.customer_id, ip, this.bank.realNow().toISOString(), Number(correct));
        if (!correct)
            throw new BankError("DEF_BAD_OTP");
        const result = this.bank.transaction(() => {
            const device = this.bank.db.prepare("SELECT public_key,revoked_at FROM auth_devices WHERE id=? AND customer_id=?")
                .get(row.device_id, row.customer_id) as {
                public_key: string | null;
                revoked_at: string | null;
            } | undefined;
            if (!device || device.revoked_at)
                throw new BankError("DEF_DEVICE_REVOKED");
            if (device.public_key && !deviceProof)
                throw new BankError("DEF_DEVICE_KEY_REQUIRED");
            if (deviceProof) {
                if (device.public_key && device.public_key !== deviceProof.publicKey)
                    throw new BankError("DEF_DEVICE_PROOF_INVALID");
                const key = deviceKey(deviceProof.publicKey);
                this.verifySignature(key, `BancoVivo:device:login:v1:${challengeId}:${row.device_id}`, deviceProof.signature);
                if (!device.public_key) {
                    if (this.bank.db.prepare("SELECT 1 FROM auth_devices WHERE public_key=?").get(deviceProof.publicKey))
                        throw new BankError("BIZ_DEVICE_KEY_EXISTS");
                    this.bank.db.prepare(`UPDATE auth_devices SET public_key=?,bound_at=?
            WHERE id=? AND public_key IS NULL`)
                        .run(deviceProof.publicKey, this.bank.now().toISOString(), row.device_id);
                    recordDeviceBinding(this.bank.db, row.customer_id, row.device_id, this.bank.realNow().toISOString(), this.bank.now().toISOString());
                    this.bank.log({ actor: row.customer_id, kind: "device_key_bound", customerId: row.customer_id,
                        route: `auth.devices:${row.device_id}`, status: 200 });
                }
            }
            this.bank.db.prepare("UPDATE auth_challenges SET used_at=? WHERE id=?")
                .run(this.bank.realNow().toISOString(), challengeId);
            this.bank.db.prepare(`UPDATE auth_devices SET trusted_at=? WHERE id=? AND trusted_at IS NULL
        AND first_seen_at<=?`).run(this.bank.now().toISOString(), row.device_id, new Date(this.bank.now().getTime() - 24 * 60 * 60000).toISOString());
            const access = token();
            const refresh = token();
            const accessExp = new Date(this.bank.realNow().getTime() + 15 * 60000).toISOString();
            const refreshExp = new Date(this.bank.realNow().getTime() + 7 * 86400000).toISOString();
            this.bank.db.prepare("INSERT INTO auth_sessions VALUES (?,?,?,?,?,?,?,NULL,NULL)")
                .run(newId("ses", this.bank.now().getTime()), row.customer_id, row.device_id, hash(access), accessExp, hash(refresh), refreshExp);
            return { access_token: access, refresh_token: refresh, expires_at: accessExp,
                customer_id: row.customer_id };
        });
        this.otpVault.delete(challengeId);
        return result;
    }
    customerForAccess(access: string): string | undefined {
        const row = this.bank.db.prepare(`SELECT s.id,s.customer_id,s.device_id,s.access_exp,s.revoked_at,
      d.revoked_at device_revoked_at,c.status customer_status
      FROM auth_sessions s JOIN auth_devices d ON d.id=s.device_id
      JOIN customers c ON c.id=s.customer_id WHERE s.access_hash=?`)
            .get(hash(access)) as {
            id: string;
            customer_id: string;
            device_id: string;
            access_exp: string;
            revoked_at: string | null;
            device_revoked_at: string | null;
            customer_status: string;
        } | undefined;
        if (!row || row.revoked_at || row.customer_status !== "active" ||
            Date.parse(row.access_exp) <= this.bank.realNow().getTime())
            return undefined;
        if (row.device_revoked_at)
            return undefined;
        return row.customer_id;
    }
    traceIdentityForAccess(access: string): {
        userId: string;
        deviceId: string;
        sessionId: string;
        geo?: string;
    } | undefined {
        if (!this.customerForAccess(access))
            return undefined;
        const row = this.bank.db.prepare(`SELECT s.id,s.customer_id,s.device_id,d.synthetic_geo
      FROM auth_sessions s JOIN auth_devices d ON d.id=s.device_id
      WHERE s.access_hash=?`).get(hash(access)) as {
            id: string;
            customer_id: string;
            device_id: string;
            synthetic_geo: string | null;
        } | undefined;
        return row ? { userId: row.customer_id, deviceId: row.device_id,
            sessionId: row.id, ...(row.synthetic_geo ? { geo: row.synthetic_geo } : {}) } : undefined;
    }
    stepUp(access: string, password: string): {
        valid_until: string;
    } {
        const customerId = this.customerForAccess(access);
        if (!customerId)
            throw new BankError("DEF_UNAUTHORIZED");
        const credentials = this.bank.db.prepare("SELECT salt,password_hash FROM auth_passwords WHERE customer_id=?")
            .get(customerId) as {
            salt: string;
            password_hash: string;
        } | undefined;
        if (!credentials || !same(passwordHash(password, credentials.salt), credentials.password_hash))
            throw new BankError("DEF_BAD_CREDENTIALS");
        const until = new Date(this.bank.realNow().getTime() + 5 * 60000).toISOString();
        this.bank.db.prepare("UPDATE auth_sessions SET step_up_until=? WHERE access_hash=? AND customer_id=?")
            .run(until, hash(access), customerId);
        const session = this.bank.db.prepare("SELECT device_id FROM auth_sessions WHERE access_hash=?")
            .get(hash(access)) as {
            device_id: string;
        };
        this.bank.log({ actor: customerId, kind: "step_up", customerId,
            route: `auth.step_up:${session.device_id}`, status: 200 });
        return { valid_until: until };
    }
    hasStepUp(access: string): boolean {
        const row = this.bank.db.prepare("SELECT step_up_until FROM auth_sessions WHERE access_hash=?")
            .get(hash(access)) as {
            step_up_until: string | null;
        } | undefined;
        return Boolean(this.customerForAccess(access) && row?.step_up_until &&
            Date.parse(row.step_up_until) > this.bank.realNow().getTime());
    }
    private deviceSession(access: string): {
        id: string;
        device_id: string;
        public_key: string | null;
    } {
        if (!this.customerForAccess(access))
            throw new BankError("DEF_UNAUTHORIZED");
        const session = this.bank.db.prepare(`SELECT s.id,s.device_id,d.public_key,d.revoked_at
      FROM auth_sessions s JOIN auth_devices d ON d.id=s.device_id
      WHERE s.access_hash=?`).get(hash(access)) as {
            id: string;
            device_id: string;
            public_key: string | null;
            revoked_at: string | null;
        } | undefined;
        if (!session || session.revoked_at)
            throw new BankError("DEF_UNAUTHORIZED");
        return session;
    }
    hasBoundDeviceKey(access: string): boolean {
        return this.deviceSession(access).public_key !== null;
    }
    private createDeviceChallenge(sessionId: string, deviceId: string, purpose: DeviceChallenge["purpose"], method: string | null, path: string | null, bodyHash: string | null): {
        challenge_id: string;
        message: string;
        expires_at: string;
    } {
        const now = this.bank.realNow();
        this.bank.db.prepare("DELETE FROM auth_device_challenges WHERE created_at<?")
            .run(new Date(now.getTime() - 7 * 86400000).toISOString());
        const active = this.bank.db.prepare(`SELECT COUNT(*) n FROM auth_device_challenges
      WHERE session_id=? AND used_at IS NULL AND expires_at>?`).get(sessionId, now.toISOString()) as {
            n: number;
        };
        if (active.n >= 20)
            throw new BankError("BIZ_DEVICE_CHALLENGE_LIMIT");
        const id = newId("device_challenge", now.getTime());
        const expires = new Date(now.getTime() + 2 * 60000).toISOString();
        this.bank.db.prepare(`INSERT INTO auth_device_challenges
      (id,session_id,device_id,purpose,method,path,body_hash,created_at,expires_at)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(id, sessionId, deviceId, purpose, method, path, bodyHash, now.toISOString(), expires);
        return { challenge_id: id,
            message: signedMessage(purpose, id, deviceId, method, path, bodyHash),
            expires_at: expires };
    }
    issueDeviceEnrollmentChallenge(access: string): {
        challenge_id: string;
        message: string;
        expires_at: string;
    } {
        return this.bank.transaction(() => {
            if (!this.hasStepUp(access))
                throw new BankError("DEF_STEP_UP_REQUIRED");
            const session = this.deviceSession(access);
            if (session.public_key)
                throw new BankError("BIZ_DEVICE_KEY_EXISTS");
            return this.createDeviceChallenge(session.id, session.device_id, "enroll", null, null, null);
        });
    }
    enrolCurrentDeviceKey(access: string, challengeId: string, publicKey: string, signature: string): {
        device_id: string;
        key_bound: true;
    } {
        return this.bank.transaction(() => {
            if (!this.hasStepUp(access))
                throw new BankError("DEF_STEP_UP_REQUIRED");
            const key = deviceKey(publicKey);
            const session = this.deviceSession(access);
            const challenge = this.bank.db.prepare(`SELECT id,session_id,device_id,purpose,method,
        path,body_hash,expires_at,used_at FROM auth_device_challenges WHERE id=?`)
                .get(challengeId) as DeviceChallenge | undefined;
            if (!challenge || challenge.session_id !== session.id ||
                challenge.device_id !== session.device_id || challenge.purpose !== "enroll" ||
                challenge.used_at || challenge.expires_at <= this.bank.realNow().toISOString())
                throw new BankError("DEF_DEVICE_PROOF_INVALID");
            this.verifySignature(key, signedMessage("enroll", challenge.id, session.device_id, null, null, null), signature);
            if (this.bank.db.prepare("SELECT 1 FROM auth_devices WHERE public_key=?").get(publicKey))
                throw new BankError("BIZ_DEVICE_KEY_EXISTS");
            const updated = this.bank.db.prepare(`UPDATE auth_devices SET public_key=?,bound_at=?
        WHERE id=? AND public_key IS NULL AND revoked_at IS NULL`)
                .run(publicKey, this.bank.now().toISOString(), session.device_id);
            if (updated.changes !== 1)
                throw new BankError("BIZ_DEVICE_KEY_EXISTS");
            this.bank.db.prepare("UPDATE auth_device_challenges SET used_at=? WHERE id=? AND used_at IS NULL")
                .run(this.bank.realNow().toISOString(), challenge.id);
            const customerId = this.customerForAccess(access)!;
            recordDeviceBinding(this.bank.db, customerId, session.device_id, this.bank.realNow().toISOString(), this.bank.now().toISOString());
            this.bank.log({ actor: customerId, kind: "device_key_bound",
                route: `auth.devices:${session.device_id}`, status: 200 });
            return { device_id: session.device_id, key_bound: true };
        });
    }
    deviceSecurityNotices(access: string, before?: number, limit?: number) {
        const session = this.deviceSession(access);
        if (!session.public_key)
            throw new BankError("DEF_DEVICE_PROOF_INVALID");
        const customerId = this.customerForAccess(access);
        if (!customerId)
            throw new BankError("DEF_UNAUTHORIZED");
        return listDeviceSecurityNotices(this.bank.db, customerId, session.device_id, before, limit);
    }
    issueDeviceOperationChallenge(access: string, method: string, path: string, body: unknown): {
        challenge_id: string;
        message: string;
        expires_at: string;
    } {
        const allowed = method === "POST" ?
            path === "/pix/transfers" || path === "/pix/med" || path === "/pix/scheduled" ||
                path === "/pix/keys" || path === "/pix/keys/claims" ||
                path === "/accounts" || path === "/accounts/payment" ||
                path === "/accounts/limits/recompute" ||
                path === "/auth/password" || path === "/devices" ||
                path === "/devices/current/pix-registration" ||
                /^\/auth\/devices\/[a-zA-Z0-9_-]+\/revoke$/.test(path) ||
                path === "/kyc/upgrade" || path === "/kyc/documents" ||
                path === "/data-sharing/consents" ||
                /^\/data-sharing\/consents\/[a-zA-Z0-9_-]+\/revoke$/.test(path) ||
                /^\/pix\/keys\/[a-zA-Z0-9_-]+\/deregister$/.test(path) ||
                /^\/pix\/keys\/claims\/[a-zA-Z0-9_-]+\/(?:verify|reissue|complete|close)$/.test(path) ||
                path === "/pix/limits/night" ||
                /^\/pix\/limits\/channels\/(?:app|scheduled)$/.test(path) ||
                /^\/pix\/automatic\/limits\/[a-zA-Z0-9_-]+$/.test(path) ||
                /^\/pix\/scheduled\/[a-zA-Z0-9_-]+\/(?:reauthorize|cancel)$/.test(path) ||
                path === "/pix/proximity/tokens" || path === "/pix/proximity/redeem" ||
                path === "/pix/automatic/mandates" ||
                path === "/pix/automatic/offers" ||
                /^\/pix\/automatic\/offers\/[a-zA-Z0-9_-]+\/revoke$/.test(path) ||
                /^\/pix\/automatic\/mandates\/[a-zA-Z0-9_-]+\/(?:revoke|charges|migrate)$/.test(path) ||
                /^\/pix\/automatic\/charges\/[a-zA-Z0-9_-]+\/(?:cancel|merchant-cancel|retry)$/.test(path) ||
                /^\/pix\/automatic\/charges\/[a-zA-Z0-9_-]+\/reauthorize$/.test(path) ||
                path === "/cards" || path === "/cards/3ds/challenges" || path === "/loans" ||
                path === "/loans/flash" ||
                /^\/loans\/[a-zA-Z0-9_-]+\/(?:prepay|refinance|renegotiate)$/.test(path) ||
                /^\/loans\/[a-zA-Z0-9_-]+\/installments\/[1-9][0-9]*\/(?:pay|partial-pay)$/.test(path) ||
                /^\/cards\/network\/[a-zA-Z0-9_-]+\/dispute$/.test(path) ||
                /^\/cards\/3ds\/challenges\/[a-zA-Z0-9_-]+\/complete$/.test(path) ||
                /^\/cards\/[a-zA-Z0-9_-]+\/wallet-tokens$/.test(path) ||
                /^\/cards\/wallet-tokens\/[a-zA-Z0-9_-]+\/revoke$/.test(path) ||
                /^\/cards\/[a-zA-Z0-9_-]+\/recurring$/.test(path) ||
                /^\/cards\/recurring\/[a-zA-Z0-9_-]+\/revoke$/.test(path) ||
                /^\/cards\/credit\/[a-zA-Z0-9_-]+\/statements\/[a-zA-Z0-9_-]+\/(?:pay|installment-plan)$/.test(path) ||
                /^\/cards\/[a-zA-Z0-9_-]+\/(?:virtual|temporary)$/.test(path) ||
                /^\/accounts\/(?:[a-zA-Z0-9_-]+\/(?:close|salary-port|salary-portability)|closed-credits\/[a-zA-Z0-9_-]+\/claim)$/.test(path)
            : method === "PATCH" ? path === "/customers/me" || /^\/cards\/[a-zA-Z0-9_-]+$/.test(path)
                : method === "GET" ? path === "/devices/current/security-notices" ||
                    /^\/cards\/[a-zA-Z0-9_-]+\/cvv$/.test(path)
                    : method === "DELETE" && /^\/devices\/[a-zA-Z0-9_-]+$/.test(path);
        if (!allowed)
            throw new BankError("BIZ_DEVICE_CHALLENGE_SCOPE");
        return this.bank.transaction(() => {
            const session = this.deviceSession(access);
            if (!session.public_key)
                throw new BankError("DEF_DEVICE_KEY_REQUIRED");
            return this.createDeviceChallenge(session.id, session.device_id, "operation", method, path, requestHash(body));
        });
    }
    verifyDeviceOperation(access: string, challengeId: string, signature: string, method: string, path: string, body: unknown): void {
        this.bank.transaction(() => {
            const session = this.deviceSession(access);
            if (!session.public_key)
                throw new BankError("DEF_DEVICE_KEY_REQUIRED");
            const challenge = this.bank.db.prepare(`SELECT id,session_id,device_id,purpose,method,
        path,body_hash,expires_at,used_at FROM auth_device_challenges WHERE id=?`)
                .get(challengeId) as DeviceChallenge | undefined;
            if (!challenge || challenge.session_id !== session.id ||
                challenge.device_id !== session.device_id || challenge.purpose !== "operation" ||
                challenge.used_at || challenge.expires_at <= this.bank.realNow().toISOString() ||
                challenge.method !== method || challenge.path !== path ||
                challenge.body_hash !== requestHash(body))
                throw new BankError("DEF_DEVICE_PROOF_INVALID");
            this.verifySignature(deviceKey(session.public_key!), signedMessage("operation", challenge.id, session.device_id, method, path, challenge.body_hash), signature);
            const updated = this.bank.db.prepare(`UPDATE auth_device_challenges SET used_at=?
        WHERE id=? AND used_at IS NULL`).run(this.bank.realNow().toISOString(), challenge.id);
            if (updated.changes !== 1)
                throw new BankError("DEF_DEVICE_PROOF_INVALID");
        });
    }
    private verifySignature(key: KeyObject, message: string, signature: string): void {
        if (!/^[A-Za-z0-9_-]{86}$/.test(signature))
            throw new BankError("DEF_DEVICE_PROOF_INVALID");
        const bytes = Buffer.from(signature, "base64url");
        if (bytes.length !== 64 || bytes.toString("base64url") !== signature ||
            !verify(null, Buffer.from(message), key, bytes))
            throw new BankError("DEF_DEVICE_PROOF_INVALID");
    }
    deviceForAccess(access: string): {
        id: string;
        first_seen_at: string;
        trusted_at: string | null;
        pix_registered_at: string | null;
    } | undefined {
        if (!this.customerForAccess(access))
            return undefined;
        return this.bank.db.prepare(`SELECT d.id,d.first_seen_at,d.trusted_at,d.pix_registered_at FROM auth_sessions s
      JOIN auth_devices d ON d.id=s.device_id WHERE s.access_hash=?`).get(hash(access)) as {
            id: string;
            first_seen_at: string;
            trusted_at: string | null;
            pix_registered_at: string | null;
        } | undefined;
    }
    registerCurrentDeviceForPix(access: string): {
        device_id: string;
        registered_at: string;
    } {
        const customerId = this.customerForAccess(access);
        if (!customerId)
            throw new BankError("DEF_UNAUTHORIZED");
        if (!this.hasStepUp(access))
            throw new BankError("DEF_STEP_UP_REQUIRED");
        const device = this.deviceForAccess(access);
        if (!device)
            throw new BankError("DEF_UNAUTHORIZED");
        if (!device.pix_registered_at) {
            this.bank.db.prepare("UPDATE auth_devices SET pix_registered_at=? WHERE id=? AND pix_registered_at IS NULL")
                .run(this.bank.now().toISOString(), device.id);
            this.bank.log({ actor: customerId, kind: "pix_device_registered", customerId,
                route: `auth.devices:${device.id}`, status: 200 });
        }
        const row = this.bank.db.prepare("SELECT pix_registered_at FROM auth_devices WHERE id=?")
            .get(device.id) as {
            pix_registered_at: string;
        };
        return { device_id: device.id, registered_at: row.pix_registered_at };
    }
    private revokeReusedRefresh(presentedHash: string): {
        customerId: string;
        sessionId: string;
    } | undefined {
        const used = this.bank.db.prepare(`SELECT s.id,s.customer_id,s.revoked_at FROM auth_refresh_used u
      JOIN auth_sessions s ON s.id=u.session_id WHERE u.refresh_hash=?`).get(presentedHash) as {
            id: string;
            customer_id: string;
            revoked_at: string | null;
        } | undefined;
        if (!used)
            return undefined;
        if (!used.revoked_at)
            this.bank.db.prepare("UPDATE auth_sessions SET revoked_at=? WHERE id=?")
                .run(this.bank.realNow().toISOString(), used.id);
        return { customerId: used.customer_id, sessionId: used.id };
    }
    private reportReusedRefresh(customerId: string, sessionId: string): never {
        this.bank.log({ actor: customerId, kind: "refresh_reuse_detected",
            customerId, route: `auth.refresh:${sessionId}`, status: 401 });
        throw new BankError("DEF_REFRESH_INVALID");
    }
    beginRefresh(refreshToken: string): {
        proof_required: false;
    } | {
        proof_required: true;
        challenge_id: string;
        message: string;
        expires_at: string;
    } {
        const outcome = this.bank.transaction(() => {
            const presentedHash = hash(refreshToken);
            const reused = this.revokeReusedRefresh(presentedHash);
            if (reused)
                return { kind: "reused" as const, ...reused };
            const now = this.bank.realNow();
            const row = this.bank.db.prepare(`SELECT s.id,s.device_id,s.refresh_exp,s.revoked_at,
        d.public_key,d.revoked_at device_revoked_at,c.status customer_status
        FROM auth_sessions s JOIN auth_devices d ON d.id=s.device_id
        JOIN customers c ON c.id=s.customer_id WHERE s.refresh_hash=?`)
                .get(presentedHash) as {
                id: string;
                device_id: string;
                refresh_exp: string;
                revoked_at: string | null;
                public_key: string | null;
                device_revoked_at: string | null;
                customer_status: string;
            } | undefined;
            if (!row || row.revoked_at || row.customer_status !== "active" ||
                Date.parse(row.refresh_exp) <= now.getTime() ||
                row.device_revoked_at)
                throw new BankError("DEF_REFRESH_INVALID");
            if (!row.public_key)
                return { kind: "ready" as const,
                    value: { proof_required: false as const } };
            this.bank.db.prepare("DELETE FROM auth_refresh_challenges WHERE created_at<?")
                .run(new Date(now.getTime() - 7 * 86400000).toISOString());
            const active = this.bank.db.prepare(`SELECT COUNT(*) n FROM auth_refresh_challenges
        WHERE session_id=? AND used_at IS NULL AND expires_at>?`)
                .get(row.id, now.toISOString()) as {
                n: number;
            };
            if (active.n >= 20)
                throw new BankError("BIZ_DEVICE_CHALLENGE_LIMIT");
            const id = newId("refresh_challenge", now.getTime());
            const expires = new Date(now.getTime() + 2 * 60000).toISOString();
            this.bank.db.prepare(`INSERT INTO auth_refresh_challenges
        (id,session_id,refresh_hash,created_at,expires_at) VALUES (?,?,?,?,?)`)
                .run(id, row.id, presentedHash, now.toISOString(), expires);
            return { kind: "ready" as const, value: { proof_required: true as const, challenge_id: id,
                    message: `BancoVivo:device:refresh:v1:${id}:${row.device_id}:${presentedHash}`,
                    expires_at: expires } };
        });
        if (outcome.kind === "reused")
            this.reportReusedRefresh(outcome.customerId, outcome.sessionId);
        return outcome.value;
    }
    refresh(refreshToken: string, proof?: {
        challengeId: string;
        signature: string;
    }): {
        access_token: string;
        refresh_token: string;
        expires_at: string;
    } {
        const presentedHash = hash(refreshToken);
        const outcome = this.bank.transaction(() => {
            const reused = this.revokeReusedRefresh(presentedHash);
            if (reused)
                return { kind: "reused" as const, ...reused };
            const row = this.bank.db.prepare(`SELECT s.id,s.customer_id,s.device_id,s.refresh_exp,s.revoked_at,
        d.public_key,d.revoked_at device_revoked_at,c.status customer_status
        FROM auth_sessions s JOIN auth_devices d ON d.id=s.device_id
        JOIN customers c ON c.id=s.customer_id WHERE s.refresh_hash=?`)
                .get(presentedHash) as {
                id: string;
                customer_id: string;
                device_id: string;
                public_key: string | null;
                refresh_exp: string;
                revoked_at: string | null;
                device_revoked_at: string | null;
                customer_status: string;
            } | undefined;
            if (!row)
                throw new BankError("DEF_REFRESH_INVALID");
            if (row.device_revoked_at)
                throw new BankError("DEF_DEVICE_REVOKED");
            if (row.revoked_at || row.customer_status !== "active" ||
                Date.parse(row.refresh_exp) <= this.bank.realNow().getTime())
                throw new BankError("DEF_REFRESH_INVALID");
            if (row.public_key) {
                if (!proof)
                    throw new BankError("DEF_DEVICE_PROOF_INVALID");
                const challenge = this.bank.db.prepare(`SELECT session_id,refresh_hash,expires_at,used_at
          FROM auth_refresh_challenges WHERE id=?`).get(proof.challengeId) as {
                    session_id: string;
                    refresh_hash: string;
                    expires_at: string;
                    used_at: string | null;
                } | undefined;
                if (!challenge || challenge.session_id !== row.id ||
                    challenge.refresh_hash !== presentedHash || challenge.used_at ||
                    challenge.expires_at <= this.bank.realNow().toISOString())
                    throw new BankError("DEF_DEVICE_PROOF_INVALID");
                this.verifySignature(deviceKey(row.public_key), `BancoVivo:device:refresh:v1:${proof.challengeId}:${row.device_id}:${presentedHash}`, proof.signature);
                const consumed = this.bank.db.prepare(`UPDATE auth_refresh_challenges SET used_at=?
          WHERE id=? AND used_at IS NULL`).run(this.bank.realNow().toISOString(), proof.challengeId);
                if (consumed.changes !== 1)
                    throw new BankError("DEF_DEVICE_PROOF_INVALID");
            }
            const access = token();
            const refresh = token();
            const accessExp = new Date(this.bank.realNow().getTime() + 15 * 60000).toISOString();
            this.bank.db.prepare("INSERT INTO auth_refresh_used VALUES (?,?,?)")
                .run(presentedHash, row.id, this.bank.realNow().toISOString());
            this.bank.db.prepare("UPDATE auth_sessions SET access_hash=?,access_exp=?,refresh_hash=? WHERE id=?")
                .run(hash(access), accessExp, hash(refresh), row.id);
            return { kind: "rotated" as const, access_token: access,
                refresh_token: refresh, expires_at: accessExp };
        });
        if (outcome.kind === "reused")
            this.reportReusedRefresh(outcome.customerId, outcome.sessionId);
        return { access_token: outcome.access_token, refresh_token: outcome.refresh_token,
            expires_at: outcome.expires_at };
    }
    revokeDevice(customerId: string, deviceId: string): void {
        const device = (this.bank.db.prepare("SELECT id FROM auth_devices WHERE customer_id=? AND id=?")
            .get(customerId, deviceId) ?? this.bank.db.prepare("SELECT id FROM auth_devices WHERE customer_id=? AND fingerprint=?")
            .get(customerId, deviceId)) as {
            id: string;
        } | undefined;
        if (!device)
            throw new BankError("DEF_NOT_FOUND");
        this.bank.transaction(() => {
            const at = this.bank.now().toISOString();
            this.bank.db.prepare(`UPDATE auth_devices SET revoked_at=COALESCE(revoked_at,?)
        WHERE id=? AND customer_id=?`).run(at, device.id, customerId);
            this.bank.db.prepare(`UPDATE auth_sessions SET revoked_at=?
        WHERE device_id=? AND customer_id=? AND revoked_at IS NULL`)
                .run(at, device.id, customerId);
        });
    }
    listDevices(customerId: string): {
        id: string;
        first_seen_at: string;
        trusted_at: string | null;
        revoked_at: string | null;
        pix_registered_at: string | null;
    }[] {
        this.bank.customer(customerId);
        return this.bank.db.prepare(`SELECT id,first_seen_at,trusted_at,revoked_at,pix_registered_at FROM auth_devices
      WHERE customer_id=? ORDER BY first_seen_at,id`).all(customerId) as {
            id: string;
            first_seen_at: string;
            trusted_at: string | null;
            revoked_at: string | null;
            pix_registered_at: string | null;
        }[];
    }
    enrolDevice(customerId: string, fingerprint: string, ip: string): string {
        this.bank.customer(customerId);
        if (!/^[a-zA-Z0-9._:-]{3,128}$/.test(fingerprint))
            throw new BankError("BIZ_INVALID_DEVICE");
        const id = newId("dev", this.bank.now().getTime());
        try {
            this.bank.db.prepare(`INSERT INTO auth_devices
      (id,customer_id,fingerprint,first_seen_at,first_seen_ip,trusted_at,revoked_at)
      VALUES (?,?,?,?,?,NULL,NULL)`).run(id, customerId, fingerprint, this.bank.now().toISOString(), ip);
        }
        catch {
            throw new BankError("BIZ_DEVICE_EXISTS");
        }
        return id;
    }
    revokeAccess(customerId: string, access: string): void {
        this.bank.db.prepare("UPDATE auth_sessions SET revoked_at=? WHERE customer_id=? AND access_hash=?")
            .run(this.bank.now().toISOString(), customerId, hash(access));
    }
}
