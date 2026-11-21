import type { DatabaseSync } from "node:sqlite";
import { BankError } from "./bank.ts";

export function installDeviceSecurityNotices(db: DatabaseSync): void {
  const columns = db.prepare("PRAGMA table_info(device_security_notices)").all() as
    { name: string; pk: number }[];
  if (columns.some((column) => column.name === "id" && column.pk === 1)) {
    db.exec("BEGIN IMMEDIATE");
    try { db.exec(`ALTER TABLE device_security_notices RENAME TO device_security_notices_legacy;
      CREATE TABLE device_security_notices (
        id INTEGER NOT NULL, customer_id TEXT NOT NULL REFERENCES customers(id),
        recipient_device_id TEXT NOT NULL REFERENCES auth_devices(id),
        new_device_id TEXT NOT NULL REFERENCES auth_devices(id),
        created_at TEXT NOT NULL, twin_at TEXT NOT NULL,
        PRIMARY KEY(recipient_device_id,id), UNIQUE(recipient_device_id,new_device_id)
      );
      INSERT INTO device_security_notices
        SELECT row_number() OVER (PARTITION BY recipient_device_id ORDER BY id),
          customer_id,recipient_device_id,new_device_id,created_at,twin_at
        FROM device_security_notices_legacy;
      DROP TABLE device_security_notices_legacy;
      COMMIT;`); }
    catch (error) { db.exec("ROLLBACK"); throw error; }
  }
  db.exec(`CREATE TABLE IF NOT EXISTS device_security_notices (
    id INTEGER NOT NULL, customer_id TEXT NOT NULL REFERENCES customers(id),
    recipient_device_id TEXT NOT NULL REFERENCES auth_devices(id),
    new_device_id TEXT NOT NULL REFERENCES auth_devices(id),
    created_at TEXT NOT NULL, twin_at TEXT NOT NULL,
    PRIMARY KEY(recipient_device_id,id), UNIQUE(recipient_device_id,new_device_id)
  );
  CREATE INDEX IF NOT EXISTS device_security_notices_recipient
    ON device_security_notices(customer_id,recipient_device_id,id);
  CREATE TRIGGER IF NOT EXISTS device_security_notices_no_replace BEFORE INSERT ON device_security_notices
    WHEN EXISTS (SELECT 1 FROM device_security_notices WHERE recipient_device_id=NEW.recipient_device_id AND
      (id=NEW.id OR new_device_id=NEW.new_device_id))
    BEGIN SELECT RAISE(ABORT,'DEVICE_NOTICE_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS device_security_notices_no_update BEFORE UPDATE ON device_security_notices
    BEGIN SELECT RAISE(ABORT,'DEVICE_NOTICE_IMMUTABLE'); END;
  CREATE TRIGGER IF NOT EXISTS device_security_notices_no_delete BEFORE DELETE ON device_security_notices
    BEGIN SELECT RAISE(ABORT,'DEVICE_NOTICE_IMMUTABLE'); END;`);
}

export function recordDeviceBinding(db: DatabaseSync, customerId: string, deviceId: string,
  realAt: string, twinAt: string): void {
  db.prepare(`INSERT INTO device_security_notices
    (id,customer_id,recipient_device_id,new_device_id,created_at,twin_at)
    SELECT (SELECT COALESCE(MAX(n.id),0)+1 FROM device_security_notices n
      WHERE n.recipient_device_id=d.id), d.customer_id,d.id,?,?,? FROM auth_devices d WHERE d.customer_id=? AND d.id<>?
      AND d.public_key IS NOT NULL AND d.revoked_at IS NULL`)
    .run(deviceId, realAt, twinAt, customerId, deviceId);
}

export function listDeviceSecurityNotices(db: DatabaseSync, customerId: string, deviceId: string,
  before?: number, limit = 20): { items: { id: number; new_device_id: string; twin_at: string }[];
    next_cursor: number | null } {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
    (before !== undefined && (!Number.isSafeInteger(before) || before < 1)))
    throw new BankError("BIZ_NOTICE_CURSOR_INVALID");
  if (before !== undefined && !db.prepare(`SELECT 1 FROM device_security_notices
    WHERE id=? AND customer_id=? AND recipient_device_id=?`).get(before, customerId, deviceId))
    throw new BankError("DEF_NOT_FOUND");
  const rows = db.prepare(`SELECT id,new_device_id,twin_at FROM device_security_notices
    WHERE customer_id=? AND recipient_device_id=? AND (? IS NULL OR id<?)
    ORDER BY id DESC LIMIT ?`).all(customerId, deviceId, before ?? null, before ?? null, limit + 1) as
    { id: number; new_device_id: string; twin_at: string }[];
  const items = rows.slice(0, limit);
  return { items, next_cursor: rows.length > limit ? items.at(-1)!.id : null };
}
