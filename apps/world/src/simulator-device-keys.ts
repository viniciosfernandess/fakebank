import { createPrivateKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { chmodSync, closeSync, mkdirSync, openSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

interface StoredKey { public_key: string; private_key: string; }

export class SimulatorDeviceKeys {
  readonly db: DatabaseSync;

  constructor(path = ":memory:") {
    if (path !== ":memory:") {
      mkdirSync(dirname(path), { recursive: true });
      closeSync(openSync(path, "a", 0o600));
      chmodSync(path, 0o600);
    }
    this.db = new DatabaseSync(path);
    this.db.exec(`CREATE TABLE IF NOT EXISTS device_keys (
      customer_id TEXT PRIMARY KEY,
      public_key TEXT NOT NULL UNIQUE,
      private_key TEXT NOT NULL
    )`);
  }

  forCustomer(customerId: string): { publicKey: string; privateKey: KeyObject } {
    let row = this.db.prepare("SELECT public_key,private_key FROM device_keys WHERE customer_id=?")
      .get(customerId) as StoredKey | undefined;
    if (!row) {
      const pair = generateKeyPairSync("ed25519");
      row = {
        public_key: pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
        private_key: pair.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url"),
      };
      this.db.prepare("INSERT INTO device_keys VALUES (?,?,?)")
        .run(customerId, row.public_key, row.private_key);
    }
    return { publicKey: row.public_key,
      privateKey: createPrivateKey({ key: Buffer.from(row.private_key, "base64url"),
        format: "der", type: "pkcs8" }) };
  }

  close(): void { this.db.close(); }
}
