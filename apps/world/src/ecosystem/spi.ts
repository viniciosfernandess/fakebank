import type { DatabaseSync } from "node:sqlite";
import { JACARANDA_ISPB } from "../pix-id.ts";
import type { TelemetryStore } from "../telemetry.ts";

export const PSP_PARTICIPANTS = [
  { ispb: JACARANDA_ISPB, name: "Banco Jacarandá" },
  { ispb: "87654321", name: "Banco Ipê" },
  { ispb: "11223344", name: "Banco Aroeira" },
] as const;
export const CASHOUT_ISPB = "99999999";

export interface SpiMessage {
  type: "pacs.008" | "pacs.002" | "pacs.004";
  end_to_end_id: string;
  from_ispb: string;
  to_ispb: string;
  amount_cents: number;
  sender_account?: string;
  recipient_account?: string;
  root_transfer_id?: string;
  deadline_at_real?: string;
  status?: "ACSC" | "RJCT";
  reason?: string;
  return_id?: string;
}

export class SpiNetwork {
  private readonly db: DatabaseSync;
  private readonly now: () => Date;
  private readonly telemetry: TelemetryStore | undefined;
  private readonly realNow: () => Date;
  constructor(db: DatabaseSync, now: () => Date, telemetry?: TelemetryStore,
    realNow: () => Date = () => new Date()) {
    this.db = db;
    this.now = now;
    this.telemetry = telemetry;
    this.realNow = realNow;
    db.exec(`CREATE TABLE IF NOT EXISTS spi_participants (
      ispb TEXT PRIMARY KEY, name TEXT NOT NULL, pi_balance_cents INTEGER NOT NULL DEFAULT 0
        CHECK(pi_balance_cents >= 0)
    );
    CREATE TABLE IF NOT EXISTS spi_messages (
      id INTEGER PRIMARY KEY, end_to_end_id TEXT NOT NULL, message_type TEXT NOT NULL,
      payload_json TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS spi_runtime_state (
      id INTEGER PRIMARY KEY CHECK(id=1), available INTEGER NOT NULL
        CHECK(available IN (0,1)), changed_at TEXT NOT NULL, changed_by TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS spi_runtime_history (
      id INTEGER PRIMARY KEY, available INTEGER NOT NULL CHECK(available IN (0,1)),
      changed_at TEXT NOT NULL, changed_by TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS spi_message_e2e ON spi_messages(end_to_end_id,id);
    CREATE UNIQUE INDEX IF NOT EXISTS spi_payment_message_unique
      ON spi_messages(end_to_end_id,message_type)
      WHERE message_type IN ('pacs.008','pacs.002');
    CREATE TABLE IF NOT EXISTS psp_accounts (
      id TEXT PRIMARY KEY, ispb TEXT NOT NULL REFERENCES spi_participants(ispb),
      holder_name TEXT NOT NULL, pix_key TEXT NOT NULL UNIQUE,
      balance_cents INTEGER NOT NULL DEFAULT 0 CHECK(balance_cents >= 0),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','frozen')),
      fraud_flag INTEGER NOT NULL DEFAULT 0 CHECK(fraud_flag IN (0,1))
    );`);
    this.messageTransaction(() => {
      // Acquire the SQLite write lock before checking or migrating legacy history,
      // including when this constructor runs inside an existing transaction.
      db.exec("UPDATE spi_runtime_state SET available=available WHERE id=0");
      const installed = db.prepare(`SELECT 1 FROM sqlite_master WHERE type='index'
        AND name='spi_return_id_unique'`).get();
      if (!installed) {
        const rows = db.prepare(`SELECT end_to_end_id,payload_json FROM spi_messages
          WHERE message_type='pacs.004' ORDER BY id`).iterate() as
          Iterable<{ end_to_end_id: string; payload_json: string }>;
        const ids = new Set<string>();
        for (const row of rows) {
          let message: unknown;
          try { message = JSON.parse(row.payload_json); }
          catch { throw new Error("SPI_RETURN_HISTORY_INVALID"); }
          if (!message || typeof message !== "object" || Array.isArray(message))
            throw new Error("SPI_RETURN_HISTORY_INVALID");
          const payload = message as Partial<SpiMessage>;
          if (payload.type !== "pacs.004" || payload.end_to_end_id !== row.end_to_end_id ||
            typeof payload.return_id !== "string" || !payload.return_id ||
            typeof payload.from_ispb !== "string" || typeof payload.to_ispb !== "string" ||
            typeof payload.reason !== "string" || !Number.isSafeInteger(payload.amount_cents) ||
            payload.amount_cents! <= 0 || ids.has(payload.return_id))
            throw new Error("SPI_RETURN_HISTORY_INVALID");
          ids.add(payload.return_id);
        }
        db.exec(`CREATE UNIQUE INDEX spi_return_id_unique
          ON spi_messages(json_extract(payload_json,'$.return_id')) WHERE message_type='pacs.004'`);
      }
      db.exec(`CREATE TRIGGER IF NOT EXISTS spi_return_id_required BEFORE INSERT ON spi_messages
        WHEN NEW.message_type='pacs.004' AND CASE WHEN json_valid(NEW.payload_json)
          THEN COALESCE(json_type(NEW.payload_json,'$.return_id'),'')<>'text' OR
            length(json_extract(NEW.payload_json,'$.return_id'))=0 ELSE 1 END
        BEGIN SELECT RAISE(ABORT,'SPI_RETURN_ID_INVALID'); END;
      CREATE TRIGGER IF NOT EXISTS spi_return_no_replace BEFORE INSERT ON spi_messages
        WHEN EXISTS (SELECT 1 FROM spi_messages WHERE id=NEW.id AND message_type='pacs.004') OR
          (NEW.message_type='pacs.004' AND json_valid(NEW.payload_json) AND EXISTS (
          SELECT 1 FROM spi_messages WHERE message_type='pacs.004' AND
          json_extract(payload_json,'$.return_id')=json_extract(NEW.payload_json,'$.return_id')))
        BEGIN SELECT RAISE(ABORT,'SPI_RETURN_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS spi_return_no_update BEFORE UPDATE ON spi_messages
        WHEN OLD.message_type='pacs.004' OR NEW.message_type='pacs.004'
        BEGIN SELECT RAISE(ABORT,'SPI_RETURN_IMMUTABLE'); END;
      CREATE TRIGGER IF NOT EXISTS spi_return_no_delete BEFORE DELETE ON spi_messages
        WHEN OLD.message_type='pacs.004' BEGIN SELECT RAISE(ABORT,'SPI_RETURN_IMMUTABLE'); END;`);
    });
    const accountColumns = db.prepare("PRAGMA table_info(psp_accounts)").all() as { name: string }[];
    if (!accountColumns.some((column) => column.name === "fraud_flag"))
      db.exec("ALTER TABLE psp_accounts ADD COLUMN fraud_flag INTEGER NOT NULL DEFAULT 0");
    const insert = db.prepare("INSERT OR IGNORE INTO spi_participants (ispb,name) VALUES (?,?)");
    for (const participant of PSP_PARTICIPANTS) insert.run(participant.ispb, participant.name);
    insert.run(CASHOUT_ISPB, "External cash-out clearing");
    db.prepare(`INSERT OR IGNORE INTO spi_runtime_state
      (id,available,changed_at,changed_by) VALUES (1,1,?,'bootstrap')`)
      .run(now().toISOString());
  }

  heartbeat(): void {
    if (!this.telemetry) throw new Error("SPI_TELEMETRY_UNAVAILABLE");
    this.availability();
    this.telemetry.emit({ source: "spi", category: "health", action: "heartbeat",
      outcome: "success", message: "SPI telemetry heartbeat" });
  }

  availability(): { available: boolean; changed_at: string; changed_by: string } {
    const row = this.db.prepare(`SELECT available,changed_at,changed_by
      FROM spi_runtime_state WHERE id=1`).get() as
      { available: number; changed_at: string; changed_by: string };
    return { ...row, available: Boolean(row.available) };
  }

  setAvailability(available: boolean, actor: string): ReturnType<SpiNetwork["availability"]> {
    if (typeof available !== "boolean" || typeof actor !== "string" || !actor.trim())
      throw new Error("SPI_CONTROL_INVALID");
    const current = this.availability();
    if (current.available === available) return current;
    const changedAt = this.now().toISOString();
    this.db.exec("SAVEPOINT spi_availability");
    try {
      this.db.prepare(`UPDATE spi_runtime_state SET available=?,changed_at=?,changed_by=?
        WHERE id=1`).run(Number(available), changedAt, actor);
      this.db.prepare(`INSERT INTO spi_runtime_history
        (available,changed_at,changed_by) VALUES (?,?,?)`)
        .run(Number(available), changedAt, actor);
      this.db.exec("RELEASE spi_availability");
    } catch (error) {
      this.db.exec("ROLLBACK TO spi_availability");
      this.db.exec("RELEASE spi_availability");
      throw error;
    }
    return this.availability();
  }

  balance(ispb: string): number {
    const row = this.db.prepare("SELECT pi_balance_cents FROM spi_participants WHERE ispb=?")
      .get(ispb) as { pi_balance_cents: number } | undefined;
    if (!row) throw new Error("SPI_PARTICIPANT_UNKNOWN");
    return row.pi_balance_cents;
  }

  fund(ispb: string, amount: number): void {
    if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error("SPI_AMOUNT_INVALID");
    const result = this.db.prepare("UPDATE spi_participants SET pi_balance_cents=pi_balance_cents+? WHERE ispb=?")
      .run(amount, ispb);
    if (result.changes !== 1) throw new Error("SPI_PARTICIPANT_UNKNOWN");
  }

  account(accountId: string): { id: string; ispb: string; holder_name: string; balance_cents: number; status: string; fraud_flag: number } | undefined {
    return this.db.prepare("SELECT id,ispb,holder_name,balance_cents,status,fraud_flag FROM psp_accounts WHERE id=?")
      .get(accountId) as ReturnType<SpiNetwork["account"]>;
  }

  lookup(key: string): { id: string; ispb: string; holder_name: string; balance_cents: number; status: string; fraud_flag: number } | undefined {
    return this.db.prepare("SELECT id,ispb,holder_name,balance_cents,status,fraud_flag FROM psp_accounts WHERE pix_key=?")
      .get(key) as ReturnType<SpiNetwork["account"]>;
  }

  #record(message: SpiMessage): void {
    this.db.prepare("INSERT INTO spi_messages (end_to_end_id,message_type,payload_json,created_at) VALUES (?,?,?,?)")
      .run(message.end_to_end_id, message.type, JSON.stringify(message), this.now().toISOString());
  }

  private messageTransaction<T>(work: () => T): T {
    this.db.exec("SAVEPOINT spi_message");
    try {
      const result = work();
      this.db.exec("RELEASE spi_message");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK TO spi_message");
      this.db.exec("RELEASE spi_message");
      throw error;
    }
  }

  settle(endToEndId: string, fromIspb: string, toIspb: string, amount: number,
    senderAccount?: string, rootTransferId?: string, deadlineAtReal?: string,
    recipientAccount?: string): boolean {
    if (!/^E\d{8}\d{12}[A-Z0-9]{11}$/.test(endToEndId) ||
      !Number.isSafeInteger(amount) || amount <= 0 || fromIspb === toIspb ||
      (senderAccount !== undefined && !/^[A-Za-z0-9_-]{1,128}$/.test(senderAccount)) ||
      (rootTransferId !== undefined && (senderAccount === undefined ||
        !/^[A-Za-z0-9_-]{1,128}$/.test(rootTransferId))) ||
      (recipientAccount !== undefined &&
        !/^[A-Za-z0-9_-]{1,128}$/.test(recipientAccount)) ||
      (deadlineAtReal !== undefined && (!Number.isFinite(Date.parse(deadlineAtReal)) ||
        new Date(deadlineAtReal).toISOString() !== deadlineAtReal)))
      throw new Error("SPI_MESSAGE_INVALID");
    return this.messageTransaction(() => {
      const prior = this.db.prepare(`SELECT 1 FROM spi_messages WHERE end_to_end_id=?
        AND message_type='pacs.002' LIMIT 1`).get(endToEndId);
      if (prior) throw new Error("SPI_DUPLICATE_SETTLEMENT");
      if (!this.availability().available) throw new Error("SPI_UNAVAILABLE");
      this.#record({ type: "pacs.008", end_to_end_id: endToEndId, from_ispb: fromIspb,
        to_ispb: toIspb, amount_cents: amount,
        ...(senderAccount ? { sender_account: senderAccount } : {}),
        ...(rootTransferId ? { root_transfer_id: rootTransferId } : {}),
        ...(recipientAccount ? { recipient_account: recipientAccount } : {}),
        ...(deadlineAtReal ? { deadline_at_real: deadlineAtReal } : {}) });
      if (deadlineAtReal && this.realNow().getTime() >= Date.parse(deadlineAtReal)) {
        this.#record({ type: "pacs.002", end_to_end_id: endToEndId, from_ispb: fromIspb,
          to_ispb: toIspb, amount_cents: amount, status: "RJCT", reason: "AB03" });
        return false;
      }
      if (recipientAccount) {
        const recipient = this.account(recipientAccount);
        const invalid = !recipient || recipient.ispb !== toIspb ||
          recipient.status !== "active";
        if (invalid || recipient.fraud_flag) {
          this.#record({ type: "pacs.002", end_to_end_id: endToEndId,
            from_ispb: fromIspb, to_ispb: toIspb, amount_cents: amount,
            status: "RJCT", reason: invalid ? "RCVR_ACCOUNT_INVALID" :
              "RCVR_FRAUD_FLAG" });
          return false;
        }
      }
      const debit = this.db.prepare(`UPDATE spi_participants SET pi_balance_cents=pi_balance_cents-?
        WHERE ispb=? AND pi_balance_cents>=?`).run(amount, fromIspb, amount);
      if (debit.changes !== 1) {
        this.#record({ type: "pacs.002", end_to_end_id: endToEndId, from_ispb: fromIspb,
          to_ispb: toIspb, amount_cents: amount, status: "RJCT", reason: "AM04" });
        return false;
      }
      const credit = this.db.prepare("UPDATE spi_participants SET pi_balance_cents=pi_balance_cents+? WHERE ispb=?")
        .run(amount, toIspb);
      if (credit.changes !== 1) throw new Error("SPI_PARTICIPANT_UNKNOWN");
      this.#record({ type: "pacs.002", end_to_end_id: endToEndId, from_ispb: fromIspb,
        to_ispb: toIspb, amount_cents: amount, status: "ACSC" });
      return true;
    });
  }

  submitPayment(endToEndId: string, fromIspb: string, toIspb: string,
    amount: number, senderAccount?: string, rootTransferId?: string,
    deadlineAtReal?: string, recipientAccount?: string): SpiMessage &
      { type: "pacs.002"; status: "ACSC" | "RJCT" } {
    return this.messageTransaction(() => {
      // Serialise the receipt lookup with writes from another connection.
      this.db.exec("UPDATE spi_runtime_state SET available=available WHERE id=0");
      const messages = this.messages(endToEndId);
      const request = messages.find((message) => message.type === "pacs.008");
      const response = messages.find((message) => message.type === "pacs.002");
      if (request || response) {
        if (!request || !response || request.from_ispb !== fromIspb ||
          request.to_ispb !== toIspb || request.amount_cents !== amount ||
          (request.sender_account !== undefined && request.sender_account !== senderAccount) ||
          (request.root_transfer_id !== undefined && request.root_transfer_id !== rootTransferId) ||
          (request.recipient_account !== undefined &&
            request.recipient_account !== recipientAccount) ||
          request.deadline_at_real !== deadlineAtReal ||
          response.from_ispb !== fromIspb || response.to_ispb !== toIspb ||
          response.amount_cents !== amount ||
          (response.status !== "ACSC" && response.status !== "RJCT"))
          throw new Error("SPI_PAYMENT_IDEMPOTENCY_CONFLICT");
        return response as SpiMessage & { type: "pacs.002"; status: "ACSC" | "RJCT" };
      }
      this.settle(endToEndId, fromIspb, toIspb, amount, senderAccount,
        rootTransferId, deadlineAtReal, recipientAccount);
      const recorded = this.messages(endToEndId).find((message) => message.type === "pacs.002");
      if (!recorded || (recorded.status !== "ACSC" && recorded.status !== "RJCT"))
        throw new Error("SPI_PAYMENT_RESPONSE_MISSING");
      return recorded as SpiMessage & { type: "pacs.002"; status: "ACSC" | "RJCT" };
    });
  }

  returnPayment(endToEndId: string, returnId: string, fromIspb: string,
    toIspb: string, amount: number, reason: string): void {
    if (!/^E\d{8}\d{12}[A-Z0-9]{11}$/.test(endToEndId) || !returnId ||
      !Number.isSafeInteger(amount) || amount <= 0 || fromIspb === toIspb)
      throw new Error("SPI_MESSAGE_INVALID");
    this.messageTransaction(() => {
      const prior = this.db.prepare(`SELECT payload_json FROM spi_messages
        WHERE message_type='pacs.004' AND json_extract(payload_json,'$.return_id')=?`)
        .get(returnId) as { payload_json: string } | undefined;
      if (prior) {
        const message = JSON.parse(prior.payload_json) as SpiMessage;
        if (message.type !== "pacs.004" || message.end_to_end_id !== endToEndId ||
          message.from_ispb !== fromIspb || message.to_ispb !== toIspb ||
          message.amount_cents !== amount || message.reason !== reason)
          throw new Error("SPI_RETURN_IDEMPOTENCY_CONFLICT");
        return;
      }
      if (!this.availability().available) throw new Error("SPI_UNAVAILABLE");
      const debit = this.db.prepare(`UPDATE spi_participants SET pi_balance_cents=pi_balance_cents-?
        WHERE ispb=? AND pi_balance_cents>=?`).run(amount, fromIspb, amount);
      if (debit.changes !== 1) throw new Error("SPI_INSUFFICIENT_LIQUIDITY");
      const credit = this.db.prepare("UPDATE spi_participants SET pi_balance_cents=pi_balance_cents+? WHERE ispb=?")
        .run(amount, toIspb);
      if (credit.changes !== 1) throw new Error("SPI_PARTICIPANT_UNKNOWN");
      this.#record({ type: "pacs.004", end_to_end_id: endToEndId, return_id: returnId,
        from_ispb: fromIspb, to_ispb: toIspb, amount_cents: amount, reason });
    });
  }

  messages(endToEndId: string): SpiMessage[] {
    const rows = this.db.prepare("SELECT payload_json FROM spi_messages WHERE end_to_end_id=? ORDER BY id")
      .all(endToEndId) as { payload_json: string }[];
    return rows.map((row) => JSON.parse(row.payload_json) as SpiMessage);
  }
}
