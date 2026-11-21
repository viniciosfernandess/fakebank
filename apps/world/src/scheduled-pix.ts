import { newId } from "./id.ts";
import { Bank, BankError, brtHour, type PixResult, type PixTransferInput } from "./bank.ts";
import { FeatureRegistry } from "./features.ts";
export type Frequency = "once" | "weekly" | "monthly";
export interface ScheduledPixJob {
    id: string;
    customer_id: string;
    from_account: string;
    to_account: string;
    amount_cents: number;
    frequency: Frequency;
    next_run_at: string;
    status: "active" | "reauthorization_required" | "cancelled" | "completed";
    scheduled_night_mode: number;
    initiating_device_id: string | null;
    authorization_expires_at: string | null;
}
function nextMonth(date: Date): Date {
    const year = date.getUTCFullYear();
    const month = date.getUTCMonth();
    const day = date.getUTCDate();
    const last = new Date(Date.UTC(year, month + 2, 0)).getUTCDate();
    const next = new Date(date);
    next.setUTCDate(1);
    next.setUTCMonth(month + 1);
    next.setUTCDate(Math.min(day, last));
    return next;
}
export class ScheduledPix {
    readonly bank: Bank;
    readonly features: FeatureRegistry;
    private readonly transferInternal: ((input: PixTransferInput) => PixResult) | undefined;
    constructor(bank: Bank, features: FeatureRegistry, transferInternal?: (input: PixTransferInput) => PixResult) {
        this.bank = bank;
        this.features = features;
        this.transferInternal = transferInternal;
        bank.db.exec(`CREATE TABLE IF NOT EXISTS scheduled_pix (
      id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
      from_account TEXT NOT NULL REFERENCES accounts(id), to_account TEXT NOT NULL REFERENCES accounts(id),
      amount_cents INTEGER NOT NULL, frequency TEXT NOT NULL, next_run_at TEXT NOT NULL,
      status TEXT NOT NULL, scheduled_night_mode INTEGER NOT NULL, created_at TEXT NOT NULL,
      initiating_device_id TEXT, authorization_expires_at TEXT
    );
    CREATE INDEX IF NOT EXISTS scheduled_pix_due ON scheduled_pix(status,next_run_at);
    CREATE TABLE IF NOT EXISTS scheduled_pix_executions (
      id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES scheduled_pix(id),
      due_at TEXT NOT NULL, transfer_id TEXT, hold_id TEXT,
      status TEXT NOT NULL, error_code TEXT,
      executed_at TEXT NOT NULL, UNIQUE(job_id,due_at)
    );`);
        if (!(bank.db.prepare("PRAGMA table_info(scheduled_pix_executions)").all() as {
            name: string;
        }[])
            .some((column) => column.name === "hold_id"))
            bank.db.exec("ALTER TABLE scheduled_pix_executions ADD COLUMN hold_id TEXT");
        if (!(bank.db.prepare("PRAGMA table_info(scheduled_pix)").all() as {
            name: string;
        }[])
            .some((column) => column.name === "initiating_device_id"))
            bank.db.exec("ALTER TABLE scheduled_pix ADD COLUMN initiating_device_id TEXT");
        if (!(bank.db.prepare("PRAGMA table_info(scheduled_pix)").all() as {
            name: string;
        }[])
            .some((column) => column.name === "authorization_expires_at"))
            bank.db.exec("ALTER TABLE scheduled_pix ADD COLUMN authorization_expires_at TEXT");
    }
    private verifyDevice(customerId: string, deviceId: string): void {
        const device = this.bank.db.prepare(`SELECT customer_id,revoked_at FROM auth_devices WHERE id=?`)
            .get(deviceId) as {
            customer_id: string;
            revoked_at: string | null;
        } | undefined;
        if (!device || device.customer_id !== customerId || device.revoked_at)
            throw new BankError("DEF_UNAUTHORIZED");
    }
    schedule(customerId: string, from: string, to: string, amountCents: number, executeAt: string, frequency: Frequency, deviceId?: string): ScheduledPixJob {
        if (!this.features.isEnabled("pix_agendado_recorrente"))
            throw new BankError("DEF_NOT_FOUND");
        const fromAccount = this.bank.ownAccount(customerId, from);
        const toAccount = this.bank.account(to);
        if (fromAccount.status !== "active" || toAccount.status !== "active")
            throw new BankError("DEF_ACCOUNT_FROZEN");
        if (!Number.isSafeInteger(amountCents) || amountCents <= 0 || amountCents > 2000000)
            throw new BankError("BIZ_INVALID_AMOUNT");
        const due = Date.parse(executeAt);
        if (!Number.isFinite(due) || due <= this.bank.now().getTime() ||
            due > this.bank.now().getTime() + 365 * 86400000)
            throw new BankError("BIZ_SCHEDULE_TIME");
        const hour = brtHour(this.bank.now());
        const nightSettings = this.bank.pixNightSettings(customerId);
        const night = hour >= nightSettings.night_start_hour || hour < 6;
        if (night && amountCents > nightSettings.night_limit_cents)
            throw new BankError("BIZ_NIGHT_LIMIT");
        const tier = this.bank.effectiveTier(customerId);
        const limit = tier === 1 ? 100000 : tier === 2 ? 500000 : tier === 3 ? 1500000 : 0;
        if (amountCents > limit)
            throw new BankError("BIZ_DAILY_LIMIT");
        if (deviceId)
            this.verifyDevice(customerId, deviceId);
        const id = newId("scheduled", this.bank.now().getTime());
        this.bank.db.prepare(`INSERT INTO scheduled_pix
      (id,customer_id,from_account,to_account,amount_cents,frequency,next_run_at,status,
        scheduled_night_mode,created_at,initiating_device_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
            .run(id, customerId, from, to, amountCents, frequency, new Date(due).toISOString(), "active", Number(night), this.bank.now().toISOString(), deviceId ?? null);
        return this.job(customerId, id);
    }
    job(customerId: string, id: string): ScheduledPixJob {
        const row = this.bank.db.prepare(`SELECT id,customer_id,from_account,to_account,amount_cents,
      frequency,next_run_at,status,scheduled_night_mode,initiating_device_id,
      authorization_expires_at
      FROM scheduled_pix WHERE id=? AND customer_id=?`)
            .get(id, customerId) as ScheduledPixJob | undefined;
        if (!row)
            throw new BankError("DEF_NOT_FOUND");
        return row;
    }
    reauthorize(customerId: string, id: string, deviceId: string): ScheduledPixJob {
        return this.bank.transaction(() => {
            const job = this.job(customerId, id);
            if ((job.status !== "active" && job.status !== "reauthorization_required") ||
                (job.status === "active" && job.next_run_at <= this.bank.now().toISOString()) ||
                this.bank.db.prepare(`SELECT 1 FROM scheduled_pix_executions
          WHERE job_id=? AND status='review_pending' LIMIT 1`).get(id))
                throw new BankError("BIZ_SCHEDULE_REAUTH_UNAVAILABLE");
            this.verifyDevice(customerId, deviceId);
            this.bank.db.prepare(`UPDATE scheduled_pix SET initiating_device_id=?,status='active',
        next_run_at=?,authorization_expires_at=? WHERE id=?`).run(deviceId, job.status === "reauthorization_required" ? this.bank.now().toISOString() : job.next_run_at, new Date(this.bank.now().getTime() + 5 * 60000).toISOString(), id);
            return this.job(customerId, id);
        });
    }
    cancel(customerId: string, id: string): void {
        this.bank.expireRiskPixHolds();
        const pending = this.bank.db.prepare(`SELECT e.hold_id FROM scheduled_pix_executions e
      JOIN scheduled_pix s ON s.id=e.job_id WHERE e.job_id=? AND s.customer_id=?
      AND e.status='review_pending'`).get(id, customerId) as {
            hold_id: string;
        } | undefined;
        const hold = pending ? this.bank.riskPixHold(pending.hold_id) : undefined;
        if (pending && !hold)
            throw new BankError("INTEGRITY_RISK_HOLD_MISSING");
        if (!pending || hold?.status === "approved")
            this.reconcileReviews();
        this.bank.transaction(() => {
            if (this.job(customerId, id).status === "completed")
                throw new BankError("BIZ_SCHEDULE_COMPLETED");
            if (pending && hold?.status !== "approved") {
                if (hold?.status === "pending")
                    this.bank.resolveRiskPixHold(pending.hold_id, "reject", "schedule_cancel");
                this.bank.db.prepare(`UPDATE scheduled_pix_executions SET status='cancelled',
          error_code='BIZ_SCHEDULE_CANCELLED',executed_at=? WHERE job_id=? AND status='review_pending'`)
                    .run(this.bank.now().toISOString(), id);
            }
            this.bank.db.prepare(`UPDATE scheduled_pix SET status='cancelled'
        WHERE id=? AND status IN ('active','reauthorization_required')`).run(id);
        });
    }
    private advance(job: ScheduledPixJob, dueAt: string): void {
        if (job.frequency === "once") {
            this.bank.db.prepare(`UPDATE scheduled_pix SET status='completed',
        authorization_expires_at=NULL WHERE id=?`)
                .run(job.id);
        }
        else {
            const next = job.frequency === "weekly" ?
                new Date(Date.parse(dueAt) + 7 * 86400000) : nextMonth(new Date(dueAt));
            this.bank.db.prepare(`UPDATE scheduled_pix SET next_run_at=?,
        authorization_expires_at=NULL WHERE id=?`)
                .run(next.toISOString(), job.id);
        }
    }
    private reconcileReviews(): void {
        const resolved = this.bank.db.prepare(`SELECT e.id,e.job_id,e.due_at,
      h.status hold_status,h.transfer_id,s.customer_id,s.from_account,s.to_account,
      s.amount_cents,s.frequency,s.next_run_at,s.status,s.scheduled_night_mode
      FROM scheduled_pix_executions e JOIN risk_pix_holds h ON h.id=e.hold_id
      JOIN scheduled_pix s ON s.id=e.job_id
      WHERE e.status='review_pending' AND h.status<>'pending'`).all() as unknown as (ScheduledPixJob & {
            id: string;
            job_id: string;
            due_at: string;
            hold_status: string;
            transfer_id: string | null;
        })[];
        for (const row of resolved)
            this.bank.transaction(() => {
                const approved = row.hold_status === "approved" && row.transfer_id;
                this.bank.db.prepare(`UPDATE scheduled_pix_executions SET transfer_id=?,status=?,
        error_code=?,executed_at=? WHERE id=? AND status='review_pending'`)
                    .run(approved ? row.transfer_id : null, approved ? "settled" : "failed", approved ? null : `BIZ_RISK_${row.hold_status.toUpperCase()}`, this.bank.now().toISOString(), row.id);
                if (row.status === "active")
                    this.advance({ ...row, id: row.job_id }, row.due_at);
            });
    }
    prepareDue(): void {
        this.bank.expireRiskPixHolds();
        this.reconcileReviews();
    }
    executeDue(): {
        succeeded: number;
        failed: number;
    } {
        this.prepareDue();
        if (!this.features.isEnabled("pix_agendado_recorrente"))
            return { succeeded: 0, failed: 0 };
        const rows = this.bank.db.prepare(`SELECT id,customer_id,from_account,to_account,amount_cents,
      frequency,next_run_at,status,scheduled_night_mode,initiating_device_id,
      authorization_expires_at FROM scheduled_pix
      WHERE status='active' AND next_run_at<=? AND NOT EXISTS
        (SELECT 1 FROM scheduled_pix_executions e WHERE e.job_id=scheduled_pix.id
          AND e.due_at=scheduled_pix.next_run_at AND e.status='review_pending')
      ORDER BY next_run_at,id LIMIT 100`)
            .all(this.bank.now().toISOString()) as unknown as ScheduledPixJob[];
        let succeeded = 0;
        let failed = 0;
        for (const job of rows) {
            if (!job.initiating_device_id) {
                this.bank.db.prepare(`UPDATE scheduled_pix SET status='reauthorization_required'
          WHERE id=? AND status='active'`).run(job.id);
                continue;
            }
            const dueAt = job.next_run_at;
            const steppedUp = Boolean(job.authorization_expires_at &&
                job.authorization_expires_at > this.bank.now().toISOString());
            if (!steppedUp && this.bank.requiresPixStepUp(job.from_account, job.to_account, job.amount_cents)) {
                this.bank.db.prepare(`UPDATE scheduled_pix SET status='reauthorization_required',
          authorization_expires_at=NULL WHERE id=? AND status='active'`).run(job.id);
                continue;
            }
            const input = { from: job.from_account, to: job.to_account, amount: job.amount_cents,
                idempotencyKey: `scheduled:${job.id}:${dueAt}`, actor: job.customer_id,
                deviceId: job.initiating_device_id, stepUpVerified: steppedUp,
                channel: "scheduled" as const };
            let transferId: string | null = null;
            let errorCode: string | null = null;
            let holdId: string | null = null;
            try {
                const transfer = this.transferInternal ? this.transferInternal(input) :
                    this.bank.transferPix(input);
                transferId = transfer.id;
                succeeded++;
            }
            catch (error) {
                if (!(error instanceof BankError) || error.code.startsWith("INTEGRITY_"))
                    throw error;
                errorCode = error.code;
                if (["DEF_STEP_UP_REQUIRED", "DEF_UNAUTHORIZED", "BIZ_NEW_DEVICE_LIMIT"]
                    .includes(errorCode)) {
                    this.bank.db.prepare(`UPDATE scheduled_pix SET status='reauthorization_required',
            authorization_expires_at=NULL WHERE id=? AND status='active'`).run(job.id);
                    continue;
                }
                holdId = error instanceof BankError && error.code === "BIZ_RISK_HOLD"
                    ? error.risk?.holdId ?? null : null;
                if (!holdId)
                    failed++;
            }
            this.bank.transaction(() => {
                this.bank.db.prepare(`INSERT OR IGNORE INTO scheduled_pix_executions
          (id,job_id,due_at,transfer_id,hold_id,status,error_code,executed_at)
          VALUES (?,?,?,?,?,?,?,?)`)
                    .run(newId("execution", this.bank.now().getTime()), job.id, dueAt, transferId, holdId, holdId ? "review_pending" : transferId ? "settled" : "failed", holdId ? null : errorCode, this.bank.now().toISOString());
                if (!holdId)
                    this.advance(job, dueAt);
            });
        }
        return { succeeded, failed };
    }
}
