import { Bank, BankError, type Account, type AccountFrozenReason } from "./bank.ts";

export interface AccountStatusChange {
  from_status: Account["status"]; to_status: Account["status"];
  reason: AccountFrozenReason | null; actor: string; changed_at: string;
}

export class AccountLifecycle {
  private readonly bank: Bank;
  constructor(bank: Bank) { this.bank = bank; }

  history(accountId: string): AccountStatusChange[] {
    this.bank.account(accountId);
    return this.bank.db.prepare(`SELECT from_status,to_status,reason,actor,changed_at
      FROM account_status_changes WHERE account_id=? ORDER BY rowid DESC LIMIT 50`)
      .all(accountId) as unknown as AccountStatusChange[];
  }

  transition(accountId: string, status: Account["status"], actor: string,
    reason: AccountFrozenReason | null = null): Account {
    return this.bank.transaction(() => {
      const current = this.bank.account(accountId);
      if (current.status === status && (current.frozen_reason ?? null) === reason)
        return this.bank.changeAccountStatus(accountId, status, actor, reason);
      if (status === "active" && current.status === "frozen" &&
        (this.activeProtection(accountId) || this.activeMedicalDispute(accountId)))
        throw new BankError("DEF_ACCOUNT_STATUS_PROTECTED");
      if (status === "closed") {
        if (current.balance_cached !== 0) throw new BankError("BIZ_ACCOUNT_CLOSE_BALANCE");
        if (this.activeProtection(accountId) || this.activeMedicalDispute(accountId) ||
          this.has("salary_account_employers", `SELECT 1 FROM salary_account_employers e
            JOIN accounts salary ON salary.id=e.account_id
            WHERE e.employer_account_id=? AND salary.status<>'closed' LIMIT 1`, accountId) ||
          this.has("salary_portability_instructions", `SELECT 1
            FROM salary_portability_instructions WHERE destination_account_id IS NOT NULL
              AND (destination_account_id=? OR account_id=?) LIMIT 1`,
            accountId, accountId) ||
          this.has("pix_keys", `SELECT 1 FROM pix_keys WHERE account_id=?
            AND status='active' LIMIT 1`, accountId) ||
          this.has("risk_pix_holds", `SELECT 1 FROM risk_pix_holds WHERE status='pending'
            AND (from_account=? OR to_account=?) LIMIT 1`, accountId, accountId) ||
          this.has("pix_transfers", `SELECT 1 FROM pix_transfers
            WHERE status NOT IN ('settled','rejected','returned_partial','returned_full')
            AND (from_account=? OR to_account=?) LIMIT 1`, accountId, accountId) ||
          this.has("scheduled_pix", `SELECT 1 FROM scheduled_pix
            WHERE status IN ('active','reauthorization_required')
            AND (from_account=? OR to_account=?) LIMIT 1`, accountId, accountId) ||
          this.has("scheduled_pix_executions", `SELECT 1 FROM scheduled_pix_executions e
            JOIN scheduled_pix j ON j.id=e.job_id WHERE e.status='review_pending'
            AND (j.from_account=? OR j.to_account=?) LIMIT 1`, accountId, accountId) ||
          this.has("pix_automatic_mandates", `SELECT 1 FROM pix_automatic_mandates
            WHERE status='active' AND (from_account=? OR merchant_account=?) LIMIT 1`,
            accountId, accountId) ||
          this.has("pix_automatic_charges", `SELECT 1 FROM pix_automatic_charges c
            JOIN pix_automatic_mandates m ON m.id=c.mandate_id
            WHERE c.status IN ('pending','review_pending','reauthorization_required')
            AND (m.from_account=? OR m.merchant_account=?) LIMIT 1`, accountId, accountId) ||
          this.has("cards", `SELECT 1 FROM cards WHERE account_id=? AND status='active' LIMIT 1`,
            accountId) ||
          this.has("loans", `SELECT 1 FROM loans WHERE account_id=? AND status='active' LIMIT 1`,
            accountId) ||
          this.has("card_network_authorizations", `SELECT 1 FROM card_network_authorizations
            WHERE account_id=? AND status='approved' LIMIT 1`, accountId) ||
          this.has("card_disputes", `SELECT 1 FROM card_disputes d
            JOIN card_network_authorizations a ON a.id=d.authorization_id
            WHERE a.account_id=? AND d.status NOT IN ('customer_won','merchant_won') LIMIT 1`,
            accountId) ||
          this.has("manual_posting_requests", `SELECT 1 FROM manual_posting_requests p,
            json_each(p.lines_json) line WHERE p.status='pending'
            AND json_extract(line.value,'$.accountId')=? LIMIT 1`, accountId) ||
          this.has("judicial_orders", `SELECT 1 FROM judicial_orders
            WHERE account_id=? AND status IN ('pending','active','release_pending') LIMIT 1`, accountId))
          throw new BankError("BIZ_ACCOUNT_CLOSE_PENDING");
      }
      return this.bank.changeAccountStatus(accountId, status, actor, reason);
    });
  }

  private has(table: string, sql: string, ...params: (string | number)[]): boolean {
    if (!this.bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table' AND name=?`)
      .get(table)) return false;
    return Boolean(this.bank.db.prepare(sql).get(...params));
  }

  private activeProtection(accountId: string): boolean {
    const now = this.bank.now().toISOString();
    return Boolean(this.bank.db.prepare(`SELECT 1 FROM balance_holds WHERE account_id=?
      AND released_at IS NULL AND expires_at>? LIMIT 1`).get(accountId, now) ||
      this.bank.db.prepare(`SELECT 1 FROM blue_containments WHERE kind='freeze_account'
        AND target=? AND lifted_at IS NULL AND expires_at>? LIMIT 1`)
        .get(accountId, this.bank.realNow().toISOString()));
  }

  private activeMedicalDispute(accountId: string): boolean {
    return Boolean(this.bank.db.prepare(`SELECT 1 FROM med_cases m
      JOIN pix_transfers p ON p.id=m.transfer_id WHERE m.status='open'
      AND (p.from_account=? OR p.to_account=?) LIMIT 1`).get(accountId, accountId));
  }
}
