import type { Bank } from "../../world/src/bank.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import { BankError } from "../../world/src/bank.ts";
import { BlueContainment } from "./blue-containment.ts";

export type AuxiliaryDamageKind = "live_session" | "live_key" | "scheduled_job" |
  "frozen_honest_account" | "balance_drift" | "data_exposure";
export interface AuxiliaryFinding { kind: AuxiliaryDamageKind; ref: string; }
const restorable = new Set<AuxiliaryDamageKind>([
  "live_session", "live_key", "scheduled_job", "frozen_honest_account", "balance_drift"]);
export function isRestorableAuxiliary(kind: AuxiliaryDamageKind): boolean {
  return restorable.has(kind);
}

export class RecoveryAux {
  readonly bank: Bank;
  readonly events: EventStore;
  constructor(bank: Bank, events: EventStore) { this.bank = bank; this.events = events; }
  private table(name: string): boolean {
    return Boolean(this.bank.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table' AND name=?`)
      .get(name));
  }
  private customer(incidentId: string): string | undefined {
    const incident = this.bank.db.prepare("SELECT entity_key FROM sentinel_incidents WHERE id=?")
      .get(incidentId) as { entity_key: string } | undefined;
    if (!incident) throw new BankError("DEF_INCIDENT_NOT_OPEN");
    const direct = this.bank.db.prepare("SELECT id FROM customers WHERE id=?")
      .get(incident.entity_key) as { id: string } | undefined;
    if (direct) return direct.id;
    return (this.bank.db.prepare("SELECT customer_id FROM accounts WHERE id=?")
      .get(incident.entity_key) as { customer_id: string | null } | undefined)?.customer_id ?? undefined;
  }
  scan(incidentId: string, from: string, to: string): AuxiliaryFinding[] {
    const customerId = this.customer(incidentId);
    const entity = (this.bank.db.prepare("SELECT entity_key FROM sentinel_incidents WHERE id=?")
      .get(incidentId) as { entity_key: string }).entity_key;
    const findings: AuxiliaryFinding[] = [];
    if (customerId && this.table("auth_sessions") && this.table("auth_devices")) {
      for (const row of this.bank.db.prepare(`SELECT s.id FROM auth_sessions s
        JOIN auth_devices d ON d.id=s.device_id WHERE s.customer_id=?
        AND s.revoked_at IS NULL AND d.revoked_at IS NOT NULL LIMIT 51`).all(customerId) as
        { id: string }[]) findings.push({ kind: "live_session", ref: row.id });
    }
    if (customerId && this.table("scheduled_pix")) {
      for (const row of this.bank.db.prepare(`SELECT j.id FROM scheduled_pix j
        JOIN customers c ON c.id=j.customer_id WHERE j.customer_id=?
        AND c.is_attacker_owned=1 AND j.status IN ('active','reauthorization_required')
        LIMIT 51`).all(customerId) as
        { id: string }[]) findings.push({ kind: "scheduled_job", ref: row.id });
    }
    if (this.table("proximity_tokens") && this.table("proximity_uses")) {
      const token = this.bank.db.prepare(`SELECT t.id FROM proximity_tokens t
        WHERE t.id=? AND t.expires_at>? AND t.used_at IS NULL
        AND EXISTS (SELECT 1 FROM proximity_uses u WHERE u.token_id=t.id)`).get(entity,
        this.bank.now().toISOString()) as { id: string } | undefined;
      if (token) findings.push({ kind: "live_key", ref: token.id });
    }
    for (const row of this.bank.db.prepare(`SELECT c.id FROM blue_containments c
      JOIN accounts a ON a.id=c.target JOIN customers customer ON customer.id=a.customer_id
      WHERE c.incident_id=? AND c.kind='freeze_account' AND c.lifted_at IS NULL
      AND c.expires_at>? AND customer.is_attacker_owned=0 LIMIT 51`)
      .all(incidentId, this.bank.realNow().toISOString()) as { id: string }[])
      findings.push({ kind: "frozen_honest_account", ref: row.id });
    if (customerId && this.table("data_share_reads")) {
      for (const row of this.bank.db.prepare(`SELECT r.id FROM data_share_reads r
        JOIN data_consents c ON c.id=r.consent_id WHERE c.customer_id=?
        AND (r.was_revoked=1 OR r.scope_granted=0)
        AND r.read_at>=? AND r.read_at<=? LIMIT 51`)
        .all(customerId, from, to) as { id: string }[])
        findings.push({ kind: "data_exposure", ref: row.id });
    }
    if (customerId) {
      for (const row of this.bank.db.prepare(`SELECT id FROM access_log WHERE customer_id=?
        AND kind='statement_foreign' AND status=200 AND ts>=? AND ts<=? LIMIT 51`)
        .all(customerId, from, to) as { id: string }[])
        findings.push({ kind: "data_exposure", ref: row.id });
    }
    for (const row of this.bank.db.prepare(`SELECT a.id FROM accounts a LEFT JOIN
      (SELECT account_id,SUM(amount) total FROM ledger_entries GROUP BY account_id) l
      ON l.account_id=a.id WHERE a.balance_cached<>COALESCE(l.total,0)
      AND (? IS NULL OR a.customer_id=?) LIMIT 51`)
      .all(customerId ?? null, customerId ?? null) as { id: string }[])
      findings.push({ kind: "balance_drift", ref: row.id });
    if (findings.length > 50) throw new BankError("DEF_DAMAGE_SCAN_TRUNCATED");
    return findings;
  }
  restore(incidentId: string, finding: AuxiliaryFinding, evidenceRef: string,
    actorId: string, from: string, to: string): boolean {
    if (!actorId || evidenceRef !== finding.ref || !isRestorableAuxiliary(finding.kind) ||
      !this.scan(incidentId, from, to).some((item) => item.kind === finding.kind &&
        item.ref === finding.ref)) throw new BankError("DEF_RESTORE_EVIDENCE");
    const now = this.bank.realNow().toISOString();
    let changed = 0;
    if (finding.kind === "live_session") changed = Number(this.bank.db.prepare(`UPDATE auth_sessions
      SET revoked_at=? WHERE id=? AND revoked_at IS NULL`).run(now, finding.ref).changes);
    else if (finding.kind === "live_key") changed = Number(this.bank.db.prepare(`UPDATE proximity_tokens
      SET used_at=?,expires_at=? WHERE id=? AND used_at IS NULL`).run(
        this.bank.now().toISOString(), this.bank.now().toISOString(), finding.ref).changes);
    else if (finding.kind === "scheduled_job") changed = Number(this.bank.db.prepare(`UPDATE scheduled_pix
      SET status='cancelled' WHERE id=? AND status IN ('active','reauthorization_required')`)
      .run(finding.ref).changes);
    else if (finding.kind === "balance_drift") {
      const unbalanced = this.bank.db.prepare(`SELECT 1 FROM ledger_entries
        GROUP BY tx_id HAVING SUM(amount)<>0 LIMIT 1`).get();
      if (unbalanced) throw new BankError("DEF_LEDGER_UNBALANCED");
      const balance = this.bank.db.prepare(`SELECT a.overdraft_limit,
        (SELECT COALESCE(SUM(amount),0) FROM ledger_entries WHERE account_id=a.id) actual
        FROM accounts a WHERE a.id=?`).get(finding.ref) as
        { overdraft_limit: number; actual: number } | undefined;
      if (!balance || balance.actual < -balance.overdraft_limit)
        throw new BankError("DEF_BALANCE_RESTORE_UNSAFE");
      changed = Number(this.bank.db.prepare(`UPDATE accounts SET balance_cached=
        (SELECT COALESCE(SUM(amount),0) FROM ledger_entries WHERE account_id=?)
        WHERE id=? AND balance_cached<>(SELECT COALESCE(SUM(amount),0)
        FROM ledger_entries WHERE account_id=?)`).run(finding.ref, finding.ref,
        finding.ref).changes);
    }
    else changed = Number(new BlueContainment(this.bank).lift(finding.ref, actorId));
    if (changed) {
      this.bank.reconcile();
      const honest = finding.kind === "frozen_honest_account" ? 1 :
        finding.kind === "balance_drift" ? (this.bank.db.prepare(`SELECT COUNT(*) n FROM accounts a
          JOIN customers c ON c.id=a.customer_id WHERE a.id=? AND c.is_attacker_owned=0`)
          .get(finding.ref) as { n: number }).n : 0;
      this.events.append({ round_id: null, ts: now,
      twin_ts: this.bank.now().toISOString(), type: "damage.restored",
      actor: { id: actorId, role: "restorer" }, incident_id: incidentId,
      area: finding.kind === "live_session" ? "auth" :
        finding.kind === "scheduled_job" || finding.kind === "live_key" ? "pix" : "accounts",
      public_summary_pt: "Estado suspeito encerrado", public: {
        incident_id: incidentId, restored_cents: 0,
        customers_made_whole: honest,
        drift_after_cents: this.bank.balanceDriftCents() },
      private: { kind: finding.kind, ref: finding.ref } });
    }
    return Boolean(changed);
  }
}
