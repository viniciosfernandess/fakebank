import { createHash, randomUUID } from "node:crypto";
import { Bank, BankError, type Posting } from "../../world/src/bank.ts";
import { seedSystemAccountId } from "../../world/src/id.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";

export interface DamageFinding { id: string; incidentId: string; roundId: string; txId: string;
  victimAccount: string; attackerAccount: string; amountCents: number; status: "open" | "restored"; }
export interface RestoreReceipt { txId: string; roundId: string; restoredCents: number; recoveredFromAttackerCents: number;
  absorbedByBankCents: number; driftAfterCents: number; }

export class BlueRestoration {
  readonly bank: Bank;
  readonly events: EventStore | undefined;
  constructor(bank: Bank, events?: EventStore) {
    this.bank = bank; this.events = events;
    bank.db.exec(`CREATE TABLE IF NOT EXISTS blue_damage_findings (
      id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, round_id TEXT NOT NULL,
      tx_id TEXT NOT NULL UNIQUE, victim_account TEXT NOT NULL, attacker_account TEXT NOT NULL,
      amount_cents INTEGER NOT NULL, status TEXT NOT NULL, assessed_at TEXT NOT NULL,
      restored_at TEXT, restore_tx_id TEXT
    );
    CREATE INDEX IF NOT EXISTS blue_damage_round ON blue_damage_findings(round_id,status);
    CREATE TABLE IF NOT EXISTS blue_restore_ledger (
      id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE REFERENCES blue_damage_findings(id),
      round_id TEXT NOT NULL, customer_id TEXT NOT NULL, amount_cents INTEGER NOT NULL,
      recovered_cents INTEGER NOT NULL, bank_loss_cents INTEGER NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS blue_restore_approvals (
      id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE REFERENCES blue_damage_findings(id),
      incident_id TEXT NOT NULL, maker_id TEXT NOT NULL, checker_id TEXT NOT NULL,
      amount_cents INTEGER NOT NULL, approved_at TEXT NOT NULL, consumed_at TEXT,
      CHECK(maker_id<>checker_id)
    );`);
  }
  private open(incidentId: string): void {
    const row = this.bank.db.prepare("SELECT state FROM sentinel_incidents WHERE id=?")
      .get(incidentId) as { state: string } | undefined;
    if (!row || !["open", "contained", "patching", "awaiting_next_window"].includes(row.state))
      throw new BankError("DEF_INCIDENT_NOT_OPEN");
  }
  private bankLossAccountId(): string {
    const existing = this.bank.db.prepare("SELECT id FROM accounts WHERE kind='system' AND system_role='bank_loss'")
      .get() as { id: string } | undefined;
    if (existing) return existing.id;
    const id = seedSystemAccountId("bank_loss");
    this.bank.addAccount({ id, customer_id: null, kind: "system", system_role: "bank_loss",
      overdraft_limit: 0, status: "active" });
    return id;
  }
  scan(input: { incidentId: string; roundId: string; from: string; to: string;
    checkNo?: 1 | 2 | "final" }): DamageFinding[] {
    this.open(input.incidentId);
    const from = Date.parse(input.from), to = Date.parse(input.to);
    if (!input.roundId || !Number.isFinite(from) || !Number.isFinite(to) || from > to)
      throw new BankError("BIZ_DAMAGE_WINDOW");
    const transfers = this.bank.db.prepare(`SELECT p.ledger_tx_id tx_id,p.from_account victim_account,
      p.to_account attacker_account,p.amount amount_cents
      FROM pix_transfers p
      JOIN accounts src ON src.id=p.from_account JOIN customers victim ON victim.id=src.customer_id
      JOIN accounts dst ON dst.id=p.to_account JOIN customers attacker ON attacker.id=dst.customer_id
      JOIN sentinel_incidents i ON i.id=? AND (i.entity_key=victim.id OR i.entity_key=attacker.id
        OR i.entity_key=src.id OR i.entity_key=dst.id)
      LEFT JOIN blue_damage_findings f ON f.tx_id=p.ledger_tx_id
      WHERE p.status='settled' AND victim.is_attacker_owned=0 AND attacker.is_attacker_owned=1
        AND ((p.settled_at>=? AND p.settled_at<=?) OR
          (f.incident_id=? AND f.status='open'))
        AND (f.id IS NULL OR f.status='open')
      ORDER BY p.settled_at,p.id LIMIT 50`)
      .all(input.incidentId, input.from, input.to, input.incidentId) as
      { tx_id: string; victim_account: string; attacker_account: string; amount_cents: number }[];
    const findings = this.bank.transaction(() => transfers.map((transfer) => {
      const existing = this.bank.db.prepare("SELECT * FROM blue_damage_findings WHERE tx_id=?")
        .get(transfer.tx_id) as Record<string, unknown> | undefined;
      if (existing && existing.incident_id !== input.incidentId) throw new BankError("DEF_DAMAGE_ALREADY_CLAIMED");
      if (!existing) this.bank.db.prepare("INSERT INTO blue_damage_findings VALUES (?,?,?,?,?,?,?,'open',?,NULL,NULL)")
        .run(`finding_${randomUUID()}`, input.incidentId, input.roundId, transfer.tx_id,
          transfer.victim_account, transfer.attacker_account, transfer.amount_cents, this.bank.now().toISOString());
      const row = this.bank.db.prepare("SELECT * FROM blue_damage_findings WHERE tx_id=?")
        .get(transfer.tx_id) as { id: string; incident_id: string; round_id: string; tx_id: string;
          victim_account: string; attacker_account: string; amount_cents: number; status: "open" | "restored" };
      return { id: row.id, incidentId: row.incident_id, roundId: row.round_id, txId: row.tx_id,
        victimAccount: row.victim_account, attackerAccount: row.attacker_account,
        amountCents: row.amount_cents, status: row.status };
    }));
    const open = findings.filter((finding) => finding.status === "open");
    const snapshotHash = createHash("sha256").update(JSON.stringify(open.map((finding) =>
      [finding.id, finding.amountCents]))).digest("hex").slice(0, 16);
    this.events?.append({ round_id: input.roundId, ts: new Date().toISOString(),
      twin_ts: this.bank.now().toISOString(), type: "damage.assessed",
      actor: { id: "damage-assessor", role: "damage_assessor" }, area: "ledger",
      incident_id: input.incidentId, public_summary_pt: "Dano financeiro avaliado",
      public: { incident_id: input.incidentId, loss_cents: open.reduce((sum, finding) => sum + finding.amountCents, 0),
        customers_affected: new Set(open.map((finding) => finding.victimAccount)).size,
        exposure_cents: 0, summary_pt: `${open.length} transferência(s) pendente(s)` },
      private: { finding_ids: open.map((finding) => finding.id), from: input.from, to: input.to,
        check_no: input.checkNo ?? 1 } },
    `damage:${input.incidentId}:${input.roundId}:${input.checkNo ?? 1}:${input.from}:${input.to}:${snapshotHash}`);
    return findings;
  }
  approve(input: { incidentId: string; findingId: string; evidenceRef: string;
    makerId: string; checkerId: string }): string {
    this.open(input.incidentId);
    if (!input.makerId || !input.checkerId || input.makerId === input.checkerId ||
      input.evidenceRef !== input.findingId) throw new BankError("DEF_RESTORE_APPROVAL_INVALID");
    return this.bank.transaction(() => {
      const finding = this.bank.db.prepare(`SELECT f.incident_id,f.status,f.amount_cents FROM blue_damage_findings f
        JOIN pix_transfers p ON p.ledger_tx_id=f.tx_id AND p.from_account=f.victim_account
          AND p.to_account=f.attacker_account AND p.amount=f.amount_cents
        JOIN accounts src ON src.id=p.from_account JOIN customers victim ON victim.id=src.customer_id
          AND victim.is_attacker_owned=0
        JOIN accounts dst ON dst.id=p.to_account JOIN customers attacker ON attacker.id=dst.customer_id
          AND attacker.is_attacker_owned=1
        WHERE f.id=?`).get(input.findingId) as
        { incident_id: string; status: string; amount_cents: number } | undefined;
      if (!finding || finding.incident_id !== input.incidentId || finding.status !== "open" ||
        finding.amount_cents > 500_000) throw new BankError("DEF_RESTORE_APPROVAL_INVALID");
      const existing = this.bank.db.prepare("SELECT * FROM blue_restore_approvals WHERE finding_id=?")
        .get(input.findingId) as { id: string; maker_id: string; checker_id: string;
          consumed_at: string | null } | undefined;
      if (existing) {
        if (existing.maker_id !== input.makerId || existing.checker_id !== input.checkerId ||
          existing.consumed_at) throw new BankError("DEF_RESTORE_APPROVAL_INVALID");
        return existing.id;
      }
      const id = `approval_${randomUUID()}`;
      this.bank.db.prepare("INSERT INTO blue_restore_approvals VALUES (?,?,?,?,?,?,?,NULL)")
        .run(id, input.findingId, input.incidentId, input.makerId, input.checkerId,
          finding.amount_cents, this.bank.now().toISOString());
      return id;
    });
  }
  restore(input: { incidentId: string; roundId: string; findingId: string; evidenceRef: string;
    actorId: string; approvalId: string }): RestoreReceipt {
    this.open(input.incidentId);
    if (!input.roundId || !input.actorId || !input.evidenceRef ||
      input.evidenceRef !== input.findingId)
      throw new BankError("DEF_RESTORE_EVIDENCE");
    const receipt = this.bank.transaction(() => {
      const row = this.bank.db.prepare(`SELECT f.*,a.customer_id victim_customer
        FROM blue_damage_findings f JOIN accounts a ON a.id=f.victim_account WHERE f.id=?`)
        .get(input.findingId) as { id: string; incident_id: string; round_id: string; tx_id: string;
          victim_account: string; attacker_account: string; amount_cents: number; status: string;
          victim_customer: string } | undefined;
      if (!row || row.incident_id !== input.incidentId) throw new BankError("DEF_RESTORE_EVIDENCE");
      if (row.status !== "open") throw new BankError("DEF_ALREADY_RESTORED");
      const approval = this.bank.db.prepare(`SELECT id FROM blue_restore_approvals WHERE id=? AND finding_id=?
        AND incident_id=? AND maker_id=? AND checker_id<>? AND amount_cents=?
        AND consumed_at IS NULL`).get(input.approvalId, row.id, row.incident_id,
          input.actorId, input.actorId, row.amount_cents);
      if (!approval) throw new BankError("DEF_RESTORE_APPROVAL_REQUIRED");
      const original = this.bank.db.prepare(`SELECT p.ledger_tx_id FROM pix_transfers p
        JOIN accounts src ON src.id=p.from_account JOIN customers victim ON victim.id=src.customer_id
        JOIN accounts dst ON dst.id=p.to_account JOIN customers attacker ON attacker.id=dst.customer_id
        WHERE p.ledger_tx_id=? AND p.from_account=? AND p.to_account=? AND p.amount=?
        AND victim.is_attacker_owned=0 AND attacker.is_attacker_owned=1`)
        .get(row.tx_id, row.victim_account, row.attacker_account, row.amount_cents);
      if (!original) throw new BankError("DEF_RESTORE_SOURCE");
      const total = this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) n FROM blue_restore_ledger
        WHERE round_id=?`).get(input.roundId) as { n: number };
      const customer = this.bank.db.prepare(`SELECT COALESCE(SUM(amount_cents),0) n FROM blue_restore_ledger
        WHERE round_id=? AND customer_id=?`).get(input.roundId, row.victim_customer) as { n: number };
      const incidentTotal = (this.bank.db.prepare(`SELECT COALESCE(SUM(l.amount_cents),0) n
        FROM blue_restore_ledger l JOIN blue_damage_findings f ON f.id=l.finding_id
        WHERE f.incident_id=?`).get(row.incident_id) as { n: number }).n;
      const hasMedApprovals = this.bank.db.prepare(`SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='blue_med_approvals'`).get();
      const medApproved = hasMedApprovals ? (this.bank.db.prepare(`SELECT COALESCE(SUM(claim_cents),0) n
        FROM blue_med_approvals WHERE incident_id=?`).get(row.incident_id) as { n: number }).n : 0;
      const medRound = hasMedApprovals ? (this.bank.db.prepare(`SELECT COALESCE(SUM(claim_cents),0) n
        FROM blue_med_approvals WHERE round_id=?`).get(input.roundId) as { n: number }).n : 0;
      const medCustomer = hasMedApprovals ? (this.bank.db.prepare(`SELECT COALESCE(SUM(m.claim_cents),0) n
        FROM blue_med_approvals m JOIN pix_transfers p ON p.id=m.transfer_id
        JOIN accounts a ON a.id=p.from_account WHERE m.round_id=? AND a.customer_id=?`)
        .get(input.roundId, row.victim_customer) as { n: number }).n : 0;
      if (total.n + medRound + row.amount_cents > 5_000_000 ||
        customer.n + medCustomer + row.amount_cents > 500_000)
        throw new BankError("DEF_RESTORE_LIMIT");
      if (incidentTotal + medApproved + row.amount_cents > 5_000_000)
        throw new BankError("DEF_RESTORE_LIMIT");
      const already = this.bank.db.prepare("SELECT 1 FROM ledger_entries WHERE reverses_tx_id=? LIMIT 1")
        .get(row.tx_id);
      if (already) throw new BankError("DEF_ALREADY_RESTORED");
      const attacker = this.bank.account(row.attacker_account);
      const recovered = Math.min(row.amount_cents, Math.max(0, attacker.balance_cached));
      const absorbed = row.amount_cents - recovered;
      const postings: Posting[] = [];
      if (recovered > 0) postings.push({ accountId: row.attacker_account, amount: -recovered,
        kind: "restore_reversal", actor: "blue_restorer", refType: "incident", refId: row.incident_id });
      if (absorbed > 0) postings.push({ accountId: this.bankLossAccountId(), amount: -absorbed,
        kind: "restore_bank_loss", actor: "blue_restorer", refType: "incident", refId: row.incident_id });
      postings.push({ accountId: row.victim_account, amount: row.amount_cents,
        kind: "restore_credit", actor: "blue_restorer", refType: "incident", refId: row.incident_id });
      const txId = this.bank.post(postings, row.tx_id);
      this.bank.db.prepare("UPDATE blue_restore_approvals SET consumed_at=? WHERE id=?")
        .run(this.bank.now().toISOString(), input.approvalId);
      this.bank.db.prepare("INSERT INTO blue_restore_ledger VALUES (?,?,?,?,?,?,?,?)")
        .run(`restore_${randomUUID()}`, row.id, input.roundId, row.victim_customer, row.amount_cents,
          recovered, absorbed, this.bank.now().toISOString());
      this.bank.db.prepare("UPDATE blue_damage_findings SET status='restored',restored_at=?,restore_tx_id=? WHERE id=?")
        .run(this.bank.now().toISOString(), txId, row.id);
      this.bank.reconcile();
      const drift = this.bank.balanceDriftCents();
      return { txId, roundId: input.roundId, restoredCents: row.amount_cents, recoveredFromAttackerCents: recovered,
        absorbedByBankCents: absorbed, driftAfterCents: drift };
    });
    this.events?.append({ round_id: receipt.roundId, ts: new Date().toISOString(), twin_ts: this.bank.now().toISOString(),
      type: "damage.restored", actor: { id: input.actorId, role: "restorer" },
      incident_id: input.incidentId, area: "ledger", public_summary_pt: "Dano financeiro restaurado",
      public: { incident_id: input.incidentId, restored_cents: receipt.restoredCents,
        customers_made_whole: 1, drift_after_cents: receipt.driftAfterCents,
        recovered_cents: receipt.recoveredFromAttackerCents,
        absorbed_cents: receipt.absorbedByBankCents },
      private: { finding_id: input.findingId, restore_tx_id: receipt.txId,
        recovered_cents: receipt.recoveredFromAttackerCents, bank_loss_cents: receipt.absorbedByBankCents } });
    return receipt;
  }
}
