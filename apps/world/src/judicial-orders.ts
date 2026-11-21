import { Bank, BankError } from "./bank.ts";
import { newId } from "./id.ts";

export interface JudicialOrder {
  id: string;
  case_reference: string;
  account_id: string;
  amount_cents: number;
  status: "pending" | "active" | "release_pending" | "released" | "rejected";
  maker_id: string;
  checker_id: string | null;
  hold_id: string | null;
  release_maker_id: string | null;
  release_checker_id: string | null;
  created_at: string;
  resolved_at: string | null;
}

const operatorId = /^[a-zA-Z0-9_-]{1,80}$/;
const caseReference = /^[a-zA-Z0-9][a-zA-Z0-9._/-]{2,127}$/;
const indefiniteHold = new Date("9999-12-31T23:59:59.999Z");

export class JudicialOrders {
  private readonly bank: Bank;
  constructor(bank: Bank) {
    this.bank = bank;
    bank.db.exec(`CREATE TABLE IF NOT EXISTS judicial_orders (
      id TEXT PRIMARY KEY,
      case_reference TEXT NOT NULL UNIQUE,
      account_id TEXT NOT NULL REFERENCES accounts(id),
      amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
      status TEXT NOT NULL CHECK(status IN ('pending','active','release_pending','released','rejected')),
      maker_id TEXT NOT NULL,
      checker_id TEXT,
      hold_id TEXT UNIQUE REFERENCES balance_holds(id),
      release_maker_id TEXT,
      release_checker_id TEXT,
      created_at TEXT NOT NULL,
      resolved_at TEXT
    );
    CREATE TABLE IF NOT EXISTS judicial_order_events (
      id TEXT PRIMARY KEY,
      order_id TEXT NOT NULL REFERENCES judicial_orders(id),
      action TEXT NOT NULL CHECK(action IN ('requested','activated','rejected','release_requested',
        'release_approved','release_rejected')),
      actor TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS judicial_order_events_order ON judicial_order_events(order_id,created_at,id);
    CREATE TRIGGER IF NOT EXISTS judicial_order_events_no_update
      BEFORE UPDATE ON judicial_order_events BEGIN SELECT RAISE(ABORT,'JUDICIAL_EVENT_IMMUTABLE'); END;
    CREATE TRIGGER IF NOT EXISTS judicial_order_events_no_delete
      BEFORE DELETE ON judicial_order_events BEGIN SELECT RAISE(ABORT,'JUDICIAL_EVENT_IMMUTABLE'); END;`);
  }

  private event(orderId: string, action: string, actor: string): void {
    this.bank.db.prepare(`INSERT INTO judicial_order_events VALUES (?,?,?,?,?)`).run(
      newId("jue", this.bank.now().getTime()), orderId, action, actor,
      this.bank.now().toISOString());
  }

  get(id: string): JudicialOrder {
    const order = this.bank.db.prepare("SELECT * FROM judicial_orders WHERE id=?")
      .get(id) as JudicialOrder | undefined;
    if (!order) throw new BankError("BIZ_JUDICIAL_ORDER_NOT_FOUND");
    return order;
  }

  request(accountId: string, amountCents: number, reference: string, makerId: string): JudicialOrder {
    if (!operatorId.test(makerId) || !caseReference.test(reference) ||
      !Number.isSafeInteger(amountCents) || amountCents <= 0)
      throw new BankError("BIZ_JUDICIAL_ORDER_INVALID");
    return this.bank.transaction(() => {
      const account = this.bank.account(accountId);
      if (account.kind === "system" || account.status !== "active")
        throw new BankError("DEF_ACCOUNT_FROZEN");
      const id = newId("jorder", this.bank.now().getTime());
      this.bank.db.prepare(`INSERT INTO judicial_orders
        (id,case_reference,account_id,amount_cents,status,maker_id,created_at)
        VALUES (?,?,?,?,'pending',?,?)`).run(id, reference, accountId, amountCents,
          makerId, this.bank.now().toISOString());
      this.event(id, "requested", makerId);
      return this.get(id);
    });
  }

  review(id: string, decision: "approve" | "reject", checkerId: string): JudicialOrder {
    if (!operatorId.test(checkerId) || !["approve", "reject"].includes(decision))
      throw new BankError("BIZ_JUDICIAL_REVIEW_INVALID");
    return this.bank.transaction(() => {
      const order = this.get(id);
      if (order.status !== "pending" || order.maker_id === checkerId)
        throw new BankError("BIZ_JUDICIAL_REVIEW_INVALID");
      let holdId: string | null = null;
      if (decision === "approve") {
        holdId = this.bank.createHold({ accountId: order.account_id,
          amount: order.amount_cents, kind: "judicial", ref: order.id,
          actor: checkerId, expiresAt: indefiniteHold });
      }
      this.bank.db.prepare(`UPDATE judicial_orders SET status=?,checker_id=?,hold_id=?,resolved_at=?
        WHERE id=? AND status='pending'`).run(decision === "approve" ? "active" : "rejected",
          checkerId, holdId, this.bank.now().toISOString(), id);
      this.event(id, decision === "approve" ? "activated" : "rejected", checkerId);
      return this.get(id);
    });
  }

  requestRelease(id: string, makerId: string): JudicialOrder {
    if (!operatorId.test(makerId)) throw new BankError("BIZ_JUDICIAL_RELEASE_INVALID");
    return this.bank.transaction(() => {
      const order = this.get(id);
      if (order.status !== "active" || order.checker_id === makerId)
        throw new BankError("BIZ_JUDICIAL_RELEASE_INVALID");
      this.bank.db.prepare(`UPDATE judicial_orders SET status='release_pending',release_maker_id=?
        WHERE id=? AND status='active'`).run(makerId, id);
      this.event(id, "release_requested", makerId);
      return this.get(id);
    });
  }

  reviewRelease(id: string, decision: "approve" | "reject", checkerId: string): JudicialOrder {
    if (!operatorId.test(checkerId) || !["approve", "reject"].includes(decision))
      throw new BankError("BIZ_JUDICIAL_RELEASE_INVALID");
    return this.bank.transaction(() => {
      const order = this.get(id);
      if (order.status !== "release_pending" || order.release_maker_id === checkerId ||
        !order.hold_id) throw new BankError("BIZ_JUDICIAL_RELEASE_INVALID");
      if (decision === "approve") {
        const changed = this.bank.db.prepare(`UPDATE balance_holds
          SET released_at=?,release_actor=? WHERE id=? AND released_at IS NULL`)
          .run(this.bank.now().toISOString(), checkerId, order.hold_id);
        if (changed.changes !== 1) throw new BankError("INTEGRITY_JUDICIAL_HOLD_MISSING");
      }
      this.bank.db.prepare(`UPDATE judicial_orders SET status=?,release_checker_id=?,resolved_at=?
        WHERE id=? AND status='release_pending'`).run(
          decision === "approve" ? "released" : "active", checkerId,
          this.bank.now().toISOString(), id);
      this.event(id, decision === "approve" ? "release_approved" : "release_rejected", checkerId);
      return this.get(id);
    });
  }
}
