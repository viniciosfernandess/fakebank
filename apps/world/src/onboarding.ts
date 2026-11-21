import { createHash } from "node:crypto";
import { AuthEngine } from "./auth.ts";
import { Bank, BankError, type Persona } from "./bank.ts";
import { newId } from "./id.ts";

export interface OnboardingApplication {
  customer_id: string;
  account_id: string;
  bureau_score: number;
  liveness_status: "pending" | "passed" | "failed";
  liveness_verifier: string | null;
  status: "pending" | "approved" | "rejected";
  submitted_at: string;
  reviewed_at: string | null;
  reviewer: string | null;
}

const personas: ReadonlySet<string> = new Set([
  "salaried", "merchant", "student", "retiree", "gig", "saver", "night_owl",
]);
const actorPattern = /^[a-zA-Z0-9_-]{1,80}$/;

export class OnboardingService {
  private readonly bank: Bank;
  private readonly auth: AuthEngine;
  constructor(bank: Bank, auth: AuthEngine) {
    this.bank = bank;
    this.auth = auth;
  }

  application(customerId: string): OnboardingApplication {
    const row = this.bank.db.prepare(`SELECT customer_id,account_id,bureau_score,
      liveness_status,liveness_verifier,status,submitted_at,reviewed_at,reviewer
      FROM onboarding_applications WHERE customer_id=?`).get(customerId) as
      OnboardingApplication | undefined;
    if (!row) throw new BankError("DEF_NOT_FOUND");
    return row;
  }

  apply(input: { cpf: string; name: string; persona: Persona; password: string }): OnboardingApplication {
    if (typeof input.cpf !== "string" || typeof input.name !== "string" ||
      typeof input.persona !== "string" || typeof input.password !== "string")
      throw new BankError("BIZ_ONBOARDING_INPUT_INVALID");
    const name = input.name.trim();
    if (name.length < 3 || name.length > 120 || !personas.has(input.persona) ||
      input.password.length < 12 || input.password.length > 256)
      throw new BankError("BIZ_ONBOARDING_INPUT_INVALID");
    return this.bank.transaction(() => {
      if (this.bank.db.prepare("SELECT 1 FROM customers WHERE cpf=?").get(input.cpf))
        throw new BankError("BIZ_CUSTOMER_EXISTS");
      const at = this.bank.now();
      const customerId = newId("cus", at.getTime());
      const accountId = newId("acc", at.getTime());
      const bureauScore = createHash("sha256").update(`synthetic-bureau-v1:${input.cpf}`)
        .digest()[0]! % 101;
      this.bank.addCustomer({ id: customerId, cpf: input.cpf, name,
        persona: input.persona, kyc_tier: 0, kyc_status: "none",
        risk_score: 100 - bureauScore, is_attacker_owned: false, status: "active" });
      this.bank.addAccount({ id: accountId, customer_id: customerId, kind: "checking",
        system_role: null, overdraft_limit: 0, status: "under_review" });
      this.auth.setPassword(customerId, input.password);
      this.bank.db.prepare(`INSERT INTO kyc_requests
        (customer_id,requested_tier,status,submitted_at,approved_at)
        VALUES (?,1,'submitted',?,NULL)`).run(customerId, at.toISOString());
      this.bank.db.prepare(`INSERT INTO kyc_history
        (customer_id,event,previous_tier,requested_tier,twin_at,recorded_at,reviewer)
        VALUES (?,'submitted',0,1,?,?,NULL)`)
        .run(customerId, at.toISOString(), this.bank.realNow().toISOString());
      this.bank.db.prepare(`INSERT INTO onboarding_applications
        (customer_id,account_id,bureau_score,liveness_status,liveness_verifier,
         status,submitted_at,reviewed_at,reviewer)
        VALUES (?,?,?,'pending',NULL,'pending',?,NULL,NULL)`)
        .run(customerId, accountId, bureauScore, at.toISOString());
      this.record(customerId, "submitted", "applicant");
      return this.application(customerId);
    });
  }

  attestLiveness(customerId: string, passed: boolean, verifier: string): OnboardingApplication {
    if (!actorPattern.test(verifier)) throw new BankError("BIZ_ONBOARDING_VERIFIER_INVALID");
    return this.bank.transaction(() => {
      const current = this.application(customerId);
      if (current.status !== "pending" || current.liveness_status !== "pending")
        throw new BankError("BIZ_ONBOARDING_NOT_PENDING");
      this.bank.db.prepare(`UPDATE onboarding_applications
        SET liveness_status=?,liveness_verifier=? WHERE customer_id=?`)
        .run(passed ? "passed" : "failed", verifier, customerId);
      this.record(customerId, passed ? "liveness_passed" : "liveness_failed", verifier);
      return this.application(customerId);
    });
  }

  review(customerId: string, decision: "approve" | "reject", reviewer: string): OnboardingApplication {
    if (!actorPattern.test(reviewer) || !["approve", "reject"].includes(decision))
      throw new BankError("BIZ_ONBOARDING_REVIEW_INVALID");
    return this.bank.transaction(() => {
      const current = this.application(customerId);
      if (current.status !== "pending") throw new BankError("BIZ_ONBOARDING_NOT_PENDING");
      if (current.liveness_verifier === reviewer)
        throw new BankError("DEF_ONBOARDING_REVIEW_SEPARATION");
      if (decision === "approve" && (current.liveness_status !== "passed" ||
        current.bureau_score < 20)) throw new BankError("DEF_ONBOARDING_EVIDENCE_REQUIRED");
      const approved = decision === "approve";
      this.bank.db.prepare(`UPDATE onboarding_applications
        SET status=?,reviewed_at=?,reviewer=? WHERE customer_id=?`)
        .run(approved ? "approved" : "rejected", this.bank.now().toISOString(),
          reviewer, customerId);
      this.bank.db.prepare(`UPDATE kyc_requests SET status=?,approved_at=? WHERE customer_id=?`)
        .run(approved ? "approved" : "rejected",
          approved ? this.bank.now().toISOString() : null, customerId);
      this.bank.db.prepare(`UPDATE customers SET kyc_tier=?,kyc_status=? WHERE id=?`)
        .run(approved ? 1 : 0, approved ? "approved" : "rejected", customerId);
      if (approved) this.bank.db.prepare(`INSERT INTO kyc_history
        (customer_id,event,previous_tier,requested_tier,twin_at,recorded_at,reviewer)
        VALUES (?,'approved',0,1,?,?,?)`)
        .run(customerId, this.bank.now().toISOString(),
          this.bank.realNow().toISOString(), reviewer);
      this.bank.changeAccountStatus(current.account_id,
        approved ? "active" : "frozen", reviewer, approved ? null : "kyc");
      this.record(customerId, approved ? "approved" : "rejected", reviewer);
      return this.application(customerId);
    });
  }

  private record(customerId: string, event: string, actor: string): void {
    this.bank.db.prepare(`INSERT INTO onboarding_events
      (id,customer_id,event,actor,twin_at,recorded_at) VALUES (?,?,?,?,?,?)`)
      .run(newId("onboarding", this.bank.now().getTime()), customerId, event, actor,
        this.bank.now().toISOString(), this.bank.realNow().toISOString());
  }
}
