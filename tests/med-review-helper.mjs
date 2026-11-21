import { OperatorAuth } from "../apps/world/src/operator-auth.ts";
import { MedOperatorReview } from "../apps/server/src/med-operator-review.ts";

export function reviewMedForTest(bank, caseId, transferId, decision = "approved") {
  const auth = new OperatorAuth(bank);
  const admin = bank.db.prepare(`SELECT id FROM operator_accounts WHERE role='admin'
    AND disabled_at IS NULL LIMIT 1`).get();
  const adminId = admin?.id ?? "medadmin";
  if (!admin) auth.bootstrap(adminId, "med-review-admin-password");
  if (!bank.db.prepare("SELECT 1 FROM operator_accounts WHERE id='medmaker'").get())
    auth.add(adminId, "medmaker", "maker", "med-review-maker-password");
  if (!bank.db.prepare("SELECT 1 FROM operator_accounts WHERE id='medreviewer'").get())
    auth.add(adminId, "medreviewer", "reviewer", "med-review-checker-password");
  const row = bank.db.prepare("SELECT transfer_id FROM med_cases WHERE id=?")
    .get(caseId);
  if (row?.transfer_id !== transferId) throw new Error("MED_TEST_TRANSFER_MISMATCH");
  const review = new MedOperatorReview(bank);
  const proposal = review.propose(caseId, decision, `med-review:${caseId}`, "medmaker",
    decision === "approved" ? "fraud_indicators" : "insufficient_evidence",
    decision === "approved" ? "Synthetic review found fraud indicators for this case." :
      "Synthetic review did not find enough fraud evidence for this case.");
  review.confirm(proposal.id, "medreviewer");
}
