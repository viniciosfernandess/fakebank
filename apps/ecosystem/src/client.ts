import { fork, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { PspNetwork } from "../../world/src/ecosystem/psp.ts";
import type { SpiMessage } from "../../world/src/ecosystem/spi.ts";
import type { PixRecipientEvidence } from "../../world/src/risk/engine.ts";
import type { DictFraudCounter } from "../../world/src/ecosystem/dict-fraud-history.ts";
import type { PspNoticeAccess, PspNoticePage } from
  "../../world/src/ecosystem/psp-notice-access.ts";
import { BankError, type ExternalPixKeyLookup } from "../../world/src/bank.ts";

interface Reply { version: 1; id: number; ok: boolean; value?: unknown; code?: string }
export interface EcosystemOperations {
  spi: { total: number; last_at: string | null };
  cautelar: { total: number; last_at: string | null };
  pi_accounts: { ispb: string; name: string; pi_balance_cents: number }[];
  recent_spi: { id: number; message_type: string; end_to_end_ref: string;
    created_at: string }[];
  recent_cautelar: { ref: string; account_ref: string; amount_cents: number;
    reason: string; status: string; created_at: string; resolved_at: string | null;
    resolved_by: string | null }[];
  recent_notices: { id: number; account_ref: string; kind: string;
    amount_cents: number; message_pt: string; created_at: string }[];
}
export interface CautelarReviewPage {
  total: number;
  rows: { id: string; account_id: string; root_transfer_id: string;
    amount_cents: number; reason: string; created_at: string;
    expires_at: string }[];
}
type Pending = { resolve: (value: unknown) => void; reject: (error: Error) => void;
  timer: NodeJS.Timeout };

export class EcosystemClient {
  private readonly child: ChildProcess;
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  private stopped = false;
  private closing?: Promise<void>;
  readonly processId: number;

  private constructor(child: ChildProcess, processId: number) {
    this.child = child;
    this.processId = processId;
    child.on("message", (raw: unknown) => {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
      const reply = raw as Partial<Reply>;
      if (reply.version !== 1 || !Number.isSafeInteger(reply.id)) return;
      const pending = this.pending.get(reply.id!);
      if (!pending) return;
      this.pending.delete(reply.id!);
      clearTimeout(pending.timer);
      if (reply.ok === true) pending.resolve(reply.value);
      else {
        const code = typeof reply.code === "string" ? reply.code :
          "ECOSYSTEM_REQUEST_FAILED";
        pending.reject(/^(DEF|BIZ)_[A-Z0-9_]+$/.test(code) ?
          new BankError(code) : new Error(code));
      }
    });
    child.on("exit", () => {
      this.stopped = true;
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("ECOSYSTEM_PROCESS_EXITED"));
      }
      this.pending.clear();
    });
    child.on("error", () => {
      this.stopped = true;
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("ECOSYSTEM_PROCESS_ERROR"));
      }
      this.pending.clear();
    });
  }

  static async start(path: string): Promise<EcosystemClient> {
    if (!existsSync(path)) throw new Error("ECOSYSTEM_FILE_MISSING");
    const worker = fileURLToPath(new URL("./worker.ts", import.meta.url));
    const child = fork(worker, [path], { execArgv: ["--disable-warning=ExperimentalWarning",
      "--experimental-strip-types"], env: { PATH: process.env.PATH ?? "" },
      stdio: ["ignore", "ignore", "ignore", "ipc"] });
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        child.kill();
        reject(new Error("ECOSYSTEM_STARTUP_TIMEOUT"));
      }, 5_000);
      const fail = () => { clearTimeout(timeout); reject(new Error("ECOSYSTEM_STARTUP_FAILED")); };
      child.once("exit", fail);
      child.once("error", fail);
      child.on("message", (raw: unknown) => {
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
        const ready = raw as { version?: unknown; ready?: unknown; pid?: unknown;
          startupError?: unknown };
        if (ready.version === 1 && typeof ready.startupError === "string") {
          clearTimeout(timeout);
          child.off("exit", fail);
          child.off("error", fail);
          reject(new Error(ready.startupError));
          return;
        }
        if (ready.version !== 1 || ready.ready !== true ||
          !Number.isSafeInteger(ready.pid)) return;
        clearTimeout(timeout);
        child.off("exit", fail);
        child.off("error", fail);
        resolve(new EcosystemClient(child, ready.pid as number));
      });
    });
  }

  private request<T>(operation: string, args: Record<string, unknown> = {},
    timeoutMs = 30_000): Promise<T> {
    if (this.stopped || !this.child.connected)
      return Promise.reject(new Error("ECOSYSTEM_PROCESS_EXITED"));
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error("ECOSYSTEM_REQUEST_TIMEOUT"));
      }, timeoutMs);
      this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject, timer });
      this.child.send({ version: 1, id, operation, args }, (error) => {
        if (error && this.pending.delete(id)) { clearTimeout(timer); reject(error); }
      });
    });
  }

  account(accountId: string): Promise<{ id: string; ispb: string; status: string;
    fraud_flag: number } | null> {
    return this.request("account", { accountId });
  }
  recipientEvidence(accountId: string, at: Date): Promise<PixRecipientEvidence> {
    return this.request("recipientEvidence", { accountId, at: at.toISOString() });
  }
  accountFraudHistory(accountId: string, at: Date): Promise<DictFraudCounter> {
    return this.request("accountFraudHistory", { accountId, at: at.toISOString() });
  }
  recipientSnapshot(accountId: string, at: Date): Promise<{
    account: { id: string; ispb: string; status: string; fraud_flag: number } | null;
    evidence: PixRecipientEvidence;
  }> {
    return this.request("recipientSnapshot", { accountId, at: at.toISOString() });
  }
  lookup(key: string): Promise<{ id: string; ispb: string; status: string;
    fraud_flag: number; holder_name: string } | null> {
    return this.request("lookup", { key });
  }
  keySnapshot(key: string, at: Date): Promise<ExternalPixKeyLookup | null> {
    return this.request("keySnapshot", { key, at: at.toISOString() });
  }
  syntheticRecipients(): Promise<{ id: string; pixKey: string }[]> {
    return this.request("syntheticRecipients");
  }
  activeCautelarSummary(at: Date): Promise<{ account_id: string;
    holds: number; blocked_cents: number }[]> {
    return this.request("activeCautelarSummary", { at: at.toISOString() });
  }
  operations(): Promise<EcosystemOperations> {
    return this.request("operations");
  }
  cautelarReviewPage(at: Date, afterExpiry: string, afterId: string):
    Promise<CautelarReviewPage> {
    return this.request("cautelarReviewPage", { at: at.toISOString(),
      afterExpiry, afterId });
  }
  paymentMessages(endToEndId: string): Promise<SpiMessage[]> {
    return this.request("paymentMessages", { endToEndId });
  }
  cautelarHold(holdId: string): Promise<ReturnType<PspNetwork["cautelarHold"]> | null> {
    return this.request("cautelarHold", { holdId });
  }
  medCaseProjection(caseId: string, rootTransferId: string): Promise<{
    hops: { id: string; case_id: string; root_transfer_id: string;
      account_id: string; ispb: string;
      blocked_cents: number; refunded_cents: number; created_at: string;
      released_at: string | null }[];
    path: ReturnType<PspNetwork["path"]> }> {
    return this.request("medCaseProjection", { caseId, rootTransferId });
  }
  moneyFlowProjection(rootTransferId: string, caseId?: string):
    Promise<Awaited<ReturnType<EcosystemClient["medCaseProjection"]>> & {
      trace: ReturnType<PspNetwork["trace"]>;
      refundSteps: Awaited<ReturnType<EcosystemClient["medRefundTimeline"]>> }> {
    return this.request("moneyFlowProjection", { rootTransferId,
      ...(caseId ? { caseId } : {}) });
  }
  openMedCase(input: { caseId: string; rootTransferId: string;
    claimAmountCents: number; createdAt: string; processedAt: string }):
    Promise<Awaited<ReturnType<EcosystemClient["medCaseProjection"]>>["hops"]> {
    return this.request("openMedCase", input);
  }
  releaseMedCase(input: { caseId: string; rootTransferId: string;
    releasedAt: string; processedAt: string }):
    Promise<Awaited<ReturnType<EcosystemClient["medCaseProjection"]>>["hops"]> {
    return this.request("releaseMedCase", input);
  }
  analyseMedCase(input: { caseId: string; rootTransferId: string;
    approvedAt: string; processedAt: string }):
    Promise<{ case_id: string; root_transfer_id: string; analysed_at: string }> {
    return this.request("analyseMedCase", input);
  }
  medRefundTimeline(caseId: string, rootTransferId: string): Promise<{
    case_id: string; ispb: string; sequence: number; requested_at: string;
    deadline_at: string; processed_at: string | null;
    refunded_cents: number | null }[]> {
    return this.request("medRefundTimeline", { caseId, rootTransferId });
  }
  settleMedCase(input: { caseId: string; rootTransferId: string;
    endToEndId: string; claimAmountCents: number; settledAt: string;
    processedAt: string }):
    Promise<Awaited<ReturnType<EcosystemClient["medCaseProjection"]>>["hops"]> {
    return this.request("settleMedCase", input);
  }
  bankPiBalance(): Promise<number> {
    return this.request("bankPiBalance");
  }
  spiAvailability(): Promise<{ available: boolean; changed_at: string;
    changed_by: string }> {
    return this.request("spiAvailability");
  }
  dictHealth(): Promise<{ ready: true }> {
    return this.request("dictHealth");
  }
  async snapshot(destination: string): Promise<void> {
    const result = await this.request<{ saved: boolean }>("snapshot", { destination }, 120_000);
    if (result.saved !== true) throw new Error("ECOSYSTEM_SNAPSHOT_REPLY_INVALID");
  }
  spiAvailabilityHistory(after: number): Promise<{ row_cursor: number; id: number;
    available: boolean; changed_at: string; changed_by: string }[]> {
    return this.request("spiAvailabilityHistory", { after });
  }
  spiSetAvailability(available: boolean, actor: string):
    ReturnType<EcosystemClient["spiAvailability"]> {
    return this.request("spiSetAvailability", { available, actor });
  }
  submitPayment(input: { endToEndId: string; toIspb: string;
    amountCents: number; senderAccount: string; rootTransferId: string;
    recipientAccount: string;
    deadlineAtReal?: string; processedAt?: string }):
    Promise<SpiMessage & { type: "pacs.002"; status: "ACSC" | "RJCT" }> {
    return this.request("submitPayment", input);
  }
  returnPix(input: { returnId: string; rootTransferId: string;
    endToEndId: string; accountId: string; amountCents: number;
    reason: "ordinary"; createdAt: string; processedAt: string }):
    Promise<{ outcome: "accepted" | "rejected";
      failureReason: string | null; fromIspb: string }> {
    return this.request("returnPix", input);
  }
  returnCautelar(input: { returnId: string; holdId: string;
    rootTransferId: string; endToEndId: string; accountId: string;
    amountCents: number; actor: string; createdAt: string;
    processedAt: string }): Promise<{ outcome: "accepted" | "rejected";
      failureReason: string | null; fromIspb: string }> {
    return this.request("returnCautelar", input);
  }
  creditInbound(input: { accountId: string; rootTransferId: string;
    endToEndId: string; amountCents: number; senderAccount: string;
    settledAt: string; processedAt?: string }): Promise<{ credited: true;
      cautelar: { id: string; reason: string } | null }> {
    return this.request("creditInbound", input);
  }
  transferPspFunds(input: { rootTransferId: string; fromAccount: string;
    toAccount: string; amountCents: number; idempotencyKey: string;
    processedAt: string }): Promise<ReturnType<PspNetwork["transfer"]>> {
    return this.request("pspTransfer", input);
  }
  cashOutPspFunds(input: { rootTransferId: string; accountId: string;
    amountCents: number; idempotencyKey: string;
    processedAt: string }): Promise<ReturnType<PspNetwork["cashOut"]>> {
    return this.request("pspCashOut", input);
  }
  placePspCautelar(input: { rootTransferId: string; accountId: string;
    amountCents: number; reason: string; idempotencyKey: string;
    processedAt: string }): Promise<NonNullable<ReturnType<PspNetwork["cautelarHold"]>>> {
    return this.request("pspPlaceCautelar", input);
  }
  releasePspCautelar(holdId: string, actor: string, processedAt: string):
    Promise<NonNullable<ReturnType<PspNetwork["cautelarHold"]>>> {
    return this.request("pspReleaseCautelar", { holdId, actor, processedAt });
  }
  expirePspCautelar(processedAt: string): Promise<number> {
    return this.request("pspExpireCautelar", { processedAt });
  }
  reconcilePsp(at?: Date): Promise<ReturnType<PspNetwork["reconcile"]>> {
    return this.request("reconcilePsp", at ? { at: at.toISOString() } : {});
  }
  beginLogin(identityId: string, clientNonce: string, signature: string):
    Promise<ReturnType<PspNoticeAccess["beginLogin"]>> {
    return this.request("noticeBeginLogin", { identityId, clientNonce, signature });
  }
  completeLogin(identityId: string, challengeId: string, signature: string):
    Promise<ReturnType<PspNoticeAccess["completeLogin"]>> {
    return this.request("noticeCompleteLogin", { identityId, challengeId, signature });
  }
  beginOperation(token: string, method: "GET" | "POST",
    request: { cursor: string | null; limit: number } | Record<string, never>):
    Promise<ReturnType<PspNoticeAccess["beginOperation"]>> {
    return this.request("noticeBeginOperation", { token, method, ...request });
  }
  notices(token: string, challengeId: string, signature: string,
    cursorToken: string | null, limit: number): Promise<PspNoticePage> {
    return this.request("noticePage", { token, challengeId, signature,
      cursor: cursorToken, limit });
  }
  async logout(token: string, challengeId: string, signature: string): Promise<void> {
    await this.request("noticeLogout", { token, challengeId, signature });
  }
  async provision(identityId: string, accountId: string, publicKey: string,
    actor: string): Promise<void> {
    await this.request("noticeProvision", { identityId, accountId, publicKey, actor });
  }
  async revoke(identityId: string, actor: string): Promise<void> {
    await this.request("noticeRevoke", { identityId, actor });
  }
  async reprovision(identityId: string, publicKey: string, actor: string): Promise<void> {
    await this.request("noticeReprovision", { identityId, publicKey, actor });
  }
  close(): Promise<void> {
    return this.closing ??= this.closeWorker();
  }

  private async closeWorker(): Promise<void> {
    if (this.stopped) return;
    try {
      await this.request("close");
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (!this.stopped && this.child.connected && code !== "EPIPE" &&
          code !== "ERR_IPC_CHANNEL_CLOSED") throw error;
    }
    await new Promise<void>((resolve) => {
      if (this.child.exitCode !== null || this.child.signalCode !== null) {
        resolve();
        return;
      }
      this.child.once("exit", () => resolve());
    });
  }
}
