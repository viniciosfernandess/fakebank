import type { EcosystemClient } from "../../ecosystem/src/client.ts";
import { Bank, BankError, type PixResult, type PixTransferInput } from "./bank.ts";
import { readDuePixCommands, readPendingPspCredits } from "./pix-outbox-commands.ts";

export interface SeparatedPixDispatchResult {
  spiProcessed: number;
  spiDeferred: number;
  pspCredited: number;
}

export const MAX_PIX_DISPATCH_CONCURRENCY = 16;

export type PixDispatchStage = "spi" | "psp";

export interface PixDispatchObservation {
  stage: PixDispatchStage;
  transferId: string;
  startedAtMs: number;
  finishedAtMs: number;
  result: "completed" | "deferred" | "error";
}

export interface PixDispatchOptions {
  spiConcurrency?: number;
  pspConcurrency?: number;
  observe?: (event: PixDispatchObservation) => void;
}

async function runDispatchStage<T>(items: readonly T[], concurrency: number,
  handle: (item: T) => Promise<void>): Promise<void> {
  if (concurrency === 1) {
    for (const item of items) await handle(item);
    return;
  }
  // Admit the oldest rows first, and drain every in-flight request before leaving the dispatch.
  for (let offset = 0; offset < items.length; offset += concurrency) {
    const results = await Promise.allSettled(items.slice(offset, offset + concurrency).map(handle));
    const failure = results.find((item) => item.status === "rejected");
    if (failure) throw failure.reason;
  }
}

export class SeparatedPixCoordinator {
  private readonly bank: Bank;
  private readonly ecosystem: EcosystemClient;
  private readonly onMedSettlementProgress: ((caseId: string,
    transferId: string) => Promise<void>) | undefined;
  private readonly pausePspReceipt: (() => boolean) | undefined;
  private readonly pauseMedCommand: ((transferId: string, stage: "opening" | "analysis" |
    "settlement" | "release") => boolean) | undefined;

  constructor(bank: Bank, ecosystem: EcosystemClient,
    onMedSettlementProgress?: (caseId: string, transferId: string) => Promise<void>,
    pausePspReceipt?: () => boolean,
    pauseMedCommand?: (transferId: string, stage: "opening" | "analysis" |
      "settlement" | "release") => boolean) {
    if (!bank.isSeparatedEcosystem) throw new Error("BANK_ECOSYSTEM_MODE_INVALID");
    this.bank = bank;
    this.ecosystem = ecosystem;
    this.onMedSettlementProgress = onMedSettlementProgress;
    this.pausePspReceipt = pausePspReceipt;
    this.pauseMedCommand = pauseMedCommand;
  }

  async enqueue(input: PixTransferInput): Promise<PixResult> {
    const snapshot = await this.ecosystem.recipientSnapshot(input.to, this.bank.now());
    if (!snapshot.account) throw new BankError("BIZ_PIX_EXTERNAL_REQUIRED");
    return this.bank.enqueueExternalPixWithEvidence(input,
      snapshot.account, snapshot.evidence);
  }

  async transferInternal(input: PixTransferInput): Promise<PixResult> {
    const history = await this.ecosystem.accountFraudHistory(input.to, this.bank.now());
    return this.bank.transferInternalPixWithHistory(input, history);
  }

  paymentMessages(endToEndId: string): ReturnType<EcosystemClient["paymentMessages"]> {
    return this.ecosystem.paymentMessages(endToEndId);
  }

  lookupExternalKey(key: string, at: Date): ReturnType<EcosystemClient["keySnapshot"]> {
    return this.ecosystem.keySnapshot(key, at);
  }

  medCaseProjection(caseId: string, rootTransferId: string):
    ReturnType<EcosystemClient["medCaseProjection"]> {
    return this.ecosystem.medCaseProjection(caseId, rootTransferId);
  }

  requestMed(customerId: string, transferId: string):
    ReturnType<Bank["requestMed"]> {
    const recipient = this.bank.db.prepare(`SELECT p.to_account FROM pix_transfers p
      JOIN accounts a ON a.id=p.from_account
      WHERE p.id=? AND a.customer_id=?`).get(transferId, customerId) as
      { to_account: string } | undefined;
    if (!recipient) throw new BankError("DEF_NOT_FOUND");
    return this.bank.db.prepare("SELECT 1 FROM accounts WHERE id=?")
      .get(recipient.to_account) ? this.bank.requestMed(customerId, transferId) :
      this.bank.requestExternalMed(customerId, transferId);
  }

  async dispatchMedOpenings(limit = 100): Promise<number> {
    let opened = 0;
    for (const command of this.bank.pendingExternalMedOpenings(limit)) {
      if (this.pauseMedCommand?.(command.transfer_id, "opening")) continue;
      const hops = await this.ecosystem.openMedCase({
        caseId: command.case_id, rootTransferId: command.transfer_id,
        claimAmountCents: command.claim_amount_cents,
        createdAt: command.created_at, processedAt: this.bank.now().toISOString(),
      });
      this.bank.applyExternalMedOpening(command.case_id, hops);
      opened++;
    }
    return opened;
  }

  async syncMedHoldAdditions(limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000)
      throw new BankError("BIZ_INVALID_LIMIT");
    const cases = this.bank.db.prepare(`SELECT m.id,m.transfer_id
      FROM med_cases m JOIN pix_transfers p ON p.id=m.transfer_id
      WHERE m.status IN ('open','rejection_pending_psp','settlement_pending_psp')
        AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id=p.to_account)
        AND EXISTS (SELECT 1 FROM med_psp_open_outbox o
          WHERE o.case_id=m.id AND o.acknowledged_at IS NOT NULL)
      ORDER BY m.opened_at,m.id LIMIT ?`).all(limit) as
      { id: string; transfer_id: string }[];
    let added = 0;
    for (const med of cases) {
      const projection = await this.ecosystem.medCaseProjection(med.id, med.transfer_id);
      added += this.bank.applyExternalMedHoldAdditions(med.id, projection.hops);
    }
    return added;
  }

  async dispatchMedReleases(limit = 100): Promise<number> {
    await this.syncMedHoldAdditions(limit);
    let released = 0;
    for (const command of this.bank.pendingExternalMedReleases(limit)) {
      if (this.pauseMedCommand?.(command.transfer_id, "release")) continue;
      const hops = await this.ecosystem.releaseMedCase({
        caseId: command.case_id, rootTransferId: command.transfer_id,
        releasedAt: command.created_at, processedAt: this.bank.now().toISOString(),
      });
      this.bank.applyExternalMedRelease(command.case_id, hops);
      await this.syncMedHoldAdditions(limit);
      released++;
    }
    return released;
  }

  async dispatchMedSettlements(limit = 100): Promise<number> {
    await this.syncMedHoldAdditions(limit);
    await this.dispatchMedAnalyses(limit);
    let settled = 0;
    for (const command of this.bank.pendingExternalMedSettlements(limit)) {
      if (this.pauseMedCommand?.(command.transfer_id, "settlement")) continue;
      for (let attempt = 0; attempt < 20; attempt++) {
        const hops = await this.ecosystem.settleMedCase({
          caseId: command.case_id, rootTransferId: command.transfer_id,
          endToEndId: command.end_to_end_id,
          claimAmountCents: command.claim_amount_cents,
          settledAt: command.created_at, processedAt: this.bank.now().toISOString(),
        });
        await this.onMedSettlementProgress?.(command.case_id, command.transfer_id);
        if (hops.some((hop) => hop.released_at === null)) continue;
        const timeline = await this.ecosystem.medRefundTimeline(
          command.case_id, command.transfer_id);
        this.bank.applyExternalMedSettlement(command.case_id, hops, timeline);
        await this.onMedSettlementProgress?.(command.case_id, command.transfer_id);
        await this.syncMedHoldAdditions(limit);
        settled++;
        break;
      }
    }
    return settled;
  }

  async dispatchMedAnalyses(limit = 100): Promise<number> {
    let analysed = 0;
    for (const command of this.bank.pendingExternalMedAnalyses(limit)) {
      if (this.pauseMedCommand?.(command.transfer_id, "analysis")) continue;
      const result = await this.ecosystem.analyseMedCase({
        caseId: command.case_id, rootTransferId: command.transfer_id,
        approvedAt: command.approved_at, processedAt: this.bank.now().toISOString(),
      });
      this.bank.applyExternalMedAnalysis(command.case_id, result);
      analysed++;
    }
    return analysed;
  }

  requestReturn(transferId: string, amountCents: number, idempotencyKey: string):
    ReturnType<Bank["requestExternalPixReturn"]> {
    return this.bank.requestExternalPixReturn(transferId, amountCents, idempotencyKey);
  }

  async requestCautelarReturn(holdId: string, actor: string):
    Promise<ReturnType<Bank["requestExternalCautelarReturn"]>> {
    const hold = await this.ecosystem.cautelarHold(holdId);
    if (!hold) throw new BankError("DEF_NOT_FOUND");
    return this.bank.requestExternalCautelarReturn(hold, actor);
  }

  async dispatchReturns(limit = 100): Promise<number> {
    let processed = 0;
    for (const command of this.bank.pendingExternalPixReturns(limit)) {
      let result;
      try {
        result = await this.ecosystem.returnPix({
          returnId: command.id, rootTransferId: command.transfer_id,
          endToEndId: command.end_to_end_id,
          accountId: command.recipient_account, amountCents: command.amount_cents,
          reason: command.reason, createdAt: command.created_at,
          processedAt: this.bank.now().toISOString(),
        });
      } catch (error) {
        if (error instanceof Error && error.message === "SPI_UNAVAILABLE") continue;
        throw error;
      }
      this.bank.applyExternalPixReturn(command.id, result);
      processed++;
    }
    return processed;
  }

  async dispatchCautelarReturns(limit = 100): Promise<number> {
    let processed = 0;
    for (const command of this.bank.pendingExternalCautelarReturns(limit)) {
      let result;
      try {
        result = await this.ecosystem.returnCautelar({
          returnId: command.id, holdId: command.hold_id,
          rootTransferId: command.transfer_id,
          endToEndId: command.end_to_end_id,
          accountId: command.recipient_account,
          amountCents: command.amount_cents, actor: command.actor,
          createdAt: command.created_at,
          processedAt: this.bank.now().toISOString(),
        });
      } catch (error) {
        if (error instanceof Error && ["SPI_UNAVAILABLE",
          "SPI_INSUFFICIENT_LIQUIDITY"].includes(error.message)) continue;
        throw error;
      }
      this.bank.applyExternalCautelarReturn(command.id, result);
      processed++;
    }
    return processed;
  }

  async resolveRiskHold(id: string, decision: "approve" | "reject", reviewer: string):
    Promise<ReturnType<Bank["resolveRiskPixHold"]>> {
    const hold = this.bank.riskPixHold(id);
    if (decision !== "approve" || !hold || this.bank.db.prepare(`SELECT 1 FROM accounts
      WHERE id=? AND customer_id IS NOT NULL`).get(hold.to_account))
      return this.bank.resolveRiskPixHold(id, decision, reviewer);
    const snapshot = await this.ecosystem.recipientSnapshot(hold.to_account, this.bank.now());
    return this.bank.resolveRiskPixHold(id, decision, reviewer, snapshot);
  }

  async dispatch(limit = 100, options: PixDispatchOptions = {}): Promise<SeparatedPixDispatchResult> {
    const { spiConcurrency = 1, pspConcurrency = 1, observe } = options;
    if ([spiConcurrency, pspConcurrency].some((value) => !Number.isSafeInteger(value) ||
      value < 1 || value > MAX_PIX_DISPATCH_CONCURRENCY))
      throw new Error("PIX_DISPATCH_CONCURRENCY_INVALID");

    const finish = (stage: PixDispatchStage, transferId: string, startedAtMs: number,
      result: PixDispatchObservation["result"]): void => {
      observe?.({ stage, transferId, startedAtMs, finishedAtMs: performance.now(), result });
    };
    let spiProcessed = 0;
    let spiDeferred = 0;
    const commands = readDuePixCommands(this.bank.db, this.bank.realNow(), limit);
    await runDispatchStage(commands, spiConcurrency, async (command) => {
      const startedAtMs = observe ? performance.now() : 0;
      let result: PixDispatchObservation["result"] = "error";
      try {
        let response;
        try {
          response = await this.ecosystem.submitPayment({
            endToEndId: command.end_to_end_id, toIspb: command.to_ispb,
            amountCents: command.amount, senderAccount: command.from_account,
            rootTransferId: command.id, recipientAccount: command.to_account,
            processedAt: this.bank.now().toISOString(),
            ...(command.deadline_at_real ? { deadlineAtReal: command.deadline_at_real } : {}),
          });
        } catch (error) {
          if (!(error instanceof Error) || error.message !== "SPI_UNAVAILABLE") throw error;
          spiDeferred++;
          result = "deferred";
          return;
        }
        this.bank.applyQueuedSpiResponse(command.id, response);
        spiProcessed++;
        result = "completed";
      } finally {
        finish("spi", command.id, startedAtMs, result);
      }
    });
    let pspCredited = 0;
    const credits = this.pausePspReceipt?.() ? [] : readPendingPspCredits(this.bank.db, limit);
    await runDispatchStage(credits, pspConcurrency, async (credit) => {
      const startedAtMs = observe ? performance.now() : 0;
      let result: PixDispatchObservation["result"] = "error";
      try {
        const receipt = await this.ecosystem.creditInbound({
          accountId: credit.to_account, rootTransferId: credit.transfer_id,
          endToEndId: credit.end_to_end_id, amountCents: credit.amount_cents,
          senderAccount: credit.from_account, settledAt: credit.settled_at,
          processedAt: this.bank.now().toISOString(),
        });
        this.bank.acknowledgePspCredit(credit.transfer_id, receipt.cautelar?.reason ?? null);
        pspCredited++;
        result = "completed";
      } finally {
        finish("psp", credit.transfer_id, startedAtMs, result);
      }
    });
    await this.dispatchReturns(limit);
    await this.dispatchCautelarReturns(limit);
    await this.dispatchMedOpenings(limit);
    await this.syncMedHoldAdditions(limit);
    await this.dispatchMedReleases(limit);
    await this.dispatchMedAnalyses(limit);
    await this.dispatchMedSettlements(limit);
    return { spiProcessed, spiDeferred, pspCredited };
  }
}
