import { mkdirSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";
import { Bank, BankError, type PixResult,
  type PixTransferInput } from "../../world/src/bank.ts";
import { AuthEngine } from "../../world/src/auth.ts";
import { createTwinApi } from "../../world/src/api.ts";
import { Gateway } from "../../world/src/gateway.ts";
import { TwinClock } from "../../world/src/clock.ts";
import { seedBank, type SeedOptions } from "../../world/src/seed.ts";
import { CustomerSimulator } from "../../world/src/simulator.ts";
import { SentinelEngine } from "../../world/src/sentinels.ts";
import { FeatureRegistry } from "../../world/src/features.ts";
import { ScheduledPix } from "../../world/src/scheduled-pix.ts";
import { PixAutomatic } from "../../world/src/pix-automatic.ts";
import { CardsEngine } from "../../world/src/cards.ts";
import { CardNetwork } from "../../world/src/ecosystem/card-network.ts";
import { CardRecurring } from "../../world/src/card-recurring.ts";
import type { EventStore } from "../../../packages/event-store/src/index.ts";
import { OpsControl } from "../../../packages/ops-control/src/index.ts";
import { BudgetLedger } from "./budget.ts";
import { RoundJanitor } from "./round-janitor.ts";
import { CampaignScheduleStore } from "./schedule-store.ts";
import type { StoredFeature, StoredSlot } from "./schedule-store.ts";
import { CampaignRestartRequired } from "./campaign-restart.ts";
import { RoundNarrator } from "./round-narrator.ts";
import type { AgentTransport } from "./agent-loop.ts";
import type { AgentRuntime } from "./runtime/agent-runtime.ts";
import { HealthTracker } from "./health-tracker.ts";
import { CodexQuotaGate } from "./runtime/quota-gate.ts";
import { BlueContainment } from "./blue-containment.ts";
import { withTrace } from "../../world/src/telemetry.ts";
import { LedgerAnchorStore } from "./ledger-anchors.ts";
import { PeriodCloseAnchorStore } from "./period-close-anchors.ts";
import { HourlyLedgerProofStore } from "./hourly-ledger-proof.ts";
import { canaryExcludedCustomers } from "./canary-exclusions.ts";
import { ensureCanaryFixture } from "./canary-fixture.ts";
import { EcosystemClient, type CautelarReviewPage,
  type EcosystemOperations } from "../../ecosystem/src/client.ts";
import { CrossBookVerifierClient } from "../../ecosystem/src/verifier-client.ts";
import type { CrossBookObservation } from "./cross-book-summary.ts";
import { SeparatedPixCoordinator } from "../../world/src/separated-pix-coordinator.ts";
import { PixOutcomeController } from "../../world/src/pix-outcome-controller.ts";
import { loadPixOutcomePolicy } from "../../world/src/pix-outcome-policy-file.ts";
import { publishSeparatedMoneyFlowMedProgress } from "./money-flow-disclosure.ts";
import type { DictFraudCounter } from "../../world/src/ecosystem/dict-fraud-history.ts";
import type { SeparatedSentinelSources } from "../../world/src/sentinels.ts";

const LAB_SPI_LATENCY_BYTES = Buffer.from(JSON.stringify({ version: 3,
  min_ms: 20, p50_ms: 80, p99_ms: 1500, max_ms: 1700,
  timeout_ms: 60_000 }));

export type RoundRunOutcome = "watching" | { partialReasons: string[] } | void;

interface CampaignRuntimeSplit {
  ecosystem: EcosystemClient;
  verifier: CrossBookVerifierClient;
  externalRecipients: { id: string; pixKey: string }[];
}

type CampaignRuntimeInput = { dataDir: string; events: EventStore; startBrtDate?: string;
  faultLab?: boolean;
  onDemand?: boolean;
  continuousIntervalMinutes?: number;
  seed?: SeedOptions; runRound?: (slot: StoredSlot) => Promise<RoundRunOutcome>;
  observeDeployment?: () => Promise<boolean>;
  observeDelayedEffects?: () => void;
  onExpiredRound?: (roundId: string, endsAt: string) => void;
  runFeature?: (slot: StoredFeature) => Promise<{ approved: boolean; reason?: string;
    titlePt?: string; summaryPt?: string }>;
  realNow?: () => Date;
  twinSpeed?: number;
  narratorTransport?: AgentTransport;
  narratorRuntime?: AgentRuntime;
  legacyBudget?: boolean;
  plantCanaries?: boolean;
  onRestart?: () => void;
  onError?: (error: unknown) => void;
  split?: CampaignRuntimeSplit };

export class CampaignRuntime {
  readonly bank: Bank;
  readonly bankPath: string;
  readonly clock: TwinClock;
  readonly auth: AuthEngine;
  readonly gateway: Gateway;
  readonly simulator: CustomerSimulator;
  readonly sentinels: SentinelEngine;
  readonly scheduledPix: ScheduledPix;
  readonly pixAutomatic: PixAutomatic;
  readonly cardNetwork: CardNetwork;
  readonly cardRecurring: CardRecurring;
  readonly budget: BudgetLedger | undefined;
  readonly health: HealthTracker;
  readonly schedule: CampaignScheduleStore;
  readonly janitor: RoundJanitor;
  readonly ledgerAnchors: LedgerAnchorStore;
  readonly periodCloseAnchors: PeriodCloseAnchorStore;
  readonly hourlyLedgerProofs: HourlyLedgerProofStore;
  readonly events: EventStore;
  readonly ops: OpsControl;
  readonly quota: CodexQuotaGate;
  readonly containment: BlueContainment;
  readonly runRound: ((slot: StoredSlot) => Promise<RoundRunOutcome>) | undefined;
  readonly observeDeployment: (() => Promise<boolean>) | undefined;
  readonly observeDelayedEffects: (() => void) | undefined;
  readonly runFeature: ((slot: StoredFeature) => Promise<{ approved: boolean; reason?: string;
    titlePt?: string; summaryPt?: string }>) | undefined;
  readonly realNow: () => Date;
  readonly onDemand: boolean;
  readonly faultLab: boolean;
  readonly continuousIntervalMs: number | undefined;
  lastTelemetry: { checked_at: string; areas: ReturnType<SentinelEngine["telemetry"]>;
    by_area: Record<string, number>; honest_blocked: number } | null = null;
  lastCrossBook: CrossBookObservation | null = null;
  private readonly api: ReturnType<typeof createTwinApi>;
  private readonly split: CampaignRuntimeSplit | undefined;
  private readonly pixCoordinator: SeparatedPixCoordinator | undefined;
  private readonly pixOutcome: PixOutcomeController | undefined;
  private internalPixHistory = new Map<string, DictFraudCounter>();
  private readonly timers: NodeJS.Timeout[] = [];
  private readonly unsubscribeAgentTelemetry: () => void;
  private busy = false;
  private dispatcherBusy = false;
  private activeSentinelScan: Promise<void> | undefined;
  private activeStreamScan: Promise<void> | undefined;
  private closed = false;
  private stopping = false;
  private activeRound: Promise<void> | undefined;
  private activeRoundId: string | undefined;
  private activeFeature: Promise<void> | undefined;
  private faultActiveReader: ((id: string, runId?: string) => boolean) | undefined;
  private labStatementOutage: { runId: string; customerId: string;
    accountId: string } | undefined;
  private labLoanOfferOutage: { runId: string; customerId: string } | undefined;
  private labPixAutomaticMandatesOutage: { runId: string; customerId: string } | undefined;
  private labKycStatusOutage: { runId: string; customerId: string } | undefined;
  private labKycSubmissionOutage: { runId: string; customerId: string } | undefined;
  static async openSeparated(input: Omit<CampaignRuntimeInput, "split">): Promise<CampaignRuntime> {
    const ecosystem = await EcosystemClient.start(join(input.dataDir, "ecosystem.sqlite"));
    let verifier: CrossBookVerifierClient | undefined;
    try {
      verifier = await CrossBookVerifierClient.start(join(input.dataDir, "bank.sqlite"),
        join(input.dataDir, "ecosystem.sqlite"));
      const externalRecipients = await ecosystem.syntheticRecipients();
      return new CampaignRuntime({ ...input, split: { ecosystem, verifier,
        externalRecipients } });
    } catch (error) {
      await verifier?.close();
      await ecosystem.close();
      throw error;
    }
  }

  constructor(input: CampaignRuntimeInput) {
    mkdirSync(input.dataDir, { recursive: true });
    this.bankPath = join(input.dataDir, "bank.sqlite");
    this.events = input.events;
    this.ops = new OpsControl(input.dataDir);
    this.realNow = input.realNow ?? (() => new Date());
    this.onDemand = input.onDemand ?? false;
    this.faultLab = input.faultLab ?? false;
    if (input.continuousIntervalMinutes !== undefined && (!this.onDemand ||
      !Number.isSafeInteger(input.continuousIntervalMinutes) ||
      input.continuousIntervalMinutes < 1 || input.continuousIntervalMinutes > 1440))
      throw new Error("CONTINUOUS_INTERVAL_INVALID");
    this.continuousIntervalMs = input.continuousIntervalMinutes === undefined ? undefined :
      input.continuousIntervalMinutes * 60_000;
    this.quota = new CodexQuotaGate(input.events, this.realNow);
    this.split = input.split;
    const outcomePolicy = this.split && process.env.PIX_OUTCOME_ENGINE === "1" ?
      loadPixOutcomePolicy(process.env.PIX_OUTCOME_POLICY_FILE) : undefined;
    let clock: TwinClock | undefined;
    this.bank = new Bank(this.bankPath, () => clock?.now() ?? this.realNow(), this.realNow,
      this.split ? { ecosystemMode: "separated",
        ...(this.faultLab ? { spiLatencyBytes: LAB_SPI_LATENCY_BYTES } : {}) } : {});
    this.pixCoordinator = this.split ?
      new SeparatedPixCoordinator(this.bank, this.split.ecosystem,
        async (_caseId, transferId) => {
          try {
            await publishSeparatedMoneyFlowMedProgress(this.bank, this.events, transferId,
              (rootTransferId, caseId) =>
                this.split!.ecosystem.moneyFlowProjection(rootTransferId, caseId));
          } catch (error) { this.onError(error); }
        }, () => Boolean(this.faultActiveReader?.("psp_receipt_delayed")),
        this.faultLab ? (transferId, stage) => {
          const fixture = `med_${stage}_delayed`;
          const row = this.bank.db.prepare("SELECT idempotency_key FROM pix_transfers WHERE id=?")
            .get(transferId) as { idempotency_key: string } | undefined;
          const key = row?.idempotency_key.match(/^sim:([0-9a-f-]{36}):(med_[a-z_]+_delayed):0$/);
          return Boolean(key && key[2] === fixture && this.faultActiveReader?.(fixture, key[1]));
        } : undefined) : undefined;
    this.pixOutcome = this.pixCoordinator && outcomePolicy ?
      new PixOutcomeController(this.pixCoordinator, this.bank.db, this.realNow, outcomePolicy) : undefined;
    this.containment = new BlueContainment(this.bank, this.events);
    const speed = input.twinSpeed ?? Number(process.env.TWIN_SPEED || 12);
    if (!Number.isFinite(speed) || speed < 1 || speed > 64)
      throw new Error("TWIN_SPEED must be between 1 and 64");
    const oldClock = this.bank.db.prepare("SELECT sql FROM sqlite_master WHERE name='runtime_clock'")
      .get() as { sql: string } | undefined;
    if (oldClock?.sql.includes("CHECK(speed=12)")) {
      this.bank.db.exec(`BEGIN IMMEDIATE;
        ALTER TABLE runtime_clock RENAME TO runtime_clock_legacy;
        CREATE TABLE runtime_clock (
          id INTEGER PRIMARY KEY CHECK(id=1), real_start_ms INTEGER NOT NULL,
          twin_start_ms INTEGER NOT NULL, speed REAL NOT NULL CHECK(speed>0 AND speed<=64)
        );
        INSERT INTO runtime_clock SELECT * FROM runtime_clock_legacy;
        DROP TABLE runtime_clock_legacy;
        COMMIT;`);
    }
    this.bank.db.exec(`CREATE TABLE IF NOT EXISTS runtime_clock (
      id INTEGER PRIMARY KEY CHECK(id=1), real_start_ms INTEGER NOT NULL,
      twin_start_ms INTEGER NOT NULL, speed REAL NOT NULL CHECK(speed>0 AND speed<=64)
    );`);
    const anchor = this.bank.db.prepare("SELECT real_start_ms,twin_start_ms,speed FROM runtime_clock WHERE id=1")
      .get() as { real_start_ms: number; twin_start_ms: number; speed: number } | undefined;
    const real = this.realNow().getTime();
    if (!anchor) this.bank.db.prepare("INSERT INTO runtime_clock VALUES (1,?,?,?)").run(real, real, speed);
    const twinNow = anchor ? anchor.twin_start_ms + (real - anchor.real_start_ms) * anchor.speed : real;
    if (anchor && anchor.speed !== speed) this.bank.db.prepare(`UPDATE runtime_clock
      SET real_start_ms=?,twin_start_ms=?,speed=? WHERE id=1`).run(real, twinNow, speed);
    clock = new TwinClock(new Date(twinNow), () => this.realNow().getTime(), speed);
    this.clock = clock;
    const seeded = this.bank.db.prepare("SELECT COUNT(*) n FROM customers").get() as { n: number };
    if (!seeded.n) {
      if (this.split) throw new Error("SEPARATED_RUNTIME_UNSEEDED");
      seedBank(this.bank, { ...input.seed,
        openWeaknesses: false });
    }
    this.ledgerAnchors = new LedgerAnchorStore(this.bank, this.events,
      join(input.dataDir, "ledger-anchors"), this.realNow);
    this.periodCloseAnchors = new PeriodCloseAnchorStore(this.bank, this.events, this.realNow);
    this.hourlyLedgerProofs = new HourlyLedgerProofStore(this.bank, this.events);
    this.auth = new AuthEngine(this.bank);
    const partnerKey = randomBytes(32).toString("hex");
    this.api = createTwinApi(this.bank, this.auth, { partnerKey,
      ...(this.faultLab ? { labStatementUnavailable: (customerId: string,
        accountId: string) => this.labStatementOutage?.customerId === customerId &&
        this.labStatementOutage.accountId === accountId,
        labLoanOfferUnavailable: (customerId: string) =>
          this.labLoanOfferOutage?.customerId === customerId,
        labPixAutomaticMandatesUnavailable: (customerId: string) =>
          this.labPixAutomaticMandatesOutage?.customerId === customerId,
        labKycStatusUnavailable: (customerId: string) =>
          this.labKycStatusOutage?.customerId === customerId,
        labKycSubmissionUnavailable: (customerId: string) =>
          this.labKycSubmissionOutage?.customerId === customerId } : {}),
      ...(this.split ? { pspNotices: this.split.ecosystem,
        pixCoordinator: this.pixCoordinator! } : {}) });
    this.gateway = new Gateway(this.bank, this.api);
    const internalTransfer = this.split ?
      (input: PixTransferInput) => this.transferSplitInternal(input) : undefined;
    this.scheduledPix = new ScheduledPix(this.bank,
      new FeatureRegistry(this.bank, this.events), internalTransfer);
    this.pixAutomatic = new PixAutomatic(this.bank, internalTransfer);
    this.cardNetwork = new CardNetwork(this.bank, new CardsEngine(this.bank));
    this.cardRecurring = new CardRecurring(this.bank, this.cardNetwork);
    this.simulator = new CustomerSimulator(this.bank, this.auth, this.gateway, this.events,
      partnerKey, join(input.dataDir, "simulator-device-keys.sqlite"), clock.speed,
      this.split ? { externalRecipients: this.split.externalRecipients,
        dispatchPendingPix: () => this.dispatchPendingPix(),
        spiStatus: async () => ({ available:
          (await this.split!.ecosystem.spiAvailability()).available }) } : undefined,
      canaryExcludedCustomers(this.bank, join(input.dataDir, "source-health.sqlite")),
      this.faultLab ? 8 : undefined);
    if (input.plantCanaries) ensureCanaryFixture(this.bank, this.auth, input.dataDir);
    this.sentinels = new SentinelEngine(this.bank, this.events,
      join(input.dataDir, "source-health.sqlite"));
    this.budget = input.legacyBudget === false ? undefined :
      new BudgetLedger(this.events, this.realNow);
    this.health = new HealthTracker(this.bank, this.events, this.realNow);
    this.schedule = new CampaignScheduleStore(this.events);
    const existingStart = this.onDemand ? this.events.db.prepare(`SELECT start_brt_date FROM campaign_slots
      LIMIT 1`).get() as { start_brt_date: string } | undefined : undefined;
    if (input.startBrtDate) this.schedule.prepare(existingStart?.start_brt_date ?? input.startBrtDate);
    const narrator = input.narratorRuntime || input.narratorTransport ?
      new RoundNarrator(this.events, this.budget, input.narratorTransport,
        input.narratorRuntime) : undefined;
    this.janitor = new RoundJanitor({ bank: this.bank, events: this.events,
      schedule: this.schedule, backupRoot: join(input.dataDir, "snapshots"),
      simulatorKeys: this.simulator.deviceKeys,
      ledgerAnchors: this.ledgerAnchors,
      periodCloseAnchors: this.periodCloseAnchors,
      sourceHealthPath: join(input.dataDir, "source-health.sqlite"),
      ...(this.split ? { verifyCrossBook: () => this.split!.verifier.verify(),
        ecosystemSnapshot: (destination: string) => this.split!.ecosystem.snapshot(destination) } : {}),
      scheduleNext: !this.onDemand,
      ...(input.onExpiredRound ? { onExpiredRound: input.onExpiredRound } : {}),
      ...(narrator ? { narrate: narrator.run.bind(narrator) } : {}) });
    this.runRound = input.runRound;
    this.observeDeployment = input.observeDeployment;
    this.observeDelayedEffects = input.observeDelayedEffects;
    this.runFeature = input.runFeature;
    this.onRestart = input.onRestart ?? (() => undefined);
    this.onError = input.onError ?? (() => undefined);
    this.unsubscribeAgentTelemetry = this.events.subscribe((event) => {
      if (!["agent.spawned", "tool.called", "agent.finished", "integrity.violation"]
        .includes(event.type)) return;
      try {
        const failed = event.type === "integrity.violation" ||
          event.public.ok === false ||
          (event.type === "agent.finished" && event.public.outcome !== "ok");
        withTrace(event.id, () => this.bank.telemetry.emit({ source: "agent",
          category: "workflow", action: event.type,
          outcome: failed ? "failure" : "success",
          severity: failed ? "warn" : "info", counterparty: event.actor.id,
          message: event.public_summary_pt }));
      } catch (error) {
        try { this.onError(error); } catch { /* Event delivery must survive telemetry failure. */ }
      }
    });
  }
  private readonly onError: (error: unknown) => void;
  private readonly onRestart: () => void;
  private transferSplitInternal(input: PixTransferInput): PixResult {
    const history = this.internalPixHistory.get(input.to);
    if (!history) throw new Error("SEPARATED_DICT_EVIDENCE_MISSING");
    return this.bank.transferInternalPixWithHistory(input, history);
  }
  private async refreshDueInternalPixHistory(kind: "scheduled" | "automatic"):
    Promise<void> {
    if (!this.split) return;
    const at = this.bank.now();
    const rows = kind === "scheduled" ? this.bank.db.prepare(`SELECT DISTINCT id FROM (
      SELECT to_account id FROM scheduled_pix WHERE status='active' AND next_run_at<=?
      AND NOT EXISTS (SELECT 1 FROM scheduled_pix_executions e
        WHERE e.job_id=scheduled_pix.id AND e.due_at=scheduled_pix.next_run_at
          AND e.status='review_pending')
      ORDER BY next_run_at,id LIMIT 100)`).all(at.toISOString()) as { id: string }[] :
      this.bank.db.prepare(`SELECT DISTINCT id FROM (
        SELECT m.merchant_account id FROM pix_automatic_charges c
        JOIN pix_automatic_mandates m ON m.id=c.mandate_id
        WHERE c.status='pending' AND COALESCE(c.next_attempt_at,c.due_at)<=?
        ORDER BY COALESCE(c.next_attempt_at,c.due_at),c.id LIMIT 100)`)
        .all(at.toISOString()) as { id: string }[];
    const pairs = await Promise.all(rows.map(async ({ id }) =>
      [id, await this.split!.ecosystem.accountFraudHistory(id, at)] as const));
    this.internalPixHistory = new Map(pairs);
  }
  get separatedEcosystem(): boolean { return Boolean(this.split); }
  async crossBookNow(): Promise<CrossBookObservation | null> {
    if (!this.split) return null;
    const report = await this.split.verifier.verify();
    const observation = { checked_at: this.realNow().toISOString(), report };
    this.lastCrossBook = observation;
    if (!report.ok) return observation;
    const reportHash = createHash("sha256").update(JSON.stringify(report))
      .digest("hex");
    const bucket = Math.floor(Date.parse(observation.checked_at) / 15_000);
    const proof = this.events.append({ round_id: null, ts: observation.checked_at,
      twin_ts: this.bank.now().toISOString(), type: "ecosystem.cross_book_check",
      actor: { id: "cross-book-verifier", role: "system" }, area: "ledger",
      public_summary_pt: "Conciliação entre banco e ecossistema verificada",
      public: { ok: true, report_sha256: reportHash },
      private: { report } }, `cross-book-check:${bucket}:${reportHash}`);
    return { ...observation, proof_ref: `events:${proof.seq}` };
  }
  async recipientFraudHistory(accountId: string, at: Date): Promise<DictFraudCounter> {
    if (!this.split) throw new Error("SEPARATED_RECIPIENT_HISTORY_UNAVAILABLE");
    return this.split.ecosystem.accountFraudHistory(accountId, at);
  }
  setFaultActiveReader(reader: (id: string, runId?: string) => boolean): void {
    if (!this.faultLab || this.faultActiveReader)
      throw new Error("FAULT_LAB_HOOK_UNAVAILABLE");
    this.faultActiveReader = reader;
  }
  detachFaultActiveReader(): void {
    this.faultActiveReader = undefined;
  }
  armLabStatementOutage(runId: string, customerId: string,
    accountId: string): void {
    if (!this.faultLab || this.labStatementOutage &&
      this.labStatementOutage.runId !== runId)
      throw new Error("FAULT_LAB_STATEMENT_OUTAGE_UNAVAILABLE");
    this.bank.ownAccount(customerId, accountId);
    this.labStatementOutage = { runId, customerId, accountId };
  }
  stopLabStatementOutage(runId: string): void {
    if (this.labStatementOutage && this.labStatementOutage.runId !== runId)
      throw new Error("FAULT_LAB_STATEMENT_OUTAGE_NOT_OWNED");
    this.labStatementOutage = undefined;
  }
  armLabLoanOfferOutage(runId: string, customerId: string): void {
    if (!this.faultLab || this.labLoanOfferOutage &&
      this.labLoanOfferOutage.runId !== runId)
      throw new Error("FAULT_LAB_LOAN_OFFER_OUTAGE_UNAVAILABLE");
    this.bank.customer(customerId);
    this.labLoanOfferOutage = { runId, customerId };
  }
  stopLabLoanOfferOutage(runId: string): void {
    if (this.labLoanOfferOutage && this.labLoanOfferOutage.runId !== runId)
      throw new Error("FAULT_LAB_LOAN_OFFER_OUTAGE_NOT_OWNED");
    this.labLoanOfferOutage = undefined;
  }
  armLabPixAutomaticMandatesOutage(runId: string, customerId: string): void {
    if (!this.faultLab || this.labPixAutomaticMandatesOutage &&
      this.labPixAutomaticMandatesOutage.runId !== runId)
      throw new Error("FAULT_LAB_PIX_AUTOMATIC_MANDATES_OUTAGE_UNAVAILABLE");
    this.bank.customer(customerId);
    this.labPixAutomaticMandatesOutage = { runId, customerId };
  }
  stopLabPixAutomaticMandatesOutage(runId: string): void {
    if (this.labPixAutomaticMandatesOutage && this.labPixAutomaticMandatesOutage.runId !== runId)
      throw new Error("FAULT_LAB_PIX_AUTOMATIC_MANDATES_OUTAGE_NOT_OWNED");
    this.labPixAutomaticMandatesOutage = undefined;
  }
  armLabKycStatusOutage(runId: string, customerId: string): void {
    if (!this.faultLab || this.labKycStatusOutage &&
      this.labKycStatusOutage.runId !== runId)
      throw new Error("FAULT_LAB_KYC_STATUS_OUTAGE_UNAVAILABLE");
    this.bank.customer(customerId);
    this.labKycStatusOutage = { runId, customerId };
  }
  stopLabKycStatusOutage(runId: string): void {
    if (this.labKycStatusOutage && this.labKycStatusOutage.runId !== runId)
      throw new Error("FAULT_LAB_KYC_STATUS_OUTAGE_NOT_OWNED");
    this.labKycStatusOutage = undefined;
  }
  armLabKycSubmissionOutage(runId: string, customerId: string): void {
    if (!this.faultLab || this.labKycSubmissionOutage &&
      this.labKycSubmissionOutage.runId !== runId)
      throw new Error("FAULT_LAB_KYC_SUBMISSION_OUTAGE_UNAVAILABLE");
    this.bank.customer(customerId);
    this.labKycSubmissionOutage = { runId, customerId };
  }
  stopLabKycSubmissionOutage(runId: string): void {
    if (this.labKycSubmissionOutage && this.labKycSubmissionOutage.runId !== runId)
      throw new Error("FAULT_LAB_KYC_SUBMISSION_OUTAGE_NOT_OWNED");
    this.labKycSubmissionOutage = undefined;
  }
  async labSpiAvailability(): Promise<{ available: boolean; changed_at: string;
    changed_by: string }> {
    if (!this.faultLab || !this.split) throw new Error("FAULT_LAB_SPI_UNAVAILABLE");
    return this.split.ecosystem.spiAvailability();
  }
  async labSetSpiAvailability(available: boolean, actor: string):
    ReturnType<EcosystemClient["spiSetAvailability"]> {
    if (!this.faultLab || !this.split) throw new Error("FAULT_LAB_SPI_UNAVAILABLE");
    return this.split.ecosystem.spiSetAvailability(available, actor);
  }
  ecosystemOperations(): Promise<EcosystemOperations> {
    if (!this.split) return Promise.reject(new Error("ECOSYSTEM_NOT_SEPARATED"));
    return this.split.ecosystem.operations();
  }
  ecosystemMoneyFlowProjection(rootTransferId: string, caseId?: string):
    ReturnType<EcosystemClient["moneyFlowProjection"]> {
    if (!this.split) return Promise.reject(new Error("ECOSYSTEM_NOT_SEPARATED"));
    return this.split.ecosystem.moneyFlowProjection(rootTransferId, caseId);
  }
  ecosystemPaymentMessages(endToEndId: string):
    ReturnType<EcosystemClient["paymentMessages"]> {
    if (!this.split) return Promise.reject(new Error("ECOSYSTEM_NOT_SEPARATED"));
    return this.split.ecosystem.paymentMessages(endToEndId);
  }
  dispatchSeparatedMedOpenings(): Promise<number> {
    if (!this.pixCoordinator) return Promise.reject(new Error("ECOSYSTEM_NOT_SEPARATED"));
    return this.pixCoordinator.dispatchMedOpenings();
  }
  async probeLabMedOpening(runId: string,
    fixture: "med_opening_delayed" | "med_analysis_delayed" |
      "med_settlement_delayed" | "med_release_delayed" = "med_opening_delayed"): Promise<void> {
    if (!this.faultLab || !this.split) throw new Error("FAULT_LAB_MED_UNAVAILABLE");
    const result = await this.simulator.localFaultProbe("external_pix", runId, fixture);
    if (result.status !== 200 && result.status !== 202)
      throw new Error("FAULT_LAB_MED_PAYMENT_FAILED");
    const acknowledged = this.bank.db.prepare(`SELECT t.id FROM pix_transfers t
      JOIN pix_psp_inbound_outbox o ON o.transfer_id=t.id
      WHERE t.idempotency_key=? AND t.status='settled' AND o.acknowledged_at IS NOT NULL`);
    for (let attempt = 0; attempt < 20; attempt++) {
      await this.dispatchPendingPix();
      const payment = acknowledged.get(`sim:${runId}:${fixture}:0`) as
        { id: string } | undefined;
      if (payment) {
        await this.simulator.submitLabExternalMed(payment.id);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error("FAULT_LAB_MED_PAYMENT_UNSETTLED");
  }
  ecosystemCautelarReviewPage(at: Date, afterExpiry: string, afterId: string):
    Promise<CautelarReviewPage> {
    if (!this.split) return Promise.reject(new Error("ECOSYSTEM_NOT_SEPARATED"));
    return this.split.ecosystem.cautelarReviewPage(at, afterExpiry, afterId);
  }
  async resolveSeparatedPspCautelar(id: string, decision: "release" | "return",
    actor: string): Promise<{ id: string; status: string; resolved_by: string | null;
      returned_cents: number; pending: boolean }> {
    if (!this.split || !this.pixCoordinator)
      throw new Error("ECOSYSTEM_NOT_SEPARATED");
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(actor))
      throw new BankError("BIZ_CAUTELAR_ACTOR_REQUIRED");
    if (decision !== "release" && decision !== "return")
      throw new BankError("BIZ_CAUTELAR_RESOLUTION_INVALID");
    const hold = await this.split.ecosystem.cautelarHold(id);
    if (!hold) throw new BankError("DEF_NOT_FOUND");
    if (hold.status !== "active" || hold.expires_at <= this.bank.now().toISOString())
      throw new BankError("BIZ_CAUTELAR_NOT_ACTIVE");
    if (decision === "release") {
      const released = await this.split.ecosystem.releasePspCautelar(id, actor,
        this.bank.now().toISOString());
      return { id: released.id, status: released.status,
        resolved_by: released.resolved_by, returned_cents: 0, pending: false };
    }
    await this.pixCoordinator.requestCautelarReturn(id, actor);
    await this.pixCoordinator.dispatchCautelarReturns();
    const command = this.bank.db.prepare(`SELECT acknowledged_at,rejected_at
      FROM pix_psp_cautelar_return_outbox WHERE hold_id=?`).get(id) as
      { acknowledged_at: string | null; rejected_at: string | null } | undefined;
    if (!command) throw new BankError("INTEGRITY_PIX_RETURN_COMMAND");
    if (command.rejected_at) throw new BankError("BIZ_CAUTELAR_NOT_ACTIVE");
    const resolved = await this.split.ecosystem.cautelarHold(id);
    if (!resolved) throw new BankError("INTEGRITY_PIX_RETURN_REPLY");
    return { id: resolved.id, status: command.acknowledged_at ?
      resolved.status : "pending_psp", resolved_by: command.acknowledged_at ?
      resolved.resolved_by : null,
    returned_cents: command.acknowledged_at ? hold.amount_cents : 0,
    pending: !command.acknowledged_at };
  }
  async dispatchPendingPix(): Promise<void> {
    if (this.faultActiveReader?.("pix_dispatch_paused")) return;
    if (this.dispatcherBusy) return;
    this.dispatcherBusy = true;
    try {
      if (this.pixOutcome) await this.pixOutcome.dispatch();
      else if (this.pixCoordinator) await this.pixCoordinator.dispatch();
      else this.bank.dispatchPendingPix();
    } finally { this.dispatcherBusy = false; }
  }
  private async sentinelSources(): Promise<SeparatedSentinelSources | undefined> {
    if (!this.split) return undefined;
    try {
      const [crossBook, activeCautelar] = await Promise.all([
        this.split.verifier.verify(),
        this.split.ecosystem.activeCautelarSummary(this.bank.now()),
      ]);
      this.lastCrossBook = { checked_at: this.realNow().toISOString(), report: crossBook };
      return { crossBook, activeCautelar };
    } catch (error) {
      this.lastCrossBook = { checked_at: this.realNow().toISOString(), report: null };
      throw error;
    }
  }
  private publishHourlyLedgerProofs(): void {
    if (!this.faultActiveReader?.("hourly_proof_paused"))
      this.hourlyLedgerProofs.publishCompleted();
  }
  async scanSentinels(): Promise<void> {
    if (this.activeSentinelScan) return this.activeSentinelScan;
    const scan = (async () => {
      const sources = await this.sentinelSources();
      if (!this.closed) this.sentinels.scan(sources);
    })();
    this.activeSentinelScan = scan;
    try { await scan; }
    finally {
      if (this.activeSentinelScan === scan) this.activeSentinelScan = undefined;
    }
  }
  async scanTelemetryStream(): Promise<void> {
    if (this.closed) return;
    this.sentinels.scanStream();
    if (!this.split || this.activeStreamScan) return;
    const scan = (async () => {
      const evidence = new Map(await Promise.all(
        this.sentinels.pendingSpiEvidenceIds().map(async (endToEndId) =>
          [endToEndId, await this.split!.ecosystem.paymentMessages(endToEndId)] as const)));
      if (!this.closed) {
        try { this.sentinels.scanSpiEvidence(evidence); }
        catch (error) {
          if (!(error instanceof Error && error.message === "SPI_EVIDENCE_REQUIRED"))
            throw error;
          return;
        }
        this.sentinels.scanStream();
      }
    })();
    this.activeStreamScan = scan;
    try { await scan; }
    finally {
      if (this.activeStreamScan === scan) this.activeStreamScan = undefined;
    }
  }
  async cycle(): Promise<void> {
    if (this.closed || this.busy) return;
    this.busy = true;
    try {
      this.containment.renewAwaitingAll();
      if (this.ops.read().level === 3) return;
      const now = this.realNow();
      await this.janitor.closeExpired(now, this.activeRoundId ? new Set([this.activeRoundId]) : undefined);
      const recovered = this.schedule.recover(now);
      if (recovered.completedUnclosed.length) {
        if (this.activeRoundId && recovered.completedUnclosed.some((slot) =>
          slot.roundId === this.activeRoundId)) return;
        await this.dispatchPendingPix();
        for (const slot of recovered.completedUnclosed)
          await this.janitor.close(slot, { status: "partial", summaryPt: "Rodada encerrada", now });
        return;
      }
      for (const feature of this.schedule.expireFeatures(now))
        this.featureSkipped(feature, "missed_window", now);
      for (const feature of this.schedule.features().filter((item) => item.state === "running" &&
        Date.parse(item.endsAt) <= now.getTime())) {
        this.schedule.closeFeature(feature.featureId, "skipped", now, "deadline");
        this.featureSkipped(feature, "deadline", now);
      }
      for (const slot of recovered.missingStartEvents) this.startEvent(slot, now);
      const traffic = await this.simulator.tick(false);
      if (this.faultLab) {
        await this.simulator.retryNotifiedCardPurchases();
        try { await this.simulator.contestNotifiedLabPix(); }
        catch (error) { this.onError(error); }
      }
      await this.dispatchPendingPix();
      if (this.split) this.scheduledPix.prepareDue();
      await this.refreshDueInternalPixHistory("scheduled");
      this.scheduledPix.executeDue();
      await this.refreshDueInternalPixHistory("automatic");
      const automaticDelayReceipts = this.faultActiveReader && this.bank.db.prepare(`SELECT 1
        FROM sqlite_master WHERE type='table' AND name='lab_automatic_pix_delay'`).get();
      this.pixAutomatic.executeDue(automaticDelayReceipts ? (id) => {
        const run = this.bank.db.prepare("SELECT run_id FROM lab_automatic_pix_delay WHERE charge_id=?")
          .get(id) as { run_id: string } | undefined;
        return Boolean(run && this.faultActiveReader?.("automatic_pix_execution_delayed", run.run_id));
      } : undefined);
      this.cardRecurring.runDue();
      this.cardNetwork.clearDue();
      if (this.split) await this.split.ecosystem.expirePspCautelar(this.bank.now().toISOString());
      else this.bank.psp.expireCautelar();
      this.bank.expireRiskPixHolds();
      this.bank.resolvePendingMed();
      await this.dispatchPendingPix();
      this.publishHourlyLedgerProofs();
      await this.scanSentinels();
      const areas = this.sentinels.telemetry();
      await this.simulator.publishCurrent(traffic, areas);
      this.lastTelemetry = { checked_at: this.realNow().toISOString(), areas,
        by_area: traffic.by_area, honest_blocked: traffic.honest_blocked };
      this.observeDelayedEffects?.();
      this.health.update();
      if (await this.observeDeployment?.()) {
        this.onRestart();
        return;
      }
      if (this.runRound) {
        const level = this.ops.read().level;
        const hasProgress = this.events.db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table'
          AND name='campaign_round_progress'`).get();
        const pendingDeployment = hasProgress ? this.schedule.list().find((item) =>
          item.state === "running" && this.events.db.prepare(`SELECT 1 FROM campaign_round_progress
            WHERE round_id=? AND json_extract(data_json,'$.pending') IS NOT NULL`)
            .get(item.roundId)) : undefined;
        const resumed = level < 3 ? pendingDeployment ?? recovered.open[0] ??
          recovered.missingStartEvents[0] : undefined;
        const continuousDue = this.continuousNextAt();
        const slot = this.activeRound || this.quota.resumeAt() ? undefined :
          resumed ?? (level === 0 && this.continuousIntervalMs !== undefined &&
            continuousDue && continuousDue.getTime() <= now.getTime() ?
            this.schedule.claimOnDemand(now) : level === 0 && !this.onDemand ?
            this.schedule.claimDue(now) : undefined);
        if (slot) {
          if (!resumed) this.startEvent(slot, now);
          this.budget?.openRun(slot.roundId, "round");
          this.activeRoundId = slot.roundId;
          const task = Promise.resolve().then(() => this.runRound!(slot)).then(async (outcome) => {
            if (outcome === "watching") return;
            if (outcome && typeof outcome === "object") {
              await this.janitor.close(slot, { status: "partial",
                reason: outcome.partialReasons.slice(0, 3).join(",") || "unresolved",
                summaryPt: "Rodada encerrada com pendências", now: this.realNow() });
              return;
            }
            if (this.events.rounds().find((round) => round.round_id === slot.roundId)?.status === "started")
              await this.janitor.close(slot, { status: "completed", summaryPt: "Rodada concluída",
                now: this.realNow() });
          }).catch(async (error) => {
            if (error instanceof CampaignRestartRequired) {
              this.onRestart();
              return;
            }
            this.onError(error);
            try {
              if (this.events.rounds().find((round) => round.round_id === slot.roundId)?.status === "started")
                await this.janitor.close(slot, { status: "partial", reason: "runtime_error",
                  summaryPt: "Rodada encerrada após falha interna", now: this.realNow() });
            } catch (closeError) { this.onError(closeError); }
          });
          this.activeRound = task.finally(() => {
            try { this.budget?.closeRun(slot.roundId); } catch (error) { this.onError(error); }
            this.activeRound = undefined;
            this.activeRoundId = undefined;
          });
        }
      }
      if (this.runFeature && !this.activeFeature) {
        const level = this.ops.read().level;
        const resumed = level < 3 ? this.schedule.features().find((item) => item.state === "running") : undefined;
        const feature = this.quota.resumeAt() ? undefined :
          resumed ?? (level === 0 ? this.schedule.claimDueFeature(now) : undefined);
        if (feature) {
          this.budget?.openRun(`product_${feature.day}`, "product");
          const task = Promise.resolve().then(() => this.runFeature!(feature)).then((result) => {
            const state = this.schedule.features().find((item) => item.featureId === feature.featureId);
            if (state?.state !== "running") return;
            if (result.approved && this.realNow().getTime() < Date.parse(feature.endsAt) &&
              this.ops.read().level < 3) {
              new FeatureRegistry(this.bank, this.events).setEnabled(feature.featureId, true,
                "campaign-runtime", result.titlePt && result.summaryPt ?
                  { titlePt: result.titlePt, summaryPt: result.summaryPt } : undefined);
              this.schedule.closeFeature(feature.featureId, "launched", this.realNow());
            } else {
              const reason = this.realNow().getTime() >= Date.parse(feature.endsAt) ? "deadline" :
                result.reason ?? "review_failed";
              this.schedule.closeFeature(feature.featureId, "skipped", this.realNow(), reason);
              this.featureSkipped(feature, reason, this.realNow());
            }
          }).catch((error) => {
            this.onError(error);
            const state = this.schedule.features().find((item) => item.featureId === feature.featureId);
            if (state?.state === "running") {
              this.schedule.closeFeature(feature.featureId, "skipped", this.realNow(), "runtime_error");
              this.featureSkipped(feature, "runtime_error", this.realNow());
            }
          });
          this.activeFeature = task.finally(() => {
            try { this.budget?.closeRun(`product_${feature.day}`); } catch (error) { this.onError(error); }
            this.activeFeature = undefined;
          });
        }
      }
    } finally { this.busy = false; }
  }
  private startEvent(slot: StoredSlot, now: Date): void {
    const open = this.bank.db.prepare("SELECT COUNT(*) n FROM weakness_state WHERE open=1").get() as { n: number };
    const features = this.bank.db.prepare("SELECT id FROM feature_flags WHERE enabled=1 ORDER BY id")
      .all() as { id: string }[];
    this.events.append({ round_id: slot.roundId, ts: now.toISOString(), twin_ts: this.clock.now().toISOString(),
      type: "round.started", actor: { id: "campaign-runtime", role: "system" },
      public_summary_pt: `Rodada ${String(slot.roundNo).padStart(2, "0")} iniciada`,
      public: { round_no: slot.roundNo, feature_ids_live: features.map((feature) => feature.id),
        open_weaknesses_count: open.n } },
    `round:${slot.roundId}:start`);
  }
  private featureSkipped(feature: StoredFeature, reason: string, now: Date): void {
    this.events.append({ round_id: null, ts: now.toISOString(), twin_ts: this.clock.now().toISOString(),
      type: "flag.changed", actor: { id: "campaign-runtime", role: "system" },
      public_summary_pt: "Novo recurso adiado após verificação", public: {
        key: feature.featureId, enabled: false, by: "campaign-runtime" }, private: { reason } },
    `feature:${feature.featureId}:skipped`);
  }
  start(): void {
    if (this.closed || this.stopping || this.timers.length) return;
    const anchorHeartbeat = () => {
      if (this.closed) return;
      try { this.ledgerAnchors.checkpoint(); }
      catch (error) {
        this.stopping = true;
        let report: Promise<void> = Promise.resolve();
        try {
          this.ops.write({ ...this.ops.readFresh(), level: 3 });
          this.sentinels.reportLedgerAnchorMismatch();
          report = this.scanSentinels();
        } catch (reportError) { this.onError(reportError); }
        this.onError(error);
        void report.catch(this.onError).finally(() => this.close().catch(this.onError));
      }
    };
    anchorHeartbeat();
    if (this.closed || this.stopping) return;
    this.timers.push(setInterval(anchorHeartbeat, 10_000));
    this.sentinels.monitorGatewayHealth();
    const gatewayHeartbeat = () => {
      if (this.faultActiveReader?.("gateway_heartbeat_silence")) return;
      try { this.gateway.heartbeat(); } catch (error) { this.onError(error); }
    };
    gatewayHeartbeat();
    this.timers.push(setInterval(gatewayHeartbeat, 10_000));
    this.sentinels.monitorRiskHealth();
    const riskHeartbeat = () => {
      try { this.bank.risk.heartbeat(); } catch (error) { this.onError(error); }
    };
    riskHeartbeat();
    this.timers.push(setInterval(riskHeartbeat, 10_000));
    this.sentinels.monitorProducerHealth("auth");
    const authHeartbeat = () => {
      if (this.faultActiveReader?.("auth_event_silence")) return;
      try { this.auth.heartbeat(); } catch (error) { this.onError(error); }
    };
    authHeartbeat();
    this.timers.push(setInterval(authHeartbeat, 10_000));
    this.sentinels.monitorProducerHealth("cards");
    const cardHeartbeat = () => {
      try { this.cardNetwork.heartbeat(); } catch (error) { this.onError(error); }
    };
    cardHeartbeat();
    this.timers.push(setInterval(cardHeartbeat, 10_000));
    for (const [source, heartbeat] of [
      ["pix", () => this.bank.heartbeatPix()],
      ["spi", () => this.split ? this.split.ecosystem.spiAvailability().then(() => {
        this.bank.telemetry.emit({ source: "spi", category: "health", action: "heartbeat",
          outcome: "success", message: "SPI process responded to health check" });
      }) : this.bank.spi.heartbeat()],
      ["dict", () => this.split ? this.split.ecosystem.dictHealth().then(() => {
        this.bank.telemetry.emit({ source: "dict", category: "health", action: "heartbeat",
          outcome: "success", message: "DICT process responded to health check" });
      }) : this.bank.heartbeatDict()],
      ["ledger", () => this.bank.heartbeatLedger()],
    ] as const) {
      this.sentinels.monitorProducerHealth(source);
      const tick = () => {
        try { void Promise.resolve(heartbeat()).catch(this.onError); }
        catch (error) { this.onError(error); }
      };
      tick();
      this.timers.push(setInterval(tick, 10_000));
    }
    const schedule = (ms: number) => this.timers.push(setInterval(() => {
      void this.cycle().catch(this.onError);
    }, ms));
    schedule(10_000);
    this.timers.push(setInterval(() => {
      if (this.closed) return;
      if (this.ops.readFresh().level !== 3)
        void this.dispatchPendingPix().catch(this.onError);
    }, 50));
    this.timers.push(setInterval(() => {
      if (this.closed || this.ops.readFresh().level === 3) return;
      void this.scanTelemetryStream().catch(this.onError);
    }, 50));
    this.timers.push(setInterval(() => {
      if (this.closed || this.ops.readFresh().level === 3) return;
      // At maximum clock speed the proof grace period is shorter than a traffic tick.
      try { this.publishHourlyLedgerProofs(); }
      catch (error) { this.onError(error); }
      void this.scanSentinels().catch(this.onError);
    }, 2_000));
    void this.cycle().catch(this.onError);
  }
  continuousNextAt(): Date | null {
    if (this.continuousIntervalMs === undefined) return null;
    const slots = this.schedule.list();
    if (slots.some((slot) => slot.state === "running") || !slots.some((slot) => slot.state === "scheduled"))
      return null;
    const last = slots.filter((slot) => slot.state === "closed").at(-1);
    return last?.closedAt ? new Date(Date.parse(last.closedAt) + this.continuousIntervalMs) :
      this.realNow();
  }
  async startOnDemandRound(): Promise<StoredSlot | undefined> {
    if (!this.onDemand || this.continuousIntervalMs !== undefined || this.closed ||
      this.ops.read().level !== 0 || this.quota.resumeAt())
      return undefined;
    const slot = this.schedule.claimOnDemand(this.realNow());
    if (slot) await this.cycle();
    return slot;
  }
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    for (const timer of this.timers) clearInterval(timer);
    this.timers.length = 0;
    while (this.busy || this.dispatcherBusy)
      await new Promise((resolve) => setTimeout(resolve, 10));
    await this.activeSentinelScan?.catch(this.onError);
    await this.activeStreamScan?.catch(this.onError);
    await this.activeRound;
    await this.activeFeature;
    this.unsubscribeAgentTelemetry();
    await this.api.close();
    this.simulator.close();
    try { await this.split?.verifier.close(); }
    finally {
      try { await this.split?.ecosystem.close(); }
      finally { this.bank.close(); }
    }
  }
}
