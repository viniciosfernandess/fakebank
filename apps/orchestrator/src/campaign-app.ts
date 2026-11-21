import type { EventStore } from "../../../packages/event-store/src/index.ts";
import type { SeedOptions } from "../../world/src/seed.ts";
import type { AgentTransport } from "./agent-loop.ts";
import type { AgentRuntime } from "./runtime/agent-runtime.ts";
import { CampaignRuntime } from "./campaign-runtime.ts";
import { CampaignController } from "./campaign-controller.ts";
import { CampaignRestartRequired } from "./campaign-restart.ts";
import type { StoredFeature, StoredSlot } from "./schedule-store.ts";

type CampaignAppInput = { dataDir: string; events: EventStore;
  bankOnly?: boolean;
  faultLab?: boolean;
  repoRoot: string; transport?: AgentTransport; runtime?: AgentRuntime; startBrtDate: string;
  onDemand?: boolean;
  continuousIntervalMinutes?: number;
  plantCanaries?: boolean;
  seed?: SeedOptions; realNow?: () => Date; onError?: (error: unknown) => void;
  twinSpeed?: number;
  onRestart?: () => void };

interface CampaignAppState {
  controller?: CampaignController;
}

function runtimeInput(input: CampaignAppInput, state: CampaignAppState):
  Parameters<typeof CampaignRuntime.openSeparated>[0] {
  return { ...input,
    legacyBudget: Boolean(input.transport),
    ...(input.transport ? { narratorTransport: input.transport } : {}),
    ...(input.runtime ? { narratorRuntime: input.runtime } : {}),
    onExpiredRound: (roundId, endsAt) => state.controller?.deferExpiredRound(roundId, endsAt),
    ...(!input.bankOnly ? { runRound: async (slot: StoredSlot) => {
      if (!state.controller) throw new Error("CAMPAIGN_CONTROLLER_NOT_READY");
      const result = await state.controller.runRound(slot);
      if (result.status === "restart") throw new CampaignRestartRequired();
      if (result.status === "partial") return { partialReasons: result.reasons };
      if (result.status === "watching") return "watching";
    } } : {}),
    ...(!input.bankOnly ? { observeDeployment: () => {
      if (!state.controller) throw new Error("CAMPAIGN_CONTROLLER_NOT_READY");
      return state.controller.observeDeployment();
    } } : {}),
    ...(!input.bankOnly ? { runFeature: (slot: StoredFeature) => {
      if (!state.controller) throw new Error("CAMPAIGN_CONTROLLER_NOT_READY");
      return state.controller.runFeature(slot);
    } } : {}) };
}

function wireCampaignApp(input: CampaignAppInput, runtime: CampaignRuntime,
  state: CampaignAppState) {
  const controller = new CampaignController({ bank: runtime.bank, auth: runtime.auth,
    gateway: runtime.gateway, clock: runtime.clock, sentinels: runtime.sentinels,
    events: input.events, ...(runtime.budget ? { budget: runtime.budget } : {}),
    ...(input.transport ? { transport: input.transport } : {}),
    ...(input.runtime ? { runtime: input.runtime } : {}),
    repoRoot: input.repoRoot, bankPath: runtime.bankPath,
    simulator: runtime.simulator, realNow: runtime.realNow,
    scanSentinels: () => runtime.scanSentinels(),
    ...(runtime.separatedEcosystem ? { paymentMessages: (endToEndId: string) =>
      runtime.ecosystemPaymentMessages(endToEndId) } : {}),
    ...(runtime.separatedEcosystem ? { separatedMed: {
      project: (transferId: string, caseId?: string) =>
        runtime.ecosystemMoneyFlowProjection(transferId, caseId),
      dispatchOpenings: () => runtime.dispatchSeparatedMedOpenings(),
    } } : {}) });
  state.controller = controller;
  return { runtime, controller };
}

export function createCampaignApp(input: CampaignAppInput) {
  const state: CampaignAppState = {};
  const runtime = new CampaignRuntime(runtimeInput(input, state));
  return wireCampaignApp(input, runtime, state);
}

export async function createSeparatedCampaignApp(input: CampaignAppInput) {
  const state: CampaignAppState = {};
  const runtime = await CampaignRuntime.openSeparated(runtimeInput(input, state));
  try { return wireCampaignApp(input, runtime, state); }
  catch (error) {
    await runtime.close().catch(() => undefined);
    throw error;
  }
}
