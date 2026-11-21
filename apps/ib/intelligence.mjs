import { createHash } from 'node:crypto';
import {
  actions, applyCommand, correction, createDay, CUTOFF, differences, END, FACILITY, forecast, futureDates,
  processMinute, record, scenarios, START, startWork, summarize,
} from './domain.mjs';

export const POLICY_VERSION = 'ib-controls-2';
const deskAction = { closing: 'closing', settlement: 'matching', treasury: 'funding' };
const reviewCodes = {
  closing: ['closing-unrecoverable', 'closing-cutoff-missed'],
  settlement: ['instruction-not-authorized', 'settlement-unrecoverable'],
  treasury: ['funding-already-committed', 'funding-window-closed', 'facility-unavailable'],
};
const watchCodes = { treasury: ['conditional-receipt', 'repair-before-funding'] };

function context(role, state) {
  const f = forecast(state);
  const { now } = state;
  if (role === 'closing') {
    const { indenture, registration } = state.documents;
    const duration = f.documents.find(({ id }) => id === 'indenture').minutes;
    return { now, required: state.release === null && state.work.closing === null && indenture.received === null,
      eta: indenture.eta, projected: f.closing, registration: registration.minutesAfterPrerequisites,
      completion: now + duration, cutoff: CUTOFF.closing, primaryCutoff: CUTOFF.primary };
  }
  const repair = correction(state);
  const firm = state.instructions.firm;
  if (role === 'settlement') {
    return { now, settled: firm.settled !== null, mismatches: differences(firm), authorized: repair.repairable,
      pending: repair.pending, authorityRevision: repair.authorityRevision, readyAt: firm.readyAt,
      repairMinutes: repair.duration, cutoff: CUTOFF.firm };
  }
  return {
    now, cash: f.cash, expectedReceipt: f.receipt, currentGap: f.gap,
    stressGap: Math.max(0, f.margin - f.cashWithoutTrade),
    canWaitForRepair: repair.repairable && !repair.pending && repair.at <= CUTOFF.firm,
    available: state.facilityUnavailable ? 0 : Math.min(FACILITY.maximum, state.balance.cash.lender),
    pending: Boolean(state.funding), failed: Boolean(state.funding?.failed),
    latest: f.latest, marginCutoff: CUTOFF.margin, feeBps: FACILITY.feeBps, lead: FACILITY.minutes,
  };
}

function evidence(role, state, facts) {
  const signal = [...state.events].reverse().find(({ code }) =>
    (role === 'closing' && code === 'closing-delay') ||
    (role === 'settlement' && ['instruction-mismatch', 'custody-authority-withdrawn'].includes(code)) ||
    (role === 'treasury' && ['instruction-mismatch', 'matching-repair-started', 'margin-update', 'facility-unavailable'].includes(code)));
  const revision = createHash('sha256')
    .update(JSON.stringify({ policy: POLICY_VERSION, role, version: state.version, event: state.events.length, facts }))
    .digest('hex');
  return { revision, signalId: signal?.id ?? null, signalAt: signal?.at ?? null,
    reviewedAt: state.now, stateVersion: state.version, policy: POLICY_VERSION };
}

function permittedProposal(role, proposal, facts, state) {
  const eligible = actions(state).find(({ id }) => id === deskAction[role]);
  if (!eligible || proposal.action !== eligible.id || proposal.completion !== eligible.completion ||
      proposal.deadline !== eligible.deadline) return false;
  if (role === 'closing') {
    const before = futureDates(state);
    const release = eligible.completion + facts.registration;
    return eligible.completion < before.indenture && release <= CUTOFF.primary &&
      proposal.code === (release <= CUTOFF.closing ? 'closing-preserved' : 'primary-protected');
  }
  if (role === 'settlement') {
    return facts.authorized && Math.max(facts.readyAt, eligible.completion) <= CUTOFF.firm &&
      proposal.code === 'settlement-preserved';
  }
  const f = forecast(state);
  return !facts.canWaitForRepair && state.now <= f.latest && f.draw > 0 && proposal.draw === f.draw &&
    proposal.fee === f.fee && proposal.residual === f.residual && proposal.code === 'funding-sized';
}

function auditOnce(state, role, code, detail) {
  const last = [...state.events].reverse().find((entry) => entry.role === role);
  if (last?.code === code && last.reason === detail.reason && last.signalId === detail.signalId) return;
  record(state, code, { role, ...detail });
}

async function evaluate(agents, role, state) {
  const facts = context(role, state);
  const proof = evidence(role, state, facts);
  let answer;
  try {
    answer = await agents.ask(role, proof.revision, facts);
  } catch {
    auditOnce(state, role, 'agent-degraded', { reason: 'unavailable', ...proof });
    return false;
  }

  if (answer?.role === role && answer.revision === proof.revision) {
    if (answer.kind === 'observe') {
      const last = [...state.events].reverse().find((entry) => entry.role === role);
      if (last?.code === 'agent-degraded' || last?.code === 'agent-rejected') {
        auditOnce(state, role, 'agent-recovered', { reason: 'valid-reply', ...proof });
      }
      return true;
    }
    if (answer.kind === 'watch' && watchCodes[role]?.includes(answer.code)) {
      auditOnce(state, role, 'agent-watch', { reason: answer.code, ...proof });
      return true;
    }
    if (answer.kind === 'review' && reviewCodes[role].includes(answer.code)) {
      auditOnce(state, role, 'agent-review', { reason: answer.code, ...proof });
      return true;
    }
    if (answer.kind === 'propose' && permittedProposal(role, answer, facts, state)) {
      startWork(state, answer.action, { role, reason: answer.code, ...proof,
        ...(role === 'treasury' && { expectedReceipt: facts.expectedReceipt, stressGap: facts.stressGap, residual: answer.residual }) });
      return true;
    }
  }

  auditOnce(state, role, 'agent-rejected', { reason: 'invalid-proposal', ...proof });
  return false;
}

async function runAgents(state, agents) {
  // Legal and custody decisions can affect Treasury, which always gets a fresh snapshot.
  let healthy = true;
  for (const role of Object.keys(deskAction)) healthy = await evaluate(agents, role, state) && healthy;
  return healthy;
}

export async function execute(current, command, agents) {
  if (command.type !== 'advance' || command.automatic !== true || current.policy !== 'predictive') {
    return applyCommand(current, command);
  }
  const { minutes } = command;
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > END - START || current.now >= END) {
    throw new RangeError('Avanço inválido.');
  }
  const state = structuredClone(current);
  const until = Math.min(END, state.now + minutes);
  let retryAt = await runAgents(state, agents) ? Infinity : state.now + 5;
  while (state.now < until) {
    state.now += 1;
    const eventCount = state.events.length;
    processMinute(state);
    if (state.now < END && (state.events.length !== eventCount || state.now === retryAt ||
        state.now === CUTOFF.margin - FACILITY.minutes)) {
      retryAt = await runAgents(state, agents) ? Infinity : state.now + 5;
    }
  }
  state.version += 1;
  return state;
}

export async function compareDay(id, agents, market = null) {
  const command = { type: 'advance', minutes: END - START, automatic: true };
  const reactive = summarize(applyCommand(createDay(id, 'reactive', market), command));
  const final = await execute(createDay(id, 'predictive', market), command, agents);
  return { reactive, predictive: summarize(final), final };
}

export async function isolatedBenchmark(agents) {
  return Promise.all(Object.entries(scenarios).map(async ([id, { name }]) => {
    const { reactive, predictive } = await compareDay(id, agents);
    return { id, name, reactive, predictive };
  }));
}
