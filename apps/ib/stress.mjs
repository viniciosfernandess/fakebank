import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { createAgents } from './agents.mjs';
import { compareDay } from './intelligence.mjs';

const seed = 0x49b2026;
let random = seed;
function choose(high) {
  random ^= random << 13;
  random ^= random >>> 17;
  random ^= random << 5;
  return (random >>> 0) % high;
}

function makeCases() {
  const anchored = [
    ['all-recoverable', {}],
    ['exact-cutoffs', { closingSignal: 645, matchingSignal: 708, marginSignal: 795 }],
    ['late-evidence', { closingSignal: 655, matchingSignal: 710, marginSignal: 811 }],
    ['withdrawal-during-work', { ssiWithdrawAt: 727 }],
    ['funding-withdrawal', { facilityDownAt: 778 }],
    ['cap-insufficient', { marginAmount: 17_500_000_000 }],
  ];
  return [
    ...anchored.map(([label, market]) => ({ label, market })),
    ...Array.from({ length: 768 }, (_, index) => {
      const closingSignal = 600 + choose(59);
      const matchingSignal = 640 + choose(112);
      const marginSignal = 690 + choose(145);
      const market = {
        closingSignal, indentureEta: 713 + choose(75), matchingSignal, marginSignal,
        marginAmount: 9_500_000_000 + choose(85) * 100_000_000,
      };
      if (choose(9) === 0) market.ssiUnconfirmed = true;
      if (choose(8) === 0) market.ssiWithdrawAt = matchingSignal + 1 + choose(65);
      if (choose(7) === 0) market.facilityDownAt = 710 + choose(130);
      const scenarios = ['combined', 'combined', 'closing', 'matching', 'liquidity', 'clean'];
      return { label: `seeded-${index}`, scenario: scenarios[choose(scenarios.length)], market };
    }),
  ];
}

function auditDay(variant, result) {
  const { market, label, scenario = 'combined' } = variant;
  const affected = (...scenarios) => ['combined', ...scenarios].includes(scenario);
  const { final, predictive, reactive } = result;
  assert.ok(predictive.reconciled && reactive.reconciled, label);
  const matchingAt = market.matchingSignal ?? 685;
  const authorityLost = market.ssiUnconfirmed || market.ssiWithdrawAt <= matchingAt + 72 ||
    market.ssiWithdrawAt <= 755;
  assert.equal(predictive.firm, !affected('matching') || (!authorityLost && matchingAt + 72 <= 780), label);

  const originalClosing = (market.indentureEta ?? 742) + 20;
  const expeditedClosing = (market.closingSignal ?? 610) + 55 + 20;
  assert.equal(predictive.closing, !affected('closing') || Math.min(originalClosing, expeditedClosing) <= 720, label);
  assert.equal(predictive.primary, !affected('closing') || Math.min(originalClosing, expeditedClosing) <= 765, label);
  const funds = final.journal.find(({ ref }) => ref === 'funding');
  const marginTransfer = final.journal.find(({ ref }) => ref === 'margin');
  assert.equal(Boolean(funds), Boolean(final.funding?.arrived), label);
  if (funds) {
    const [draw, fee] = funds.legs;
    assert.ok(draw.amount <= 2_500_000_000 && draw.from === 'lender' && fee.to === 'lender', label);
    assert.ok(funds.at >= final.funding.requested + 45 && funds.at < (market.facilityDownAt ?? Infinity), label);
    assert.equal(fee.amount, Math.ceil(draw.amount * 8 / 10_000), label);
  }
  const firmDvP = final.journal.find(({ ref }) => ref === 'firm');
  assert.equal(Boolean(firmDvP), predictive.firm, label);
  if (firmDvP) assert.deepEqual(firmDvP.legs.map(({ asset }) => asset), ['cash', 'BV-DEB-02'], label);
  const availableByCutoff = 3_500_000_000 + (funds && funds.at <= 840 ? final.funding.net : 0) +
    (firmDvP ? 8_500_000_000 : 0);
  assert.equal(predictive.margin, availableByCutoff >= final.margin.amount, label);
  assert.equal(Boolean(marginTransfer), predictive.margin, label);
  if (marginTransfer) assert.equal(marginTransfer.legs[0].from, 'firm', label);
  for (const event of predictive.actions) {
    assert.ok(event.decision?.signalId && event.decision.signalId < event.id, label);
    assert.ok(event.decision.signalAt <= event.at, label);
  }
  const review = final.events.filter(({ code }) => code === 'agent-review');
  if (!predictive.firm) assert.ok(review.some(({ role }) => role === 'settlement'), label);
  if (!predictive.margin) assert.ok(review.some(({ role }) => role === 'treasury') ||
    predictive.actions.some(({ decision }) => decision.residual > 0), label);
  assert.equal(final.events.filter(({ code }) => code === 'agent-degraded' || code === 'agent-rejected').length, 0, label);
}

const cases = makeCases();
const totals = {
  reactive: { closing: 0, primary: 0, firm: 0, margin: 0, fundingFeeCents: 0 },
  predictive: { closing: 0, primary: 0, firm: 0, margin: 0, fundingFeeCents: 0 },
};
const agents = createAgents();
const durations = [];
const start = performance.now();
try {
  for (let cursor = 0; cursor < cases.length; cursor += 24) {
    await Promise.all(cases.slice(cursor, cursor + 24).map(async (entry) => {
      const started = performance.now();
      const result = await compareDay(entry.scenario ?? 'combined', agents, entry.market);
      auditDay(entry, result);
      durations.push(performance.now() - started);
      for (const [mode, total] of Object.entries(totals)) {
        const day = result[mode];
        for (const milestone of ['closing', 'primary', 'firm', 'margin']) total[milestone] += Number(day[milestone]);
        total.fundingFeeCents += day.cost;
      }
    }));
  }
} finally {
  agents.close();
}
assert.ok(totals.predictive.closing > totals.reactive.closing);
assert.ok(totals.predictive.firm > totals.reactive.firm);
assert.ok(totals.predictive.margin > totals.reactive.margin);
durations.sort((a, b) => a - b);
console.log(JSON.stringify({
  seed, pairedDays: cases.length, concurrentDays: 24, totals,
  elapsedMs: Math.round(performance.now() - start),
  p95PairMs: Math.round(durations[Math.ceil(durations.length * 0.95) - 1]),
}, null, 2));
