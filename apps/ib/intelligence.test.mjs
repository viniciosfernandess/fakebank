import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { test } from 'node:test';
import { createAgents } from './agents.mjs';
import { createDay, END, START } from './domain.mjs';
import { compareDay, execute, POLICY_VERSION } from './intelligence.mjs';
import { createIbServer } from './server.mjs';

const command = { type: 'advance', minutes: END - START, automatic: true };

function instructionRecords(end) {
  return end.events.filter(({ code }) => code === 'matching-repair-started');
}

test('live process specialists act on observed evidence, with a distinct recorded role and replay fingerprint', async (t) => {
  const agents = createAgents();
  t.after(() => agents.close());
  const { predictive, reactive, final } = await compareDay('combined', agents);
  assert.deepEqual([predictive.closingAt, predictive.primaryAt, predictive.firmAt, predictive.marginAt], [685, 730, 757, 840]);
  assert.equal(reactive.misses.length, 3);
  assert.equal(predictive.misses.length, 0);
  assert.equal(predictive.cost, 1_200_961);
  assert.equal(final.funding.net, 1_500_000_000);
  const roles = ['closing', 'settlement', 'treasury'];
  assert.deepEqual(predictive.actions.map(({ decision }) => decision.role), roles);
  for (const event of predictive.actions) {
    const { revision, signalId, signalAt, reviewedAt, policy } = event.decision;
    assert.match(revision, /^[a-f0-9]{64}$/);
    assert.equal(policy, POLICY_VERSION);
    const source = final.events.find(({ id }) => id === signalId);
    assert.ok(source.id < event.id);
    assert.equal(source.at, signalAt);
    assert.equal(reviewedAt, event.at);
    assert.ok(source.at <= event.at);
  }
  const rerun = await compareDay('combined', agents);
  assert.deepEqual(rerun.final, final);
});

test('custody authorization is required both before repair and when the finished repair would apply', async (t) => {
  const agents = createAgents();
  t.after(() => agents.close());
  const noAuthority = (await compareDay('matching', agents, { ssiUnconfirmed: true })).final;
  assert.equal(instructionRecords(noAuthority).length, 0);
  assert.equal(noAuthority.instructions.firm.settled, null);
  assert.ok(noAuthority.events.some(({ reason }) => reason === 'instruction-not-authorized'));

  const withdrawn = (await compareDay('matching', agents, { ssiWithdrawAt: 720 })).final;
  assert.equal(instructionRecords(withdrawn).length, 1);
  assert.equal(withdrawn.instructions.firm.settled, null);
  assert.ok(withdrawn.events.some(({ code }) => code === 'instruction-repair-rejected'));
  assert.ok(!withdrawn.journal.some(({ ref }) => ref === 'firm'));
  assert.equal(withdrawn.balance['BV-DEB-02'].firm, 85_000);
});

test('impossible and late funding stay visible and cannot create cash', async (t) => {
  const agents = createAgents();
  t.after(() => agents.close());
  const unavailable = await compareDay('liquidity', agents, { facilityDownAt: 770 });
  assert.ok(unavailable.final.events.some(({ code }) => code === 'funding-failed'));
  assert.equal(unavailable.final.journal.find(({ ref }) => ref === 'funding'), undefined);
  assert.equal(unavailable.final.margin.paid, null);
  assert.equal(unavailable.predictive.cost, 0);
  assert.ok(unavailable.predictive.reconciled);

  const late = await compareDay('liquidity', agents, { marginSignal: 805 });
  assert.equal(late.final.funding, null);
  assert.equal(late.final.margin.paid, null);
  assert.ok(late.final.events.some(({ reason }) => reason === 'funding-window-closed'));

  const capped = await compareDay('liquidity', agents, { marginAmount: 17_000_000_000 });
  assert.equal(capped.final.funding.draw, 2_500_000_000);
  assert.equal(capped.final.margin.paid, null);
  assert.equal(capped.predictive.actions[0].decision.residual, 2_502_000_000);
});

test('future observations and client accounts never enter role inputs, and bad replies are rejected', async (t) => {
  const actual = createAgents();
  t.after(() => actual.close());
  const rejectedRoles = new Set();
  let sources = 0;
  const agents = {
    async ask(role, revision, facts) {
      assert.ok(!Object.hasOwn(facts, 'scenario'));
      assert.ok(!Object.hasOwn(facts, 'market'));
      assert.ok(!Object.hasOwn(facts, 'balance'));
      assert.equal(Object.hasOwn(facts, 'stressGap'), role === 'treasury');
      if (role === 'treasury' && facts.now < 740) assert.notEqual(facts.currentGap, 1_500_000_000);
      const answer = await actual.ask(role, revision, facts);
      sources++;
      if (answer.kind !== 'propose' || rejectedRoles.has(role)) return answer;
      rejectedRoles.add(role);
      if (role === 'closing') return { ...answer, revision: 'previous-revision' };
      if (role === 'settlement') return { ...answer, action: 'closing' };
      return { ...answer, draw: answer.draw + 1 };
    },
  };
  const final = await execute(createDay('combined'), command, agents);
  assert.ok(sources > 15);
  for (const [role, signal] of [['closing', 610], ['settlement', 685], ['treasury', 740]]) {
    const rejected = final.events.find((event) => event.role === role && event.code === 'agent-rejected');
    const accepted = final.events.find(({ decision }) => decision?.role === role);
    assert.equal(rejected.at, signal);
    assert.ok(accepted.at > signal);
  }
  assert.equal(final.margin.paid, 840);
});

test('a hung process is killed and does not prevent the other roles from acting', async (t) => {
  let stuck;
  let restarts = 0;
  const agents = createAgents({ timeout: 150, start: (role, spawnForRole) => {
    if (role !== 'settlement') return spawnForRole(role);
    restarts += 1;
    if (restarts > 1) return spawnForRole(role);
    stuck = spawn(process.execPath, ['-e', `
      process.on('message', ({ job, revision, facts }) => {
        if (facts.now < 685) process.send({ job, revision, role: 'settlement', kind: 'observe' });
      });
    `], { env: {}, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    return stuck;
  } });
  t.after(() => agents.close());
  const final = await execute(createDay('combined'), command, agents);
  assert.equal(stuck.killed, true);
  assert.equal(restarts, 2);
  assert.equal(final.events.find(({ code }) => code === 'agent-degraded').role, 'settlement');
  assert.equal(final.events.find(({ decision }) => decision?.role === 'settlement').at, 690);
  assert.equal(final.margin.paid, 840);
});

test('an operator change during a predictive run invalidates the earlier asynchronous result', async (t) => {
  const server = createIbServer(':memory:');
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const body = { dayId: 1, version: 0 };
  const post = (extra) => fetch(origin + '/api/day', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...body, ...extra }),
  });
  const open = post(command);
  const reset = post({ type: 'reset', scenario: 'clean', policy: 'predictive' });
  const [earlier, later] = await Promise.all([open, reset]);
  assert.equal(later.status, 200);
  assert.equal(earlier.status, 409);
  const current = await fetch(origin + '/api/day').then((response) => response.json());
  assert.equal(current.dayId, 2);
  assert.equal(current.scenario, 'clean');
  assert.equal(current.events.length, 1);
  const parallel = await Promise.all(Array.from({ length: 48 }, () =>
    fetch(origin + '/api/benchmark').then((response) => response.json())));
  assert.ok(parallel.every((result) => result.length === 5 && result[0].predictive.misses.length === 0));
  assert.ok(parallel.every((result) => result[0].predictive.actions.every(({ decision }) =>
    decision?.policy === POLICY_VERSION)));
});
