import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { actions, applyCommand, CUTOFF, createDay, END, forecast, outcomes, START } from './domain.mjs';
import { createIbServer } from './server.mjs';
import { createAgents } from './agents.mjs';
import { isolatedBenchmark } from './intelligence.mjs';

const advance = (state, until, automatic = false) =>
  applyCommand(state, { type: 'advance', minutes: until - state.now, automatic });
const act = (state, id) => applyCommand(state, { type: 'act', id });

test('both policies share inputs and the predictive policy meets all deadlines after real misses', async (t) => {
  const agents = createAgents();
  t.after(() => agents.close());
  const cases = Object.fromEntries((await isolatedBenchmark(agents)).map((item) => [item.id, item]));
  const combined = cases.combined;
  assert.deepEqual(combined.reactive.misses.map(({ code }) => code),
    ['closing-missed', 'settlement-missed', 'margin-missed']);
  assert.deepEqual(combined.predictive.actions.map(({ at }) => at), [610, 685, 740]);
  assert.equal(combined.predictive.cost, 1_200_961);
  assert.equal(combined.reactive.cost, 2_000_000);
  assert.ok(!cases.closing.reactive.closing);
  assert.ok(!cases.matching.reactive.firm);
  assert.equal(cases.liquidity.reactive.marginAt, 885);
  assert.deepEqual(cases.clean.predictive.actions, []);
  for (const pair of Object.values(cases)) {
    assert.ok(pair.reactive.reconciled);
    assert.ok(pair.predictive.reconciled);
    for (const metric of ['closing', 'primary', 'firm', 'margin']) assert.ok(pair.predictive[metric]);
  }
});

test('forecast learns from visible signals and a rematch can avoid an unnecessary draw', () => {
  const start = createDay('combined');
  assert.deepEqual(forecast(start), forecast(createDay('clean')));
  assert.deepEqual(actions(advance(start, 609)), []);
  const delayed = advance(start, 610);
  assert.equal(forecast(delayed).closing, 762);
  assert.equal(actions(delayed)[0].id, 'closing');
  const released = advance(act(delayed, 'closing'), 685);
  assert.equal(released.release, 685);
  assert.notEqual(released.instructions.firm.received.custody, released.instructions.firm.delivered.custody);
  assert.equal(forecast(released).firm, null);
  assert.ok(forecast(released).gap > 0);
  const rematch = act(released, 'matching');
  assert.equal(forecast(rematch).firm, 757);
  assert.equal(forecast(rematch).gap, 0);
  const update = advance(rematch, 740);
  assert.equal(forecast(update).gap, 1_500_000_000);
  assert.equal(forecast(update).latest, 795);
  assert.deepEqual(actions(update).map(({ id }) => id), ['funding']);
  const funding = act(update, 'funding');
  assert.equal(funding.funding.net, 1_500_000_000);
  assert.equal(funding.funding.at, 785);
  assert.throws(() => act(funding, 'funding'), /indisponível/);
  const final = advance(funding, END);
  assert.ok(outcomes(final).margin);
  assert.equal(final.balance.cash.issuer, 9_000_000_000);
  assert.equal(final.balance.cash.firm, 0);
});

test('DvP moves both legs or neither, and unavailable cash cannot be substituted', () => {
  const start = createDay('clean');
  const compromised = structuredClone(start);
  compromised.balance.cash.buyer = 0;
  const day = advance(compromised, CUTOFF.firm);
  assert.equal(day.instructions.firm.settled, null);
  assert.equal(day.journal.some(({ ref }) => ref === 'firm'), false);
  assert.equal(day.balance['BV-DEB-02'].firm, start.balance['BV-DEB-02'].firm);
  assert.equal(day.balance.cash.firm, start.balance.cash.firm);
  assert.equal(day.balance.cash.issuer, 9_000_000_000);
  assert.equal(forecast(day).cash, start.balance.cash.firm);
  const normal = advance(start, CUTOFF.firm);
  assert.deepEqual(normal.journal.find(({ ref }) => ref === 'firm').legs.map((leg) => leg.asset),
    ['cash', 'BV-DEB-02']);
  assert.equal(normal.balance['BV-DEB-02'].buyer, 85_000);
  assert.equal(normal.balance.cash.firm, 12_000_000_000);
  assert.ok(outcomes(normal).reconciled);
});

async function launch(file) {
  const server = createIbServer(file);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    fetch: (path, options) => fetch(base + path, options),
    post: (body, headers = {}) => fetch(base + '/api/day', {
      method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
    }),
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

test('HTTP serves the operator workflow, rejects stale writes, and persists across restart', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'banco-vivo-ib-test-'));
  const path = join(dir, 'ib.sqlite');
  let app = await launch(path);
  t.after(async () => {
    if (app) await app.close();
    await rm(dir, { recursive: true });
  });
  const page = await app.fetch('/');
  assert.match(await page.text(), /Sala de operações/);
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal((await app.fetch('/app.mjs')).status, 200);
  assert.equal((await app.fetch('/style.css')).status, 200);
  assert.equal((await app.fetch('/api/scenarios').then((response) => response.json())).length, 5);
  const start = await app.fetch('/api/day').then((response) => response.json());
  assert.equal(start.now, START);
  const advanceDay = { dayId: start.dayId, version: start.version, type: 'advance', minutes: 70, automatic: false };
  assert.equal((await app.post(advanceDay, { origin: 'https://example.com' })).status, 403);
  assert.equal((await app.post({ ...advanceDay, type: 'act', id: 'matching' })).status, 400);
  assert.equal((await app.post({ ...advanceDay, invalid: 'x'.repeat(2048) })).status, 413);
  const responses = await Promise.all([app.post(advanceDay), app.post(advanceDay)]);
  assert.deepEqual(responses.map(({ status }) => status).sort(), [200, 409]);
  const updated = await responses.find(({ status }) => status === 200).json();
  assert.equal(updated.now, 610);
  assert.equal(updated.actions[0].id, 'closing');
  assert.equal((await app.fetch('/api/benchmark').then((response) => response.json())).length, 5);
  assert.deepEqual(await app.fetch('/api/day').then((response) => response.json()), updated);

  await app.close();
  app = await launch(path);
  assert.deepEqual(await app.fetch('/api/day').then((response) => response.json()), updated);
  const next = await app.post({ dayId: updated.dayId, version: updated.version,
    type: 'reset', scenario: 'matching', policy: 'reactive' }).then((response) => response.json());
  assert.equal(next.dayId, updated.dayId + 1);
  assert.equal(next.version, 0);
  assert.equal((await app.post(advanceDay)).status, 409);
  await app.close();
  app = null;
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    assert.deepEqual(db.prepare('SELECT DISTINCT day_id FROM events ORDER BY day_id').all().map(({ day_id }) => day_id), [1, 2]);
    assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
  } finally {
    db.close();
  }
});

test('storage rejects SQLite databases belonging to another application', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'banco-vivo-ib-foreign-'));
  try {
    const path = join(dir, 'foreign.sqlite');
    const db = new DatabaseSync(path);
    db.exec('CREATE TABLE external_data (id INTEGER PRIMARY KEY); INSERT INTO external_data VALUES(3)');
    db.close();
    assert.throws(() => createIbServer(path), /não é um SQLite compatível/);
    const check = new DatabaseSync(path, { readOnly: true });
    assert.equal(check.prepare('SELECT id FROM external_data').get().id, 3);
    check.close();
  } finally {
    await rm(dir, { recursive: true });
  }
});
