import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { lstatSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createDay, presentation, scenarios,
} from './domain.mjs';
import { createAgents } from './agents.mjs';
import { execute, isolatedBenchmark, POLICY_VERSION } from './intelligence.mjs';

const staticFiles = new Map([
  ['/', ['index.html', 'text/html']],
  ['/app.mjs', ['app.mjs', 'text/javascript']],
  ['/style.css', ['style.css', 'text/css']],
]);
const web = fileURLToPath(new URL('./web/', import.meta.url));
const applicationId = 0x42564942;

function checkedPath(path, kind) {
  let entry;
  try {
    entry = lstatSync(path);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  if (!(kind === 'directory' ? entry.isDirectory() : entry.isFile()) || entry.isSymbolicLink()) {
    throw new Error('O armazenamento do IB precisa ser um arquivo local em diretório próprio.');
  }
}

function openDatabase(path) {
  if (path !== ':memory:') {
    checkedPath(dirname(dirname(path)), 'directory');
    checkedPath(dirname(path), 'directory');
    checkedPath(path, 'file');
    checkedPath(path + '-journal', 'file');
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  }
  const db = new DatabaseSync(path, { enableForeignKeyConstraints: true });
  try {
    db.exec('PRAGMA busy_timeout=3000; BEGIN IMMEDIATE');
    const { application_id: id } = db.prepare('PRAGMA application_id').get();
    const { user_version: version } = db.prepare('PRAGMA user_version').get();
    const { count } = db.prepare("SELECT COUNT(*) AS count FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").get();
    if (id === 0 && count === 0 && version === 0) {
      db.exec(`
        PRAGMA application_id=${applicationId};
        PRAGMA user_version=1;
        CREATE TABLE current_day (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), day_id INTEGER NOT NULL, body TEXT NOT NULL);
        CREATE TABLE events (day_id INTEGER NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL,
          PRIMARY KEY (day_id, seq));
      `);
    } else if (id !== applicationId || version !== 1) {
      throw new Error('O arquivo informado não é um SQLite compatível do IB.');
    }
    const initial = createDay();
    const { changes } = db.prepare('INSERT OR IGNORE INTO current_day VALUES (1, 1, ?)').run(JSON.stringify(initial));
    if (changes) db.prepare('INSERT INTO events VALUES (1, 1, ?)').run(JSON.stringify(initial.events[0]));
    db.exec('COMMIT');
  } catch (error) {
    db.close();
    throw error;
  }
  return db;
}

function dataStore(path) {
  const db = openDatabase(path);
  const load = db.prepare('SELECT day_id, body FROM current_day WHERE singleton = 1');
  const update = db.prepare('UPDATE current_day SET day_id = ?, body = ? WHERE singleton = 1');
  const insert = db.prepare('INSERT INTO events VALUES (?, ?, ?)');
  return {
    read() {
      const { day_id: dayId, body } = load.get();
      return { dayId, ...presentation(JSON.parse(body)), intelligencePolicy: POLICY_VERSION };
    },
    async change(input, agents) {
      if (!input || !Number.isSafeInteger(input.dayId) || !Number.isSafeInteger(input.version)) {
        throw new RangeError('Identificação do dia ou versão inválida.');
      }
      function assertCurrent(row) {
        const state = JSON.parse(row.body);
        if (input.dayId !== row.day_id || input.version !== state.version) {
          const error = new Error('O dia já mudou. Atualize o painel e tente novamente.');
          error.status = 409;
          throw error;
        }
        return state;
      }
      const initial = load.get();
      const current = assertCurrent(initial);
      const dayId = initial.day_id;
      const nextDay = input.type === 'reset' ? dayId + 1 : dayId;
      const next = nextDay !== dayId ? createDay(input.scenario, input.policy) : await execute(current, input, agents);
      const view = { dayId: nextDay, ...presentation(next), intelligencePolicy: POLICY_VERSION };
      db.exec('BEGIN IMMEDIATE');
      try {
        // Agents run outside the SQLite lock. A newer operator command wins.
        assertCurrent(load.get());
        for (const event of next.events.slice(nextDay === dayId ? current.events.length : 0)) {
          insert.run(nextDay, event.id, JSON.stringify(event));
        }
        update.run(nextDay, JSON.stringify(next));
        db.exec('COMMIT');
        return view;
      } catch (error) {
        db.exec('ROLLBACK');
        throw error;
      }
    },
    close: () => db.close(),
  };
}

async function readCommand(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] ?? '')) {
    const error = new Error('Envie o comando como JSON.');
    error.status = 415;
    throw error;
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size <= 2048) chunks.push(chunk);
  }
  if (size > 2048) {
    const error = new Error('Comando excedeu o limite.');
    error.status = 413;
    throw error;
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function respond(response, status, payload, mime = 'application/json') {
  response.writeHead(status, {
    'Content-Type': `${mime}; charset=utf-8`,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'Referrer-Policy': 'no-referrer',
  });
  response.end(mime === 'application/json' ? JSON.stringify(payload) : payload);
}

export function createIbServer(file, { agentOptions } = {}) {
  const store = dataStore(file);
  const agents = createAgents(agentOptions);
  let benchmarkInFlight;
  let activeWrites = 0;
  const server = createServer({ maxHeaderSize: 4096, requestTimeout: 5_000 }, async (request, response) => {
    try {
      const host = request.headers.host;
      if (!host || !/^127\.0\.0\.1:\d+$/.test(host) ||
          request.headers.origin && request.headers.origin !== `http://${host}` ||
          request.headers['sec-fetch-site'] === 'cross-site') {
        return respond(response, 403, { error: 'Acesso permitido apenas no endereço local.' });
      }
      if (request.method === 'GET') {
        if (request.url === '/api/day') return respond(response, 200, store.read());
        if (request.url === '/api/benchmark') {
          benchmarkInFlight ??= isolatedBenchmark(agents).finally(() => { benchmarkInFlight = undefined; });
          return respond(response, 200, await benchmarkInFlight);
        }
        if (request.url === '/api/scenarios') return respond(response, 200, Object.entries(scenarios).map(([id, { name }]) => ({ id, name })));
        const staticFile = staticFiles.get(request.url);
        if (staticFile) {
          const [name, mime] = staticFile;
          return respond(response, 200, readFileSync(join(web, name)), mime);
        }
      }
      if (request.method === 'POST' && request.url === '/api/day') {
        if (activeWrites >= 16) return respond(response, 429, { error: 'A fila do IB está ocupada. Tente novamente.' });
        activeWrites += 1;
        try {
          return respond(response, 200, await store.change(await readCommand(request), agents));
        } finally {
          activeWrites -= 1;
        }
      }
      return respond(response, 404, { error: 'Rota inexistente.' });
    } catch (error) {
      if (response.destroyed) return;
      const status = error.status ?? (error instanceof SyntaxError || error instanceof RangeError ? 400 : 500);
      if (status === 500) console.error(error);
      respond(response, status, { error: status === 500 ? 'Falha local no processamento.' : error.message });
    }
  });
  server.once('close', () => {
    agents.close();
    store.close();
  });
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.IB_PORT ?? '3100');
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new RangeError('IB_PORT inválida.');
  const file = process.argv.includes('--memory') ? ':memory:' :
    fileURLToPath(new URL('../../data/investment-banking/ib.sqlite', import.meta.url));
  createIbServer(file).listen(port, '127.0.0.1', () => console.log(`Banco Vivo IB · http://127.0.0.1:${port}`));
}
