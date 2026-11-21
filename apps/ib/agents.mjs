import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const entry = fileURLToPath(new URL('./agent-worker.mjs', import.meta.url));
const roles = ['closing', 'settlement', 'treasury'];

export function createAgents({ timeout = 500, start = spawnAgent } = {}) {
  const slots = Object.fromEntries(roles.map((role) => [role, { pending: 0, chain: Promise.resolve(), process: null }]));
  let serial = 0;
  let closed = false;

  function retire(slot) {
    const child = slot.process;
    slot.process = null;
    if (child && child.exitCode === null) child.kill('SIGKILL');
  }

  function request(slot, role, revision, facts) {
    return new Promise((resolve, reject) => {
      if (closed) return reject(new Error('Agent pool is closed.'));
      const child = slot.process ??= start(role, spawnAgent);
      const job = ++serial;
      let settled = false;
      function finish(error, result) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.removeListener('message', onMessage);
        child.removeListener('exit', onExit);
        child.removeListener('error', finish);
        if (error) {
          retire(slot);
          reject(error);
        } else {
          resolve(result);
        }
      }
      function onExit() {
        finish(new Error('Agent exited before replying.'));
      }
      function onMessage(result) {
        if (result?.job !== job) return;
        finish(null, result);
      }
      const timer = setTimeout(() => finish(new Error('Agent deadline exceeded.')), timeout);
      child.once('exit', onExit);
      child.once('error', finish);
      child.on('message', onMessage);
      child.send({ job, revision, facts }, (error) => {
        if (error) finish(error);
      });
    });
  }

  return {
    ask(role, revision, facts) {
      const slot = slots[role];
      if (!slot || closed || slot.pending >= 128) return Promise.reject(new Error('Agent queue is unavailable.'));
      slot.pending += 1;
      const result = slot.chain.then(() => request(slot, role, revision, facts));
      slot.chain = result.catch(() => {}).finally(() => { slot.pending -= 1; });
      return result;
    },
    close() {
      closed = true;
      for (const slot of Object.values(slots)) retire(slot);
    },
  };
}

function spawnAgent(role) {
  const child = fork(entry, [role], {
    env: {},
    execArgv: ['--permission', `--allow-fs-read=${entry}`, '--max-old-space-size=48'],
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  });
  // A process may terminate between jobs.
  child.on('error', () => {});
  return child;
}
