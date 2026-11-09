const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { prepareBackendExit, stopChild, createExitCoordinator } = require('./backend-shutdown.cjs');

const ack = () => ({ ok: true, json: async () => ({ running: false, exit_prepared: true }) });

test('preparation uses authenticated POST and requires the explicit drain acknowledgement', async () => {
  await prepareBackendExit({ baseUrl: 'http://127.0.0.1:8765', token: 'test-only-token',
    fetchImpl: async (url, options) => {
      assert.equal(url, 'http://127.0.0.1:8765/api/runtime/prepare-exit');
      assert.equal(options.method, 'POST');
      assert.equal(options.headers['X-NetBot-Token'], 'test-only-token');
      assert.ok(options.signal instanceof AbortSignal);
      return ack();
    } });
});

test('503 retries without terminating the backend', async () => {
  let calls = 0;
  await prepareBackendExit({ baseUrl: 'http://127.0.0.1', token: 'test', sleep: async () => {},
    fetchImpl: async () => ++calls < 3 ? { ok: false, status: 503 } : ack() });
  assert.equal(calls, 3);
});

test('authentication failure is not retried or accepted as a safe exit', async () => {
  let calls = 0;
  await assert.rejects(prepareBackendExit({ baseUrl: 'http://127.0.0.1', token: 'test',
    fetchImpl: async () => { calls++; return { ok: false, status: 401 }; } }), /HTTP 401/);
  assert.equal(calls, 1);
});

test('running or missing acknowledgement is rejected', async () => {
  for (const state of [{ running: true, exit_prepared: true }, { running: false }, {}]) {
    await assert.rejects(prepareBackendExit({ baseUrl: 'http://127.0.0.1', token: 'test',
      fetchImpl: async () => ({ ok: true, json: async () => state }) }), /did not confirm/);
  }
});

test('network failures have a bounded retry deadline', async () => {
  let clock = 0, calls = 0;
  await assert.rejects(prepareBackendExit({ baseUrl: 'http://127.0.0.1', token: 'test',
    timeoutMs: 10, now: () => clock, sleep: async ms => { clock += ms; },
    fetchImpl: async () => { calls++; throw new Error('unavailable'); } }), /timed out/);
  assert.equal(calls, 1);
});

test('reentrant close waits for preparation before terminate and quit', async () => {
  const calls = [];
  let release;
  const prepared = new Promise(resolve => { release = resolve; });
  const coordinator = createExitCoordinator({ prepare: async () => { calls.push('prepare'); await prepared; },
    terminate: () => calls.push('terminate'), finish: () => calls.push('quit') });
  let vetoes = 0;
  const event = { preventDefault: () => vetoes++ };
  coordinator.request(event);
  coordinator.request(event);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, ['prepare']);
  release();
  await coordinator.pending();
  assert.deepEqual(calls, ['prepare', 'terminate', 'quit']);
  coordinator.request(event);
  assert.equal(vetoes, 2);
});

test('failed preparation never kills and permits a later close retry', async () => {
  let attempts = 0, killed = 0, finished = 0, errors = 0;
  const coordinator = createExitCoordinator({ prepare: () => { if (++attempts === 1) throw new Error('busy'); },
    terminate: () => killed++, finish: () => finished++, onError: () => errors++ });
  const event = { preventDefault() {} };
  coordinator.request(event);
  await coordinator.pending();
  assert.equal(killed, 0);
  assert.equal(finished, 0);
  assert.equal(errors, 1);
  coordinator.request(event);
  await coordinator.pending();
  assert.equal(killed, 1);
  assert.equal(finished, 1);
});

test('notification failure cannot remove the close veto', async () => {
  const coordinator = createExitCoordinator({ prepare: () => { throw new Error('busy'); },
    terminate: () => assert.fail('must not kill'), finish: () => assert.fail('must not quit'),
    onError: () => { throw new Error('notification failed'); } });
  coordinator.request({ preventDefault() {} });
  await coordinator.pending();
});

test('post-drain process stop waits for exit and can escalate a stuck child', async () => {
  const child = new EventEmitter();
  child.exitCode = null;
  child.signalCode = null;
  const signals = [];
  child.kill = signal => { signals.push(signal); if (signal === 'SIGKILL') child.emit('exit', 0); return true; };
  await stopChild(child, { graceMs: 1, forceMs: 20 });
  assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(child.listenerCount('exit'), 0);
});

test('an exited child is not signalled again', async () => {
  await stopChild({ exitCode: 0, kill: () => assert.fail('already exited') });
});
