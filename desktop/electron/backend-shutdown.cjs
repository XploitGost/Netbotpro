const { performance } = require('node:perf_hooks');

async function prepareBackendExit({ baseUrl, token, fetchImpl = fetch,
  attempts = 12, timeoutMs = 120000, requestTimeoutMs = 30000,
  sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms)),
  now = () => performance.now() }) {
  const deadline = now() + timeoutMs;
  for (let attempt = 0; attempt < attempts && now() < deadline; attempt++) {
    let response;
    try {
      response = await fetchImpl(`${baseUrl}/api/runtime/prepare-exit`, {
        method: 'POST', headers: { 'X-NetBot-Token': token },
        signal: AbortSignal.timeout(Math.max(1, Math.floor(Math.min(requestTimeoutMs, deadline - now())))),
      });
    } catch (_) {
      response = null;
    }
    if (response?.ok) {
      const state = await response.json();
      if (state.exit_prepared !== true || state.running !== false) {
        throw new Error('Backend did not confirm a drained shutdown');
      }
      return;
    }
    if (response && response.status !== 503) {
      throw new Error(`Backend shutdown preparation returned HTTP ${response.status}`);
    }
    if (attempt + 1 < attempts && now() < deadline) {
      await sleep(Math.min(1000, Math.max(0, deadline - now())));
    }
  }
  throw new Error('Backend shutdown preparation timed out; capture history was not discarded');
}

function stopChild(child, { graceMs = 4000, forceMs = 2000 } = {}) {
  if (!child || child.exitCode != null || child.signalCode != null) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const done = error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.off('exit', exited);
      child.off('error', failed);
      error ? reject(error) : resolve();
    };
    const exited = () => done();
    const failed = error => done(error);
    child.once('exit', exited);
    child.once('error', failed);
    timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (error) { done(error); }
      if (!settled) timer = setTimeout(() => done(new Error('Backend did not exit')), forceMs);
    }, graceMs);
    try { child.kill('SIGTERM'); } catch (error) { done(error); }
  });
}

function createExitCoordinator({ prepare, terminate, finish, onBegin = () => {}, onError = () => {} }) {
  let allowed = false;
  let pending = null;
  return {
    request(event) {
      if (allowed) return;
      event.preventDefault();
      if (pending) return;
      pending = Promise.resolve().then(onBegin).then(prepare).then(terminate).then(() => {
        allowed = true;
        finish();
      }).catch(error => {
        allowed = false;
        try { onError(error); } catch (_) { /* Keep the exit veto even if notification fails. */ }
      }).finally(() => { pending = null; });
    },
    pending: () => pending,
  };
}

module.exports = { prepareBackendExit, stopChild, createExitCoordinator };
