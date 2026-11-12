// Explicit live test of a freshly packaged candidate, with disposable metadata storage.
import { _electron } from 'playwright';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { execFileSync } from 'node:child_process';

const executable = process.env.NETBOT_CANDIDATE_EXE;
const python = process.env.NETBOT_SMOKE_PYTHON_BIN;
const duration = Number(process.env.NETBOT_CANDIDATE_DURATION || 60);
assert.ok(executable && python, 'Explicit candidate executable and report Python are required');
assert.ok(duration >= 15 && duration <= 120, 'Live test must last 15..120 seconds');
await fs.access(executable);
const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'netbot-candidate-smoke-'));
const listener = net.createServer();
await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
const port = listener.address().port;
await new Promise(resolve => listener.close(resolve));
async function bytes(folder) {
  let total = 0;
  for (const entry of await fs.readdir(folder, { withFileTypes: true })) {
    const file = path.join(folder, entry.name);
    try { total += entry.isDirectory() ? await bytes(file) : (await fs.stat(file)).size; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return total;
}
let app, ownerPid, report, peakBytes = 0;
try {
  app = await _electron.launch({ executablePath: executable, args: [], timeout: 45000,
    env: { ...process.env, NETBOT_CANDIDATE_PROFILE: profile, NETBOT_PORT: String(port), NETBOT_HOST: '127.0.0.1', NETBOT_DISABLE_GPU: '1' } });
  ownerPid = app.process().pid;
  const window = await app.firstWindow();
  const errors = [];
  window.on('pageerror', error => errors.push(error.name));
  await window.getByRole('heading', { name: 'Command Center', exact: true }).waitFor({ timeout: 45000 });
  const runtime = await window.evaluate(() => window.netbotproDesktop);
  const request = async (endpoint, options = {}) => {
    const result = await fetch(`http://127.0.0.1:${port}/api${endpoint}`, { ...options,
      headers: { 'X-NetBot-Token': runtime.localToken, ...options.headers }, signal: AbortSignal.timeout(10000) });
    assert.ok(result.ok, `Candidate API status ${result.status}`);
    return result.json();
  };
  await window.locator('nav.app-nav').getByRole('button', { name: 'Live Monitor', exact: true }).click();
  const bar = window.locator('header[aria-label="Capture status"]');
  await bar.getByRole('button', { name: 'Start', exact: true }).click({ timeout: 20000 });
  await window.waitForFunction(() => { const stop = document.querySelector('.soc-stop'); return stop && !stop.disabled; }, null, { timeout: 20000 });
  console.log(JSON.stringify({ stage: 'capture_started', durationSeconds: duration, isolatedCandidate: true }));
  const started = Date.now();
  let pendingPeak = 0, interfaceChanges = 0, previousInterface, last;
  while (Date.now() - started < duration * 1000) {
    last = await request('/sniffer/state');
    assert.equal(last.running, true, 'Capture unexpectedly stopped');
    assert.ok(!last.ipc_callback_errors, 'Capture callback failure');
    pendingPeak = Math.max(pendingPeak, Number(last.journal_pending_records || 0));
    if (previousInterface && last.selected_iface && previousInterface !== last.selected_iface) interfaceChanges++;
    previousInterface = last.selected_iface || previousInterface;
    peakBytes = Math.max(peakBytes, await bytes(profile));
    assert.ok(peakBytes < 128 * 1024**2, 'Candidate storage budget exceeded');
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  const panel = window.locator('.lm-packets');
  await panel.locator('tbody tr[tabindex]').first().locator('td').first().click({ timeout: 10000 });
  await window.getByRole('button', { name: 'Open in Investigate', exact: true }).click();
  await window.getByRole('heading', { name: 'Key Findings', exact: true }).waitFor({ timeout: 15000 });
  await window.locator('nav.app-nav').getByRole('button', { name: 'Live Monitor', exact: true }).click();
  const follow = panel.getByRole('switch', { name: 'Auto-follow' });
  if (await follow.isChecked()) await follow.click();
  await follow.click();
  await window.waitForFunction(() => document.querySelector('.lm-follow input')?.checked);
  const stoppedAt = Date.now();
  await bar.getByRole('button', { name: 'Stop', exact: true }).click();
  await window.waitForFunction(() => { const start = document.querySelector('.soc-start'); return start && !start.disabled; });
  let final;
  for (let attempt = 0; attempt < 30; attempt++) {
    final = await request('/sniffer/state');
    if (!final.running) break;
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  assert.equal(final.running, false, 'Capture did not stop');
  const capture = final.observability?.capture || final;
  const persistence = final.observability?.persistence || {};
  report = { live: true, packagedCandidate: true, durationSeconds: Math.round((Date.now() - started) / 1000),
    accepted: capture.ipc_accepted, acknowledged: capture.journal_acknowledged_records,
    pendingFinal: capture.journal_pending_records, pendingPeak, interfaceChanges,
    historyFailed: persistence.failed_writes, historyDropped: persistence.dropped_writes,
    driverBufferDroppedReported: capture.driver_stats?.buffer_dropped_reported ?? null,
    driverCoverageComplete: capture.driver_stats?.coverage_complete ?? null,
    stopMilliseconds: Date.now() - stoppedAt, rendererErrors: errors.length, profilePeakBytes: peakBytes };
  console.log(JSON.stringify({ stage: 'capture_stopped', ...report }));
  assert.ok(report.acknowledged > 0, 'No history-confirmed traffic');
  assert.equal(report.accepted, report.acknowledged, 'Capture acknowledgement mismatch');
  assert.equal(report.pendingFinal, 0, 'Journal pending after Stop');
  assert.equal(report.historyFailed, 0, 'History write failure');
  assert.equal(report.historyDropped, 0, 'History write drop');
  assert.equal(report.rendererErrors, 0, 'Renderer error');
  assert.ok(!report.driverBufferDroppedReported, 'Driver reported drops');
  await app.close(); app = null;
  const log = await fs.readFile(path.join(profile, 'logs/desktop-backend.log'), 'utf8');
  assert.match(log, /capture and history drain confirmed/);
  const rows = Number(execFileSync(python, ['-c', 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute("SELECT COUNT(*) FROM packets").fetchone()[0]); c.close()', path.join(profile, 'data/history.db')], { encoding: 'utf8', windowsHide: true, timeout: 10000 }).trim());
  report.historyRows = rows;
  assert.equal(rows, report.acknowledged, 'Stored history mismatch');
} finally {
  if (app) {
    let timer;
    try { await Promise.race([app.close(), new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Candidate close deadline')), 15000); })]); }
    catch { if (ownerPid) execFileSync('taskkill', ['/PID', String(ownerPid), '/T', '/F'], { windowsHide: true, stdio: 'ignore', timeout: 10000 }); }
    finally { clearTimeout(timer); }
  }
  assert.equal(path.dirname(profile), path.resolve(os.tmpdir()));
  assert.ok(path.basename(profile).startsWith('netbot-candidate-smoke-'));
  await fs.rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}
console.log(JSON.stringify({ ...report, temporaryProfileRemoved: true }));
