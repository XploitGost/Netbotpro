// Source-built desktop entry with synthetic transport, never a production capture.
import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const dist = path.join(repo, 'frontend/dist');
const output = path.join(repo, '.runtime/source-desktop-check');
await fs.mkdir(output, { recursive: true });
const server = http.createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    const file = path.resolve(dist, '.' + pathname);
    if (!file.startsWith(dist + path.sep)) { response.writeHead(403).end(); return; }
    response.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html');
    response.end(await fs.readFile(file));
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const packet = { id: 'fixture-packet', ts: '2026-01-01T12:00:01Z', src: '192.0.2.10', dst: '198.51.100.1', proto: 'ICMP', length: 74 };
const agent = { agent_id: 'fixture-agent', hostname: 'fixture-host', ip_address: '192.0.2.10', status: 'online', version: '0.2.0' };
let browser;
try {
  browser = await chromium.launch({ headless: true, ...(process.env.NETBOT_CHROME_PATH ? { executablePath: process.env.NETBOT_CHROME_PATH } : { channel: 'chrome' }) });
  for (const viewport of [{ width: 1672, height: 941 }, { width: 390, height: 844 }]) {
    const context = await browser.newContext({ viewport, reducedMotion: 'reduce' });
    const page = await context.newPage();
    const errors = [], requests = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(() => {
      window.WebSocket = class {
        constructor() { this.readyState = 1; window.fixtureSocket = this; setTimeout(() => this.onopen?.(), 0); }
        close() { this.readyState = 3; }
      };
    });
    await page.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== base) { await route.abort(); return; }
      if (!url.pathname.startsWith('/api/')) { await route.continue(); return; }
      requests.push(url.pathname);
      let body = {};
      switch (url.pathname) {
        case '/api/status': body = { ok: true, local_token_required: false }; break;
        case '/api/dashboard': body = { state: { running: true, packet_count: 100 }, recent_packets: [packet], recent_alerts: [] }; break;
        case '/api/settings': body = { iface: 'iface=default' }; break;
        case '/api/interfaces': body = { items: [], preflight: { ready: true, checks: [] } }; break;
        case '/api/agents': body = [agent]; break;
        case '/api/reports': body = []; break;
        case '/api/packets': body = { items: [{ ...packet, id: url.searchParams.get('offset') === '25' ? 'older' : packet.id }], total: 100, limit: 25, offset: Number(url.searchParams.get('offset') || 0), source: 'memory' }; break;
        case '/api/alerts': body = { items: [], total: 0, offset: 0, limit: 25 }; break;
        case '/api/packets/fixture-packet': body = packet; break;
        case '/api/packets/fixture-packet/context': body = { packet, related_alerts: [], related_packets: [packet] }; break;
        case '/api/packets/fixture-packet/details': body = { layers: [{ name: 'ICMP', fields: [] }], hex: { rows: [], warning: 'Metadata only' } }; break;
      }
      await route.fulfill({ json: body });
    });
    const navigate = async name => {
      if (viewport.width < 1000) await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
      await page.locator('nav.app-nav').getByRole('button', { name, exact: true }).click();
    };
    await page.goto(base + '/desktop.html');
    await page.getByRole('heading', { name: 'Command Center', exact: true }).waitFor();
    await navigate('Live Monitor');
    const panel = page.locator('.lm-packets');
    await panel.locator('tbody tr[tabindex]').first().waitFor();
    const follow = panel.getByRole('switch', { name: 'Auto-follow' });
    await follow.setChecked(false);
    assert.equal(await follow.isChecked(), false);
    await follow.click();
    await page.waitForFunction(() => document.querySelector('.lm-follow input')?.checked);
    assert.equal(await follow.isChecked(), true);
    await panel.locator('tbody tr[tabindex]').first().locator('td').first().click();
    await page.getByRole('heading', { name: 'Live Monitor', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Open in Investigate', exact: true }).click();
    await page.getByRole('heading', { name: 'Packet Investigation', exact: true }).waitFor();
    await page.getByRole('heading', { name: 'Key Findings', exact: true }).waitFor();
    await navigate('Fleet');
    await page.locator('.ff-table-wrap tbody tr').first().click();
    await page.locator('.ff-inspector').getByText('fixture-host', { exact: true }).waitFor();
    assert.ok(await page.locator('.ff-main').evaluate(node => node.getBoundingClientRect().top + scrollY) >= (viewport.width <= 600 ? 154 : 54));
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({ path: path.join(output, `fleet-${viewport.width}.png`), fullPage: true });
    await navigate('Live Monitor');
    await page.screenshot({ path: path.join(output, `monitor-${viewport.width}.png`), fullPage: true });
    // Frequent websocket updates must not restart every effect depending on the API client.
    const before = requests.filter(value => value === '/api/interfaces').length;
    await page.evaluate(value => {
      for (let index = 0; index < 30; index++) window.fixtureSocket?.onmessage?.({ data: JSON.stringify({ type: 'packet_batch', events: [{ type: 'packet:new', payload: { ...value, id: 'stream-' + index } }] }) });
    }, packet);
    await page.waitForTimeout(700);
    assert.ok(requests.filter(value => value === '/api/interfaces').length - before <= 1);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ viewport, sourceDesktop: true, syntheticTransport: true, navigation: true, selection: true, autoFollow: true, fleetInspector: true, errors }));
    await context.close();
  }
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
