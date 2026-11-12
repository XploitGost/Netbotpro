// Exercise the standard frontend build, NOT the preserved desktop overlay.
import { chromium } from "playwright";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const dist = path.join(repo, "frontend/dist");
await fs.access(path.join(dist, "app.html"));
const server = http.createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, "http://localhost").pathname;
    const file = path.resolve(dist, "." + (pathname === "/" ? "/app.html" : pathname));
    if (!file.startsWith(dist + path.sep)) { response.writeHead(403).end(); return; }
    const content = await fs.readFile(file);
    response.setHeader("Content-Type", file.endsWith(".js") ? "text/javascript" : file.endsWith(".css") ? "text/css" : "text/html");
    response.end(content);
  } catch { response.writeHead(404).end(); }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const packet = (id, octet) => ({ id, ts: "12:00:01", src: `192.0.2.${octet}`, dst: "198.51.100.1", proto: "ICMP", length: 74 });
let browser;
try {
  browser = await chromium.launch({ headless: true,
    ...(process.env.NETBOT_CHROME_PATH ? { executablePath: process.env.NETBOT_CHROME_PATH } : { channel: "chrome" }) });
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
    const context = await browser.newContext({ viewport });
    const page = await context.newPage();
    const errors = [];
    const queries = [];
    let unavailable = false;
    page.on("pageerror", (error) => errors.push(error.message));
    await page.addInitScript(() => {
      const sockets = [];
      window.WebSocket = class {
        constructor() { this.readyState = 1; sockets.push(this); setTimeout(() => this.onopen?.(), 0); }
        close() { this.readyState = 3; }
      };
      window.emitFixturePacket = (packet) => sockets.at(-1)?.onmessage?.({ data: JSON.stringify({
        type: "packet_batch", events: [{ type: "packet:new", payload: packet }],
      }) });
    });
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== base) { await route.abort(); return; }
      if (!url.pathname.startsWith("/api/")) { await route.continue(); return; }
      let body = {};
      switch (url.pathname) {
        case "/api/status": body = { ok: true, local_token_required: false }; break;
        case "/api/dashboard": body = { state: { running: true, packet_count: 100 },
          recent_packets: [packet("seed", 1)], recent_alerts: [] }; break;
        case "/api/settings": body = { iface: "iface=default" }; break;
        case "/api/interfaces": body = { items: [], preflight: { ready: true, checks: [] } }; break;
        case "/api/agents": case "/api/reports": body = []; break;
        case "/api/packets": {
          queries.push(Object.fromEntries(url.searchParams));
          if (unavailable) {
            await route.fulfill({ status: 503, json: { detail: "Fixture history unavailable" } }); return;
          }
          const offset = Number(url.searchParams.get("offset") || 0);
          body = { items: [packet("page-" + offset, offset === 0 ? 10 : 25)], total: 100, limit: 25, offset, source: "memory" };
          break;
        }
        case "/api/alerts": body = { items: [], total: 0, offset: 0, limit: 25 }; break;
      }
      await route.fulfill({ json: body });
    });
    await page.goto(base + "/app.html?page=monitor");
    const panel = page.locator("section.page-card").filter({ has: page.getByRole("heading", { name: "Packets", exact: true }) });
    await panel.getByRole("button", { name: "Pause Auto Follow", exact: true }).waitFor();
    await panel.getByRole("button", { name: "Next", exact: true }).click();
    await panel.getByRole("button", { name: "Resume Auto Follow", exact: true }).waitFor();
    await panel.getByRole("button", { name: "192.0.2.25", exact: true }).first().waitFor();
    assert.match(await panel.locator("tbody").innerText(), /192\.0\.2\.25/);
    await panel.getByRole("button", { name: "Resume Auto Follow", exact: true }).click();
    await panel.getByRole("button", { name: "Pause Auto Follow", exact: true }).waitFor();
    await panel.getByRole("button", { name: "192.0.2.10", exact: true }).first().waitFor();
    assert.equal(queries.at(-1).offset, "0");
    assert.match(await panel.locator("tbody").innerText(), /192\.0\.2\.10/);
    await panel.getByRole("button", { name: "Pause Auto Follow", exact: true }).click();
    await page.evaluate((value) => window.emitFixturePacket(value), packet("paused", 99));
    await panel.getByText("Rows: 101 from memory", { exact: true }).waitFor();
    assert.doesNotMatch(await panel.locator("tbody").innerText(), /192\.0\.2\.99/);
    unavailable = true;
    await panel.getByRole("button", { name: "Resume Auto Follow", exact: true }).click();
    await page.getByText("Fixture history unavailable", { exact: true }).waitFor();
    assert.equal(await panel.getByRole("button", { name: "Resume Auto Follow", exact: true }).count(), 1);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ viewport, standardFrontend: true, mockedTransport: true,
      resumeAtNewestPage: true, pauseStable: true, failedResumeStaysPaused: true, pageErrors: errors.length }));
    await context.close();
  }
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
