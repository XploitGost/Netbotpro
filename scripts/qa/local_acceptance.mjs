import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const localTokenFile = path.join(repoRoot, ".runtime", "local-token.txt");
const frontendUrl = process.env.NETBOT_FRONTEND_URL || "http://127.0.0.1:5173";
const apiBaseUrl = process.env.NETBOT_API_BASE_URL || "http://127.0.0.1:8765/api";
const localToken = process.env.NETBOT_LOCAL_TOKEN || readLocalTokenFile();
const requestTimeoutMs = Number(process.env.NETBOT_ACCEPTANCE_TIMEOUT_MS || 8000);
const requestRetries = Number(process.env.NETBOT_ACCEPTANCE_RETRIES || 2);
const enableCaptureCheck = /^(1|true|yes)$/i.test(process.env.NETBOT_ACCEPTANCE_CAPTURE || "");

const checks = [];

function readLocalTokenFile() {
  try {
    return fs.readFileSync(localTokenFile, "utf8").trim();
  } catch (_error) {
    return "";
  }
}

function record(label, ok, detail = "") {
  checks.push({ label, ok, detail });
  const status = ok ? "OK" : "FAIL";
  console.log(`[${status}] ${label}${detail ? ` - ${detail}` : ""}`);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function fetchOnce(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        ...(localToken ? { "X-NetBot-Token": localToken } : {}),
        ...(options.headers || {}),
      },
    });
  } catch (error) {
    const reason = error?.name === "AbortError"
      ? `timed out after ${requestTimeoutMs}ms`
      : (error?.cause?.message || error?.message || "request failed");
    throw new Error(`${url} ${reason}`);
  } finally {
    clearTimeout(timer);
  }
}

async function fetchWithTimeout(url, options = {}) {
  let lastError;
  for (let attempt = 0; attempt <= requestRetries; attempt += 1) {
    try {
      return await fetchOnce(url, options);
    } catch (error) {
      lastError = error;
      if (attempt < requestRetries) {
        await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
      }
    }
  }
  throw lastError;
}

async function getJson(path, label) {
  const response = await fetchWithTimeout(`${apiBaseUrl}${path}`);
  assert(response.ok, `${label} returned HTTP ${response.status}`);
  const payload = await response.json();
  record(label, true, `${path}`);
  return payload;
}

async function postJson(path, label, body = {}) {
  const response = await fetchWithTimeout(`${apiBaseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  assert(response.ok || response.status === 409, `${label} returned HTTP ${response.status}`);
  const payload = await response.json();
  record(label, true, response.ok ? path : `${path} returned expected unavailable state`);
  return { response, payload };
}

function expectObject(value, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
}

function expectPaginated(payload, label) {
  expectObject(payload, label);
  assert(Array.isArray(payload.items), `${label}.items must be an array`);
  assert(Number.isInteger(payload.total), `${label}.total must be an integer`);
  assert(Number.isInteger(payload.limit), `${label}.limit must be an integer`);
  assert(Number.isInteger(payload.offset), `${label}.offset must be an integer`);
}

async function checkFrontend() {
  const response = await fetchWithTimeout(frontendUrl);
  assert(response.ok, `frontend returned HTTP ${response.status}`);
  const html = await response.text();
  for (const expected of ["NetBotPro", "root"]) {
    assert(html.includes(expected), `frontend HTML did not include ${expected}`);
  }
  record("frontend shell", true, frontendUrl);
}

async function checkApiContracts() {
  const status = await getJson("/status", "api status");
  assert(status.ok === true, "api status must include ok=true");
  expectObject(status.sniffer, "status.sniffer");
  expectObject(status.observability, "status.observability");

  const interfaces = await getJson("/interfaces", "capture interfaces");
  const interfaceItems = Array.isArray(interfaces.items)
    ? interfaces.items
    : (Array.isArray(interfaces.interfaces) ? interfaces.interfaces : null);
  assert(Array.isArray(interfaceItems), "interfaces.items must be an array");
  expectObject(interfaces.preflight, "interfaces.preflight");
  assert(Array.isArray(interfaces.preflight.checks), "interfaces.preflight.checks must be an array");
  assert(typeof interfaces.preflight.ready === "boolean", "interfaces.preflight.ready must be boolean");
  record(
    "capture preflight",
    true,
    `${interfaceItems.length} interface(s), ready=${interfaces.preflight.ready}`,
  );

  const dashboard = await getJson("/dashboard", "dashboard contract");
  expectObject(dashboard.state, "dashboard.state");
  for (const listName of ["top_sources", "top_destinations", "top_protocols", "recent_alerts", "recent_packets"]) {
    assert(Array.isArray(dashboard[listName]), `dashboard.${listName} must be an array`);
  }

  const packets = await getJson("/packets?limit=5&offset=0", "packets contract");
  expectPaginated(packets, "packets");

  const alerts = await getJson("/alerts?limit=5&offset=0", "alerts contract");
  expectPaginated(alerts, "alerts");

  const settings = await getJson("/settings", "settings contract");
  expectObject(settings, "settings");

  const reports = await getJson("/reports", "reports contract");
  assert(Array.isArray(reports), "reports must be an array");
}

async function checkOptionalCaptureStart() {
  if (!enableCaptureCheck) {
    record("live capture start", true, "skipped; set NETBOT_ACCEPTANCE_CAPTURE=1 to exercise Start/Stop Sniffer");
    return;
  }

  const { response, payload } = await postJson("/sniffer/start", "live capture start");
  if (response.status === 409) {
    assert(payload.detail, "capture unavailable response should include detail");
    return;
  }
  expectObject(payload, "sniffer start response");
  await postJson("/sniffer/stop", "live capture stop");
}

async function main() {
  try {
    await checkFrontend();
    await checkApiContracts();
    await checkOptionalCaptureStart();
  } catch (error) {
    record("acceptance", false, error.message);
    process.exitCode = 1;
    return;
  }

  const failed = checks.filter((check) => !check.ok);
  if (failed.length) {
    process.exitCode = 1;
    return;
  }
  console.log(`[OK] local acceptance passed (${checks.length} checks)`);
}

main();
