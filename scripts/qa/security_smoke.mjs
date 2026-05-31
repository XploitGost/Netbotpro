import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const localTokenFile = path.join(repoRoot, ".runtime", "local-token.txt");
const apiBaseUrl = process.env.NETBOT_API_BASE_URL || "http://127.0.0.1:8765/api";
const localToken = process.env.NETBOT_LOCAL_TOKEN || readLocalTokenFile();
const timeoutMs = Number(process.env.NETBOT_SECURITY_SMOKE_TIMEOUT_MS || 8000);
const retries = Number(process.env.NETBOT_SECURITY_SMOKE_RETRIES || 2);

function readLocalTokenFile() {
  try {
    return fs.readFileSync(localTokenFile, "utf8").trim();
  } catch (_error) {
    return "";
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function requestOnce(pathname, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(`${apiBaseUrl}${pathname}`, {
      ...options,
      signal: controller.signal,
      headers: {
        ...(options.headers || {}),
      },
    });
  } catch (error) {
    const reason = error?.name === "AbortError"
      ? `timed out after ${timeoutMs}ms`
      : (error?.cause?.message || error?.message || "request failed");
    throw new Error(`${apiBaseUrl}${pathname} ${reason}`);
  } finally {
    clearTimeout(timer);
  }
}

async function request(pathname, options = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return await requestOnce(pathname, options);
    } catch (error) {
      lastError = error;
      if (attempt < retries) {
        await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
      }
    }
  }
  throw lastError;
}

async function expectStatus(label, pathname, expectedStatus, options = {}) {
  const response = await request(pathname, options);
  assert(
    response.status === expectedStatus,
    `${label} expected HTTP ${expectedStatus}, got HTTP ${response.status}`,
  );
  console.log(`[OK] ${label} - HTTP ${response.status}`);
  return response;
}

async function main() {
  if (!localToken) {
    throw new Error("security smoke requires NETBOT_LOCAL_TOKEN or .runtime/local-token.txt");
  }

  await expectStatus("status stays public-local", "/status", 200);
  await expectStatus("settings rejects missing token", "/settings", 401);
  await expectStatus("settings rejects bad token", "/settings", 401, {
    headers: { "X-NetBot-Token": "bad-token" },
  });
  await expectStatus("settings accepts local token", "/settings", 200, {
    headers: { "X-NetBot-Token": localToken },
  });
  await expectStatus("unsafe export path rejected", "/exports/download?path=..%2Fsecret.zip", 400, {
    headers: { "X-NetBot-Token": localToken },
  });
  await expectStatus("unsafe firewall target rejected", "/firewall/block", 400, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-NetBot-Token": localToken,
    },
    body: JSON.stringify({ ip: "127.0.0.1" }),
  });

  console.log("[OK] security smoke passed");
}

main().catch((error) => {
  console.error(`[FAIL] security smoke failed: ${error.message}`);
  process.exit(1);
});
