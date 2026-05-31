import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const localTokenFile = path.join(repoRoot, ".runtime", "local-token.txt");
const baseUrl = process.env.NETBOT_FRONTEND_URL || "http://127.0.0.1:5173";
const apiBaseUrl = process.env.NETBOT_API_BASE_URL || "http://127.0.0.1:8765/api";
const localToken = process.env.NETBOT_LOCAL_TOKEN || readLocalTokenFile();
const requestTimeoutMs = Number(process.env.NETBOT_SMOKE_TIMEOUT_MS || 8000);
const requestRetries = Number(process.env.NETBOT_SMOKE_RETRIES || 2);

function readLocalTokenFile() {
  try {
    return fs.readFileSync(localTokenFile, "utf8").trim();
  } catch (_error) {
    return "";
  }
}

async function fetchOnce(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
  try {
    return await fetch(url, {
      signal: controller.signal,
      headers: localToken ? { "X-NetBot-Token": localToken } : {},
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

async function fetchOk(url, label) {
  let lastError;
  for (let attempt = 0; attempt <= requestRetries; attempt += 1) {
    try {
      const response = await fetchOnce(url);
      if (!response.ok) {
        throw new Error(`${label} returned HTTP ${response.status}`);
      }
      return response;
    } catch (error) {
      lastError = error;
      if (attempt < requestRetries) {
        await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
      }
    }
  }
  throw lastError;
}

async function main() {
  const html = await (await fetchOk(baseUrl, "frontend")).text();
  for (const expected of ["NetBotPro", "root"]) {
    if (!html.includes(expected)) {
      throw new Error(`frontend HTML did not include ${expected}`);
    }
  }

  const status = await (await fetchOk(`${apiBaseUrl}/status`, "api status")).json();
  if (!status?.ok) {
    throw new Error("api status did not report ok=true");
  }

  const interfaces = await (await fetchOk(`${apiBaseUrl}/interfaces`, "api interfaces")).json();
  if (!interfaces?.preflight || !Array.isArray(interfaces.preflight.checks)) {
    throw new Error("api interfaces did not include capture preflight checks");
  }

  console.log("[OK] frontend smoke passed");
}

main().catch((error) => {
  console.error(`[FAIL] frontend smoke failed: ${error.message}`);
  process.exit(1);
});
