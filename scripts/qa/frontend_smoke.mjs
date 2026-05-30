const baseUrl = process.env.NETBOT_FRONTEND_URL || "http://127.0.0.1:5173";
const apiBaseUrl = process.env.NETBOT_API_BASE_URL || "http://127.0.0.1:8765/api";

async function fetchOk(url, label) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${label} returned HTTP ${response.status}`);
  }
  return response;
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
