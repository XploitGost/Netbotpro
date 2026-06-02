function desktopRuntime() {
  if (typeof window === "undefined") return null;
  return window.netbotproDesktop || null;
}

const REMOTE_API_STORAGE_KEY = "netbot_remote_api_base";
const REMOTE_WS_STORAGE_KEY = "netbot_remote_ws_base";

function normalizeRemoteBase(value, suffix) {
  const text = String(value || "").trim();
  if (!text) return "";
  try {
    const parsed = new URL(text, window.location.href);
    if (!["http:", "https:", "ws:", "wss:"].includes(parsed.protocol)) {
      return "";
    }
    parsed.hash = "";
    parsed.search = "";
    const normalized = parsed.toString().replace(/\/+$/, "");
    if (!suffix || normalized.endsWith(suffix)) {
      return normalized;
    }
    return `${normalized}${suffix}`;
  } catch {
    return "";
  }
}

function readRemoteConfigParam(name, storageKey, suffix) {
  if (typeof window === "undefined") return "";
  try {
    const params = new URLSearchParams(window.location.search);
    const fromQuery = normalizeRemoteBase(params.get(name), suffix);
    if (fromQuery) {
      window.sessionStorage.setItem(storageKey, fromQuery);
      return fromQuery;
    }
  } catch {
  }
  try {
    return normalizeRemoteBase(window.sessionStorage.getItem(storageKey), suffix);
  } catch {
    return "";
  }
}

export function getDesktopRuntime() {
  return desktopRuntime();
}

export function getApiBase() {
  const runtime = desktopRuntime();
  if (runtime?.apiBase) return String(runtime.apiBase);
  const remoteApi = readRemoteConfigParam("api", REMOTE_API_STORAGE_KEY, "/api");
  if (remoteApi) return remoteApi;
  return "/api";
}

export function getWsBase() {
  const runtime = desktopRuntime();
  if (runtime?.wsBase) return String(runtime.wsBase);
  const remoteWs = readRemoteConfigParam("ws", REMOTE_WS_STORAGE_KEY, "/ws");
  if (remoteWs) return remoteWs;
  return "";
}

export function getManagedLocalToken() {
  const runtime = desktopRuntime();
  if (!runtime?.managedLocalToken || !runtime?.localToken) {
    return "";
  }
  return String(runtime.localToken);
}

export function isManagedLocalToken() {
  return Boolean(getManagedLocalToken());
}

function encodeProtocolToken(localToken) {
  const text = String(localToken || "").trim();
  if (!text) return "";
  if (typeof window !== "undefined" && typeof window.btoa === "function") {
    const bytes = typeof TextEncoder === "function" ? new TextEncoder().encode(text) : null;
    const binary = bytes ? Array.from(bytes, (value) => String.fromCharCode(value)).join("") : text;
    const utf8 = window.btoa(binary);
    return utf8.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  return "";
}

export function buildWsEventsTransport(localToken) {
  const wsBase = getWsBase();
  const protocols = ["netbot.v1"];
  const encodedToken = encodeProtocolToken(localToken);
  if (encodedToken) {
    protocols.push(`netbot.auth.${encodedToken}`);
  }
  if (wsBase) {
    return { url: `${wsBase}/events`, protocols };
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return { url: `${protocol}://${window.location.host}/ws/events`, protocols };
}
