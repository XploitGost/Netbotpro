function desktopRuntime() {
  if (typeof window === "undefined") return null;
  return window.netbotproDesktop || null;
}

export function getDesktopRuntime() {
  return desktopRuntime();
}

export function getApiBase() {
  const runtime = desktopRuntime();
  if (runtime?.apiBase) return String(runtime.apiBase);
  return "/api";
}

export function getWsBase() {
  const runtime = desktopRuntime();
  if (runtime?.wsBase) return String(runtime.wsBase);
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
