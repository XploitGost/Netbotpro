function desktopRuntime() {
  if (typeof window === "undefined") return null;
  return window.netbotproDesktop || null;
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

export function buildWsEventsUrl(localToken) {
  const wsBase = getWsBase();
  const tokenQuery = localToken ? `?token=${encodeURIComponent(localToken)}` : "";
  if (wsBase) {
    return `${wsBase}/events${tokenQuery}`;
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}/ws/events${tokenQuery}`;
}
