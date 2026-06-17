import { buildAuthHeaders } from "./useLocalAuth";
import { getApiBase } from "../lib/runtimeConfig";

async function readResponsePayload(res) {
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }
  try {
    const text = await res.text();
    return text ? { detail: text } : null;
  } catch {
    return null;
  }
}

function inferDownloadFilename(exportPath, res) {
  const disposition = res.headers.get("content-disposition") || "";
  const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
    }
  }
  const plainMatch = disposition.match(/filename="?([^";]+)"?/i);
  if (plainMatch?.[1]) {
    return plainMatch[1];
  }
  const parts = String(exportPath || "").split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] || "netbotpro-export";
}

export function useApiClient(localToken) {
  const apiBase = getApiBase();

  async function request(path, options = {}) {
    const res = await fetch(`${apiBase}${path}`, {
      ...options,
      headers: buildAuthHeaders(localToken, options.headers || {}),
    });
    const data = await readResponsePayload(res);
    if (!res.ok) {
      throw new Error(data?.detail || `Request failed for ${path} (${res.status})`);
    }
    return data ?? {};
  }

  return {
    apiBase,
    getStatus: () => request("/status"),
    getDashboard: () => request("/dashboard"),
    getMonitoringMetrics: () => request("/monitoring/metrics"),
    getSettings: () => request("/settings"),
    getInterfaces: () => request("/interfaces"),
    getAgents: () => request("/agents"),
    getFlows: (params = {}) => request(`/flows?${new URLSearchParams(params).toString()}`),
    getFlowsSummary: () => request("/flows/summary"),
    getFlow: (id) => request(`/flows/${encodeURIComponent(id)}`),
    getFlowTimeline: (id) => request(`/flows/${encodeURIComponent(id)}/timeline`),
    getConversations: () => request("/conversations"),
    getProtocolsSummary: () => request("/protocols/summary"),
    getProtocolIntelligence: () => request("/protocols/intelligence"),
    getFlowSummaryReport: () => request("/reports/flows/summary"),
    getAgentsOverview: () => request("/agents/overview"),
    getAgentAlertsSummary: () => request("/agents/alerts/summary"),
    getAgentRiskSummary: () => request("/agents/risk/summary"),
    getAgentFleetSummary: () => request("/agents/reports/fleet-summary"),
    getAgent: (id) => request(`/agents/${encodeURIComponent(id)}`),
    getAgentTelemetry: (id, range = "24h") => request(`/agents/${encodeURIComponent(id)}/telemetry?range=${encodeURIComponent(range)}`),
    getAgentHealthHistory: (id, range = "24h") => request(`/agents/${encodeURIComponent(id)}/health/history?range=${encodeURIComponent(range)}`),
    getAgentAlertsHistory: (id, range = "24h") => request(`/agents/${encodeURIComponent(id)}/alerts/history?range=${encodeURIComponent(range)}`),
    getAgentRiskHistory: (id, range = "24h") => request(`/agents/${encodeURIComponent(id)}/risk/history?range=${encodeURIComponent(range)}`),
    putSettings: (payload) => request("/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }),
    startSniffer: (payload) => request("/sniffer/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }),
    stopSniffer: () => request("/sniffer/stop", { method: "POST" }),
    resetSession: () => request("/session/reset", { method: "POST" }),
    getPackets: (params) => request(`/packets?${new URLSearchParams(params).toString()}`),
    getPacketDetail: (id) => request(`/packets/${encodeURIComponent(id)}`),
    getPacketContext: (id) => request(`/packets/${encodeURIComponent(id)}/context`),
    getPacketDissection: (id) => request(`/packets/${encodeURIComponent(id)}/details`),
    getPacketHex: (id) => request(`/packets/${encodeURIComponent(id)}/hex`),
    getPacketExpert: (id) => request(`/packets/${encodeURIComponent(id)}/expert`),
    getPacketFilterHelp: () => request("/packets/filter/help"),
    getPacketFilterSuggestions: () => request("/packets/filter/suggestions"),
    getSavedFilters: () => request("/filters"),
    createSavedFilter: (payload) => request("/filters", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }),
    searchPackets: (query) => request(`/packets/search?q=${encodeURIComponent(query)}`),
    getFlowStream: (id) => request(`/flows/${encodeURIComponent(id)}/stream`),
    getExpertSummary: () => request("/expert/summary"),
    getAlerts: (params) => request(`/alerts?${new URLSearchParams(params).toString()}`),
    getAlertDetail: (id) => request(`/alerts/${encodeURIComponent(id)}`),
    getAlertContext: (id) => request(`/alerts/${encodeURIComponent(id)}/context`),
    getReports: () => request("/reports"),
    runTraceroute: (payload) => request("/traceroute", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }),
    exportSession: (payload) => request("/exports/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }),
    exportInvestigation: (payload) => request("/exports/investigation", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }),
    downloadExport: async (exportPath) => {
      const res = await fetch(`${apiBase}/exports/download?path=${encodeURIComponent(exportPath)}`, {
        headers: buildAuthHeaders(localToken),
      });
      if (!res.ok) {
        const data = await readResponsePayload(res);
        throw new Error(data?.detail || `Export download failed (${res.status})`);
      }
      return {
        blob: await res.blob(),
        filename: inferDownloadFilename(exportPath, res),
      };
    },
    analyzePcap: async (file) => {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(`${apiBase}/analyze-pcap`, { method: "POST", headers: buildAuthHeaders(localToken), body: form });
      const data = await readResponsePayload(res);
      if (!res.ok) {
        throw new Error(data?.detail || `Offline analysis failed (${res.status})`);
      }
      return data ?? {};
    },
  };
}
