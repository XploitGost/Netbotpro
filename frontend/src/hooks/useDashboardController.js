import { useEffect, useMemo, useRef, useState } from "react";
import { useApiClient } from "./useApiClient";
import { useLocalAuth } from "./useLocalAuth";
import { useLiveEvents } from "./useLiveEvents";
import { getPeerInfo, isPrivateIp } from "../lib/networkView";

export const PAGE_SIZE = 25;
const TIMELINE_BUCKETS = 30;
const TIMELINE_BUCKET_MS = 2_000;
const HISTORY_CACHE_TTL_MS = 5_000;

const defaultSettings = {
  iface: "iface=default",
  ids_ml_threshold: 0.25,
  tr_timeout: 1.5,
  tr_mode: "UDP",
  auto_block: false,
  persist_logs: false,
  whitelist_ips: "",
};

function createTimeline(now = Date.now()) {
  const base = now - (TIMELINE_BUCKETS - 1) * TIMELINE_BUCKET_MS;
  return Array.from({ length: TIMELINE_BUCKETS }, (_, index) => {
    const bucketTime = base + index * TIMELINE_BUCKET_MS;
    return {
      time: bucketTime,
      label: new Date(bucketTime).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      packets: 0,
      alerts: 0,
      alertScore: 0,
    };
  });
}

function normalizeTimeline(current, now = Date.now()) {
  const timeline = current.length ? current.map((item) => ({ ...item })) : createTimeline(now);
  while (timeline.length && now - timeline[timeline.length - 1].time >= TIMELINE_BUCKET_MS) {
    const nextTime = timeline[timeline.length - 1].time + TIMELINE_BUCKET_MS;
    timeline.shift();
    timeline.push({
      time: nextTime,
      label: new Date(nextTime).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      packets: 0,
      alerts: 0,
      alertScore: 0,
    });
  }
  return timeline;
}

function parseTimestamp(value) {
  if (!value) return Date.now();
  const direct = Date.parse(value);
  if (!Number.isNaN(direct)) return direct;
  const match = /^(\d{2}):(\d{2}):(\d{2})$/.exec(String(value).trim());
  if (match) {
    const now = new Date();
    now.setHours(Number(match[1]), Number(match[2]), Number(match[3]), 0);
    return now.getTime();
  }
  return Date.now();
}

function recordTimelineSample(current, kind, sample) {
  const sampleTime = parseTimestamp(sample?.ts);
  const next = normalizeTimeline(current, Math.max(Date.now(), sampleTime));
  if (!next.length) return next;
  const bucketIndex = Math.max(0, Math.min(next.length - 1, Math.floor((sampleTime - next[0].time) / TIMELINE_BUCKET_MS)));
  const bucket = { ...next[bucketIndex] };
  if (kind === "packet") {
    bucket.packets += 1;
  } else {
    bucket.alerts += 1;
    bucket.alertScore = Math.max(bucket.alertScore, Number(sample?.score || 0));
  }
  next[bucketIndex] = bucket;
  return next;
}

function seedTimeline(packets, alerts) {
  let timeline = createTimeline();
  [...(packets || [])].reverse().forEach((packet) => {
    timeline = recordTimelineSample(timeline, "packet", packet);
  });
  [...(alerts || [])].reverse().forEach((alert) => {
    timeline = recordTimelineSample(timeline, "alert", alert);
  });
  return timeline;
}

function appendBatchToTimeline(current, kind, messages) {
  return messages.reduce((timeline, message) => recordTimelineSample(timeline, kind, message.payload), current);
}

function chooseFocusTarget(item, preferredRole = "either") {
  const src = String(item?.src || "").trim();
  const dst = String(item?.dst || "").trim();
  const peer = getPeerInfo(item);
  if (preferredRole === "src" && src) return { ip: src, role: "src" };
  if (preferredRole === "dst" && dst) return { ip: dst, role: "dst" };
  if (peer.ip && peer.ip !== "-") return { ip: peer.ip, role: peer.role };
  if (src && dst) {
    if (isPrivateIp(src) && !isPrivateIp(dst)) return { ip: dst, role: "dst" };
    if (isPrivateIp(dst) && !isPrivateIp(src)) return { ip: src, role: "src" };
  }
  if (src) return { ip: src, role: "src" };
  if (dst) return { ip: dst, role: "dst" };
  return null;
}

function matchesFocusedTarget(row, focusedTarget) {
  if (!focusedTarget?.ip) return false;
  if (focusedTarget.role === "dst") return String(row?.dst || "") === focusedTarget.ip;
  if (focusedTarget.role === "src") return String(row?.src || "") === focusedTarget.ip;
  return String(row?.src || "") === focusedTarget.ip || String(row?.dst || "") === focusedTarget.ip;
}

function getPacketId(packet, index, offset = 0) {
  return String(packet?.id ?? offset + index);
}

function getAlertId(alert, index, offset = 0) {
  return String(alert?.id ?? offset + index);
}

function buildHistoryCacheKey(query, offset) {
  return JSON.stringify({ query, offset, limit: PAGE_SIZE });
}

export function useDashboardController() {
  const { localToken, setLocalToken } = useLocalAuth();
  const api = useApiClient(localToken);
  const [activePage, setActivePage] = useState("monitor");
  const [dashboard, setDashboard] = useState(null);
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [packetQuery, setPacketQuery] = useState({ src: "", dst: "", proto: "", text: "", only_alerts: false, only_remote: true });
  const [alertQuery, setAlertQuery] = useState({ src: "", dst: "", attack: "", proto: "", text: "", min_score: "", only_remote: true });
  const [packetMeta, setPacketMeta] = useState({ total: 0, source: "memory", offset: 0, limit: PAGE_SIZE });
  const [alertMeta, setAlertMeta] = useState({ total: 0, source: "memory", offset: 0, limit: PAGE_SIZE });
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedPacketId, setSelectedPacketId] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [settings, setSettings] = useState(defaultSettings);
  const [interfaces, setInterfaces] = useState([]);
  const [recommendedInterface, setRecommendedInterface] = useState("");
  const [recommendedInterfaceLabel, setRecommendedInterfaceLabel] = useState("");
  const [tracerouteTarget, setTracerouteTarget] = useState("");
  const [tracerouteResult, setTracerouteResult] = useState(null);
  const [offlineFile, setOfflineFile] = useState(null);
  const [offlineResult, setOfflineResult] = useState(null);
  const [exportInfo, setExportInfo] = useState(null);
  const [reports, setReports] = useState([]);
  const [connectionState, setConnectionState] = useState("connecting");
  const [statusMessage, setStatusMessage] = useState("Connecting to local backend...");
  const [observability, setObservability] = useState({});
  const [error, setError] = useState("");
  const [localTokenRequired, setLocalTokenRequired] = useState(false);
  const [liveFollow, setLiveFollow] = useState(true);
  const [focusedTarget, setFocusedTarget] = useState(null);
  const [timeline, setTimeline] = useState(() => createTimeline());
  const packetOffsetRef = useRef(0);
  const alertOffsetRef = useRef(0);
  const focusQuerySnapshotRef = useRef(null);
  const packetHistoryCacheRef = useRef(new Map());
  const alertHistoryCacheRef = useRef(new Map());

  function clearHistoryCaches() {
    packetHistoryCacheRef.current.clear();
    alertHistoryCacheRef.current.clear();
  }

  function readCache(cacheRef, key) {
    const entry = cacheRef.current.get(key);
    if (!entry || entry.expiresAt <= Date.now()) {
      cacheRef.current.delete(key);
      return null;
    }
    return entry.data;
  }

  function writeCache(cacheRef, key, data) {
    cacheRef.current.set(key, { data, expiresAt: Date.now() + HISTORY_CACHE_TTL_MS });
  }

  function mergeObservability(next) {
    if (!next || typeof next !== "object") return;
    setObservability((current) => ({
      ...current,
      ...next,
      event_bus: next.event_bus || current.event_bus,
      persistence: next.persistence || current.persistence,
      auto_block: next.auto_block || current.auto_block,
      history: next.history || current.history,
    }));
  }

  useEffect(() => {
    packetOffsetRef.current = packetMeta.offset;
  }, [packetMeta.offset]);

  useEffect(() => {
    alertOffsetRef.current = alertMeta.offset;
  }, [alertMeta.offset]);

  useEffect(() => {
    let active = true;

    async function loadInitial() {
      try {
        const [dashboardData, settingsData, interfacesData] = await Promise.all([
          api.getDashboard(),
          api.getSettings(),
          api.getInterfaces().catch(() => ({ recommended: "", items: [] })),
        ]);
        if (!active) return;
        clearHistoryCaches();
        setDashboard(dashboardData);
        mergeObservability(dashboardData.observability || dashboardData.state?.observability || {});
        setLocalTokenRequired(Boolean(dashboardData.local_token_required));
        setPackets(dashboardData.recent_packets || []);
        setAlerts(dashboardData.recent_alerts || []);
        setTimeline(seedTimeline(dashboardData.recent_packets || [], dashboardData.recent_alerts || []));
        setPacketMeta({ total: dashboardData.state?.packet_count || 0, source: "memory", offset: 0, limit: PAGE_SIZE });
        setAlertMeta({ total: dashboardData.state?.total_alerts || 0, source: "memory", offset: 0, limit: PAGE_SIZE });
        const interfaceItems = interfacesData.items || [];
        const validValues = new Set(interfaceItems.map((item) => item.value));
        const nextIface = validValues.has(settingsData.iface) ? settingsData.iface : "iface=default";
        setSettings((current) => ({ ...current, ...settingsData, iface: nextIface || current.iface || "iface=default" }));
        setInterfaces(interfaceItems);
        setRecommendedInterface(interfacesData.recommended || "");
        setRecommendedInterfaceLabel(interfacesData.recommended_label || "");
        const reportsData = await api.getReports();
        if (!active) return;
        setReports(reportsData || []);
        setStatusMessage("Dashboard synced");
      } catch (err) {
        if (!active) return;
        setError(String(err));
        setStatusMessage("Unable to load initial data");
      }
    }

    loadInitial();
    return () => {
      active = false;
    };
  }, [localToken]);

  async function loadPacketHistory(customQuery = packetQuery, offset = packetMeta.offset) {
    const params = new URLSearchParams();
    Object.entries(customQuery).forEach(([key, value]) => {
      if (typeof value === "boolean") {
        if (value) params.set(key, "true");
      } else if (String(value || "").trim()) {
        params.set(key, String(value));
      }
    });
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", String(offset));
    const cacheKey = buildHistoryCacheKey(customQuery, offset);
    const cached = readCache(packetHistoryCacheRef, cacheKey);
    const data = cached || await api.getPackets(params);
    if (!cached) writeCache(packetHistoryCacheRef, cacheKey, data);
    mergeObservability(data.observability || {});
    setPackets(data.items || []);
    setPacketMeta({ total: data.total || 0, source: data.source || "memory", offset: data.offset || 0, limit: data.limit || PAGE_SIZE });
    setSelectedPacket(null);
    setSelectedPacketId("");
    if (data.query_ms != null) {
      setStatusMessage(`Packet history loaded in ${data.query_ms} ms`);
    }
  }

  async function loadAlertHistory(customQuery = alertQuery, offset = alertMeta.offset) {
    const params = new URLSearchParams();
    Object.entries(customQuery).forEach(([key, value]) => {
      if (typeof value === "boolean") {
        if (value) params.set(key, "true");
      } else if (String(value || "").trim()) {
        params.set(key, String(value));
      }
    });
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", String(offset));
    const cacheKey = buildHistoryCacheKey(customQuery, offset);
    const cached = readCache(alertHistoryCacheRef, cacheKey);
    const data = cached || await api.getAlerts(params);
    if (!cached) writeCache(alertHistoryCacheRef, cacheKey, data);
    mergeObservability(data.observability || {});
    setAlerts(data.items || []);
    setAlertMeta({ total: data.total || 0, source: data.source || "memory", offset: data.offset || 0, limit: data.limit || PAGE_SIZE });
    setSelectedAlert(null);
    setSelectedAlertId("");
    if (data.query_ms != null) {
      setStatusMessage(`Alert history loaded in ${data.query_ms} ms`);
    }
  }

  async function loadReports() {
    const data = await api.getReports();
    setReports(data || []);
  }

  async function loadPacketDetail(packet, index) {
    try {
      const packetId = getPacketId(packet, index, packetMeta.offset);
      setSelectedPacketId(packetId);
      setSelectedPacket(await api.getPacketDetail(packetId));
      setActivePage("monitor");
    } catch (err) {
      setError(String(err));
    }
  }

  async function loadAlertDetail(alert, index) {
    try {
      const alertId = getAlertId(alert, index, alertMeta.offset);
      setSelectedAlertId(alertId);
      setSelectedAlert(await api.getAlertDetail(alertId));
      setActivePage("monitor");
    } catch (err) {
      setError(String(err));
    }
  }

  async function applyFocusedTarget(target) {
    if (!target?.ip) return;
    if (!focusQuerySnapshotRef.current) {
      focusQuerySnapshotRef.current = {
        packetQuery: { ...packetQuery },
        alertQuery: { ...alertQuery },
      };
    }
    setFocusedTarget(target);
    setLiveFollow(false);
    const nextPacketQuery = {
      ...packetQuery,
      src: target.role === "src" ? target.ip : "",
      dst: target.role === "dst" ? target.ip : "",
      text: "",
      only_remote: true,
    };
    const nextAlertQuery = {
      ...alertQuery,
      src: target.role === "src" ? target.ip : "",
      dst: target.role === "dst" ? target.ip : "",
      text: "",
      only_remote: true,
    };
    setPacketQuery(nextPacketQuery);
    setAlertQuery(nextAlertQuery);
    setStatusMessage(`Locked on ${target.role === "dst" ? "destination" : "source"} ${target.ip}`);
    setActivePage("monitor");
    try {
      await Promise.all([loadPacketHistory(nextPacketQuery, 0), loadAlertHistory(nextAlertQuery, 0)]);
    } catch (err) {
      setError(String(err));
    }
  }

  async function clearFocusedTarget() {
    const snapshot = focusQuerySnapshotRef.current;
    focusQuerySnapshotRef.current = null;
    setFocusedTarget(null);
    setLiveFollow(true);
    setStatusMessage("Live follow restored");
    if (!snapshot) return;
    setPacketQuery(snapshot.packetQuery);
    setAlertQuery(snapshot.alertQuery);
    try {
      await Promise.all([loadPacketHistory(snapshot.packetQuery, 0), loadAlertHistory(snapshot.alertQuery, 0)]);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleTrackRow(item, preferredRole = "either") {
    const target = chooseFocusTarget(item, preferredRole);
    await applyFocusedTarget(target);
  }

  function resumeLiveFollow() {
    setLiveFollow(true);
    setStatusMessage("Live lists are following the newest traffic");
  }

  async function startSniffer() {
    setError("");
    try {
      const data = await api.startSniffer({ iface: settings.iface || "iface=default" });
      setDashboard((current) => ({ ...(current || {}), state: data }));
    } catch (err) {
      setError(String(err));
    }
  }

  async function stopSniffer() {
    setError("");
    try {
      const data = await api.stopSniffer();
      setDashboard((current) => ({ ...(current || {}), state: data }));
    } catch (err) {
      setError(String(err));
    }
  }

  async function saveSettings() {
    setError("");
    try {
      const data = await api.putSettings({
        iface: settings.iface || "iface=default",
        ids_ml_threshold: Number(settings.ids_ml_threshold),
        tr_timeout: Number(settings.tr_timeout),
        tr_mode: settings.tr_mode,
        auto_block: Boolean(settings.auto_block),
        persist_logs: Boolean(settings.persist_logs),
        whitelist_ips: settings.whitelist_ips,
      });
      setSettings((current) => ({ ...current, ...data, iface: data.iface || current.iface || "iface=default" }));
      setStatusMessage("Settings saved");
    } catch (err) {
      setError(String(err));
    }
  }

  async function applyPacketFilters() {
    setError("");
    try {
      await loadPacketHistory(packetQuery, 0);
    } catch (err) {
      setError(String(err));
    }
  }

  async function applyAlertFilters() {
    setError("");
    try {
      await loadAlertHistory(alertQuery, 0);
    } catch (err) {
      setError(String(err));
    }
  }

  async function runTraceroute() {
    setError("");
    try {
      const data = await api.runTraceroute({
        target: tracerouteTarget,
        mode: settings.tr_mode,
        timeout: Number(settings.tr_timeout),
      });
      setTracerouteResult(data);
    } catch (err) {
      setError(String(err));
    }
  }

  async function exportSession(format) {
    setError("");
    try {
      const data = await api.exportSession({ format });
      setExportInfo(data);
      await loadReports();
      setStatusMessage(`Export created: ${data.format}`);
    } catch (err) {
      setError(String(err));
    }
  }

  async function runOfflineAnalysis() {
    if (!offlineFile) {
      setError("Choose a PCAP file first");
      return;
    }
    setError("");
    try {
      const data = await api.analyzePcap(offlineFile);
      setOfflineResult(data);
      setStatusMessage("Offline PCAP analysis complete");
    } catch (err) {
      setError(String(err));
    }
  }

  async function resetSessionData() {
    setError("");
    try {
      const state = await api.resetSession();
      clearHistoryCaches();
      setDashboard((current) => ({
        ...(current || {}),
        state,
        top_sources: [],
        top_destinations: [],
        top_protocols: [],
        recent_packets: [],
        recent_alerts: [],
      }));
      setPackets([]);
      setAlerts([]);
      setPacketMeta((current) => ({ total: 0, source: current.source, offset: 0, limit: PAGE_SIZE }));
      setAlertMeta((current) => ({ total: 0, source: current.source, offset: 0, limit: PAGE_SIZE }));
      setSelectedPacket(null);
      setSelectedAlert(null);
      setSelectedPacketId("");
      setSelectedAlertId("");
      setFocusedTarget(null);
      setLiveFollow(true);
      focusQuerySnapshotRef.current = null;
      setTimeline(createTimeline());
      setStatusMessage("Live session data cleared");
    } catch (err) {
      setError(String(err));
    }
  }

  async function paginatePackets(direction) {
    const nextOffset = Math.max(0, packetMeta.offset + direction * PAGE_SIZE);
    if (nextOffset >= packetMeta.total && direction > 0) return;
    try {
      await loadPacketHistory(packetQuery, nextOffset);
    } catch (err) {
      setError(String(err));
    }
  }

  async function paginateAlerts(direction) {
    const nextOffset = Math.max(0, alertMeta.offset + direction * PAGE_SIZE);
    if (nextOffset >= alertMeta.total && direction > 0) return;
    try {
      await loadAlertHistory(alertQuery, nextOffset);
    } catch (err) {
      setError(String(err));
    }
  }

  function handlePacketQueryChange(key, value) {
    setPacketQuery((current) => ({ ...current, [key]: value }));
  }

  function handleAlertQueryChange(key, value) {
    setAlertQuery((current) => ({ ...current, [key]: value }));
  }

  function handleSettingsChange(key, value) {
    setSettings((current) => ({ ...current, [key]: value }));
  }

  useLiveEvents({
    localToken,
    onPacketsBatch: (messages) => {
      clearHistoryCaches();
      setTimeline((current) => appendBatchToTimeline(current, "packet", messages));
      setPackets((current) => (liveFollow && packetOffsetRef.current === 0 ? [...messages.map((message) => message.payload), ...current].slice(0, PAGE_SIZE) : current));
      setPacketMeta((current) => ({ ...current, total: Math.max(current.total + messages.length, messages.length) }));
      setDashboard((current) => {
        if (!current) return current;
        const nextState = { ...(current.state || {}) };
        nextState.packet_count = Math.min((nextState.packet_count || 0) + messages.length, 300);
        nextState.total_packets = (nextState.total_packets || 0) + messages.length;
        return { ...current, state: nextState };
      });
    },
    onAlertsBatch: (messages) => {
      clearHistoryCaches();
      setTimeline((current) => appendBatchToTimeline(current, "alert", messages));
      setAlerts((current) => (liveFollow && alertOffsetRef.current === 0 ? [...messages.map((message) => message.payload), ...current].slice(0, PAGE_SIZE) : current));
      setAlertMeta((current) => ({ ...current, total: Math.max(current.total + messages.length, messages.length) }));
      setDashboard((current) => {
        if (!current) return current;
        const nextState = { ...(current.state || {}) };
        nextState.total_alerts = (nextState.total_alerts || 0) + messages.length;
        return { ...current, state: nextState };
      });
    },
    onState: (message) => {
      clearHistoryCaches();
      if (message.type === "sniffer:reset") {
        mergeObservability(message.payload?.observability || {});
        setPackets([]);
        setAlerts([]);
        setSelectedPacket(null);
        setSelectedAlert(null);
        setSelectedPacketId("");
        setSelectedAlertId("");
        setFocusedTarget(null);
        setLiveFollow(true);
        setTimeline(createTimeline());
        setDashboard((current) => ({
          ...(current || {}),
          top_sources: [],
          top_destinations: [],
          top_protocols: [],
          recent_packets: [],
          recent_alerts: [],
          state: message.payload,
        }));
        return;
      }
      mergeObservability(message.payload?.observability || {});
      setDashboard((current) => ({ ...(current || {}), state: message.payload }));
    },
    onStatusChange: (state, message) => {
      setConnectionState(state);
      setStatusMessage(message);
    },
  });

  const sniffer = dashboard?.state || {};
  const topSources = dashboard?.top_sources || [];
  const topDestinations = dashboard?.top_destinations || [];
  const topProtocols = dashboard?.top_protocols || [];
  const topRemotes = dashboard?.top_remotes || [];
  const topConversations = dashboard?.top_conversations || [];

  const connectionLabel = useMemo(() => {
    if (connectionState === "live") return "Live";
    if (connectionState === "reconnecting") return "Reconnecting";
    if (connectionState === "degraded") return "Degraded";
    return "Connecting";
  }, [connectionState]);

  const focusedPacketCount = useMemo(
    () => packets.filter((packet) => matchesFocusedTarget(packet, focusedTarget)).length,
    [packets, focusedTarget]
  );
  const focusedAlerts = useMemo(
    () => alerts.filter((alert) => matchesFocusedTarget(alert, focusedTarget)),
    [alerts, focusedTarget]
  );

  return {
    api,
    localToken,
    setLocalToken,
    activePage,
    setActivePage,
    packets,
    alerts,
    packetQuery,
    alertQuery,
    packetMeta,
    alertMeta,
    selectedPacket,
    selectedAlert,
    selectedPacketId,
    selectedAlertId,
    settings,
    interfaces,
    recommendedInterface,
    recommendedInterfaceLabel,
    tracerouteTarget,
    setTracerouteTarget,
    tracerouteResult,
    offlineResult,
    setOfflineFile,
    exportInfo,
    reports,
    connectionState,
    connectionLabel,
    statusMessage,
    observability,
    error,
    localTokenRequired,
    liveFollow,
    setLiveFollow,
    focusedTarget,
    timeline,
    sniffer,
    topSources,
    topDestinations,
    topProtocols,
    topRemotes,
    topConversations,
    focusedPacketCount,
    focusedAlerts,
    startSniffer,
    stopSniffer,
    resetSessionData,
    saveSettings,
    runTraceroute,
    exportSession,
    runOfflineAnalysis,
    loadPacketDetail,
    loadAlertDetail,
    applyPacketFilters,
    applyAlertFilters,
    paginatePackets,
    paginateAlerts,
    handlePacketQueryChange,
    handleAlertQueryChange,
    handleSettingsChange,
    handleTrackRow,
    clearFocusedTarget,
    resumeLiveFollow,
  };
}
