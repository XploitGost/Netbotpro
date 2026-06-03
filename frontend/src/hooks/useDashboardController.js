import { useEffect, useMemo, useRef, useState } from "react";
import { useApiClient } from "./useApiClient";
import { useLocalAuth } from "./useLocalAuth";
import { useLiveEvents } from "./useLiveEvents";
import { getPeerInfo, isPrivateIp } from "../lib/networkView";

export const PAGE_SIZE = 25;
const VALID_PAGES = new Set(["monitor", "inspect", "settings", "traceroute", "exports", "reports", "offline"]);
const TIMELINE_BUCKETS = 30;
const TIMELINE_BUCKET_MS = 2_000;
const HISTORY_CACHE_TTL_MS = 5_000;
const DETAIL_CACHE_TTL_MS = 12_000;

const defaultSettings = {
  iface: "iface=default",
  ids_ml_threshold: 0.25,
  tr_timeout: 1.5,
  tr_mode: "UDP",
  auto_block: false,
  persist_logs: false,
  whitelist_ips: "",
  retention_minutes: 0,
  payload_capture_enabled: false,
  alert_only_mode: false,
  safe_use_policy_accepted: false,
  remote_dashboard_allowlist: "",
  capture_mode: "metadata",
  allow_full_capture: false,
  forensic_duration_minutes: 0,
  forensic_confirmed: false,
};

function initialActivePage() {
  if (typeof window === "undefined") {
    return "monitor";
  }
  try {
    const page = new URLSearchParams(window.location.search).get("page") || "";
    return VALID_PAGES.has(page) ? page : "monitor";
  } catch {
    return "monitor";
  }
}

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

function blockingCaptureDetail(preflight) {
  if (!preflight || !Array.isArray(preflight.checks)) return "";
  const blocking = preflight.checks.find((check) => !check?.ok && String(check?.severity || "error") === "error");
  return String(blocking?.detail || "").trim();
}

function normalizeErrorMessage(error, fallback = "Request failed") {
  const text = String(error ?? "").trim();
  if (!text) return fallback;
  return text.replace(/^Error:\s*/i, "").trim() || fallback;
}

export function useDashboardController() {
  const { localToken, setLocalToken, managedLocalToken } = useLocalAuth();
  const api = useApiClient(localToken);
  const [activePage, setActivePage] = useState(initialActivePage);
  const [dashboard, setDashboard] = useState(null);
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [packetQuery, setPacketQuery] = useState({ src: "", dst: "", proto: "", process: "", pid: "", text: "", only_alerts: false, only_remote: true });
  const [alertQuery, setAlertQuery] = useState({ src: "", dst: "", attack: "", proto: "", process: "", pid: "", text: "", min_score: "", only_remote: true });
  const [packetMeta, setPacketMeta] = useState({ total: 0, source: "memory", offset: 0, limit: PAGE_SIZE });
  const [alertMeta, setAlertMeta] = useState({ total: 0, source: "memory", offset: 0, limit: PAGE_SIZE });
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [selectedPacketContext, setSelectedPacketContext] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedAlertContext, setSelectedAlertContext] = useState(null);
  const [selectedPacketId, setSelectedPacketId] = useState("");
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [inspectionPinned, setInspectionPinned] = useState({ kind: "", id: "" });
  const [settings, setSettings] = useState(defaultSettings);
  const [interfaces, setInterfaces] = useState([]);
  const [recommendedInterface, setRecommendedInterface] = useState("");
  const [recommendedInterfaceLabel, setRecommendedInterfaceLabel] = useState("");
  const [capturePreflight, setCapturePreflight] = useState(null);
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
  const [loadingState, setLoadingState] = useState({
    bootstrap: true,
    packets: false,
    alerts: false,
    packetDetail: false,
    alertDetail: false,
    exports: false,
    reports: false,
    traceroute: false,
    offlineAnalysis: false,
    settings: false,
    snifferAction: false,
  });
  const [localTokenRequired, setLocalTokenRequired] = useState(false);
  const [liveFollow, setLiveFollow] = useState(true);
  const [focusedTarget, setFocusedTarget] = useState(null);
  const [timeline, setTimeline] = useState(() => createTimeline());
  const packetOffsetRef = useRef(0);
  const alertOffsetRef = useRef(0);
  const focusQuerySnapshotRef = useRef(null);
  const packetHistoryCacheRef = useRef(new Map());
  const alertHistoryCacheRef = useRef(new Map());
  const packetDetailCacheRef = useRef(new Map());
  const alertDetailCacheRef = useRef(new Map());
  const packetHistoryRequestRef = useRef(0);
  const alertHistoryRequestRef = useRef(0);
  const packetDetailRequestRef = useRef(0);
  const alertDetailRequestRef = useRef(0);

  function clearHistoryCaches() {
    packetHistoryCacheRef.current.clear();
    alertHistoryCacheRef.current.clear();
    packetDetailCacheRef.current.clear();
    alertDetailCacheRef.current.clear();
  }

  function setLoading(key, value) {
    setLoadingState((current) => (current[key] === value ? current : { ...current, [key]: value }));
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

  function readDetailCache(cacheRef, key) {
    const entry = cacheRef.current.get(key);
    if (!entry || entry.expiresAt <= Date.now()) {
      cacheRef.current.delete(key);
      return null;
    }
    return entry.data;
  }

  function writeDetailCache(cacheRef, key, data) {
    cacheRef.current.set(key, { data, expiresAt: Date.now() + DETAIL_CACHE_TTL_MS });
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
      setLoading("bootstrap", true);
      setLoading("reports", true);
      try {
        const statusData = await api.getStatus();
        if (!active) return;
        setLocalTokenRequired(Boolean(statusData.local_token_required));
        mergeObservability(statusData.observability || {});

        if (statusData.local_token_required && !localToken) {
          setDashboard((current) => ({ ...(current || {}), state: statusData.sniffer || {} }));
          setPackets([]);
          setAlerts([]);
          setTimeline(createTimeline());
          setPacketMeta({ total: 0, source: "memory", offset: 0, limit: PAGE_SIZE });
          setAlertMeta({ total: 0, source: "memory", offset: 0, limit: PAGE_SIZE });
          setStatusMessage("Enter the local token to unlock dashboard data");
          setLoading("bootstrap", false);
          setLoading("reports", false);
          return;
        }

        const [dashboardData, settingsData, interfacesData] = await Promise.all([
          api.getDashboard(),
          api.getSettings(),
          api.getInterfaces().catch(() => ({ recommended: "", items: [], preflight: null })),
        ]);
        if (!active) return;
        clearHistoryCaches();
        setDashboard(dashboardData);
        mergeObservability(dashboardData.observability || dashboardData.state?.observability || {});
        setLocalTokenRequired(Boolean(statusData.local_token_required || dashboardData.local_token_required));
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
        setCapturePreflight(interfacesData.preflight || null);
        const reportsData = await api.getReports();
        if (!active) return;
        setReports(reportsData || []);
        setStatusMessage("Dashboard synced");
      } catch (err) {
        if (!active) return;
        setError(normalizeErrorMessage(err, "Unable to load initial data"));
        setStatusMessage("Unable to load initial data");
      } finally {
        if (!active) return;
        setLoading("bootstrap", false);
        setLoading("reports", false);
      }
    }

    loadInitial();
    return () => {
      active = false;
    };
  }, [localToken]);

  async function loadPacketHistory(customQuery = packetQuery, offset = packetMeta.offset) {
    const requestId = packetHistoryRequestRef.current + 1;
    packetHistoryRequestRef.current = requestId;
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
    try {
      if (!cached) {
        setLoading("packets", true);
      }
      const data = cached || await api.getPackets(params);
      if (packetHistoryRequestRef.current !== requestId) {
        return;
      }
      if (!cached) writeCache(packetHistoryCacheRef, cacheKey, data);
      mergeObservability(data.observability || {});
      setPackets(data.items || []);
      setPacketMeta({ total: data.total || 0, source: data.source || "memory", offset: data.offset || 0, limit: data.limit || PAGE_SIZE });
      if (!(inspectionPinned.kind === "packet" && inspectionPinned.id)) {
        setSelectedPacket(null);
        setSelectedPacketContext(null);
        setSelectedPacketId("");
      }
      if (data.query_ms != null) {
        setStatusMessage(`Packet history loaded in ${data.query_ms} ms`);
      }
    } finally {
      if (packetHistoryRequestRef.current === requestId) {
        setLoading("packets", false);
      }
    }
  }

  async function loadAlertHistory(customQuery = alertQuery, offset = alertMeta.offset) {
    const requestId = alertHistoryRequestRef.current + 1;
    alertHistoryRequestRef.current = requestId;
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
    try {
      if (!cached) {
        setLoading("alerts", true);
      }
      const data = cached || await api.getAlerts(params);
      if (alertHistoryRequestRef.current !== requestId) {
        return;
      }
      if (!cached) writeCache(alertHistoryCacheRef, cacheKey, data);
      mergeObservability(data.observability || {});
      setAlerts(data.items || []);
      setAlertMeta({ total: data.total || 0, source: data.source || "memory", offset: data.offset || 0, limit: data.limit || PAGE_SIZE });
      if (!(inspectionPinned.kind === "alert" && inspectionPinned.id)) {
        setSelectedAlert(null);
        setSelectedAlertContext(null);
        setSelectedAlertId("");
      }
      if (data.query_ms != null) {
        setStatusMessage(`Alert history loaded in ${data.query_ms} ms`);
      }
    } finally {
      if (alertHistoryRequestRef.current === requestId) {
        setLoading("alerts", false);
      }
    }
  }

  async function loadReports() {
    setLoading("reports", true);
    try {
      const data = await api.getReports();
      setReports(data || []);
    } finally {
      setLoading("reports", false);
    }
  }

  async function loadPacketDetail(packet, index) {
    const requestId = packetDetailRequestRef.current + 1;
    packetDetailRequestRef.current = requestId;
    try {
      setActivePage("inspect");
      const packetId = getPacketId(packet, index, packetMeta.offset);
      setSelectedPacketId(packetId);
      setSelectedPacketContext(null);
      const cached = readDetailCache(packetDetailCacheRef, packetId);
      if (!cached) {
        setLoading("packetDetail", true);
      }
      const [detail, context] = cached || await Promise.all([api.getPacketDetail(packetId), api.getPacketContext(packetId).catch(() => null)]);
      if (packetDetailRequestRef.current !== requestId) {
        return;
      }
      if (!cached) {
        writeDetailCache(packetDetailCacheRef, packetId, [detail, context]);
      }
      setSelectedPacket(detail);
      setSelectedPacketContext(context);
      setInspectionPinned((current) => (current.kind === "packet" ? { kind: "packet", id: packetId } : current));
    } catch (err) {
      if (packetDetailRequestRef.current === requestId) {
        setError(normalizeErrorMessage(err, "Unable to load packet detail"));
      }
    } finally {
      if (packetDetailRequestRef.current === requestId) {
        setLoading("packetDetail", false);
      }
    }
  }

  async function loadAlertDetail(alert, index) {
    const requestId = alertDetailRequestRef.current + 1;
    alertDetailRequestRef.current = requestId;
    try {
      setActivePage("inspect");
      const alertId = getAlertId(alert, index, alertMeta.offset);
      setSelectedAlertId(alertId);
      setSelectedAlertContext(null);
      const cached = readDetailCache(alertDetailCacheRef, alertId);
      if (!cached) {
        setLoading("alertDetail", true);
      }
      const [detail, context] = cached || await Promise.all([api.getAlertDetail(alertId), api.getAlertContext(alertId).catch(() => null)]);
      if (alertDetailRequestRef.current !== requestId) {
        return;
      }
      if (!cached) {
        writeDetailCache(alertDetailCacheRef, alertId, [detail, context]);
      }
      setSelectedAlert(detail);
      setSelectedAlertContext(context);
      setInspectionPinned((current) => (current.kind === "alert" ? { kind: "alert", id: alertId } : current));
    } catch (err) {
      if (alertDetailRequestRef.current === requestId) {
        setError(normalizeErrorMessage(err, "Unable to load alert detail"));
      }
    } finally {
      if (alertDetailRequestRef.current === requestId) {
        setLoading("alertDetail", false);
      }
    }
  }

  async function openPacketDetailById(packetId) {
    const targetId = String(packetId || "").trim();
    if (!targetId) return;
    const existingIndex = packets.findIndex((packet, index) => {
      const rowId = getPacketId(packet, index, packetMeta.offset);
      return rowId === targetId || String(packet?.capture_id || "").trim() === targetId;
    });
    if (existingIndex >= 0) {
      await loadPacketDetail(packets[existingIndex], existingIndex);
      return;
    }
    const requestId = packetDetailRequestRef.current + 1;
    packetDetailRequestRef.current = requestId;
    try {
      setActivePage("inspect");
      setSelectedPacketId(targetId);
      setSelectedPacketContext(null);
      const cached = readDetailCache(packetDetailCacheRef, targetId);
      if (!cached) {
        setLoading("packetDetail", true);
      }
      const [detail, context] = cached || await Promise.all([api.getPacketDetail(targetId), api.getPacketContext(targetId).catch(() => null)]);
      if (packetDetailRequestRef.current !== requestId) {
        return;
      }
      if (!cached) {
        writeDetailCache(packetDetailCacheRef, targetId, [detail, context]);
      }
      setSelectedPacket(detail);
      setSelectedPacketContext(context);
      setInspectionPinned((current) => (current.kind === "packet" ? { kind: "packet", id: targetId } : current));
    } catch (err) {
      if (packetDetailRequestRef.current === requestId) {
        setError(normalizeErrorMessage(err, "Unable to open packet detail"));
      }
    } finally {
      if (packetDetailRequestRef.current === requestId) {
        setLoading("packetDetail", false);
      }
    }
  }

  async function openAlertDetailById(alertId) {
    const targetId = String(alertId || "").trim();
    if (!targetId) return;
    const existingIndex = alerts.findIndex((alert, index) => getAlertId(alert, index, alertMeta.offset) === targetId);
    if (existingIndex >= 0) {
      await loadAlertDetail(alerts[existingIndex], existingIndex);
      return;
    }
    const requestId = alertDetailRequestRef.current + 1;
    alertDetailRequestRef.current = requestId;
    try {
      setActivePage("inspect");
      setSelectedAlertId(targetId);
      setSelectedAlertContext(null);
      const cached = readDetailCache(alertDetailCacheRef, targetId);
      if (!cached) {
        setLoading("alertDetail", true);
      }
      const [detail, context] = cached || await Promise.all([api.getAlertDetail(targetId), api.getAlertContext(targetId).catch(() => null)]);
      if (alertDetailRequestRef.current !== requestId) {
        return;
      }
      if (!cached) {
        writeDetailCache(alertDetailCacheRef, targetId, [detail, context]);
      }
      setSelectedAlert(detail);
      setSelectedAlertContext(context);
      setInspectionPinned((current) => (current.kind === "alert" ? { kind: "alert", id: targetId } : current));
    } catch (err) {
      if (alertDetailRequestRef.current === requestId) {
        setError(normalizeErrorMessage(err, "Unable to open alert detail"));
      }
    } finally {
      if (alertDetailRequestRef.current === requestId) {
        setLoading("alertDetail", false);
      }
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
      process: "",
      pid: "",
      text: "",
      only_remote: true,
    };
    const nextAlertQuery = {
      ...alertQuery,
      src: target.role === "src" ? target.ip : "",
      dst: target.role === "dst" ? target.ip : "",
      process: "",
      pid: "",
      text: "",
      only_remote: true,
    };
    setPacketQuery(nextPacketQuery);
    setAlertQuery(nextAlertQuery);
    setStatusMessage(`Locked on ${target.role === "dst" ? "destination" : "source"} ${target.ip}`);
    setActivePage("inspect");
    try {
      await Promise.all([loadPacketHistory(nextPacketQuery, 0), loadAlertHistory(nextAlertQuery, 0)]);
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to lock the current focus target"));
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
      setError(normalizeErrorMessage(err, "Unable to restore the live focus view"));
    }
  }

  async function handleTrackRow(item, preferredRole = "either") {
    const target = chooseFocusTarget(item, preferredRole);
    await applyFocusedTarget(target);
  }

  async function filterByProcess(item) {
    const processName = String(item?.process_name || "").trim();
    const pid = String(item?.pid || "").trim();
    const processLabel = processName || (pid ? `PID ${pid}` : "selected process");
    const nextPacketQuery = {
      ...packetQuery,
      src: "",
      dst: "",
      process: processName,
      pid,
      text: "",
    };
    const nextAlertQuery = {
      ...alertQuery,
      src: "",
      dst: "",
      process: processName,
      pid,
      text: "",
    };
    focusQuerySnapshotRef.current = null;
    setFocusedTarget(null);
    setLiveFollow(false);
    setActivePage("monitor");
    setPacketQuery(nextPacketQuery);
    setAlertQuery(nextAlertQuery);
    setStatusMessage(`Filtering traffic for ${processLabel}`);
    try {
      await Promise.all([loadPacketHistory(nextPacketQuery, 0), loadAlertHistory(nextAlertQuery, 0)]);
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to filter traffic by process"));
    }
  }

  function resumeLiveFollow() {
    setLiveFollow(true);
    setStatusMessage("Live lists are following the newest traffic");
  }

  function freezeLiveFollow() {
    setLiveFollow(false);
    setStatusMessage("Live lists are frozen for investigation");
  }

  function toggleInspectionPin(kind) {
    if (kind === "packet" && selectedPacketId) {
      setInspectionPinned((current) => (current.kind === "packet" && current.id === selectedPacketId ? { kind: "", id: "" } : { kind: "packet", id: selectedPacketId }));
      return;
    }
    if (kind === "alert" && selectedAlertId) {
      setInspectionPinned((current) => (current.kind === "alert" && current.id === selectedAlertId ? { kind: "", id: "" } : { kind: "alert", id: selectedAlertId }));
    }
  }

  async function navigatePacketDetail(step) {
    const currentIndex = packets.findIndex((packet, index) => getPacketId(packet, index, packetMeta.offset) === selectedPacketId);
    if (currentIndex < 0) return;
    const nextIndex = currentIndex + step;
    if (nextIndex < 0 || nextIndex >= packets.length) return;
    await loadPacketDetail(packets[nextIndex], nextIndex);
  }

  async function navigateAlertDetail(step) {
    const currentIndex = alerts.findIndex((alert, index) => getAlertId(alert, index, alertMeta.offset) === selectedAlertId);
    if (currentIndex < 0) return;
    const nextIndex = currentIndex + step;
    if (nextIndex < 0 || nextIndex >= alerts.length) return;
    await loadAlertDetail(alerts[nextIndex], nextIndex);
  }

  async function startSniffer() {
    setError("");
    setLoading("snifferAction", true);
    const unavailableDetail = blockingCaptureDetail(capturePreflight);
    if (capturePreflight && !capturePreflight.ready && unavailableDetail) {
      setError(unavailableDetail);
      setStatusMessage(unavailableDetail);
      setLoading("snifferAction", false);
      return;
    }
    try {
      const data = await api.startSniffer({
        iface: settings.iface || "iface=default",
        capture_mode: settings.capture_mode || "metadata",
        forensic_duration_minutes: Number(settings.forensic_duration_minutes || 0),
        forensic_confirmed: Boolean(settings.forensic_confirmed),
      });
      setDashboard((current) => ({ ...(current || {}), state: data }));
      setStatusMessage("Live capture started");
    } catch (err) {
      const message = normalizeErrorMessage(err, "Unable to start live capture");
      setError(message);
      setStatusMessage(message);
    } finally {
      setLoading("snifferAction", false);
    }
  }

  async function stopSniffer() {
    setError("");
    setLoading("snifferAction", true);
    try {
      const data = await api.stopSniffer();
      setDashboard((current) => ({ ...(current || {}), state: data }));
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to stop live capture"));
    } finally {
      setLoading("snifferAction", false);
    }
  }

  async function saveSettings() {
    setError("");
    setLoading("settings", true);
    try {
      const data = await api.putSettings({
        iface: settings.iface || "iface=default",
        ids_ml_threshold: Number(settings.ids_ml_threshold),
        tr_timeout: Number(settings.tr_timeout),
        tr_mode: settings.tr_mode,
        auto_block: Boolean(settings.auto_block),
        persist_logs: Boolean(settings.persist_logs),
        whitelist_ips: settings.whitelist_ips,
        retention_minutes: Number(settings.retention_minutes || 0),
        payload_capture_enabled: Boolean(settings.payload_capture_enabled),
        alert_only_mode: Boolean(settings.alert_only_mode),
        safe_use_policy_accepted: Boolean(settings.safe_use_policy_accepted),
        remote_dashboard_allowlist: settings.remote_dashboard_allowlist,
        capture_mode: settings.capture_mode || "metadata",
        allow_full_capture: Boolean(settings.allow_full_capture),
        forensic_duration_minutes: Number(settings.forensic_duration_minutes || 0),
        forensic_confirmed: Boolean(settings.forensic_confirmed),
      });
      setSettings((current) => ({ ...current, ...data, iface: data.iface || current.iface || "iface=default" }));
      setStatusMessage("Settings saved");
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to save settings"));
    } finally {
      setLoading("settings", false);
    }
  }

  async function applyPacketFilters() {
    setError("");
    try {
      await loadPacketHistory(packetQuery, 0);
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to load packet history"));
    }
  }

  async function applyAlertFilters() {
    setError("");
    try {
      await loadAlertHistory(alertQuery, 0);
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to load alert history"));
    }
  }

  async function runTraceroute() {
    setError("");
    setLoading("traceroute", true);
    try {
      const data = await api.runTraceroute({
        target: tracerouteTarget,
        mode: settings.tr_mode,
        timeout: Number(settings.tr_timeout),
      });
      setTracerouteResult(data);
    } catch (err) {
      setError(normalizeErrorMessage(err, "Traceroute failed"));
    } finally {
      setLoading("traceroute", false);
    }
  }

  async function exportSession(format) {
    setError("");
    setLoading("exports", true);
    try {
      const data = await api.exportSession({ format });
      setExportInfo(data);
      await loadReports();
      setStatusMessage(`Export created: ${data.format}`);
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to create session export"));
    } finally {
      setLoading("exports", false);
    }
  }

  async function exportInvestigation(payload) {
    setError("");
    setLoading("exports", true);
    try {
      const data = await api.exportInvestigation(payload);
      setExportInfo(data);
      await loadReports();
      setStatusMessage(`Investigation export created: ${data.path}`);
      return data;
    } catch (err) {
      const message = normalizeErrorMessage(err, "Unable to create investigation export");
      setError(message);
      setStatusMessage(message);
      throw err;
    } finally {
      setLoading("exports", false);
    }
  }

  async function downloadExport(path) {
    if (!path || typeof window === "undefined") {
      return;
    }
    setError("");
    setLoading("exports", true);
    try {
      const { blob, filename } = await api.downloadExport(path);
      const objectUrl = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = filename;
      anchor.rel = "noopener";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 0);
      setStatusMessage(`Downloaded ${filename}`);
    } catch (err) {
      const message = normalizeErrorMessage(err, "Export download failed");
      setError(message);
      setStatusMessage(message);
    } finally {
      setLoading("exports", false);
    }
  }

  async function runOfflineAnalysis() {
    if (!offlineFile) {
      setError("Choose a PCAP file first");
      return;
    }
    setError("");
    setLoading("offlineAnalysis", true);
    try {
      const data = await api.analyzePcap(offlineFile);
      setOfflineResult(data);
      setStatusMessage("Offline PCAP analysis complete");
    } catch (err) {
      setError(normalizeErrorMessage(err, "Offline PCAP analysis failed"));
    } finally {
      setLoading("offlineAnalysis", false);
    }
  }

  async function resetSessionData() {
    setError("");
    setLoading("snifferAction", true);
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
      setSelectedPacketContext(null);
      setSelectedAlert(null);
      setSelectedAlertContext(null);
      setSelectedPacketId("");
      setSelectedAlertId("");
      setInspectionPinned({ kind: "", id: "" });
      setFocusedTarget(null);
      setLiveFollow(true);
      focusQuerySnapshotRef.current = null;
      setTimeline(createTimeline());
      setStatusMessage("Live session data cleared");
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to reset live session data"));
    } finally {
      setLoading("snifferAction", false);
    }
  }

  async function paginatePackets(direction) {
    const nextOffset = Math.max(0, packetMeta.offset + direction * PAGE_SIZE);
    if (nextOffset >= packetMeta.total && direction > 0) return;
    try {
      await loadPacketHistory(packetQuery, nextOffset);
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to paginate packet history"));
    }
  }

  async function paginateAlerts(direction) {
    const nextOffset = Math.max(0, alertMeta.offset + direction * PAGE_SIZE);
    if (nextOffset >= alertMeta.total && direction > 0) return;
    try {
      await loadAlertHistory(alertQuery, nextOffset);
    } catch (err) {
      setError(normalizeErrorMessage(err, "Unable to paginate alert history"));
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
        setSelectedPacketContext(null);
        setSelectedAlert(null);
        setSelectedAlertContext(null);
        setSelectedPacketId("");
        setSelectedAlertId("");
        setInspectionPinned({ kind: "", id: "" });
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
  const topProcesses = dashboard?.top_processes || [];
  const topRemotes = dashboard?.top_remotes || [];
  const topConversations = dashboard?.top_conversations || [];

  const connectionLabel = useMemo(() => {
    if (connectionState === "live") return "Live";
    if (connectionState === "reconnecting") return "Reconnecting";
    if (connectionState === "degraded") return "Degraded";
    return "Connecting";
  }, [connectionState]);
  const captureUnavailableDetail = useMemo(() => blockingCaptureDetail(capturePreflight), [capturePreflight]);
  const canStartSniffer = useMemo(() => !capturePreflight || Boolean(capturePreflight.ready), [capturePreflight]);

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
    selectedPacketContext,
    selectedAlert,
    selectedAlertContext,
    selectedPacketId,
    selectedAlertId,
    inspectionPinned,
    settings,
    interfaces,
    recommendedInterface,
    recommendedInterfaceLabel,
    capturePreflight,
    captureUnavailableDetail,
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
    loadingState,
    localTokenRequired,
    managedLocalToken,
    canStartSniffer,
    liveFollow,
    setLiveFollow,
    focusedTarget,
    timeline,
    sniffer,
    topSources,
    topDestinations,
    topProtocols,
    topProcesses,
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
    exportInvestigation,
    downloadExport,
    runOfflineAnalysis,
    loadPacketDetail,
    loadAlertDetail,
    openPacketDetailById,
    openAlertDetailById,
    applyPacketFilters,
    applyAlertFilters,
    paginatePackets,
    paginateAlerts,
    handlePacketQueryChange,
    handleAlertQueryChange,
    handleSettingsChange,
    handleTrackRow,
    filterByProcess,
    toggleInspectionPin,
    navigatePacketDetail,
    navigateAlertDetail,
    freezeLiveFollow,
    clearFocusedTarget,
    resumeLiveFollow,
  };
}
