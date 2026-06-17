function toNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : 0;
}

function worstLevel(...levels) {
  if (levels.includes("degraded")) return "degraded";
  if (levels.includes("warning")) return "warning";
  return "healthy";
}

export function levelLabel(level) {
  if (level === "degraded") return "Degraded";
  if (level === "warning") return "Warning";
  return "Healthy";
}

export function levelClass(level) {
  return `ops-${level || "healthy"}`;
}

export function formatMs(value) {
  return `${toNumber(value).toFixed(1)} ms`;
}

function snapshotAgeSeconds(value, now = Date.now()) {
  if (!value) return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return null;
  return Math.max(0, Math.round((now - parsed) / 1000));
}

function normalizeLevel(level) {
  if (level === "critical") return "degraded";
  if (level === "degraded" || level === "warning" || level === "healthy") return level;
  return "healthy";
}

export function buildOpsSnapshot(observability, operationalMetrics = null) {
  const eventBus = observability?.event_bus || {};
  const persistence = observability?.persistence || {};
  const history = observability?.history || {};
  const autoBlock = observability?.auto_block || {};
  const capture = operationalMetrics?.capture || {};
  const flows = operationalMetrics?.flows || {};
  const pressureReasons = Array.isArray(operationalMetrics?.pressure_reasons)
    ? operationalMetrics.pressure_reasons
    : [];
  const ageSeconds = snapshotAgeSeconds(operationalMetrics?.generated_at);
  const packetsList = history.packets_list || {};
  const alertsList = history.alerts_list || {};
  const packetDetail = history.packet_detail || {};
  const alertDetail = history.alert_detail || {};

  const queueSize = toNumber(persistence.queue_size);
  const droppedWrites = toNumber(persistence.dropped_writes);
  const avgFlushMs = toNumber(persistence.avg_flush_ms || persistence.last_flush_ms);
  const wsDropped = toNumber(eventBus.dropped_messages);
  const queryLatencyMs = Math.max(toNumber(packetsList.last_ms), toNumber(alertsList.last_ms));
  const queryErrorCount = toNumber(packetsList.errors) + toNumber(alertsList.errors) + toNumber(packetDetail.errors) + toNumber(alertDetail.errors);
  const persistenceState = persistence.shutdown_flush_timeout
    ? "Shutdown timeout"
    : queueSize > 0 && !persistence.drain_completed
      ? "Draining"
      : toNumber(persistence.flush_errors) > 0
        ? "Errors"
        : "Healthy";

  const persistenceLevel = droppedWrites > 0 || toNumber(persistence.flush_errors) > 0 || toNumber(persistence.shutdown_flush_timeout) > 0
    ? "degraded"
    : queueSize >= 250 || avgFlushMs >= 250 || toNumber(persistence.flush_retries) > 0
      ? "warning"
      : "healthy";

  const streamLevel = wsDropped > 0
    ? "degraded"
    : toNumber(eventBus.subscribers) === 0 && toNumber(eventBus.published_messages) > 0
      ? "warning"
      : "healthy";

  const queryLevel = queryErrorCount > 0 || queryLatencyMs >= 450
    ? "degraded"
    : queryLatencyMs >= 180
      ? "warning"
      : "healthy";

  const autoBlockLevel = toNumber(autoBlock.failed_total) > 0
    ? "warning"
    : "healthy";

  const backendLevel = normalizeLevel(operationalMetrics?.health);
  const freshnessLevel = ageSeconds == null || ageSeconds <= 120 ? "healthy" : ageSeconds <= 300 ? "warning" : "degraded";
  const overall = worstLevel(backendLevel, freshnessLevel, persistenceLevel, streamLevel, queryLevel, autoBlockLevel);

  const summaryCards = [
    {
      label: "Runtime Health",
      value: levelLabel(backendLevel),
      hint: pressureReasons.length ? `${pressureReasons.length} pressure signal${pressureReasons.length === 1 ? "" : "s"}` : "No pressure signals",
      level: backendLevel,
    },
    {
      label: "Snapshot Age",
      value: ageSeconds == null ? "Unknown" : `${ageSeconds}s`,
      hint: ageSeconds == null ? "Refresh to verify freshness" : ageSeconds > 120 ? "Snapshot may be stale" : "Fresh snapshot",
      level: freshnessLevel,
    },
    {
      label: "Capture",
      value: capture.running ? "Running" : "Stopped",
      hint: capture.interface || "No interface selected",
      level: capture.running ? "healthy" : "warning",
    },
    {
      label: "Flows",
      value: String(toNumber(flows.total)),
      hint: `${toNumber(flows.active)} active | ${toNumber(flows.external)} external`,
      level: toNumber(flows.risk_distribution?.critical) > 0 || toNumber(flows.risk_distribution?.high) > 0 ? "warning" : "healthy",
    },
    {
      label: "Queue Size",
      value: String(queueSize),
      hint: `High-water ${toNumber(persistence.queue_high_water_mark)}`,
      level: persistenceLevel,
    },
    {
      label: "Dropped Writes",
      value: String(droppedWrites),
      hint: persistence.overload_policy ? `Policy ${persistence.overload_policy}` : "No write drops",
      level: droppedWrites > 0 ? "degraded" : "healthy",
    },
    {
      label: "Avg Flush",
      value: formatMs(avgFlushMs),
      hint: `Last ${formatMs(persistence.last_flush_ms)}`,
      level: avgFlushMs >= 250 ? "warning" : "healthy",
    },
    {
      label: "Query Latency",
      value: formatMs(queryLatencyMs),
      hint: `Errors ${queryErrorCount}`,
      level: queryLevel,
    },
    {
      label: "WS Drops",
      value: String(wsDropped),
      hint: `Published ${toNumber(eventBus.published_messages)}`,
      level: streamLevel,
    },
    {
      label: "Persistence",
      value: persistenceState,
      hint: `Drain ${toNumber(persistence.drain_completed) ? "complete" : "active"}`,
      level: persistenceLevel,
    },
  ];

  return {
    overall,
    generatedAt: operationalMetrics?.generated_at || "",
    ageSeconds,
    capture,
    flows,
    pressureReasons,
    eventBus,
    persistence,
    history,
    autoBlock,
    packetsList,
    alertsList,
    packetDetail,
    alertDetail,
    queryLatencyMs,
    queryErrorCount,
    persistenceState,
    summaryCards,
  };
}
