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

function safeQueueDropReason(value) {
  const allowed = new Set([
    "queue_full_drop_newest",
    "queue_full_drop_oldest",
    "queue_full_after_drop_oldest",
  ]);
  return allowed.has(value) ? value : "";
}

function safeWebSocketDropReason(value) {
  const allowed = new Set([
    "client_queue_full_coalesce",
    "client_queue_full_drop_oldest",
    "client_queue_full_drop_newest",
    "client_queue_full_after_policy",
  ]);
  return allowed.has(value) ? value : "";
}

export function buildOpsSnapshot(observability, operationalMetrics = null) {
  const eventBus = observability?.event_bus || {};
  const eventAggregator = operationalMetrics?.event_aggregator || observability?.event_aggregator || {};
  const websocket = operationalMetrics?.websocket || observability?.websocket || {};
  const packetQueue = operationalMetrics?.packet_queue || observability?.packet_queue || {};
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
  const packetQueueDepth = toNumber(packetQueue.current_depth ?? packetQueue.queue_size);
  const packetQueueMaxSize = toNumber(packetQueue.max_size);
  const packetQueueUtilization = toNumber(packetQueue.utilization_percent);
  const packetQueueDropped = toNumber(packetQueue.dropped_total ?? packetQueue.dropped_packets);
  const packetQueueHighWater = toNumber(packetQueue.high_water_mark ?? packetQueue.queue_high_water_mark);
  const packetQueueWorkerAlive = packetQueue.worker_alive !== false;
  const droppedWrites = toNumber(persistence.dropped_writes);
  const avgFlushMs = toNumber(persistence.avg_flush_ms || persistence.last_flush_ms);
  const wsDropped = toNumber(eventBus.dropped_messages);
  const wsClients = toNumber(websocket.clients ?? websocket.websocket_clients);
  const wsSlowClients = toNumber(websocket.slow_clients ?? websocket.websocket_slow_clients);
  const wsEventDrops = toNumber(websocket.dropped_for_slow_client_total) + toNumber(eventAggregator.events_dropped_total);
  const wsEventCoalesced = toNumber(websocket.coalesced_for_slow_client_total) + toNumber(eventAggregator.events_coalesced_total);
  const wsSendLatency = toNumber(websocket.send_latency_ms_p95 ?? websocket.websocket_send_latency_ms);
  const wsBatchesSent = toNumber(eventAggregator.batches_sent_total);
  const wsEventsReceived = toNumber(eventAggregator.events_received_total);
  const wsEventsSent = toNumber(eventAggregator.events_sent_total);
  const wsSubscribers = toNumber(eventBus.subscribers);
  const wsPublished = toNumber(eventBus.published_messages);
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
    : wsSlowClients > 0 || wsEventDrops > 0 || wsEventCoalesced > 0 || wsSendLatency >= 250
      ? "warning"
    : wsSubscribers === 0 && wsPublished > 0
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
  const packetQueueLevel = packetQueue.health
    ? normalizeLevel(packetQueue.health)
    : !packetQueueWorkerAlive || packetQueueDropped >= 100
      ? "degraded"
      : packetQueueDropped > 0 || packetQueueUtilization >= 80 || (packetQueueMaxSize > 0 && packetQueueDepth >= packetQueueMaxSize * 0.8)
        ? "warning"
        : "healthy";
  const freshnessLevel = ageSeconds == null || ageSeconds <= 120 ? "healthy" : ageSeconds <= 300 ? "warning" : "degraded";
  const criticalFlows = toNumber(flows.risk_distribution?.critical);
  const highFlows = toNumber(flows.risk_distribution?.high);
  const overall = worstLevel(backendLevel, freshnessLevel, packetQueueLevel, persistenceLevel, streamLevel, queryLevel, autoBlockLevel);
  const recommendedActions = [];

  if (backendLevel !== "healthy") {
    recommendedActions.push("Review runtime pressure signals reported by the backend.");
  }
  if (freshnessLevel !== "healthy") {
    recommendedActions.push("Refresh the ops snapshot before making a decision.");
  }
  if (!packetQueueWorkerAlive) {
    recommendedActions.push("Packet queue worker is not running. Restart capture or inspect backend logs.");
  }
  if (packetQueueDropped > 0) {
    recommendedActions.push("Packet drops were detected. Review overflow policy, queue size, and capture pressure.");
  }
  if (packetQueueUtilization >= 80 || (packetQueueMaxSize > 0 && packetQueueDepth >= packetQueueMaxSize * 0.8)) {
    recommendedActions.push("Increase queue size, reduce capture rate, or enable batching before heavier workloads.");
  }
  if (packetQueueMaxSize > 0 && packetQueueHighWater >= packetQueueMaxSize * 0.9) {
    recommendedActions.push("Queue pressure is approaching capacity. Consider increasing NETBOT_PACKET_QUEUE_MAX_SIZE.");
  }
  if (criticalFlows > 0) {
    recommendedActions.push("Review critical flows and related alerts first.");
  } else if (highFlows > 0) {
    recommendedActions.push("Review high-risk flows for unusual destinations.");
  }
  if (!capture.running) {
    recommendedActions.push("Start capture or confirm monitoring is intentionally paused.");
  }
  if (droppedWrites > 0 || toNumber(persistence.flush_errors) > 0 || queueSize >= 250) {
    recommendedActions.push("Check persistence backlog and export/report write health.");
  }
  if (queryLevel !== "healthy") {
    recommendedActions.push("Check history query latency and packet/alert storage load.");
  }
  if (wsDropped > 0) {
    recommendedActions.push("Check live stream subscribers for dropped websocket events.");
  }
  if (wsSlowClients > 0) {
    recommendedActions.push("One or more WebSocket clients are slow. Reduce realtime update pressure or inspect frontend performance.");
  }
  if (wsEventDrops > 0) {
    recommendedActions.push("Realtime event drops were detected. Review batch size, batch interval, and client queue settings.");
  }
  if (wsEventCoalesced > 0) {
    recommendedActions.push("Realtime updates are being coalesced to protect performance. Consider increasing batch windows or reducing capture pressure.");
  }
  if (wsSendLatency >= 250) {
    recommendedActions.push("WebSocket send latency is high. Check browser load, network latency, and backend event pressure.");
  } else if (wsSubscribers === 0 && wsPublished > 0) {
    recommendedActions.push("Open the live dashboard or verify websocket subscribers are connected.");
  }
  if (autoBlockLevel !== "healthy") {
    recommendedActions.push("Review auto-block failures and firewall permissions.");
  }
  if (!recommendedActions.length) {
    recommendedActions.push("No immediate action needed.");
  }

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
      level: criticalFlows > 0
        ? "degraded"
        : highFlows > 0
          ? "warning"
          : "healthy",
    },
    {
      label: "Packet Queue",
      value: packetQueueMaxSize ? `${packetQueueDepth}/${packetQueueMaxSize}` : String(packetQueueDepth),
      hint: `${packetQueueUtilization.toFixed(1)}% used | Drops ${packetQueueDropped}`,
      level: packetQueueLevel,
    },
    {
      label: "Write Queue",
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
      value: String(wsDropped + wsEventDrops),
      hint: `Batches ${wsBatchesSent} | Clients ${wsClients}`,
      level: streamLevel,
    },
    {
      label: "Event Batches",
      value: String(wsBatchesSent),
      hint: `${wsEventsSent} sent from ${wsEventsReceived} received`,
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
    recommendedActions,
    capture,
    flows,
    pressureReasons,
    eventBus,
    eventAggregator,
    websocket,
    websocketLevel: streamLevel,
    safeWebSocketDropReason: safeWebSocketDropReason(websocket.last_drop_reason || eventAggregator.last_drop_reason),
    packetQueue,
    safeLastDropReason: safeQueueDropReason(packetQueue.last_drop_reason),
    packetQueueLevel,
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
