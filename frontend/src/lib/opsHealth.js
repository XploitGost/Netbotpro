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

function safeFlowWorkerDropReason(value) {
  const allowed = new Set([
    "flow_worker_queue_full_drop_oldest",
    "flow_worker_queue_full_after_drop_oldest",
    "flow_worker_queue_full_drop_newest",
    "flow_worker_queue_full_reject_new",
    "flow_worker_queue_block_timeout",
    "worker_pool_closed",
  ]);
  return allowed.has(value) ? value : "";
}

function safeFlowWorkerError(value) {
  const errorType = String(value || "");
  return errorType.length <= 80 && /^[A-Za-z0-9_]+$/.test(errorType) ? errorType : "";
}

function safeFlowWorkerReasons(value) {
  const allowed = new Set([
    "flow_worker_queue_backlog",
    "flow_worker_high_utilization",
    "flow_worker_slow_jobs",
    "flow_worker_job_failures",
    "flow_worker_dropped_jobs",
    "flow_worker_not_alive",
  ]);
  return Array.isArray(value) ? value.filter((reason) => allowed.has(reason)) : [];
}

function safeLiveRingError(value) {
  const errorType = String(value || "");
  return errorType.length <= 80 && /^[A-Za-z0-9_]+$/.test(errorType) ? errorType : "";
}

function safeLiveRingReasons(value) {
  const allowed = new Set([
    "live_ring_high_utilization",
    "live_ring_frequent_evictions",
    "live_ring_query_limit_rejections",
    "live_ring_errors",
  ]);
  return Array.isArray(value) ? value.filter((reason) => allowed.has(reason)) : [];
}

export function buildOpsSnapshot(observability, operationalMetrics = null) {
  const eventBus = observability?.event_bus || {};
  const eventAggregator = operationalMetrics?.event_aggregator || observability?.event_aggregator || {};
  const websocket = operationalMetrics?.websocket || observability?.websocket || {};
  const packetQueue = operationalMetrics?.packet_queue || observability?.packet_queue || {};
  const flowWorkerPool = operationalMetrics?.flow_worker_pool || observability?.flow_worker_pool || {};
  const safeFlowWorkerPool = {
    ...flowWorkerPool,
    last_error: safeFlowWorkerError(flowWorkerPool.last_error),
    last_drop_reason: safeFlowWorkerDropReason(flowWorkerPool.last_drop_reason),
    pressure_reasons: safeFlowWorkerReasons(flowWorkerPool.pressure_reasons),
  };
  const liveRingBuffer = operationalMetrics?.live_ring_buffer || observability?.live_ring_buffer || {};
  const safeLiveRingCategories = Object.fromEntries(
    Object.entries(liveRingBuffer.categories || {})
      .filter(([category]) => ["packet", "flow", "alert", "expert_info", "protocol_metadata", "agent_status", "ops_event"].includes(category))
      .map(([category, values]) => [category, {
        records: toNumber(values?.records),
        capacity: toNumber(values?.capacity),
        utilization_percent: toNumber(values?.utilization_percent),
        evicted_total: toNumber(values?.evicted_total),
      }]),
  );
  const safeLiveRingBuffer = {
    enabled: liveRingBuffer.enabled === true,
    health: ["healthy", "degraded", "critical"].includes(liveRingBuffer.health) ? liveRingBuffer.health : "healthy",
    total_records: toNumber(liveRingBuffer.total_records),
    total_capacity: toNumber(liveRingBuffer.total_capacity),
    utilization_percent: toNumber(liveRingBuffer.utilization_percent),
    records_added_total: toNumber(liveRingBuffer.records_added_total),
    records_evicted_total: toNumber(liveRingBuffer.records_evicted_total),
    records_dropped_total: toNumber(liveRingBuffer.records_dropped_total),
    query_count_total: toNumber(liveRingBuffer.query_count_total),
    query_limit_rejected_total: toNumber(liveRingBuffer.query_limit_rejected_total),
    last_added_at: String(liveRingBuffer.last_added_at || ""),
    last_evicted_at: String(liveRingBuffer.last_evicted_at || ""),
    last_error: safeLiveRingError(liveRingBuffer.last_error),
    pressure_reasons: safeLiveRingReasons(liveRingBuffer.pressure_reasons),
    categories: safeLiveRingCategories,
  };
  const serviceAttribution = operationalMetrics?.service_attribution || observability?.service_attribution || {};
  const safeServiceAttributionReasons = Array.isArray(serviceAttribution.pressure_reasons)
    ? serviceAttribution.pressure_reasons.filter((reason) => [
      "service_attribution_registry_error",
      "service_attribution_high_latency",
      "service_attribution_errors",
      "service_attribution_high_unknown_rate",
    ].includes(reason))
    : [];
  const safeServiceAttribution = {
    enabled: serviceAttribution.enabled !== false,
    health: ["healthy", "degraded", "critical"].includes(serviceAttribution.health) ? serviceAttribution.health : "healthy",
    registry_size: toNumber(serviceAttribution.registry_size),
    attributed_flows_total: toNumber(serviceAttribution.attributed_flows_total),
    unknown_flows_total: toNumber(serviceAttribution.unknown_flows_total),
    high_confidence_total: toNumber(serviceAttribution.high_confidence_total),
    medium_confidence_total: toNumber(serviceAttribution.medium_confidence_total),
    low_confidence_total: toNumber(serviceAttribution.low_confidence_total),
    encrypted_unknown_total: toNumber(serviceAttribution.encrypted_unknown_total),
    cdn_only_total: toNumber(serviceAttribution.cdn_only_total),
    attribution_errors_total: toNumber(serviceAttribution.attribution_errors_total),
    avg_attribution_latency_ms: toNumber(serviceAttribution.avg_attribution_latency_ms),
    p95_attribution_latency_ms: toNumber(serviceAttribution.p95_attribution_latency_ms),
    last_error: /^[A-Za-z0-9_]{1,80}$/.test(String(serviceAttribution.last_error || "")) ? String(serviceAttribution.last_error) : "",
    pressure_reasons: safeServiceAttributionReasons,
  };
  const persistence = operationalMetrics?.persistence || observability?.persistence || {};
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

  const queueSize = toNumber(persistence.queue_depth ?? persistence.queue_size);
  const packetQueueDepth = toNumber(packetQueue.current_depth ?? packetQueue.queue_size);
  const packetQueueMaxSize = toNumber(packetQueue.max_size);
  const packetQueueUtilization = toNumber(packetQueue.utilization_percent);
  const packetQueueDropped = toNumber(packetQueue.dropped_total ?? packetQueue.dropped_packets);
  const packetQueueHighWater = toNumber(packetQueue.high_water_mark ?? packetQueue.queue_high_water_mark);
  const packetQueueWorkerAlive = packetQueue.worker_alive !== false;
  const flowWorkersEnabled = flowWorkerPool.enabled === true;
  const flowWorkerCount = toNumber(flowWorkerPool.worker_count);
  const flowWorkerActive = toNumber(flowWorkerPool.active_workers);
  const flowWorkerDepth = toNumber(flowWorkerPool.queue_depth_total);
  const flowWorkerMax = toNumber(flowWorkerPool.queue_max_total);
  const flowWorkerUtilization = toNumber(flowWorkerPool.utilization_percent);
  const flowWorkerFailed = toNumber(flowWorkerPool.jobs_failed_total);
  const flowWorkerDropped = toNumber(flowWorkerPool.jobs_dropped_total);
  const flowWorkerRejected = toNumber(flowWorkerPool.jobs_rejected_total);
  const flowWorkerSlowJobs = toNumber(flowWorkerPool.slow_jobs_total);
  const flowWorkerP95 = toNumber(flowWorkerPool.p95_processing_latency_ms);
  const liveRingEnabled = safeLiveRingBuffer.enabled;
  const liveRingUtilization = safeLiveRingBuffer.utilization_percent;
  const liveRingEvicted = safeLiveRingBuffer.records_evicted_total;
  const liveRingQueryRejected = safeLiveRingBuffer.query_limit_rejected_total;
  const droppedWrites = toNumber(persistence.events_dropped_total ?? persistence.dropped_writes);
  const failedWrites = toNumber(persistence.events_failed_total ?? persistence.failed_writes);
  const persistenceUtilization = toNumber(persistence.utilization_percent ?? persistence.queue_utilization_percent);
  const persistenceLatencyAvg = toNumber(persistence.write_latency_ms_avg ?? persistence.write_latency_avg_ms ?? persistence.avg_flush_ms);
  const persistenceLatencyP95 = toNumber(persistence.write_latency_ms_p95 ?? persistence.write_latency_p95_ms ?? persistence.p95_flush_ms);
  const persistenceRetries = toNumber(persistence.retry_total ?? persistence.flush_retries);
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

  const persistenceLevel = normalizeLevel(persistence.health) !== "healthy"
    ? normalizeLevel(persistence.health)
    : droppedWrites > 0 || failedWrites > 0 || toNumber(persistence.flush_errors) > 0 || toNumber(persistence.shutdown_flush_timeout) > 0
    ? "degraded"
    : persistenceUtilization >= 80 || persistenceLatencyAvg >= 250 || persistenceLatencyP95 >= 500 || persistenceRetries > 0
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
  const flowWorkerLevel = flowWorkersEnabled
    ? normalizeLevel(flowWorkerPool.health) !== "healthy"
      ? normalizeLevel(flowWorkerPool.health)
      : flowWorkerActive < flowWorkerCount || flowWorkerFailed > 0 || flowWorkerDropped > 0
        ? "degraded"
        : flowWorkerUtilization >= 80 || flowWorkerRejected > 0 || flowWorkerSlowJobs > 0 || flowWorkerP95 >= 100
          ? "warning"
          : "healthy"
    : "healthy";
  const liveRingLevel = liveRingEnabled
    ? normalizeLevel(safeLiveRingBuffer.health) !== "healthy"
      ? normalizeLevel(safeLiveRingBuffer.health)
      : safeLiveRingBuffer.last_error || safeLiveRingBuffer.records_dropped_total > 0
        ? "degraded"
        : liveRingUtilization >= 90 || liveRingQueryRejected > 0
          ? "warning"
          : "healthy"
    : "healthy";
  const serviceAttributionLevel = safeServiceAttribution.enabled
    ? normalizeLevel(safeServiceAttribution.health)
    : "healthy";
  const freshnessLevel = ageSeconds == null || ageSeconds <= 120 ? "healthy" : ageSeconds <= 300 ? "warning" : "degraded";
  const criticalFlows = toNumber(flows.risk_distribution?.critical);
  const highFlows = toNumber(flows.risk_distribution?.high);
  const overall = worstLevel(backendLevel, freshnessLevel, packetQueueLevel, flowWorkerLevel, liveRingLevel, serviceAttributionLevel, persistenceLevel, streamLevel, queryLevel, autoBlockLevel);
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
  if (flowWorkersEnabled && flowWorkerActive < flowWorkerCount) {
    recommendedActions.push("A flow worker appears unhealthy. Restart capture or inspect backend runtime logs.");
  }
  if (flowWorkerUtilization >= 80) {
    recommendedActions.push("Flow worker backlog is growing. Increase worker count, reduce capture pressure, or inspect slow packet processing.");
  }
  if (flowWorkerP95 >= 100 || flowWorkerSlowJobs > 0) {
    recommendedActions.push("Packet processing is slow. Review DPI cost, protocol analysis, and worker count.");
  }
  if (flowWorkerFailed > 0) {
    recommendedActions.push("Flow worker jobs are failing. Inspect backend logs and recent packet processing errors.");
  }
  if (flowWorkerDropped > 0 || flowWorkerRejected > 0) {
    recommendedActions.push("Flow worker jobs were dropped due to processing pressure. Review worker queue size and overflow policy.");
  }
  if (liveRingEnabled && safeLiveRingBuffer.pressure_reasons.includes("live_ring_high_utilization")) {
    recommendedActions.push("Live ring buffer is near capacity. Increase category caps or reduce live capture pressure.");
  }
  if (liveRingEnabled && safeLiveRingBuffer.pressure_reasons.includes("live_ring_frequent_evictions")) {
    recommendedActions.push("Live ring buffer is evicting old records frequently. This is safe but recent history may be shorter than expected.");
  }
  if (liveRingEnabled && liveRingQueryRejected > 0) {
    recommendedActions.push("Live ring buffer query limit was capped. Reduce requested result size or inspect a narrower time range.");
  }
  if (liveRingEnabled && safeLiveRingBuffer.last_error) {
    recommendedActions.push("Live ring buffer reported errors. Inspect backend logs and recent live capture activity.");
  }
  if (safeServiceAttributionReasons.includes("service_attribution_registry_error")) {
    recommendedActions.push("Service attribution registry failed to load. Check service_fingerprints.json.");
  }
  if (safeServiceAttributionReasons.includes("service_attribution_high_unknown_rate")) {
    recommendedActions.push("Many flows could not be attributed. This may be normal with ECH, DoH, VPN, proxy, or shared CDN traffic.");
  }
  if (safeServiceAttributionReasons.includes("service_attribution_high_latency")) {
    recommendedActions.push("Service attribution latency is high. Review fingerprint registry size and matching rules.");
  }
  if (safeServiceAttribution.attribution_errors_total > 0) {
    recommendedActions.push("Service attribution errors were observed. Inspect backend logs and recent flow metadata.");
  }
  if (criticalFlows > 0) {
    recommendedActions.push("Review critical flows and related alerts first.");
  } else if (highFlows > 0) {
    recommendedActions.push("Review high-risk flows for unusual destinations.");
  }
  if (!capture.running) {
    recommendedActions.push("Start capture or confirm monitoring is intentionally paused.");
  }
  if (droppedWrites > 0) {
    recommendedActions.push("Persistence events were dropped due to storage pressure. Review queue size and overflow policy.");
  }
  if (failedWrites > 0 || toNumber(persistence.flush_errors) > 0) {
    recommendedActions.push("Persistence writes are failing. Inspect backend logs and database availability.");
  }
  if (persistenceUtilization >= 80) {
    recommendedActions.push("Persistence backlog is growing. Increase batch size, reduce capture pressure, or inspect database performance.");
  }
  if (persistenceLatencyAvg >= 250 || persistenceLatencyP95 >= 500) {
    recommendedActions.push("Storage writes are slow. Check disk speed, database locks, and batch flush intervals.");
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
      label: "Flow Workers",
      value: flowWorkersEnabled ? `${flowWorkerActive}/${flowWorkerCount}` : "Disabled",
      hint: `${flowWorkerDepth}/${flowWorkerMax} queued | P95 ${formatMs(flowWorkerP95)}`,
      level: flowWorkerLevel,
    },
    {
      label: "Live Ring",
      value: liveRingEnabled ? `${safeLiveRingBuffer.total_records}/${safeLiveRingBuffer.total_capacity}` : "Disabled",
      hint: `${liveRingUtilization.toFixed(1)}% used | Evicted ${liveRingEvicted}`,
      level: liveRingLevel,
    },
    {
      label: "Attribution",
      value: String(safeServiceAttribution.attributed_flows_total),
      hint: `Unknown ${safeServiceAttribution.unknown_flows_total} | High ${safeServiceAttribution.high_confidence_total}`,
      level: serviceAttributionLevel,
    },
    {
      label: "Write Queue",
      value: String(queueSize),
      hint: `${persistenceUtilization.toFixed(1)}% used | Max ${toNumber(persistence.queue_max ?? persistence.max_size)}`,
      level: persistenceLevel,
    },
    {
      label: "Dropped Writes",
      value: String(droppedWrites),
      hint: persistence.overflow_policy ? `Policy ${persistence.overflow_policy}` : "No write drops",
      level: droppedWrites > 0 ? "degraded" : "healthy",
    },
    {
      label: "Avg Flush",
      value: formatMs(persistenceLatencyAvg),
      hint: `P95 ${formatMs(persistenceLatencyP95)}`,
      level: persistenceLatencyAvg >= 250 ? "warning" : "healthy",
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
      hint: `P95 ${formatMs(persistenceLatencyP95)} | Failed ${failedWrites}`,
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
    flowWorkerPool: safeFlowWorkerPool,
    flowWorkerLevel,
    safeFlowWorkerDropReason: safeFlowWorkerPool.last_drop_reason,
    liveRingBuffer: safeLiveRingBuffer,
    liveRingLevel,
    serviceAttribution: safeServiceAttribution,
    serviceAttributionLevel,
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
    persistenceUtilization,
    persistenceLatencyAvg,
    persistenceLatencyP95,
    persistenceRetries,
    summaryCards,
  };
}
