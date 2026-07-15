import { AccordionPanel } from "./AccordionPanel";
import { buildOpsSnapshot, formatMs, levelClass, levelLabel } from "../lib/opsHealth";

function MetricRow({ label, value, level = "healthy", hint = "" }) {
  return (
    <div className={`ops-metric-row ${levelClass(level)}`}>
      <div>
        <dt>{label}</dt>
        {hint ? <small>{hint}</small> : null}
      </div>
      <dd>{value}</dd>
    </div>
  );
}

function SummaryCard({ card }) {
  return (
    <article className={`ops-summary-card ${levelClass(card.level)}`}>
      <span>{card.label}</span>
      <strong>{card.value}</strong>
      <small>{card.hint}</small>
    </article>
  );
}

function formatGeneratedAt(value) {
  if (!value) return "Backend snapshot";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return "Backend snapshot";
  return `Updated ${new Date(parsed).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
}

export function OpsPanel({ observability, operationalMetrics = null, isRefreshing = false, onRefresh = null }) {
  const snapshot = buildOpsSnapshot(observability, operationalMetrics);
  const levelFor = (label, fallback = "healthy") => snapshot.summaryCards.find((card) => card.label === label)?.level || fallback;
  const packetQueue = snapshot.packetQueue;
  const packetQueueLastDropReason = snapshot.safeLastDropReason || "No drops recorded";
  const flowWorkerPool = snapshot.flowWorkerPool;
  const flowWorkerLastDropReason = snapshot.safeFlowWorkerDropReason || "No drops recorded";
  const liveRingBuffer = snapshot.liveRingBuffer;
  const serviceAttribution = snapshot.serviceAttribution;
  const incidents = snapshot.incidents;
  const persistence = snapshot.persistence;
  const eventBus = snapshot.eventBus;
  const eventAggregator = snapshot.eventAggregator;
  const websocket = snapshot.websocket;
  const websocketLastDropReason = snapshot.safeWebSocketDropReason || "No drops recorded";
  const autoBlock = snapshot.autoBlock;
  const capture = snapshot.capture;
  const flows = snapshot.flows;
  const packetsList = snapshot.packetsList;
  const alertsList = snapshot.alertsList;
  const packetDetail = snapshot.packetDetail;
  const alertDetail = snapshot.alertDetail;

  return (
    <div className="panel-body">
      <div className="panel-toolbar">
        <div>
          <p className="eyebrow">Ops Monitor</p>
          <h3 className="ops-title">Runtime Health</h3>
          <p className="muted">{formatGeneratedAt(snapshot.generatedAt)}</p>
        </div>
        <div className="ops-toolbar-actions">
          {onRefresh ? (
            <button type="button" className="secondary" disabled={isRefreshing} onClick={onRefresh}>
              {isRefreshing ? "Refreshing..." : "Refresh"}
            </button>
          ) : null}
          <span className={`ops-state-pill ${levelClass(snapshot.overall)}`}>{levelLabel(snapshot.overall)}</span>
        </div>
      </div>

      <div className="ops-summary-grid">
        {snapshot.summaryCards.map((card) => <SummaryCard key={card.label} card={card} />)}
      </div>

      <AccordionPanel
        eyebrow="System"
        title="Capture and Flow Pressure"
        subtitle="Backend health snapshot from the protected monitoring metrics endpoint."
        badge={levelLabel(levelFor("Runtime Health"))}
        defaultOpen
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Capture State" value={capture.running ? "Running" : "Stopped"} level={capture.running ? "healthy" : "warning"} hint={capture.interface || "No interface selected"} />
          <MetricRow label="Packets Observed" value={String(capture.total_packets || 0)} hint={`Alerts ${capture.total_alerts || 0}`} />
          <MetricRow label="Total Flows" value={String(flows.total || 0)} hint={`${flows.active || 0} active | ${flows.external || 0} external`} />
          <MetricRow label="Risky Flows" value={String((flows.risk_distribution?.high || 0) + (flows.risk_distribution?.critical || 0))} level={(flows.risk_distribution?.critical || 0) > 0 ? "degraded" : (flows.risk_distribution?.high || 0) > 0 ? "warning" : "healthy"} hint={`Critical ${flows.risk_distribution?.critical || 0}`} />
        </dl>
        {snapshot.pressureReasons.length ? (
          <div className="ops-pressure-list">
            {snapshot.pressureReasons.map((reason) => <span key={reason}>{reason}</span>)}
          </div>
        ) : null}
        <div className="ops-action-list">
          <p className="eyebrow">Recommended Actions</p>
          <ul>
            {snapshot.recommendedActions.map((action) => <li key={action}>{action}</li>)}
          </ul>
        </div>
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Performance"
        title="Packet Intake Queue"
        subtitle="Bounded packet queue between capture and packet processing."
        badge={levelLabel(snapshot.packetQueueLevel)}
        defaultOpen
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Queue Depth" value={`${packetQueue.current_depth ?? packetQueue.queue_size ?? 0}/${packetQueue.max_size ?? 0}`} level={snapshot.packetQueueLevel} hint={`${Number(packetQueue.utilization_percent || 0).toFixed(1)}% used`} />
          <MetricRow label="Max Size" value={String(packetQueue.max_size ?? 0)} hint="NETBOT_PACKET_QUEUE_MAX_SIZE" />
          <MetricRow label="Utilization" value={`${Number(packetQueue.utilization_percent || 0).toFixed(1)}%`} level={Number(packetQueue.utilization_percent || 0) >= 80 ? "degraded" : "healthy"} hint={`Depth ${packetQueue.current_depth ?? packetQueue.queue_size ?? 0}`} />
          <MetricRow label="Accepted Packets" value={String(packetQueue.accepted_total ?? packetQueue.accepted_packets ?? 0)} hint="Accepted by bounded intake queue" />
          <MetricRow label="Dropped Packets" value={String(packetQueue.dropped_total ?? packetQueue.dropped_packets ?? 0)} level={Number(packetQueue.dropped_total ?? packetQueue.dropped_packets ?? 0) > 0 ? "degraded" : "healthy"} hint={`Oldest ${packetQueue.dropped_oldest_total ?? packetQueue.dropped_oldest ?? 0} | Newest ${packetQueue.dropped_newest_total ?? packetQueue.dropped_newest ?? 0}`} />
          <MetricRow label="Dropped Oldest" value={String(packetQueue.dropped_oldest_total ?? packetQueue.dropped_oldest ?? 0)} />
          <MetricRow label="Dropped Newest" value={String(packetQueue.dropped_newest_total ?? packetQueue.dropped_newest ?? 0)} />
          <MetricRow label="High-water Mark" value={String(packetQueue.high_water_mark ?? packetQueue.queue_high_water_mark ?? 0)} hint="Peak observed queue depth" />
          <MetricRow label="Overflow Policy" value={packetQueue.overflow_policy || "drop_oldest"} hint={packetQueueLastDropReason} />
          <MetricRow label="Worker" value={packetQueue.worker_alive === false ? "Stopped" : "Running"} level={packetQueue.worker_alive === false ? "degraded" : "healthy"} hint={`Health ${packetQueue.health || "healthy"}`} />
        </dl>
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Intelligence"
        title="Service Attribution"
        subtitle="Metadata-only destination correlation using the local fingerprint registry."
        badge={serviceAttribution.enabled ? levelLabel(snapshot.serviceAttributionLevel) : "Disabled"}
        defaultOpen
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Attribution State" value={serviceAttribution.enabled ? "Enabled" : "Disabled"} level={snapshot.serviceAttributionLevel} hint={`Health ${serviceAttribution.health || "healthy"}`} />
          <MetricRow label="Registry Size" value={String(serviceAttribution.registry_size || 0)} hint="Local service fingerprints" />
          <MetricRow label="Attributed Flows" value={String(serviceAttribution.attributed_flows_total || 0)} hint={`Unknown ${serviceAttribution.unknown_flows_total || 0}`} />
          <MetricRow label="High Confidence" value={String(serviceAttribution.high_confidence_total || 0)} hint={`Medium ${serviceAttribution.medium_confidence_total || 0} | Low ${serviceAttribution.low_confidence_total || 0}`} />
          <MetricRow label="Encrypted Unknown" value={String(serviceAttribution.encrypted_unknown_total || 0)} level={Number(serviceAttribution.encrypted_unknown_total || 0) > 0 ? "warning" : "healthy"} />
          <MetricRow label="CDN-only" value={String(serviceAttribution.cdn_only_total || 0)} hint="Shared infrastructure without final-service evidence" />
          <MetricRow label="Attribution Errors" value={String(serviceAttribution.attribution_errors_total || 0)} level={Number(serviceAttribution.attribution_errors_total || 0) > 0 ? "degraded" : "healthy"} hint={serviceAttribution.last_error || "None"} />
          <MetricRow label="Average Latency" value={formatMs(serviceAttribution.avg_attribution_latency_ms || 0)} />
          <MetricRow label="Latency p95" value={formatMs(serviceAttribution.p95_attribution_latency_ms || 0)} level={Number(serviceAttribution.p95_attribution_latency_ms || 0) >= 25 ? "warning" : "healthy"} />
          <MetricRow label="Pressure Reasons" value={(serviceAttribution.pressure_reasons || []).join(", ") || "None"} level={(serviceAttribution.pressure_reasons || []).length ? "warning" : "healthy"} />
        </dl>
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Intelligence"
        title="Incident Correlation Engine"
        subtitle="Bounded correlation of redacted alerts, flows, attribution, and expert signals."
        badge={incidents.enabled ? levelLabel(snapshot.incidentLevel) : "Disabled"}
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Engine State" value={incidents.enabled ? "Enabled" : "Disabled"} level={snapshot.incidentLevel} hint={`Health ${incidents.health}`} />
          <MetricRow label="Open Incidents" value={String(incidents.open_total)} hint={`Limit ${incidents.max_open_incidents}`} level={incidents.open_total >= incidents.max_open_incidents && incidents.max_open_incidents ? "degraded" : "healthy"} />
          <MetricRow label="Created / Updated" value={`${incidents.created_total} / ${incidents.updated_total}`} hint={`Resolved ${incidents.resolved_total} | Suppressed ${incidents.suppressed_total}`} />
          <MetricRow label="Signals" value={String(incidents.signals_received_total)} hint={`Correlated ${incidents.signals_correlated_total} | Ignored ${incidents.signals_ignored_total}`} />
          <MetricRow label="Dropped Signals" value={String(incidents.signals_dropped_total)} level={incidents.signals_dropped_total ? "degraded" : "healthy"} />
          <MetricRow label="High / Critical" value={`${incidents.high_severity_total} / ${incidents.critical_severity_total}`} level={incidents.critical_severity_total ? "degraded" : incidents.high_severity_total ? "warning" : "healthy"} />
          <MetricRow label="Correlation Latency" value={formatMs(incidents.avg_correlation_latency_ms)} hint={`P95 ${formatMs(incidents.p95_correlation_latency_ms)}`} />
          <MetricRow label="Last Created" value={incidents.last_created_at || "Not yet"} hint={`Updated ${incidents.last_updated_at || "Not yet"}`} />
          <MetricRow label="Pressure Reasons" value={incidents.pressure_reasons.join(", ") || "None"} level={incidents.pressure_reasons.length ? "warning" : "healthy"} />
        </dl>
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Live Memory"
        title="Live Ring Buffer"
        subtitle="Bounded, redacted recent packet, flow, alert, and expert history."
        badge={liveRingBuffer.enabled ? levelLabel(snapshot.liveRingLevel) : "Disabled"}
        defaultOpen
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Buffer State" value={liveRingBuffer.enabled ? "Enabled" : "Disabled"} level={snapshot.liveRingLevel} hint={`Health ${liveRingBuffer.health || "healthy"}`} />
          <MetricRow label="Records" value={`${liveRingBuffer.total_records || 0}/${liveRingBuffer.total_capacity || 0}`} level={snapshot.liveRingLevel} hint={`${Number(liveRingBuffer.utilization_percent || 0).toFixed(1)}% used`} />
          <MetricRow label="Records Added" value={String(liveRingBuffer.records_added_total || 0)} hint="Redacted live summaries accepted" />
          <MetricRow label="Records Evicted" value={String(liveRingBuffer.records_evicted_total || 0)} level={(liveRingBuffer.pressure_reasons || []).includes("live_ring_frequent_evictions") ? "warning" : "healthy"} hint="Oldest records removed at capacity" />
          <MetricRow label="Records Dropped" value={String(liveRingBuffer.records_dropped_total || 0)} level={Number(liveRingBuffer.records_dropped_total || 0) > 0 ? "degraded" : "healthy"} />
          <MetricRow label="Queries" value={String(liveRingBuffer.query_count_total || 0)} hint={`Capped ${liveRingBuffer.query_limit_rejected_total || 0}`} level={Number(liveRingBuffer.query_limit_rejected_total || 0) > 0 ? "warning" : "healthy"} />
          <MetricRow label="Last Added" value={liveRingBuffer.last_added_at || "Not yet"} />
          <MetricRow label="Last Evicted" value={liveRingBuffer.last_evicted_at || "Not yet"} />
          <MetricRow label="Last Error" value={liveRingBuffer.last_error || "None"} level={liveRingBuffer.last_error ? "degraded" : "healthy"} />
          <MetricRow label="Pressure Reasons" value={(liveRingBuffer.pressure_reasons || []).join(", ") || "None"} level={(liveRingBuffer.pressure_reasons || []).length ? "warning" : "healthy"} />
        </dl>
        {Object.keys(liveRingBuffer.categories || {}).length ? (
          <div className="ops-worker-grid" aria-label="Live ring buffer category status">
            {Object.entries(liveRingBuffer.categories).map(([category, values]) => (
              <article className="ops-worker-item" key={category}>
                <div>
                  <strong>{category.replaceAll("_", " ")}</strong>
                  <small>{Number(values.utilization_percent || 0).toFixed(1)}% used</small>
                </div>
                <span>{values.records || 0}/{values.capacity || 0} records</span>
                <small>{values.evicted_total || 0} evicted</small>
              </article>
            ))}
          </div>
        ) : null}
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Performance"
        title="Flow Worker Pool"
        subtitle="Ordered per-flow processing lanes between packet intake and analysis."
        badge={flowWorkerPool.enabled ? levelLabel(snapshot.flowWorkerLevel) : "Disabled"}
        defaultOpen
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Pool State" value={flowWorkerPool.enabled ? "Enabled" : "Disabled"} level={snapshot.flowWorkerLevel} hint={`Health ${flowWorkerPool.health || "healthy"}`} />
          <MetricRow label="Active Workers" value={`${flowWorkerPool.active_workers || 0}/${flowWorkerPool.worker_count || 0}`} level={snapshot.flowWorkerLevel} hint="Stable flow-to-worker assignment" />
          <MetricRow label="Queue Depth" value={`${flowWorkerPool.queue_depth_total || 0}/${flowWorkerPool.queue_max_total || 0}`} level={Number(flowWorkerPool.utilization_percent || 0) >= 80 ? "degraded" : "healthy"} hint={`${Number(flowWorkerPool.utilization_percent || 0).toFixed(1)}% used`} />
          <MetricRow label="Overflow Policy" value={flowWorkerPool.overflow_policy || "drop_oldest"} hint={flowWorkerLastDropReason} />
          <MetricRow label="Jobs Received" value={String(flowWorkerPool.jobs_received_total || 0)} hint={`Processed ${flowWorkerPool.jobs_processed_total || 0}`} />
          <MetricRow label="Jobs Failed" value={String(flowWorkerPool.jobs_failed_total || 0)} level={Number(flowWorkerPool.jobs_failed_total || 0) > 0 ? "degraded" : "healthy"} hint={`Last error ${flowWorkerPool.last_error || "None"}`} />
          <MetricRow label="Jobs Dropped" value={String(flowWorkerPool.jobs_dropped_total || 0)} level={Number(flowWorkerPool.jobs_dropped_total || 0) > 0 ? "degraded" : "healthy"} hint={`Rejected ${flowWorkerPool.jobs_rejected_total || 0}`} />
          <MetricRow label="Unknown Flow Keys" value={String(flowWorkerPool.unknown_flow_key_total || 0)} hint="Safely routed to a fallback lane" />
          <MetricRow label="Slow Jobs" value={String(flowWorkerPool.slow_jobs_total || 0)} level={Number(flowWorkerPool.slow_jobs_total || 0) > 0 ? "warning" : "healthy"} hint={flowWorkerPool.last_slow_job_at || "None recorded"} />
          <MetricRow label="Average Latency" value={formatMs(flowWorkerPool.avg_processing_latency_ms || 0)} />
          <MetricRow label="Latency p95" value={formatMs(flowWorkerPool.p95_processing_latency_ms || 0)} level={Number(flowWorkerPool.p95_processing_latency_ms || 0) >= 100 ? "warning" : "healthy"} />
          <MetricRow label="Max Latency" value={formatMs(flowWorkerPool.max_processing_latency_ms || 0)} />
          <MetricRow label="Pressure Reasons" value={(flowWorkerPool.pressure_reasons || []).join(", ") || "None"} level={(flowWorkerPool.pressure_reasons || []).length ? "warning" : "healthy"} />
        </dl>
        {(flowWorkerPool.per_worker || []).length ? (
          <div className="ops-worker-grid" aria-label="Flow worker status">
            {flowWorkerPool.per_worker.map((worker) => (
              <article className="ops-worker-item" key={worker.worker_id}>
                <div>
                  <strong>Worker {worker.worker_id}</strong>
                  <small>{worker.worker_alive ? "Running" : "Stopped"}</small>
                </div>
                <span>{worker.queue_depth || 0}/{worker.queue_max || 0} queued</span>
                <small>{worker.processed_total || 0} processed | p95 {formatMs(worker.p95_latency_ms || 0)}</small>
              </article>
            ))}
          </div>
        ) : null}
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Write Path"
        title="Persistence Engine"
        subtitle="Queue pressure, batching behavior, retries, and shutdown drain state."
        badge={levelLabel(levelFor("Persistence"))}
        defaultOpen
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Persistence Health" value={persistence.health || "healthy"} level={persistence.health || "healthy"} hint={persistence.worker_alive === false ? "Worker stopped" : "Worker running"} />
          <MetricRow label="Queue Depth" value={String(persistence.queue_depth ?? persistence.current_depth ?? persistence.queue_size ?? 0)} level={levelFor("Write Queue")} hint={`Max ${persistence.queue_max ?? persistence.max_size ?? 0}`} />
          <MetricRow label="Queue Max" value={String(persistence.queue_max ?? persistence.max_size ?? 0)} hint="NETBOT_PERSISTENCE_QUEUE_MAX" />
          <MetricRow label="Utilization" value={`${Number(persistence.utilization_percent ?? persistence.queue_utilization_percent ?? 0).toFixed(1)}%`} level={Number(persistence.utilization_percent ?? persistence.queue_utilization_percent ?? 0) >= 80 ? "degraded" : "healthy"} hint={`High-water ${persistence.high_water_mark ?? persistence.queue_high_water_mark ?? 0}`} />
          <MetricRow label="Batches Written" value={String(persistence.batches_written_total ?? persistence.flush_batches ?? 0)} />
          <MetricRow label="Events Received" value={String(persistence.events_received_total ?? persistence.accepted_writes ?? 0)} hint={`Written ${persistence.events_written_total || 0} | Batches ${persistence.batches_written_total ?? persistence.flush_batches ?? 0}`} />
          <MetricRow label="Events Written" value={String(persistence.events_written_total || 0)} />
          <MetricRow label="Dropped Events" value={String(persistence.events_dropped_total ?? persistence.dropped_writes ?? 0)} level={levelFor("Dropped Writes")} hint={`Policy ${persistence.overflow_policy ?? persistence.overload_policy ?? "drop_oldest"}`} />
          <MetricRow label="Failed Writes" value={String(persistence.events_failed_total ?? persistence.failed_writes ?? 0)} level={Number(persistence.events_failed_total ?? persistence.failed_writes ?? 0) > 0 ? "degraded" : "healthy"} hint={`Last error ${persistence.last_error || "None"}`} />
          <MetricRow label="Retries" value={String(persistence.retry_total ?? persistence.flush_retries ?? 0)} level={Number(persistence.retry_total ?? persistence.flush_retries ?? 0) > 0 ? "warning" : "healthy"} hint={`Backlog age ${formatMs(persistence.backlog_age_ms || 0)}`} />
          <MetricRow label="Write Latency Average" value={formatMs(persistence.write_latency_ms_avg ?? persistence.write_latency_avg_ms ?? persistence.avg_flush_ms ?? 0)} level={Number(persistence.write_latency_ms_avg ?? persistence.write_latency_avg_ms ?? persistence.avg_flush_ms ?? 0) >= 250 ? "warning" : "healthy"} />
          <MetricRow label="Write Latency p95" value={formatMs(persistence.write_latency_ms_p95 ?? persistence.write_latency_p95_ms ?? persistence.p95_flush_ms ?? 0)} level={Number(persistence.write_latency_ms_p95 ?? persistence.write_latency_p95_ms ?? persistence.p95_flush_ms ?? 0) >= 500 ? "degraded" : "healthy"} />
          <MetricRow label="Backlog Age" value={formatMs(persistence.backlog_age_ms || 0)} />
          <MetricRow label="Last Flush" value={persistence.last_flush_at || "Not yet"} hint={persistence.last_drop_reason || "No persistence drops"} />
          <MetricRow label="Last Error" value={persistence.last_error || "None"} />
          <MetricRow label="Last Drop Reason" value={persistence.last_drop_reason || "None"} />
          <MetricRow label="Pressure Reasons" value={(persistence.pressure_reasons || []).join(", ") || "None"} level={(persistence.pressure_reasons || []).length ? "warning" : "healthy"} />
        </dl>
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Read Path"
        title="History Query Path"
        subtitle="Realtime query latency for packet and alert list/detail routes."
        badge={levelLabel(snapshot.queryErrorCount > 0 || snapshot.queryLatencyMs >= 180 ? "warning" : "healthy")}
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Packets List" value={formatMs(packetsList.last_ms || 0)} level={Number(packetsList.last_ms || 0) >= 180 ? "warning" : "healthy"} hint={`Avg ${formatMs(packetsList.avg_ms || 0)} | Calls ${packetsList.calls || 0}`} />
          <MetricRow label="Alerts List" value={formatMs(alertsList.last_ms || 0)} level={Number(alertsList.last_ms || 0) >= 180 ? "warning" : "healthy"} hint={`Avg ${formatMs(alertsList.avg_ms || 0)} | Calls ${alertsList.calls || 0}`} />
          <MetricRow label="Packet Detail" value={formatMs(packetDetail.last_ms || 0)} hint={`Errors ${packetDetail.errors || 0} | Calls ${packetDetail.calls || 0}`} />
          <MetricRow label="Alert Detail" value={formatMs(alertDetail.last_ms || 0)} hint={`Errors ${alertDetail.errors || 0} | Calls ${alertDetail.calls || 0}`} />
        </dl>
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Stream"
        title="WebSocket Event Aggregator"
        subtitle="Batched realtime updates and bounded slow-client protection."
        badge={levelLabel(levelFor("WS Drops"))}
        defaultOpen
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Aggregator Health" value={eventAggregator.health || "healthy"} level={snapshot.websocketLevel} hint={`Packet window ${eventAggregator.packet_batch_ms || 500} ms`} />
          <MetricRow label="WebSocket Clients" value={String(websocket.clients ?? websocket.websocket_clients ?? eventBus.subscribers ?? 0)} hint={`Slow ${websocket.slow_clients ?? websocket.websocket_slow_clients ?? 0}`} level={Number(websocket.slow_clients ?? websocket.websocket_slow_clients ?? 0) > 0 ? "degraded" : "healthy"} />
          <MetricRow label="Batches Sent" value={String(eventAggregator.batches_sent_total || 0)} hint={`Avg size ${Number(eventAggregator.websocket_batch_size_avg || 0).toFixed(1)}`} />
          <MetricRow label="Events Received" value={String(eventAggregator.events_received_total || 0)} hint={`Sent ${eventAggregator.events_sent_total || 0}`} />
          <MetricRow label="Events Coalesced" value={String(eventAggregator.events_coalesced_total || 0)} level={Number(eventAggregator.events_coalesced_total || 0) > 0 ? "warning" : "healthy"} hint="Summary and slow-client protection" />
          <MetricRow label="Events Dropped" value={String((eventAggregator.events_dropped_total || 0) + (websocket.dropped_for_slow_client_total || 0))} level={Number((eventAggregator.events_dropped_total || 0) + (websocket.dropped_for_slow_client_total || 0)) > 0 ? "degraded" : "healthy"} hint={websocketLastDropReason} />
          <MetricRow label="Packet Batch Window" value={`${eventAggregator.packet_batch_ms || 500} ms`} hint={`Max ${eventAggregator.packet_batch_max || 250}`} />
          <MetricRow label="Alert Batch Window" value={`${eventAggregator.alert_batch_ms || 500} ms`} hint={`Max ${eventAggregator.alert_batch_max || 100}`} />
          <MetricRow label="Send Latency p95" value={formatMs(websocket.send_latency_ms_p95 || websocket.websocket_send_latency_ms || 0)} level={Number(websocket.send_latency_ms_p95 || websocket.websocket_send_latency_ms || 0) >= 250 ? "warning" : "healthy"} hint={`avg ${formatMs(websocket.send_latency_ms_avg || websocket.websocket_send_latency_ms_avg || 0)} | p50 ${formatMs(websocket.send_latency_ms_p50 || 0)}`} />
          <MetricRow label="Client Queue" value={String(websocket.client_queue_depth_max ?? websocket.websocket_client_queue_depth ?? 0)} hint={`Max ${websocket.client_queue_max || eventAggregator.client_queue_max || 1000}`} />
          <MetricRow label="WS Subscribers" value={String(eventBus.subscribers || 0)} hint={`Published ${eventBus.published_messages || 0}`} />
          <MetricRow label="Dropped Events" value={String(eventBus.dropped_messages || 0)} level={Number(eventBus.dropped_messages || 0) > 0 ? "degraded" : "healthy"} hint={`Dropped subscribers ${eventBus.dropped_subscribers || 0}`} />
        </dl>
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Actions"
        title="Event Bus and Auto Block"
        subtitle="Automatic firewall action counters remain separate from websocket batching."
        badge={levelLabel(levelFor("WS Drops"))}
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Auto Blocks" value={String(autoBlock.blocked_total || 0)} hint={`Cooldown skips ${autoBlock.cooldown_skips || 0}`} />
          <MetricRow label="Auto Block Failures" value={String(autoBlock.failed_total || 0)} level={Number(autoBlock.failed_total || 0) > 0 ? "warning" : "healthy"} hint={`Private skips ${autoBlock.private_ip_skips || 0} | Whitelist skips ${autoBlock.whitelist_skips || 0}`} />
        </dl>
      </AccordionPanel>
    </div>
  );
}
