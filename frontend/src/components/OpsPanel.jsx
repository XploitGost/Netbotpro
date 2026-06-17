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

export function OpsPanel({ observability, operationalMetrics = null }) {
  const snapshot = buildOpsSnapshot(observability, operationalMetrics);
  const levelFor = (label, fallback = "healthy") => snapshot.summaryCards.find((card) => card.label === label)?.level || fallback;
  const persistence = snapshot.persistence;
  const eventBus = snapshot.eventBus;
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
        <span className={`ops-state-pill ${levelClass(snapshot.overall)}`}>{levelLabel(snapshot.overall)}</span>
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
      </AccordionPanel>

      <AccordionPanel
        eyebrow="Write Path"
        title="Persistence Engine"
        subtitle="Queue pressure, batching behavior, retries, and shutdown drain state."
        badge={levelLabel(levelFor("Persistence"))}
        defaultOpen
      >
        <dl className="ops-metric-grid">
          <MetricRow label="Queue Size" value={String(persistence.queue_size || 0)} level={levelFor("Queue Size")} hint={`High-water ${persistence.queue_high_water_mark || 0}`} />
          <MetricRow label="Dropped Writes" value={String(persistence.dropped_writes || 0)} level={levelFor("Dropped Writes")} hint={`Policy ${persistence.overload_policy || "drop_oldest"}`} />
          <MetricRow label="Average Batch Size" value={Number(persistence.avg_batch_size || 0).toFixed(1)} hint={`Last batch ${persistence.last_batch_size || 0}`} />
          <MetricRow label="Average Flush" value={formatMs(persistence.avg_flush_ms || 0)} level={Number(persistence.avg_flush_ms || 0) >= 250 ? "warning" : "healthy"} hint={`Last flush ${formatMs(persistence.last_flush_ms || 0)}`} />
          <MetricRow label="Flush Retries" value={String(persistence.flush_retries || 0)} level={Number(persistence.flush_retries || 0) > 0 ? "warning" : "healthy"} hint={`Errors ${persistence.flush_errors || 0}`} />
          <MetricRow label="Queue Drift" value={formatMs(persistence.last_queue_drift_ms || 0)} hint={`Batches ${persistence.flush_batches || 0}`} />
          <MetricRow label="Drain Completed" value={Number(persistence.drain_completed || 0) ? "Yes" : "No"} level={Number(persistence.shutdown_flush_timeout || 0) ? "degraded" : "healthy"} hint={`Shutdown timeout ${persistence.shutdown_flush_timeout || 0}`} />
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
        title="Event Bus and Auto Block"
        subtitle="Delivery health for websocket subscribers and automatic firewall actions."
        badge={levelLabel(levelFor("WS Drops"))}
      >
        <dl className="ops-metric-grid">
          <MetricRow label="WS Subscribers" value={String(eventBus.subscribers || 0)} hint={`Published ${eventBus.published_messages || 0}`} />
          <MetricRow label="Dropped Events" value={String(eventBus.dropped_messages || 0)} level={Number(eventBus.dropped_messages || 0) > 0 ? "degraded" : "healthy"} hint={`Dropped subscribers ${eventBus.dropped_subscribers || 0}`} />
          <MetricRow label="Auto Blocks" value={String(autoBlock.blocked_total || 0)} hint={`Cooldown skips ${autoBlock.cooldown_skips || 0}`} />
          <MetricRow label="Auto Block Failures" value={String(autoBlock.failed_total || 0)} level={Number(autoBlock.failed_total || 0) > 0 ? "warning" : "healthy"} hint={`Private skips ${autoBlock.private_ip_skips || 0} | Whitelist skips ${autoBlock.whitelist_skips || 0}`} />
        </dl>
      </AccordionPanel>
    </div>
  );
}
