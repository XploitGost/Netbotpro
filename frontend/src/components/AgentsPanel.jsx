import { useMemo, useState } from "react";

function formatDate(value) {
  if (!value) return "-";
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return String(value);
  return new Date(timestamp).toLocaleString();
}

function formatPercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "-";
  return `${Math.round(number)}%`;
}

function percentValue(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, Math.round(number)));
}

function latestTelemetry(agent) {
  return agent?.last_telemetry && typeof agent.last_telemetry === "object"
    ? agent.last_telemetry
    : {};
}

function healthValue(agent, key) {
  return latestTelemetry(agent)?.health?.[key];
}

function capture(agent) {
  return latestTelemetry(agent)?.capture || {};
}

function alerts(agent) {
  return latestTelemetry(agent)?.alerts_summary || {};
}

function risk(agent) {
  return agent?.risk || latestTelemetry(agent)?.risk || { score: 0, severity: "low" };
}

function alertTotal(agent) {
  const item = alerts(agent);
  return Number(item.total_alerts || item.total || item.count || 0);
}

function criticalTotal(agent) {
  const item = alerts(agent);
  return Number(item.critical_count || item.critical || 0);
}

function captureRunning(agent) {
  const item = capture(agent);
  return Boolean(item.running || item.capture_running);
}

function captureMode(agent) {
  const item = capture(agent);
  return item.mode || item.capture_mode || "metadata";
}

function MetricCard({ label, value, hint, tone = "neutral" }) {
  return (
    <div className={`agent-metric-card agent-metric-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{hint}</small>
    </div>
  );
}

function RiskBadge({ value }) {
  const item = value || { score: 0, severity: "low" };
  return (
    <span className={`agent-risk agent-risk-${item.severity || "low"}`}>
      <span className="agent-risk-dot" />
      {item.score ?? 0} {item.severity || "low"}
    </span>
  );
}

function HealthBars({ agent }) {
  const metrics = [
    ["CPU", healthValue(agent, "cpu_percent")],
    ["RAM", healthValue(agent, "memory_percent")],
    ["Disk", healthValue(agent, "disk_percent")],
  ];
  return (
    <div className="agent-health-bars">
      {metrics.map(([label, value]) => (
        <div key={label} className="agent-health-bar">
          <span>{label}</span>
          <div className="agent-health-track">
            <i style={{ width: `${percentValue(value)}%` }} />
          </div>
          <em>{formatPercent(value)}</em>
        </div>
      ))}
    </div>
  );
}

function TrendList({ items = [], value }) {
  const sample = items.slice(-12);
  return (
    <div className="agent-trend-row">
      {sample.map((item, index) => (
        <span
          key={`${item.received_at || index}-${index}`}
          style={{ height: `${Math.max(12, Math.min(72, Number(value(item)) || 0))}px` }}
          title={`${value(item)}`}
        />
      ))}
      {!sample.length ? <p className="muted">No history yet.</p> : null}
    </div>
  );
}

function AgentSkeletonRows() {
  return Array.from({ length: 4 }, (_, index) => (
    <tr key={index} className="agent-skeleton-row">
      <td><span /></td>
      <td><span /></td>
      <td><span /></td>
      <td><span /></td>
      <td><span /></td>
      <td><span /></td>
      <td><span /></td>
      <td><span /></td>
    </tr>
  ));
}

export function AgentsPanel({
  agents = [],
  overview = null,
  alertsSummary = null,
  riskSummary = null,
  agentTelemetry = [],
  agentHealthHistory = [],
  agentAlertsHistory = [],
  agentRiskHistory = [],
  selectedAgentId = "",
  historyRange = "24h",
  isLoading = false,
  error = "",
  onRefresh,
  onSelectAgent,
  onExportFleetSummary,
}) {
  const [statusFilter, setStatusFilter] = useState("all");
  const [focusFilter, setFocusFilter] = useState("all");
  const [osFilter, setOsFilter] = useState("all");
  const [sortBy, setSortBy] = useState("risk");
  const selectedAgent =
    agents.find((agent) => agent.agent_id === selectedAgentId) || agents[0] || null;
  const osOptions = useMemo(
    () => Array.from(new Set(agents.map((agent) => agent.os || agent.platform).filter(Boolean))).sort(),
    [agents]
  );
  const filteredAgents = useMemo(() => {
    const rows = agents.filter((agent) => {
      if (statusFilter !== "all" && agent.status !== statusFilter) return false;
      if (osFilter !== "all" && (agent.os || agent.platform) !== osFilter) return false;
      if (focusFilter === "high-risk" && !["high", "critical"].includes(risk(agent).severity)) return false;
      if (focusFilter === "critical-alerts" && criticalTotal(agent) <= 0) return false;
      if (focusFilter === "capture-running" && !captureRunning(agent)) return false;
      return true;
    });
    return [...rows].sort((left, right) => {
      if (sortBy === "last_seen") {
        return Date.parse(right.last_seen || 0) - Date.parse(left.last_seen || 0);
      }
      if (sortBy === "alerts") {
        return alertTotal(right) - alertTotal(left);
      }
      return Number(risk(right).score || 0) - Number(risk(left).score || 0);
    });
  }, [agents, focusFilter, osFilter, sortBy, statusFilter]);
  const hasAgents = agents.length > 0;

  return (
    <div className="agents-panel">
      {error ? (
        <div className="agent-state agent-state-error">
          <div>
            <p className="eyebrow">Agent API</p>
            <strong>Fleet data could not be loaded.</strong>
            <p className="muted">
              {error} Confirm the central backend is running and retry.
            </p>
          </div>
          <button type="button" className="secondary" onClick={onRefresh}>
            Retry
          </button>
        </div>
      ) : null}

      {overview?.demo_data ? (
        <div className="agent-demo-banner">
          <strong>Demo data</strong>
          <span>Not live production telemetry.</span>
        </div>
      ) : null}

      <div className="agent-overview-grid">
        <MetricCard
          label="Fleet"
          value={overview?.total_agents ?? agents.length}
          hint={`${overview?.online_agents ?? 0} online / ${overview?.offline_agents ?? 0} offline`}
          tone="calm"
        />
        <MetricCard
          label="High Risk"
          value={overview?.high_risk_agents ?? 0}
          hint="High or critical servers"
          tone="warning"
        />
        <MetricCard
          label="Alerts"
          value={alertsSummary?.total_alerts ?? overview?.total_alerts ?? 0}
          hint={`${alertsSummary?.critical_count ?? overview?.critical_alerts ?? 0} critical`}
          tone="active"
        />
        <MetricCard
          label="Risk Mix"
          value={`${riskSummary?.buckets?.critical ?? 0} critical`}
          hint={`${riskSummary?.buckets?.high ?? 0} high / ${riskSummary?.buckets?.medium ?? 0} medium`}
          tone="neutral"
        />
        <MetricCard
          label="Avg Health"
          value={`${formatPercent(overview?.average_cpu_percent)} CPU`}
          hint={`${formatPercent(overview?.average_memory_percent)} RAM / ${formatPercent(overview?.average_disk_percent)} disk`}
          tone="calm"
        />
      </div>

      <div className="agent-command-bar">
        <div>
          <p className="eyebrow">Agent Fleet</p>
          <strong>{filteredAgents.length} visible host{filteredAgents.length === 1 ? "" : "s"}</strong>
        </div>
        <div className="agent-filter-row">
          {["all", "online", "offline"].map((item) => (
            <button
              key={item}
              type="button"
              className={statusFilter === item ? "primary agent-chip" : "secondary agent-chip"}
              onClick={() => setStatusFilter(item)}
            >
              {item === "all" ? "All" : item}
            </button>
          ))}
          {[
            ["all", "Any"],
            ["high-risk", "High risk"],
            ["critical-alerts", "Critical alerts"],
            ["capture-running", "Capturing"],
          ].map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={focusFilter === value ? "primary agent-chip" : "secondary agent-chip"}
              onClick={() => setFocusFilter(value)}
            >
              {label}
            </button>
          ))}
          <select value={osFilter} onChange={(event) => setOsFilter(event.target.value)}>
            <option value="all">All OS</option>
            {osOptions.map((os) => (
              <option key={os} value={os}>{os}</option>
            ))}
          </select>
          <select value={sortBy} onChange={(event) => setSortBy(event.target.value)}>
            <option value="risk">Sort risk</option>
            <option value="last_seen">Sort last seen</option>
            <option value="alerts">Sort alerts</option>
          </select>
        </div>
        <div className="agent-command-actions">
          <button type="button" className="secondary" disabled={isLoading} onClick={onRefresh}>Refresh fleet</button>
          <button type="button" className="primary" disabled={isLoading || !hasAgents} onClick={onExportFleetSummary}>Export summary</button>
        </div>
      </div>

      {!hasAgents && !isLoading ? (
        <div className="agent-empty-state">
          <p className="eyebrow">No Agents Registered</p>
          <h3>Agent Mode is ready for read-only server monitoring.</h3>
          <p className="muted">
            Start a real agent with scripts/dev/start-agent.ps1, or seed a demo fleet with scripts/dev/seed-agent-demo.ps1 -Reset -Count 4.
          </p>
          <div className="agent-empty-actions">
            <button type="button" className="primary" onClick={onRefresh}>
              Refresh
            </button>
          </div>
        </div>
      ) : null}

      <div className={`table-wrap ${!hasAgents && !isLoading ? "agent-hidden-table" : ""}`}>
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Status</th>
              <th>OS</th>
              <th>Health</th>
              <th>Capture</th>
              <th>Alerts Today</th>
              <th>Risk</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && !filteredAgents.length ? <AgentSkeletonRows /> : null}
            {filteredAgents.map((agent) => (
              <tr key={agent.agent_id} className={agent.agent_id === selectedAgentId ? "selected-row" : ""}>
                <td>
                  <button type="button" className="table-link" onClick={() => onSelectAgent(agent.agent_id, historyRange)}>
                    {agent.display_name || agent.hostname || agent.agent_id}
                  </button>
                  <div className="table-subline">{agent.agent_id}</div>
                </td>
                <td>
                  <span className={`agent-status agent-status-${agent.status === "online" ? "online" : "offline"}`}>
                    {agent.status || "unknown"}
                  </span>
                </td>
                <td>{agent.os || agent.platform || "-"}</td>
                <td>
                  <HealthBars agent={agent} />
                </td>
                <td>
                  <span className={captureRunning(agent) ? "agent-capture-on" : "agent-capture-off"}>
                    {captureRunning(agent) ? "running" : "stopped"}
                  </span>
                  <div className="table-subline">{captureMode(agent)}</div>
                </td>
                <td>{alertTotal(agent)} / {criticalTotal(agent)} critical</td>
                <td>
                  <RiskBadge value={risk(agent)} />
                </td>
                <td>{formatDate(agent.last_seen)}</td>
              </tr>
            ))}
            {!filteredAgents.length ? (
              <tr>
                <td colSpan="8" className="table-empty">
                  {isLoading ? "Loading agents..." : "No agents match the current filters."}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {selectedAgent ? (
        <div className="agents-detail-grid">
          <div className="mini-panel agent-detail-hero">
            <div className="agent-detail-title">
              <div>
                <p className="eyebrow">Agent Details</p>
                <h3>{selectedAgent.display_name || selectedAgent.hostname || selectedAgent.agent_id}</h3>
              </div>
              <RiskBadge value={risk(selectedAgent)} />
            </div>
            <div className="agent-detail-metrics">
              <MetricCard label="CPU" value={formatPercent(healthValue(selectedAgent, "cpu_percent"))} hint="Latest sample" />
              <MetricCard label="RAM" value={formatPercent(healthValue(selectedAgent, "memory_percent"))} hint="Latest sample" />
              <MetricCard label="Disk" value={formatPercent(healthValue(selectedAgent, "disk_percent"))} hint="Latest sample" />
            </div>
            <dl className="detail-grid">
              <dt>Hostname</dt>
              <dd>{selectedAgent.hostname || "-"}</dd>
              <dt>Status</dt>
              <dd>{selectedAgent.status || "-"}</dd>
              <dt>Last Heartbeat</dt>
              <dd>{formatDate(selectedAgent.last_seen)}</dd>
              <dt>Last Telemetry</dt>
              <dd>{formatDate(selectedAgent.last_telemetry_at)}</dd>
              <dt>Network</dt>
              <dd>{latestTelemetry(selectedAgent)?.network?.interface_count ?? 0} interfaces</dd>
              <dt>Capture</dt>
              <dd>{captureMode(selectedAgent)} / {captureRunning(selectedAgent) ? "running" : "stopped"}</dd>
            </dl>
          </div>
          <div className="mini-panel">
            <div className="panel-toolbar">
              <div>
                <p className="eyebrow">History</p>
                <strong>{historyRange}</strong>
              </div>
              <div className="agent-filter-row">
                <button type="button" className="secondary" onClick={() => onSelectAgent(selectedAgent.agent_id, "1h")}>
                  1h
                </button>
                <button type="button" className="secondary" onClick={() => onSelectAgent(selectedAgent.agent_id, "24h")}>
                  24h
                </button>
                <button type="button" className="secondary" onClick={() => onSelectAgent(selectedAgent.agent_id, "7d")}>
                  7d
                </button>
                <button type="button" className="secondary" onClick={() => onSelectAgent(selectedAgent.agent_id, "30d")}>
                  30d
                </button>
              </div>
            </div>
            <p className="muted">Health</p>
            <TrendList items={agentHealthHistory} value={(item) => percentValue(item.cpu_percent)} />
            <p className="muted">Alerts</p>
            <TrendList items={agentAlertsHistory} value={(item) => Number(item.total_alerts || 0) * 8} />
            <p className="muted">Risk</p>
            <TrendList items={agentRiskHistory} value={(item) => Number(item.score ?? 0)} />
          </div>
          <div className="mini-panel">
            <p className="eyebrow">Recent Alerts</p>
            <pre className="agent-json-preview">
              {JSON.stringify(alerts(selectedAgent).recent_alerts || [], null, 2)}
            </pre>
          </div>
          <div className="mini-panel">
            <p className="eyebrow">Flow Summary</p>
            <pre className="agent-json-preview">
              {JSON.stringify(latestTelemetry(selectedAgent)?.flows_summary || {}, null, 2)}
            </pre>
          </div>
        </div>
      ) : null}
    </div>
  );
}
