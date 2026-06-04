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

function TrendList({ items = [], value }) {
  const sample = items.slice(-12);
  return (
    <div className="agent-trend-row">
      {sample.map((item, index) => (
        <span key={`${item.received_at || index}-${index}`}>
          {value(item)}
        </span>
      ))}
      {!sample.length ? <p className="muted">No history yet.</p> : null}
    </div>
  );
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
  onRefresh,
  onSelectAgent,
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

  return (
    <div className="agents-panel">
      <div className="agent-overview-grid">
        <div className="ops-summary-card">
          <span>Total Agents</span>
          <strong>{overview?.total_agents ?? agents.length}</strong>
          <small>{overview?.online_agents ?? 0} online / {overview?.offline_agents ?? 0} offline</small>
        </div>
        <div className="ops-summary-card">
          <span>High Risk</span>
          <strong>{overview?.high_risk_agents ?? 0}</strong>
          <small>High or critical servers</small>
        </div>
        <div className="ops-summary-card">
          <span>Total Alerts</span>
          <strong>{alertsSummary?.total_alerts ?? overview?.total_alerts ?? 0}</strong>
          <small>{alertsSummary?.critical_count ?? overview?.critical_alerts ?? 0} critical</small>
        </div>
        <div className="ops-summary-card">
          <span>Risk Mix</span>
          <strong>{riskSummary?.buckets?.critical ?? 0} critical</strong>
          <small>{riskSummary?.buckets?.high ?? 0} high / {riskSummary?.buckets?.medium ?? 0} medium</small>
        </div>
      </div>

      <div className="panel-toolbar">
        <div>
          <p className="eyebrow">Agent Fleet</p>
          <strong>{filteredAgents.length} visible host{filteredAgents.length === 1 ? "" : "s"}</strong>
        </div>
        <div className="agent-filter-row">
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="all">All status</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
          </select>
          <select value={focusFilter} onChange={(event) => setFocusFilter(event.target.value)}>
            <option value="all">All agents</option>
            <option value="high-risk">High risk</option>
            <option value="critical-alerts">Critical alerts</option>
            <option value="capture-running">Capture running</option>
          </select>
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
          <button type="button" className="secondary" disabled={isLoading} onClick={onRefresh}>
            Refresh
          </button>
        </div>
      </div>

      <div className="table-wrap">
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
                  CPU {formatPercent(healthValue(agent, "cpu_percent"))}
                  <div className="table-subline">
                    RAM {formatPercent(healthValue(agent, "memory_percent"))} / Disk {formatPercent(healthValue(agent, "disk_percent"))}
                  </div>
                </td>
                <td>
                  {captureMode(agent)}
                  <div className="table-subline">{captureRunning(agent) ? "running" : "stopped"}</div>
                </td>
                <td>{alertTotal(agent)} / {criticalTotal(agent)} critical</td>
                <td>
                  <span className={`agent-risk agent-risk-${risk(agent).severity}`}>
                    {risk(agent).score ?? 0} {risk(agent).severity}
                  </span>
                </td>
                <td>{formatDate(agent.last_seen)}</td>
              </tr>
            ))}
            {!filteredAgents.length ? (
              <tr>
                <td colSpan="8" className="table-empty">No agents match the current filters.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {selectedAgent ? (
        <div className="agents-detail-grid">
          <div className="mini-panel">
            <p className="eyebrow">Agent Details</p>
            <h3>{selectedAgent.display_name || selectedAgent.hostname || selectedAgent.agent_id}</h3>
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
                <button type="button" className="secondary" onClick={() => onSelectAgent(selectedAgent.agent_id, "24h")}>
                  24h
                </button>
                <button type="button" className="secondary" onClick={() => onSelectAgent(selectedAgent.agent_id, "7d")}>
                  7d
                </button>
              </div>
            </div>
            <p className="muted">Health</p>
            <TrendList items={agentHealthHistory} value={(item) => `CPU ${formatPercent(item.cpu_percent)}`} />
            <p className="muted">Alerts</p>
            <TrendList items={agentAlertsHistory} value={(item) => `${item.total_alerts || 0}`} />
            <p className="muted">Risk</p>
            <TrendList items={agentRiskHistory} value={(item) => `${item.score ?? 0}`} />
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
