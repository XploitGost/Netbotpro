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
  return agent?.last_telemetry && typeof agent.last_telemetry === "object" ? agent.last_telemetry : {};
}

function healthValue(agent, key) {
  return latestTelemetry(agent)?.health?.[key];
}

function captureLabel(agent) {
  const capture = latestTelemetry(agent)?.capture || {};
  if (!Object.keys(capture).length) return "No capture summary";
  const running = capture.running || capture.capture_running ? "running" : "stopped";
  return `${capture.mode || capture.capture_mode || "metadata"} / ${running}`;
}

function alertLabel(agent) {
  const alerts = latestTelemetry(agent)?.alerts_summary || {};
  const total = Number(alerts.total || alerts.count || alerts.total_alerts || 0);
  const high = Number(alerts.high || alerts.critical || alerts.high_count || alerts.critical_count || 0);
  return high > 0 ? `${total} alerts / ${high} high` : `${total} alerts`;
}

export function AgentsPanel({
  agents = [],
  agentTelemetry = [],
  selectedAgentId = "",
  isLoading = false,
  onRefresh,
  onSelectAgent,
}) {
  const selectedAgent = agents.find((agent) => agent.agent_id === selectedAgentId) || agents[0] || null;

  return (
    <div className="agents-panel">
      <div className="panel-toolbar">
        <div>
          <p className="eyebrow">Agent Fleet</p>
          <strong>{agents.length} registered host{agents.length === 1 ? "" : "s"}</strong>
        </div>
        <button type="button" className="secondary" disabled={isLoading} onClick={onRefresh}>
          Refresh
        </button>
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
              <th>Alerts</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.agent_id} className={agent.agent_id === selectedAgentId ? "selected-row" : ""}>
                <td>
                  <button type="button" className="table-link" onClick={() => onSelectAgent(agent.agent_id)}>
                    {agent.display_name || agent.hostname || agent.agent_id}
                  </button>
                  <div className="table-subline">{agent.agent_id}</div>
                </td>
                <td>
                  <span className={`agent-status agent-status-${agent.status === "online" ? "online" : "offline"}`}>
                    {agent.status || "unknown"}
                  </span>
                </td>
                <td>
                  {agent.os || agent.platform || "-"}
                  <div className="table-subline">{agent.agent_version || ""}</div>
                </td>
                <td>
                  CPU {formatPercent(healthValue(agent, "cpu_percent"))}
                  <div className="table-subline">
                    RAM {formatPercent(healthValue(agent, "memory_percent"))} / Disk {formatPercent(healthValue(agent, "disk_percent"))}
                  </div>
                </td>
                <td>{captureLabel(agent)}</td>
                <td>{alertLabel(agent)}</td>
                <td>{formatDate(agent.last_seen)}</td>
              </tr>
            ))}
            {!agents.length ? (
              <tr>
                <td colSpan="7" className="table-empty">
                  No agents registered yet.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {selectedAgent ? (
        <div className="agents-detail-grid">
          <div className="mini-panel">
            <p className="eyebrow">Selected Host</p>
            <h3>{selectedAgent.display_name || selectedAgent.hostname || selectedAgent.agent_id}</h3>
            <dl className="detail-grid">
              <dt>Hostname</dt>
              <dd>{selectedAgent.hostname || "-"}</dd>
              <dt>Platform</dt>
              <dd>{selectedAgent.platform || selectedAgent.os || "-"}</dd>
              <dt>Machine</dt>
              <dd>{selectedAgent.machine || "-"}</dd>
              <dt>Last Telemetry</dt>
              <dd>{formatDate(selectedAgent.last_telemetry_at)}</dd>
            </dl>
          </div>
          <div className="mini-panel">
            <p className="eyebrow">Recent Telemetry</p>
            <div className="agent-telemetry-list">
              {agentTelemetry.slice(-5).reverse().map((item) => (
                <div key={item.received_at || JSON.stringify(item)} className="agent-telemetry-item">
                  <strong>{formatDate(item.received_at)}</strong>
                  <span>
                    CPU {formatPercent(item.health?.cpu_percent)} / RAM {formatPercent(item.health?.memory_percent)}
                  </span>
                </div>
              ))}
              {!agentTelemetry.length ? <p className="muted">No telemetry history loaded.</p> : null}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
