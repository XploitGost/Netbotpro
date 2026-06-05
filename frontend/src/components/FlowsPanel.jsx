import { useEffect, useMemo, useState } from "react";

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function RiskBadge({ flow }) {
  return (
    <span className={`flow-risk flow-risk-${flow.risk_level || "low"}`}>
      {flow.risk_score || 0} {flow.risk_level || "low"}
    </span>
  );
}

function SummaryCard({ label, value, hint }) {
  return (
    <div className="flow-summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{hint}</small>
    </div>
  );
}

export function FlowsPanel({ api }) {
  const [flows, setFlows] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selectedId, setSelectedId] = useState("");
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [query, setQuery] = useState({
    protocol: "",
    risk: "",
    direction: "",
    src_ip: "",
    dst_ip: "",
    port: "",
    has_alerts: false,
    sort: "risk",
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function loadFlows(nextQuery = query) {
    if (!api) return;
    setLoading(true);
    setError("");
    try {
      const [flowData, summaryData] = await Promise.all([
        api.getFlows(nextQuery),
        api.getFlowsSummary(),
      ]);
      const items = flowData.items || [];
      setFlows(items);
      setSummary(summaryData);
      if (!selectedId && items[0]?.flow_id) {
        await selectFlow(items[0].flow_id);
      }
    } catch (err) {
      setError(err?.message || "Unable to load flows");
    } finally {
      setLoading(false);
    }
  }

  async function selectFlow(flowId) {
    if (!api || !flowId) return;
    setSelectedId(flowId);
    try {
      const [detail, events] = await Promise.all([
        api.getFlow(flowId),
        api.getFlowTimeline(flowId),
      ]);
      setSelectedFlow(detail);
      setTimeline(events.items || []);
    } catch (err) {
      setError(err?.message || "Unable to load flow details");
    }
  }

  useEffect(() => {
    loadFlows();
  }, [api]);

  const topProtocol = useMemo(
    () => summary?.top_protocols?.[0]?.protocol || "-",
    [summary]
  );

  return (
    <div className="flows-workspace">
      <div className="flow-summary-grid">
        <SummaryCard label="Total flows" value={summary?.total_flows || 0} hint="Directional network sessions" />
        <SummaryCard label="External" value={summary?.external_flows || 0} hint="Inbound and outbound flows" />
        <SummaryCard label="Top protocol" value={topProtocol} hint="Metadata-safe protocol detection" />
        <SummaryCard label="High risk" value={summary?.risk_distribution?.high || 0} hint="Review with critical flows" />
      </div>

      <div className="flow-toolbar">
        <select aria-label="Protocol filter" value={query.protocol} onChange={(event) => setQuery({ ...query, protocol: event.target.value })}>
          <option value="">All protocols</option>
          {["DNS", "HTTP", "TLS", "SSH", "RDP", "SMB", "SMTP", "IMAP", "POP3", "ICMP", "UNKNOWN"].map((item) => <option key={item}>{item}</option>)}
        </select>
        <select aria-label="Risk filter" value={query.risk} onChange={(event) => setQuery({ ...query, risk: event.target.value })}>
          <option value="">All risks</option>
          {["low", "medium", "high", "critical"].map((item) => <option key={item}>{item}</option>)}
        </select>
        <select aria-label="Direction filter" value={query.direction} onChange={(event) => setQuery({ ...query, direction: event.target.value })}>
          <option value="">All directions</option>
          {["inbound", "outbound", "internal", "local"].map((item) => <option key={item}>{item}</option>)}
        </select>
        <input aria-label="Source IP filter" placeholder="Source IP" value={query.src_ip} onChange={(event) => setQuery({ ...query, src_ip: event.target.value })} />
        <input aria-label="Destination IP filter" placeholder="Destination IP" value={query.dst_ip} onChange={(event) => setQuery({ ...query, dst_ip: event.target.value })} />
        <select aria-label="Sort flows" value={query.sort} onChange={(event) => setQuery({ ...query, sort: event.target.value })}>
          <option value="risk">Sort by risk</option>
          <option value="last_seen">Sort by last seen</option>
          <option value="bytes">Sort by bytes</option>
          <option value="packets">Sort by packets</option>
          <option value="alerts">Sort by alerts</option>
        </select>
        <label className="flow-alert-toggle">
          <input type="checkbox" checked={query.has_alerts} onChange={(event) => setQuery({ ...query, has_alerts: event.target.checked })} />
          Has alerts
        </label>
        <button type="button" className="primary" disabled={loading} onClick={() => loadFlows(query)}>
          {loading ? "Loading..." : "Apply"}
        </button>
      </div>

      {error ? <p className="error">{error}</p> : null}
      {!loading && !flows.length ? (
        <div className="empty-state">
          <h3>No flows observed</h3>
          <p className="muted">Start capture or analyze a PCAP to build protocol-aware conversations.</p>
        </div>
      ) : null}

      <div className="flows-layout">
        <div className="table-scroll">
          <table className="flow-table">
            <thead><tr><th>Protocol</th><th>Source to destination</th><th>Direction</th><th>Packets</th><th>Bytes</th><th>Risk</th><th>Alerts</th></tr></thead>
            <tbody>
              {flows.map((flow) => (
                <tr key={flow.flow_id} className={selectedId === flow.flow_id ? "flow-row-selected" : ""} onClick={() => selectFlow(flow.flow_id)}>
                  <td><strong>{flow.app_protocol}</strong><small>{flow.transport}</small></td>
                  <td><strong>{flow.src_ip}:{flow.src_port || "-"}</strong><small>to {flow.dst_ip}:{flow.dst_port || "-"}</small></td>
                  <td>{flow.direction}</td>
                  <td>{flow.packets_count}</td>
                  <td>{formatBytes(flow.bytes_total)}</td>
                  <td><RiskBadge flow={flow} /></td>
                  <td>{flow.related_alert_ids?.length || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <aside className="flow-detail">
          <div>
            <p className="eyebrow">Flow details</p>
            <h3>{selectedFlow ? `${selectedFlow.app_protocol} conversation` : "Select a flow"}</h3>
          </div>
          {selectedFlow ? (
            <>
              <div className="flow-detail-metrics">
                <span><small>Duration</small><strong>{selectedFlow.duration_ms} ms</strong></span>
                <span><small>Process</small><strong>{selectedFlow.process_name || "Not mapped"}</strong></span>
                <span><small>Sent / received</small><strong>{formatBytes(selectedFlow.bytes_sent)} / {formatBytes(selectedFlow.bytes_received)}</strong></span>
              </div>
              <section>
                <h4>Risk reasons</h4>
                <ul>{selectedFlow.risk_reasons?.map((reason) => <li key={reason}>{reason}</li>)}</ul>
              </section>
              <section>
                <h4>Protocol metadata</h4>
                <dl className="flow-metadata">
                  {Object.entries(selectedFlow.metadata || {}).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{Array.isArray(value) ? value.join(", ") : String(value)}</dd></div>)}
                </dl>
              </section>
              <section>
                <h4>Conversation timeline</h4>
                <div className="flow-timeline">
                  {timeline.map((event, index) => <article key={`${event.timestamp}-${index}`}><span className={`flow-event-dot flow-event-${event.severity || "info"}`} /><div><strong>{event.summary}</strong><small>{event.event_type} · {event.timestamp}</small></div></article>)}
                </div>
              </section>
            </>
          ) : null}
        </aside>
      </div>
    </div>
  );
}
