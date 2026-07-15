import { useEffect, useState } from "react";

function safeText(value) {
  return String(value || "")
    .replace(/\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[REDACTED]")
    .replace(/\b(password|token|api_key|secret|session)\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]");
}

function TextList({ title, items = [] }) {
  return (
    <section>
      <h4>{title}</h4>
      {items.length ? <ul>{items.map((item, index) => <li key={`${title}-${index}`}>{safeText(item)}</li>)}</ul> : <p className="muted">No evidence available.</p>}
    </section>
  );
}

export function IncidentsPanel({ api }) {
  const [items, setItems] = useState([]);
  const [selected, setSelected] = useState(null);
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function load(nextStatus = status, nextSeverity = severity) {
    if (!api) return;
    setLoading(true);
    setError("");
    try {
      const result = await api.getIncidents({ status: nextStatus, severity: nextSeverity, limit: 200 });
      const nextItems = result.items || [];
      setItems(nextItems);
      if (!selected && nextItems[0]) await selectIncident(nextItems[0].incident_id);
    } catch (err) {
      setError(err?.message || "Unable to load incidents");
    } finally {
      setLoading(false);
    }
  }

  async function selectIncident(id) {
    if (!api || !id) return;
    try {
      const result = await api.getIncident(id);
      setSelected(result.incident || null);
    } catch (err) {
      setError(err?.message || "Unable to load incident details");
    }
  }

  useEffect(() => { load(); }, [api]);

  return (
    <div className="incidents-workspace">
      <div className="incident-toolbar">
        <select aria-label="Incident status filter" value={status} onChange={(event) => setStatus(event.target.value)}>
          <option value="open">Open</option><option value="all">All statuses</option><option value="resolved">Resolved</option><option value="suppressed">Suppressed</option>
        </select>
        <select aria-label="Incident severity filter" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">All severities</option>{["low", "medium", "high", "critical"].map((value) => <option key={value}>{value}</option>)}
        </select>
        <button type="button" className="primary" disabled={loading} onClick={() => load()}>{loading ? "Loading..." : "Refresh incidents"}</button>
      </div>
      {error ? <p className="error">{safeText(error)}</p> : null}
      {!loading && !items.length ? <div className="empty-state"><h3>No correlated incidents</h3><p className="muted">The engine waits for multiple related signals before creating an incident.</p></div> : null}
      {items.length ? <div className="incidents-layout">
        <div className="incident-list" aria-label="Incident list">
          {items.map((incident) => (
            <button key={incident.incident_id} type="button" className={`incident-row ${selected?.incident_id === incident.incident_id ? "incident-row-selected" : ""}`} onClick={() => selectIncident(incident.incident_id)}>
              <span className={`severity-pill severity-${incident.severity}`}>{incident.severity}</span>
              <span><strong>{safeText(incident.title)}</strong><small>{safeText(incident.source_hosts?.join(", ") || "Unknown source")} | {safeText(incident.services?.join(", ") || "Unattributed service")}</small></span>
              <em>{incident.confidence} confidence</em>
            </button>
          ))}
        </div>
        <aside className="incident-detail">
          {!selected ? <p className="muted">Select an incident to review its evidence.</p> : <>
            <div className="incident-detail-head"><div><p className="eyebrow">{safeText(selected.type).replaceAll("_", " ")}</p><h3>{safeText(selected.title)}</h3></div><span className={`severity-pill severity-${selected.severity}`}>{selected.severity}</span></div>
            <dl className="flow-metadata">
              <div><dt>Status</dt><dd>{safeText(selected.status)}</dd></div><div><dt>Confidence</dt><dd>{safeText(selected.confidence)}</dd></div>
              <div><dt>Signals</dt><dd>{selected.signal_count || 0}</dd></div><div><dt>Last seen</dt><dd>{safeText(selected.last_seen)}</dd></div>
              <div><dt>Applications</dt><dd>{safeText(selected.applications?.join(", ") || "Unknown")}</dd></div><div><dt>Domains</dt><dd>{safeText(selected.domains?.join(", ") || "Unavailable")}</dd></div>
            </dl>
            <TextList title="Evidence" items={selected.evidence} />
            <TextList title="Correlation reasons" items={selected.correlation_reasons} />
            <TextList title="Recommended investigation" items={selected.recommended_investigation_steps} />
            <TextList title="False-positive notes" items={selected.false_positive_notes} />
            <section><h4>Timeline</h4><div className="flow-timeline">{(selected.timeline || []).map((event, index) => <article key={`${event.timestamp}-${index}`}><span className={`flow-event-dot flow-event-${event.severity || "info"}`} /><div><strong>{safeText(event.summary)}</strong><small>{safeText(event.source)} | {safeText(event.timestamp)}</small></div></article>)}</div></section>
            <section className="incident-related"><span>{selected.related_flows?.length || 0} flows</span><span>{selected.related_alerts?.length || 0} alerts</span><span>{selected.related_agents?.length || 0} agents</span></section>
          </>}
        </aside>
      </div> : null}
    </div>
  );
}
