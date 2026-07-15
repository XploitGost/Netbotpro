import { useEffect, useState } from "react";

function safeText(value) {
  return String(value || "")
    .replace(/\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+/gi, "[REDACTED_HEADER]")
    .replace(/\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[REDACTED]")
    .replace(/\b(password|token|api_key|secret|session)\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED_JWT]");
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
  const [markdown, setMarkdown] = useState("");
  const [exporting, setExporting] = useState(false);
  const [copyState, setCopyState] = useState("");

  async function load(nextStatus = status, nextSeverity = severity) {
    if (!api) return;
    setLoading(true);
    setError("");
    try {
      const result = await api.getIncidents({ status: nextStatus, severity: nextSeverity, limit: 200 });
      const nextItems = result.items || [];
      setItems(nextItems);
      if (!nextItems.length) {
        setSelected(null);
      } else if (!selected || !nextItems.some((item) => item.incident_id === selected.incident_id)) {
        await selectIncident(nextItems[0].incident_id);
      }
    } catch (err) {
      setError(err?.message || "Unable to load incidents");
    } finally {
      setLoading(false);
    }
  }

  async function selectIncident(id) {
    if (!api || !id) return;
    try {
      setMarkdown("");
      setCopyState("");
      const result = await api.getIncident(id);
      setSelected(result.incident || null);
    } catch (err) {
      setError(err?.message || "Unable to load incident details");
    }
  }

  async function generateSummary() {
    if (!api || !selected?.incident_id) return;
    setExporting(true);
    setCopyState("");
    try {
      const result = await api.getIncidentSummary(selected.incident_id);
      setMarkdown(safeText(result.markdown || ""));
    } catch (err) {
      setError(err?.message || "Unable to generate incident summary");
    } finally {
      setExporting(false);
    }
  }

  async function copySummary() {
    if (!markdown) return;
    try {
      await navigator.clipboard.writeText(markdown);
      setCopyState("Copied");
    } catch {
      setCopyState("Select the summary text and copy it manually.");
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
      {!loading && !items.length ? <div className="empty-state incident-empty-state"><p className="eyebrow">Incident queue clear</p><h3>No correlated incidents in this view</h3><p className="muted">NetBotPro creates an incident only after multiple related signals meet the correlation threshold. Adjust the filters or continue monitoring.</p></div> : null}
      {items.length ? <div className="incidents-layout">
        <div className="incident-list" aria-label="Incident list">
          {items.map((incident) => (
            <button key={incident.incident_id} type="button" className={`incident-row ${selected?.incident_id === incident.incident_id ? "incident-row-selected" : ""}`} onClick={() => selectIncident(incident.incident_id)}>
              <span className={`severity-pill incident-severity severity-${incident.severity}`} aria-label={`Severity ${incident.severity}`}>{incident.severity}</span>
              <span><strong>{safeText(incident.title)}</strong><small>{safeText(incident.source_hosts?.join(", ") || "Unknown source")} | {safeText(incident.services?.join(", ") || "Unattributed service")}</small></span>
              <em>{incident.confidence} confidence</em>
            </button>
          ))}
        </div>
        <aside className="incident-detail">
          {!selected ? <p className="muted">Select an incident to review its evidence.</p> : <>
            <div className="incident-detail-head"><div><p className="eyebrow">{safeText(selected.type).replaceAll("_", " ")}</p><h3>{safeText(selected.title)}</h3></div><span className={`severity-pill incident-severity severity-${selected.severity}`} aria-label={`Severity ${selected.severity}`}>{selected.severity}</span></div>
            <div className="incident-time-strip"><span><small>First seen</small><strong>{safeText(selected.first_seen)}</strong></span><span><small>Last seen</small><strong>{safeText(selected.last_seen)}</strong></span></div>
            <dl className="flow-metadata">
              <div><dt>Status</dt><dd>{safeText(selected.status)}</dd></div><div><dt>Confidence</dt><dd>{safeText(selected.confidence)}</dd></div>
              <div><dt>Signals</dt><dd>{selected.signal_count || 0}</dd></div><div><dt>Source hosts</dt><dd>{safeText(selected.source_hosts?.join(", ") || "Unknown")}</dd></div>
              <div><dt>Applications</dt><dd>{safeText(selected.applications?.join(", ") || "Unknown")}</dd></div><div><dt>Services / domains</dt><dd>{safeText([...(selected.services || []), ...(selected.domains || [])].join(", ") || "Unavailable")}</dd></div>
            </dl>
            <TextList title="Evidence" items={selected.evidence} />
            <TextList title="Correlation reasons" items={selected.correlation_reasons} />
            <TextList title="Recommended investigation" items={selected.recommended_investigation_steps} />
            <TextList title="False-positive notes" items={selected.false_positive_notes} />
            <section><h4>Timeline</h4><div className="flow-timeline">{(selected.timeline || []).map((event, index) => <article key={`${event.timestamp}-${index}`}><span className={`flow-event-dot flow-event-${event.severity || "info"}`} /><div><strong>{safeText(event.summary)}</strong><small>{safeText(event.source)} | {safeText(event.timestamp)}</small></div></article>)}</div></section>
            <section className="incident-related"><span>{selected.related_flows?.length || 0} flows</span><span>{selected.related_alerts?.length || 0} alerts</span><span>{selected.related_agents?.length || 0} agents</span></section>
            <section className="incident-export">
              <div className="incident-export-head"><div><h4>Incident summary</h4><p className="muted">Redacted Markdown for tickets, notes, or handoff.</p></div><div className="incident-export-actions"><button type="button" className="secondary" disabled={exporting} onClick={generateSummary}>{exporting ? "Generating..." : markdown ? "Refresh Markdown" : "Generate Markdown"}</button>{markdown ? <button type="button" className="primary" onClick={copySummary}>Copy Markdown</button> : null}</div></div>
              {markdown ? <textarea aria-label="Incident Markdown summary" readOnly rows="14" value={markdown} onFocus={(event) => event.target.select()} /> : null}
              {copyState ? <p className="incident-copy-state" role="status">{copyState}</p> : null}
            </section>
          </>}
        </aside>
      </div> : null}
    </div>
  );
}
