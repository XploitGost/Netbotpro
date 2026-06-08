import { useEffect, useMemo, useState } from "react";

export function DeepPacketPanel({ api, packetId }) {
  const [details, setDetails] = useState(null);
  const [stream, setStream] = useState(null);
  const [error, setError] = useState("");
  const [fieldSearch, setFieldSearch] = useState("");
  const [activeTab, setActiveTab] = useState("tree");

  useEffect(() => {
    let active = true;
    setDetails(null);
    setStream(null);
    setError("");
    if (!packetId) return () => { active = false; };
    api.getPacketDissection(packetId)
      .then(async (result) => {
        if (!active) return;
        setDetails(result);
        if (result.related_flow_id) {
          const nextStream = await api.getFlowStream(result.related_flow_id).catch(() => null);
          if (active) setStream(nextStream);
        }
      })
      .catch((reason) => active && setError(String(reason).replace(/^Error:\s*/, "")));
    return () => { active = false; };
  }, [api.apiBase, packetId]);

  const visibleLayers = useMemo(() => {
    const term = fieldSearch.trim().toLowerCase();
    if (!term) return details?.layers || [];
    return (details?.layers || []).map((layer) => ({
      ...layer,
      fields: layer.fields.filter((field) =>
        `${field.label} ${field.key} ${field.display_value}`.toLowerCase().includes(term)
      ),
    })).filter((layer) => layer.fields.length || layer.name.toLowerCase().includes(term));
  }, [details, fieldSearch]);

  if (!packetId) return <div className="empty-state"><h3>Select a packet for deep inspection</h3><p className="muted">Layer details, redacted bytes, stream context, and expert warnings appear here.</p></div>;
  if (error) return <p className="form-error">{error}</p>;
  if (!details) return <p className="muted">Loading deep packet inspection...</p>;

  return (
    <div className="dpi-panel">
      <div className="dpi-header">
        <div>
          <p className="eyebrow">Protocol Stack</p>
          <h3>{details.protocol_stack.join(" / ")}</h3>
          <p className="muted">{details.summary || "Metadata-safe packet dissection"}</p>
        </div>
        <span className="side-pill side-flow">{details.direction}</span>
      </div>
      <div className="inspection-tab-row" role="tablist" aria-label="Deep packet views">
        {["tree", "hex", "stream", "expert"].map((tab) => (
          <button key={tab} type="button" role="tab" className={`payload-tab ${activeTab === tab ? "payload-tab-active" : ""}`} onClick={() => setActiveTab(tab)}>
            {tab === "tree" ? "Packet Tree" : tab === "hex" ? "Hex / Bytes" : tab === "stream" ? "Follow Stream" : "Expert Info"}
          </button>
        ))}
      </div>
      {activeTab === "tree" ? (
        <>
          <input className="dpi-search" aria-label="Search packet fields" placeholder="Search fields" value={fieldSearch} onChange={(event) => setFieldSearch(event.target.value)} />
          <div className="dpi-layer-list">
            {visibleLayers.map((layer) => (
              <details key={layer.name} className="dpi-layer" open>
                <summary><strong>{layer.name}</strong><span>{layer.summary}</span></summary>
                <div className="dpi-fields">
                  {layer.fields.map((field) => (
                    <div key={field.key} className={`dpi-field dpi-field-${field.severity}`}>
                      <span>{field.label}</span><code>{field.display_value}</code>
                      {field.byte_range?.length ? <small>bytes {field.byte_range.join("-")}</small> : null}
                    </div>
                  ))}
                </div>
              </details>
            ))}
          </div>
        </>
      ) : null}
      {activeTab === "hex" ? (
        <div className="dpi-hex">
          <p className="notice-banner">{details.hex.warning}</p>
          {details.hex.rows.length ? details.hex.rows.map((row) => (
            <div key={row.offset} className="dpi-hex-row"><code>{row.offset}</code><code>{row.hex}</code><code>{row.ascii_redacted}</code></div>
          )) : <div className="empty-state"><h3>Headers-only mode</h3><p className="muted">Raw payload bytes are not exposed in metadata mode.</p></div>}
        </div>
      ) : null}
      {activeTab === "stream" ? (
        <div className="dpi-stream">
          <p className="notice-banner">{stream?.warnings?.[0] || "Stream metadata is unavailable for this packet."}</p>
          {(stream?.chunks || []).map((chunk) => (
            <article key={`${chunk.packet_id}-${chunk.timestamp}`} className={`dpi-chunk dpi-chunk-${chunk.direction}`}>
              <strong>{chunk.direction.replaceAll("_", " ")}</strong>
              <span>{chunk.length} bytes</span>
              <code>{chunk.preview_redacted || "Metadata-only chunk"}</code>
            </article>
          ))}
        </div>
      ) : null}
      {activeTab === "expert" ? (
        <div className="inspection-activity-list">
          {details.expert_items.length ? details.expert_items.map((item, index) => (
            <article key={`${item.category}-${index}`} className="inspection-activity-item">
              <span className={`risk-badge risk-${item.severity === "error" ? "critical" : item.severity === "warn" ? "high" : "low"}`}>{item.severity}</span>
              <strong>{item.message}</strong>
              <p className="muted">{item.category}</p>
            </article>
          )) : <div className="empty-state"><h3>No expert warnings</h3><p className="muted">No packet-level anomalies were identified.</p></div>}
        </div>
      ) : null}
    </div>
  );
}
