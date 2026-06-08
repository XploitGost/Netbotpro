import { useEffect, useMemo, useState } from "react";

function Metric({ label, value, hint }) {
  return (
    <div className="protocol-metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{hint}</small>
    </div>
  );
}

export function ProtocolIntelligencePanel({ api }) {
  const [intelligence, setIntelligence] = useState(null);
  const [suggestions, setSuggestions] = useState({ fields: [], examples: [] });
  const [savedFilters, setSavedFilters] = useState([]);
  const [query, setQuery] = useState("");
  const [searchResult, setSearchResult] = useState(null);
  const [error, setError] = useState("");

  const load = () => Promise.all([
    api.getProtocolIntelligence(),
    api.getPacketFilterSuggestions(),
    api.getSavedFilters(),
  ]).then(([nextIntelligence, nextSuggestions, nextFilters]) => {
    setIntelligence(nextIntelligence);
    setSuggestions(nextSuggestions);
    setSavedFilters(nextFilters);
    setError("");
  }).catch((reason) => setError(String(reason).replace(/^Error:\s*/, "")));

  useEffect(() => { load(); }, [api.apiBase]);

  const protocols = intelligence?.protocols?.protocols || [];
  const warningCount = useMemo(
    () => (intelligence?.tcp?.expert_hints?.length || 0)
      + (intelligence?.dns?.suspicious?.length || 0)
      + (intelligence?.http?.suspicious?.length || 0)
      + (intelligence?.tls?.warnings?.length || 0),
    [intelligence]
  );

  async function runSearch(event) {
    event.preventDefault();
    try {
      setSearchResult(await api.searchPackets(query));
      setError("");
    } catch (reason) {
      setError(String(reason).replace(/^Error:\s*/, ""));
    }
  }

  async function saveFilter(expression) {
    try {
      await api.createSavedFilter({ name: `Saved ${savedFilters.filter((item) => !item.is_builtin).length + 1}`, expression });
      await load();
    } catch (reason) {
      setError(String(reason).replace(/^Error:\s*/, ""));
    }
  }

  return (
    <div className="protocol-workspace">
      <div className="protocol-toolbar">
        <form className="protocol-search" onSubmit={runSearch}>
          <input aria-label="Packet search" placeholder="Search safe packet metadata" value={query} onChange={(event) => setQuery(event.target.value)} />
          <button className="primary" type="submit">Search</button>
        </form>
        <button className="secondary" type="button" onClick={load}>Refresh intelligence</button>
      </div>
      {error ? <p className="form-error">{error}</p> : null}
      <div className="protocol-metric-grid">
        <Metric label="Protocols" value={protocols.length} hint="Detected in current flow window" />
        <Metric label="TCP packets" value={intelligence?.tcp?.total_packets || 0} hint={intelligence?.tcp?.handshake_incomplete ? "Incomplete handshake observed" : "Handshake state tracked"} />
        <Metric label="DNS queries" value={intelligence?.dns?.query_count || 0} hint={`${Math.round((intelligence?.dns?.nxdomain_rate || 0) * 100)}% NXDOMAIN`} />
        <Metric label="Expert hints" value={warningCount} hint="Metadata-safe analysis hints" />
      </div>
      <div className="protocol-layout">
        <section className="protocol-section">
          <div className="protocol-section-head"><h3>Protocol statistics</h3><span>{intelligence?.protocols?.total_packets || 0} packets</span></div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Protocol</th><th>Packets</th><th>Flows</th><th>Bytes</th><th>Risk</th></tr></thead>
              <tbody>
                {protocols.length ? protocols.map((item) => (
                  <tr key={item.protocol}><td><span className="protocol-pill">{item.protocol}</span></td><td>{item.packet_count}</td><td>{item.flow_count}</td><td>{item.bytes_total}</td><td>{item.risk_avg}</td></tr>
                )) : <tr><td colSpan="5" className="table-empty">No protocol statistics yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
        <section className="protocol-section">
          <div className="protocol-section-head"><h3>Display filters</h3><span>{savedFilters.length} available</span></div>
          <div className="filter-chip-list">
            {savedFilters.map((item) => (
              <button key={item.id} type="button" className="filter-chip" title={item.expression} onClick={() => setQuery(item.expression)}>{item.name}</button>
            ))}
          </div>
          <label className="protocol-field-label" htmlFor="safe-filter-expression">Build from suggestions</label>
          <div className="protocol-filter-builder">
            <input id="safe-filter-expression" list="display-filter-fields" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="protocol == TLS" />
            <datalist id="display-filter-fields">{suggestions.fields.map((field) => <option key={field} value={field} />)}</datalist>
            <button type="button" className="secondary" disabled={!query.trim()} onClick={() => saveFilter(query)}>Save filter</button>
          </div>
          <div className="filter-example-list">
            {(suggestions.examples || []).slice(0, 5).map((example) => <code key={example}>{example}</code>)}
          </div>
        </section>
      </div>
      <div className="protocol-layout">
        <section className="protocol-section">
          <div className="protocol-section-head"><h3>DNS / HTTP intelligence</h3><span>Redacted metadata</span></div>
          <dl className="protocol-summary-list">
            <div><dt>Unique domains</dt><dd>{intelligence?.dns?.unique_domains || 0}</dd></div>
            <div><dt>DNS suspicious hints</dt><dd>{intelligence?.dns?.suspicious?.length || 0}</dd></div>
            <div><dt>HTTP requests</dt><dd>{intelligence?.http?.request_count || 0}</dd></div>
            <div><dt>External cleartext HTTP</dt><dd>{intelligence?.http?.external_cleartext_http_count || 0}</dd></div>
          </dl>
        </section>
        <section className="protocol-section">
          <div className="protocol-section-head"><h3>TLS / TCP intelligence</h3><span>No decryption</span></div>
          <dl className="protocol-summary-list">
            <div><dt>TLS metadata packets</dt><dd>{intelligence?.tls?.packet_count || 0}</dd></div>
            <div><dt>Deprecated TLS</dt><dd>{intelligence?.tls?.deprecated_tls_count || 0}</dd></div>
            <div><dt>TCP resets</dt><dd>{intelligence?.tcp?.resets || 0}</dd></div>
            <div><dt>Retransmission hints</dt><dd>{intelligence?.tcp?.retransmission_hints || 0}</dd></div>
          </dl>
        </section>
      </div>
      {searchResult ? (
        <section className="protocol-section">
          <div className="protocol-section-head"><h3>Packet search results</h3><span>{searchResult.total} matches</span></div>
          <div className="packet-search-results">
            {searchResult.items.length ? searchResult.items.map((item, index) => <code key={`${item.id || "result"}-${index}`}>{JSON.stringify(item)}</code>) : <p className="muted">No safe metadata matched this query.</p>}
          </div>
        </section>
      ) : null}
    </div>
  );
}
