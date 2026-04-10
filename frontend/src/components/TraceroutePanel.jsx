export function TraceroutePanel({ tracerouteResult, tracerouteTarget, onTargetChange, onRunTraceroute }) {
  return (
    <div className="panel-body">
      <p className="eyebrow">Traceroute</p>
      <div className="stack">
        <input value={tracerouteTarget} onChange={(event) => onTargetChange(event.target.value)} placeholder="8.8.8.8 or example.com" />
        <button className="secondary" onClick={onRunTraceroute}>Run Traceroute</button>
        <div className="table-wrap compact-table">
          <table>
            <thead>
              <tr>
                <th>Hop</th>
                <th>IP</th>
                <th>RTT</th>
              </tr>
            </thead>
            <tbody>
              {(tracerouteResult?.hops || []).length === 0 ? (
                <tr><td colSpan="3" className="muted">No traceroute results yet</td></tr>
              ) : tracerouteResult.hops.map((hop, index) => (
                <tr key={`${hop.ip || "hop"}-${index}`}>
                  <td>{hop.hop ?? "-"}</td>
                  <td>{hop.ip || "-"}</td>
                  <td>{hop.rtt_ms ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
