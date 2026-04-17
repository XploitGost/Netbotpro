import { MiniList } from "./MiniList";

function SummaryCard({ label, value, hint }) {
  return (
    <div className="graph-summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
      {hint ? <small>{hint}</small> : null}
    </div>
  );
}

function TimelineTable({ timeline }) {
  if (!timeline?.length) {
    return <p className="muted">No alert timeline yet</p>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Alerts</th>
          </tr>
        </thead>
        <tbody>
          {timeline.map((item) => (
            <tr key={item.time}>
              <td>{item.time}</td>
              <td>{item.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function OfflineAnalysisPanel({ offlineResult, isBusy = false, onFileChange, onRunAnalysis }) {
  const summary = offlineResult?.summary || {};
  const alerts = offlineResult?.alerts || [];
  const suspicious = Boolean(summary.suspicious);

  return (
    <div className="panel-body">
      <p className="eyebrow">Offline PCAP Analysis</p>
      <div className="stack">
        <input type="file" accept=".pcap,.pcapng" onChange={(event) => onFileChange(event.target.files?.[0] || null)} disabled={isBusy} />
        <button className="secondary" onClick={onRunAnalysis} disabled={isBusy}>Analyze PCAP</button>
        {isBusy ? <p className="table-status">Analyzing PCAP...</p> : null}

        {!offlineResult ? <p className="table-empty">{isBusy ? "Reading packets and building the offline summary..." : "No offline analysis yet."}</p> : null}

        {offlineResult ? (
          <>
            <div className={`analysis-banner ${suspicious ? "analysis-banner-danger" : "analysis-banner-ok"}`}>
              <strong>{suspicious ? "Attack indicators detected in the PCAP" : "No attack indicators were detected in the PCAP"}</strong>
              <span>
                Packets: {summary.total_packets || 0} | Alerts: {summary.total_alerts || 0} | Attack types: {summary.attack_types || 0}
              </span>
            </div>

            <div className="graph-summary-grid">
              <SummaryCard label="Packets" value={String(summary.total_packets || 0)} hint="Packets parsed from PCAP" />
              <SummaryCard label="Alerts" value={String(summary.total_alerts || 0)} hint="Detections raised by the IDS pipeline" />
              <SummaryCard label="Attack Types" value={String(summary.attack_types || 0)} hint={suspicious ? "Detected attack families" : "No detected attack families"} />
            </div>

            <div className="analysis-grid">
              <MiniList title="Top Attack Types" items={(offlineResult.top_attack_types || []).map((item) => ({ label: item.attack_type, count: item.count }))} />
              <MiniList title="Top Targets" items={(offlineResult.top_targets || []).map((item) => ({ label: item.target, count: item.count }))} />
              <MiniList title="Severity Breakdown" items={(offlineResult.severity_breakdown || []).map((item) => ({ label: item.severity, count: item.count }))} />
            </div>

            <div className="analysis-grid">
              <MiniList title="Top IPs" items={(offlineResult.top_ips || []).map((item) => ({ label: item.ip, count: item.count }))} />
              <MiniList title="Top Countries" items={(offlineResult.top_countries || []).map((item) => ({ label: item.country, count: item.count }))} />
              <MiniList title="Top Ports" items={(offlineResult.top_ports || []).map((item) => ({ label: String(item.port), count: item.count }))} />
            </div>

            <div className="analysis-grid">
              <MiniList title="Top Protocols" items={(offlineResult.top_protocols || []).map((item) => ({ label: item.protocol, count: item.count }))} />
              <section className="mini-panel mini-list-panel analysis-timeline-panel">
                <p className="eyebrow">Alert Timeline</p>
                <TimelineTable timeline={offlineResult.timeline || []} />
              </section>
            </div>

            <section className="mini-panel mini-list-panel">
              <p className="eyebrow">Detected Alerts</p>
              {alerts.length === 0 ? <p className="muted">This PCAP did not trigger any detections.</p> : null}
              {alerts.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Attack</th>
                        <th>Severity</th>
                        <th>Engine</th>
                        <th>Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.slice(0, 100).map((alert, index) => (
                        <tr key={`${alert.packet_id || "pcap"}-${index}`}>
                          <td>{alert.ts || "-"}</td>
                          <td>{alert.src || "-"}</td>
                          <td>{alert.dst || "-"}</td>
                          <td>{alert.attack_type || "-"}</td>
                          <td>{alert.severity || "-"}</td>
                          <td>{alert.engine || "-"}</td>
                          <td>{Number(alert.score || 0).toFixed(3)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </section>
          </>
        ) : null}
      </div>
    </div>
  );
}
