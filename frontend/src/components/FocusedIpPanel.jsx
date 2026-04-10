export function FocusedIpPanel({
  focusedTarget,
  focusedPacketCount,
  focusedAlerts,
  liveFollow,
  onClearFocusedTarget,
  onResumeLive,
}) {
  const lastAlert = focusedAlerts[0];

  return (
    <div className="panel-body stack">
      {!focusedTarget ? <p className="muted">No IP is pinned yet. Click any source or destination in packets, alerts, or top talkers to lock onto it.</p> : null}

      {focusedTarget ? (
        <>
          <div className="focus-header">
            <div>
              <p className="focus-label">Pinned IP</p>
              <h4>{focusedTarget.ip}</h4>
              <p className="muted">Tracking as {focusedTarget.role === "dst" ? "destination" : "source"} and keeping the tables from jumping.</p>
            </div>
            <div className="focus-actions">
              <button className="secondary" onClick={onResumeLive} disabled={liveFollow}>Resume Follow</button>
              <button className="primary" onClick={onClearFocusedTarget}>Release Pin</button>
            </div>
          </div>

          <div className="focus-stats">
            <div className="focus-stat">
              <span>Visible packets</span>
              <strong>{focusedPacketCount}</strong>
            </div>
            <div className="focus-stat">
              <span>Visible alerts</span>
              <strong>{focusedAlerts.length}</strong>
            </div>
            <div className="focus-stat">
              <span>Latest severity</span>
              <strong>{lastAlert?.severity || "none"}</strong>
            </div>
          </div>

          {lastAlert ? (
            <div className={`focus-alert severity-${String(lastAlert.severity || "info").toLowerCase()}`}>
              <p className="focus-label">Last alert</p>
              <strong>{lastAlert.attack_type || "Alert"}</strong>
              <p>{lastAlert.detail || "No detail"}</p>
            </div>
          ) : (
            <p className="muted">No alert has been recorded for this pinned IP in the current view.</p>
          )}
        </>
      ) : null}
    </div>
  );
}
