import { getFlowSummary, getPeerInfo } from "../lib/networkView";
import { useWindowedRows } from "../hooks/useWindowedRows";

export function AlertsPanel({
  alerts,
  alertMeta,
  alertQuery,
  selectedAlertId,
  focusedTarget,
  liveFollow,
  onAlertQueryChange,
  onApplyAlertFilters,
  onPaginateAlerts,
  onSelectAlert,
  onTrackTarget,
  onToggleFollow,
  pageSize,
}) {
  const { visibleItems, startIndex, topSpacerHeight, bottomSpacerHeight, onScroll, isWindowed } = useWindowedRows(alerts, {
    enabled: alerts.length > 40,
    rowHeight: 60,
    containerHeight: 520,
  });

  return (
    <div className="panel-body">
      <div className="panel-toolbar">
        <p className="eyebrow">Alerts</p>
        <div className="toolbar-chips">
          <span className={`graph-chip ${liveFollow ? "chip-live" : "chip-paused"}`}>{liveFollow ? "Following newest" : "Pinned view"}</span>
          {focusedTarget?.ip ? <span className="graph-chip graph-chip-focus">{focusedTarget.ip}</span> : null}
        </div>
      </div>
      <div className="filter-grid">
        <input placeholder="src" value={alertQuery.src} onChange={(event) => onAlertQueryChange("src", event.target.value)} />
        <input placeholder="attack" value={alertQuery.attack} onChange={(event) => onAlertQueryChange("attack", event.target.value)} />
        <input placeholder="proto" value={alertQuery.proto} onChange={(event) => onAlertQueryChange("proto", event.target.value)} />
        <input placeholder="detail text" value={alertQuery.text} onChange={(event) => onAlertQueryChange("text", event.target.value)} />
        <input placeholder="min score" value={alertQuery.min_score} onChange={(event) => onAlertQueryChange("min_score", event.target.value)} />
        <label className="toggle">
          <input type="checkbox" checked={Boolean(alertQuery.only_remote)} onChange={(event) => onAlertQueryChange("only_remote", event.target.checked)} />
          <span>Only remote traffic</span>
        </label>
        <button className="secondary" onClick={onApplyAlertFilters}>Apply Alert Filters</button>
      </div>
      <div className="actions-row inline-actions">
        <button className="secondary" onClick={() => onToggleFollow(!liveFollow)}>
          {liveFollow ? "Pause Auto Follow" : "Resume Auto Follow"}
        </button>
      </div>
      <div className="table-head">
        <p className="meta-line">Rows: {alertMeta.total} from {alertMeta.source}</p>
        <div className="pager">
          <button className="secondary" onClick={() => onPaginateAlerts(-1)} disabled={alertMeta.offset <= 0}>Prev</button>
          <span>{alertMeta.offset + 1}-{Math.min(alertMeta.offset + alerts.length, alertMeta.total || alerts.length)}</span>
          <button className="secondary" onClick={() => onPaginateAlerts(1)} disabled={alertMeta.offset + pageSize >= alertMeta.total}>Next</button>
        </div>
      </div>
      <div className={`table-wrap ${isWindowed ? "table-wrap-windowed" : ""}`} onScroll={onScroll}>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Remote / Peer</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Flow</th>
              <th>Attack</th>
              <th>Score</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 ? (
              <tr><td colSpan="7" className="muted">No alerts yet</td></tr>
            ) : topSpacerHeight > 0 ? (
              <tr className="spacer-row" aria-hidden="true"><td colSpan="7" style={{ height: `${topSpacerHeight}px` }} /></tr>
            ) : null}
            {visibleItems.map((alert, index) => (
              (() => {
                const absoluteIndex = startIndex + index;
                const flow = getFlowSummary(alert.src, alert.dst);
                const peer = getPeerInfo(alert);
                return (
                  <tr
                    key={`${alert.id ?? alert.ts ?? "alert"}-${absoluteIndex}`}
                    onClick={() => onSelectAlert(alert, absoluteIndex)}
                    className={`click-row severity-${String(alert.severity || "info").toLowerCase()} ${selectedAlertId === String(alert.id ?? alertMeta.offset + absoluteIndex) ? "row-selected" : ""} ${focusedTarget?.ip && (alert.src === focusedTarget.ip || alert.dst === focusedTarget.ip) ? "row-focused" : ""}`}
                  >
                    <td>{alert.ts || "-"}</td>
                    <td>
                      <button className="table-link" onClick={(event) => { event.stopPropagation(); onTrackTarget(alert, peer.role); }}>
                        {peer.ip || "-"}
                      </button>
                    </td>
                    <td>
                      <button className="table-link" onClick={(event) => { event.stopPropagation(); onTrackTarget({ src: alert.src, dst: alert.dst }, "src"); }}>
                        {alert.src || "-"}
                      </button>
                    </td>
                    <td>
                      <button className="table-link" onClick={(event) => { event.stopPropagation(); onTrackTarget({ src: alert.src, dst: alert.dst }, "dst"); }}>
                        {alert.dst || "-"}
                      </button>
                    </td>
                    <td><span className="side-pill side-flow">{flow.label}</span></td>
                    <td>
                      <span className={`severity-pill severity-${String(alert.severity || "info").toLowerCase()}`}>
                        {alert.attack_type || "-"}
                      </span>
                      {alert.app_protocol ? (
                        <div className="table-subline">
                          <span className="side-pill side-flow">{alert.app_protocol}</span>
                        </div>
                      ) : null}
                    </td>
                    <td>{Number(alert.score || 0).toFixed(3)}</td>
                  </tr>
                );
              })()
            ))}
            {alerts.length > 0 && bottomSpacerHeight > 0 ? (
              <tr className="spacer-row" aria-hidden="true"><td colSpan="7" style={{ height: `${bottomSpacerHeight}px` }} /></tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}
