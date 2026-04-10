function buildLine(points, width, height, valueKey, maxValue) {
  if (!points.length || maxValue <= 0) return "";
  return points
    .map((point, index) => {
      const x = (index / Math.max(points.length - 1, 1)) * width;
      const y = height - (point[valueKey] / maxValue) * height;
      return `${index === 0 ? "M" : "L"} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(" ");
}

function buildArea(points, width, height, valueKey, maxValue) {
  if (!points.length || maxValue <= 0) return "";
  const line = buildLine(points, width, height, valueKey, maxValue);
  return `${line} L ${width} ${height} L 0 ${height} Z`;
}

export function LiveGraphPanel({ timeline, focusedTarget, liveFollow }) {
  const width = 780;
  const height = 240;
  const maxValue = Math.max(1, ...timeline.map((item) => Math.max(item.packets, item.alerts)));
  const packetPath = buildLine(timeline, width, height, "packets", maxValue);
  const packetArea = buildArea(timeline, width, height, "packets", maxValue);
  const alertPath = buildLine(timeline, width, height, "alerts", maxValue);
  const alertArea = buildArea(timeline, width, height, "alerts", maxValue);
  const packetWindowCount = timeline.reduce((sum, item) => sum + item.packets, 0);
  const alertWindowCount = timeline.reduce((sum, item) => sum + item.alerts, 0);
  const peakAlertScore = timeline.reduce((max, item) => Math.max(max, item.alertScore), 0);
  const peakPackets = timeline.reduce((max, item) => Math.max(max, item.packets), 0);
  const hottestBucket = timeline.reduce(
    (current, item) => ((item.packets + item.alerts) > (current.packets + current.alerts) ? item : current),
    timeline[0] || { label: "-", packets: 0, alerts: 0 }
  );
  const averagePackets = packetWindowCount / Math.max(timeline.length, 1);

  return (
    <div className="panel-body stack">
      <div className="graph-meta">
        <div className="graph-chip graph-chip-packets">Packets 60s: {packetWindowCount}</div>
        <div className="graph-chip graph-chip-alerts">Alerts 60s: {alertWindowCount}</div>
        <div className="graph-chip">Peak packet burst: {peakPackets}</div>
        <div className="graph-chip">Peak score: {peakAlertScore.toFixed(2)}</div>
        <div className="graph-chip">{liveFollow ? "Auto-follow on" : "Auto-follow paused"}</div>
        {focusedTarget?.ip ? <div className="graph-chip graph-chip-focus">Pinned: {focusedTarget.ip}</div> : null}
      </div>

      <div className="graph-summary-grid">
        <div className="graph-summary-card">
          <span>Average packet rate</span>
          <strong>{averagePackets.toFixed(1)}</strong>
          <small>per 2-second bucket</small>
        </div>
        <div className="graph-summary-card">
          <span>Hottest window</span>
          <strong>{hottestBucket.label}</strong>
          <small>{hottestBucket.packets} packets / {hottestBucket.alerts} alerts</small>
        </div>
        <div className="graph-summary-card">
          <span>Alert pressure</span>
          <strong>{packetWindowCount ? ((alertWindowCount / packetWindowCount) * 100).toFixed(1) : "0.0"}%</strong>
          <small>alerts per packet in view</small>
        </div>
      </div>

      <div className="graph-stage">
        <svg viewBox={`0 0 ${width} ${height}`} className="traffic-graph" role="img" aria-label="Live packets and alerts chart">
          {[0.2, 0.4, 0.6, 0.8, 1].map((ratio) => (
            <line
              key={ratio}
              x1="0"
              x2={width}
              y1={height - ratio * height}
              y2={height - ratio * height}
              className="graph-grid-line"
            />
          ))}
          {timeline.map((point, index) => {
            const x = (index / Math.max(timeline.length - 1, 1)) * width;
            return <line key={point.time} x1={x} x2={x} y1={height - 12} y2={height} className="graph-axis-tick" />;
          })}
          <path d={packetArea} className="graph-area graph-area-packets" />
          <path d={alertArea} className="graph-area graph-area-alerts" />
          <path d={packetPath} className="graph-line graph-line-packets" />
          <path d={alertPath} className="graph-line graph-line-alerts" />
          {timeline.map((point, index) => {
            const x = (index / Math.max(timeline.length - 1, 1)) * width;
            const yPackets = height - (point.packets / maxValue) * height;
            const yAlerts = height - (point.alerts / maxValue) * height;
            return (
              <g key={`${point.time}-dots`}>
                <circle cx={x} cy={yPackets} r={point.packets > 0 ? 2.6 : 0} className="graph-dot graph-dot-packets" />
                <circle cx={x} cy={yAlerts} r={point.alerts > 0 ? 3.6 : 0} className="graph-dot graph-dot-alerts" />
              </g>
            );
          })}
        </svg>
      </div>

      <div className="graph-label-row">
        {timeline.filter((_, index) => index % 5 === 0 || index === timeline.length - 1).map((point) => (
          <span key={`${point.time}-label`} className="muted">{point.label}</span>
        ))}
      </div>

      <div className="graph-legend">
        <span><i className="legend-swatch legend-packets" />Packet rate</span>
        <span><i className="legend-swatch legend-alerts" />Alert bursts</span>
        <span className="muted">Each point represents 2 seconds and stays in a rolling 60-second window.</span>
      </div>
    </div>
  );
}
