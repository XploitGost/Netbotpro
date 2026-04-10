import { buildOpsSnapshot, levelClass, levelLabel } from "../lib/opsHealth";

export function HeroPanel({
  connectionLabel,
  connectionState,
  statusMessage,
  observability,
  localToken,
  localTokenRequired,
  onTokenChange,
  onStartSniffer,
  onStopSniffer,
  onResetData,
}) {
  const snapshot = buildOpsSnapshot(observability);
  const summaryCards = snapshot.summaryCards.slice(0, 4);

  return (
    <section className="hero card">
      <div className="hero-copy">
        <p className="eyebrow">NetBotPro Live Console</p>
        <h1 className="hero-title">Live Network Monitor</h1>
        <div className="hero-health-row">
          <span className={`ops-state-pill ${levelClass(snapshot.overall)}`}>Ops {levelLabel(snapshot.overall)}</span>
          <span className={`graph-chip ${levelClass(connectionState === "degraded" ? "degraded" : connectionState === "reconnecting" ? "warning" : "healthy")}`}>
            Stream {connectionLabel}
          </span>
        </div>
        <div className="hero-metrics">
          {summaryCards.map((card) => (
            <span key={card.label} className={`graph-chip ${levelClass(card.level)}`}>
              {card.label}: {card.value}
            </span>
          ))}
        </div>
      </div>
      <div className="hero-side">
        <div className={`status-badge status-${connectionState}`}>{connectionLabel}</div>
        <p className="muted">{statusMessage}</p>
        {localTokenRequired ? (
          <div className="stack">
            <input
              type="password"
              value={localToken}
              placeholder="Local token"
              onChange={(event) => onTokenChange(event.target.value)}
            />
            <p className="muted">Sensitive actions require the local token from `NETBOT_LOCAL_TOKEN`.</p>
          </div>
        ) : null}
        <div className="hero-actions">
          <button className="primary" onClick={onStartSniffer}>Start Sniffer</button>
          <button className="secondary" onClick={onStopSniffer}>Stop Sniffer</button>
          <button className="secondary" onClick={onResetData}>Reset Data</button>
        </div>
      </div>
    </section>
  );
}
