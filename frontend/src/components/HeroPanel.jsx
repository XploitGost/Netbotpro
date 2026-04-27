import { buildOpsSnapshot, levelClass, levelLabel } from "../lib/opsHealth";

export function HeroPanel({
  connectionLabel,
  connectionState,
  statusMessage,
  observability,
  localToken,
  localTokenRequired,
  managedLocalToken,
  capturePreflight,
  captureUnavailableDetail,
  canStartSniffer,
  error,
  isBusy = false,
  onTokenChange,
  onStartSniffer,
  onStopSniffer,
  onResetData,
}) {
  const snapshot = buildOpsSnapshot(observability);
  const summaryCards = snapshot.summaryCards.slice(0, 4);
  const captureRecommendations = Array.isArray(capturePreflight?.recommendations)
    ? capturePreflight.recommendations.filter((item) => String(item || "").trim())
    : [];
  const failedChecks = Array.isArray(capturePreflight?.checks)
    ? capturePreflight.checks.filter((check) => !check?.ok)
    : [];

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
        {localTokenRequired && !managedLocalToken ? (
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
        {localTokenRequired && managedLocalToken ? (
          <p className="muted">Sensitive actions are secured with a desktop-managed local token.</p>
        ) : null}
        {!canStartSniffer && captureUnavailableDetail ? (
          <p className="error">Live capture unavailable: {captureUnavailableDetail}</p>
        ) : null}
        {capturePreflight?.requires_elevation ? (
          <p className="muted">Run the desktop app as Administrator if you want live capture and firewall actions.</p>
        ) : null}
        {failedChecks.length ? (
          <div className="hero-capture-notes">
            <p className="muted">Capture checks</p>
            <ul className="hero-list">
              {failedChecks.slice(0, 3).map((check) => (
                <li key={check.code}>
                  <strong>{check.label}:</strong> {check.detail}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {captureRecommendations.length ? (
          <div className="hero-capture-notes">
            <p className="muted">Suggested next steps</p>
            <ul className="hero-list">
              {captureRecommendations.map((item, index) => (
                <li key={`${index}-${item}`}>{item}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {isBusy ? <p className="table-status">Applying desktop action...</p> : null}
        {error ? <p className="error">{error}</p> : null}
        <div className="hero-actions">
          <button className="primary" onClick={onStartSniffer} disabled={isBusy || !canStartSniffer}>Start Sniffer</button>
          <button className="secondary" onClick={onStopSniffer} disabled={isBusy}>Stop Sniffer</button>
          <button className="secondary" onClick={onResetData} disabled={isBusy}>Reset Data</button>
        </div>
      </div>
    </section>
  );
}
