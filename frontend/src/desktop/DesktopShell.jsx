import { useState } from "react";
import { Navigation, Topbar } from "./CommandCenter";

export function DesktopShell({ controller: c, children }) {
  const [navigationOpen, setNavigationOpen] = useState(false);
  const ready = c.localTokenAccepted && !c.loadingState.bootstrap;
  const health = ready ? c.sniffer.health || "idle" : "unavailable";
  return <div className="shell desktop-shell">
    <Navigation activePage={c.activePage} onNavigate={c.setActivePage}
      healthLabel={health.replace(/^./, (letter) => letter.toUpperCase())}
      healthState={health === "healthy" ? "verified" : "pending"}
      streamLabel={c.connectionLabel} lastUpdated={c.statusMessage}
      open={navigationOpen} onClose={() => setNavigationOpen(false)} />
    <Topbar api={c.api} fixtureMode={false} backendState={ready ? "connected" : "connecting"}
      dashboardState={ready ? "success" : "loading"} connectionState={c.connectionState}
      connectionLabel={c.connectionState === "live" ? "Connected" : c.connectionLabel}
      sniffer={c.sniffer} settings={c.settings} interfaces={c.interfaces}
      isBusy={c.loadingState.snifferAction} canStartSniffer={ready && c.canStartSniffer && !c.sniffer.running}
      onStartSniffer={c.startSniffer} onStopSniffer={c.stopSniffer}
      onOpenSettings={() => c.setActivePage("settings")} onToggleNav={() => setNavigationOpen((open) => !open)} />
    <main className="soc-main desktop-main">
      {c.localTokenRequired && !c.managedLocalToken && !c.localTokenAccepted &&
        <label className="desktop-auth">Local token<input aria-label="Local token" type="password"
          autoComplete="off" value={c.localToken} onChange={(event) => c.setLocalToken(event.target.value)} /></label>}
      {c.error && <p className="desktop-error" role="alert">{c.error}</p>}
      {children}
    </main>
  </div>;
}
