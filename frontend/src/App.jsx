import { useEffect } from "react";
import { AlertsPanel } from "./components/AlertsPanel";
import { AppNav } from "./components/AppNav";
import { DetailPanel } from "./components/DetailPanel";
import { ExportPanel } from "./components/ExportPanel";
import { FocusedIpPanel } from "./components/FocusedIpPanel";
import { HeroPanel } from "./components/HeroPanel";
import { LiveGraphPanel } from "./components/LiveGraphPanel";
import { MiniList } from "./components/MiniList";
import { OfflineAnalysisPanel } from "./components/OfflineAnalysisPanel";
import { OpsPanel } from "./components/OpsPanel";
import { PacketsPanel } from "./components/PacketsPanel";
import { ReportsPanel } from "./components/ReportsPanel";
import { SettingsPanel } from "./components/SettingsPanel";
import { StatCard } from "./components/StatCard";
import { TraceroutePanel } from "./components/TraceroutePanel";
import { PAGE_SIZE, useDashboardController } from "./hooks/useDashboardController";

function PageSection({ title, subtitle, children, wide = false, fullWidth = false }) {
  return (
    <section className={`card page-card ${wide ? "page-card-wide" : ""} ${fullWidth ? "page-card-full" : ""}`}>
      <div className="page-card-head">
        <h2>{title}</h2>
        {subtitle ? <p className="muted">{subtitle}</p> : null}
      </div>
      {children}
    </section>
  );
}

function InspectSummaryCard({ label, value, hint, tone = "neutral" }) {
  return (
    <div className={`inspect-summary-card inspect-summary-${tone}`}>
      <p className="eyebrow">{label}</p>
      <strong>{value}</strong>
      <p className="muted">{hint}</p>
    </div>
  );
}

function App() {
  const {
    localToken,
    setLocalToken,
    activePage,
    setActivePage,
    packets,
    alerts,
    packetQuery,
    alertQuery,
    packetMeta,
    alertMeta,
    selectedPacket,
    selectedAlert,
    selectedPacketId,
    selectedAlertId,
    settings,
    interfaces,
    recommendedInterface,
    recommendedInterfaceLabel,
    capturePreflight,
    captureUnavailableDetail,
    tracerouteTarget,
    setTracerouteTarget,
    tracerouteResult,
    offlineResult,
    setOfflineFile,
    exportInfo,
    reports,
    connectionState,
    connectionLabel,
    statusMessage,
    observability,
    error,
    localTokenRequired,
    managedLocalToken,
    canStartSniffer,
    liveFollow,
    setLiveFollow,
    focusedTarget,
    timeline,
    sniffer,
    topSources,
    topProtocols,
    topRemotes,
    topConversations,
    focusedPacketCount,
    focusedAlerts,
    startSniffer,
    stopSniffer,
    resetSessionData,
    saveSettings,
    runTraceroute,
    exportSession,
    downloadExport,
    runOfflineAnalysis,
    loadPacketDetail,
    loadAlertDetail,
    applyPacketFilters,
    applyAlertFilters,
    paginatePackets,
    paginateAlerts,
    handlePacketQueryChange,
    handleAlertQueryChange,
    handleSettingsChange,
    handleTrackRow,
    clearFocusedTarget,
    resumeLiveFollow,
  } = useDashboardController();

  useEffect(() => {
    if (typeof window !== "undefined") {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }, [activePage]);

  const monitorPage = (
    <section className="page-grid page-grid-monitor">
      <PageSection title="Traffic Graph" subtitle="Realtime graph for packets and alerts" fullWidth>
        <LiveGraphPanel focusedTarget={focusedTarget} liveFollow={liveFollow} timeline={timeline} />
      </PageSection>
      <PageSection title="Ops Snapshot" subtitle="Health-aware runtime telemetry for stream, queries, and persistence" fullWidth>
        <OpsPanel observability={observability} />
      </PageSection>
      <PageSection title="Packets" subtitle="Realtime packet table with clear LAN/WAN markers" wide fullWidth>
        <PacketsPanel
          packets={packets}
          packetMeta={packetMeta}
          packetQuery={packetQuery}
          selectedPacketId={selectedPacketId}
          focusedTarget={focusedTarget}
          liveFollow={liveFollow}
          onPacketQueryChange={handlePacketQueryChange}
          onApplyPacketFilters={applyPacketFilters}
          onPaginatePackets={paginatePackets}
          onSelectPacket={loadPacketDetail}
          onTrackTarget={handleTrackRow}
          onToggleFollow={setLiveFollow}
          pageSize={PAGE_SIZE}
        />
      </PageSection>
      <PageSection title="Alerts" subtitle="Detections with source, destination, and traffic direction" wide fullWidth>
        <AlertsPanel
          alerts={alerts}
          alertMeta={alertMeta}
          alertQuery={alertQuery}
          selectedAlertId={selectedAlertId}
          focusedTarget={focusedTarget}
          liveFollow={liveFollow}
          onAlertQueryChange={handleAlertQueryChange}
          onApplyAlertFilters={applyAlertFilters}
          onPaginateAlerts={paginateAlerts}
          onSelectAlert={loadAlertDetail}
          onTrackTarget={handleTrackRow}
          onToggleFollow={setLiveFollow}
          pageSize={PAGE_SIZE}
        />
      </PageSection>
    </section>
  );

  const inspectPage = (
    <section className="page-grid page-grid-inspect">
      <PageSection title="Investigation Desk" subtitle="Selected traffic and focused targets live here now" fullWidth>
        <div className="inspect-summary-grid">
          <InspectSummaryCard
            label="Selected Packet"
            value={selectedPacket ? `${selectedPacket.src || "-"} -> ${selectedPacket.dst || "-"}` : "No packet selected"}
            hint={selectedPacket ? `${selectedPacket.proto || "Unknown"} packet • ${selectedPacket.ts || "No time"}` : "Click any packet row in Monitor to inspect it here."}
            tone={selectedPacket ? "active" : "neutral"}
          />
          <InspectSummaryCard
            label="Selected Alert"
            value={selectedAlert?.attack_type || "No alert selected"}
            hint={selectedAlert ? `${selectedAlert.severity || "info"} severity • ${selectedAlert.ts || "No time"}` : "Click any alert row in Monitor to bring its detail here."}
            tone={selectedAlert ? "warning" : "neutral"}
          />
          <InspectSummaryCard
            label="Pinned Focus"
            value={focusedTarget?.ip || "No IP pinned"}
            hint={focusedTarget ? `Tracking ${focusedTarget.role === "dst" ? "destination" : "source"} traffic across the live tables.` : "Track any source, destination, or peer to keep context stable."}
            tone={focusedTarget ? "focus" : "neutral"}
          />
        </div>
      </PageSection>
      <PageSection title="Packet Detail" subtitle="Selected packet metadata without the long monitor scroll" wide>
        <DetailPanel title="Packet Detail" data={selectedPacket} />
      </PageSection>
      <PageSection title="Alert Detail" subtitle="Selected detection context and scoring" wide>
        <DetailPanel title="Alert Detail" data={selectedAlert} />
      </PageSection>
      <PageSection title="Pinned Target" subtitle="Lock onto one IP without the view jumping" fullWidth>
        <FocusedIpPanel
          focusedTarget={focusedTarget}
          focusedPacketCount={focusedPacketCount}
          focusedAlerts={focusedAlerts}
          liveFollow={liveFollow}
          onClearFocusedTarget={clearFocusedTarget}
          onResumeLive={resumeLiveFollow}
        />
      </PageSection>
      <PageSection title="Top Sources" subtitle="Most active source IPs">
        <MiniList title="Top Sources" items={topSources} onSelect={(item) => handleTrackRow({ src: item.label }, "src")} />
      </PageSection>
      <PageSection title="Top Remote IPs" subtitle="Most active external peers">
        <MiniList title="Top Remote IPs" items={topRemotes} onSelect={(item) => handleTrackRow({ remote_ip: item.label }, "either")} />
      </PageSection>
      <PageSection title="Top Protocols" subtitle="Current protocol mix">
        <MiniList title="Top Protocols" items={topProtocols} />
      </PageSection>
      <PageSection title="Top Conversations" subtitle="Busiest local-to-remote conversations" fullWidth>
        <MiniList title="Top Conversations" items={topConversations} />
      </PageSection>
    </section>
  );

  const settingsPage = (
    <section className="page-grid page-grid-single">
      <PageSection title="Settings" subtitle="Runtime controls in a dedicated page" wide>
        <SettingsPanel
          settings={settings}
          interfaceOptions={interfaces}
          recommendedInterface={recommendedInterface}
          recommendedInterfaceLabel={recommendedInterfaceLabel}
          onChange={handleSettingsChange}
          onSave={saveSettings}
        />
      </PageSection>
    </section>
  );

  const traceroutePage = (
    <section className="page-grid page-grid-single">
      <PageSection title="Traceroute" subtitle="Route probing in its own page" wide>
        <TraceroutePanel
          tracerouteResult={tracerouteResult}
          tracerouteTarget={tracerouteTarget}
          onTargetChange={setTracerouteTarget}
          onRunTraceroute={runTraceroute}
        />
      </PageSection>
    </section>
  );

  const exportsPage = (
    <section className="page-grid page-grid-single">
      <PageSection title="Exports" subtitle="Session exports separated from monitoring" wide>
        <ExportPanel error={error} exportInfo={exportInfo} onDownload={downloadExport} onExport={exportSession} />
      </PageSection>
    </section>
  );

  const reportsPage = (
    <section className="page-grid page-grid-single">
      <PageSection title="Reports" subtitle="Generated report archive" wide>
        <ReportsPanel onDownload={downloadExport} reports={reports} />
      </PageSection>
    </section>
  );

  const offlinePage = (
    <section className="page-grid page-grid-single">
      <PageSection title="Offline Analysis" subtitle="Analyze PCAP files in a dedicated workspace" wide>
        <OfflineAnalysisPanel offlineResult={offlineResult} onFileChange={setOfflineFile} onRunAnalysis={runOfflineAnalysis} />
      </PageSection>
    </section>
  );

  const currentPage = {
    monitor: monitorPage,
    inspect: inspectPage,
    settings: settingsPage,
    traceroute: traceroutePage,
    exports: exportsPage,
    reports: reportsPage,
    offline: offlinePage,
  }[activePage];

  return (
    <main className="shell">
      <AppNav activePage={activePage} onNavigate={setActivePage} />

      <HeroPanel
        connectionLabel={connectionLabel}
        connectionState={connectionState}
        statusMessage={statusMessage}
        observability={observability}
        localToken={localToken}
        localTokenRequired={localTokenRequired}
        managedLocalToken={managedLocalToken}
        capturePreflight={capturePreflight}
        captureUnavailableDetail={captureUnavailableDetail}
        canStartSniffer={canStartSniffer}
        error={error}
        onTokenChange={setLocalToken}
        onStartSniffer={startSniffer}
        onStopSniffer={stopSniffer}
        onResetData={resetSessionData}
      />

      <section className="stats-grid">
        <StatCard label="Sniffer" value={sniffer.running ? "Running" : "Stopped"} hint={`Interface: ${sniffer.iface || "default"}`} />
        <StatCard label="Packets" value={String(sniffer.total_packets || packetMeta.total || 0)} hint="Total live packets seen" />
        <StatCard label="Alerts" value={String(sniffer.total_alerts || alertMeta.total || 0)} hint="Total alerts emitted" />
      </section>

      {currentPage}
    </main>
  );
}

export default App;
