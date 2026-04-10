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

function App() {
  const {
    api,
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

  const monitorPage = (
    <section className="page-grid">
      <PageSection title="Traffic Graph" subtitle="Realtime graph for packets and alerts">
        <LiveGraphPanel focusedTarget={focusedTarget} liveFollow={liveFollow} timeline={timeline} />
      </PageSection>
      <PageSection title="Pinned Target" subtitle="Lock onto one IP without the view jumping">
        <FocusedIpPanel
          focusedTarget={focusedTarget}
          focusedPacketCount={focusedPacketCount}
          focusedAlerts={focusedAlerts}
          liveFollow={liveFollow}
          onClearFocusedTarget={clearFocusedTarget}
          onResumeLive={resumeLiveFollow}
        />
      </PageSection>
      <PageSection title="Ops Snapshot" subtitle="Health-aware runtime telemetry for stream, queries, and persistence" fullWidth>
        <OpsPanel observability={observability} />
      </PageSection>
      <PageSection title="Top Sources" subtitle="Most active source IPs">
        <MiniList title="Top Sources" items={topSources} onSelect={(item) => handleTrackRow({ src: item.label }, "src")} />
      </PageSection>
      <PageSection title="Top Remote IPs" subtitle="Most active external peers">
        <MiniList title="Top Remote IPs" items={topRemotes} onSelect={(item) => handleTrackRow({ remote_ip: item.label }, "either")} />
      </PageSection>
      <PageSection title="Top Conversations" subtitle="Busiest local-to-remote conversations" fullWidth>
        <MiniList title="Top Conversations" items={topConversations} />
      </PageSection>
      <PageSection title="Top Protocols" subtitle="Current protocol mix">
        <MiniList title="Top Protocols" items={topProtocols} />
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
      <PageSection title="Packet Detail" subtitle="Selected packet metadata">
        <DetailPanel title="Packet Detail" data={selectedPacket} />
      </PageSection>
      <PageSection title="Alert Detail" subtitle="Selected alert metadata">
        <DetailPanel title="Alert Detail" data={selectedAlert} />
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
        <ExportPanel apiBase={api.apiBase} error={error} exportInfo={exportInfo} onExport={exportSession} />
      </PageSection>
    </section>
  );

  const reportsPage = (
    <section className="page-grid page-grid-single">
      <PageSection title="Reports" subtitle="Generated report archive" wide>
        <ReportsPanel apiBase={api.apiBase} reports={reports} />
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
