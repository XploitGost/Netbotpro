import { useEffect, useMemo } from "react";
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
import { buildAlertInspectionContext, buildAlertInspectionModel, buildCaptureInspectionContext, buildPacketInspectionContext, buildPacketInspectionModel } from "./lib/inspectionModel";

function PageSection({ title, subtitle, children, wide = false, fullWidth = false, actions = null }) {
  return (
    <section className={`card page-card ${wide ? "page-card-wide" : ""} ${fullWidth ? "page-card-full" : ""}`}>
      <div className={`page-card-head ${actions ? "page-card-head-with-actions" : ""}`}>
        <div>
          <h2>{title}</h2>
          {subtitle ? <p className="muted">{subtitle}</p> : null}
        </div>
        {actions ? <div className="page-card-head-actions">{actions}</div> : null}
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

function cleanInspectCopy(value) {
  return String(value ?? "").replaceAll("â€¢", "|").trim();
}

function normalizeInspectCopy(value) {
  return String(value ?? "")
    .replaceAll("\u2022", "|")
    .replaceAll("\u00e2\u20ac\u00a2", "|")
    .replaceAll("\u00c3\u00a2\u00e2\u201a\u00ac\u00c2\u00a2", "|")
    .trim();
}

function createInvestigationExportPayload({ kind, id, model }) {
  return {
    format: "html",
    kind,
    id,
    headline: model?.headline || `${kind} investigation`,
    summary_text: model?.summaryText || model?.interpretedSummary || "",
    interpreted_summary: model?.interpretedSummary || model?.summaryText || "",
    analyst_cards: Array.isArray(model?.analystCards) ? model.analystCards : [],
    model,
  };
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
    selectedPacketContext,
    selectedAlert,
    selectedAlertContext,
    selectedPacketId,
    selectedAlertId,
    inspectionPinned,
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
    loadingState,
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
    topProcesses,
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
    exportInvestigation,
    downloadExport,
    runOfflineAnalysis,
    loadPacketDetail,
    loadAlertDetail,
    openPacketDetailById,
    openAlertDetailById,
    applyPacketFilters,
    applyAlertFilters,
    paginatePackets,
    paginateAlerts,
    handlePacketQueryChange,
    handleAlertQueryChange,
    handleSettingsChange,
    handleTrackRow,
    filterByProcess,
    toggleInspectionPin,
    navigatePacketDetail,
    navigateAlertDetail,
    freezeLiveFollow,
    clearFocusedTarget,
    resumeLiveFollow,
  } = useDashboardController();

  const captureContext = useMemo(() => buildCaptureInspectionContext({
    packetMeta,
    settings,
    interfaces,
    capturePreflight,
    sniffer,
  }), [packetMeta, settings, interfaces, capturePreflight, sniffer]);
  const packetInspectionContext = useMemo(
    () => selectedPacketContext || buildPacketInspectionContext(selectedPacket, packets, alerts),
    [selectedPacketContext, selectedPacket, packets, alerts]
  );
  const alertInspectionContext = useMemo(
    () => selectedAlertContext || buildAlertInspectionContext(selectedAlert, packets, alerts),
    [selectedAlertContext, selectedAlert, packets, alerts]
  );
  const packetInspection = useMemo(() => buildPacketInspectionModel(selectedPacket, {
    context: packetInspectionContext,
    capture: captureContext,
  }), [selectedPacket, packetInspectionContext, captureContext]);
  const alertInspection = useMemo(
    () => buildAlertInspectionModel(selectedAlert, { context: alertInspectionContext }),
    [selectedAlert, alertInspectionContext]
  );
  const selectedPacketIndex = packets.findIndex((packet, index) => String(packet?.id ?? packetMeta.offset + index) === selectedPacketId);
  const selectedAlertIndex = alerts.findIndex((alert, index) => String(alert?.id ?? alertMeta.offset + index) === selectedAlertId);
  const packetNavigation = {
    canPrevious: selectedPacketIndex > 0,
    canNext: selectedPacketIndex >= 0 && selectedPacketIndex < packets.length - 1,
    canPin: Boolean(selectedPacketId),
    pinned: inspectionPinned.kind === "packet" && inspectionPinned.id === selectedPacketId,
    frozen: !liveFollow,
    onPrevious: () => navigatePacketDetail(-1),
    onNext: () => navigatePacketDetail(1),
    onPin: () => toggleInspectionPin("packet"),
    onFreeze: () => (liveFollow ? freezeLiveFollow() : resumeLiveFollow()),
    onOpenPacket: openPacketDetailById,
    onOpenAlert: openAlertDetailById,
    onFilterProcess: filterByProcess,
  };
  const alertNavigation = {
    canPrevious: selectedAlertIndex > 0,
    canNext: selectedAlertIndex >= 0 && selectedAlertIndex < alerts.length - 1,
    canPin: Boolean(selectedAlertId),
    pinned: inspectionPinned.kind === "alert" && inspectionPinned.id === selectedAlertId,
    frozen: !liveFollow,
    onPrevious: () => navigateAlertDetail(-1),
    onNext: () => navigateAlertDetail(1),
    onPin: () => toggleInspectionPin("alert"),
    onFreeze: () => (liveFollow ? freezeLiveFollow() : resumeLiveFollow()),
    onOpenPacket: openPacketDetailById,
    onOpenAlert: openAlertDetailById,
    onFilterProcess: filterByProcess,
  };
  const inspectSummaryCards = !packetInspection.empty
    ? packetInspection.analystCards
    : !alertInspection.empty
      ? alertInspection.analystCards
      : [
          {
            label: "Protocol Guess",
            value: "No packet selected",
            hint: "Pick a packet from Monitor to get an analyst summary here.",
            tone: "neutral",
          },
          {
            label: "Risk",
            value: "Waiting for inspection",
            hint: "Risk, confidence, and service guess appear once a packet is selected.",
            tone: "neutral",
          },
          {
            label: "Flow / Conversation",
            value: focusedTarget?.ip || "No flow pinned",
            hint: focusedTarget ? "Pinned target context stays visible while you inspect traffic." : "Track a source, destination, or peer to lock the investigation context.",
            tone: focusedTarget ? "focus" : "neutral",
          },
          {
            label: "Process Attribution",
            value: "Not mapped yet",
            hint: "Socket attribution, host metadata, and decode details appear here once a process match is available.",
            tone: "neutral",
          },
          {
            label: "Why It Matters",
            value: selectedAlert?.attack_type || "Inspection desk is idle",
            hint: selectedAlert ? "An alert is selected; packet context will fill in after you pick related traffic." : "Alert and packet detail stay here so you do not need to scroll back through Monitor.",
            tone: selectedAlert ? "warning" : "neutral",
          },
        ];
  const canExportPacket = Boolean(selectedPacketId) && !packetInspection.empty;
  const canExportAlert = Boolean(selectedAlertId) && !alertInspection.empty;
  const inspectActions = (
    <div className="actions-row">
      <button
        type="button"
        className="secondary"
        disabled={loadingState.exports || !canExportPacket}
        onClick={() => exportInvestigation(createInvestigationExportPayload({ kind: "packet", id: selectedPacketId, model: packetInspection }))}
      >
        Export Packet Report
      </button>
      <button
        type="button"
        className="secondary"
        disabled={loadingState.exports || !canExportAlert}
        onClick={() => exportInvestigation(createInvestigationExportPayload({ kind: "alert", id: selectedAlertId, model: alertInspection }))}
      >
        Export Alert Report
      </button>
    </div>
  );

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
          isLoading={loadingState.packets}
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
          isLoading={loadingState.alerts}
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
      <PageSection title="Analyst Summary" subtitle="Fast answers for the packet or alert you are inspecting" fullWidth actions={inspectActions}>
        <div className="inspect-summary-grid">
          {inspectSummaryCards.map((card) => (
            <InspectSummaryCard
              key={card.label}
              label={card.label}
              value={normalizeInspectCopy(card.value)}
              hint={normalizeInspectCopy(card.hint)}
              tone={card.tone || "neutral"}
            />
          ))}
        </div>
      </PageSection>
      <PageSection title="Packet Detail" subtitle="Interpretation, correlation, and payload context for the selected packet" wide>
        <DetailPanel
          title="Packet Detail"
          model={packetInspection}
          selectionKey={selectedPacketId}
          navigation={packetNavigation}
          emptyMessage={loadingState.packetDetail ? "Loading packet inspection..." : "Select a packet from Monitor to open the inspection view."}
        />
      </PageSection>
      <PageSection title="Alert Detail" subtitle="Detection context and scoring without the monitor scroll" wide>
        <DetailPanel
          title="Alert Detail"
          model={alertInspection}
          selectionKey={selectedAlertId}
          navigation={alertNavigation}
          emptyMessage={loadingState.alertDetail ? "Loading alert inspection..." : "Select an alert from Monitor to inspect its detection metadata."}
        />
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
      <PageSection title="Top Processes" subtitle="Most active processes in the live sample">
        <MiniList title="Top Processes" items={topProcesses} onSelect={filterByProcess} />
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
          isBusy={loadingState.settings}
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
          isBusy={loadingState.traceroute}
          onTargetChange={setTracerouteTarget}
          onRunTraceroute={runTraceroute}
        />
      </PageSection>
    </section>
  );

  const exportsPage = (
    <section className="page-grid page-grid-single">
      <PageSection title="Exports" subtitle="Session exports separated from monitoring" wide>
        <ExportPanel error={error} exportInfo={exportInfo} isBusy={loadingState.exports} onDownload={downloadExport} onExport={exportSession} />
      </PageSection>
    </section>
  );

  const reportsPage = (
    <section className="page-grid page-grid-single">
      <PageSection title="Reports" subtitle="Generated report archive" wide>
        <ReportsPanel isLoading={loadingState.reports} onDownload={downloadExport} reports={reports} />
      </PageSection>
    </section>
  );

  const offlinePage = (
    <section className="page-grid page-grid-single">
      <PageSection title="Offline Analysis" subtitle="Analyze PCAP files in a dedicated workspace" wide>
        <OfflineAnalysisPanel offlineResult={offlineResult} isBusy={loadingState.offlineAnalysis} onFileChange={setOfflineFile} onRunAnalysis={runOfflineAnalysis} />
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
        isBusy={loadingState.snifferAction}
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
