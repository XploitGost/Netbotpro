import { getFlowSummary, getPeerInfo, getTrafficSide } from "../lib/networkView";
import { useWindowedRows } from "../hooks/useWindowedRows";

export function PacketsPanel({
  packets,
  packetMeta,
  packetQuery,
  selectedPacketId,
  focusedTarget,
  liveFollow,
  onPacketQueryChange,
  onApplyPacketFilters,
  onPaginatePackets,
  onSelectPacket,
  onTrackTarget,
  onToggleFollow,
  pageSize,
}) {
  const { visibleItems, startIndex, topSpacerHeight, bottomSpacerHeight, onScroll, isWindowed } = useWindowedRows(packets, {
    enabled: packets.length > 40,
    rowHeight: 76,
    containerHeight: 520,
  });

  return (
    <div className="panel-body">
      <div className="panel-toolbar">
        <p className="eyebrow">Packets</p>
        <div className="toolbar-chips">
          <span className={`graph-chip ${liveFollow ? "chip-live" : "chip-paused"}`}>{liveFollow ? "Following newest" : "Pinned view"}</span>
          {focusedTarget?.ip ? <span className="graph-chip graph-chip-focus">{focusedTarget.ip}</span> : null}
        </div>
      </div>
      <div className="filter-grid">
        <input placeholder="src" value={packetQuery.src} onChange={(event) => onPacketQueryChange("src", event.target.value)} />
        <input placeholder="dst" value={packetQuery.dst} onChange={(event) => onPacketQueryChange("dst", event.target.value)} />
        <input placeholder="proto" value={packetQuery.proto} onChange={(event) => onPacketQueryChange("proto", event.target.value)} />
        <input placeholder="process" value={packetQuery.process} onChange={(event) => onPacketQueryChange("process", event.target.value)} />
        <input placeholder="pid" value={packetQuery.pid} onChange={(event) => onPacketQueryChange("pid", event.target.value)} />
        <input placeholder="text" value={packetQuery.text} onChange={(event) => onPacketQueryChange("text", event.target.value)} />
        <label className="toggle">
          <input type="checkbox" checked={packetQuery.only_alerts} onChange={(event) => onPacketQueryChange("only_alerts", event.target.checked)} />
          <span>Only packets with alerts</span>
        </label>
        <label className="toggle">
          <input type="checkbox" checked={Boolean(packetQuery.only_remote)} onChange={(event) => onPacketQueryChange("only_remote", event.target.checked)} />
          <span>Only remote traffic</span>
        </label>
        <button className="secondary" onClick={onApplyPacketFilters}>Apply Packet Filters</button>
      </div>
      <div className="actions-row inline-actions">
        <button className="secondary" onClick={() => onToggleFollow(!liveFollow)}>
          {liveFollow ? "Pause Auto Follow" : "Resume Auto Follow"}
        </button>
      </div>
      <div className="table-head">
        <p className="meta-line">Rows: {packetMeta.total} from {packetMeta.source}</p>
        <div className="pager">
          <button className="secondary" onClick={() => onPaginatePackets(-1)} disabled={packetMeta.offset <= 0}>Prev</button>
          <span>{packetMeta.offset + 1}-{Math.min(packetMeta.offset + packets.length, packetMeta.total || packets.length)}</span>
          <button className="secondary" onClick={() => onPaginatePackets(1)} disabled={packetMeta.offset + pageSize >= packetMeta.total}>Next</button>
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
              <th>Process</th>
              <th>Flow</th>
              <th>Protocol</th>
            </tr>
          </thead>
          <tbody>
            {packets.length === 0 ? (
              <tr><td colSpan="7" className="muted">No packets yet</td></tr>
            ) : topSpacerHeight > 0 ? (
              <tr className="spacer-row" aria-hidden="true"><td colSpan="7" style={{ height: `${topSpacerHeight}px` }} /></tr>
            ) : null}
            {visibleItems.map((packet, index) => (
              (() => {
                const absoluteIndex = startIndex + index;
                const srcSide = getTrafficSide(packet.src);
                const dstSide = getTrafficSide(packet.dst);
                const flow = getFlowSummary(packet.src, packet.dst);
                const peer = getPeerInfo(packet);
                const processLabel = packet.process_name || (packet.pid ? `PID ${packet.pid}` : "Unknown");
                const processHint = packet.executable_path || packet.parent_process_name || packet.attribution_reason_unavailable || packet.attribution_confidence || "-";
                return (
                  <tr
                    key={`${packet.id ?? packet.ts ?? "pkt"}-${absoluteIndex}`}
                    onClick={() => onSelectPacket(packet, absoluteIndex)}
                    className={`click-row ${selectedPacketId === String(packet.id ?? packetMeta.offset + absoluteIndex) ? "row-selected" : ""} ${packet.is_alert ? "row-alert" : ""} ${focusedTarget?.ip && (packet.src === focusedTarget.ip || packet.dst === focusedTarget.ip) ? "row-focused" : ""}`}
                  >
                    <td>{packet.ts || "-"}</td>
                    <td>
                      <button className="table-link" onClick={(event) => { event.stopPropagation(); onTrackTarget(packet, peer.role); }}>
                        {peer.ip || "-"}
                      </button>
                      <div className="table-subline">
                        <span className={`side-pill side-${peer.side.tone}`}>{peer.side.label}</span>
                      </div>
                    </td>
                    <td>
                      <button className="table-link" onClick={(event) => { event.stopPropagation(); onTrackTarget({ src: packet.src, dst: packet.dst }, "src"); }}>
                        {packet.src || "-"}
                      </button>
                      <div className="table-subline">
                        <span className={`side-pill side-${srcSide.tone}`}>{srcSide.label}</span>
                      </div>
                    </td>
                    <td>
                      <button className="table-link" onClick={(event) => { event.stopPropagation(); onTrackTarget({ src: packet.src, dst: packet.dst }, "dst"); }}>
                        {packet.dst || "-"}
                      </button>
                      <div className="table-subline">
                        <span className={`side-pill side-${dstSide.tone}`}>{dstSide.label}</span>
                      </div>
                    </td>
                    <td>
                      <span>{processLabel}</span>
                      <div className="table-subline">
                        <span className="muted">{processHint}</span>
                      </div>
                    </td>
                    <td><span className="side-pill side-flow">{flow.label}</span></td>
                    <td>
                      <span className={`protocol-pill ${packet.is_alert ? "protocol-pill-alert" : ""}`}>{packet.proto || "-"}</span>
                      {packet.app_protocol ? (
                        <div className="table-subline">
                          <span className="side-pill side-flow">{packet.app_protocol}</span>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                );
              })()
            ))}
            {packets.length > 0 && bottomSpacerHeight > 0 ? (
              <tr className="spacer-row" aria-hidden="true"><td colSpan="7" style={{ height: `${bottomSpacerHeight}px` }} /></tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}
