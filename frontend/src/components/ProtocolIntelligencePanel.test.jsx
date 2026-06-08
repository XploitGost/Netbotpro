import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ProtocolIntelligencePanel } from "./ProtocolIntelligencePanel";

const api = {
  apiBase: "/api",
  getProtocolIntelligence: vi.fn(async () => ({
    protocols: { total_packets: 3, protocols: [{ protocol: "TLS", packet_count: 3, flow_count: 1, bytes_total: 900, risk_avg: 12 }] },
    tcp: { total_packets: 3, expert_hints: [], resets: 0, retransmission_hints: 0 },
    dns: { query_count: 0, unique_domains: 0, nxdomain_rate: 0, suspicious: [] },
    http: { request_count: 0, external_cleartext_http_count: 0, suspicious: [] },
    tls: { packet_count: 3, deprecated_tls_count: 0, warnings: [], decryption: "not_performed" },
  })),
  getPacketFilterSuggestions: vi.fn(async () => ({ fields: ["tls.sni"], examples: ["protocol == TLS"] })),
  getSavedFilters: vi.fn(async () => [{ id: "builtin-1", name: "TLS traffic", expression: "protocol == TLS", is_builtin: true }]),
  searchPackets: vi.fn(async () => ({ total: 0, items: [] })),
  createSavedFilter: vi.fn(async () => ({})),
};

describe("ProtocolIntelligencePanel", () => {
  it("renders statistics, saved filters, and safe packet search", async () => {
    render(<ProtocolIntelligencePanel api={api} />);
    expect(await screen.findByText("Protocol statistics")).toBeInTheDocument();
    expect(screen.getByText("TLS traffic")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Packet search"), { target: { value: "TLS" } });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText("0 matches")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("raw-secret");
  });
});
