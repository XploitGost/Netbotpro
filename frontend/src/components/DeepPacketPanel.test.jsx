import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DeepPacketPanel } from "./DeepPacketPanel";

const api = {
  apiBase: "/api",
  getPacketDissection: vi.fn(async () => ({
    protocol_stack: ["Ethernet", "IPv4", "TCP", "HTTP"],
    summary: "GET /login?token=[REDACTED]",
    direction: "outbound",
    related_flow_id: "flow-1",
    layers: [{ name: "HTTP", summary: "GET /login", fields: [{ label: "Path", key: "http.path", display_value: "/login?token=[REDACTED]", byte_range: [], severity: "info" }] }],
    hex: { warning: "ASCII is always redacted.", rows: [{ offset: "0000", hex: "47 45 54", ascii_redacted: "GET" }] },
    expert_items: [{ severity: "warn", category: "security", message: "Cleartext HTTP to an external destination" }],
  })),
  getFlowStream: vi.fn(async () => ({ warnings: ["Stream previews are redacted."], chunks: [] })),
};

describe("DeepPacketPanel", () => {
  it("renders packet tree, hex, and expert views without secrets", async () => {
    render(<DeepPacketPanel api={api} packetId="pkt-1" />);
    expect(await screen.findByText("Ethernet / IPv4 / TCP / HTTP")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Hex / Bytes" }));
    expect(screen.getByText("47 45 54")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Expert Info" }));
    expect(screen.getByText("Cleartext HTTP to an external destination")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("raw-secret");
  });
});
