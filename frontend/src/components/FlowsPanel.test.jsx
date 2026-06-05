// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FlowsPanel } from "./FlowsPanel";

afterEach(cleanup);

const emptyApi = {
  getFlows: vi.fn(async () => ({ items: [] })),
  getFlowsSummary: vi.fn(async () => ({ total_flows: 0, risk_distribution: {} })),
  getFlow: vi.fn(),
  getFlowTimeline: vi.fn(),
};

describe("FlowsPanel", () => {
  it("renders filters and an empty state", async () => {
    render(<FlowsPanel api={emptyApi} />);
    expect(screen.getByLabelText("Protocol filter")).toBeTruthy();
    expect(screen.getByLabelText("Risk filter")).toBeTruthy();
    await waitFor(() => expect(screen.getByText("No flows observed")).toBeTruthy());
  });

  it("renders risk badges and keeps sensitive values out of details", async () => {
    const flow = {
      flow_id: "flow-1",
      app_protocol: "HTTP",
      transport: "TCP",
      src_ip: "10.0.0.2",
      dst_ip: "203.0.113.10",
      src_port: 50000,
      dst_port: 80,
      direction: "outbound",
      packets_count: 4,
      bytes_total: 900,
      bytes_sent: 700,
      bytes_received: 200,
      duration_ms: 120,
      risk_score: 65,
      risk_level: "high",
      risk_reasons: ["Unusual outbound destination"],
      metadata: { path: "/login?token=[REDACTED]" },
      related_alert_ids: [],
    };
    const api = {
      ...emptyApi,
      getFlows: vi.fn(async () => ({ items: [flow] })),
      getFlowsSummary: vi.fn(async () => ({ total_flows: 1, external_flows: 1, risk_distribution: { high: 1 }, top_protocols: [{ protocol: "HTTP" }] })),
      getFlow: vi.fn(async () => flow),
      getFlowTimeline: vi.fn(async () => ({ items: [] })),
    };
    render(<FlowsPanel api={api} />);
    await waitFor(() => expect(screen.getByText("65 high")).toBeTruthy());
    expect(document.body.textContent).toContain("[REDACTED]");
    expect(document.body.textContent).not.toContain("Bearer real-secret");
  });
});
