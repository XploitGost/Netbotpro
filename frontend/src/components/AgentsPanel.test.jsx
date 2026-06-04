// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AgentsPanel } from "./AgentsPanel";

afterEach(() => {
  cleanup();
});

describe("AgentsPanel", () => {
  it("renders a useful empty state without token or raw payload fields", () => {
    render(
      <AgentsPanel
        agents={[]}
        overview={{ total_agents: 0 }}
        onRefresh={vi.fn()}
        onSelectAgent={vi.fn()}
      />
    );

    expect(screen.getByText("No Agents Registered")).toBeTruthy();
    expect(screen.getByText(/seed-agent-demo.ps1/)).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/token:/i);
    expect(document.body.textContent).not.toMatch(/raw payload/i);
  });

  it("shows demo mode and export controls for seeded fleets", () => {
    render(
      <AgentsPanel
        agents={[
          {
            agent_id: "agent-1",
            display_name: "Web Server",
            hostname: "web-demo-01",
            status: "online",
            os: "Ubuntu",
            last_seen: "2026-01-01T00:00:00+00:00",
            last_telemetry: {
              health: { cpu_percent: 20, memory_percent: 30, disk_percent: 40 },
              capture: { capture_running: true, capture_mode: "metadata" },
              alerts_summary: { total_alerts: 0 },
            },
            risk: { score: 0, severity: "low" },
          },
        ]}
        overview={{ total_agents: 1, online_agents: 1, offline_agents: 0, demo_data: true }}
        onRefresh={vi.fn()}
        onSelectAgent={vi.fn()}
        onExportFleetSummary={vi.fn()}
      />
    );

    expect(screen.getByText("Demo data")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Export summary" })).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/X-NetBot-Agent-Token/i);
  });
});
