// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AgentsPanel, agentAddress } from "./AgentsPanel";

afterEach(() => {
  cleanup();
});

describe("AgentsPanel", () => {
  it('reads real telemetry addresses without selecting loopback or MAC addresses', () => {
    expect(agentAddress({last_telemetry:{network:{interfaces:[{addresses:['127.0.0.1','00:11:22:33:44:55','192.168.1.8']}]}}})).toBe('192.168.1.8');
    expect(agentAddress({})).toBe('-');
    expect(agentAddress({ip_address:'10.0.0.2'})).toBe('10.0.0.2');
  });
  it('renders capture packet_count and preserves zero', () => {
    render(<AgentsPanel agents={[{agent_id:'real-agent',last_telemetry:{capture:{packet_count:0}}}]} onSelectAgent={vi.fn()} />);
    expect(screen.getByRole('columnheader',{name:'Packets'})).toBeTruthy();
    const row=screen.getByText('real-agent',{selector:'button'}).closest('tr');
    expect(row.cells[4].textContent).toBe('0');
  });
  it("renders a useful empty state without token or raw payload fields", () => {
    const seedDemoFleet = vi.fn();
    render(
      <AgentsPanel
        agents={[]}
        overview={{ total_agents: 0 }}
        onRefresh={vi.fn()}
        onSelectAgent={vi.fn()}
        onSeedDemoFleet={seedDemoFleet}
      />
    );

    expect(screen.getByText("No Agents Registered")).toBeTruthy();
    const seedButton = screen.getByRole("button", { name: "Seed demo fleet" });
    seedButton.click();
    expect(seedDemoFleet).toHaveBeenCalledOnce();
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
