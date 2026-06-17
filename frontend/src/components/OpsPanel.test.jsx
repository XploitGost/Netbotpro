// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OpsPanel } from "./OpsPanel";

afterEach(cleanup);

describe("OpsPanel", () => {
  it("renders the protected monitoring metrics snapshot and refresh control", () => {
    const onRefresh = vi.fn();
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:00:00Z",
          health: "degraded",
          pressure_reasons: ["queue backlog high"],
          capture: {
            running: true,
            interface: "Ethernet",
            total_packets: 42,
            total_alerts: 2,
          },
          flows: {
            total: 7,
            active: 3,
            external: 2,
            risk_distribution: { high: 1, critical: 0 },
          },
        }}
        onRefresh={onRefresh}
      />
    );

    expect(screen.getAllByText("Runtime Health").length).toBeGreaterThan(0);
    expect(screen.getByText("Capture and Flow Pressure")).toBeTruthy();
    expect(screen.getByText("queue backlog high")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect(onRefresh).toHaveBeenCalledOnce();
    expect(document.body.textContent).not.toMatch(/token|authorization|cookie/i);
  });

  it("disables refresh while a metrics request is in flight", () => {
    render(<OpsPanel observability={{}} isRefreshing onRefresh={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Refreshing..." }).disabled).toBe(true);
  });
});
