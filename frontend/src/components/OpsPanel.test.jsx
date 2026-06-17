// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { OpsPanel } from "./OpsPanel";

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-06-17T10:01:00Z"));
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

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
    expect(screen.getByText("60s")).toBeTruthy();
    expect(screen.getByText("Capture and Flow Pressure")).toBeTruthy();
    expect(screen.getByText("queue backlog high")).toBeTruthy();
    expect(screen.getByText("Review high-risk flows for unusual destinations.")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect(onRefresh).toHaveBeenCalledOnce();
    expect(document.body.textContent).not.toMatch(/token|authorization|cookie/i);
  });

  it("disables refresh while a metrics request is in flight", () => {
    render(<OpsPanel observability={{}} isRefreshing onRefresh={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Refreshing..." }).disabled).toBe(true);
  });

  it("marks an old backend snapshot as stale", () => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T09:55:00Z",
          health: "healthy",
          capture: {},
          flows: {},
        }}
      />
    );

    expect(screen.getByText("Snapshot may be stale")).toBeTruthy();
    expect(screen.getByText("Degraded")).toBeTruthy();
  });

  it("treats critical flow pressure as degraded in the summary", () => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "healthy",
          capture: {},
          flows: {
            total: 2,
            active: 1,
            external: 1,
            risk_distribution: { high: 0, critical: 1 },
          },
        }}
      />
    );

    const flowsCard = screen.getByText("Flows").closest("article");
    expect(flowsCard?.className).toContain("ops-degraded");
    expect(screen.getByText("Review critical flows and related alerts first.")).toBeTruthy();
  });

  it("shows a calm action when the ops snapshot is healthy", () => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "healthy",
          capture: { running: true },
          flows: {
            total: 0,
            active: 0,
            external: 0,
            risk_distribution: {},
          },
        }}
      />
    );

    expect(screen.getByText("No immediate action needed.")).toBeTruthy();
  });

  it("recommends checking capture when monitoring is stopped", () => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "healthy",
          capture: { running: false },
          flows: {
            total: 0,
            active: 0,
            external: 0,
            risk_distribution: {},
          },
        }}
      />
    );

    expect(screen.getByText("Start capture or confirm monitoring is intentionally paused.")).toBeTruthy();
  });

  it("recommends checking history storage when query latency is high", () => {
    render(
      <OpsPanel
        observability={{
          history: {
            packets_list: { last_ms: 220, errors: 0 },
            alerts_list: { last_ms: 20, errors: 0 },
          },
        }}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "healthy",
          capture: { running: true },
          flows: { risk_distribution: {} },
        }}
      />
    );

    expect(screen.getByText("Check history query latency and packet/alert storage load.")).toBeTruthy();
  });

  it("recommends checking firewall permissions when auto-block fails", () => {
    render(
      <OpsPanel
        observability={{
          auto_block: {
            failed_total: 2,
          },
        }}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "healthy",
          capture: { running: true },
          flows: { risk_distribution: {} },
        }}
      />
    );

    expect(screen.getByText("Review auto-block failures and firewall permissions.")).toBeTruthy();
  });
});
