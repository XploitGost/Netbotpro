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
          packet_queue: {
            max_size: 100,
            current_depth: 20,
            utilization_percent: 20,
            dropped_total: 0,
            high_water_mark: 25,
            accepted_total: 42,
            overflow_policy: "drop_oldest",
            worker_alive: true,
            health: "healthy",
          },
          event_aggregator: {
            packet_batch_ms: 500,
            packet_batch_max: 250,
            alert_batch_ms: 500,
            alert_batch_max: 100,
            batches_sent_total: 3,
            events_received_total: 42,
            events_sent_total: 40,
            health: "healthy",
          },
          websocket: {
            clients: 1,
            slow_clients: 0,
            client_queue_max: 1000,
            send_latency_ms_p95: 4,
            health: "healthy",
          },
        }}
        onRefresh={onRefresh}
      />
    );

    expect(screen.getAllByText("Runtime Health").length).toBeGreaterThan(0);
    expect(screen.getByText("60s")).toBeTruthy();
    expect(screen.getByText("Capture and Flow Pressure")).toBeTruthy();
    expect(screen.getByText("Packet Intake Queue")).toBeTruthy();
    expect(screen.getByText("WebSocket Event Aggregator")).toBeTruthy();
    expect(screen.getByText("Batches Sent")).toBeTruthy();
    expect(screen.getAllByText("20/100").length).toBeGreaterThan(0);
    expect(screen.getByText("queue backlog high")).toBeTruthy();
    expect(screen.getByText("Review runtime pressure signals reported by the backend.")).toBeTruthy();
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

  it("recommends checking websocket subscribers when stream events have no listeners", () => {
    render(
      <OpsPanel
        observability={{
          event_bus: {
            subscribers: 0,
            published_messages: 10,
            dropped_messages: 0,
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

    expect(screen.getByText("Open the live dashboard or verify websocket subscribers are connected.")).toBeTruthy();
  });

  it("recommends checking persistence when the write queue is backing up", () => {
    render(
      <OpsPanel
        observability={{
          persistence: {
            queue_size: 300,
            utilization_percent: 85,
            dropped_writes: 0,
            flush_errors: 0,
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

    expect(screen.getByText("Persistence backlog is growing. Increase batch size, reduce capture pressure, or inspect database performance.")).toBeTruthy();
  });

  it("renders batch persistence latency, failures, and flow write metrics", () => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "degraded",
          capture: { running: true },
          flows: { risk_distribution: {} },
          persistence: {
            persistence_enabled: true,
            queue_max: 5000,
            queue_depth: 50,
            queue_utilization_percent: 1,
            events_received_total: 700,
            events_written_total: 698,
            events_failed_total: 2,
            batches_written_total: 4,
            write_latency_p95_ms: 18.5,
            write_latency_avg_ms: 7.2,
            retry_total: 1,
            backlog_age_ms: 20,
            overflow_policy: "drop_oldest",
            worker_alive: true,
            health: "degraded",
            flows: { flush_batches: 4, persisted_total: 20, failed_total: 0 },
          },
        }}
      />
    );

    expect(screen.getByText("Queue Max")).toBeTruthy();
    expect(screen.getAllByText("5000").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Events Received").length).toBeGreaterThan(0);
    expect(screen.getByText("Events Written")).toBeTruthy();
    expect(screen.getByText("Failed Writes")).toBeTruthy();
    expect(screen.getByText("Write Latency p95")).toBeTruthy();
    expect(screen.getByText("18.5 ms")).toBeTruthy();
    expect(screen.getByText("Pressure Reasons")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/authorization|cookie|raw-secret/i);
  });

  it.each([
    [
      { utilization_percent: 85 },
      "Persistence backlog is growing. Increase batch size, reduce capture pressure, or inspect database performance.",
    ],
    [
      { events_failed_total: 1 },
      "Persistence writes are failing. Inspect backend logs and database availability.",
    ],
    [
      { events_dropped_total: 1 },
      "Persistence events were dropped due to storage pressure. Review queue size and overflow policy.",
    ],
    [
      { write_latency_ms_avg: 300 },
      "Storage writes are slow. Check disk speed, database locks, and batch flush intervals.",
    ],
  ])("renders persistence operational action %#", (persistence, expected) => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "degraded",
          capture: { running: true },
          flows: { risk_distribution: {} },
          persistence: {
            enabled: true,
            queue_depth: 1,
            queue_max: 5000,
            worker_alive: true,
            health: "degraded",
            ...persistence,
          },
        }}
      />
    );
    expect(screen.getByText(expected)).toBeTruthy();
  });

  it.each(["healthy", "degraded", "critical"])(
    "renders persistence %s health",
    (health) => {
      render(
        <OpsPanel
          observability={{}}
          operationalMetrics={{
            generated_at: "2026-06-17T10:01:00Z",
            health,
            capture: { running: true },
            flows: { risk_distribution: {} },
            persistence: { enabled: true, health, worker_alive: true },
          }}
        />
      );
      expect(screen.getAllByText(health).length).toBeGreaterThan(0);
    }
  );

  it("renders packet queue pressure and action", () => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "degraded",
          capture: { running: true },
          flows: { risk_distribution: {} },
          packet_queue: {
            max_size: 100,
            current_depth: 85,
            utilization_percent: 85,
            dropped_total: 0,
            high_water_mark: 90,
            overflow_policy: "drop_oldest",
            worker_alive: true,
            health: "degraded",
          },
        }}
      />
    );

    expect(screen.getByText("Packet Intake Queue")).toBeTruthy();
    expect(screen.getAllByText("85/100").length).toBeGreaterThan(0);
    expect(screen.getByText("Increase queue size, reduce capture rate, or enable batching before heavier workloads.")).toBeTruthy();
  });

  it("renders dropped packet and worker warnings without secrets", () => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "critical",
          capture: { running: true },
          flows: { risk_distribution: {} },
          packet_queue: {
            max_size: 100,
            current_depth: 5,
            utilization_percent: 5,
            dropped_total: 2,
            dropped_oldest_total: 1,
            dropped_newest_total: 1,
            high_water_mark: 95,
            accepted_total: 200,
            overflow_policy: "drop_newest",
            worker_alive: false,
            last_drop_reason: "queue_full_drop_newest",
            health: "critical",
          },
        }}
      />
    );

    expect(screen.getByText("Dropped Packets")).toBeTruthy();
    expect(screen.getByText("Packet drops were detected. Review overflow policy, queue size, and capture pressure.")).toBeTruthy();
    expect(screen.getByText("Packet queue worker is not running. Restart capture or inspect backend logs.")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/token|authorization|cookie|secret/i);
  });

  it("renders websocket pressure warnings without sensitive values", () => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "degraded",
          capture: { running: true },
          flows: { risk_distribution: {} },
          event_aggregator: {
            packet_batch_ms: 500,
            packet_batch_max: 250,
            alert_batch_ms: 500,
            alert_batch_max: 100,
            batches_sent_total: 8,
            events_received_total: 500,
            events_sent_total: 450,
            events_coalesced_total: 20,
            events_dropped_total: 5,
            websocket_batch_size_avg: 56.2,
            last_drop_reason: "Authorization: Bearer raw-token",
            health: "degraded",
          },
          websocket: {
            clients: 2,
            slow_clients: 1,
            client_queue_max: 1000,
            client_queue_depth_max: 900,
            send_latency_ms_p50: 30,
            send_latency_ms_p95: 300,
            dropped_for_slow_client_total: 5,
            coalesced_for_slow_client_total: 2,
            last_drop_reason: "client_queue_full_coalesce",
            health: "degraded",
          },
        }}
      />
    );

    expect(screen.getByText("WebSocket Event Aggregator")).toBeTruthy();
    expect(screen.getByText("One or more WebSocket clients are slow. Reduce realtime update pressure or inspect frontend performance.")).toBeTruthy();
    expect(screen.getByText("Realtime event drops were detected. Review batch size, batch interval, and client queue settings.")).toBeTruthy();
    expect(screen.getByText("Realtime updates are being coalesced to protect performance. Consider increasing batch windows or reducing capture pressure.")).toBeTruthy();
    expect(screen.getByText("WebSocket send latency is high. Check browser load, network latency, and backend event pressure.")).toBeTruthy();
    expect(screen.getByText("client_queue_full_coalesce")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/raw-token|authorization/i);
  });

  it("renders high-water queue warning and hides unsafe drop reason text", () => {
    render(
      <OpsPanel
        observability={{}}
        operationalMetrics={{
          generated_at: "2026-06-17T10:01:00Z",
          health: "degraded",
          capture: { running: true },
          flows: { risk_distribution: {} },
          packet_queue: {
            max_size: 100,
            current_depth: 10,
            utilization_percent: 10,
            dropped_total: 0,
            high_water_mark: 95,
            accepted_total: 200,
            overflow_policy: "drop_oldest",
            worker_alive: true,
            last_drop_reason: "Authorization: Bearer raw-token",
            health: "degraded",
          },
        }}
      />
    );

    expect(screen.getByText("Queue pressure is approaching capacity. Consider increasing NETBOT_PACKET_QUEUE_MAX_SIZE.")).toBeTruthy();
    expect(screen.getAllByText("No drops recorded").length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toMatch(/raw-token|authorization/i);
  });
});
