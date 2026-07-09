// @vitest-environment jsdom

import { cleanup, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useLiveEvents } from "./useLiveEvents";

class FakeWebSocket {
  static instances = [];

  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.readyState = 1;
    FakeWebSocket.instances.push(this);
    setTimeout(() => this.onopen?.(), 0);
  }

  close() {
    this.readyState = 3;
  }

  emit(data) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }
}

function Harness(props) {
  useLiveEvents({
    localToken: "local-token",
    onStatusChange: vi.fn(),
    ...props,
  });
  return <div>live</div>;
}

afterEach(() => {
  cleanup();
  FakeWebSocket.instances = [];
  vi.restoreAllMocks();
});

describe("useLiveEvents", () => {
  it("waits without opening a websocket while disabled", async () => {
    vi.stubGlobal("WebSocket", FakeWebSocket);
    const onStatusChange = vi.fn();

    render(<Harness enabled={false} onStatusChange={onStatusChange} />);

    await waitFor(() => {
      expect(FakeWebSocket.instances.length).toBe(0);
      expect(onStatusChange).toHaveBeenCalledWith(
        "waiting",
        "Enter the local token to start live stream"
      );
    });
  });

  it("processes packet and alert batch messages", async () => {
    vi.stubGlobal("WebSocket", FakeWebSocket);
    const onPacketsBatch = vi.fn();
    const onAlertsBatch = vi.fn();

    render(<Harness onPacketsBatch={onPacketsBatch} onAlertsBatch={onAlertsBatch} />);
    await waitFor(() => expect(FakeWebSocket.instances.length).toBe(1));

    FakeWebSocket.instances[0].emit({
      type: "packet_batch",
      events: [
        { type: "packet:new", payload: { id: "pkt-1" } },
        { type: "packet:new", payload: { id: "pkt-2" } },
      ],
    });
    FakeWebSocket.instances[0].emit({
      type: "alert_batch",
      events: [{ type: "alert:new", payload: { id: "alert-1" } }],
    });

    await waitFor(() => {
      expect(onPacketsBatch).toHaveBeenCalledWith([
        { type: "packet:new", payload: { id: "pkt-1" } },
        { type: "packet:new", payload: { id: "pkt-2" } },
      ]);
      expect(onAlertsBatch).toHaveBeenCalledWith([
        { type: "alert:new", payload: { id: "alert-1" } },
      ]);
    });
  });

  it("routes flow, dashboard, ops, and agent batch messages to state handlers", async () => {
    vi.stubGlobal("WebSocket", FakeWebSocket);
    const onState = vi.fn();

    render(<Harness onState={onState} />);
    await waitFor(() => expect(FakeWebSocket.instances.length).toBe(1));

    FakeWebSocket.instances[0].emit({
      type: "flow_delta",
      timestamp: "2026-07-07T00:00:00Z",
      updates: [{ type: "flow:updated", payload: { flow_id: "flow-1" } }],
    });
    FakeWebSocket.instances[0].emit({
      type: "dashboard_summary",
      timestamp: "2026-07-07T00:00:01Z",
      summary: { packet_count: 10 },
    });
    FakeWebSocket.instances[0].emit({
      type: "ops_health_update",
      timestamp: "2026-07-07T00:00:02Z",
      health: { health: "degraded" },
    });
    FakeWebSocket.instances[0].emit({
      type: "agent_status_batch",
      timestamp: "2026-07-07T00:00:03Z",
      agents: [{ type: "agent:status", payload: { agent_id: "agent-1" } }],
    });

    await waitFor(() => {
      expect(onState).toHaveBeenCalledWith({
        version: 1,
        type: "flow_delta",
        timestamp: "2026-07-07T00:00:00Z",
        payload: { updates: [{ type: "flow:updated", payload: { flow_id: "flow-1" } }] },
      });
      expect(onState).toHaveBeenCalledWith({
        version: 1,
        type: "dashboard:summary",
        timestamp: "2026-07-07T00:00:01Z",
        payload: { packet_count: 10 },
      });
      expect(onState).toHaveBeenCalledWith({
        version: 1,
        type: "ops:health",
        timestamp: "2026-07-07T00:00:02Z",
        payload: { health: "degraded" },
      });
      expect(onState).toHaveBeenCalledWith({
        version: 1,
        type: "agent:status_batch",
        timestamp: "2026-07-07T00:00:03Z",
        payload: { agents: [{ type: "agent:status", payload: { agent_id: "agent-1" } }] },
      });
    });
  });
});
