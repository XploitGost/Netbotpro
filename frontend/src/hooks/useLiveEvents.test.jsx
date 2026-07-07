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
});
