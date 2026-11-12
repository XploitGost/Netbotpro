// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useDashboardController } from "./useDashboardController";

const fixture = vi.hoisted(() => ({ api: {}, live: null }));
vi.mock("./useApiClient", () => ({ useApiClient: () => fixture.api }));
vi.mock("./useLocalAuth", () => ({ useLocalAuth: () => ({ localToken: "fixture", setLocalToken: vi.fn(), managedLocalToken: true }) }));
vi.mock("./useLiveEvents", () => ({ useLiveEvents: (handlers) => { fixture.live = handlers; } }));

function page(id, offset = 0) {
  return { items: [{ id, proto: "ICMP", src: "192.0.2.1", dst: "198.51.100.1" }],
    total: 100, offset, limit: 25, source: "memory" };
}

beforeEach(() => {
  fixture.api = Object.fromEntries([
    "getStatus", "getDashboard", "getSettings", "getInterfaces", "getAgents", "getAgentsOverview",
    "getAgentAlertsSummary", "getAgentRiskSummary", "getMonitoringMetrics", "getReports", "getPackets", "getAlerts",
    "getPacketDetail", "getPacketContext", "getAlertDetail", "getAlertContext",
  ].map((key) => [key, vi.fn().mockResolvedValue({})]));
  fixture.api.getStatus.mockResolvedValue({ local_token_required: false });
  fixture.api.getDashboard.mockResolvedValue({ state: { packet_count: 100 }, recent_packets: page("initial").items, recent_alerts: [] });
  fixture.api.getPackets.mockImplementation((params) => Promise.resolve(page("page-" + params.get("offset"), Number(params.get("offset")))));
  fixture.api.getAlerts.mockResolvedValue({ items: [], total: 0, offset: 0, limit: 25 });
  fixture.live = null;
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

async function controller() {
  const hook = renderHook(() => useDashboardController());
  await waitFor(() => expect(hook.result.current.loadingState.bootstrap).toBe(false));
  return hook;
}

describe("dashboard live-follow continuity", () => {
  it("supports a desktop default without changing the standard default", async () => {
    const { result } = renderHook(() => useDashboardController({ defaultPage: "command" }));
    await waitFor(() => expect(result.current.loadingState.bootstrap).toBe(false));
    expect(result.current.activePage).toBe("command");
    expect(result.current.localTokenAccepted).toBe(true);
  });

  it("selects monitor evidence in place when navigation is disabled", async () => {
    const { result } = await controller();
    fixture.api.getPacketDetail.mockResolvedValue(page("detail").items[0]);
    await act(async () => result.current.loadPacketDetail(page("detail").items[0], 0, { navigate: false }));
    expect(result.current.activePage).toBe("monitor");
    expect(result.current.selectedPacketId).toBe("detail");
    await act(async () => result.current.loadPacketDetail(page("detail").items[0], 0));
    expect(result.current.activePage).toBe("inspect");
  });

  it("keeps a paused list stable while traffic counters continue", async () => {
    const { result } = await controller();
    act(() => result.current.freezeLiveFollow());
    act(() => fixture.live.onPacketsBatch([{ payload: page("new").items[0] }]));
    expect(result.current.packets[0].id).toBe("initial");
    expect(result.current.packetMeta.total).toBe(101);
  });

  it("resumes from an older page by fetching the newest filtered page", async () => {
    const { result } = await controller();
    act(() => result.current.handlePacketQueryChange("proto", "ICMP"));
    await act(async () => result.current.paginatePackets(1));
    expect(result.current.packetMeta.offset).toBe(25);
    await act(async () => result.current.toggleLiveFollow(true));
    expect(result.current.packetMeta.offset).toBe(0);
    expect(result.current.packets[0].id).toBe("page-0");
    expect(fixture.api.getPackets.mock.calls.at(-1)[0].get("proto")).toBe("ICMP");
    expect(fixture.api.getAlerts.mock.calls.at(-1)[0].get("offset")).toBe("0");
    act(() => fixture.live.onPacketsBatch([{ payload: page("new").items[0] }]));
    expect(result.current.packets[0].id).toBe("new");
  });

  it("does not claim live follow when resynchronization fails", async () => {
    const { result } = await controller();
    act(() => result.current.freezeLiveFollow());
    fixture.api.getPackets.mockRejectedValue(new Error("fixture history unavailable"));
    await act(async () => result.current.resumeLiveFollow());
    expect(result.current.liveFollow).toBe(false);
    expect(result.current.error).toContain("fixture history unavailable");
  });

  it("ignores a late resume response after the user pauses again", async () => {
    const { result } = await controller();
    let resolve;
    fixture.api.getPackets.mockReturnValue(new Promise((done) => { resolve = done; }));
    let pending;
    act(() => { pending = result.current.resumeLiveFollow(); });
    act(() => result.current.freezeLiveFollow());
    expect(fixture.api.getPackets.mock.calls.at(-1)[1].signal.aborted).toBe(true);
    await act(async () => { resolve(page("late")); await pending; });
    expect(result.current.liveFollow).toBe(false);
    expect(result.current.packets[0].id).toBe("initial");
    expect(result.current.loadingState.packets).toBe(false);
  });

  it("refreshes rather than reusing the history page cache", async () => {
    const { result } = await controller();
    await act(async () => result.current.applyPacketFilters());
    fixture.api.getPackets.mockResolvedValue(page("fresh"));
    await act(async () => result.current.resumeLiveFollow());
    expect(fixture.api.getPackets).toHaveBeenCalledTimes(2);
    expect(result.current.packets[0].id).toBe("fresh");
  });

  it("releases the loading state and cancels a stalled sibling after failure", async () => {
    const { result } = await controller();
    let resolve;
    fixture.api.getPackets.mockReturnValue(new Promise((done) => { resolve = done; }));
    fixture.api.getAlerts.mockRejectedValue(new Error("fixture alert history unavailable"));
    await act(async () => result.current.resumeLiveFollow());
    expect(result.current.loadingState.packets).toBe(false);
    expect(result.current.loadingState.alerts).toBe(false);
    expect(fixture.api.getPackets.mock.calls.at(-1)[1].signal.aborted).toBe(true);
    expect(result.current.statusMessage).toContain("remains paused");
    await act(async () => resolve(page("late")));
    expect(result.current.packets[0].id).toBe("initial");
  });

  it("cancels resynchronization when capture reset arrives", async () => {
    const { result } = await controller();
    let resolve;
    fixture.api.getPackets.mockReturnValue(new Promise((done) => { resolve = done; }));
    let pending;
    act(() => { pending = result.current.resumeLiveFollow(); });
    act(() => fixture.live.onState({ type: "sniffer:reset", payload: { running: false } }));
    await act(async () => { resolve(page("before-reset")); await pending; });
    expect(result.current.packets).toEqual([]);
    expect(result.current.liveFollow).toBe(true);
  });

  it("bounds an entirely stalled refresh and permits retry", async () => {
    const { result } = await controller();
    vi.useFakeTimers();
    let resolve;
    fixture.api.getPackets.mockReturnValue(new Promise((done) => { resolve = done; }));
    let pending;
    act(() => { pending = result.current.resumeLiveFollow(); });
    await act(async () => vi.advanceTimersByTime(8000));
    expect(result.current.liveFollow).toBe(false);
    expect(result.current.loadingState.packets).toBe(false);
    expect(result.current.error).toContain("timed out");
    expect(fixture.api.getPackets.mock.calls.at(-1)[1].signal.aborted).toBe(true);
    await act(async () => { resolve(page("late")); await pending; });
    fixture.api.getPackets.mockResolvedValue(page("retry"));
    await act(async () => result.current.resumeLiveFollow());
    expect(result.current.liveFollow).toBe(true);
    expect(result.current.packets[0].id).toBe("retry");
  });
});
