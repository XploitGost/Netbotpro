// @vitest-environment jsdom
import { cleanup, renderHook } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { useApiClient } from "./useApiClient";

const fixture = vi.hoisted(() => ({ base: "/api" }));
vi.mock("../lib/runtimeConfig", () => ({ getApiBase: () => fixture.base, getManagedLocalToken: () => "", isManagedLocalToken: () => false }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); fixture.base = "/api"; });

it("keeps API identity stable across unrelated renders but updates authentication", () => {
  const { result, rerender } = renderHook(({ token }) => useApiClient(token), { initialProps: { token: "fixture" } });
  const original = result.current;
  rerender({ token: "fixture" });
  expect(result.current).toBe(original);
  rerender({ token: "new-fixture" });
  expect(result.current).not.toBe(original);
  const authenticated = result.current;
  fixture.base = "/other-api";
  rerender({ token: "new-fixture" });
  expect(result.current).not.toBe(authenticated);
});

it("passes cancellation and auth to history requests", async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: true, headers: new Headers({ "content-type": "application/json" }), json: async () => ({ items: [] }) });
  vi.stubGlobal("fetch", fetch);
  const { result } = renderHook(() => useApiClient("fixture"));
  const controller = new AbortController();
  await result.current.getPackets(new URLSearchParams({ offset: "0" }), { signal: controller.signal });
  expect(fetch.mock.calls[0][1].signal).toBe(controller.signal);
  expect(fetch.mock.calls[0][1].headers["X-NetBot-Token"]).toBe("fixture");
});
