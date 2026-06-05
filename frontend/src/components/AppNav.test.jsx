// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AppNav } from "./AppNav";

afterEach(() => {
  cleanup();
});

describe("AppNav", () => {
  it("renders the main workspaces and marks the active page", () => {
    render(<AppNav activePage="monitor" onNavigate={() => {}} />);

    expect(screen.getByText("NetBotPro Web")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Monitor" }).className).toContain("primary");
    expect(screen.getByRole("button", { name: "Inspect" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Flows" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reports" })).toBeTruthy();
  });

  it("notifies the controller when an analyst changes workspace", () => {
    const onNavigate = vi.fn();
    render(<AppNav activePage="monitor" onNavigate={onNavigate} />);

    fireEvent.click(screen.getByRole("button", { name: "Reports" }));

    expect(onNavigate).toHaveBeenCalledWith("reports");
  });
});
