import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { IncidentsPanel } from "./IncidentsPanel";

const incident = {
  incident_id: "inc-1",
  title: "Possible Beaconing",
  type: "possible_beaconing",
  severity: "high",
  confidence: "high",
  status: "open",
  signal_count: 4,
  source_hosts: ["10.0.0.5"],
  applications: ["browser.exe"],
  services: ["Unknown encrypted destination"],
  domains: ["unknown.example"],
  evidence: ["Repeated outbound TLS", "token=raw-secret"],
  correlation_reasons: ["Same source host within correlation window"],
  recommended_investigation_steps: ["Review the destination."],
  false_positive_notes: ["Background updates may be periodic."],
  related_flows: ["flow-1"], related_alerts: ["alert-1"], related_agents: [],
  timeline: [{ timestamp: "2026-07-15T12:00:00Z", source: "alert", severity: "high", summary: "Bearer another-secret" }],
};

describe("IncidentsPanel", () => {
  it("renders an empty state", async () => {
    const api = { getIncidents: vi.fn().mockResolvedValue({ items: [] }), getIncident: vi.fn() };
    render(<IncidentsPanel api={api} />);
    expect(await screen.findByText("No correlated incidents")).toBeTruthy();
  });

  it("renders incident details, evidence, timeline, and masks sensitive mock data", async () => {
    const api = { getIncidents: vi.fn().mockResolvedValue({ items: [incident] }), getIncident: vi.fn().mockResolvedValue({ incident }) };
    render(<IncidentsPanel api={api} />);
    await screen.findAllByText("Possible Beaconing");
    await waitFor(() => expect(screen.getByText("Evidence")).toBeTruthy());
    expect(screen.getByText("Correlation reasons")).toBeTruthy();
    expect(screen.getByText("Timeline")).toBeTruthy();
    expect(screen.getByText("1 flows")).toBeTruthy();
    expect(document.body.textContent).not.toContain("raw-secret");
    expect(document.body.textContent).not.toContain("another-secret");
    expect(screen.getAllByText("high").length).toBeGreaterThan(0);
    fireEvent.click(screen.getAllByRole("button", { name: "Refresh incidents" }).at(-1));
    await waitFor(() => expect(api.getIncidents).toHaveBeenCalledTimes(2));
  });
});
