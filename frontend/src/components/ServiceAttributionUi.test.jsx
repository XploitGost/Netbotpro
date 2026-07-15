// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { buildPacketInspectionModel } from "../lib/inspectionModel";
import { DetailPanel } from "./DetailPanel";

afterEach(cleanup);

describe("service attribution inspection", () => {
  it("renders explainable metadata-only attribution in Inspect", () => {
    const packet = {
      id: "packet-service-1",
      src: "10.0.0.5",
      dst: "203.0.113.20",
      sport: 52000,
      dport: 443,
      proto: "TCP",
      length: 144,
      service_attribution: {
        application_name: "chrome.exe",
        service_name: "YouTube",
        service_category: "Video Streaming",
        domain: "r1.googlevideo.com",
        attribution_confidence: "high",
        confidence_score: 95,
        attribution_sources: ["tls_sni", "dns", "fingerprint"],
        attribution_reasons: ["TLS SNI matched r1.googlevideo.com"],
        is_encrypted: true,
        is_unknown: false,
        is_cdn: false,
        credential: "Bearer raw-inspect-secret",
      },
    };

    render(
      <DetailPanel
        title="Packet Details"
        model={buildPacketInspectionModel(packet)}
        selectionKey={packet.id}
      />
    );

    expect(screen.getByText("Service Attribution")).toBeTruthy();
    expect(screen.getByText("YouTube")).toBeTruthy();
    expect(screen.getByText("Video Streaming")).toBeTruthy();
    expect(screen.getByText("r1.googlevideo.com")).toBeTruthy();
    expect(screen.getByText("tls_sni, dns, fingerprint")).toBeTruthy();
    expect(screen.getByText("TLS SNI matched r1.googlevideo.com")).toBeTruthy();
    expect(document.body.textContent).not.toContain("raw-inspect-secret");
  });

  it("labels an encrypted destination as unknown without guessing a service", () => {
    const model = buildPacketInspectionModel({
      id: "packet-service-2",
      src: "10.0.0.5",
      dst: "203.0.113.21",
      dport: 443,
      proto: "TCP",
      length: 80,
      service_attribution: {
        service_name: "Unknown encrypted destination",
        service_category: "Unknown",
        attribution_confidence: "low",
        confidence_score: 20,
        attribution_sources: [],
        attribution_reasons: ["No visible DNS, SNI, or HTTP Host evidence was available."],
        is_encrypted: true,
        is_unknown: true,
        is_cdn: false,
      },
    });

    render(<DetailPanel title="Packet Details" model={model} />);
    expect(screen.getByText("Unknown encrypted destination")).toBeTruthy();
    expect(screen.getByText("low")).toBeTruthy();
    expect(screen.getByText("No visible DNS, SNI, or HTTP Host evidence was available.")).toBeTruthy();
  });
});
