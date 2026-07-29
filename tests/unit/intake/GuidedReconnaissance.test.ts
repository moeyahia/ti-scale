import { describe, expect, test } from "bun:test";
import { MissionIntakeService, MissionIntakeValidationError } from "../../../server/intake/MissionIntakeService";
import { validateMissionIntakeRequest } from "../../../server/intake/validation";
import { completeRuntimeManifests } from "../domain/fixtures";

function service(): MissionIntakeService {
  return new MissionIntakeService({
    readRuntimeManifests: () => completeRuntimeManifests(),
    clock: () => new Date("2026-07-20T12:00:00.000Z"),
  });
}

describe("Guided first reconnaissance step", () => {
  test("publishes versioned readable presets and an explicit unavailable manual fallback", () => {
    const registry = service().snapshot("guided", "safe_recon").guidedReconnaissance;
    expect(registry.registryVersion).toBe(1);
    expect(registry.tcpPortPresets.map(({ id, version }) => ({ id, version }))).toEqual([
      { id: "focused_services", version: 1 },
      { id: "web_services", version: 1 },
      { id: "remote_management", version: 1 },
    ]);
    expect(registry.tcpPortPresets.every(({ description }) => description.length > 60)).toBeTrue();
    expect(registry.modes.find(({ id }) => id === "tcp_service_scan")).toMatchObject({
      toolId: "kali:nmap-tcp-connect-service-scan",
      readiness: "unavailable",
      manualFallbackAvailable: true,
    });
    expect(registry.modes.find(({ id }) => id === "tcp_service_scan")?.remediation)
      .toContain("fresh activation receipt");
  });

  test("keeps existing target-derived behavior when the optional selection is absent", () => {
    const resolved = service().resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "lab.example.test" }],
      executionPreference: "single_step_agent",
    });
    expect(resolved.request.journey).toBe("guided");
    if (resolved.request.journey !== "guided") throw new Error("Expected Guided request");
    expect(resolved.request.guidedReconnaissance).toBeUndefined();
  });

  test("normalizes a custom individual-port list and preserves its source", () => {
    const request = validateMissionIntakeRequest({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.20" }],
      executionPreference: "single_step_agent",
      guidedReconnaissance: {
        mode: "tcp_service_scan",
        portSelection: { source: "custom", ports: [8443, 22, 443, 22] },
      },
    });
    const resolved = service().resolve(request);
    expect(resolved.request.journey).toBe("guided");
    if (resolved.request.journey !== "guided") throw new Error("Expected Guided request");
    expect(resolved.request.guidedReconnaissance).toEqual({
      mode: "tcp_service_scan",
      portSelection: { source: "custom", ports: [22, 443, 8443] },
    });
  });

  test("rejects preset drift, ranges disguised as values, and non-host targets with correction guidance", () => {
    expect(() => validateMissionIntakeRequest({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.20" }],
      guidedReconnaissance: {
        mode: "tcp_service_scan",
        portSelection: {
          source: "preset",
          presetId: "focused_services",
          presetVersion: 1,
          ports: [22, 80],
        },
      },
    })).toThrow("does not match reviewed preset");

    expect(() => validateMissionIntakeRequest({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.20" }],
      guidedReconnaissance: {
        mode: "tcp_service_scan",
        portSelection: { source: "custom", ports: ["1-1024"] },
      },
    })).toThrow("Use individual ports such as 22, 80, and 443");

    expect(() => service().resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "https://lab.example.test" }],
      guidedReconnaissance: { mode: "host_liveness" },
    })).toThrow(MissionIntakeValidationError);
    expect(() => service().resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "https://lab.example.test" }],
      guidedReconnaissance: { mode: "host_liveness" },
    })).toThrow("requires one host, IP address, or hostname");
  });
});
