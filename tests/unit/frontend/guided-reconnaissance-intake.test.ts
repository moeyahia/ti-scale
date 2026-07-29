import { describe, expect, test } from "bun:test";
import { MissionIntakeService } from "../../../server/intake/MissionIntakeService";
import {
  parseIntakeRegistrySnapshot,
  parseResolvedMissionIntake,
} from "../../../src/domain/schemas/intake";

describe("Guided reconnaissance intake client contract", () => {
  test("parses the server-owned registry and exact normalized selection without a duplicated UI preset", () => {
    const service = new MissionIntakeService();
    const registry = parseIntakeRegistrySnapshot(service.snapshot("guided", "safe_recon"));
    expect(registry.guidedReconnaissance.registryVersion).toBe(1);
    expect(registry.guidedReconnaissance.tcpPortPresets[0]).toMatchObject({
      id: "focused_services",
      version: 1,
      ports: [22, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443],
    });

    const resolved = parseResolvedMissionIntake(service.resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.20" }],
      guidedReconnaissance: {
        mode: "tcp_service_scan",
        portSelection: { source: "custom", ports: [8443, 22, 443, 22] },
      },
    }));
    expect(resolved.request.journey).toBe("guided");
    if (resolved.request.journey !== "guided") throw new Error("Expected Guided request");
    expect(resolved.request.guidedReconnaissance).toEqual({
      mode: "tcp_service_scan",
      portSelection: { source: "custom", ports: [22, 443, 8443] },
    });
  });
});
