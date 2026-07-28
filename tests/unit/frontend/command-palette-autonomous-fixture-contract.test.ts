import { describe, expect, test } from "bun:test";
import { MissionIntakeService } from "../../../server/intake";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import { autonomousCommandPaletteReservedTarget } from "../../e2e/support/autonomousCommandPaletteFixture";
import { normalizeFixtureNamespace } from "../../e2e/support/fixtureNamespace";
import { completeRuntimeManifests } from "../domain/fixtures";

describe("Autonomous Command Palette fixture contract", () => {
  test("keeps a maximum-length Playwright namespace inside one executable reserved DNS label", () => {
    const observedAt = "2026-07-24T00:00:00.000Z";
    const namespace = normalizeFixtureNamespace(
      "chromium-1440-autonomous-command-palette-e2e-command-palette-autonomous-search-worker-0",
    );
    expect(namespace).toHaveLength(64);

    const target = autonomousCommandPaletteReservedTarget(namespace);
    expect(target.endsWith(".invalid")).toBe(true);
    expect(target.split(".")[0]!.length).toBeLessThanOrEqual(63);

    const resolved = new MissionIntakeService({
      readRuntimeManifests: () => completeRuntimeManifests({ catalogObservedAt: observedAt }),
      clock: () => new Date(observedAt),
    }).resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: target }],
      templateId: "safe_recon",
      title: "Autonomous palette fixture contract",
      objective: "Validate bounded Autonomous search without executing or contacting the represented target.",
    });

    expect(resolved.normalizedTargets).toEqual([
      expect.objectContaining({ type: "domain", value: target }),
    ]);
    const request = validateMissionCreateRequest(resolved.request);
    expect(request.journey).toBe("autonomous");
    if (request.journey !== "autonomous") throw new Error("Expected an Autonomous request");
    expect(request.contract.allowedActionClasses).toEqual([
      "dns_domain_certificate_discovery",
    ]);
  });
});
