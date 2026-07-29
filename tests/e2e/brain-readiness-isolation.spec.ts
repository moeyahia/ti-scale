import { expect, test } from "./support/playwright";
import { createOfflineVaultProjectionFixture } from "./support/brainReadinessFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

interface BrainReadinessResponse {
  readonly dependencies: {
    readonly secondBrain: {
      readonly status: string;
      readonly canonicalStoreAvailable: boolean;
      readonly lexicalIndexSynchronized: boolean;
      readonly vaultProjection: {
        readonly status: string;
        readonly configuredConnections: number;
        readonly connectedConnections: number;
        readonly reachableConnections: number;
        readonly healthVerifiedConnections: number;
        readonly reason: string;
      };
    };
  };
}

test("optional Obsidian degradation stays visible without blocking canonical Brain mission readiness", async ({ page, browserAudit }, testInfo) => {
  const baselineResponse = await browserAudit.request(page.request, {
    method: "GET",
    url: "/api/v2/system/readiness",
  });
  expect(baselineResponse.status(), await baselineResponse.text()).toBe(200);
  const baseline = await baselineResponse.json() as BrainReadinessResponse;

  createOfflineVaultProjectionFixture(canonicalFixtureNamespace(testInfo, "brain-readiness-isolation"));

  const readinessResponse = await browserAudit.request(page.request, {
    method: "GET",
    url: "/api/v2/system/readiness",
  });
  expect(readinessResponse.status(), await readinessResponse.text()).toBe(200);
  const readiness = await readinessResponse.json() as BrainReadinessResponse;
  const beforeBrain = baseline.dependencies.secondBrain;
  const afterBrain = readiness.dependencies.secondBrain;
  const beforeVault = beforeBrain.vaultProjection;
  const afterVault = afterBrain.vaultProjection;
  const baselineHadUsableVault = beforeVault.healthVerifiedConnections > 0;

  expect(afterVault.configuredConnections).toBe(beforeVault.configuredConnections + 1);
  expect(afterVault.connectedConnections).toBe(beforeVault.connectedConnections + 1);
  expect(afterVault.reachableConnections).toBe(beforeVault.reachableConnections);
  expect(afterVault.healthVerifiedConnections).toBe(beforeVault.healthVerifiedConnections);
  expect(readiness.dependencies.secondBrain).toMatchObject({
    status: baselineHadUsableVault ? "healthy" : "degraded",
    canonicalStoreAvailable: true,
    lexicalIndexSynchronized: true,
    vaultProjection: {
      status: baselineHadUsableVault ? "healthy" : "degraded",
    },
  });
  expect(afterVault.reachableConnections).toBeLessThan(afterVault.connectedConnections);
  expect(afterVault.reason).toContain(
    baselineHadUsableVault
      ? "additional active connection"
      : "unavailable or outside the configured Vault sandbox",
  );
  const csrf = (await page.context().cookies())
    .find(({ name }) => name === "ti_scale_csrf")?.value;
  expect(csrf, "The authenticated E2E session must carry its CSRF proof").toBeTruthy();

  const resolveResponse = await browserAudit.request(page.request, {
    method: "POST",
    url: "/api/v2/registries/intake/resolve",
    options: {
      headers: { "X-Ti-Scale-CSRF": csrf! },
      data: {
        journey: "autonomous",
        authorizationAcknowledged: true,
        targets: [{ value: "lab:brain-readiness-isolation" }],
      },
    },
  });
  expect(resolveResponse.status(), await resolveResponse.text()).toBe(200);
  const resolved = await resolveResponse.json() as { request: Record<string, unknown> };

  const preflightResponse = await browserAudit.request(page.request, {
    method: "POST",
    url: "/api/v2/missions/autonomous/preflight",
    options: {
      headers: { "X-Ti-Scale-CSRF": csrf! },
      data: resolved.request,
    },
  });
  expect(preflightResponse.status(), await preflightResponse.text()).toBe(200);
  const preflight = await preflightResponse.json() as {
    readiness: { checks: Array<{ id: string; status: string; impact: string }> };
  };
  expect(preflight.readiness.checks.find(({ id }) => id === "memory_policy")).toMatchObject({
    status: "pass",
    impact: "Requested memory scopes will be filtered to confirmed memories and verified lessons.",
  });
});
