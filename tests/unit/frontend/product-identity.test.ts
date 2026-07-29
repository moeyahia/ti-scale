import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  PRODUCT_BRAND_LINE,
  PRODUCT_DESCRIPTOR,
  PRODUCT_NAME,
  PRODUCT_RELEASE_LABEL,
  PRODUCT_WORDMARK,
} from "../../../src/lib/productIdentity";
import { TI_SCALE_BROWSER_NAMESPACE } from "../../../src/lib/browserNamespaces";

const surfacePaths = [
  "../../../src/app/shell/AppShell.tsx",
  "../../../src/app/providers/AuthProvider.tsx",
  "../../../src/app/ErrorBoundary.tsx",
  "../../../src/app/router/RouteView.tsx",
  "../../../src/features/brain/BrainControlPage.tsx",
  "../../../src/features/brain/BrainGraphPage.tsx",
  "../../../src/features/brain/BrainVaultPage.tsx",
  "../../../src/features/overview/OverviewPage.tsx",
  "../../../src/features/manual/UserManualPage.tsx",
  "../../../src/features/missions/DirectPlanEditor.tsx",
  "../../../src/features/missions/RegistryMissionIntakePage.tsx",
  "../../../src/features/missions/MissionPortfolioPage.tsx",
  "../../../src/features/run-intelligence/ArtifactIntelligenceSurface.tsx",
  "../../../src/features/runs/CompletionReview.tsx",
  "../../../src/features/system/SystemPage.tsx",
] as const;

function source(path: string): string {
  return readFileSync(new URL(path, import.meta.url), "utf8");
}

describe("Ti-Scale product identity", () => {
  test("publishes one consistent user-facing identity", () => {
    expect({
      name: PRODUCT_NAME,
      wordmark: PRODUCT_WORDMARK,
      descriptor: PRODUCT_DESCRIPTOR,
      brandLine: PRODUCT_BRAND_LINE,
      releaseLabel: PRODUCT_RELEASE_LABEL,
    }).toEqual({
      name: "Ti-Scale",
      wordmark: "TI-SCALE",
      descriptor: "Command Intelligence",
      brandLine: "TI-SCALE // COMMAND INTELLIGENCE",
      releaseLabel: "Command Intelligence · 2.4 live",
    });
  });

  test("keeps audited surfaces standalone and consistently branded", () => {
    const auditedSurfaceCopy = surfacePaths
      .map(source)
      .join("\n")
      .replaceAll("Ti-Scale-Brain", "existing-vault-path");

    expect(auditedSurfaceCopy).toContain("Ti-Scale");
    for (const disallowed of ["parallel preview", "isolated V2", "legacy application", "V2 preview"]) {
      expect(auditedSurfaceCopy).not.toContain(disallowed);
    }
  });

  test("uses standalone namespaces and attack-centric vault guidance", () => {
    expect(TI_SCALE_BROWSER_NAMESPACE).toBe("ti-scale");
    expect(source("../../../src/data/api/client.ts")).toContain("ti_scale_csrf=");
    expect(source("../../../src/features/brain/BrainVaultPage.tsx")).toContain("Attack Knowledge Vault");
    expect(source("../../../src/features/brain/BrainVaultPage.tsx")).toContain('placeholder="Custom-Research-Vault"');
  });
});
