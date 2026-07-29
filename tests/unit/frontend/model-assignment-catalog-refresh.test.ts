import { describe, expect, test } from "bun:test";
import {
  catalogItemSelectableForAgent,
  fallbackSelectionIsValid,
  configurationReceiptLabel,
  currentCatalogEquivalent,
  reconcileSavedCatalogReceipt,
} from "../../../src/features/agents/modelAssignmentCatalogRefresh";
import type {
  ModelCatalogItem,
  ModelConfiguration,
} from "../../../src/domain/types/modelConfiguration";

const NOW = "2026-07-28T16:00:00.000Z";

function configured(overrides: Partial<ModelConfiguration> = {}): ModelConfiguration {
  return {
    id: "modelcfg-old-attestation",
    providerId: "provider:local",
    modelId: "policy:safe-recon",
    displayName: "Safe Recon",
    executionBoundary: "local_deterministic_policy",
    reasoningEffort: null,
    contextPolicy: {},
    capabilities: {
      displayName: "Safe Recon",
      executionBoundary: "local_deterministic_policy",
      toolCalling: false,
      structuredOutput: true,
      compatibleActionClassIds: ["active_host_discovery"],
      compatibleAgentIds: ["ReconScout"],
      supportedReasoningEfforts: [],
      localDeterministicActionClassIdsByAgent: {
        ReconScout: ["active_host_discovery"],
      },
    },
    contextLimit: null,
    costClass: "unknown",
    latencyClass: "unknown",
    disclosureClass: "local_only",
    enforcementMode: "enforced_executor",
    authState: "authenticated",
    healthState: "healthy",
    catalogSource: "runtime-source-manifest",
    catalogRetrievedAt: NOW,
    configurationSource: "manual",
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function catalog(overrides: Partial<ModelCatalogItem> = {}): ModelCatalogItem {
  return {
    configurationId: "modelcfg-current-attestation",
    providerId: "provider:local",
    modelId: "policy:safe-recon",
    displayName: "Safe Recon",
    executionBoundary: "local_deterministic_policy",
    reasoningEffort: null,
    supportedReasoningEfforts: [],
    contextLimit: null,
    costClass: "unknown",
    latencyClass: "unknown",
    disclosureClass: "local_only",
    enforcementMode: "enforced_executor",
    authState: "authenticated",
    healthState: "healthy",
    catalogSource: "runtime-source-manifest",
    catalogRetrievedAt: NOW,
    capabilities: {
      toolCalling: false,
      structuredOutput: true,
      compatibleActionClassIds: ["active_host_discovery"],
      localDeterministicActionClassIdsByAgent: {
        ReconScout: ["active_host_discovery"],
      },
    },
    compatibleAgentIds: ["ReconScout"],
    selectable: true,
    unavailableReasons: [],
    ...overrides,
  };
}

describe("agent model catalog-attestation refresh", () => {
  test("retains an exact current receipt when its immutable ID remains live", () => {
    const exact = catalog({ configurationId: "modelcfg-old-attestation" });
    expect(currentCatalogEquivalent(
      [exact],
      configured(),
      "ReconScout",
    )).toBe(exact);
  });

  test("stages the one current selectable route with the exact same execution tuple", () => {
    const renewed = catalog();
    expect(currentCatalogEquivalent(
      [renewed],
      configured(),
      "ReconScout",
    )).toBe(renewed);
    expect(configurationReceiptLabel(configured())).toContain(
      "provider:local · Safe Recon (policy:safe-recon)",
    );
    expect(configurationReceiptLabel(configured())).toContain(
      "modelcfg-old-attestation",
    );
    expect(reconcileSavedCatalogReceipt(
      [renewed],
      "modelcfg-old-attestation",
      configured(),
      "ReconScout",
    )).toEqual({
      state: "staged",
      item: renewed,
    });
  });

  test("derives refresh state only from the saved baseline receipt", () => {
    const saved = catalog({ configurationId: "modelcfg-old-attestation" });
    expect(reconcileSavedCatalogReceipt(
      [
        saved,
        catalog({
          configurationId: "operator-manual-selection",
          providerId: "provider:alternate",
        }),
      ],
      "modelcfg-old-attestation",
      configured(),
      "ReconScout",
    )).toEqual({
      state: "current",
      item: saved,
    });
  });

  test("requires a nonempty fallback to remain selectable for its scope", () => {
    expect(fallbackSelectionIsValid(
      [catalog()],
      "",
      "ReconScout",
    )).toBe(true);
    expect(fallbackSelectionIsValid(
      [catalog()],
      "missing-configuration",
      "ReconScout",
    )).toBe(false);
    expect(fallbackSelectionIsValid(
      [catalog({ selectable: false })],
      "modelcfg-current-attestation",
      "ReconScout",
    )).toBe(false);
    expect(fallbackSelectionIsValid(
      [catalog({ compatibleAgentIds: ["WebBreaker"] })],
      "modelcfg-current-attestation",
      "ReconScout",
    )).toBe(false);
  });

  test("fails a workspace default closed unless every canonical specialist is compatible", () => {
    const workspaceAgentIds = ["ReconScout", "WebBreaker"];
    const universal = catalog({
      compatibleAgentIds: workspaceAgentIds,
    });
    const partial = catalog({
      compatibleAgentIds: ["ReconScout"],
    });

    expect(catalogItemSelectableForAgent(
      universal,
      null,
      workspaceAgentIds,
    )).toBe(true);
    expect(catalogItemSelectableForAgent(
      partial,
      null,
      workspaceAgentIds,
    )).toBe(false);
    expect(catalogItemSelectableForAgent(universal, null)).toBe(false);
    expect(fallbackSelectionIsValid(
      [partial],
      partial.configurationId,
      null,
      workspaceAgentIds,
    )).toBe(false);
  });

  test("does not guess across ambiguous, incompatible, or materially changed routes", () => {
    expect(currentCatalogEquivalent(
      [
        catalog({ configurationId: "modelcfg-current-a" }),
        catalog({ configurationId: "modelcfg-current-b" }),
      ],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(currentCatalogEquivalent(
      [catalog({ compatibleAgentIds: ["WebBreaker"] })],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(currentCatalogEquivalent(
      [catalog({ reasoningEffort: "high" })],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(currentCatalogEquivalent(
      [catalog({ executionBoundary: "provider_tool_calling" })],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(currentCatalogEquivalent(
      [catalog({ enforcementMode: "advisor_only" })],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(currentCatalogEquivalent(
      [catalog({ disclosureClass: "public_only" })],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(currentCatalogEquivalent(
      [catalog({ contextLimit: 131_072 })],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(currentCatalogEquivalent(
      [catalog({
        capabilities: {
          ...catalog().capabilities,
          toolCalling: true,
        },
      })],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(currentCatalogEquivalent(
      [catalog({
        capabilities: {
          ...catalog().capabilities,
          compatibleActionClassIds: [
            "active_host_discovery",
            "port_service_enumeration",
          ],
        },
      })],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(currentCatalogEquivalent(
      [catalog({
        capabilities: {
          ...catalog().capabilities,
          localDeterministicActionClassIdsByAgent: {
            ReconScout: [
              "active_host_discovery",
              "port_service_enumeration",
            ],
          },
        },
      })],
      configured(),
      "ReconScout",
    )).toBeUndefined();
    expect(reconcileSavedCatalogReceipt(
      [catalog({ executionBoundary: "provider_tool_calling" })],
      "modelcfg-old-attestation",
      configured(),
      "ReconScout",
    )).toEqual({ state: "unresolved" });
  });
});
