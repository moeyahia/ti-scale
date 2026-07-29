import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { parseAutonomousPlanningSelection } from "../../../src/domain/schemas/commandOs";
import {
  AUTONOMOUS_LOCAL_PLANNING_SELECTION,
  type AutonomousPlanningSelection,
} from "../../../src/domain/types/commandOs";
import type {
  ModelCatalog,
  ModelCatalogItem,
} from "../../../src/domain/types/modelConfiguration";
import {
  AutonomousPlanningSelectionEditor,
  AutonomousPlanningSelectionReview,
} from "../../../src/features/missions/AutonomousPlanningSelection";
import {
  configurationSelectableForPlanning,
  firstPlanningConfiguration,
  planningAgentIds,
  planningSelectionFromConfiguration,
  samePlanningSelection,
} from "../../../src/features/missions/autonomousPlanningSelectionState";

const OBSERVED_AT = "2026-07-28T12:00:00.000Z";

function item(input: Partial<ModelCatalogItem> & {
  configurationId: string;
  modelId: string;
}): ModelCatalogItem {
  return {
    configurationId: input.configurationId,
    providerId: input.providerId ?? "provider-advisory",
    modelId: input.modelId,
    displayName: input.displayName ?? input.modelId,
    executionBoundary: input.executionBoundary ?? "provider_tool_calling",
    reasoningEffort: input.reasoningEffort ?? null,
    supportedReasoningEfforts: input.supportedReasoningEfforts ?? ["low", "high"],
    contextLimit: input.contextLimit ?? 128_000,
    costClass: input.costClass ?? "standard",
    latencyClass: input.latencyClass ?? "standard",
    disclosureClass: input.disclosureClass ?? "sanitized_internal",
    enforcementMode: input.enforcementMode ?? "advisor_only",
    authState: input.authState ?? "authenticated",
    healthState: input.healthState ?? "healthy",
    catalogSource: input.catalogSource ?? "unit-live-catalog",
    catalogRetrievedAt: input.catalogRetrievedAt ?? OBSERVED_AT,
    capabilities: input.capabilities ?? {
      toolCalling: false,
      structuredOutput: true,
      compatibleActionClassIds: [],
      localDeterministicActionClassIdsByAgent: {},
    },
    compatibleAgentIds: input.compatibleAgentIds ?? ["ReconScout"],
    selectable: input.selectable ?? true,
    unavailableReasons: input.unavailableReasons ?? [],
  };
}

const primaryLow = item({
  configurationId: "cfg-planning-primary-low",
  modelId: "planner-primary",
  displayName: "Planning Primary",
  reasoningEffort: "low",
});
const primaryHigh = item({
  configurationId: "cfg-planning-primary-high",
  modelId: "planner-primary",
  displayName: "Planning Primary",
  reasoningEffort: "high",
});
const fallback = item({
  configurationId: "cfg-planning-fallback",
  providerId: "provider-fallback",
  modelId: "planner-fallback",
  displayName: "Planning Fallback",
  reasoningEffort: "low",
});
const executor = item({
  configurationId: "cfg-executor",
  providerId: "provider-execution",
  modelId: "executor",
  enforcementMode: "enforced_executor",
});
const unhealthyAdvisor = item({
  configurationId: "cfg-planning-unhealthy",
  providerId: "provider-unhealthy",
  modelId: "planner-unhealthy",
  healthState: "unavailable",
  selectable: false,
  unavailableReasons: ["Provider health is unavailable."],
});
const catalog: ModelCatalog = {
  schemaVersion: "2.4",
  observedAt: OBSERVED_AT,
  items: [primaryLow, primaryHigh, fallback, executor, unhealthyAdvisor],
};
const providerSelection: AutonomousPlanningSelection = {
  route: "provider_advisory",
  agentId: "ReconScout",
  primaryConfigurationId: primaryHigh.configurationId,
  fallbackConfigurationId: fallback.configurationId,
  enforcementMode: "advisor_only",
  disclosureClass: "sanitized_internal",
  executionAuthority: "none",
};

describe("Autonomous planning selection", () => {
  test("normalizes legacy omission and rejects any provider execution authority", () => {
    expect(parseAutonomousPlanningSelection(undefined)).toEqual(
      AUTONOMOUS_LOCAL_PLANNING_SELECTION,
    );
    expect(parseAutonomousPlanningSelection(providerSelection)).toEqual(
      providerSelection,
    );
    expect(() => parseAutonomousPlanningSelection({
      ...providerSelection,
      enforcementMode: "enforced_executor",
    })).toThrow("provider advisory boundary is invalid");
    expect(() => parseAutonomousPlanningSelection({
      ...providerSelection,
      executionAuthority: "tools",
    })).toThrow("provider advisory boundary is invalid");
    expect(() => parseAutonomousPlanningSelection({
      ...providerSelection,
      fallbackConfigurationId: providerSelection.primaryConfigurationId,
    })).toThrow("fallback must differ");
  });

  test("admits only healthy, structured advisor-only configurations", () => {
    expect(configurationSelectableForPlanning(primaryLow, "ReconScout")).toBe(true);
    expect(configurationSelectableForPlanning(executor, "ReconScout")).toBe(false);
    expect(configurationSelectableForPlanning(unhealthyAdvisor, "ReconScout")).toBe(false);
    expect(planningAgentIds(catalog.items)).toEqual(["ReconScout"]);
    expect(firstPlanningConfiguration(catalog.items, "ReconScout", {
      providerId: primaryLow.providerId,
      modelId: primaryLow.modelId,
      preferredReasoningEffort: "high",
    })?.configurationId).toBe(primaryHigh.configurationId);
    expect(planningSelectionFromConfiguration(
      "ReconScout",
      primaryLow,
      fallback.configurationId,
    )).toEqual({
      route: "provider_advisory",
      agentId: "ReconScout",
      primaryConfigurationId: primaryLow.configurationId,
      fallbackConfigurationId: fallback.configurationId,
      enforcementMode: "advisor_only",
      disclosureClass: "sanitized_internal",
      executionAuthority: "none",
    });
  });

  test("compares local legacy and explicit selections without silent route drift", () => {
    expect(samePlanningSelection(undefined, AUTONOMOUS_LOCAL_PLANNING_SELECTION))
      .toBe(true);
    expect(samePlanningSelection(undefined, providerSelection)).toBe(false);
    expect(samePlanningSelection(providerSelection, {
      ...providerSelection,
      primaryConfigurationId: primaryLow.configurationId,
    })).toBe(false);
  });

  test("renders application-owned planning controls and readable signed review", () => {
    const markup = renderToStaticMarkup(<AutonomousPlanningSelectionEditor
      idPrefix="autonomous-intake-team"
      selection={providerSelection}
      agents={[{
        id: "ReconScout",
        displayName: "ReconScout",
        role: "Reconnaissance specialist",
      }]}
      catalog={catalog}
      catalogUpdatedAt={Date.now()}
      catalogLoading={false}
      readinessCheck={{
        id: "contract_planning_selection",
        label: "Signed planning route",
        status: "pass",
        impact: "The exact advisor-only planning model is ready.",
        journeys: ["autonomous"],
      }}
      readinessStale={false}
      onChange={() => undefined}
    />);
    expect(markup).toContain('data-control-id="autonomous-intake-team-planning-route-local"');
    expect(markup).toContain('data-control-id="autonomous-intake-team-planning-route-provider"');
    expect(markup).toContain('aria-label="Autonomous planning agent"');
    expect(markup).toContain('aria-label="Autonomous planning primary provider"');
    expect(markup).toContain('aria-label="Autonomous planning primary model"');
    expect(markup).toContain('aria-label="Autonomous planning primary reasoning effort"');
    expect(markup).toContain('aria-label="Autonomous planning fallback provider"');
    expect(markup).toContain('aria-label="Autonomous planning fallback model"');
    expect(markup).toContain('aria-label="Autonomous planning fallback reasoning effort"');
    expect(markup).toContain("Advisor only");
    expect(markup).toContain("Execution authority");
    expect(markup).toContain("None");
    expect(markup).toContain("Provider health is Unavailable.");

    const review = renderToStaticMarkup(<AutonomousPlanningSelectionReview
      selection={providerSelection}
      catalog={catalog}
      readinessCheck={{
        id: "contract_planning_selection",
        label: "Signed planning route",
        status: "pass",
        impact: "The exact advisor-only planning model is ready.",
        journeys: ["autonomous"],
      }}
    />);
    expect(review).toContain("Pinned plan construction");
    expect(review).toContain("Planning Primary");
    expect(review).toContain("High");
    expect(review).toContain("Planning Fallback");
    expect(review).toContain("Execution authority");
    expect(review).toContain("None");
  });
});
