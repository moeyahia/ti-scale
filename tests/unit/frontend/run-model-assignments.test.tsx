import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  ModelConfiguration,
  RunModelAssignmentPage,
} from "../../../src/domain/types/modelConfiguration";
import { RunModelAssignmentReceiptList } from "../../../src/features/missions/RunModelAssignmentsPanel";

const NOW = "2026-07-28T18:00:00.000Z";

function configuration(overrides: Partial<ModelConfiguration> = {}): ModelConfiguration {
  return {
    id: "configuration-primary",
    providerId: "openrouter",
    modelId: "openai/gpt-5.6",
    displayName: "GPT-5.6",
    executionBoundary: "provider_tool_calling",
    reasoningEffort: "high",
    contextPolicy: { maximumContextTokens: 120_000 },
    capabilities: { toolCalling: true, structuredOutput: true },
    contextLimit: 400_000,
    costClass: "high",
    latencyClass: "standard",
    disclosureClass: "sanitized_internal",
    enforcementMode: "enforced_executor",
    authState: "authenticated",
    healthState: "healthy",
    catalogSource: "live_provider_catalog",
    catalogRetrievedAt: NOW,
    configurationSource: "manual",
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function page(): RunModelAssignmentPage {
  return {
    schemaVersion: "2.4",
    activeRunPinning: "immutable",
    items: [{
      assignment: {
        id: "assignment-recon",
        agentId: "ReconScout",
        missionId: "mission-one",
        runId: "run-one",
        stepId: null,
        purpose: "execution",
        primaryConfigurationId: "configuration-primary",
        fallbackConfigurationId: "configuration-fallback",
        inheritanceLevel: "mission",
        pinned: true,
        resolutionReason: "Pinned from the reviewed mission contract.",
        resolvedAt: NOW,
        createdAt: NOW,
      },
      primaryConfiguration: configuration(),
      fallbackConfiguration: configuration({
        id: "configuration-fallback",
        providerId: "local-runtime",
        modelId: "local-safe-recon",
        displayName: "Local Safe Recon",
        executionBoundary: "local_deterministic_policy",
        reasoningEffort: null,
        disclosureClass: "local_only",
      }),
    }, {
      assignment: {
        id: "assignment-planning",
        agentId: "VulnIntel",
        missionId: "mission-one",
        runId: "run-one",
        stepId: null,
        purpose: "planning",
        primaryConfigurationId: "configuration-planning",
        fallbackConfigurationId: null,
        inheritanceLevel: "agent",
        pinned: true,
        resolutionReason: "Pinned from the reviewed advisory preference.",
        resolvedAt: NOW,
        createdAt: NOW,
      },
      primaryConfiguration: configuration({
        id: "configuration-planning",
        providerId: "openrouter",
        modelId: "anthropic/claude-sonnet",
        displayName: "Claude Sonnet",
        enforcementMode: "advisor_only",
      }),
      fallbackConfiguration: null,
    }],
  };
}

describe("run model assignment receipt list", () => {
  test("shows the exact immutable provider, model, reasoning, fallback, enforcement, and disclosure receipts", () => {
    const markup = renderToStaticMarkup(
      <RunModelAssignmentReceiptList page={page()} />,
    );

    expect(markup).toContain("ReconScout");
    expect(markup).toContain("Pinned from the reviewed mission contract.");
    expect(markup).toContain("openrouter · GPT-5.6 · openai/gpt-5.6");
    expect(markup).toContain("High");
    expect(markup).toContain("Enforced Executor");
    expect(markup).toContain("Provider Tool Calling");
    expect(markup).toContain("Sanitized Internal");
    expect(markup).toContain("local-runtime · Local Safe Recon · local-safe-recon");
    expect(markup).toContain("Local Deterministic Policy");
    expect(markup).toContain("Local Only");
    expect(markup).toContain("configuration-primary");
    expect(markup).toContain("Execution configuration");
    expect(markup).toContain("Execution pin");
    expect(markup).toContain("Planning configuration");
    expect(markup).toContain("Advisory pin");
    expect(markup).toContain("No execution authority.");
    expect(markup).toContain("planning, explanation, and critique only");
    expect(markup).toContain("Provider boundary");
    expect(markup).toContain("Advisor Only");
  });

  test("does not invent a provider/model receipt when the run has no pinned assignments", () => {
    const markup = renderToStaticMarkup(
      <RunModelAssignmentReceiptList
        page={{ schemaVersion: "2.4", activeRunPinning: "immutable", items: [] }}
      />,
    );

    expect(markup).toContain("No model assignment was pinned");
    expect(markup).toContain("does not infer a model");
    expect(markup).not.toContain("ReconScout");
  });
});
