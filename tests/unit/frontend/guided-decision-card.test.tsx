import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { NavigationProvider } from "../../../src/app/router/navigation";
import type { GuidedDecision } from "../../../src/domain/types/runtimeV2";
import {
  DecisionCard,
  guidedDecisionActionKind,
} from "../../../src/features/decisions/DecisionsPage";

const BASE_DECISION: Omit<GuidedDecision, "requestedParameters"> = {
  id: "decision-guided-safety",
  missionId: "mission-guided-safety",
  runId: "run-guided-safety",
  stepId: "step-guided-safety",
  status: "pending",
  actionFingerprint: "f".repeat(64),
  rationale: "Perform only the exact represented Guided step.",
  riskClass: "low",
  reversibility: "Read only",
  expiresAt: "2100-01-01T00:00:00.000Z",
  createdAt: "2026-07-16T00:00:00.000Z",
};

function renderDecision(requestedParameters: unknown): string {
  return renderToStaticMarkup(
    <NavigationProvider>
      <DecisionCard
        decision={{ ...BASE_DECISION, requestedParameters }}
        onChanged={() => undefined}
      />
    </NavigationProvider>,
  );
}

describe("Guided decision action-kind safety", () => {
  test("reads nested represented actions and never offers execution for manual work", () => {
    const requestedParameters = {
      action: {
        actionType: "manual_header_review",
        actionClass: "passive_intelligence_osint",
        target: "fixture.local",
        arguments: {},
        kind: "manual",
        idempotent: true,
        destructive: false,
      },
      explanation: "Review the retained response locally.",
    };

    expect(guidedDecisionActionKind(requestedParameters)).toBe("manual");
    const markup = renderDecision(requestedParameters);
    expect(markup).toContain("This operator-run step cannot be dispatched through MCP.");
    expect(markup).not.toContain("Run this exact step");
  });

  test("supports legacy flattened manual decisions and resolves conflicts fail-closed", () => {
    expect(guidedDecisionActionKind({ kind: "manual", target: "legacy.fixture" })).toBe("manual");
    expect(guidedDecisionActionKind({ kind: "manual", action: { kind: "tool" } })).toBe("manual");
    expect(guidedDecisionActionKind({ kind: "tool", action: { kind: "manual" } })).toBe("manual");
    expect(renderDecision({ kind: "manual", target: "legacy.fixture" })).not.toContain("Run this exact step");
  });

  test("does not dispatch an absent or unrecognized retained action kind", () => {
    for (const requestedParameters of [
      {},
      { action: { kind: "future_unknown_kind" } },
      { kind: 42 },
      null,
    ]) {
      expect(guidedDecisionActionKind(requestedParameters)).toBeNull();
      const markup = renderDecision(requestedParameters);
      expect(markup).toContain("no recognized executable action kind");
      expect(markup).not.toContain("Run this exact step");
    }
  });

  test("keeps executable tool actions available for deliberate exact-step authorization", () => {
    const requestedParameters = {
      actionType: "bounded_header_probe",
      actionClass: "passive_intelligence_osint",
      target: "fixture.local",
      arguments: { readOnly: true },
      kind: "tool",
      idempotent: true,
      destructive: false,
    };

    expect(guidedDecisionActionKind(requestedParameters)).toBe("tool");
    const markup = renderDecision(requestedParameters);
    expect(markup).toContain("Run this exact step");
    expect(markup).not.toContain("This operator-run step cannot be dispatched through MCP.");
  });
});
