import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  AutonomousMissionPreflight,
  ReadinessCheck,
} from "../../../src/domain/types/commandOs";
import type { RuntimeReadinessSnapshot } from "../../../src/domain/types/runtimeReadiness";
import {
  AutonomousReadinessReview,
  groupAutonomousReadinessBlockers,
} from "../../../src/features/missions/AutonomousReadinessReview";

function check(id: string, label: string, status: ReadinessCheck["status"]): ReadinessCheck {
  return {
    id,
    label,
    status,
    journeys: ["autonomous"],
    impact: `${label} is not currently satisfied for unattended execution.`,
    ...(status === "fail" ? { remediation: `Repair ${label.toLocaleLowerCase("en-US")} and rerun preflight.` } : {}),
  };
}

const CHECKS: readonly ReadinessCheck[] = [
  check("execution_boundary_autonomous", "Autonomous execution boundary", "fail"),
  check("contract_action_boundary", "Executable action boundary", "fail"),
  check("provider_execution_autonomous", "Autonomous provider enforcement", "fail"),
  check("contract_provider_inventory", "Inspected enforcing provider paths", "fail"),
  check("contract_specialist_selection", "Signed specialist pool", "fail"),
  check("mcp_execution_autonomous", "Autonomous MCP execution", "fail"),
  check("contract_evidence_capability", "Required evidence capability", "fail"),
  check("provider_token_accounting_autonomous", "Exact token accounting", "fail"),
  check("provider_cost_accounting_autonomous", "Exact cost accounting", "fail"),
  check("database", "Canonical database", "pass"),
];

const PREFLIGHT: AutonomousMissionPreflight = {
  schemaVersion: "2.4",
  outcome: {
    id: "assessment",
    label: "Autonomous Assessment",
    concisePromise: "Evaluate the signed assessment outcomes.",
    completionMeaning: "Completion does not imply access or root control.",
    requiredTerminalSuccessCriteria: [],
    requiredActionClassIds: [],
  },
  contract: { version: 1, hash: "a".repeat(64) },
  readiness: { status: "blocked", score: 51, checks: [...CHECKS] },
  context: { candidates: [], selectedNodeIds: [], invalidSelectedNodeIds: [] },
  execution: {
    providers: [],
    tools: [],
    team: {
      candidates: [],
      selectedAgentIds: [],
      invalidSelectedAgentIds: [],
      recommendedAgentIds: [],
      effectiveAgentIds: [],
      modelAssignments: [],
    },
  },
  policySummary: {
    provider: "No enforcing provider",
    tools: "No Autonomous tool chain",
    notifications: "In product",
    reporting: "Local",
    retention: "Operator managed",
    storage: "Bounded",
  },
};

const RUNTIME: RuntimeReadinessSnapshot = {
  schemaVersion: "2.4",
  status: "degraded",
  execution: {
    autonomous: "unavailable",
    guided: "ready",
    guidedToolExecution: "ready",
    localCommanderGuidance: "ready",
    actionBoundaryActive: false,
    delegationEnforced: false,
    noHandsCommanderEnforced: false,
  },
  dependencies: {
    providers: {
      status: "unavailable",
      initializing: false,
      probing: 0,
      reason: "No enforcing provider",
      declared: 0,
      callable: 0,
      enforcing: 0,
      guidedCapable: 0,
    },
    mcp: {
      status: "unavailable",
      initializing: false,
      probingServers: 0,
      reason: "No runnable Autonomous MCP server",
      configuredServers: 0,
      runnableServers: 0,
      executionMode: "disabled",
    },
    secondBrain: { status: "healthy", canonicalStoreAvailable: true, reason: null },
  },
  checkedAt: "2026-07-20T00:00:00.000Z",
};

describe("Autonomous mission readiness review", () => {
  test("groups every Autonomous blocker into an operator-readable system layer", () => {
    const groups = groupAutonomousReadinessBlockers(CHECKS);
    expect(groups.map((group) => [group.id, group.checks.length])).toEqual([
      ["execution_boundary", 2],
      ["provider", 2],
      ["specialist", 1],
      ["tools_mcp", 2],
      ["budgets", 2],
    ]);
    expect(groups.flatMap((group) => group.checks)).toHaveLength(9);
  });

  test("names the selected journey and separates Guided exact-step tools from Autonomous execution", () => {
    const markup = renderToStaticMarkup(
      <AutonomousReadinessReview preflight={PREFLIGHT} runtime={RUNTIME} />,
    );

    expect(markup).toContain("Selected journey · Autonomous");
    expect(markup).toContain("Autonomous launch is blocked");
    expect(markup).toContain("Autonomous readiness score 51 out of 100");
    expect(markup).toContain("9 failing checks prevent unattended execution");
    expect(markup).toContain("Guided local tools are available");
    expect(markup).toContain("one reviewed local specialist action after you approve its exact target and parameters");
    expect(markup).toContain("This does not provide unattended planning or Autonomous execution");
    expect(markup).toContain("Execution boundary");
    expect(markup).toContain("Provider enforcement");
    expect(markup).toContain("Specialist assignment");
    expect(markup).toContain("Tools, MCP, and evidence producers");
    expect(markup).toContain("Budgets and accounting");
  });

  test("does not claim Guided tool availability without a current runtime attestation", () => {
    const markup = renderToStaticMarkup(
      <AutonomousReadinessReview preflight={PREFLIGHT} />,
    );
    expect(markup).toContain("Guided local tool status could not be verified in this review");
    expect(markup).not.toContain("Guided local tools are available");
  });

  test("retires an old blocker snapshot while current runtime readiness is rechecked", () => {
    const markup = renderToStaticMarkup(
      <AutonomousReadinessReview
        preflight={PREFLIGHT}
        runtime={RUNTIME}
        preflightRefreshing
      />,
    );

    expect(markup).toContain("Refreshing Autonomous readiness");
    expect(markup).toContain("retired the old score and blockers");
    expect(markup).toContain('data-readiness-review-state="refreshing"');
    expect(markup).not.toContain("Autonomous readiness score 51 out of 100");
    expect(markup).not.toContain("9 failing checks prevent unattended execution");
  });

  test("keeps the stale score retired when its automatic replacement fails", () => {
    const markup = renderToStaticMarkup(
      <AutonomousReadinessReview
        preflight={PREFLIGHT}
        runtime={RUNTIME}
        preflightRefreshFailed
      />,
    );

    expect(markup).toContain("Autonomous readiness needs a new review");
    expect(markup).toContain("previous score and blockers are retired");
    expect(markup).toContain('data-readiness-review-state="refresh-failed"');
    expect(markup).not.toContain("Autonomous readiness score 51 out of 100");
    expect(markup).not.toContain("9 failing checks prevent unattended execution");
  });
});
