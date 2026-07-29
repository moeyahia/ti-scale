import { describe, expect, test } from "bun:test";
import {
  deriveCommandOsDurableActionBoundary,
  type DurableActionBoundaryInput,
} from "../DurableActionBoundary";

const ENFORCED_POLICY = {
  routingEnabled: true,
  delegationEnforced: true,
  noHandsCommanderEnforced: true,
  directCommanderToolsAllowed: false,
  specialistAssignmentRequired: true,
} as const;

const LIVE_SPECIALIST = {
  agentId: "ReconScout",
  mcpServer: "reconnaissance",
  toolNames: ["quick_scan"],
} as const;

function ready(overrides: Partial<DurableActionBoundaryInput> = {}): DurableActionBoundaryInput {
  return {
    runtimeCoordinatorReady: true,
    policy: ENFORCED_POLICY,
    specialistInventory: [LIVE_SPECIALIST],
    ...overrides,
  };
}

describe("dynamic Ti-Scale durable action boundary", () => {
  test("re-evaluates a stale startup inventory and becomes active after live discovery", () => {
    expect(deriveCommandOsDurableActionBoundary(ready({ specialistInventory: [] }))).toBe(false);

    expect(deriveCommandOsDurableActionBoundary(ready({
      specialistInventory: [LIVE_SPECIALIST],
    }))).toBe(true);
  });

  test("fails closed when the coordinator or any enforcement policy is missing", () => {
    const missingConditions: readonly DurableActionBoundaryInput[] = [
      ready({ runtimeCoordinatorReady: false }),
      ready({ runtimeCoordinatorReady: undefined }),
      ready({ policy: null }),
      ready({ policy: { ...ENFORCED_POLICY, routingEnabled: false } }),
      ready({ policy: { ...ENFORCED_POLICY, delegationEnforced: false } }),
      ready({ policy: { ...ENFORCED_POLICY, noHandsCommanderEnforced: false } }),
      ready({ policy: { ...ENFORCED_POLICY, noHandsCommanderEnforced: undefined } }),
      ready({ policy: { ...ENFORCED_POLICY, directCommanderToolsAllowed: true } }),
      ready({ policy: { ...ENFORCED_POLICY, directCommanderToolsAllowed: undefined } }),
      ready({ policy: { ...ENFORCED_POLICY, specialistAssignmentRequired: false } }),
    ];

    for (const input of missingConditions) {
      expect(deriveCommandOsDurableActionBoundary(input)).toBe(false);
    }
  });

  test("requires one current specialist binding with a nonblank MCP server and tool", () => {
    const unavailableInventories: DurableActionBoundaryInput["specialistInventory"][] = [
      null,
      undefined,
      [],
      [{ ...LIVE_SPECIALIST, agentId: " " }],
      [{ ...LIVE_SPECIALIST, mcpServer: " " }],
      [{ ...LIVE_SPECIALIST, toolNames: [] }],
      [{ ...LIVE_SPECIALIST, toolNames: [" "] }],
      [
        { agentId: "ReconScout", mcpServer: "reconnaissance", toolNames: [] },
        { agentId: "WebBreaker", mcpServer: "", toolNames: ["quick_scan"] },
      ],
    ];

    for (const specialistInventory of unavailableInventories) {
      expect(deriveCommandOsDurableActionBoundary(ready({ specialistInventory }))).toBe(false);
    }
  });

  test("accepts surrounding whitespace without treating blank bindings as callable", () => {
    expect(deriveCommandOsDurableActionBoundary(ready({
      specialistInventory: [{
        agentId: " ReconScout ",
        mcpServer: " reconnaissance ",
        toolNames: [" ", " quick_scan "],
      }],
    }))).toBe(true);
  });
});
