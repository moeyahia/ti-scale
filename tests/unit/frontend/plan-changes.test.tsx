import { afterEach, describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { createDatabaseConnection, migrateDatabase } from "../../../server/db";
import { PlanChangeService } from "../../../server/plan-changes";
import { planChangesApi } from "../../../src/data/api/planChanges";
import { parsePlanChangeApply, parsePlanChangeDetail } from "../../../src/domain/schemas/planChanges";
import { PlanChangeRequestCard, PlanVersionHistory, reviseEffectiveStrategyOperation } from "../../../src/features/missions/PlanChangePanel";
import type { RunPlan, RuntimeRun } from "../../../src/domain/types/runtimeV2";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

function proposalFixture() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  const now = "2026-07-16T16:00:00.000Z";
  database.prepare(`INSERT INTO missions (id, name, objective, journey, status, authorization_status, scope_json, success_criteria_json, retention_policy_json, memory_policy_json, created_by, created_at, updated_at) VALUES ('mission-ui-plan', 'UI plan', 'Show exact amendment state', 'guided', 'active', 'verified', '{}', '[]', '{}', '{}', 'operator', ?, ?)`).run(now, now);
  database.prepare(`INSERT INTO agents (id, role, display_name, status, provider_policy_json, tool_policy_json, configuration_json, version, created_at, updated_at) VALUES ('agent-ui-plan', 'recon', 'Recon specialist', 'available', '{}', '{}', '{}', '1', ?, ?)`).run(now, now);
  database.prepare(`INSERT INTO runs (id, mission_id, journey, status, current_plan_id, current_step_id, created_at, updated_at, version) VALUES ('run-ui-plan', 'mission-ui-plan', 'guided', 'queued', 'plan-ui-plan', 'step-ui-plan', ?, ?, 1)`).run(now, now);
  database.prepare(`INSERT INTO plans (id, run_id, version, status, strategy_summary, rationale_summary, plan_hash, created_by, created_at, activated_at) VALUES ('plan-ui-plan', 'run-ui-plan', 1, 'active', 'Original evidence plan', 'Preserve attributable observations', ?, 'planner', ?, ?)`).run("b".repeat(64), now, now);
  database.prepare(`INSERT INTO plan_steps (id, plan_id, run_id, ordinal, phase, title, objective, status, success_criteria_json, dependencies_json, action_class, risk_class, assigned_agent_id, created_at, updated_at) VALUES ('step-ui-plan', 'plan-ui-plan', 'run-ui-plan', 0, 'Recon', 'Map scope', 'Map only supplied scope', 'ready', '["Scope mapped"]', '[]', 'passive_intelligence_osint', 'low', 'agent-ui-plan', ?, ?)`).run(now, now);
  database.prepare(`INSERT INTO mission_constraints (id, mission_id, constraint_type, value_json, source, created_at) VALUES ('constraint-ui-plan', 'mission-ui-plan', 'represented_action', ?, 'step-ui-plan', ?)`)
    .run(JSON.stringify({ action: { actionType: "passive_intelligence_osint", actionClass: "passive_intelligence_osint", target: "fixture.local", arguments: {}, intentSummary: "Collect attributable scope facts", kind: "manual", idempotent: true, destructive: false }, explanation: "Collect bounded facts.", rationale: "Reduce uncertainty.", reversibility: "Read-only", dependencies: [] }), now);
  database.prepare(`INSERT INTO mission_targets (id, mission_id, target, target_type, disposition, normalized_target, metadata_json, created_at) VALUES ('target-ui-plan', 'mission-ui-plan', 'fixture.local', 'domain', 'allowed', 'fixture.local', '{}', ?)`)
    .run(now);
  const request = new PlanChangeService(database, () => new Date(now), (prefix) => `${prefix}_ui_fixture`).propose({
    missionId: "mission-ui-plan", runId: "run-ui-plan", basePlanId: "plan-ui-plan",
    expectedRunVersion: 1, expectedPlanVersion: 1,
    requestText: "Narrow the plan to the evidence-backed hypothesis.",
    operations: [{ kind: "update_plan", strategySummary: "Evidence-backed scope validation" }],
  }, { id: "operator-ui", type: "operator" });
  return { database, request };
}

function directProposalFixture() {
  const fixture = proposalFixture();
  const request = new PlanChangeService(
    fixture.database,
    () => new Date("2026-07-16T16:01:00.000Z"),
    (prefix) => `${prefix}_ui_direct_fixture`,
  ).propose({
    missionId: "mission-ui-plan",
    runId: "run-ui-plan",
    basePlanId: "plan-ui-plan",
    expectedRunVersion: 1,
    expectedPlanVersion: 1,
    requestText: "Represent the exact bounded identity check before plan activation.",
    operations: [{
      kind: "set_represented_action",
      stepId: "step-ui-plan",
      representation: {
        action: {
          actionType: "passive_scope_revalidation",
          target: "fixture.local",
          arguments: { maxRecords: 25 },
          intentSummary: "Revalidate attributable target identity with a local record bound.",
          kind: "tool",
          idempotent: true,
          destructive: false,
        },
        explanation: "Recheck the approved identity with a local record bound.",
        rationale: "Prevent later work from drifting outside scope.",
        reversibility: "Read-only lookup.",
      },
    }],
  }, { id: "operator-ui", type: "operator" });
  return { database: fixture.database, request };
}

describe("strict plan-change client boundary", () => {
  test("parses all structured impacts and rejects unsupported or fabricated impact fields", () => {
    const fixture = proposalFixture();
    try {
      const parsed = parsePlanChangeDetail({ schemaVersion: "2.4", request: fixture.request, contextPackId: "ctx-plan-proposal" });
      expect(parsed.request).toMatchObject({ status: "validated", version: 1 });
      expect(parsed.contextPackId).toBe("ctx-plan-proposal");
      expect(parsePlanChangeDetail({ schemaVersion: "2.4", request: fixture.request }).contextPackId).toBeNull();
      expect(parsePlanChangeApply({
        schemaVersion: "2.4",
        request: fixture.request,
        resultPlanId: "plan-ui-plan-v2",
        resultPlanVersion: 2,
        guidedDecisionId: null,
        contextPackId: "ctx-plan-apply",
      }).contextPackId).toBe("ctx-plan-apply");
      expect(parsed.request.structuredDiff).toEqual([expect.objectContaining({ path: "strategySummary" })]);
      expect(() => parsePlanChangeDetail({ schemaVersion: "2.4", request: fixture.request, contextPackId: "ctx-plan-proposal", decorativeScore: 99 })).toThrow("unsupported field decorativeScore");
      expect(() => parsePlanChangeDetail({ schemaVersion: "2.4", request: { ...fixture.request, decorativeScore: 99 } })).toThrow("unsupported field decorativeScore");
      expect(() => parsePlanChangeDetail({ schemaVersion: "2.4", request: { ...fixture.request, budgetImpact: { ...fixture.request.budgetImpact, durationEstimate: "3 hours" } } })).toThrow("must remain not_observed");
    } finally { fixture.database.close(); }
  });

  test("rejects malformed operation-specific response payloads before the direct editor can dereference them", () => {
    const fixture = directProposalFixture();
    try {
      expect(parsePlanChangeDetail({ schemaVersion: "2.4", request: fixture.request }).request.normalizedChange.operations).toHaveLength(1);
      expect(() => parsePlanChangeDetail({
        schemaVersion: "2.4",
        request: {
          ...fixture.request,
          normalizedChange: {
            ...fixture.request.normalizedChange,
            operations: [{ kind: "set_represented_action", stepId: "step-ui-plan" }],
          },
        },
      })).toThrow("operation[0] is missing representation");
      expect(() => parsePlanChangeDetail({
        schemaVersion: "2.4",
        request: {
          ...fixture.request,
          normalizedChange: {
            ...fixture.request.normalizedChange,
            operations: [{
              ...fixture.request.normalizedChange.operations[0],
              undocumentedExecutionFlag: true,
            }],
          },
        },
      })).toThrow("operation[0] contains unsupported field undocumentedExecutionFlag");
      expect(() => parsePlanChangeDetail({
        schemaVersion: "2.4",
        request: {
          ...fixture.request,
          normalizedChange: {
            ...fixture.request.normalizedChange,
            operations: [{
              kind: "set_represented_action",
              stepId: "step-ui-plan",
              representation: {
                action: {
                  actionType: "bounded_lookup",
                  target: "fixture.local",
                  arguments: [],
                  intentSummary: "Collect one bounded fact",
                  kind: "tool",
                  idempotent: true,
                  destructive: false,
                },
                explanation: "Collect one fact.",
                rationale: "Reduce uncertainty.",
                reversibility: "Read-only.",
              },
            }],
          },
        },
      })).toThrow("operation[0].representation.action.arguments must be an object");
    } finally { fixture.database.close(); }
  });

  test("parses the exact immutable restore operation and rejects extra fields", () => {
    const fixture = proposalFixture();
    try {
      const restoreRequest = {
        ...fixture.request,
        normalizedChange: {
          summary: "Restore historical plan v1 as a new immutable version.",
          operations: [{ kind: "restore_plan_version", targetPlanId: "plan-ui-plan-v1", targetPlanVersion: 1 }],
        },
      };
      expect(parsePlanChangeDetail({ schemaVersion: "2.4", request: restoreRequest }).request.normalizedChange.operations)
        .toEqual([{ kind: "restore_plan_version", targetPlanId: "plan-ui-plan-v1", targetPlanVersion: 1 }]);
      expect(() => parsePlanChangeDetail({
        schemaVersion: "2.4",
        request: {
          ...restoreRequest,
          normalizedChange: {
            ...restoreRequest.normalizedChange,
            operations: [{ kind: "restore_plan_version", targetPlanId: "plan-ui-plan-v1", targetPlanVersion: 1, mutateHistoricalRecord: true }],
          },
        },
      })).toThrow("operation[0] contains unsupported field mutateHistoricalRecord");
    } finally { fixture.database.close(); }
  });

  test("uses the canonical run-scoped mutation path with an idempotency key", async () => {
    const fixture = proposalFixture();
    try {
      const keys: string[] = [];
      let attempts = 0;
      globalThis.fetch = (async (input, init) => {
        expect(String(input)).toBe("/api/v2/runs/run-ui-plan/plan-changes");
        expect(init?.method).toBe("POST");
        const idempotencyKey = new Headers(init?.headers).get("Idempotency-Key");
        expect(idempotencyKey).toMatch(/^plan-change-create:[a-f0-9-]{36}$/u);
        keys.push(idempotencyKey!);
        expect(JSON.parse(String(init?.body))).toMatchObject({ basePlanId: "plan-ui-plan", expectedRunVersion: 1 });
        attempts += 1;
        if (attempts === 1) throw new TypeError("connection ended before a response was received");
        return new Response(JSON.stringify({ schemaVersion: "2.4", request: fixture.request, contextPackId: "ctx-plan-proposal" }), { status: 201, headers: { "content-type": "application/json", "x-request-id": "request-plan-change" } });
      }) as typeof fetch;
      const mutation = { basePlanId: "plan-ui-plan", expectedRunVersion: 1, expectedPlanVersion: 1, operations: [{ kind: "update_plan" as const, strategySummary: "Evidence-backed scope validation" }] };
      await expect(planChangesApi.create("run-ui-plan", mutation)).rejects.toThrow("connection ended before a response was received");
      const result = await planChangesApi.create("run-ui-plan", mutation);
      await planChangesApi.create("run-ui-plan", mutation);
      expect(result.request.id).toBe(fixture.request.id);
      expect(result.contextPackId).toBe("ctx-plan-proposal");
      expect(keys[0]).toBe(keys[1]);
      expect(keys[2]).not.toBe(keys[0]);
    } finally { fixture.database.close(); }
  });
});

describe("PlanChangeRequestCard", () => {
  test("revises only the effective final strategy operation in a multi-operation request", () => {
    const operations = [
      { kind: "update_plan", strategySummary: "Intermediate strategy", rationaleSummary: "Preserve the first rationale" },
      { kind: "set_dependencies", stepId: "step-ui-plan", dependencyStepIds: [] },
      { kind: "update_plan", strategySummary: "Effective strategy", rationaleSummary: "Preserve the effective rationale" },
    ] as const;
    expect(reviseEffectiveStrategyOperation(operations, "Operator revision")).toEqual([
      operations[0],
      operations[1],
      { ...operations[2], strategySummary: "Operator revision" },
    ]);
    expect(reviseEffectiveStrategyOperation([operations[1]], "New strategy")).toEqual([
      operations[1],
      { kind: "update_plan", strategySummary: "New strategy" },
    ]);
  });

  test("renders exact diffs, measured blockers, and an explicit no-execution apply contract", () => {
    const fixture = proposalFixture();
    try {
      const markup = renderToStaticMarkup(<PlanChangeRequestCard request={fixture.request} runVersion={1} basePlanVersion={1} />);
      expect(markup).toContain("Exact reviewed diff");
      expect(markup).toContain("Original evidence plan");
      expect(markup).toContain("Evidence-backed scope validation");
      expect(markup).toContain("Duration and provider cost are not observed");
      expect(markup).toContain("Apply new plan version");
      expect(markup).toMatch(/<button[^>]*aria-label="Save and revalidate [^"]+"[^>]*disabled=""/u);
      expect(markup).not.toContain("estimated 3 hours");
    } finally { fixture.database.close(); }
  });

  test("disables apply and explains why when the server reports an unsafe in-flight boundary", () => {
    const fixture = proposalFixture();
    try {
      const request = {
        ...fixture.request,
        status: "proposed" as const,
        inflightImpact: {
          ...fixture.request.inflightImpact,
          safeToApply: false,
          leaseOwner: "worker-active",
          activeStepIds: ["step-ui-plan"],
          requiresCancellation: true,
          reasons: ["Run lease is owned by worker-active; this service will not cancel or reinterpret its work."],
        },
      };
      const markup = renderToStaticMarkup(<PlanChangeRequestCard request={request} runVersion={1} basePlanVersion={1} />);
      expect(markup).toContain("This proposal cannot be applied yet");
      expect(markup).toContain("will not cancel or reinterpret its work");
      expect(markup).toMatch(/<button[^>]*aria-label="Apply new plan version from [^"]+"[^>]*disabled=""/u);
    } finally { fixture.database.close(); }
  });

  test("offers the exact structured editor for direct operations without a blank strategy editor", () => {
    const fixture = directProposalFixture();
    try {
      const markup = renderToStaticMarkup(<PlanChangeRequestCard request={fixture.request} runVersion={1} basePlanVersion={1} />);
      expect(markup).toContain(`aria-label="Edit exact represented action in ${fixture.request.id}"`);
      expect(markup).toContain("Edit structured proposal");
      expect(markup).not.toContain(`Revised strategy summary for ${fixture.request.id}`);
      expect(markup).toContain("Apply new plan version");
    } finally { fixture.database.close(); }
  });

  test("does not offer a direct editor that could rewrite a historical snapshot", () => {
    const fixture = proposalFixture();
    try {
      const request = {
        ...fixture.request,
        normalizedChange: {
          summary: "Restore historical plan v1 as a new immutable version.",
          operations: [{ kind: "restore_plan_version" as const, targetPlanId: "plan-ui-plan-v1", targetPlanVersion: 1 }],
        },
      };
      const markup = renderToStaticMarkup(<PlanChangeRequestCard request={request} runVersion={1} basePlanVersion={1} />);
      expect(markup).toContain("Historical snapshot:");
      expect(markup).toContain("plan v1");
      expect(markup).not.toContain("this proposal restores plan-ui-plan-v1");
      expect(markup).toContain("Apply new plan version");
      expect(markup).not.toContain("Edit structured proposal");
    } finally { fixture.database.close(); }
  });
});

describe("PlanVersionHistory", () => {
  const run = {
    id: "run-history", missionId: "mission-history", missionName: "History fixture", objective: "Review plan history", journey: "guided", status: "queued",
    statusReason: null, progress: 0, nextAction: null, currentPlanId: "plan-v2", currentStepId: "step-v2", currentOwnerId: null, lastHeartbeatAt: null,
    leaseExpiresAt: null, startedAt: null, endedAt: null, createdAt: "2026-07-16T16:00:00.000Z", updatedAt: "2026-07-16T16:00:00.000Z", version: 2,
  } satisfies RuntimeRun;
  const historical = {
    id: "plan-v1", runId: run.id, version: 1, status: "superseded", strategySummary: "Map the approved surface", rationaleSummary: "Begin with attributable discovery", createdAt: run.createdAt, activatedAt: run.createdAt,
    steps: [{ id: "step-v1", ordinal: 0, phase: "Recon", title: "Map scope", objective: "Map approved scope", status: "cancelled", assignedAgentId: "agent-recon", riskClass: "low", successCriteria: ["Scope mapped"], dependencyStepIds: [], action: { actionType: "passive_intelligence_osint", actionClass: "passive_intelligence_osint", target: "fixture.local", arguments: {}, intentSummary: "Map scope", kind: "manual", idempotent: true, destructive: false }, explanation: "Map approved scope.", rationale: "Reduce uncertainty.", reversibility: "Read-only" }],
  } satisfies RunPlan;
  const active = {
    ...historical,
    id: "plan-v2",
    version: 2,
    status: "active",
    strategySummary: "Validate a narrower hypothesis",
    steps: [{ ...historical.steps[0], id: "step-v2", title: "Validate hypothesis" }],
  } satisfies RunPlan;

  test("renders an application-owned history selector, readable comparison, and disabled reviewed rollback", () => {
    const markup = renderToStaticMarkup(<PlanVersionHistory run={run} activePlan={active} plans={[active, historical]} />);
    expect(markup).toContain("Compare and prepare a rollback");
    expect(markup).toContain('role="combobox"');
    expect(markup).toContain("Plan v2 and plan v1 comparison");
    expect(markup).toContain("Validate hypothesis");
    expect(markup).toContain("Map scope");
    expect(markup).toMatch(/<button[^>]*data-control-id="plan-version-rollback-prepare"[^>]*disabled=""/u);
    expect(markup).toContain("never reactivates or edits an old record");
  });

  test("disables rollback controls when plan history is a stale cached projection", () => {
    const markup = renderToStaticMarkup(<PlanVersionHistory run={run} activePlan={active} plans={[active, historical]} historyCurrent={false} />);
    expect(markup).toContain("Plan history is not current");
    expect(markup).toContain("cached history cannot authorize a restore");
    expect(markup).toMatch(/<button[^>]*data-control-id="plan-version-rollback-prepare"[^>]*disabled=""/u);
    expect(markup).toMatch(/<button[^>]*role="combobox"[^>]*disabled=""[^>]*aria-label="Historical plan to compare"/u);
  });
});
