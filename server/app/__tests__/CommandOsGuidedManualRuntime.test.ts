import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createProductionGuidedManualRuntime,
  DeterministicManualOutcomeEvaluator,
  FailClosedManualExecutionPort,
  LocalGuidedManualPlanner,
  localGuidedManualAgentProjection,
  MissionRuntimeEngine,
} from "../../command-runtime";
import { createLocalGuidedManualInterpreterRouter } from "../../guided-commander";
import { createMissionRuntimeV2Router } from "../../routes/missionRuntimeV2Routes";
import { createRuntimeReadinessProviders } from "../RuntimeReadiness";
import { createCommandOsApplication, type CommandOsApplication } from "../CommandOsApplication";
import type { RuntimeProjectionInput } from "../RuntimeProjectionService";

const applications: CommandOsApplication[] = [];
const runtimes: MissionRuntimeEngine[] = [];
const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(runtimes.splice(0).map((runtime) => runtime.stop()));
  await Promise.all(servers.splice(0).map((server) =>
    new Promise<void>((resolve) => server.close(() => resolve()))));
  await Promise.all(applications.splice(0).map((application) => application.stop()));
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function runtimeProjection(): RuntimeProjectionInput {
  const readiness: RuntimeProjectionInput["readiness"] = {
    actionBoundaryActive: false,
    delegationEnforced: false,
    noHandsCommanderEnforced: true,
    directCommanderToolsDenied: true,
    specialistAssignmentRequired: false,
    specialistsConfigured: 0,
    providers: [],
    mcp: {
      enabled: false,
      executionMode: "disabled" as const,
      startPermitted: false,
      configuredServers: 0,
      runnableServers: 0,
      missingDependencies: 0,
      missingSecrets: 0,
    },
    eventStream: "healthy" as const,
    secondBrain: "healthy" as const,
    legacyExecutionEnabled: false,
    guidedManualPlanning: {
      status: "ready" as const,
      plannerId: "ti-scale.local-guided-manual-planner",
      executionMode: "manual_only" as const,
      targetInteraction: "operator_only" as const,
      providerContact: false,
      toolDispatch: false,
      reason: "A local deterministic planner creates represented manual Guided steps without provider, target, tool, or MCP contact.",
    },
  };
  return {
    readiness,
    agents: [localGuidedManualAgentProjection()],
    mcpServers: [],
  };
}

async function json(response: Response): Promise<Record<string, any>> {
  const body = await response.json() as Record<string, any>;
  if (!response.ok) throw new Error(`${response.status}: ${JSON.stringify(body)}`);
  return body;
}

async function waitForStatus(
  runtime: MissionRuntimeEngine,
  runId: string,
  expected: string,
): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (runtime.repository.getRunProjection(runId).status === expected) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Run ${runId} did not reach ${expected}`);
}

describe("production-composed local Guided manual runtime", () => {
  test("creates, plans, waits, and locally attests ingestion without verifying or completing unsupported text", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-guided-manual-api-"));
    directories.push(directory);
    let runtime: MissionRuntimeEngine | undefined;
    const application = createCommandOsApplication({
      databasePath: join(directory, "ti-scale.sqlite"),
      localCommanderGuidanceMounted: true,
      readinessProviders: (_database, readRuntimeProjection) =>
        createRuntimeReadinessProviders(() => readRuntimeProjection().readiness),
      runtimeProjection,
      resolveActor: () => "operator:test",
      assertRunMutationLease: ({ runId }) =>
        runtime?.assertControlPlaneMutationAuthority(runId),
      projectionIntervalMs: 60_000,
    });
    applications.push(application);
    runtime = createProductionGuidedManualRuntime({
      database: application.database,
      brainContext: application.brainContext,
      workerId: "production-guided-manual-api-test",
      scanIntervalMs: 50,
      leaseTtlMs: 1_000,
      decisionTtlMs: 60_000,
    });
    runtimes.push(runtime);

    const app = express();
    app.use(express.json({ limit: "1mb" }));
    app.use(application.router);
    app.use(createLocalGuidedManualInterpreterRouter({
      database: application.database,
      brainContext: application.brainContext,
      resolveActor: () => "operator:test",
      assertRunMutationLease: ({ runId }) =>
        runtime?.assertControlPlaneMutationAuthority(runId),
    }));
    app.use(createMissionRuntimeV2Router({
      runtime,
      resolveActor: () => "operator:test",
    }));
    const server = createServer(app);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server did not bind");
    const baseUrl = `http://127.0.0.1:${address.port}`;

    application.start();
    await runtime.start();
    const readiness = await json(await fetch(`${baseUrl}/api/v2/system/readiness`));
    expect(readiness.execution).toMatchObject({
      autonomous: "unavailable",
      guided: "manual_only",
      localCommanderGuidance: "ready",
      actionBoundaryActive: false,
    });

    const created = await json(await fetch(`${baseUrl}/api/v2/missions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "guided-manual-production-create-0001",
      },
      body: JSON.stringify({
        journey: "guided",
        launch: true,
        authorizationConfirmed: true,
        title: "Production manual Guided API fixture",
        objective: "Establish one attributable baseline for the exact approved local test address",
        target: "https://guided-manual.example.test/",
        engagementId: "eng-guided-manual-api",
        explanationDepth: "balanced",
        executionPreference: "manual",
        evidenceExpectations: ["one attributable bounded text result"],
      }),
    }));
    const missionId = created.mission.id as string;
    const runId = created.run.id as string;
    await waitForStatus(runtime, runId, "waiting_guided_decision");
    const decision = runtime.repository.requireCurrentPendingDecision(runId
      ? (application.database.prepare(`
          SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
        `).get(runId) as { id: string }).id
      : "", new Date().toISOString());

    const localGuidance = await json(await fetch(
      `${baseUrl}/api/v2/guided/${missionId}/commander/show-next-step`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "guided-manual-production-local-guidance-0001",
        },
        body: JSON.stringify({
          runId,
          stepId: decision.stepId,
          expectedFingerprint: decision.actionFingerprint,
        }),
      },
    ));
    expect(localGuidance.guidance).toEqual({
      mode: "local_deterministic",
      providerContacted: false,
      toolDispatched: false,
      targetContacted: false,
      planMutated: false,
      exactDecisionRequired: true,
    });
    expect(localGuidance.result.assistantMessage.body).toContain(
      "Only the exact decision card can authorize one represented action",
    );
    expect(runtime.repository.requireCurrentPendingDecision(
      decision.id,
      new Date().toISOString(),
    ).actionFingerprint).toBe(decision.actionFingerprint);

    const interpreted = await json(await fetch(
      `${baseUrl}/api/v2/guided/${missionId}/commander/interpret-result`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "guided-manual-production-interpret-0001",
        },
        body: JSON.stringify({
          runId,
          stepId: decision.stepId,
          expectedFingerprint: decision.actionFingerprint,
          result: {
            source: "paste",
            mediaType: "text/plain",
            text: "At 18:00 UTC the exact approved address returned HTTP 200 with title Guided Manual Test and no redirect.",
          },
        }),
      },
    ));
    expect(interpreted.ingestion).toMatchObject({
      mode: "local_deterministic_ingestion_only",
      providerContacted: false,
      toolDispatched: false,
      targetContacted: false,
    });
    expect(interpreted.result.evidenceId).toMatch(/^evidence/u);
    const transcript = await json(await fetch(
      `${baseUrl}/api/v2/guided/${missionId}/commander/transcript?runId=${encodeURIComponent(runId)}`,
    ));
    expect(transcript.currentObservation).toMatchObject({
      evidenceId: interpreted.result.evidenceId,
      reviewKind: "ingestion_attestation",
      verificationState: "unverified",
      reviewSummary: expect.stringContaining("no semantic interpretation"),
    });

    const completionResponse = await fetch(
      `${baseUrl}/api/v2/guided-decisions/${decision.id}/manual-result`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "guided-manual-production-accept-0001",
        },
        body: JSON.stringify({
          expectedFingerprint: decision.actionFingerprint,
          expectedParameters: decision.requestedParameters,
          evidenceId: interpreted.result.evidenceId,
        }),
      },
    );
    expect(completionResponse.status).toBe(409);
    const rejectedCompletion = await completionResponse.json() as Record<string, any>;
    expect(rejectedCompletion.error).toMatchObject({
      code: "guided_evidence_scope_conflict",
      retryable: false,
    });
    expect(runtime.repository.getRunProjection(runId).status).toBe("waiting_guided_decision");

    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?
    `).get(runId)).toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id WHERE a.run_id = ?
    `).get(runId)).toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence
      WHERE run_id = ? AND verification_state = 'verified'
    `).get(runId)).toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence_chain_events ec
      JOIN evidence e ON e.id = ec.evidence_id
      WHERE e.run_id = ? AND ec.event_type = 'ingestion_attested'
    `).get(runId)).toEqual({ count: 1 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence_chain_events ec
      JOIN evidence e ON e.id = ec.evidence_id
      WHERE e.run_id = ? AND ec.event_type = 'interpreted'
    `).get(runId)).toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM actions WHERE run_id = ?
    `).get(runId)).toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM run_evaluations WHERE run_id = ?
    `).get(runId)).toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'guided.commander.show_next_step'
    `).get(runId)).toEqual({ count: 1 });
    const phasePack = application.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_context_packs
      WHERE run_id = ? AND purpose LIKE 'Phase transition:%'
    `).get(runId) as { count: number };
    expect(phasePack.count).toBeGreaterThanOrEqual(1);
  });

  test("fails skip closed for expired, stale-plan, and ambiguous decisions and refuses approval on legacy ownership", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-guided-boundary-api-"));
    directories.push(directory);
    let runtime: MissionRuntimeEngine | undefined;
    const application = createCommandOsApplication({
      databasePath: join(directory, "ti-scale.sqlite"),
      readinessProviders: (_database, readRuntimeProjection) =>
        createRuntimeReadinessProviders(() => readRuntimeProjection().readiness),
      runtimeProjection,
      resolveActor: () => "operator:test",
      assertRunMutationLease: ({ runId }) =>
        runtime?.assertControlPlaneMutationAuthority(runId),
      projectionIntervalMs: 60_000,
    });
    applications.push(application);
    runtime = createProductionGuidedManualRuntime({
      database: application.database,
      brainContext: application.brainContext,
      workerId: "production-guided-boundary-api-test",
      scanIntervalMs: 50,
      leaseTtlMs: 5_000,
      decisionTtlMs: 60_000,
    });
    runtimes.push(runtime);

    const app = express();
    app.use(express.json({ limit: "1mb" }));
    app.use(application.router);
    app.use(createMissionRuntimeV2Router({ runtime, resolveActor: () => "operator:test" }));
    const server = createServer(app);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server did not bind");
    const baseUrl = `http://127.0.0.1:${address.port}`;

    application.start();
    await runtime.start();

    async function createFixture(suffix: string) {
      const created = await json(await fetch(`${baseUrl}/api/v2/missions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `guided-boundary-create-${suffix}-0001`,
        },
        body: JSON.stringify({
          journey: "guided",
          launch: true,
          authorizationConfirmed: true,
          title: `Guided boundary ${suffix}`,
          objective: "Establish one attributable baseline for the exact approved test address",
          target: `https://${suffix}.example.test/`,
          engagementId: `eng-guided-boundary-${suffix}`,
          explanationDepth: "balanced",
          executionPreference: "manual",
          evidenceExpectations: ["one attributable bounded text result"],
        }),
      }));
      const missionId = created.mission.id as string;
      const runId = created.run.id as string;
      await waitForStatus(runtime!, runId, "waiting_guided_decision");
      const decision = runtime!.repository.requireCurrentPendingDecision(
        (application.database.prepare(`
          SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
        `).get(runId) as { id: string }).id,
      );
      return { missionId, runId, decision };
    }

    async function decide(
      decision: ReturnType<MissionRuntimeEngine["repository"]["requireCurrentPendingDecision"]>,
      action: "skip" | "approve",
      key: string,
    ): Promise<Response> {
      return fetch(`${baseUrl}/api/v2/guided-decisions/${decision.id}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify({
          expectedFingerprint: decision.actionFingerprint,
          expectedParameters: decision.requestedParameters,
          ...(action === "skip" ? { reason: "Skip only this exact represented step" } : {}),
        }),
      });
    }

    const expired = await createFixture("expired");
    application.database.prepare("UPDATE guided_decisions SET expires_at = '1970-01-01T00:00:00.000Z' WHERE id = ?")
      .run(expired.decision.id);
    const expiredResponse = await decide(expired.decision, "skip", "guided-boundary-skip-expired-0001");
    expect(expiredResponse.status).toBe(409);
    expect(await expiredResponse.json()).toMatchObject({
      error: { code: "guided_decision_expired" },
    });
    expect(runtime.repository.getRunProjection(expired.runId).status).toBe("blocked");
    expect(application.database.prepare(`
      SELECT status FROM guided_decisions WHERE id = ?
    `).get(expired.decision.id)).toEqual({ status: "expired" });
    expect(application.database.prepare(`
      SELECT code FROM failure_diagnoses WHERE run_id = ? ORDER BY created_at DESC LIMIT 1
    `).get(expired.runId)).toEqual({ code: "guided_decision_expired" });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'guided.decision_skipped'
    `).get(expired.runId)).toEqual({ count: 0 });

    const stale = await createFixture("stale-plan");
    const staleCheckpointsBefore = application.database.prepare(`
      SELECT COUNT(*) AS count FROM checkpoints WHERE run_id = ?
    `).get(stale.runId) as { count: number };
    application.database.prepare("UPDATE runs SET current_plan_id = NULL WHERE id = ?")
      .run(stale.runId);
    const staleResponse = await decide(stale.decision, "skip", "guided-boundary-skip-stale-0001");
    expect(staleResponse.status).toBe(409);
    expect(await staleResponse.json()).toMatchObject({
      error: { code: "guided_step_stale" },
    });
    expect(application.database.prepare("SELECT status FROM guided_decisions WHERE id = ?")
      .get(stale.decision.id)).toEqual({ status: "pending" });
    expect(runtime.repository.getRunProjection(stale.runId).status).toBe("blocked");
    expect(application.database.prepare(`
      SELECT code FROM failure_diagnoses WHERE run_id = ? ORDER BY created_at DESC LIMIT 1
    `).get(stale.runId)).toEqual({ code: "guided_active_plan_integrity_conflict" });
    expect((application.database.prepare(`
      SELECT COUNT(*) AS count FROM checkpoints WHERE run_id = ?
    `).get(stale.runId) as { count: number }).count).toBeGreaterThan(staleCheckpointsBefore.count);
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'guided.decision_skipped'
    `).get(stale.runId)).toEqual({ count: 0 });

    const ambiguous = await createFixture("ambiguous");
    application.database.prepare("DROP INDEX idx_guided_decisions_one_pending_per_run").run();
    const otherStepId = "step-guided-boundary-ambiguous-other";
    application.database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        success_criteria_json, dependencies_json, action_class, risk_class,
        assigned_agent_id, created_at, updated_at
      ) SELECT ?, plan_id, run_id, ordinal + 100, phase,
        title || ' (other)', objective, 'pending', success_criteria_json,
        dependencies_json, action_class, risk_class, assigned_agent_id,
        created_at, updated_at
      FROM plan_steps WHERE id = ?
    `).run(otherStepId, ambiguous.decision.stepId);
    application.database.prepare(`
      INSERT INTO guided_decisions (
        id, mission_id, run_id, step_id, requested_action_fingerprint,
        requested_parameters_json, rationale, risk_class, reversibility,
        status, expires_at, created_at
      ) SELECT ?, mission_id, run_id, ?, requested_action_fingerprint,
        requested_parameters_json, rationale, risk_class, reversibility,
        'pending', expires_at, created_at
      FROM guided_decisions WHERE id = ?
    `).run("decision-guided-boundary-ambiguous-copy", otherStepId, ambiguous.decision.id);
    const ambiguousCheckpointsBefore = application.database.prepare(`
      SELECT COUNT(*) AS count FROM checkpoints WHERE run_id = ?
    `).get(ambiguous.runId) as { count: number };
    const ambiguousResponse = await decide(
      ambiguous.decision,
      "skip",
      "guided-boundary-skip-ambiguous-0001",
    );
    expect(ambiguousResponse.status).toBe(409);
    expect(await ambiguousResponse.json()).toMatchObject({
      error: { code: "guided_pending_decision_conflict" },
    });
    expect(runtime.repository.getRunProjection(ambiguous.runId).status).toBe("blocked");
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'guided.decision_skipped'
    `).get(ambiguous.runId)).toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT code FROM failure_diagnoses WHERE run_id = ? ORDER BY created_at DESC LIMIT 1
    `).get(ambiguous.runId)).toEqual({ code: "guided_decision_integrity_conflict" });
    expect((application.database.prepare(`
      SELECT COUNT(*) AS count FROM checkpoints WHERE run_id = ?
    `).get(ambiguous.runId) as { count: number }).count).toBeGreaterThan(ambiguousCheckpointsBefore.count);

    const legacy = await createFixture("legacy-approval");
    application.database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?")
      .run(legacy.missionId);
    const continuationsBefore = application.database.prepare(`
      SELECT COUNT(*) AS count FROM runtime_continuations WHERE run_id = ?
    `).get(legacy.runId) as { count: number };
    const eventsBefore = application.database.prepare(`
      SELECT COUNT(*) AS count FROM events WHERE run_id = ?
    `).get(legacy.runId) as { count: number };
    const legacyResponse = await decide(
      legacy.decision,
      "approve",
      "guided-boundary-approve-legacy-0001",
    );
    expect(legacyResponse.status).toBe(409);
    expect(await legacyResponse.json()).toMatchObject({
      error: {
        code: "control_plane_mismatch",
        humanMessage: "This mission and run are controlled elsewhere, so Ti-Scale made no changes.",
        retryable: false,
        category: "policy_denied",
      },
    });
    expect(application.database.prepare("SELECT status FROM guided_decisions WHERE id = ?")
      .get(legacy.decision.id)).toEqual({ status: "pending" });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM runtime_continuations WHERE run_id = ?
    `).get(legacy.runId)).toEqual(continuationsBefore);
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?")
      .get(legacy.runId)).toEqual({ count: 0 });
    expect(application.database.prepare(`SELECT COUNT(*) AS count FROM events WHERE run_id = ?`)
      .get(legacy.runId)).toEqual(eventsBefore);
  });

  test("rejects every operator mutation before idempotency for both split control-plane directions", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-cross-plane-api-"));
    directories.push(directory);
    let runtime: MissionRuntimeEngine | undefined;
    const execution = new FailClosedManualExecutionPort();
    const application = createCommandOsApplication({
      databasePath: join(directory, "ti-scale.sqlite"),
      readinessProviders: (_database, readRuntimeProjection) =>
        createRuntimeReadinessProviders(() => readRuntimeProjection().readiness),
      runtimeProjection,
      resolveActor: () => "operator:test",
      assertRunMutationLease: ({ runId }) =>
        runtime?.assertControlPlaneMutationAuthority(runId),
      projectionIntervalMs: 60_000,
    });
    applications.push(application);
    runtime = new MissionRuntimeEngine({
      database: application.database,
      planner: new LocalGuidedManualPlanner(),
      outcomeEvaluator: new DeterministicManualOutcomeEvaluator(application.database),
      brainContext: application.brainContext,
      execution,
      supportedJourneys: ["guided"],
      workerId: "production-guided-cross-plane-api-test",
      scanIntervalMs: 60_000,
      leaseTtlMs: 5_000,
      decisionTtlMs: 60_000,
    });
    runtimes.push(runtime);

    const app = express();
    app.use(express.json({ limit: "1mb" }));
    app.use(application.router);
    app.use(createMissionRuntimeV2Router({ runtime, resolveActor: () => "operator:test" }));
    const server = createServer(app);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server did not bind");
    const baseUrl = `http://127.0.0.1:${address.port}`;
    application.start();

    async function createSplitFixture(
      suffix: string,
      split: "mission_legacy" | "run_legacy",
    ) {
      const created = await json(await fetch(`${baseUrl}/api/v2/missions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `cross-plane-create-${suffix}-0001`,
        },
        body: JSON.stringify({
          journey: "guided",
          launch: true,
          authorizationConfirmed: true,
          title: `Cross-plane ${suffix}`,
          objective: "Represent one exact authorized local test step",
          target: `https://${suffix}.example.test/`,
          engagementId: `eng-cross-plane-${suffix}`,
          explanationDepth: "balanced",
          executionPreference: "manual",
          evidenceExpectations: [],
        }),
      }));
      const missionId = created.mission.id as string;
      const runId = created.run.id as string;
      await runtime!.processRunNow(runId);
      const decision = runtime!.repository.requireCurrentPendingDecision(
        (application.database.prepare(`
          SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
        `).get(runId) as { id: string }).id,
      );
      if (split === "mission_legacy") {
        application.database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?")
          .run(missionId);
      } else {
        application.database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?")
          .run(runId);
      }
      return { missionId, runId, decision };
    }

    function stateSnapshot(missionId: string, runId: string, decisionId: string) {
      return {
        mission: application.database.prepare("SELECT * FROM missions WHERE id = ?").get(missionId),
        run: application.database.prepare("SELECT * FROM runs WHERE id = ?").get(runId),
        decision: application.database.prepare("SELECT * FROM guided_decisions WHERE id = ?").get(decisionId),
        events: application.database.prepare("SELECT COUNT(*) AS count FROM events WHERE run_id = ?").get(runId),
        audits: application.database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE run_id = ?").get(runId),
        actions: application.database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?").get(runId),
        continuations: application.database.prepare("SELECT COUNT(*) AS count FROM runtime_continuations WHERE run_id = ?").get(runId),
        leases: application.database.prepare("SELECT * FROM control_plane_leases WHERE run_id = ?").all(runId),
        idempotency: application.database.prepare(`
          SELECT COUNT(*) AS count FROM settings WHERE key LIKE 'idempotency.runtime.%'
        `).get(),
      };
    }

    for (const split of ["mission_legacy", "run_legacy"] as const) {
      const fixture = await createSplitFixture(split, split);
      const body = {
        expectedFingerprint: fixture.decision.actionFingerprint,
        expectedParameters: fixture.decision.requestedParameters,
      };
      const resume = {
        reason: "Resume only the exact inspected checkpoint",
        expectedRunVersion: 1,
        expectedRunStatus: "blocked" as const,
        expectedCheckpointId: "checkpoint-cross-plane-placeholder",
        expectedCheckpointStateHash: "0".repeat(64),
        expectedCheckpointEventSequence: 0,
      };
      const requests = [
        ["approve", `/api/v2/guided-decisions/${fixture.decision.id}/approve`, body],
        ["reject", `/api/v2/guided-decisions/${fixture.decision.id}/reject`, { ...body, reason: "Reject this exact step" }],
        ["manual", `/api/v2/guided-decisions/${fixture.decision.id}/manual-result`, { ...body, evidenceId: "evidence-cross-plane-placeholder" }],
        ["skip", `/api/v2/guided-decisions/${fixture.decision.id}/skip`, { ...body, reason: "Skip this exact step" }],
        ["stop", `/api/v2/guided-decisions/${fixture.decision.id}/stop`, { ...body, reason: "Stop this Guided mission" }],
        ["pause", `/api/v2/runs/${fixture.runId}/pause`, { reason: "Pause this run" }],
        ["resume", `/api/v2/runs/${fixture.runId}/resume`, resume],
        ["cancel", `/api/v2/runs/${fixture.runId}/cancel`, { reason: "Cancel this run" }],
      ] as const;
      const before = stateSnapshot(fixture.missionId, fixture.runId, fixture.decision.id);
      for (const [name, path, requestBody] of requests) {
        const response = await fetch(`${baseUrl}${path}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": `cross-plane-${split}-${name}-0001`,
          },
          body: JSON.stringify(requestBody),
        });
        expect(response.status).toBe(409);
        expect(await response.json()).toEqual({
          error: {
            code: "control_plane_mismatch",
            message: `Run ${fixture.runId} is not exclusively owned by Ti-Scale`,
            humanMessage: "This mission and run are controlled elsewhere, so Ti-Scale made no changes.",
            retryable: false,
            category: "policy_denied",
            traceId: expect.any(String),
            remediation: "Open this run through its owning control plane; imported legacy runs remain read-only in Ti-Scale.",
            timestamp: expect.any(String),
          },
        });
      }

      const directCalls: Array<() => Promise<unknown>> = [
        () => runtime!.approveGuidedDecision(fixture.decision.id, "operator:test"),
        () => runtime!.rejectGuidedDecision(fixture.decision.id, "operator:test", "Reject exact step"),
        () => runtime!.submitManualGuidedResult(fixture.decision.id, "operator:test", "evidence-placeholder"),
        () => runtime!.skipGuidedDecision(fixture.decision.id, "operator:test", "Skip exact step"),
        () => runtime!.stopGuidedMission(fixture.decision.id, "operator:test", "Stop exact mission"),
        () => runtime!.cancelRun(fixture.runId, "operator:test", "Cancel exact run"),
        () => runtime!.acceptExecutionResult({
          actionId: "action-cross-plane-placeholder",
          runId: fixture.runId,
          actionFingerprint: "fingerprint-cross-plane-placeholder",
          success: true,
          summary: "Result must not be accepted across ownership.",
          progress: {},
        }),
        () => runtime!.replayContinuations(fixture.runId),
      ];
      for (const call of directCalls) {
        await expect(call()).rejects.toMatchObject({
          code: "control_plane_mismatch",
        });
      }
      expect(() => runtime!.pauseRun(fixture.runId, "operator:test", "Pause exact run"))
        .toThrow(expect.objectContaining({ code: "control_plane_mismatch" }));
      expect(() => runtime!.assertResumeRunBoundary(fixture.runId, resume))
        .toThrow(expect.objectContaining({ code: "control_plane_mismatch" }));
      expect(() => runtime!.notifyContinuationAvailable(fixture.runId))
        .toThrow(expect.objectContaining({ code: "control_plane_mismatch" }));
      expect(() => runtime!.assertV2ControlPlaneOwnership(fixture.runId))
        .toThrow(expect.objectContaining({ code: "control_plane_mismatch" }));
      expect(() => runtime!.assertControlPlaneMutationAuthority(fixture.runId))
        .toThrow(expect.objectContaining({ code: "control_plane_mismatch" }));
      expect(stateSnapshot(fixture.missionId, fixture.runId, fixture.decision.id)).toEqual(before);
    }
    expect(execution.dispatchAttemptCount).toBe(0);
    expect(execution.resumeAttemptCount).toBe(0);
  });
});
