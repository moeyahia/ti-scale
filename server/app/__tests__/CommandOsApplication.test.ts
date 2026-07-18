import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DATABASE_MIGRATIONS } from "../../db";
import { ControlPlaneLeaseService, type ControlPlaneLease } from "../../control-plane";
import { createRuntimeReadinessProviders } from "../RuntimeReadiness";
import { createCommandOsApplication, type CommandOsApplication } from "../CommandOsApplication";

const temporaryDirectories: string[] = [];
const servers: Server[] = [];
const applications: CommandOsApplication[] = [];

afterEach(async () => {
  await Promise.all(applications.splice(0).map((application) => application.stop()));
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("CommandOsApplication", () => {
  test("reopens a valid canonical store and fails closed when the existing image is corrupt", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-app-integrity-"));
    temporaryDirectories.push(directory);
    const databasePath = join(directory, "ti-scale.sqlite");
    const snapshot = {
      actionBoundaryActive: false,
      delegationEnforced: false,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: false,
      specialistsConfigured: 0,
      providers: [],
      mcp: { enabled: false, executionMode: "disabled" as const, startPermitted: false, configuredServers: 0, runnableServers: 0, missingDependencies: 0, missingSecrets: 0 },
      eventStream: "healthy" as const,
      secondBrain: "healthy" as const,
      legacyExecutionEnabled: false,
    };
    const options = {
      databasePath,
      readinessProviders: () => createRuntimeReadinessProviders(() => snapshot),
      runtimeProjection: () => ({ readiness: snapshot, agents: [], mcpServers: [] }),
      resolveActor: () => "operator",
      projectionIntervalMs: 60_000,
    };
    const initial = createCommandOsApplication(options);
    await initial.stop();
    const reopened = createCommandOsApplication(options);
    expect(reopened.database.pragma("quick_check")).toEqual([{ quick_check: "ok" }]);
    await reopened.stop();

    writeFileSync(databasePath, "corrupt-existing-ti-scale-store", { flag: "w" });
    rmSync(`${databasePath}-wal`, { force: true });
    rmSync(`${databasePath}-shm`, { force: true });
    expect(() => createCommandOsApplication(options)).toThrow();
  });

  test("migrates, starts, serves real health, and stops cleanly", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-app-"));
    temporaryDirectories.push(directory);
    const snapshot = {
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
    };
    const mutationLeases = new Map<string, () => ControlPlaneLease>();
    const commandOs = createCommandOsApplication({
      databasePath: join(directory, "ti-scale.sqlite"),
      readinessProviders: () => createRuntimeReadinessProviders(() => snapshot),
      runtimeProjection: () => ({ readiness: snapshot, agents: [], mcpServers: [] }),
      resolveActor: () => "operator",
      assertRunMutationLease: ({ runId }) => mutationLeases.get(runId)?.(),
      projectionIntervalMs: 60_000,
    });
    applications.push(commandOs);
    const app = express();
    app.use(express.json());
    app.use(commandOs.router);
    const server = createServer(app);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server has no TCP address");

    commandOs.start();
    expect(commandOs.started).toBe(true);
    const response = await fetch(`http://127.0.0.1:${address.port}/api/v2/system/readiness`);
    expect(response.status).toBe(200);
    const health = await response.json() as any;
    expect(health.status).toBe("degraded");
    expect(health.database.currentMigration).toBe(DATABASE_MIGRATIONS.at(-1)?.version);
    expect(health.eventStream.status).toBe("healthy");
    expect(health.execution).toMatchObject({ autonomous: "unavailable", guided: "unavailable" });
    expect(health.dependencies).toMatchObject({
      providers: { status: "unavailable", declared: 0, callable: 0, enforcing: 0 },
      mcp: { status: "unavailable", configuredServers: 0, runnableServers: 0 },
      specialists: { status: "unavailable", configured: 0 },
    });

    const overview = await fetch(`http://127.0.0.1:${address.port}/api/v2/overview`);
    expect(overview.status).toBe(200);
    const body = await overview.json() as any;
    expect(body.schemaVersion).toBe("2.4");
    expect(body.readiness.status).toBe("blocked");

    const openApiResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/openapi.json`);
    expect(openApiResponse.status).toBe(200);
    const openApi = await openApiResponse.json() as any;
    expect(openApi.openapi).toBe("3.1.0");
    expect(openApi.info.title).toBe("Ti-Scale API");
    expect(openApi.components.schemas.Journey.enum).toEqual(["autonomous", "guided"]);

    const eventContractResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/contracts/events`);
    expect(eventContractResponse.status).toBe(200);
    const eventContract = await eventContractResponse.json() as any;
    expect(eventContract.schemaVersion).toBe("2.4");
    expect(eventContract.resume.replayEndpoint).toBe("/api/v2/events/replay");

    const registryResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/registries/intake?journey=autonomous&templateId=safe_recon`,
    );
    expect(registryResponse.status).toBe(200);
    const registry = await registryResponse.json() as any;
    expect(registry.schemaVersion).toBe("2.4");
    expect(registry.source.status).toBe("unavailable");
    expect(Object.keys(registry.actionClasses.classes)).toHaveLength(26);
    expect(Object.keys(registry.evidenceTypes.types)).toHaveLength(21);
    expect(Object.keys(registry.deliverables.deliverables)).toHaveLength(15);

    const resolvedResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/registries/intake/resolve`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          journey: "autonomous",
          authorizationAcknowledged: true,
          targets: [{ value: "10.10.10.0/24" }],
        }),
      },
    );
    expect(resolvedResponse.status).toBe(200);
    const resolved = await resolvedResponse.json() as any;
    expect(resolved.request.authorization.allowedTargets).toEqual(["10.10.10.0/24"]);
    expect(resolved.request.contract.destructivePolicy).toBe("prohibited");
    expect(resolved.inferredFields).toContain("title");
    expect(resolved.limitations.join(" ")).toContain("No attested runtime capability manifest");

    const researchResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/research`);
    expect(researchResponse.status).toBe(200);
    const research = await researchResponse.json() as any;
    expect(research.schemaVersion).toBe("2.4");
    expect(research.readiness.status).toBe("blocked");
    expect(research.catalog.map((campaign: { id: string }) => campaign.id)).toEqual([
      "repeated_no_progress_action_reduction",
      "specialist_routing_quality",
      "memory_retrieval_precision",
    ]);
    expect(research.publicLlmBoundary).toMatchObject({
      role: "proposal_only",
      rawClientEvidenceAllowed: false,
      directToolExecutionAllowed: false,
      automaticPromotionAllowed: false,
    });

    const campaignResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/research/campaigns`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "app-research-campaign-1" },
      body: JSON.stringify({ catalogId: "repeated_no_progress_action_reduction", ownerAcknowledged: true }),
    });
    expect(campaignResponse.status).toBe(201);
    const campaign = await campaignResponse.json() as any;
    expect(campaign.campaign).toMatchObject({ status: "draft", dimensionCount: 3, experimentCount: 0 });

    const stoppedResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/research/campaigns/${encodeURIComponent(campaign.campaign.id)}/stop`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "app-research-stop-1" },
      body: JSON.stringify({ expectedUpdatedAt: campaign.campaign.updatedAt, reason: "Stop before benchmark configuration." }),
    });
    expect(stoppedResponse.status).toBe(200);
    expect((await stoppedResponse.json() as any).campaign.status).toBe("stopped");

    const missionId = "mission-operational-truth-app";
    const now = new Date().toISOString();
    commandOs.database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, status, authorization_status,
        scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
        created_by, created_at, updated_at
      ) VALUES (?, ?, ?, 'guided', 'active', 'verified', '{}', '[]', '{}', '{}', ?, ?, ?)
    `).run(missionId, "Operational truth application test", "Keep raw output out of evidence", "operator", now, now);
    commandOs.database.prepare(`
      INSERT INTO mission_targets (
        id, mission_id, target, target_type, disposition, normalized_target,
        metadata_json, created_at
      ) VALUES ('target-operational-truth-app', ?, 'fixture.local', 'domain', 'allowed', 'fixture.local', '{}', ?)
    `).run(missionId, now);

    const runId = "run-intelligence-app";
    commandOs.database.prepare(`
      INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
      VALUES (?, ?, 'guided', 'queued', ?, ?)
    `).run(runId, missionId, now, now);
    const operationalTruthLeases = new ControlPlaneLeaseService(commandOs.database);
    const operationalTruthLeaseOwner = "ti-scale-application-truth-runtime";
    const operationalTruthLeaseToken = "ti-scale-application-truth-token-000000";
    operationalTruthLeases.acquire({
      runId,
      controlPlane: "ti_scale",
      leaseOwner: operationalTruthLeaseOwner,
      leaseToken: operationalTruthLeaseToken,
      ttlMs: 300_000,
    });
    mutationLeases.set(runId, () => operationalTruthLeases.assertMutationAuthority({
      runId,
      controlPlane: "ti_scale",
      leaseOwner: operationalTruthLeaseOwner,
      leaseToken: operationalTruthLeaseToken,
    }));

    const logResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/operational-truth/missions/${missionId}/logs`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "app-operational-log-1" },
        body: JSON.stringify({
          runId,
          severity: "info",
          domain: "recon",
          recordType: "command_output",
          humanSummary: "Authorized scanner returned raw output for parsing.",
          technicalPayload: { stdout: "raw output is a log, not verified evidence" },
          sensitivity: "internal",
          occurredAt: now,
        }),
      },
    );
    expect(logResponse.status).toBe(201);
    expect((await logResponse.json() as any).log.recordType).toBe("command_output");

    const verifiedResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/operational-truth/missions/${missionId}/verified-evidence`,
    );
    expect(verifiedResponse.status).toBe(200);
    expect((await verifiedResponse.json() as any).items).toEqual([]);

    const missionRuntimeResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/missions/${missionId}/runtime`,
    );
    expect(missionRuntimeResponse.status).toBe(200);
    const missionRuntime = await missionRuntimeResponse.json() as any;
    expect(missionRuntime).toMatchObject({
      schemaVersion: "2.4",
      mission: { id: missionId, journey: "guided" },
      runs: [{ id: runId, missionId, journey: "guided", status: "queued" }],
    });

    const runsResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/runs?journey=guided`);
    expect(runsResponse.status).toBe(200);
    expect((await runsResponse.json() as any).items).toMatchObject([
      { id: runId, missionId, journey: "guided", status: "queued" },
    ]);

    const runResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/runs/${runId}`);
    expect(runResponse.status).toBe(200);
    expect(await runResponse.json() as any).toMatchObject({
      schemaVersion: "2.4",
      run: { id: runId, missionId, journey: "guided", status: "queued" },
      latestCheckpoint: null,
    });

    const plansResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/runs/${runId}/plans`);
    expect(plansResponse.status).toBe(200);
    expect((await plansResponse.json() as any).items).toEqual([]);

    const decisionsResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/decisions?runId=${runId}`);
    expect(decisionsResponse.status).toBe(200);
    expect((await decisionsResponse.json() as any).items).toEqual([]);

    const transcriptRunId = "run-guided-transcript-planning-app";
    commandOs.database.prepare(`
      INSERT INTO runs (id, mission_id, journey, status, status_reason, created_at, updated_at)
      VALUES (?, ?, 'guided', 'planning', 'Building the first represented Guided step', ?, ?)
    `).run(transcriptRunId, missionId, now, now);
    const transcriptResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/guided/${missionId}/commander/transcript?runId=${transcriptRunId}`,
    );
    expect(transcriptResponse.status).toBe(200);
    expect(await transcriptResponse.json() as any).toMatchObject({
      schemaVersion: "2.4",
      mission: { id: missionId },
      run: { id: transcriptRunId, status: "planning", currentStepId: null },
      currentStep: null,
      currentObservation: null,
      items: [],
      nextCursor: null,
    });
    const unavailableProviderMutation = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/guided/${missionId}/commander/explain-more`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
    );
    expect(unavailableProviderMutation.status).toBe(404);

    const planChangeRunId = "run-plan-change-app";
    const planChangePlanId = "plan-change-base-app";
    const planChangeStepId = "plan-change-step-app";
    commandOs.database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, provider_policy_json, tool_policy_json,
        configuration_json, version, created_at, updated_at
      ) VALUES ('agent-plan-change-app', 'recon', 'Plan change specialist', 'available', '{}', '{}', '{}', '1', ?, ?)
    `).run(now, now);
    commandOs.database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, current_plan_id, current_step_id,
        created_at, updated_at, version
      ) VALUES (?, ?, 'guided', 'queued', ?, ?, ?, ?, 1)
    `).run(planChangeRunId, missionId, planChangePlanId, planChangeStepId, now, now);
    const controlPlaneLeases = new ControlPlaneLeaseService(commandOs.database);
    const controlLeaseOwner = "ti-scale-application-test-runtime";
    const controlLeaseToken = "ti-scale-application-test-token-000000";
    controlPlaneLeases.acquire({
      runId: planChangeRunId,
      controlPlane: "ti_scale",
      leaseOwner: controlLeaseOwner,
      leaseToken: controlLeaseToken,
      ttlMs: 300_000,
    });
    mutationLeases.set(planChangeRunId, () => controlPlaneLeases.assertMutationAuthority({
      runId: planChangeRunId,
      controlPlane: "ti_scale",
      leaseOwner: controlLeaseOwner,
      leaseToken: controlLeaseToken,
    }));
    commandOs.database.prepare(`
      INSERT INTO plans (
        id, run_id, version, status, strategy_summary, rationale_summary,
        plan_hash, created_by, created_at, activated_at
      ) VALUES (?, ?, 1, 'active', 'Map authorized scope', 'Preserve evidence', ?, 'planner', ?, ?)
    `).run(planChangePlanId, planChangeRunId, "c".repeat(64), now, now);
    commandOs.database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        success_criteria_json, dependencies_json, action_class, risk_class,
        assigned_agent_id, created_at, updated_at
      ) VALUES (?, ?, ?, 0, 'Recon', 'Map scope', 'Map attributable scope', 'ready',
        '["Scope mapped"]', '[]', 'passive_intelligence_osint', 'low',
        'agent-plan-change-app', ?, ?)
    `).run(planChangeStepId, planChangePlanId, planChangeRunId, now, now);
    commandOs.database.prepare(`
      INSERT INTO mission_constraints (
        id, mission_id, constraint_type, value_json, source, created_at
      ) VALUES ('constraint-plan-change-app', ?, 'represented_action', ?, ?, ?)
    `).run(missionId, JSON.stringify({
      action: {
        actionType: "passive_intelligence_osint",
        actionClass: "passive_intelligence_osint",
        target: "fixture.local",
        arguments: {},
        intentSummary: "Collect attributable scope facts",
        kind: "manual",
        idempotent: true,
        destructive: false,
      },
      explanation: "Collect one bounded observation.",
      rationale: "Reduce uncertainty.",
      reversibility: "Read-only",
      dependencies: [],
    }), planChangeStepId, now);
    const planChangeResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/runs/${planChangeRunId}/plan-changes`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "app-plan-change-1" },
        body: JSON.stringify({
          basePlanId: planChangePlanId,
          expectedRunVersion: 1,
          expectedPlanVersion: 1,
          requestText: "Clarify the bounded strategy before execution.",
          operations: [{ kind: "update_plan", strategySummary: "Map only attributable authorized scope" }],
        }),
      },
    );
    expect(planChangeResponse.status).toBe(201);
    expect(await planChangeResponse.json() as any).toMatchObject({
      schemaVersion: "2.4",
      request: {
        runId: planChangeRunId,
        basePlanId: planChangePlanId,
        status: "validated",
        inflightImpact: { safeToApply: true },
      },
    });

    const metricResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/runs/${runId}/intelligence/metrics/recompute`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "app-run-metrics-1" },
        body: "{}",
      },
    );
    expect(metricResponse.status).toBe(200);
    const metricBody = await metricResponse.json() as any;
    expect(metricBody.snapshot).toMatchObject({ runId, missionId, metricSchemaVersion: "run-metrics-v2.4.0" });
    expect(metricBody.snapshot.metrics.length).toBeGreaterThan(40);

    const topologyResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/missions/${missionId}/intelligence/topology?runId=${runId}`,
    );
    expect(topologyResponse.status).toBe(200);
    expect((await topologyResponse.json() as any).digitalTwin).toMatchObject({ missionId, runId, nodes: [], edges: [] });

    const cveResponse = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/missions/${missionId}/intelligence/cves?runId=${runId}`,
    );
    expect(cveResponse.status).toBe(200);
    expect(await cveResponse.json() as any).toEqual({ schemaVersion: "2.4", items: [] });
  });
});
