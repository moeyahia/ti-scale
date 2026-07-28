import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import { createServer as createTcpServer } from "node:net";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createProductionGuidedLocalToolRuntime,
  localGuidedManualAgentProjection,
  type MissionRuntimeEngine,
} from "../../command-runtime";
import { emptyRuntimeSourceManifests } from "../../domain";
import {
  DirectProcessLocalToolInvocationAdapter,
  LocalToolCapabilityManifest,
  OperationalTruthLocalToolOutputRecorder,
  parseBubblewrapProbeSandboxDescriptor,
  ReviewedLocalToolExecutionPort,
} from "../../local-tools";
import { createMissionRuntimeV2Router } from "../../routes/missionRuntimeV2Routes";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import type { TrustedLocalFileReceipt } from "../../trusted-runtime-config";
import { composeReviewedWebAssessmentLocalManifest } from "../../web-assessment-tools";
import { applyLocalGuidedToolRuntimeProjection, projectLocalGuidedToolRuntime } from "../LocalGuidedToolRuntimeProjection";
import { LocalGuidedToolActivationCoordinator } from "../LocalGuidedToolActivationCoordinator";
import type { LoadedLocalGuidedToolConfiguration } from "../LocalGuidedToolConfiguration";
import { createRuntimeReadinessProviders } from "../RuntimeReadiness";
import { createCommandOsApplication, type CommandOsApplication } from "../CommandOsApplication";
import type { RuntimeProjectionInput } from "../RuntimeProjectionService";

const TOOL_TEMPLATE = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json",
  import.meta.url,
);
const SANDBOX_TEMPLATE = new URL(
  "../../../deployment/runtime-config/bubblewrap-probe-sandbox.v1.json",
  import.meta.url,
);
const EXPECTED_REVIEWED_TOOL_IDS = Object.freeze([
  "kali:curl-http-metadata",
  "kali:ffuf-bounded-content-discovery",
  "kali:host-dns-query",
  "kali:ncat-tcp-connect",
  "kali:nmap-tcp-connect-service-scan",
  "kali:ping-host-liveness",
  "kali:whatweb-bounded-fingerprint",
] as const);
const REVIEWED_WEB_TOOL_IDS = Object.freeze([
  "kali:ffuf-bounded-content-discovery",
  "kali:whatweb-bounded-fingerprint",
] as const);
const applications: CommandOsApplication[] = [];
const runtimes: MissionRuntimeEngine[] = [];
const activations: LocalGuidedToolActivationCoordinator[] = [];
const executionPorts: ReviewedLocalToolExecutionPort[] = [];
const servers: Server[] = [];
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(activations.splice(0).map((activation) => activation.stop()));
  await Promise.all(runtimes.splice(0).map((runtime) => runtime.stop()));
  for (const execution of executionPorts.splice(0)) execution.close();
  await Promise.all(servers.splice(0).map((server) =>
    new Promise<void>((resolve) => server.close(() => resolve()))));
  await Promise.all(applications.splice(0).map((application) => application.stop()));
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function receipt(sourceSha256: string): TrustedLocalFileReceipt {
  return {
    schemaVersion: "ti-scale.trusted-local-file-receipt.v1",
    sourcePath: "/reviewed/config.json",
    trustRoot: "/reviewed",
    sourceSha256,
    canonicalSha256: sourceSha256,
    byteSize: 1,
    ownerUid: 0,
    ownerGid: 0,
    mode: 0o600,
    device: "1",
    inode: "1",
  };
}

function configuration(runtimeRoot: string): LoadedLocalGuidedToolConfiguration {
  const manifest = composeReviewedWebAssessmentLocalManifest(
    new LocalToolCapabilityManifest(
      JSON.parse(readFileSync(TOOL_TEMPLATE, "utf8")),
    ),
  );
  const probeSandbox = parseBubblewrapProbeSandboxDescriptor(
    JSON.parse(readFileSync(SANDBOX_TEMPLATE, "utf8")),
  );
  return {
    status: "loaded",
    manifest,
    webAssessmentIncluded: true,
    probeSandbox,
    workspaceMappings: {
      schemaVersion: "ti-scale.engagement-workspace-mappings.v1",
      mappingVersion: "guided-local-integration-v1",
      mappings: [{ logicalRoot: "/engagements", runtimeRoot }],
    },
    receipts: {
      capabilityManifest: receipt(manifest.descriptor.manifestSha256),
      probeSandbox: receipt(probeSandbox.expectedSha256),
      workspaceMappings: receipt("a".repeat(64)),
    },
  };
}

function baselineProjection(): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: false,
      delegationEnforced: false,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: false,
      specialistsConfigured: 0,
      providers: [],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      eventStream: "healthy",
      secondBrain: "healthy",
      legacyExecutionEnabled: false,
      guidedManualPlanning: {
        status: "ready",
        plannerId: "ti-scale.local-guided-manual-planner",
        executionMode: "manual_only",
        targetInteraction: "operator_only",
        providerContact: false,
        toolDispatch: false,
        reason: "Manual representation remains the fail-closed fallback.",
      },
    },
    agents: [localGuidedManualAgentProjection()],
    mcpServers: [],
    capabilityManifests: emptyRuntimeSourceManifests(),
  };
}

async function responseJson(response: Response): Promise<Record<string, any>> {
  const raw = await response.text();
  let body: Record<string, any>;
  try {
    body = JSON.parse(raw) as Record<string, any>;
  } catch {
    throw new Error(`${response.status}: expected JSON, received ${raw.slice(0, 500) || "an empty body"}`);
  }
  if (!response.ok) throw new Error(`${response.status}: ${JSON.stringify(body)}`);
  return body;
}

async function waitForStatus(runtime: MissionRuntimeEngine, runId: string, expected: string) {
  for (let attempt = 0; attempt < 3_000; attempt += 1) {
    const current = runtime.repository.getRunProjection(runId).status;
    if (current === expected) return;
    if (["blocked", "failed", "cancelled"].includes(current) && current !== expected) {
      throw new Error(`Run ${runId} reached ${current} instead of ${expected}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Run ${runId} did not reach ${expected}`);
}

describe("production-composed reviewed local Guided runtime", () => {
  test("proves all seven reviewed bindings through mounted V2 actions while exact-decision failures dispatch nothing", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-guided-local-api-"));
    roots.push(root);
    const workspaceRoot = join(root, "engagements");
    mkdirSync(workspaceRoot, { mode: 0o700 });
    const configured = configuration(workspaceRoot);
    let runtime: MissionRuntimeEngine | undefined;
    let adapter: DirectProcessLocalToolInvocationAdapter | undefined;
    let activation: LocalGuidedToolActivationCoordinator | undefined;
    const plannerHeldToolIds = new Set<string>();
    const runtimeProjection = (): RuntimeProjectionInput => applyLocalGuidedToolRuntimeProjection(
      baselineProjection(),
      projectLocalGuidedToolRuntime({
        baselineManifests: emptyRuntimeSourceManifests(),
        manifest: configured.manifest,
        activationReceipts: activation?.snapshot().activationReceipts ?? [],
        adapterId: adapter?.adapterId ?? null,
      }),
    );
    const application = createCommandOsApplication({
      databasePath: join(root, "ti-scale.sqlite"),
      readinessProviders: (_database, readProjection) =>
        createRuntimeReadinessProviders(() => readProjection().readiness),
      runtimeProjection,
      readToolExecutionPreflight: (toolId) =>
        activation?.runner.readToolExecutionPreflight(toolId),
      resolveActor: () => "operator:test",
      assertRunMutationLease: ({ runId }) =>
        runtime?.assertControlPlaneMutationAuthority(runId),
      projectionIntervalMs: 60_000,
    });
    applications.push(application);
    const resolver = new EngagementWorkspaceResolver(configured.workspaceMappings.mappings);
    adapter = new DirectProcessLocalToolInvocationAdapter({
      manifest: configured.manifest,
      workspaceResolver: resolver,
      sandboxExecutable: {
        path: configured.probeSandbox.executablePath,
        expectedSha256: configured.probeSandbox.expectedSha256,
      },
    });
    const execution = new ReviewedLocalToolExecutionPort({
      database: application.database,
      executionJourney: "guided",
      manifest: configured.manifest,
      adapter,
      workspaceResolver: resolver,
      outputRecorder: new OperationalTruthLocalToolOutputRecorder(application.database, configured.manifest),
      assertControlPlaneAuthority: (runId) => {
        if (!runtime) throw new Error("Runtime authority is unavailable");
        return runtime.assertControlPlaneMutationAuthority(runId);
      },
    });
    let dispatchFailure: unknown;
    const provedToolIds = new Set<string>();
    const provedRunIds = new Set<string>();
    let forceAuthoritySweepBeforeDispatch = false;
    let authoritySweepAtDispatch: ReturnType<MissionRuntimeEngine["maintainWaitingGuidedAuthorities"]> | undefined;
    const reviewedDispatch = execution.dispatch.bind(execution);
    execution.dispatch = async (action, signal) => {
      try {
        if (forceAuthoritySweepBeforeDispatch) {
          if (!runtime) throw new Error("Runtime authority is unavailable");
          authoritySweepAtDispatch = runtime.maintainWaitingGuidedAuthorities();
          forceAuthoritySweepBeforeDispatch = false;
        }
        await reviewedDispatch(action, signal);
      } catch (error) {
        dispatchFailure = error;
        throw error;
      }
    };
    executionPorts.push(execution);
    runtime = createProductionGuidedLocalToolRuntime({
      database: application.database,
      brainContext: application.brainContext,
      manifest: configured.manifest,
      logicalWorkspace: "/engagements",
      readReadyToolIds: () => new Set(
        [...(activation?.readyToolIds() ?? new Set<string>())]
          .filter((toolId) => !plannerHeldToolIds.has(toolId)),
      ),
      execution,
      workerId: "guided-local-api-integration",
      scanIntervalMs: 50,
      leaseTtlMs: 5_000,
      decisionTtlMs: 60_000,
    });
    runtimes.push(runtime);
    activation = new LocalGuidedToolActivationCoordinator({
      configuration: configured,
      adapter,
      executionPort: execution,
      workspaceResolver: resolver,
    });
    activations.push(activation);
    const activationSnapshot = await activation.start();
    expect(activationSnapshot.status).toBe("ready");
    expect([...activation.readyToolIds()].sort()).toEqual([...EXPECTED_REVIEWED_TOOL_IDS]);

    const app = express();
    app.use(express.json({ limit: "1mb" }));
    app.get("/fixture-http", (_request, response) => {
      response.setHeader("X-Ti-Scale-Fixture", "reviewed-local-tool");
      response.status(204).end();
    });
    app.get("/fixture-http-negative", (_request, response) => {
      response.setHeader("X-Ti-Scale-Fixture", "reviewed-local-negative");
      response.status(404).end();
    });
    app.get("/fixture-web/", (_request, response) => {
      response.type("html").status(200).send(
        "<!doctype html><html><head><title>Ti-Scale disposable fixture</title></head><body>reviewed loopback fixture</body></html>",
      );
    });
    app.get("/fixture-web/health", (_request, response) => {
      response.type("text").status(200).send("healthy");
    });
    app.get("/fixture-web/login", (_request, response) => {
      response.type("html").status(401).send("<html><title>Fixture login</title></html>");
    });
    app.use(application.router);
    app.use(createMissionRuntimeV2Router({ runtime, resolveActor: () => "operator:test" }));
    const server = createServer(app);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server did not bind");
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const tcpTarget = `tcp://127.0.0.1:${address.port}`;

    application.start();
    await runtime.start();
    const readiness = await responseJson(await fetch(`${baseUrl}/api/v2/system/readiness`));
    expect(readiness.execution.guided).toBe("ready");
    expect(runtimeProjection().readiness.guidedLocalToolExecution).toMatchObject({
      status: "ready",
      readyToolIds: expect.arrayContaining(["kali:ncat-tcp-connect"]),
      exactDecisionRequired: true,
      providerContact: false,
      mcpTransport: false,
    });
    const capabilitySelfTests = await responseJson(await fetch(
      `${baseUrl}/api/v2/system/capability-self-tests`,
    ));
    const localDependencyResults = (capabilitySelfTests.results as Array<Record<string, any>>)
      .filter((entry) => entry.component.kind === "tool_dependency"
        && String(entry.component.id).startsWith("kali:"));
    expect(localDependencyResults).toHaveLength(EXPECTED_REVIEWED_TOOL_IDS.length * 7);
    expect(localDependencyResults.every((entry) =>
      entry.status === "pass"
      && entry.availability === "available"
      && entry.freshness.state === "fresh")).toBeTrue();

    const scenarios = [
      {
        key: "http",
        toolId: "kali:curl-http-metadata",
        target: `${baseUrl}/fixture-http`,
        heldToolIds: REVIEWED_WEB_TOOL_IDS,
        objective: "Check one exact local HTTP endpoint and retain its bounded metadata as a log-backed observation",
        observationType: "http_metadata_response",
        expectedResult: { responseObserved: true, statusCode: 204 },
      },
      {
        key: "dns",
        toolId: "kali:host-dns-query",
        target: "localhost.localdomain",
        heldToolIds: [],
        objective: "Resolve one exact local DNS name and retain the bounded resolver result as a log-backed observation",
        observationType: "dns_record_query",
        expectedResult: { queryName: "localhost.localdomain", recordType: "A", noRecord: false },
      },
      {
        key: "ping",
        toolId: "kali:ping-host-liveness",
        target: "127.0.0.1",
        heldToolIds: [],
        objective: "Check one exact loopback host and retain the bounded liveness result as a log-backed observation",
        observationType: "host_liveness",
        expectedResult: { host: "127.0.0.1", responded: true, received: 2 },
      },
      {
        key: "tcp",
        toolId: "kali:ncat-tcp-connect",
        target: tcpTarget,
        heldToolIds: [],
        objective: "Check one exact local TCP service without an application payload and retain the bounded result as a log-backed observation",
        observationType: "tcp_connectivity",
        expectedResult: { host: "127.0.0.1", port: address.port, connectionEstablished: true },
      },
      {
        key: "nmap",
        toolId: "kali:nmap-tcp-connect-service-scan",
        target: "127.0.0.1",
        heldToolIds: [],
        objective: "Inspect one exact loopback TCP port and retain the bounded service result as a log-backed observation",
        observationType: "tcp_service_scan",
        expectedResult: {
          host: "127.0.0.1",
          requestedPorts: [address.port],
          openPortCount: 1,
          scanCompleted: true,
        },
        guidedReconnaissance: {
          mode: "tcp_service_scan",
          portSelection: { source: "custom", ports: [address.port] },
        },
      },
    ] as const;

    for (const [index, scenario] of scenarios.entries()) {
      plannerHeldToolIds.clear();
      for (const toolId of scenario.heldToolIds) plannerHeldToolIds.add(toolId);
      dispatchFailure = undefined;
      const created = await responseJson(await fetch(`${baseUrl}/api/v2/missions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `guided-local-api-create-000${index + 1}`,
        },
        body: JSON.stringify({
          journey: "guided",
          launch: true,
          authorizationConfirmed: true,
          title: `Reviewed local ${scenario.key} API fixture`,
          objective: scenario.objective,
          target: scenario.target,
          engagementId: `eng-guided-local-api-${scenario.key}`,
          explanationDepth: "balanced",
          executionPreference: "single_step_agent",
          evidenceExpectations: [],
          ...("guidedReconnaissance" in scenario
            ? { guidedReconnaissance: scenario.guidedReconnaissance }
            : {}),
        }),
      }));
      const runId = created.run.id as string;
      await waitForStatus(runtime, runId, "waiting_guided_decision");
      const decisionId = (application.database.prepare(`
        SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
      `).get(runId) as { id: string }).id;
      const decision = runtime.repository.requireCurrentPendingDecision(decisionId);
      const representedStep = runtime.repository.listPlans(runId)[0]?.steps[0];
      expect(representedStep?.action).toMatchObject({
        actionType: scenario.toolId,
        target: scenario.target,
        kind: "tool",
      });
      expect(decision.requestedParameters).toMatchObject({
        actionType: scenario.toolId,
        target: scenario.target,
        kind: "tool",
        arguments: {
          executionBinding: "reviewed_local_process",
          toolId: scenario.toolId,
          parameters: { workspace: "/engagements" },
        },
      });
      if (scenario.key === "tcp") {
        expect(decision.requestedParameters).toMatchObject({
          arguments: { parameters: { target: "127.0.0.1", port: address.port } },
        });
        // Deterministically reproduce the production race: the authority
        // maintenance interval lands after the action commit changed the run
        // from waiting to running, but before the reviewed adapter repeats its
        // server-only control-plane assertion. In-flight continuation work
        // must keep the token fenced throughout this window.
        forceAuthoritySweepBeforeDispatch = true;
      }

      const rejected = await fetch(`${baseUrl}/api/v2/guided-decisions/${decision.id}/approve`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `guided-local-api-reject-stale-000${index + 1}`,
        },
        body: JSON.stringify({
          expectedFingerprint: "0".repeat(64),
          expectedParameters: decision.requestedParameters,
          reason: `Deliberately reject a stale ${scenario.key} card without dispatch`,
        }),
      });
      expect(rejected.status).toBe(409);
      expect(await rejected.json()).toMatchObject({
        error: {
          code: "guided_action_changed",
          humanMessage: "The Guided action card changed or was stale. Review the current exact step before deciding.",
          retryable: false,
          category: "conflict",
        },
      });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?").get(runId))
        .toEqual({ count: 0 });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records WHERE run_id = ?").get(runId))
        .toEqual({ count: 0 });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM observations WHERE run_id = ?").get(runId))
        .toEqual({ count: 0 });

      await responseJson(await fetch(`${baseUrl}/api/v2/guided-decisions/${decision.id}/approve`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `guided-local-api-approve-000${index + 1}`,
        },
        body: JSON.stringify({
          expectedFingerprint: decision.actionFingerprint,
          expectedParameters: decision.requestedParameters,
          reason: `Run only this exact represented ${scenario.key} check`,
        }),
      }));
      try {
        await waitForStatus(runtime, runId, "completed");
      } catch (error) {
        const diagnosis = application.database.prepare(`
          SELECT code, human_reason, raw_error_log_id, remediation
          FROM failure_diagnoses WHERE run_id = ? ORDER BY created_at DESC LIMIT 1
        `).get(runId);
        const actions = application.database.prepare(`
          SELECT id, status, result_summary, error_category FROM actions WHERE run_id = ?
        `).all(runId);
        const calls = application.database.prepare(`
          SELECT id, status, error_category, output_summary FROM tool_calls
          WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
        `).all(runId);
        const events = application.database.prepare(`
          SELECT event_type, summary, payload_json FROM events WHERE run_id = ? ORDER BY sequence DESC LIMIT 8
        `).all(runId);
        const dispatch = dispatchFailure instanceof Error
          ? { name: dispatchFailure.name, message: dispatchFailure.message, code: (dispatchFailure as { code?: unknown }).code }
          : dispatchFailure;
        throw new Error(`${error instanceof Error ? error.message : error}; ${JSON.stringify({
          scenario: scenario.key,
          authoritySweepAtDispatch,
          diagnosis,
          actions,
          calls,
          events,
          dispatch,
        })}`);
      }

      expect(application.database.prepare(`
        SELECT provider, tool_name, mcp_server_id, status FROM tool_calls
        WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
      `).get(runId)).toEqual({
        provider: "reviewed-local-process",
        tool_name: scenario.toolId,
        mcp_server_id: null,
        status: "succeeded",
      });
      const log = application.database.prepare(`
        SELECT domain, record_type, human_summary, technical_payload_json
        FROM engagement_log_records WHERE run_id = ?
      `).get(runId) as Record<string, string>;
      expect(log).toMatchObject({
        domain: "local_tool_execution",
        record_type: "bounded_process_output",
        human_summary: expect.stringContaining("Engagement Log"),
      });
      expect(JSON.parse(log.technical_payload_json)).toMatchObject({
        exitCode: 0,
        termination: "exited",
        semanticOutcome: "positive_observation",
        shell: false,
      });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?").get(runId))
        .toEqual({ count: 1 });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records WHERE run_id = ?").get(runId))
        .toEqual({ count: 1 });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM observations WHERE run_id = ?").get(runId))
        .toEqual({ count: 1 });
      const observation = application.database.prepare(`
        SELECT o.id, o.observation_type, o.verification_state, o.normalized_value_json,
          source.log_record_id, source.parser_id, log.action_id, log.tool_call_id
        FROM observations o
        JOIN observation_log_sources source ON source.observation_id = o.id
        JOIN engagement_log_records log ON log.id = source.log_record_id
        WHERE o.run_id = ?
      `).get(runId) as Record<string, string>;
      expect(observation).toMatchObject({
        observation_type: scenario.observationType,
        verification_state: "unverified",
        parser_id: "ti-scale.reviewed-local-tool-normalizer",
        action_id: expect.stringContaining("action_"),
        tool_call_id: expect.stringContaining("local_tool_"),
      });
      const normalizedObservation = JSON.parse(observation.normalized_value_json);
      expect(normalizedObservation).toMatchObject({
        semanticOutcome: "positive_observation",
        runId,
        stepId: representedStep?.id,
        actionId: observation.action_id,
        toolCallId: observation.tool_call_id,
        toolId: scenario.toolId,
        target: scenario.target,
        result: scenario.expectedResult,
        provenance: {
          logRecordId: observation.log_record_id,
          actionId: observation.action_id,
          toolCallId: observation.tool_call_id,
        },
      });
      const observationPage = await responseJson(await fetch(
        `${baseUrl}/api/v2/operational-truth/missions/${created.mission.id}/observations?runId=${runId}`,
      ));
      expect(observationPage.items).toHaveLength(1);
      expect(observationPage.items[0]).toMatchObject({
        id: observation.id,
        runId,
        stepId: representedStep?.id,
        observationType: scenario.observationType,
        verificationState: "unverified",
        sources: [{
          logRecordId: observation.log_record_id,
          parserId: "ti-scale.reviewed-local-tool-normalizer",
          parserVersion: "1.1.0",
        }],
      });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?").get(runId))
        .toEqual({ count: 0 });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates WHERE run_id = ?").get(runId))
        .toEqual({ count: 0 });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?").get(runId))
        .toEqual({ count: 0 });
      expect(application.database.prepare(`
        SELECT COUNT(*) AS count FROM tool_calls tc
        JOIN actions a ON a.id = tc.action_id
        WHERE a.run_id = ? AND tc.mcp_server_id IS NOT NULL
      `).get(runId)).toEqual({ count: 0 });
      provedToolIds.add(scenario.toolId);
      provedRunIds.add(runId);
    }

    plannerHeldToolIds.clear();
    const webTarget = `${baseUrl}/fixture-web/`;
    const webCreated = await responseJson(await fetch(`${baseUrl}/api/v2/missions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "guided-local-api-create-web-pack-0001",
      },
      body: JSON.stringify({
        journey: "guided",
        launch: true,
        authorizationConfirmed: true,
        title: "Reviewed local web pack API fixture",
        objective: "Identify the exact disposable web service and check only the fixed reviewed path dictionary",
        target: webTarget,
        engagementId: "eng-guided-local-api-web-pack",
        explanationDepth: "balanced",
        executionPreference: "single_step_agent",
        evidenceExpectations: [],
      }),
    }));
    const webRunId = webCreated.run.id as string;
    await waitForStatus(runtime, webRunId, "waiting_guided_decision");
    const webPlan = runtime.repository.listPlans(webRunId)[0];
    expect(webPlan?.steps.map(({ action }) => action.actionType)).toEqual([
      "kali:whatweb-bounded-fingerprint",
      "kali:ffuf-bounded-content-discovery",
    ]);

    let priorDecisionId: string | undefined;
    for (const [index, expectedToolId] of REVIEWED_WEB_TOOL_IDS.slice().reverse().entries()) {
      let decisionId: string | undefined;
      for (let attempt = 0; attempt < 3_000; attempt += 1) {
        const pending = application.database.prepare(`
          SELECT id FROM guided_decisions
          WHERE run_id = ? AND status = 'pending' ORDER BY created_at ASC
        `).all(webRunId) as Array<{ id: string }>;
        if (pending.length === 1 && pending[0]?.id !== priorDecisionId) {
          decisionId = pending[0]!.id;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      if (!decisionId) throw new Error(`Web step ${index + 1} did not publish one new exact decision`);
      const decision = runtime.repository.requireCurrentPendingDecision(decisionId);
      expect(decision.requestedParameters).toMatchObject({
        kind: "tool",
        actionType: expectedToolId,
        target: webTarget,
        arguments: {
          executionBinding: "reviewed_local_process",
          toolId: expectedToolId,
          parameters: { workspace: "/engagements", url: webTarget },
        },
      });

      const rejected = await fetch(`${baseUrl}/api/v2/guided-decisions/${decision.id}/approve`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `guided-local-api-reject-web-${index + 1}`,
        },
        body: JSON.stringify({
          expectedFingerprint: "0".repeat(64),
          expectedParameters: decision.requestedParameters,
          reason: "A stale web decision must fail without target contact",
        }),
      });
      expect(rejected.status).toBe(409);
      expect(await rejected.json()).toMatchObject({
        error: { code: "guided_action_changed", category: "conflict", retryable: false },
      });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?").get(webRunId))
        .toEqual({ count: index });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records WHERE run_id = ?").get(webRunId))
        .toEqual({ count: index });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM observations WHERE run_id = ?").get(webRunId))
        .toEqual({ count: index });

      await responseJson(await fetch(`${baseUrl}/api/v2/guided-decisions/${decision.id}/approve`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `guided-local-api-approve-web-${index + 1}`,
        },
        body: JSON.stringify({
          expectedFingerprint: decision.actionFingerprint,
          expectedParameters: decision.requestedParameters,
          reason: `Run only this exact represented ${expectedToolId} action`,
        }),
      }));
      priorDecisionId = decision.id;
      if (index === 0) {
        for (let attempt = 0; attempt < 3_000; attempt += 1) {
          const next = application.database.prepare(`
            SELECT id FROM guided_decisions
            WHERE run_id = ? AND status = 'pending' AND id <> ?
          `).get(webRunId, priorDecisionId) as { id: string } | null;
          if (next) break;
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      } else {
        await waitForStatus(runtime, webRunId, "completed");
      }
    }

    const webActions = application.database.prepare(`
      SELECT id, action_type, status FROM actions WHERE run_id = ? ORDER BY created_at ASC
    `).all(webRunId) as Array<Record<string, string>>;
    expect(webActions.map(({ action_type, status }) => ({ action_type, status }))).toEqual([
      { action_type: "kali:whatweb-bounded-fingerprint", status: "succeeded" },
      { action_type: "kali:ffuf-bounded-content-discovery", status: "succeeded" },
    ]);
    for (const action of webActions) provedToolIds.add(action.action_type);
    const webCalls = application.database.prepare(`
      SELECT tc.tool_name, tc.provider, tc.mcp_server_id, tc.status
      FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
      WHERE a.run_id = ? ORDER BY tc.created_at ASC
    `).all(webRunId) as Array<Record<string, string | null>>;
    expect(webCalls).toEqual([
      {
        tool_name: "kali:whatweb-bounded-fingerprint",
        provider: "reviewed-local-process",
        mcp_server_id: null,
        status: "succeeded",
      },
      {
        tool_name: "kali:ffuf-bounded-content-discovery",
        provider: "reviewed-local-process",
        mcp_server_id: null,
        status: "succeeded",
      },
    ]);
    const webLogs = application.database.prepare(`
      SELECT domain, record_type, technical_payload_json
      FROM engagement_log_records WHERE run_id = ? ORDER BY occurred_at ASC
    `).all(webRunId) as Array<Record<string, string>>;
    expect(webLogs).toHaveLength(2);
    expect(webLogs.every(({ domain, record_type, technical_payload_json }) =>
      domain === "local_tool_execution"
      && record_type === "bounded_process_output"
      && JSON.parse(technical_payload_json).semanticOutcome === "positive_observation"
      && JSON.parse(technical_payload_json).shell === false)).toBeTrue();
    const webObservations = application.database.prepare(`
      SELECT o.id, o.observation_type, o.verification_state, o.normalized_value_json,
        source.log_record_id, source.parser_id, source.parser_version
      FROM observations o
      JOIN observation_log_sources source ON source.observation_id = o.id
      WHERE o.run_id = ? ORDER BY o.first_seen_at ASC
    `).all(webRunId) as Array<Record<string, string>>;
    expect(webObservations.map(({ observation_type, verification_state, parser_id, parser_version }) => ({
      observation_type, verification_state, parser_id, parser_version,
    }))).toEqual([
      {
        observation_type: "web_technology_fingerprint",
        verification_state: "unverified",
        parser_id: "ti-scale.reviewed-local-tool-normalizer",
        parser_version: "1.1.0",
      },
      {
        observation_type: "web_endpoint_discovery",
        verification_state: "unverified",
        parser_id: "ti-scale.reviewed-local-tool-normalizer",
        parser_version: "1.1.0",
      },
    ]);
    expect(webObservations.map(({ normalized_value_json }) =>
      JSON.parse(normalized_value_json).toolId)).toEqual([
      "kali:whatweb-bounded-fingerprint",
      "kali:ffuf-bounded-content-discovery",
    ]);
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates WHERE run_id = ?").get(webRunId))
      .toEqual({ count: 0 });
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?").get(webRunId))
      .toEqual({ count: 0 });
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?").get(webRunId))
      .toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id
      WHERE a.run_id = ? AND tc.mcp_server_id IS NOT NULL
    `).get(webRunId)).toEqual({ count: 0 });

    const webLogPage = await responseJson(await fetch(
      `${baseUrl}/api/v2/operational-truth/missions/${webCreated.mission.id}/logs?runId=${webRunId}`,
    ));
    const webObservationPage = await responseJson(await fetch(
      `${baseUrl}/api/v2/operational-truth/missions/${webCreated.mission.id}/observations?runId=${webRunId}`,
    ));
    const webCandidatePage = await responseJson(await fetch(
      `${baseUrl}/api/v2/operational-truth/missions/${webCreated.mission.id}/evidence-candidates?runId=${webRunId}`,
    ));
    const webEvidencePage = await responseJson(await fetch(
      `${baseUrl}/api/v2/operational-truth/missions/${webCreated.mission.id}/verified-evidence?runId=${webRunId}`,
    ));
    expect(webLogPage.items).toHaveLength(2);
    expect(webObservationPage.items).toHaveLength(2);
    expect(webCandidatePage.items).toHaveLength(0);
    expect(webEvidencePage.items).toHaveLength(0);
    provedRunIds.add(webRunId);

    const portReservation = createTcpServer();
    const closedPort = await new Promise<number>((resolve, reject) => {
      portReservation.once("error", reject);
      portReservation.listen(0, "127.0.0.1", () => {
        portReservation.off("error", reject);
        const reserved = portReservation.address();
        if (!reserved || typeof reserved === "string") {
          reject(new Error("Disposable TCP reservation did not bind"));
          return;
        }
        resolve(reserved.port);
      });
    });
    await new Promise<void>((resolve) => portReservation.close(() => resolve()));
    const negativeScenarios = [
      {
        key: "http-negative",
        toolId: "kali:curl-http-metadata",
        target: `${baseUrl}/fixture-http-negative`,
        heldToolIds: REVIEWED_WEB_TOOL_IDS,
        observationType: "http_metadata_response",
        expectedExitCode: 22,
        expectedResult: { responseObserved: true, statusCode: 404 },
      },
      {
        key: "tcp-refused",
        toolId: "kali:ncat-tcp-connect",
        target: `tcp://127.0.0.1:${closedPort}`,
        heldToolIds: [],
        observationType: "tcp_connectivity",
        expectedExitCode: 1,
        expectedResult: {
          host: "127.0.0.1",
          port: closedPort,
          connectionEstablished: false,
          refusalObserved: true,
        },
      },
    ] as const;
    for (const [index, scenario] of negativeScenarios.entries()) {
      plannerHeldToolIds.clear();
      for (const toolId of scenario.heldToolIds) plannerHeldToolIds.add(toolId);
      const created = await responseJson(await fetch(`${baseUrl}/api/v2/missions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `guided-local-api-create-negative-${index + 1}`,
        },
        body: JSON.stringify({
          journey: "guided",
          launch: true,
          authorizationConfirmed: true,
          title: `Reviewed local ${scenario.key} API fixture`,
          objective: "Retain a bounded negative result without turning it into a failure or evidence",
          target: scenario.target,
          engagementId: `eng-guided-local-api-${scenario.key}`,
          explanationDepth: "balanced",
          executionPreference: "single_step_agent",
          evidenceExpectations: [],
        }),
      }));
      const runId = created.run.id as string;
      await waitForStatus(runtime, runId, "waiting_guided_decision");
      const decisionRow = application.database.prepare(`
        SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
      `).get(runId) as { id: string };
      const decision = runtime.repository.requireCurrentPendingDecision(decisionRow.id);
      expect(decision.requestedParameters).toMatchObject({
        actionType: scenario.toolId,
        target: scenario.target,
        arguments: { executionBinding: "reviewed_local_process", toolId: scenario.toolId },
      });
      await responseJson(await fetch(`${baseUrl}/api/v2/guided-decisions/${decision.id}/approve`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": `guided-local-api-approve-negative-${index + 1}`,
        },
        body: JSON.stringify({
          expectedFingerprint: decision.actionFingerprint,
          expectedParameters: decision.requestedParameters,
          reason: `Run only this exact represented ${scenario.key} check`,
        }),
      }));
      await waitForStatus(runtime, runId, "completed");
      expect(application.database.prepare(`
        SELECT a.status AS action_status, tc.status AS tool_status, tc.error_category
        FROM actions a JOIN tool_calls tc ON tc.action_id = a.id WHERE a.run_id = ?
      `).get(runId)).toEqual({
        action_status: "succeeded",
        tool_status: "succeeded",
        error_category: null,
      });
      const log = application.database.prepare(`
        SELECT severity, human_summary, technical_payload_json
        FROM engagement_log_records WHERE run_id = ?
      `).get(runId) as Record<string, string>;
      expect(log).toMatchObject({
        severity: "notice",
        human_summary: expect.stringContaining("valid negative observation"),
      });
      expect(JSON.parse(log.technical_payload_json)).toMatchObject({
        semanticOutcome: "negative_observation",
        exitCode: scenario.expectedExitCode,
        termination: "exited",
      });
      const observation = application.database.prepare(`
        SELECT observation_type, verification_state, normalized_value_json
        FROM observations WHERE run_id = ?
      `).get(runId) as Record<string, string>;
      expect(observation).toMatchObject({
        observation_type: scenario.observationType,
        verification_state: "unverified",
      });
      expect(JSON.parse(observation.normalized_value_json)).toMatchObject({
        semanticOutcome: "negative_observation",
        toolId: scenario.toolId,
        target: scenario.target,
        result: scenario.expectedResult,
      });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates WHERE run_id = ?").get(runId))
        .toEqual({ count: 0 });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?").get(runId))
        .toEqual({ count: 0 });
      expect(application.database.prepare("SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?").get(runId))
        .toEqual({ count: 0 });
      expect(application.database.prepare(`
        SELECT COUNT(*) AS count FROM tool_calls tc
        JOIN actions a ON a.id = tc.action_id
        WHERE a.run_id = ? AND tc.mcp_server_id IS NOT NULL
      `).get(runId)).toEqual({ count: 0 });
      const negativeLogs = await responseJson(await fetch(
        `${baseUrl}/api/v2/operational-truth/missions/${created.mission.id}/logs?runId=${runId}`,
      ));
      const negativeObservations = await responseJson(await fetch(
        `${baseUrl}/api/v2/operational-truth/missions/${created.mission.id}/observations?runId=${runId}`,
      ));
      expect(negativeLogs.items).toHaveLength(1);
      expect(negativeObservations.items).toHaveLength(1);
      provedRunIds.add(runId);
    }

    expect([...provedToolIds].sort()).toEqual([...EXPECTED_REVIEWED_TOOL_IDS]);
    expect(provedRunIds.size).toBe(scenarios.length + 1 + negativeScenarios.length);
    const proofRunIds = [...provedRunIds];
    const proofRunPlaceholders = proofRunIds.map(() => "?").join(", ");
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM provider_turns
      WHERE run_id IN (${proofRunPlaceholders})
    `).get(...proofRunIds)).toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id
      WHERE a.run_id IN (${proofRunPlaceholders}) AND tc.mcp_server_id IS NOT NULL
    `).get(...proofRunIds)).toEqual({ count: 0 });
    expect(authoritySweepAtDispatch).toMatchObject({ released: 0, held: 0, contended: 0 });
  }, 60_000);
});
