import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, test } from "bun:test";
import type {
  BrainContextRequest,
  BrainContextResult,
  BrainContextService,
} from "../../brain-runtime";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
  AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
  AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
} from "../../domain";
import {
  LocalToolCapabilityManifest,
  parseLocalToolCapabilityManifestDocument,
  type LocalProcessToolInvocation,
  type LocalProcessToolResult,
  type LocalProcessToolResultSink,
  type ReviewedLocalProcessInvocationAdapter,
} from "../../local-tools";
import { digestCanonicalJson } from "../../mcp";
import { MemoryRepository, type MemoryNode } from "../../memory";
import { PageCaptureService, type PageCaptureRecord } from "../../page-captures";
import {
  ActionRepository,
  REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
  type DurableAction,
} from "../../orchestration";
import { ReconDigitalTwinService } from "../../run-intelligence";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import { composeReviewedWebAssessmentLocalManifest } from "../../web-assessment-tools";
import {
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
  AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_TOOL_ID,
  AUTONOMOUS_WHATWEB_ACTION_CLASS,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  AUTONOMOUS_WHATWEB_TOOL_ID,
  AutonomousReconTopologyProjector,
  AutonomousWebEvidenceVerifier,
  AutonomousWebSurfaceResultAwarePort,
  AutonomousWebSurfaceExecution,
  authorizeAutonomousDerivedWebOrigins,
  autonomousHttpMetadataFailureCode,
  autonomousWebCompositeToolCallId,
  autonomousWebSurfaceResultReceiptSha256,
  type WebPhaseMemoryGuardReceipt,
  createAutonomousFullTcpBaselineManifest,
  type AutonomousWebSurfacePlanningConfiguration,
} from "..";
import { OperationalTruthService } from "../../intelligence-v24";

const NOW = new Date("2026-07-22T18:00:00.000Z");
const TARGET = "192.0.2.44";
const MISSION_ID = "mission-web-phase";
const RUN_ID = "run-web-phase";
const PLAN_ID = "plan-web-phase";
const CONTRACT_ID = "contract-web-phase";
const AGENT_ID = "specialist:web-phase";
const RECON_PRODUCT_AGENT_ID = "ReconScout";
const WEB_PRODUCT_AGENT_ID = "WebBreaker";
const CONTEXT_PACK_ID = "context-web-phase";
const WORKSPACE = "/engagements";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function outputHash(stdout: string, stderr: string): string {
  return createHash("sha256").update(stdout).update("\u0000").update(stderr).digest("hex");
}

function manifest(): LocalToolCapabilityManifest {
  const base = parseLocalToolCapabilityManifestDocument(JSON.parse(readFileSync(
    new URL(
      "../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json",
      import.meta.url,
    ),
    "utf8",
  )) as unknown);
  const fullTcp = createAutonomousFullTcpBaselineManifest().list()
    .map(({ bindingSha256: _bindingSha256, ...tool }) => tool);
  return composeReviewedWebAssessmentLocalManifest(new LocalToolCapabilityManifest({
    ...base,
    manifestVersion: "autonomous-web-execution-test-v1",
    tools: [...base.tools, ...fullTcp],
  }));
}

const configuration: AutonomousWebSurfacePlanningConfiguration = {
  policyId: "policy:web-phase",
  httpMetadataBindingId: "binding:http-phase",
  whatwebBindingId: "binding:whatweb-phase",
  endpointDiscoveryBindingId: "binding:endpoint-discovery-phase",
  agentId: AGENT_ID,
  providerId: "provider:local-web-phase",
  modelId: "policy:local-web-phase",
  modelConfigurationHash: "a".repeat(64),
  logicalWorkspace: WORKSPACE,
  maximumOrigins: 8,
  httpMetadataSuccessCriterion: AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
  whatwebSuccessCriterion: AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
  endpointDiscoverySuccessCriterion: AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
};

class ImmediateWebAdapter implements ReviewedLocalProcessInvocationAdapter {
  private sink?: LocalProcessToolResultSink;
  readonly dispatches: LocalProcessToolInvocation[] = [];

  constructor(
    private readonly tools: LocalToolCapabilityManifest,
    private readonly transformAction: (action: DurableAction) => DurableAction = (action) => action,
    private readonly httpExitCode = 0,
  ) {}

  bindResultSink(sink: LocalProcessToolResultSink): () => void {
    this.sink = sink;
    return () => { if (this.sink === sink) this.sink = undefined; };
  }

  async dispatch(invocation: LocalProcessToolInvocation): Promise<void> {
    if (!this.sink) throw new Error("result sink missing");
    this.dispatches.push(invocation);
    const stdout = invocation.toolId === AUTONOMOUS_HTTP_METADATA_TOOL_ID
      && this.httpExitCode !== 0
      ? ""
      : invocation.toolId === AUTONOMOUS_HTTP_METADATA_TOOL_ID
      ? [
          "HTTP/1.1 200 OK",
          "Server: Apache/2.4.58",
          "Content-Type: text/html",
          "Set-Cookie: session=must-not-survive",
          "Authorization: Bearer must-not-survive",
          "",
        ].join("\r\n")
      : invocation.toolId === AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID
        ? [
            JSON.stringify({
              url: new URL("admin", String(invocation.parameters.url)).href,
              status: 200,
              length: 128,
              words: 8,
              lines: 4,
              redirectlocation: "",
            }),
            JSON.stringify({
              url: new URL("health", String(invocation.parameters.url)).href,
              status: 403,
              length: 32,
              words: 2,
              lines: 1,
              redirectlocation: "/login?next=/health",
            }),
          ].join("\n")
        : `${String(invocation.parameters.url)} [200 OK] HTTPServer[Apache/2.4.58] Title[Lab] HTML5`;
    const stderr = invocation.toolId === AUTONOMOUS_HTTP_METADATA_TOOL_ID
      && this.httpExitCode !== 0
      ? `curl: (${this.httpExitCode}) transient transport failure`
      : "";
    const tool = this.tools.resolve(invocation.toolId)!;
    const result: LocalProcessToolResult = {
      invocationId: invocation.invocationId,
      action: this.transformAction(invocation.action),
      toolId: invocation.toolId,
      startedAt: NOW.toISOString(),
      endedAt: new Date(NOW.getTime() + 25).toISOString(),
      wallClockMs: 25,
      exitCode: invocation.toolId === AUTONOMOUS_HTTP_METADATA_TOOL_ID
        ? this.httpExitCode
        : 0,
      signal: null,
      termination: "exited",
      spawnErrorCode: null,
      stdout,
      stderr,
      observedOutputBytes: Buffer.byteLength(stdout) + Buffer.byteLength(stderr),
      retainedOutputBytes: Buffer.byteLength(stdout) + Buffer.byteLength(stderr),
      outputSha256: outputHash(stdout, stderr),
      outputTruncated: false,
      executable: {
        sourcePath: tool.executable.path,
        sourceSha256: tool.executable.expectedSha256,
        snapshotSha256: tool.executable.expectedSha256,
        sandboxPath: "/run/ti-scale/tool",
      },
      sandbox: {
        executablePath: "/usr/bin/bwrap",
        executableSha256: "b".repeat(64),
        shell: false,
        environmentSha256: "e".repeat(64),
      },
    };
    await this.sink.acceptLocalProcessToolResult(result);
  }

  async cancelRun(): Promise<void> {}
}

class SilentWebAdapter implements ReviewedLocalProcessInvocationAdapter {
  private sink?: LocalProcessToolResultSink;
  readonly dispatches: LocalProcessToolInvocation[] = [];
  cancelCalls = 0;
  private releaseCancellation!: () => void;
  private readonly cancellation = new Promise<void>((resolve) => {
    this.releaseCancellation = resolve;
  });

  bindResultSink(sink: LocalProcessToolResultSink): () => void {
    this.sink = sink;
    return () => { if (this.sink === sink) this.sink = undefined; };
  }

  async dispatch(invocation: LocalProcessToolInvocation): Promise<void> {
    this.dispatches.push(invocation);
  }

  async cancelRun(): Promise<void> {
    this.cancelCalls += 1;
    await this.cancellation;
  }

  finishCancellation(): void {
    this.releaseCancellation();
  }
}

class AbortRejectingWebAdapter implements ReviewedLocalProcessInvocationAdapter {
  readonly dispatches: LocalProcessToolInvocation[] = [];
  cancelCalls = 0;
  private releaseCancellation!: () => void;
  private readonly cancellation = new Promise<void>((resolve) => {
    this.releaseCancellation = resolve;
  });

  bindResultSink(): () => void {
    return () => undefined;
  }

  dispatch(invocation: LocalProcessToolInvocation, signal: AbortSignal): Promise<void> {
    this.dispatches.push(invocation);
    return new Promise((_, reject) => {
      const rejectForAbort = () => reject(new Error("adapter dispatch observed abort"));
      if (signal.aborted) rejectForAbort();
      else signal.addEventListener("abort", rejectForAbort, { once: true });
    });
  }

  async cancelRun(): Promise<void> {
    this.cancelCalls += 1;
    await this.cancellation;
  }

  finishCancellation(): void {
    this.releaseCancellation();
  }
}

class FailingDispatchAdapter implements ReviewedLocalProcessInvocationAdapter {
  private sink?: LocalProcessToolResultSink;
  readonly dispatches: LocalProcessToolInvocation[] = [];

  bindResultSink(sink: LocalProcessToolResultSink): () => void {
    this.sink = sink;
    return () => { if (this.sink === sink) this.sink = undefined; };
  }

  async dispatch(invocation: LocalProcessToolInvocation): Promise<void> {
    this.dispatches.push(invocation);
    throw new Error("simulated process crash after durable contact intent");
  }

  async cancelRun(): Promise<void> {}
}

function insertAction(
  database: SqliteDatabase,
  input: Readonly<{
    id: string;
    stepId: string;
    actionType: string;
    actionClass: string;
    status: "queued" | "running" | "succeeded";
  }>,
): DurableAction {
  const fingerprint = createHash("sha256").update(input.id).digest("hex");
  const argumentsJson = JSON.stringify({
    input: {
      schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
      executionBinding: "reviewed_local_process",
      toolId: input.actionType,
      parameters: { target: TARGET, workspace: WORKSPACE },
    },
    orchestration: {
      target: TARGET,
      kind: "tool",
      idempotent: true,
      destructive: false,
      planVersion: 1,
    },
  });
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, assignment_id, action_type, action_class, fingerprint,
      normalized_arguments_json, scoped_target, status, intent_summary,
      contract_id, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Bounded web phase', ?, ?, ?, ?)
  `).run(
    input.id, MISSION_ID, RUN_ID, input.stepId, `assignment-${input.stepId}`,
    input.actionType, input.actionClass, fingerprint, argumentsJson, TARGET, input.status,
    CONTRACT_ID, NOW.toISOString(),
    NOW.toISOString(), NOW.toISOString(),
  );
  return new ActionRepository(database).get(input.id);
}

function fixture(fingerprints: readonly Record<string, unknown>[]) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  const now = NOW.toISOString();
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      success_criteria_json, memory_policy_json, created_by, created_at,
      updated_at, control_plane
    ) VALUES (?, 'Web phase', 'Verify evidence-derived web services', 'autonomous',
      'active', 'verified', ?, ?, 'operator:test', ?, ?, 'ti_scale')
  `).run(MISSION_ID, JSON.stringify([
    AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
    AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
    AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
  ]), JSON.stringify({
    exactContextNodeIds: ["mem-exact-web-lesson"],
    allowedScopes: ["verified_lessons"],
  }), now, now);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-web-phase', ?, ?, 'ip', 'allowed', ?, ?)
  `).run(MISSION_ID, TARGET, TARGET, now);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, 'web-recon', 'Web Recon', 'available', '{}', ?, '{}',
      'test-v1', ?, ?, ?)
  `).run(AGENT_ID, JSON.stringify({
    allowedTools: [
      AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
      AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
      AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
    ],
    deniedTools: [],
    approvalRequiredTools: [],
  }), now, now, now);
  const productTools = [
    AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
    AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
    AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  ];
  for (const productAgentId of [
    RECON_PRODUCT_AGENT_ID,
    WEB_PRODUCT_AGENT_ID,
  ]) {
    database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, provider_policy_json, tool_policy_json,
        configuration_json, version, last_heartbeat_at, created_at, updated_at
      ) VALUES (?, 'product-agent', ?, 'available', '{}', ?, ?,
        'test-v1', ?, ?, ?)
    `).run(
      productAgentId,
      productAgentId,
      JSON.stringify({
        allowedTools: productTools,
        deniedTools: [],
        approvalRequiredTools: [],
      }),
      JSON.stringify({
        userFacing: true,
        productAgent: true,
        runtimeBindingAgentIds: [AGENT_ID],
      }),
      now,
      now,
      now,
    );
    for (const capability of productTools) {
      database.prepare(`
        INSERT INTO agent_capabilities (
          agent_id, capability, source, enabled, metadata_json
        ) VALUES (?, ?, 'test-product-owner', 1, '{}')
      `).run(productAgentId, capability);
    }
  }
  for (const capability of [
    AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
    AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
    AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  ]) {
    database.prepare(`
      INSERT INTO agent_capabilities (agent_id, capability, source, enabled, metadata_json)
      VALUES (?, ?, 'test', 1, '{}')
    `).run(AGENT_ID, capability);
  }
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{}', '{}', '[]', ?,
      'operator:test', ?, ?)
  `).run(CONTRACT_ID, MISSION_ID, "c".repeat(64), JSON.stringify({
    allowedActionClasses: [
      AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
      AUTONOMOUS_WHATWEB_ACTION_CLASS,
      AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
    ],
    prohibitedActionClasses: [],
    specialistAgentIds: [RECON_PRODUCT_AGENT_ID, WEB_PRODUCT_AGENT_ID],
    destructivePolicy: "prohibited",
  }), JSON.stringify(["verified_lessons"]), now, now);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, current_plan_id,
      current_step_id, progress, status_reason, budget_json, budget_usage_json,
      started_at, created_at, updated_at, version, control_plane,
      contract_version_bound, contract_hash_bound
    ) VALUES (?, ?, 'autonomous', 'running', ?, ?, 'step-http', 0, 'Web phase',
      '{}', '{}', ?, ?, ?, 1, 'ti_scale', 1, ?)
  `).run(RUN_ID, MISSION_ID, CONTRACT_ID, PLAN_ID, now, now, now, "c".repeat(64));
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash, created_by,
      created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Evidence-derived web continuation', ?,
      'local-planner', ?, ?)
  `).run(PLAN_ID, RUN_ID, "d".repeat(64), now, now);
  for (const [id, ordinal, assignedAgentId] of [
    ["step-full-tcp", 1, RECON_PRODUCT_AGENT_ID],
    ["step-http", 2, WEB_PRODUCT_AGENT_ID],
    ["step-whatweb", 3, RECON_PRODUCT_AGENT_ID],
    ["step-endpoint", 4, WEB_PRODUCT_AGENT_ID],
  ] as const) {
    database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        assigned_agent_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'Safe recon', ?, 'Retain bounded evidence', 'running', ?, ?, ?)
    `).run(id, PLAN_ID, RUN_ID, ordinal, id, assignedAgentId, now, now);
    database.prepare(`
      INSERT INTO assignments (
        id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
        last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'active', 'worker:web-test', ?, ?, ?, ?, ?, ?)
    `).run(
      `assignment-${id}`, RUN_ID, id, assignedAgentId, now, now,
      new Date(NOW.getTime() + 60_000).toISOString(), now, now, now,
    );
  }
  const fullAction = insertAction(database, {
    id: "action-full-tcp", stepId: "step-full-tcp",
    actionType: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    actionClass: "port_service_enumeration", status: "succeeded",
  });
  const httpAction = insertAction(database, {
    id: "action-http", stepId: "step-http",
    actionType: AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
    actionClass: AUTONOMOUS_HTTP_METADATA_ACTION_CLASS, status: "running",
  });
  const whatwebAction = insertAction(database, {
    id: "action-whatweb", stepId: "step-whatweb",
    actionType: AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
    actionClass: AUTONOMOUS_WHATWEB_ACTION_CLASS, status: "queued",
  });
  const endpointAction = insertAction(database, {
    id: "action-endpoint", stepId: "step-endpoint",
    actionType: AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
    actionClass: AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS, status: "queued",
  });
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, created_by, created_at
    ) VALUES (?, ?, ?, 'autonomous', 'Web phase', 'Use confirmed context', '{}',
      1024, 'brain-context', ?)
  `).run(CONTEXT_PACK_ID, MISSION_ID, RUN_ID, now);
  const content = {
    target: TARGET,
    discoveredPortCoverageComplete: true,
    fingerprints,
  };
  const contentReceipt = digestCanonicalJson(content, { maxBytes: 1_000_000, maxDepth: 20 });
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, extracted_text, created_by, created_at
    ) VALUES ('evidence-full-tcp-version', ?, ?, 'step-full-tcp', ?, 'specialist:test',
      ?, ?, ?, ?, ?, 1, 'private', 'verified', 'Full TCP versions', ?, 'test', ?)
  `).run(
    MISSION_ID, RUN_ID, fullAction.id, now, TARGET,
    AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE, contentReceipt.sha256,
    JSON.stringify({
      method: "deterministic_full_tcp_artifact_and_coverage_validation",
      compositeToolId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
      rawProcessOutputPromoted: false,
      successCriterionReferences: [],
    }),
    contentReceipt.canonicalJson, now,
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES ('custody-full-tcp-version-acquired', 'evidence-full-tcp-version',
      'acquired', 'specialist:test', '{}', ?),
      ('custody-full-tcp-version-verified', 'evidence-full-tcp-version',
      'verified', 'autonomous-full-tcp-evidence-verifier', '{}', ?)
  `).run(now, now);
  return { database, httpAction, whatwebAction, endpointAction };
}

function seedEndpointPageCapture(
  database: SqliteDatabase,
  input: Readonly<{
    endpointEvidenceId: string;
    endpointObservationId: string;
  }>,
): Readonly<{
  capture: PageCaptureRecord;
  artifactId: string;
  artifactHash: string;
  captureEvidenceId: string;
  addCustody: () => void;
}> {
  const endpointUrl = "http://192.0.2.44:8080/admin";
  const artifactId = "artifact-endpoint-admin-capture";
  const artifactHash = createHash("sha256")
    .update("immutable admin screenshot bytes")
    .digest("hex");
  const captureContentHash = createHash("sha256")
    .update("normalized admin page content")
    .digest("hex");
  const captureEvidenceId = "evidence-endpoint-admin-capture";
  database.prepare(`
    INSERT INTO artifacts (
      id, mission_id, run_id, step_id, action_id, artifact_type, storage_uri,
      content_hash, byte_size, media_type, sensitivity, metadata_json,
      created_at, journey
    ) VALUES (?, ?, ?, 'step-endpoint', NULL, 'screenshot', ?, ?, 4096,
      'image/png', 'private', ?, ?, 'autonomous')
  `).run(
    artifactId,
    MISSION_ID,
    RUN_ID,
    "artifacts-v2/page-captures/admin.png",
    artifactHash,
    JSON.stringify({
      source: "playwright.page.screenshot",
      redactionState: "pending",
    }),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, extracted_text, artifact_id, created_by,
      created_at
    ) VALUES (?, ?, ?, 'step-endpoint', NULL, ?, ?, ?, 'web_page_capture', ?,
      ?, 0.99, 'private',
      'verified', 'Verified immutable screenshot artifact', NULL, ?, ?, ?)
  `).run(
    captureEvidenceId,
    MISSION_ID,
    RUN_ID,
    `specialist:${AGENT_ID}`,
    NOW.toISOString(),
    endpointUrl,
    artifactHash,
    JSON.stringify({
      schemaVersion: "ti-scale.page-capture-artifact-evidence.v1",
      method: "verified_page_capture_artifact",
      artifactId,
      observationId: input.endpointObservationId,
      captureTool: "playwright.page.screenshot",
      captureContentHash,
      redactionState: "pending",
    }),
    artifactId,
    AGENT_ID,
    NOW.toISOString(),
  );
  const capture = new PageCaptureService(database, () => NOW).create({
    missionId: MISSION_ID,
    runId: RUN_ID,
    planId: PLAN_ID,
    stepId: "step-endpoint",
    serviceNodeId: (database.prepare(`
      SELECT id FROM topology_nodes
      WHERE mission_id = ? AND run_id = ? AND node_type = 'endpoint'
        AND json_extract(properties_json, '$.data.url') = ?
    `).get(MISSION_ID, RUN_ID, endpointUrl) as { readonly id: string }).id,
    url: endpointUrl,
    responseStatus: 200,
    viewport: {
      width: 1_440,
      height: 900,
      deviceScaleFactor: 1,
      isMobile: false,
      fullPage: false,
    },
    screenshot: { artifactId, sha256: artifactHash },
    contentHash: captureContentHash,
    capturedByAgentId: AGENT_ID,
    captureTool: "playwright.page.screenshot",
    sensitivity: "private",
    redactionState: "pending",
    capturedAt: NOW.toISOString(),
    evidenceIds: [input.endpointEvidenceId, captureEvidenceId],
    observationIds: [input.endpointObservationId],
  }, { type: "agent", id: AGENT_ID });
  return {
    capture,
    artifactId,
    artifactHash,
    captureEvidenceId,
    addCustody: () => {
      const custody = {
        schemaVersion: "ti-scale.page-capture-artifact-evidence.v1",
        pageCaptureId: capture.id,
        artifactId,
        observationId: input.endpointObservationId,
        captureTool: capture.captureTool,
        contentHash: artifactHash,
      };
      database.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'acquired', ?, ?, ?),
          (?, ?, 'verified', 'page-capture-artifact-verifier', ?, ?)
      `).run(
        "custody-endpoint-admin-capture-acquired",
        captureEvidenceId,
        AGENT_ID,
        JSON.stringify(custody),
        NOW.toISOString(),
        "custody-endpoint-admin-capture-verified",
        captureEvidenceId,
        JSON.stringify({
          ...custody,
          method: "verified_page_capture_artifact",
        }),
        NOW.toISOString(),
      );
    },
  };
}

function seedCompositeToolCall(database: SqliteDatabase, action: DurableAction): void {
  database.prepare(`
    INSERT INTO tool_calls (
      id, action_id, provider, tool_name, normalized_arguments_json, status,
      started_at, created_at
    ) VALUES (?, ?, 'reviewed-local-process', ?, '{}', 'running', ?, ?)
  `).run(autonomousWebCompositeToolCallId(action.id), action.id, action.actionType,
    NOW.toISOString(), NOW.toISOString());
}

function fakeBrainContext(
  nodes: readonly MemoryNode[] = [],
  policyOverrides: Readonly<Record<string, unknown>> = {},
) {
  let unusedCalls = 0;
  const usedCalls: string[][] = [];
  let request: BrainContextRequest | null = null;
  const service = {
    retrieve: (input: BrainContextRequest) => {
      request = input;
      return ({
      hook: "phase_transition" as const,
      status: nodes.length > 0 ? "ready" as const : "no_relevant_memory" as const,
      contextPack: {
        id: CONTEXT_PACK_ID,
        missionId: MISSION_ID,
        runId: RUN_ID,
        ...(input.stepId ? { stepId: input.stepId } : {}),
        ...(input.actionId ? { actionId: input.actionId } : {}),
        journey: "autonomous" as const,
        purpose: "Test web phase",
        queryRedacted: "Test web phase",
        scopePolicy: {
          missionId: MISSION_ID,
          allowGlobal: true,
          journey: "autonomous" as const,
          maximumSensitivity: "private" as const,
          allowedStatuses: ["confirmed", "verified"] as const,
          allowedNodeTypes: nodes.map(({ nodeType }) => nodeType),
          allowedScopeClasses: ["verified_attack_knowledge"] as const,
          contextBudget: 4_000,
          limit: 12,
          ...policyOverrides,
        },
        contextBudget: 1_024,
        retrievalMetrics: {},
        releaseDataClass: "canonical" as const,
        createdBy: "brain-context-test",
        createdAt: NOW.toISOString(),
        items: nodes.map((node) => ({
          nodeId: node.id,
          used: false,
          relevanceReason: "Exact typed web-hazard fixture",
        })),
      },
      items: nodes.map((node) => ({
        node,
        relevanceReason: "Exact typed web-hazard fixture",
      })),
      auditRecordId: "audit-web-phase",
    } satisfies BrainContextResult);
    },
    recordUnusedContext: () => { unusedCalls += 1; },
    recordContextUse: (_context: BrainContextResult, nodeIds: readonly string[]) => {
      usedCalls.push([...nodeIds]);
    },
  } as unknown as BrainContextService;
  return {
    service,
    unusedCalls: () => unusedCalls,
    usedCalls: () => usedCalls,
    request: () => request,
  };
}

function verifiedMemoryNode(
  repository: MemoryRepository,
  input: Readonly<{
    id: string;
    nodeType: MemoryNode["nodeType"];
    title: string;
    body?: string;
  }>,
): MemoryNode {
  return repository.createNode({
    id: input.id,
    nodeType: input.nodeType,
    title: input.title,
    summary: `Verified reusable ${input.nodeType.replaceAll("_", " ")} fixture.`,
    body: input.body ?? "Reviewed typed knowledge used only through a local deterministic guard.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.98,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "A local deterministic evaluation and operator review verified this reusable fixture.",
      sources: [{
        sourceType: "evaluation",
        sourceId: `evaluation-${input.id}`,
        acquiredAt: NOW.toISOString(),
      }],
    },
    authorType: "operator",
    authorId: "operator:test",
    retentionPolicy: { journeys: ["autonomous"], allowAutonomous: true },
  });
}

function opaqueMemoryId(label: string): string {
  return `mem_${createHash("sha256").update(label, "utf8").digest("hex")}`;
}

function seedWebHazard(
  database: SqliteDatabase,
  suffix: string,
  productName: string,
  exactVersion: string,
): readonly MemoryNode[] {
  const repository = new MemoryRepository(database, { clock: () => NOW });
  const procedure = verifiedMemoryNode(repository, {
    id: opaqueMemoryId(`web-procedure-${suffix}`),
    nodeType: "attack_procedure",
    title: `Reviewed web procedure ${suffix}`,
  });
  const product = verifiedMemoryNode(repository, {
    id: opaqueMemoryId(`web-product-${suffix}`),
    nodeType: "technology_product",
    title: productName,
    body: JSON.stringify({ exactVersion }),
  });
  const version = verifiedMemoryNode(repository, {
    id: opaqueMemoryId(`web-version-${suffix}`),
    nodeType: "exact_version_fingerprint",
    title: `${productName} ${exactVersion}`,
    body: JSON.stringify({ product: productName, exactVersion }),
  });
  const hazard = verifiedMemoryNode(repository, {
    id: opaqueMemoryId(`web-hazard-${suffix}`),
    nodeType: "operational_hazard",
    title: `${productName} ${exactVersion} application hang hazard`,
    body: JSON.stringify({
      observedSymptom: "The application hangs and stops responding.",
      affectedComponent: productName,
    }),
  });
  const recovery = verifiedMemoryNode(repository, {
    id: opaqueMemoryId(`web-recovery-${suffix}`),
    nodeType: "recovery_pattern",
    title: `${productName} bounded recovery`,
  });
  database.prepare(`
    INSERT INTO operational_hazard_profiles (
      node_id, procedure_node_id, procedure_version_node_id,
      product_node_ids_json, version_node_ids_json, stack_node_ids_json,
      prerequisite_node_ids_json, observed_state_node_ids_json,
      ordered_steps_json, normalized_parameters_json,
      load_min, concurrency_min, timing_window_ms,
      observed_symptom, affected_component, state_before, state_after,
      reproducibility_count, attempt_count, recovery_pattern_node_id,
      recovery_action_summary, recovery_cost_json,
      unsafe_retry_conditions_json, safe_retry_gate_json,
      alternative_sequence_json, alternative_procedure_node_id,
      applicability_constraints_json, confidence, observed_at, fresh_until,
      version, created_at, updated_at
    ) VALUES (?, ?, NULL, ?, ?, '[]', '[]', '[]', '[]', '{}',
      1, 1, 5000, 'The application hangs and stops responding', ?,
      'Healthy response path', 'Unresponsive response path', 2, 2, ?,
      'Use the reviewed recovery and re-establish health before a different plan',
      '{"requiresDisposableTargetReset":true}',
      '["Do not repeat the hazardous sequence while health is degraded"]',
      '["Confirm the bounded health endpoint responds normally"]',
      '["Choose a non-contact analysis path"]', NULL, '{}', 0.98, ?, ?, 1, ?, ?)
  `).run(
    hazard.id,
    procedure.id,
    JSON.stringify([product.id]),
    JSON.stringify([version.id]),
    productName,
    recovery.id,
    NOW.toISOString(),
    new Date(NOW.getTime() + 30 * 24 * 60 * 60 * 1_000).toISOString(),
    NOW.toISOString(),
    NOW.toISOString(),
  );
  return Object.freeze([product, version, hazard, recovery]);
}

function authorizeHazardMemory(
  database: SqliteDatabase,
  nodes: readonly MemoryNode[],
  additionalScopes: readonly string[] = [],
): void {
  const scopes = ["verified_attack_knowledge", ...additionalScopes];
  database.prepare(`
    UPDATE missions SET memory_policy_json = ?, updated_at = ? WHERE id = ?
  `).run(JSON.stringify({
    exactContextNodeIds: nodes.map(({ id }) => id),
    allowedScopes: scopes,
  }), NOW.toISOString(), MISSION_ID);
  database.prepare(`
    UPDATE mission_contracts SET memory_scopes_json = ? WHERE id = ?
  `).run(JSON.stringify(scopes), CONTRACT_ID);
}

async function prepareEndpointAction(
  item: ReturnType<typeof fixture>,
  tools: LocalToolCapabilityManifest,
  adapter: ImmediateWebAdapter,
): Promise<DurableAction> {
  await executeAndVerify(item.database, item.httpAction, tools, adapter);
  item.database.prepare(`
    UPDATE actions SET status = 'succeeded', ended_at = ?, updated_at = ? WHERE id = ?
  `).run(NOW.toISOString(), NOW.toISOString(), item.httpAction.id);
  item.database.prepare(`
    UPDATE actions SET status = 'running', started_at = ?, updated_at = ? WHERE id = ?
  `).run(NOW.toISOString(), NOW.toISOString(), item.whatwebAction.id);
  await executeAndVerify(
    item.database,
    { ...item.whatwebAction, status: "running" as const },
    tools,
    adapter,
  );
  item.database.prepare(`
    UPDATE actions SET status = 'succeeded', ended_at = ?, updated_at = ? WHERE id = ?
  `).run(NOW.toISOString(), NOW.toISOString(), item.whatwebAction.id);
  item.database.prepare(`
    UPDATE actions SET status = 'running', started_at = ?, updated_at = ? WHERE id = ?
  `).run(NOW.toISOString(), NOW.toISOString(), item.endpointAction.id);
  item.database.prepare(`
    UPDATE runs SET current_step_id = 'step-endpoint', updated_at = ? WHERE id = ?
  `).run(NOW.toISOString(), RUN_ID);
  return { ...item.endpointAction, status: "running" as const };
}

function guardReceipt(database: SqliteDatabase, actionId: string): WebPhaseMemoryGuardReceipt {
  const row = database.prepare(`
    SELECT value_json FROM settings
    WHERE key LIKE 'runtime.autonomous-web-memory-guard.%'
      AND json_extract(value_json, '$.actionId') = ?
  `).get(actionId) as { readonly value_json: string } | undefined;
  if (!row) throw new Error(`Missing memory guard receipt for ${actionId}`);
  return JSON.parse(row.value_json) as WebPhaseMemoryGuardReceipt;
}

function resultAwarePort(
  database: SqliteDatabase,
  tools: LocalToolCapabilityManifest,
  adapter: ReviewedLocalProcessInvocationAdapter,
  brainContext: BrainContextService,
) {
  return new AutonomousWebSurfaceResultAwarePort({
    database,
    manifest: tools,
    configuration,
    adapter,
    workspaceResolver: new EngagementWorkspaceResolver([{
      logicalRoot: "/engagements",
      runtimeRoot: "/tmp",
    }]),
    brainContext,
    assertControlPlaneAuthority: () => ({
      runId: RUN_ID,
      controlPlane: "ti_scale" as const,
      leaseOwner: "worker:web-test",
      acquiredAt: NOW.toISOString(),
      heartbeatAt: NOW.toISOString(),
      expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
      version: 1,
    }),
    now: () => NOW,
  });
}

async function executeAndVerify(
  database: SqliteDatabase,
  action: DurableAction,
  tools: LocalToolCapabilityManifest,
  adapter: ImmediateWebAdapter,
) {
  const result = await executeOnly(database, action, tools, adapter);
  return new AutonomousWebEvidenceVerifier({
    database, manifest: tools, configuration,
    assertCanonicalAuthority: () => undefined,
    now: () => NOW,
  }).process(result);
}

async function executeOnly(
  database: SqliteDatabase,
  action: DurableAction,
  tools: LocalToolCapabilityManifest,
  adapter: ReviewedLocalProcessInvocationAdapter,
) {
  seedCompositeToolCall(database, action);
  const phase = action.actionType === AUTONOMOUS_HTTP_METADATA_ACTION_TYPE
    ? "http_metadata" as const
    : action.actionType === AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE
      ? "whatweb_fingerprint" as const
      : "endpoint_discovery" as const;
  const executor = new AutonomousWebSurfaceExecution({
    database,
    manifest: tools,
    configuration,
    adapter,
    workspaceResolver: new EngagementWorkspaceResolver([{
      logicalRoot: "/engagements",
      runtimeRoot: "/tmp",
    }]),
    assertOriginAuthority: ({ action: current, authorization: proof }) => {
      const refreshed = authorizeAutonomousDerivedWebOrigins(
        database,
        current,
        configuration,
        phase,
      );
      if (refreshed.authorizationSha256 !== proof.authorizationSha256) {
        throw new Error("authorization changed");
      }
      return refreshed;
    },
    now: () => NOW,
  });
  const authorization = authorizeAutonomousDerivedWebOrigins(
    database, action, configuration, phase,
  );
  const result = await executor.execute({ action, authorization, contextPackId: CONTEXT_PACK_ID },
    new AbortController().signal);
  executor.close();
  return result;
}

describe("Autonomous evidence-derived web execution", () => {
  test("retains raw HTTP output only as redacted logs, then verifies WhatWeb evidence", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const http = await executeAndVerify(item.database, item.httpAction, tools, adapter);
    expect(http.executionResult.success).toBe(true);
    const evidence = item.database.prepare(`
      SELECT evidence_type, extracted_text FROM evidence WHERE id = ?
    `).get(http.evidenceIds[0]) as { evidence_type: string; extracted_text: string };
    expect(evidence.evidence_type).toBe("http_exchange");
    const normalized = JSON.parse(evidence.extracted_text);
    expect(normalized.responses[0]).toMatchObject({
      origin: "http://192.0.2.44:8080/",
      request: { method: "HEAD", redirectPolicy: "never", credentialsSent: false },
      response: { statusCode: 200, server: "Apache/2.4.58" },
    });
    expect(evidence.extracted_text).not.toContain("must-not-survive");
    const raw = item.database.prepare(`
      SELECT technical_payload_json FROM engagement_log_records
      WHERE action_id = ? AND record_type = 'bounded_child_process_output'
    `).get(item.httpAction.id) as { technical_payload_json: string };
    expect(raw.technical_payload_json).not.toContain("must-not-survive");
    expect(raw.technical_payload_json).toContain("[REDACTED]");
    const httpGraph = new ReconDigitalTwinService(item.database)
      .getGraph(MISSION_ID, RUN_ID);
    expect(httpGraph.nodes.map(({ nodeType }) => nodeType).sort()).toEqual([
      "asset",
      "service",
      "web_origin",
    ]);
    expect(httpGraph.edges.map(({ edgeType }) => edgeType).sort()).toEqual([
      "exposes",
      "serves_web_origin",
    ]);
    expect(item.database.prepare(`
      SELECT category, value, evidence_id FROM asset_layer_observations
      ORDER BY category
    `).all()).toEqual([
      {
        category: "http.content_type",
        value: "http://192.0.2.44:8080/ → text/html",
        evidence_id: http.evidenceIds[0],
      },
      {
        category: "http.server_header",
        value: "http://192.0.2.44:8080/ → Apache/2.4.58",
        evidence_id: http.evidenceIds[0],
      },
      {
        category: "http.status",
        value: "http://192.0.2.44:8080/ → 200 OK",
        evidence_id: http.evidenceIds[0],
      },
    ]);

    item.database.prepare(`
      UPDATE actions SET status = 'succeeded', ended_at = ?, updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), NOW.toISOString(), item.httpAction.id);
    item.database.prepare(`
      UPDATE actions SET status = 'running', started_at = ?, updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), NOW.toISOString(), item.whatwebAction.id);
    const canonicalWhatWeb = { ...item.whatwebAction, status: "running" as const };
    const whatweb = await executeAndVerify(item.database, canonicalWhatWeb, tools, adapter);
    expect(whatweb.executionResult.success).toBe(true);
    const technology = item.database.prepare(`
      SELECT evidence_type, extracted_text FROM evidence WHERE id = ?
    `).get(whatweb.evidenceIds[0]) as { evidence_type: string; extracted_text: string };
    expect(technology.evidence_type).toBe("service_version_fingerprint");
    expect(technology.extracted_text).toContain("Apache/2.4.58");
    const completedGraph = new ReconDigitalTwinService(item.database)
      .getGraph(MISSION_ID, RUN_ID);
    expect(completedGraph.nodes.filter(({ nodeType }) =>
      nodeType === "technology_signal")).toHaveLength(2);
    expect(completedGraph.edges.filter(({ edgeType }) =>
      edgeType === "has_fingerprint_signal")).toHaveLength(2);
    expect(completedGraph.nodes.filter(({ nodeType }) =>
      nodeType === "technology_signal").every(({ evidence: links, properties }) =>
      links.some(({ evidenceId }) => evidenceId === whatweb.evidenceIds[0])
      && properties.claimBoundary
        === "verified_fingerprint_signal_not_confirmed_software")).toBeTrue();
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM asset_layer_observations
      WHERE osi_layer = 7 AND evidence_id = ?
    `).get(whatweb.evidenceIds[0])).toEqual({ count: 3 });
    if (!http.observationId || !whatweb.observationId) {
      throw new Error("Expected verified web observations");
    }
    const truth = new OperationalTruthService(item.database, { clock: () => NOW });
    const projector = new AutonomousReconTopologyProjector(item.database);
    const beforeReplay = {
      nodes: completedGraph.nodes.length,
      edges: completedGraph.edges.length,
      osi: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM asset_layer_observations
      `).get() as { readonly count: number }).count,
    };
    projector.project(
      truth.repository.getObservation(http.observationId),
      http.evidenceIds,
    );
    projector.project(
      truth.repository.getObservation(whatweb.observationId),
      whatweb.evidenceIds,
    );
    expect({
      nodes: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM topology_nodes
      `).get() as { readonly count: number }).count,
      edges: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM topology_edges
      `).get() as { readonly count: number }).count,
      osi: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM asset_layer_observations
      `).get() as { readonly count: number }).count,
    }).toEqual(beforeReplay);
    expect(JSON.stringify(completedGraph)).not.toContain("must-not-survive");
    expect(adapter.dispatches.map(({ toolId }) => toolId)).toEqual([
      AUTONOMOUS_HTTP_METADATA_TOOL_ID,
      AUTONOMOUS_WHATWEB_TOOL_ID,
    ]);
  });

  test("runs bounded FFUF after verified WhatWeb, uses Brain context, and promotes only normalized endpoint evidence", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);

    await executeAndVerify(item.database, item.httpAction, tools, adapter);
    item.database.prepare(`
      UPDATE actions SET status = 'succeeded', ended_at = ?, updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), NOW.toISOString(), item.httpAction.id);
    item.database.prepare(`
      UPDATE actions SET status = 'running', started_at = ?, updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), NOW.toISOString(), item.whatwebAction.id);
    await executeAndVerify(
      item.database,
      { ...item.whatwebAction, status: "running" as const },
      tools,
      adapter,
    );
    item.database.prepare(`
      UPDATE actions SET status = 'succeeded', ended_at = ?, updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), NOW.toISOString(), item.whatwebAction.id);
    item.database.prepare(`
      UPDATE actions SET status = 'running', started_at = ?, updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), NOW.toISOString(), item.endpointAction.id);
    item.database.prepare(`
      UPDATE runs SET current_step_id = 'step-endpoint', updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), RUN_ID);

    const brain = fakeBrainContext();
    const port = resultAwarePort(item.database, tools, adapter, brain.service);
    const delivered: unknown[] = [];
    port.bindResultSink({
      async acceptExecutionResult(result) {
        delivered.push(result);
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "running",
          nextAction: null,
          evidenceIds: result.progress.evidenceIds ?? [],
        };
      },
    });
    await port.dispatch(
      { ...item.endpointAction, status: "running" as const },
      new AbortController().signal,
    );

    expect(delivered).toHaveLength(1);
    expect(adapter.dispatches.map(({ toolId }) => toolId)).toEqual([
      AUTONOMOUS_HTTP_METADATA_TOOL_ID,
      AUTONOMOUS_WHATWEB_TOOL_ID,
      AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID,
    ]);
    expect(brain.request()).toMatchObject({
      hook: "phase_transition",
      journey: "autonomous",
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: "step-endpoint",
      actionId: item.endpointAction.id,
      availabilityPolicy: "required",
    });
    const evidence = item.database.prepare(`
      SELECT id, evidence_type, extracted_text, provenance_json
      FROM evidence WHERE action_id = ? AND verification_state = 'verified'
    `).get(item.endpointAction.id) as {
      id: string;
      evidence_type: string;
      extracted_text: string;
      provenance_json: string;
    };
    expect(evidence.evidence_type).toBe("endpoint_discovery_result");
    const normalized = JSON.parse(evidence.extracted_text);
    expect(normalized).toMatchObject({
      phase: "endpoint_discovery",
      parentTarget: TARGET,
      rawProcessOutputPromoted: false,
      responses: [{
        origin: "http://192.0.2.44:8080/",
        discovery: {
          dictionaryVersion: "ti-scale.web-paths.v1",
          requestBudget: 14,
          maximumConcurrency: 2,
          maximumRatePerSecond: 10,
          recursive: false,
          redirectFollowed: false,
          matchCount: 2,
        },
      }],
    });
    expect(normalized.responses[0].discovery.matches.map(({ path }: { path: string }) => path))
      .toEqual(["admin", "health"]);
    expect(evidence.extracted_text).not.toContain("stdout");
    expect(JSON.parse(evidence.provenance_json)).toMatchObject({
      virtualToolId: AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
      constituentToolIds: [AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID],
      rawProcessOutputPromoted: false,
    });
    const endpointGraph = new ReconDigitalTwinService(item.database)
      .getGraph(MISSION_ID, RUN_ID);
    const endpointNodes = endpointGraph.nodes
      .filter(({ nodeType }) => nodeType === "endpoint")
      .sort((left, right) => left.primaryLabel.localeCompare(right.primaryLabel));
    expect(endpointNodes).toHaveLength(2);
    expect(endpointNodes.map(({
      primaryLabel,
      scopeStatus,
      sensitivity,
      properties,
      evidence: links,
    }) => ({
      primaryLabel,
      scopeStatus,
      sensitivity,
      statusCode: properties.statusCode,
      redactionState: properties.redactionState,
      rawProcessOutputPromoted: properties.rawProcessOutputPromoted,
      contactAuthorityGrantedByProjection:
        properties.contactAuthorityGrantedByProjection,
      evidenceIds: links.map(({ evidenceId }) => evidenceId),
    }))).toEqual([
      {
        primaryLabel: "http://192.0.2.44:8080/admin",
        scopeStatus: "allowed",
        sensitivity: "private",
        statusCode: 200,
        redactionState: "not_required",
        rawProcessOutputPromoted: false,
        contactAuthorityGrantedByProjection: false,
        evidenceIds: [evidence.id],
      },
      {
        primaryLabel: "http://192.0.2.44:8080/health",
        scopeStatus: "allowed",
        sensitivity: "private",
        statusCode: 403,
        redactionState: "redacted",
        rawProcessOutputPromoted: false,
        contactAuthorityGrantedByProjection: false,
        evidenceIds: [evidence.id],
      },
    ]);
    expect(endpointGraph.edges.filter(({ edgeType }) =>
      edgeType === "exposes_endpoint")).toHaveLength(2);
    expect(item.database.prepare(`
      SELECT category, value, evidence_id
      FROM asset_layer_observations
      WHERE category = 'ffuf.endpoint_status'
      ORDER BY value
    `).all()).toEqual([
      {
        category: "ffuf.endpoint_status",
        value: "http://192.0.2.44:8080/admin → HTTP 200",
        evidence_id: evidence.id,
      },
      {
        category: "ffuf.endpoint_status",
        value: "http://192.0.2.44:8080/health → HTTP 403",
        evidence_id: evidence.id,
      },
    ]);
    expect(item.database.prepare(`
      SELECT category, value, evidence_id
      FROM asset_layer_observations
      WHERE category = 'ffuf.fixed_dictionary_check'
    `).get()).toEqual({
      category: "ffuf.fixed_dictionary_check",
      value: "http://192.0.2.44:8080/ → 14 paths checked; 2 matches",
      evidence_id: evidence.id,
    });
    expect(endpointGraph.nodes.filter(({ nodeType }) =>
      nodeType === "page_capture_artifact")).toHaveLength(0);
    expect(JSON.stringify(endpointNodes)).not.toContain("/login?next=/health");
    const endpointObservation = item.database.prepare(`
      SELECT id FROM observations WHERE source_tool = ?
    `).get(AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE) as { readonly id: string };
    const endpointProjector = new AutonomousReconTopologyProjector(item.database);
    const endpointCounts = {
      nodes: endpointGraph.nodes.length,
      edges: endpointGraph.edges.length,
      osi: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM asset_layer_observations
      `).get() as { readonly count: number }).count,
    };
    endpointProjector.project(
      new OperationalTruthService(item.database, { clock: () => NOW })
        .repository.getObservation(endpointObservation.id),
      [evidence.id],
    );
    expect({
      nodes: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM topology_nodes
      `).get() as { readonly count: number }).count,
      edges: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM topology_edges
      `).get() as { readonly count: number }).count,
      osi: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM asset_layer_observations
      `).get() as { readonly count: number }).count,
    }).toEqual(endpointCounts);
    const raw = item.database.prepare(`
      SELECT technical_payload_json FROM engagement_log_records
      WHERE action_id = ? AND record_type = 'bounded_child_process_output'
    `).get(item.endpointAction.id) as { technical_payload_json: string };
    expect((JSON.parse(raw.technical_payload_json) as { stdout: string }).stdout)
      .toContain('"status":200');
    expect(await port.replayPendingResults()).toBe(0);
    expect(item.database.prepare(`
      SELECT status, json_extract(redacted_payload_json, '$.deliveryState') AS delivery_state
      FROM tool_calls WHERE id = ?
    `).get(autonomousWebCompositeToolCallId(item.endpointAction.id))).toEqual({
      status: "succeeded",
      delivery_state: "accepted",
    });
    port.close();
  });

  test("projects only exactly bound and custodied page-capture artifacts, with redaction and idempotent replay", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const endpointAction = await prepareEndpointAction(item, tools, adapter);
    const endpoint = await executeAndVerify(
      item.database,
      endpointAction,
      tools,
      adapter,
    );
    if (!endpoint.observationId || endpoint.evidenceIds.length !== 1) {
      throw new Error("Expected one verified endpoint observation and evidence record");
    }
    const capture = seedEndpointPageCapture(item.database, {
      endpointEvidenceId: endpoint.evidenceIds[0]!,
      endpointObservationId: endpoint.observationId,
    });
    const projector = new AutonomousReconTopologyProjector(item.database);
    const observation = new OperationalTruthService(
      item.database,
      { clock: () => NOW },
    ).repository.getObservation(endpoint.observationId);
    const captureNodeCount = () => (item.database.prepare(`
      SELECT COUNT(*) AS count FROM topology_nodes
      WHERE node_type = 'page_capture_artifact'
    `).get() as { readonly count: number }).count;

    // A canonical page_capture row is not enough without a separate,
    // artifact-bound acquired+verified custody chain.
    projector.project(observation, endpoint.evidenceIds);
    expect(captureNodeCount()).toBe(0);

    capture.addCustody();
    item.database.prepare(`
      UPDATE artifacts SET content_hash = ? WHERE id = ?
    `).run("f".repeat(64), capture.artifactId);
    projector.project(observation, endpoint.evidenceIds);
    expect(captureNodeCount()).toBe(0);

    item.database.prepare(`
      UPDATE artifacts SET content_hash = ? WHERE id = ?
    `).run(capture.artifactHash, capture.artifactId);
    item.database.prepare(`
      UPDATE artifacts SET sensitivity = 'internal' WHERE id = ?
    `).run(capture.artifactId);
    projector.project(observation, endpoint.evidenceIds);
    expect(captureNodeCount()).toBe(0);

    item.database.prepare(`
      UPDATE artifacts SET sensitivity = 'private' WHERE id = ?
    `).run(capture.artifactId);
    const projected = projector.project(observation, endpoint.evidenceIds);
    expect(projected.status).toBe("materialized");
    expect(captureNodeCount()).toBe(1);
    const graph = new ReconDigitalTwinService(item.database)
      .getGraph(MISSION_ID, RUN_ID);
    const captureNode = graph.nodes.find(({ nodeType }) =>
      nodeType === "page_capture_artifact");
    expect(captureNode).toBeDefined();
    expect(captureNode).toMatchObject({
      primaryLabel: "admin · viewport capture",
      scopeStatus: "allowed",
      verificationState: "verified",
      sensitivity: "private",
      properties: {
        pageCaptureId: capture.capture.id,
        url: "http://192.0.2.44:8080/admin",
        responseStatus: 200,
        artifactId: capture.artifactId,
        artifactContentHash: capture.artifactHash,
        artifactRole: "viewport",
        redactionState: "pending",
        previewAvailable: false,
        rawArtifactBytesPromoted: false,
      },
    });
    expect(new Set(captureNode!.evidence.map(({ evidenceId }) => evidenceId)))
      .toEqual(new Set([
        endpoint.evidenceIds[0]!,
        capture.captureEvidenceId,
      ]));
    expect(graph.edges.filter(({ edgeType }) =>
      edgeType === "has_page_capture_artifact")).toHaveLength(1);
    expect(item.database.prepare(`
      SELECT category, value, evidence_id
      FROM asset_layer_observations
      WHERE category = 'web.page_capture_artifact'
    `).get()).toEqual({
      category: "web.page_capture_artifact",
      value: "http://192.0.2.44:8080/admin → viewport capture (pending)",
      evidence_id: capture.captureEvidenceId,
    });
    expect(JSON.stringify(captureNode)).not.toContain("storage_uri");
    expect(JSON.stringify(captureNode)).not.toContain("immutable admin screenshot bytes");

    const stableCounts = {
      nodes: graph.nodes.length,
      edges: graph.edges.length,
      osi: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM asset_layer_observations
      `).get() as { readonly count: number }).count,
    };
    projector.project(observation, endpoint.evidenceIds);
    expect({
      nodes: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM topology_nodes
      `).get() as { readonly count: number }).count,
      edges: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM topology_edges
      `).get() as { readonly count: number }).count,
      osi: (item.database.prepare(`
        SELECT COUNT(*) AS count FROM asset_layer_observations
      `).get() as { readonly count: number }).count,
    }).toEqual(stableCounts);
  });

  test("blocks FFUF before adapter dispatch when the Context Pack exactly matches a verified hang hazard", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const endpointAction = await prepareEndpointAction(item, tools, adapter);
    const nodes = seedWebHazard(item.database, "apache", "Apache", "2.4.58");
    authorizeHazardMemory(item.database, nodes);
    const brain = fakeBrainContext(nodes);
    const port = resultAwarePort(item.database, tools, adapter, brain.service);
    const delivered: Array<Readonly<{
      success: boolean;
      failureCode: string | null;
      failureCategory: string | null;
    }>> = [];
    port.bindResultSink({
      async acceptExecutionResult(result) {
        delivered.push({
          success: result.success,
          failureCode: result.failure?.code ?? null,
          failureCategory: result.failureCategory ?? null,
        });
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "running",
          nextAction: null,
        };
      },
    });

    await port.dispatch(endpointAction, new AbortController().signal);

    expect(adapter.dispatches.map(({ toolId }) => toolId)).toEqual([
      AUTONOMOUS_HTTP_METADATA_TOOL_ID,
      AUTONOMOUS_WHATWEB_TOOL_ID,
    ]);
    expect(delivered).toEqual([{
      success: false,
      failureCode: "autonomous_endpoint_discovery_blocked_by_verified_hazard",
      failureCategory: "policy_denied",
    }]);
    const receipt = guardReceipt(item.database, endpointAction.id);
    expect(receipt).toMatchObject({
      decision: "block_endpoint_discovery",
      reasonCode: "verified_hang_or_crash_hazard_match",
      contextRetrievalAuditRecordId: "audit-web-phase",
      matchedTechnologyNodeIds: [nodes.find(({ nodeType }) => nodeType === "technology_product")!.id],
      matchedVersionNodeIds: [nodes.find(({ nodeType }) => nodeType === "exact_version_fingerprint")!.id],
      matchedHazardNodeIds: [nodes.find(({ nodeType }) => nodeType === "operational_hazard")!.id],
      matchedRecoveryNodeIds: [nodes.find(({ nodeType }) => nodeType === "recovery_pattern")!.id],
    });
    expect(brain.usedCalls()).toEqual([[...receipt.usedNodeIds]]);
    expect(brain.unusedCalls()).toBe(0);
    expect(item.database.prepare(`
      SELECT action, resource_id FROM audit_records WHERE id = ?
    `).get(receipt.influenceAuditRecordId)).toEqual({
      action: "brain.web_phase_memory_guard.compiled",
      resource_id: receipt.receiptId,
    });
    expect(item.database.prepare(`
      SELECT json_extract(redacted_payload_json, '$.memoryGuardReceiptId') AS receipt_id,
        json_extract(redacted_payload_json, '$.memoryInfluenceAuditId') AS audit_id
      FROM tool_calls WHERE id = ?
    `).get(autonomousWebCompositeToolCallId(endpointAction.id))).toEqual({
      receipt_id: receipt.receiptId,
      audit_id: receipt.influenceAuditRecordId,
    });
    port.close();
  });

  test("keeps unrelated technology memory unused and lets bounded FFUF continue", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const endpointAction = await prepareEndpointAction(item, tools, adapter);
    const nodes = seedWebHazard(item.database, "nginx", "nginx", "1.25.4");
    authorizeHazardMemory(item.database, nodes);
    const brain = fakeBrainContext(nodes);
    const port = resultAwarePort(item.database, tools, adapter, brain.service);
    const delivered: boolean[] = [];
    port.bindResultSink({
      async acceptExecutionResult(result) {
        delivered.push(result.success);
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "running",
          nextAction: null,
          evidenceIds: result.progress.evidenceIds ?? [],
        };
      },
    });

    await port.dispatch(endpointAction, new AbortController().signal);

    expect(delivered).toEqual([true]);
    expect(adapter.dispatches.at(-1)?.toolId).toBe(AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID);
    expect(guardReceipt(item.database, endpointAction.id)).toMatchObject({
      decision: "allow",
      reasonCode: "no_verified_technology_hazard_match",
      usedNodeIds: [],
      ignoredNodeIds: nodes.map(({ id }) => id).sort(),
    });
    expect(brain.usedCalls()).toEqual([]);
    expect(brain.unusedCalls()).toBe(1);
    port.close();
  });

  test("does not let a different engagement's hazard memory influence FFUF", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const endpointAction = await prepareEndpointAction(item, tools, adapter);
    item.database.prepare(`
      UPDATE missions SET engagement_id = 'engagement-current', updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), MISSION_ID);
    const original = seedWebHazard(item.database, "other-engagement", "Apache", "2.4.58");
    for (const node of original) {
      item.database.prepare(`
        UPDATE memory_nodes SET scope = 'engagement', engagement_id = 'engagement-other',
          mission_id = NULL WHERE id = ?
      `).run(node.id);
    }
    const repository = new MemoryRepository(item.database, { clock: () => NOW });
    const crossEngagementNodes = original.map(({ id }) => repository.requireNode(id));
    authorizeHazardMemory(item.database, crossEngagementNodes, ["engagement_memory"]);
    const brain = fakeBrainContext(crossEngagementNodes, {
      engagementId: "engagement-current",
      allowedScopeClasses: ["verified_attack_knowledge", "engagement_memory"],
    });
    const port = resultAwarePort(item.database, tools, adapter, brain.service);
    const delivered: boolean[] = [];
    port.bindResultSink({
      async acceptExecutionResult(result) {
        delivered.push(result.success);
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "running",
          nextAction: null,
          evidenceIds: result.progress.evidenceIds ?? [],
        };
      },
    });

    await port.dispatch(endpointAction, new AbortController().signal);

    expect(delivered).toEqual([true]);
    expect(adapter.dispatches.at(-1)?.toolId).toBe(AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID);
    expect(guardReceipt(item.database, endpointAction.id)).toMatchObject({
      decision: "allow",
      reasonCode: "no_verified_technology_hazard_match",
      usedNodeIds: [],
      ignoredNodeIds: crossEngagementNodes.map(({ id }) => id).sort(),
    });
    expect(brain.usedCalls()).toEqual([]);
    expect(brain.unusedCalls()).toBe(1);
    port.close();
  });

  test("records explicit no-memory behavior without changing bounded FFUF", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const endpointAction = await prepareEndpointAction(item, tools, adapter);
    item.database.prepare(`
      UPDATE missions SET memory_policy_json = ?, updated_at = ? WHERE id = ?
    `).run(JSON.stringify({ exactContextNodeIds: [], allowedScopes: [] }), NOW.toISOString(), MISSION_ID);
    item.database.prepare(`
      UPDATE mission_contracts SET memory_scopes_json = '[]' WHERE id = ?
    `).run(CONTRACT_ID);
    const brain = fakeBrainContext();
    const port = resultAwarePort(item.database, tools, adapter, brain.service);
    const delivered: boolean[] = [];
    port.bindResultSink({
      async acceptExecutionResult(result) {
        delivered.push(result.success);
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "running",
          nextAction: null,
          evidenceIds: result.progress.evidenceIds ?? [],
        };
      },
    });

    await port.dispatch(endpointAction, new AbortController().signal);

    expect(delivered).toEqual([true]);
    expect(adapter.dispatches.at(-1)?.toolId).toBe(AUTONOMOUS_ENDPOINT_DISCOVERY_TOOL_ID);
    expect(guardReceipt(item.database, endpointAction.id)).toMatchObject({
      decision: "allow",
      reasonCode: "no_relevant_memory",
      usedNodeIds: [],
      ignoredNodeIds: [],
    });
    expect(brain.usedCalls()).toEqual([]);
    expect(brain.unusedCalls()).toBe(1);
    port.close();
  });

  test("records an empty verified web surface as explicit not-applicable evidence", async () => {
    const item = fixture([{
      port: 22, transport: "tcp", state: "open", service: "ssh", version: "OpenSSH",
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const promotion = await executeAndVerify(item.database, item.httpAction, tools, adapter);
    expect(adapter.dispatches).toHaveLength(0);
    expect(promotion.executionResult.success).toBe(true);
    expect(promotion.evidenceIds).toEqual(["evidence-full-tcp-version"]);
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence WHERE evidence_type = 'http_exchange'
    `).get()).toEqual({ count: 0 });
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM engagement_log_records WHERE action_id = ?
    `).get(item.httpAction.id)).toEqual({ count: 0 });
    const event = item.database.prepare(`
      SELECT payload_json FROM events
      WHERE event_type = 'autonomous_criterion_not_applicable' AND run_id = ?
    `).get(RUN_ID) as { payload_json: string };
    expect(JSON.parse(event.payload_json)).toMatchObject({
      outcome: "not_applicable",
      sourceEvidenceIds: ["evidence-full-tcp-version"],
    });

    item.database.prepare(`
      UPDATE actions SET status = 'succeeded', ended_at = ?, updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), NOW.toISOString(), item.httpAction.id);
    item.database.prepare(`
      UPDATE actions SET status = 'running', started_at = ?, updated_at = ? WHERE id = ?
    `).run(NOW.toISOString(), NOW.toISOString(), item.whatwebAction.id);
    const whatweb = await executeAndVerify(
      item.database,
      { ...item.whatwebAction, status: "running" as const },
      tools,
      adapter,
    );
    expect(whatweb.executionResult.success).toBe(true);
    expect(whatweb.evidenceIds).toEqual(["evidence-full-tcp-version"]);
    expect(adapter.dispatches).toHaveLength(0);
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence
      WHERE action_id IN (?, ?)
    `).get(item.httpAction.id, item.whatwebAction.id)).toEqual({ count: 0 });
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM events
      WHERE event_type = 'autonomous_criterion_not_applicable' AND run_id = ?
    `).get(RUN_ID)).toEqual({ count: 2 });
  });

  test("rejects a changed composite result instead of treating it as an idempotent duplicate", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const result = await executeOnly(item.database, item.httpAction, tools, adapter);
    const verifier = new AutonomousWebEvidenceVerifier({
      database: item.database,
      manifest: tools,
      configuration,
      assertCanonicalAuthority: () => undefined,
      now: () => NOW,
    });
    expect(verifier.process(result).duplicate).toBe(false);
    expect(() => verifier.process({ ...result, resultSha256: "f".repeat(64) }))
      .toThrow("incoming fingerprint or result hash differs");
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence WHERE action_id = ?
    `).get(item.httpAction.id)).toEqual({ count: 1 });
  });

  test("rejects any changed child action envelope before accepting a process result", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools, (action) => Object.freeze({
      ...action,
      contractId: "contract-substituted-after-dispatch",
    }));
    await expect(executeOnly(item.database, item.httpAction, tools, adapter))
      .rejects.toThrow("complete parent action envelope");
  });

  test("independently rejects a recomputed composite hash with a changed child envelope", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const result = await executeOnly(
      item.database,
      item.httpAction,
      tools,
      new ImmediateWebAdapter(tools),
    );
    const child = result.children[0]!;
    const { resultSha256: _originalSha256, ...originalBody } = result;
    const tamperedBody = Object.freeze({
      ...originalBody,
      children: Object.freeze([Object.freeze({
        ...child,
        inputSha256: "f".repeat(64),
        result: Object.freeze({
          ...child.result,
          action: Object.freeze({
            ...child.result.action,
            runId: "run-substituted-after-execution",
          }),
        }),
      })]),
    });
    const tampered = Object.freeze({
      ...tamperedBody,
      resultSha256: autonomousWebSurfaceResultReceiptSha256(tamperedBody),
    });
    const verifier = new AutonomousWebEvidenceVerifier({
      database: item.database,
      manifest: tools,
      configuration,
      assertCanonicalAuthority: () => undefined,
      now: () => NOW,
    });
    expect(() => verifier.process(tampered)).toThrow("canonical parent action");
  });

  test("waits for process-group cancellation before rejecting without an unhandled child promise", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new SilentWebAdapter();
    const authorization = authorizeAutonomousDerivedWebOrigins(
      item.database, item.httpAction, configuration, "http_metadata",
    );
    const executor = new AutonomousWebSurfaceExecution({
      database: item.database,
      manifest: tools,
      configuration,
      adapter,
      workspaceResolver: new EngagementWorkspaceResolver([{
        logicalRoot: "/engagements",
        runtimeRoot: "/tmp",
      }]),
      assertOriginAuthority: () => authorization,
      now: () => NOW,
    });
    const controller = new AbortController();
    const execution = executor.execute({
      action: item.httpAction,
      authorization,
      contextPackId: CONTEXT_PACK_ID,
    }, controller.signal);
    while (adapter.dispatches.length === 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, 1));
    }
    let settled = false;
    void execution.then(() => { settled = true; }, () => { settled = true; });
    controller.abort();
    await Promise.resolve();
    expect(adapter.cancelCalls).toBe(1);
    expect(settled).toBe(false);
    adapter.finishCancellation();
    await expect(execution).rejects.toThrow("process group finished stopping");
    expect(settled).toBe(true);
    executor.close();
  });

  test("does not let an abort-driven dispatch rejection outrun process-group cleanup", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new AbortRejectingWebAdapter();
    const authorization = authorizeAutonomousDerivedWebOrigins(
      item.database, item.httpAction, configuration, "http_metadata",
    );
    const executor = new AutonomousWebSurfaceExecution({
      database: item.database,
      manifest: tools,
      configuration,
      adapter,
      workspaceResolver: new EngagementWorkspaceResolver([{
        logicalRoot: "/engagements",
        runtimeRoot: "/tmp",
      }]),
      assertOriginAuthority: () => authorization,
      now: () => NOW,
    });
    const controller = new AbortController();
    const execution = executor.execute({
      action: item.httpAction,
      authorization,
      contextPackId: CONTEXT_PACK_ID,
    }, controller.signal);
    while (adapter.dispatches.length === 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, 1));
    }
    let settled = false;
    void execution.then(() => { settled = true; }, () => { settled = true; });
    controller.abort();
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
    expect(adapter.cancelCalls).toBe(1);
    expect(settled).toBe(false);
    adapter.finishCancellation();
    await expect(execution).rejects.toThrow("process group finished stopping");
    expect(settled).toBe(true);
    executor.close();
  });

  test("rechecks canonical authority before every origin and blocks the second changed origin", async () => {
    const item = fixture([
      { port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null },
      { port: 8081, transport: "tcp", state: "open", service: "http-alt", version: null },
    ]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const authorization = authorizeAutonomousDerivedWebOrigins(
      item.database, item.httpAction, configuration, "http_metadata",
    );
    let fences = 0;
    const executor = new AutonomousWebSurfaceExecution({
      database: item.database,
      manifest: tools,
      configuration,
      adapter,
      workspaceResolver: new EngagementWorkspaceResolver([{
        logicalRoot: "/engagements",
        runtimeRoot: "/tmp",
      }]),
      assertOriginAuthority: () => {
        fences += 1;
        if (fences === 2) throw new Error("simulated contract change");
        return authorization;
      },
      now: () => NOW,
    });
    await expect(executor.execute({
      action: item.httpAction,
      authorization,
      contextPackId: CONTEXT_PACK_ID,
    }, new AbortController().signal)).rejects.toThrow("simulated contract change");
    expect(adapter.dispatches).toHaveLength(1);
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence WHERE action_id = ?
    `).get(item.httpAction.id)).toEqual({ count: 0 });
    executor.close();
  });

  test("uses durable contact intent to prevent an implicit duplicate after a crash", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const authorization = authorizeAutonomousDerivedWebOrigins(
      item.database, item.httpAction, configuration, "http_metadata",
    );
    const firstAdapter = new FailingDispatchAdapter();
    const createExecutor = (adapter: ReviewedLocalProcessInvocationAdapter) =>
      new AutonomousWebSurfaceExecution({
        database: item.database,
        manifest: tools,
        configuration,
        adapter,
        workspaceResolver: new EngagementWorkspaceResolver([{
          logicalRoot: "/engagements",
          runtimeRoot: "/tmp",
        }]),
        assertOriginAuthority: () => authorization,
        now: () => NOW,
      });
    const first = createExecutor(firstAdapter);
    await expect(first.execute({
      action: item.httpAction,
      authorization,
      contextPackId: CONTEXT_PACK_ID,
    }, new AbortController().signal)).rejects.toThrow("simulated process crash");
    first.close();
    expect(firstAdapter.dispatches).toHaveLength(1);

    const secondAdapter = new FailingDispatchAdapter();
    const second = createExecutor(secondAdapter);
    await expect(second.execute({
      action: item.httpAction,
      authorization,
      contextPackId: CONTEXT_PACK_ID,
    }, new AbortController().signal)).rejects.toThrow("already has a durable contact intent");
    expect(secondAdapter.dispatches).toHaveLength(0);
    second.close();
  });

  test("runs the result-aware path with a mandatory Brain Context Pack and atomic terminal receipt", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const brain = fakeBrainContext();
    const port = resultAwarePort(item.database, tools, adapter, brain.service);
    const delivered: unknown[] = [];
    port.bindResultSink({
      async acceptExecutionResult(result) {
        delivered.push(result);
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "running",
          nextAction: null,
          evidenceIds: result.progress.evidenceIds ?? [],
        };
      },
    });
    await port.dispatch(item.httpAction, new AbortController().signal);
    expect(delivered).toHaveLength(1);
    expect(brain.unusedCalls()).toBe(1);
    expect(brain.request()).toMatchObject({
      hook: "phase_transition",
      journey: "autonomous",
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: "step-http",
      actionId: item.httpAction.id,
      availabilityPolicy: "required",
      allowGlobal: true,
      exactNodeIds: ["mem-exact-web-lesson"],
      exactNodeIdsOnly: true,
      allowedScopeClasses: ["verified_lessons"],
      requireApplicableExactNodeIds: true,
    });
    expect(item.database.prepare(`
      SELECT status,
        json_extract(redacted_payload_json, '$.deliveryState') AS delivery_state,
        json_extract(redacted_payload_json, '$.resultAccepted') AS accepted
      FROM tool_calls WHERE id = ?
    `).get(autonomousWebCompositeToolCallId(item.httpAction.id))).toEqual({
      status: "succeeded",
      delivery_state: "accepted",
      accepted: 1,
    });
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence WHERE action_id = ? AND verification_state = 'verified'
    `).get(item.httpAction.id)).toEqual({ count: 1 });
    port.close();
  });

  test("classifies a curl reset as retryable transport failure without promoting evidence", async () => {
    expect(autonomousHttpMetadataFailureCode(28))
      .toBe("autonomous_http_metadata_timeout");
    for (const exitCode of [5, 6, 7, 18, 35, 52, 55, 56]) {
      expect(autonomousHttpMetadataFailureCode(exitCode))
        .toBe("autonomous_http_metadata_transient_network");
    }
    expect(autonomousHttpMetadataFailureCode(2))
      .toBe("autonomous_http_metadata_failed");

    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools, (action) => action, 52);
    const brain = fakeBrainContext();
    const port = resultAwarePort(item.database, tools, adapter, brain.service);
    const delivered: Array<{
      success: boolean;
      failureCategory?: string;
      failure?: { code?: string };
    }> = [];
    port.bindResultSink({
      async acceptExecutionResult(result) {
        delivered.push(result);
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "recovering",
          nextAction: null,
        };
      },
    });

    await port.dispatch(item.httpAction, new AbortController().signal);

    expect(delivered).toHaveLength(1);
    expect(delivered[0]).toMatchObject({
      success: false,
      failureCategory: "transient_network",
      failure: { code: "autonomous_http_metadata_transient_network" },
    });
    expect(item.database.prepare(`
      SELECT status, error_category FROM tool_calls WHERE id = ?
    `).get(autonomousWebCompositeToolCallId(item.httpAction.id))).toEqual({
      status: "failed",
      error_category: "transient_network",
    });
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM evidence WHERE action_id = ?
    `).get(item.httpAction.id)).toEqual({ count: 0 });
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM observations WHERE run_id = ?
    `).get(item.httpAction.runId)).toEqual({ count: 0 });
    port.close();
  });

  test("bounds permanent runtime receipt rejection and records a terminal delivery diagnosis", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const brain = fakeBrainContext();
    const port = resultAwarePort(item.database, tools, adapter, brain.service);
    let attempts = 0;
    port.bindResultSink({
      async acceptExecutionResult(result) {
        attempts += 1;
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: false,
          duplicate: false,
          runState: "running",
          nextAction: null,
        };
      },
    });
    await port.dispatch(item.httpAction, new AbortController().signal);
    expect(await port.replayPendingResults()).toBe(0);
    expect(await port.replayPendingResults()).toBe(0);
    expect(await port.replayPendingResults()).toBe(0);
    expect(attempts).toBe(3);
    expect(item.database.prepare(`
      SELECT json_extract(redacted_payload_json, '$.deliveryState') AS state,
        json_extract(redacted_payload_json, '$.deliveryAttemptCount') AS attempts
      FROM tool_calls WHERE id = ?
    `).get(autonomousWebCompositeToolCallId(item.httpAction.id))).toEqual({
      state: "quarantined",
      attempts: 3,
    });
    expect(item.database.prepare(`
      SELECT code, state, retryable FROM failure_diagnoses WHERE action_id = ?
    `).get(item.httpAction.id)).toEqual({
      code: "autonomous_web_result_delivery_quarantined",
      state: "terminal",
      retryable: 0,
    });
    port.close();
  });

  test("quarantines a malformed durable delivery payload once instead of replaying it forever", async () => {
    const item = fixture([{
      port: 8080, transport: "tcp", state: "open", service: "http-alt", version: null,
    }]);
    const tools = manifest();
    const adapter = new ImmediateWebAdapter(tools);
    const brain = fakeBrainContext();
    const port = resultAwarePort(item.database, tools, adapter, brain.service);
    port.bindResultSink({
      async acceptExecutionResult(result) {
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "running",
          nextAction: null,
        };
      },
    });
    const invocationId = autonomousWebCompositeToolCallId(item.httpAction.id);
    item.database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, normalized_arguments_json, status,
        redacted_payload_json, started_at, ended_at, created_at
      ) VALUES (?, ?, 'reviewed-local-process', ?, '{}', 'succeeded', ?, ?, ?, ?)
    `).run(
      invocationId,
      item.httpAction.id,
      item.httpAction.actionType,
      JSON.stringify({ malformed: true }),
      NOW.toISOString(),
      NOW.toISOString(),
      NOW.toISOString(),
    );
    expect(await port.replayPendingResults()).toBe(0);
    expect(await port.replayPendingResults()).toBe(0);
    expect(item.database.prepare(`
      SELECT json_extract(redacted_payload_json, '$.deliveryState') AS state,
        json_extract(redacted_payload_json, '$.deliveryAttemptCount') AS attempts,
        json_extract(redacted_payload_json, '$.deliveryLastError') AS error
      FROM tool_calls WHERE id = ?
    `).get(invocationId)).toEqual({
      state: "quarantined",
      attempts: 1,
      error: "runtime_result_payload_malformed",
    });
    expect(item.database.prepare(`
      SELECT COUNT(*) AS count FROM failure_diagnoses WHERE action_id = ?
    `).get(item.httpAction.id)).toEqual({ count: 1 });
    port.close();
  });
});
