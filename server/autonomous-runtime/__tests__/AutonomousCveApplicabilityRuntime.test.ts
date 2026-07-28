import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import { BrainContextService } from "../../brain-runtime";
import type { ExecutionResult } from "../../command-runtime";
import {
  PinnedLocalAuthoritativeCveCandidateCatalog,
  cveCandidateCatalogSnapshotSha256,
  parsePinnedLocalCveCandidateCatalogDocument,
} from "../../cve-intelligence";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
  AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
} from "../../domain";
import {
  LocalToolCapabilityManifest,
  parseLocalToolCapabilityManifestDocument,
  type LocalProcessToolInvocation,
  type LocalProcessToolResultSink,
  type ReviewedLocalProcessInvocationAdapter,
} from "../../local-tools";
import { MemoryRepository, SecondBrainService } from "../../memory";
import {
  ActionRepository,
  REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
} from "../../orchestration";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import {
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID,
  AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION,
  AutonomousGeneralSafeReconExecutionFactory,
  createAutonomousFullTcpBaselineManifest,
  type AutonomousCveApplicabilityConfiguration,
  type AutonomousDnsSafeReconConfiguration,
  type AutonomousFullTcpPlanningConfiguration,
  type AutonomousIpSafeReconConfiguration,
} from "..";

const NOW = new Date("2026-07-22T12:00:00.000Z");
const MISSION_ID = "mission-cve-runtime";
const RUN_ID = "run-cve-runtime";
const PLAN_ID = "plan-cve-runtime";
const SOURCE_STEP_ID = "step-cve-source-version";
const STEP_ID = "step-cve-applicability";
const ASSIGNMENT_ID = "assignment-cve-runtime";
const AGENT_ID = "specialist:cve-runtime";
const PRODUCT_AGENT_ID = "VulnIntel";
const TARGET = "127.0.0.1";
const MODEL_HASH = "a".repeat(64);
const CONTRACT_HASH = "c".repeat(64);
const CATALOG_SOURCE_HASH = "d".repeat(64);

function manifest(): LocalToolCapabilityManifest {
  const base = parseLocalToolCapabilityManifestDocument(JSON.parse(readFileSync(
    new URL("../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json", import.meta.url),
    "utf8",
  )) as unknown);
  const full = createAutonomousFullTcpBaselineManifest();
  return new LocalToolCapabilityManifest({
    ...base,
    manifestVersion: "autonomous-cve-runtime-fixture-v1",
    tools: [
      ...base.tools,
      ...full.list().map(({ bindingSha256: _bindingSha256, ...tool }) => tool),
    ],
  });
}

function configurations(workspace: string, catalogSnapshotSha256: string): Readonly<{
  dns: AutonomousDnsSafeReconConfiguration;
  ip: AutonomousIpSafeReconConfiguration;
  fullTcp: AutonomousFullTcpPlanningConfiguration;
  cve: AutonomousCveApplicabilityConfiguration;
}> {
  const common = {
    policyId: "policy:cve-runtime",
    agentId: AGENT_ID,
    providerId: "provider:local-deterministic-cve-runtime",
    modelId: "policy:local-cve-runtime-v1",
    modelConfigurationHash: MODEL_HASH,
  } as const;
  return {
    dns: {
      ...common,
      bindingId: "binding:cve-runtime-dns",
      logicalWorkspace: workspace,
      recordType: "A",
      successCriterion: AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
    },
    ip: {
      ...common,
      livenessBindingId: "binding:cve-runtime-liveness",
      serviceScanBindingId: "binding:cve-runtime-unused-service-scan",
      logicalWorkspace: workspace,
      ports: [80],
      livenessSuccessCriterion: AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
      serviceScanSuccessCriterion: AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
    },
    fullTcp: {
      ...common,
      bindingId: "binding:cve-runtime-full-tcp",
      logicalWorkspace: workspace,
      successCriterion: AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
    },
    cve: {
      ...common,
      bindingId: AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID,
      catalogId: "catalog:autonomous-cve-runtime-fixture",
      catalogSnapshotSha256,
      maximumCandidatesPerProduct: 10,
      nvdEnrichment: "disabled",
      successCriterion: AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION,
    },
  };
}

function candidateCatalog() {
  const document = parsePinnedLocalCveCandidateCatalogDocument({
    schemaVersion: "ti-scale.authoritative-cve-candidate-catalog.v1",
    catalogId: "catalog:autonomous-cve-runtime-fixture",
    catalogVersion: "fixture-2026.07.22-v1",
    generatedAt: "2026-07-22T11:50:00.000Z",
    candidates: [{
      cveId: "CVE-2026-12345",
      title: "Fixture Server bounded parsing issue",
      component: {
        product: "Fixture Server",
        aliases: ["FixtureServer"],
      },
      affectedRanges: [{
        id: "affected-1.2",
        scheme: "semver",
        lower: { version: "1.2.0", inclusive: true },
        upper: { version: "1.2.5", inclusive: false },
      }],
      sources: [{
        kind: "nvd",
        authority: "NIST National Vulnerability Database",
        recordUrl: "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        retrievedAt: "2026-07-22T11:50:00.000Z",
        sourceVersion: "NVD API 2.0 fixture snapshot",
        contentSha256: CATALOG_SOURCE_HASH,
        retrievalReceiptId: "receipt:cve-2026-12345",
        retrievalReceiptSha256: "e".repeat(64),
      }],
    }],
  }, NOW);
  const snapshot = cveCandidateCatalogSnapshotSha256(document);
  return {
    document,
    snapshot,
    port: new PinnedLocalAuthoritativeCveCandidateCatalog(document, {
      catalogId: document.catalogId,
      catalogSnapshotSha256: snapshot,
      maximumCandidatesPerProduct: 10,
      now: () => NOW,
    }),
  };
}

function seed(
  database: ReturnType<typeof createDatabaseConnection>,
  workspace: string,
  cve: AutonomousCveApplicabilityConfiguration,
) {
  const now = NOW.toISOString();
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      success_criteria_json, memory_policy_json, created_by, created_at,
      updated_at, control_plane
    ) VALUES (?, 'Autonomous CVE runtime fixture', 'Classify one verified service version',
      'autonomous', 'active', 'verified', ?, ?, 'operator:test', ?, ?, 'ti_scale')
  `).run(
    MISSION_ID,
    JSON.stringify([AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION]),
    JSON.stringify({ exactContextNodeIds: [], allowedScopes: [] }),
    now,
    now,
  );
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-cve-runtime', ?, ?, 'ip', 'allowed', ?, ?)
  `).run(MISSION_ID, TARGET, TARGET, now);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, 'autonomous-safe-reconnaissance-specialist', 'CVE Runtime', 'available',
      '{}', ?, '{}', 'fixture-v1', ?, ?, ?)
  `).run(AGENT_ID, JSON.stringify({
    allowedTools: [AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE],
    deniedTools: [],
    approvalRequiredTools: [],
  }), now, now, now);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, 'product-agent', 'VulnIntel', 'available', '{}', ?, ?,
      'fixture-v1', ?, ?, ?)
  `).run(
    PRODUCT_AGENT_ID,
    JSON.stringify({
      allowedTools: [AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE],
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
  database.prepare(`
    INSERT INTO agent_capabilities (agent_id, capability, source, enabled)
    VALUES (?, ?, 'live-route-attestation', 1)
  `).run(AGENT_ID, AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE);
  database.prepare(`
    INSERT INTO agent_capabilities (agent_id, capability, source, enabled)
    VALUES (?, ?, 'product-owner', 1)
  `).run(PRODUCT_AGENT_ID, AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE);
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES ('contract-cve-runtime', ?, 1, 'confirmed', ?, '{}', ?,
      '{"toolCalls":1,"retries":0}', '{"conditions":[]}',
      '["machine_readable_export"]', '[]', 'operator:test', ?, ?)
  `).run(MISSION_ID, CONTRACT_HASH, JSON.stringify({
    allowedActionClasses: [AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS],
    prohibitedActionClasses: [],
    destructivePolicy: "prohibited",
    boundedDestructiveTargets: [],
    evidenceRequirements: [AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE],
    specialistAgentIds: [PRODUCT_AGENT_ID],
  }), now, now);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, current_plan_id,
      current_step_id, progress, budget_json, budget_usage_json, started_at,
      created_at, updated_at, version, control_plane,
      contract_version_bound, contract_hash_bound
    ) VALUES (?, ?, 'autonomous', 'running', 'contract-cve-runtime', ?, ?, 0,
      '{"toolCalls":1,"retries":0}', '{}', ?, ?, ?, 1, 'ti_scale', 1, ?)
  `).run(RUN_ID, MISSION_ID, PLAN_ID, STEP_ID, now, now, now, CONTRACT_HASH);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Verified version then local CVE comparison',
      'The candidate catalogue is pinned', ?, 'mission-planner', ?, ?)
  `).run(PLAN_ID, RUN_ID, "f".repeat(64), now, now);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'full_tcp_baseline', 'Verified source version',
      'Retain the source fingerprint', 'completed', '[]', '[]',
      'port_service_enumeration', 'medium', ?, ?, ?, ?)
  `).run(SOURCE_STEP_ID, PLAN_ID, RUN_ID, AGENT_ID, now, now, now);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, 1, 'verified_cve_applicability',
      'Compare verified version with reviewed CVEs',
      'Create a conservative applicability assessment', 'running', ?, ?, ?, 'low',
      ?, ?, ?, ?)
  `).run(
    STEP_ID,
    PLAN_ID,
    RUN_ID,
    JSON.stringify([AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION]),
    JSON.stringify([SOURCE_STEP_ID]),
    AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
    PRODUCT_AGENT_ID,
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
      last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'active', 'runtime:cve-fixture', ?, ?, ?, ?, ?, ?)
  `).run(
    ASSIGNMENT_ID,
    RUN_ID,
    STEP_ID,
    PRODUCT_AGENT_ID,
    now,
    now,
    new Date(NOW.getTime() + 60_000).toISOString(),
    now,
    now,
    now,
  );

  const observationId = "observation-cve-version";
  const logId = "log-cve-version";
  const sourceEvidenceId = "evidence-cve-version";
  const assetId = "asset-cve-runtime";
  const serviceId = "service-cve-runtime-http";
  database.prepare(`
    INSERT INTO engagement_log_records (
      id, mission_id, run_id, plan_id, step_id, agent_id, severity, domain,
      record_type, human_summary, technical_payload_json, content_hash,
      sensitivity, occurred_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'notice', 'recon', 'tool_result',
      'Verified service fingerprint source', '{}', ?, 'private', ?, ?)
  `).run(logId, MISSION_ID, RUN_ID, PLAN_ID, SOURCE_STEP_ID, AGENT_ID, "1".repeat(64), now, now);
  database.prepare(`
    INSERT INTO observations (
      id, mission_id, run_id, step_id, asset_id, observation_type, statement,
      normalized_value_json, confidence, verification_state, source_agent_id,
      source_tool, first_seen_at, last_seen_at, sensitivity, created_at
    ) VALUES (?, ?, ?, ?, ?, 'service_version', 'Fixture Server 1.2.3 was reported',
      ?, 0.94, 'corroborated', ?, 'kali:nmap-full-tcp-service-version-light',
      ?, ?, 'private', ?)
  `).run(
    observationId,
    MISSION_ID,
    RUN_ID,
    SOURCE_STEP_ID,
    assetId,
    JSON.stringify({ service: "http", version: "Fixture Server 1.2.3" }),
    AGENT_ID,
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO observation_log_sources (
      observation_id, log_record_id, parser_id, parser_version, created_at
    ) VALUES (?, ?, 'reviewed-nmap', 'fixture-v1', ?)
  `).run(observationId, logId, now);
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, extracted_text, created_by, created_at
    ) VALUES (?, ?, ?, ?, 'reviewed-nmap', ?, ?, 'service_version_fingerprint', ?,
      ?, 0.96, 'private', 'verified', 'Verified service/version fingerprint', ?, ?, ?)
  `).run(
    sourceEvidenceId,
    MISSION_ID,
    RUN_ID,
    SOURCE_STEP_ID,
    now,
    TARGET,
    "2".repeat(64),
    JSON.stringify({ parser: "reviewed-nmap", rawBannerConfirmed: false }),
    JSON.stringify({ observationId, identificationStrength: "nmap_version_light" }),
    AGENT_ID,
    now,
  );
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, properties_json, confidence,
      verification_state, originating_agent_id, originating_tool, sensitivity,
      first_seen_at, last_seen_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'asset', ?, ?, 'allowed', 'validated', ?, 0.98,
      'verified', ?, 'reviewed-nmap', 'private', ?, ?, ?, ?)
  `).run(
    assetId,
    MISSION_ID,
    RUN_ID,
    TARGET,
    `ip:${TARGET}`,
    JSON.stringify({
      data: {
        address: TARGET,
        hostReportedUp: true,
        transportObservation: "tcp_connect_scan",
      },
      provenance: {
        method: "reviewed_local_nmap_observation",
        observationIds: [observationId],
        sourceAgentId: AGENT_ID,
        sourceRef: observationId,
        sourceTool: "ti-scale:autonomous-full-tcp-baseline",
      },
    }),
    AGENT_ID,
    now,
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, properties_json, confidence,
      verification_state, originating_agent_id, originating_tool, sensitivity,
      first_seen_at, last_seen_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'service', 'HTTP Fixture Server', ?, 'allowed', 'validated', ?,
      0.94, 'verified', ?, 'reviewed-nmap', 'private', ?, ?, ?, ?)
  `).run(
    serviceId,
    MISSION_ID,
    RUN_ID,
    `service:${TARGET}:80/tcp`,
    JSON.stringify({
      data: {
        host: TARGET,
        port: 80,
        transport: "tcp",
        service: "http",
        state: "open",
        version: "Fixture Server 1.2.3",
        versionDerivation: "nmap_version_light_observation",
      },
      provenance: {
        method: "reviewed_local_nmap_observation",
        observationIds: [observationId],
        sourceAgentId: AGENT_ID,
        sourceRef: observationId,
        sourceTool: "ti-scale:autonomous-full-tcp-baseline",
      },
    }),
    AGENT_ID,
    now,
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO topology_edges (
      id, mission_id, source_node_id, target_node_id, edge_type, properties_json,
      confidence, verification_state, sensitivity, first_seen_at, last_seen_at
    ) VALUES ('edge-cve-exposes', ?, ?, ?, 'exposes', '{}', 0.94, 'verified',
      'private', ?, ?)
  `).run(MISSION_ID, assetId, serviceId, now, now);
  database.prepare(`
    INSERT INTO topology_evidence_links (
      subject_type, subject_id, evidence_id, relationship, created_at
    ) VALUES ('node', ?, ?, 'supports', ?), ('node', ?, ?, 'supports', ?)
  `).run(assetId, sourceEvidenceId, now, serviceId, sourceEvidenceId, now);

  return new ActionRepository(database).create({
    intent: {
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: STEP_ID,
      assignmentId: ASSIGNMENT_ID,
      planVersion: 1,
      actionType: AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
      actionClass: AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
      arguments: {
        schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
        executionBinding: "reviewed_local_process",
        toolId: AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
        parameters: {
          target: TARGET,
          catalogId: cve.catalogId,
          catalogSnapshotSha256: cve.catalogSnapshotSha256,
        },
      },
      target: TARGET,
      intentSummary: "Compare verified version evidence with the pinned local CVE catalogue",
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
    fingerprint: createHash("sha256").update("cve-runtime-action").digest("hex"),
    contractId: "contract-cve-runtime",
    now,
  });
}

class NoTargetAdapter implements ReviewedLocalProcessInvocationAdapter {
  private sink?: LocalProcessToolResultSink;
  readonly dispatches: LocalProcessToolInvocation[] = [];

  bindResultSink(sink: LocalProcessToolResultSink): () => void {
    if (this.sink) throw new Error("sink already bound");
    this.sink = sink;
    return () => { if (this.sink === sink) this.sink = undefined; };
  }

  async dispatch(invocation: LocalProcessToolInvocation): Promise<void> {
    this.dispatches.push(invocation);
    throw new Error("The local CVE phase must never dispatch a target process");
  }

  async cancelRun(): Promise<void> {}
}

describe("Autonomous CVE applicability runtime", () => {
  test("persists a Brain-audited conservative assessment through the real general runtime route", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    try {
      const catalog = candidateCatalog();
      const config = configurations("/engagements/cve-runtime", catalog.snapshot);
      const action = seed(database, "/engagements/cve-runtime", config.cve);
      const adapter = new NoTargetAdapter();
      const brain = new BrainContextService({
        database,
        secondBrain: new SecondBrainService(new MemoryRepository(database, {
          clock: () => NOW,
        })),
      });
      const factory = new AutonomousGeneralSafeReconExecutionFactory({
        manifest: manifest(),
        dnsConfiguration: config.dns,
        ipConfiguration: config.ip,
        fullTcpConfiguration: config.fullTcp,
        cveApplicabilityConfiguration: config.cve,
        cveCandidateCatalog: catalog.port,
        brainContext: brain,
        adapter,
        workspaceResolver: new EngagementWorkspaceResolver([{
          logicalRoot: "/engagements",
          runtimeRoot: "/tmp",
        }]),
        now: () => NOW,
      });
      const port = factory.create({
        database,
        assertControlPlaneAuthority: () => ({
          runId: RUN_ID,
          controlPlane: "ti_scale",
          leaseOwner: "runtime:cve-fixture",
          acquiredAt: NOW.toISOString(),
          heartbeatAt: NOW.toISOString(),
          expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
          version: 1,
        }),
      });
      const delivered: ExecutionResult[] = [];
      port.bindResultSink?.({
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

      await port.dispatch(action, new AbortController().signal);

      expect(adapter.dispatches).toEqual([]);
      expect(delivered).toHaveLength(1);
      expect(delivered[0]).toMatchObject({
        success: true,
        progress: {
          stepStates: { [STEP_ID]: "completed" },
        },
      });
      expect(database.prepare(`
        SELECT cve_id, applicability, confidence, version_evidence_id
        FROM cve_applicability_records WHERE mission_id = ?
      `).get(MISSION_ID)).toEqual({
        cve_id: "CVE-2026-12345",
        applicability: "possible",
        confidence: 0.55,
        version_evidence_id: "evidence-cve-version",
      });
      expect(database.prepare(`
        SELECT verification_state, evidence_type,
          json_extract(provenance_json, '$.bannerOnlyConfirmationPermitted') AS banner_confirmation,
          context_pack_id
        FROM evidence e LEFT JOIN events ev
          ON ev.run_id = e.run_id AND ev.event_type = 'autonomous_cve_applicability_completed'
        WHERE e.action_id = ? AND e.evidence_type = ?
      `).get(action.id, AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE)).toMatchObject({
        verification_state: "verified",
        evidence_type: AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE,
        banner_confirmation: 0,
        context_pack_id: expect.stringMatching(/^ctx_/u),
      });
      expect(database.prepare(`
        SELECT status, provider, tool_name,
          json_extract(redacted_payload_json, '$.resultAccepted') AS accepted
        FROM tool_calls WHERE action_id = ?
      `).get(action.id)).toEqual({
        status: "succeeded",
        provider: "reviewed-local-intelligence",
        tool_name: AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
        accepted: 1,
      });
      const immutableReceipt = database.prepare(`
        SELECT e.content_hash,
          json_extract(tc.redacted_payload_json, '$.immutableResultReceiptSha256')
            AS tool_receipt_sha256,
          json_extract(tc.redacted_payload_json,
            '$.catalogQueryReceipts[0].queryReceiptId') AS catalog_receipt_id,
          json_extract(tc.redacted_payload_json,
            '$.catalogQueryReceipts[0].queryReceiptSha256') AS catalog_receipt_sha256,
          json_extract(e.provenance_json,
            '$.catalogQueryReceipts[0].queryReceiptSha256') AS evidence_catalog_receipt_sha256,
          json_extract(ev.payload_json, '$.immutableResultReceiptSha256')
            AS event_receipt_sha256
        FROM tool_calls tc
        JOIN actions a ON a.id = tc.action_id
        JOIN evidence e ON e.action_id = a.id
          AND e.evidence_type = ?
        JOIN events ev ON ev.run_id = a.run_id
          AND ev.event_type = 'autonomous_cve_applicability_completed'
        WHERE tc.action_id = ?
      `).get(AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE, action.id) as {
        readonly content_hash: string;
        readonly tool_receipt_sha256: string;
        readonly catalog_receipt_id: string;
        readonly catalog_receipt_sha256: string;
        readonly evidence_catalog_receipt_sha256: string;
        readonly event_receipt_sha256: string;
      };
      expect(immutableReceipt.tool_receipt_sha256).toBe(immutableReceipt.content_hash);
      expect(immutableReceipt.event_receipt_sha256).toBe(immutableReceipt.content_hash);
      expect(immutableReceipt.catalog_receipt_id).toMatch(/^cvecat_[a-f0-9]{40}$/u);
      expect(immutableReceipt.catalog_receipt_sha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(immutableReceipt.evidence_catalog_receipt_sha256)
        .toBe(immutableReceipt.catalog_receipt_sha256);
      expect(database.prepare(`
        SELECT e.sequence, s.last_sequence, o.status AS outbox_status
        FROM events e
        JOIN run_event_sequences s ON s.run_id = e.run_id
        JOIN event_outbox o ON o.event_id = e.id
        WHERE e.run_id = ? AND e.event_type = 'autonomous_cve_applicability_completed'
      `).get(RUN_ID)).toEqual({
        sequence: 1,
        last_sequence: 1,
        outbox_status: "pending",
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM memory_context_packs
        WHERE mission_id = ? AND run_id = ? AND action_id = ?
      `).get(MISSION_ID, RUN_ID, action.id)).toEqual({ count: 1 });
      factory.close();
    } finally {
      database.close();
    }
  });
});
