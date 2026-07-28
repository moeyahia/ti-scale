import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  LocalToolCapabilityManifest,
  parseLocalToolCapabilityManifestDocument,
  type LocalProcessToolResult,
} from "../../local-tools";
import {
  ActionRepository,
  REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
  type DurableAction,
} from "../../orchestration";
import {
  AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
  AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
} from "../../domain";
import {
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  AutonomousIpEvidenceVerifier,
  AutonomousIpVerifiedOutputRecorder,
  createAutonomousIpSafeReconPlanningPolicy,
  createAutonomousLocalSafeReconPlanningPolicy,
  type AutonomousDnsSafeReconConfiguration,
  type AutonomousIpSafeReconConfiguration,
} from "..";

const NOW = new Date("2026-07-20T06:00:00.000Z");
const TARGET = "192.0.2.25";
const MISSION_ID = "mission-autonomous-ip";
const RUN_ID = "run-autonomous-ip";
const PLAN_ID = "plan-autonomous-ip";
const CONTRACT_ID = "contract-autonomous-ip";
const CONTRACT_HASH = "c".repeat(64);
const AGENT_ID = "specialist:autonomous-safe-recon";
const OWNER = "runtime:autonomous-safe-recon-test";
const WORKSPACE = "/engagements/autonomous-safe-recon";
const MODEL_HASH = "a".repeat(64);

const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function database(): SqliteDatabase {
  const value = createDatabaseConnection({ filename: ":memory:" });
  databases.push(value);
  migrateDatabase(value);
  return value;
}

function manifest(): LocalToolCapabilityManifest {
  const document = parseLocalToolCapabilityManifestDocument(JSON.parse(readFileSync(
    new URL("../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json", import.meta.url),
    "utf8",
  )) as unknown);
  return new LocalToolCapabilityManifest(document);
}

function configuration(): AutonomousIpSafeReconConfiguration {
  return {
    policyId: "reviewed-autonomous-local-safe-recon-v2",
    livenessBindingId: "binding-autonomous-ip-liveness-v1",
    serviceScanBindingId: "binding-autonomous-ip-services-v1",
    agentId: AGENT_ID,
    providerId: "provider:local-deterministic-safe-recon",
    modelId: "policy:local-safe-recon-v2",
    modelConfigurationHash: MODEL_HASH,
    logicalWorkspace: WORKSPACE,
    ports: [22, 80, 443],
    livenessSuccessCriterion: AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
    serviceScanSuccessCriterion: AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
  };
}

function dnsConfiguration(): AutonomousDnsSafeReconConfiguration {
  return {
    policyId: configuration().policyId,
    bindingId: "binding-autonomous-dns-a-v2",
    agentId: AGENT_ID,
    providerId: configuration().providerId,
    modelId: configuration().modelId,
    modelConfigurationHash: MODEL_HASH,
    logicalWorkspace: WORKSPACE,
    recordType: "A",
    successCriterion: AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
  };
}

function seed(
  db: SqliteDatabase,
  options: Readonly<{
    prohibitedTarget?: boolean;
    tamperedPorts?: boolean;
  }> = {},
): Readonly<{ liveness: DurableAction; scan: DurableAction }> {
  const now = NOW.toISOString();
  const criteria = [
    AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
    AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
  ];
  db.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      success_criteria_json, memory_policy_json, created_by, created_at,
      updated_at, control_plane
    ) VALUES (?, 'Autonomous IP Safe Recon', 'Retain a bounded host and service baseline',
      'autonomous', 'active', 'verified', ?, '{}', 'operator:test', ?, ?, 'ti_scale')
  `).run(MISSION_ID, JSON.stringify(criteria), now, now);
  db.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-ip-allowed', ?, ?, 'ip', 'allowed', ?, ?)
  `).run(MISSION_ID, TARGET, TARGET, now);
  if (options.prohibitedTarget) {
    db.prepare(`
      INSERT INTO mission_targets (
        id, mission_id, target, target_type, disposition, normalized_target, created_at
      ) VALUES ('target-ip-prohibited', ?, ?, 'ip', 'prohibited', ?, ?)
    `).run(MISSION_ID, TARGET, TARGET, now);
  }
  db.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, 'safe-reconnaissance', 'Autonomous Safe Recon Specialist', 'available',
      '{}', ?, '{}', 'test-v1', ?, ?, ?)
  `).run(AGENT_ID, JSON.stringify({
    allowedTools: [AUTONOMOUS_IP_LIVENESS_TOOL_ID, AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID],
    deniedTools: [],
    approvalRequiredTools: [],
  }), now, now, now);
  for (const toolId of [AUTONOMOUS_IP_LIVENESS_TOOL_ID, AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID]) {
    db.prepare(`
      INSERT INTO agent_capabilities (agent_id, capability, source, enabled)
      VALUES (?, ?, 'reviewed-local-manifest', 1)
    `).run(AGENT_ID, toolId);
  }
  const actionPolicy = {
    allowedActionClasses: [
      AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
      AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
    ],
    prohibitedActionClasses: [],
    destructivePolicy: "prohibited",
    boundedDestructiveTargets: [],
    evidenceRequirements: [
      "asset_discovery_proof",
      "port_service_scan_result",
      "service_version_fingerprint",
    ],
    specialistAgentIds: [AGENT_ID],
  };
  db.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{"toolCalls":2,"retries":1}',
      '{"conditions":[]}', '[]', '[]', 'operator:test', ?, ?)
  `).run(CONTRACT_ID, MISSION_ID, CONTRACT_HASH, JSON.stringify(actionPolicy), now, now);
  db.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, current_plan_id,
      current_step_id, progress, status_reason, budget_json, budget_usage_json,
      started_at, created_at, updated_at, version, control_plane,
      contract_version_bound, contract_hash_bound
    ) VALUES (?, ?, 'autonomous', 'running', ?, ?, 'step-ip-liveness', 0,
      'Run bounded Safe IP Recon', '{"toolCalls":2,"retries":1}', '{}',
      ?, ?, ?, 1, 'ti_scale', 1, ?)
  `).run(RUN_ID, MISSION_ID, CONTRACT_ID, PLAN_ID, now, now, now, CONTRACT_HASH);
  db.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Bounded liveness then service baseline',
      'Local deterministic reviewed bindings', ?, 'mission-planner', ?, ?)
  `).run(PLAN_ID, RUN_ID, "d".repeat(64), now, now);
  const steps = [{
    id: "step-ip-liveness",
    ordinal: 0,
    title: "Check exact host liveness",
    criterion: criteria[0]!,
    actionClass: AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  }, {
    id: "step-ip-services",
    ordinal: 1,
    title: "Check reviewed TCP ports",
    criterion: criteria[1]!,
    actionClass: AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
  }];
  for (const step of steps) {
    db.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        success_criteria_json, dependencies_json, action_class, risk_class,
        assigned_agent_id, started_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'Safe IP Recon', ?, 'Retain one deterministic fact',
        'running', ?, ?, ?, 'medium', ?, ?, ?, ?)
    `).run(
      step.id,
      PLAN_ID,
      RUN_ID,
      step.ordinal,
      step.title,
      JSON.stringify([step.criterion]),
      JSON.stringify(step.ordinal === 0 ? [] : ["step-ip-liveness"]),
      step.actionClass,
      AGENT_ID,
      now,
      now,
      now,
    );
    db.prepare(`
      INSERT INTO assignments (
        id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
        last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
    `).run(
      `assignment-${step.id}`,
      RUN_ID,
      step.id,
      AGENT_ID,
      OWNER,
      now,
      now,
      new Date(NOW.getTime() + 60_000).toISOString(),
      now,
      now,
      now,
    );
  }
  db.prepare(`
    INSERT INTO control_plane_leases (
      run_id, control_plane, lease_owner, lease_token_hash, acquired_at,
      heartbeat_at, expires_at, released_at, version
    ) VALUES (?, 'ti_scale', ?, ?, ?, ?, ?, NULL, 1)
  `).run(
    RUN_ID,
    OWNER,
    "f".repeat(64),
    now,
    now,
    new Date(NOW.getTime() + 60_000).toISOString(),
  );

  const actions = new ActionRepository(db);
  const liveness = actions.create({
    intent: {
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: "step-ip-liveness",
      assignmentId: "assignment-step-ip-liveness",
      planVersion: 1,
      actionType: AUTONOMOUS_IP_LIVENESS_TOOL_ID,
      actionClass: AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
      arguments: {
        schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
        executionBinding: "reviewed_local_process",
        toolId: AUTONOMOUS_IP_LIVENESS_TOOL_ID,
        parameters: { workspace: WORKSPACE, target: TARGET },
      },
      target: TARGET,
      intentSummary: "Check exact approved host liveness",
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
    fingerprint: "1".repeat(64),
    contractId: CONTRACT_ID,
    now,
  });
  const scan = actions.create({
    intent: {
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: "step-ip-services",
      assignmentId: "assignment-step-ip-services",
      planVersion: 1,
      actionType: AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
      actionClass: AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
      arguments: {
        schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
        executionBinding: "reviewed_local_process",
        toolId: AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
        parameters: {
          workspace: WORKSPACE,
          target: TARGET,
          ports: options.tamperedPorts ? "22,80,444" : "22,80,443",
        },
      },
      target: TARGET,
      intentSummary: "Check exact reviewed TCP port set",
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
    fingerprint: "2".repeat(64),
    contractId: CONTRACT_ID,
    now,
  });
  for (const action of [liveness, scan]) {
    const toolId = String(action.actionType);
    db.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, mcp_server_id,
        normalized_arguments_json, status, started_at, created_at
      ) VALUES (?, ?, 'reviewed-local-process', ?, NULL, '{}', 'running', ?, ?)
    `).run(
      `local_tool_${createHash("sha256").update(action.id).digest("hex").slice(0, 40)}`,
      action.id,
      toolId,
      "2026-07-20T05:59:58.000Z",
      "2026-07-20T05:59:58.000Z",
    );
  }
  return { liveness, scan };
}

function result(
  action: DurableAction,
  options: Readonly<{
    stdout?: string;
    stderr?: string;
    exitCode?: number | null;
    startedAt?: string;
    endedAt?: string;
    outputTruncated?: boolean;
    termination?: LocalProcessToolResult["termination"];
  }> = {},
): LocalProcessToolResult {
  const toolId = String(action.actionType);
  const localManifest = manifest();
  const tool = localManifest.resolve(toolId)!;
  const stdout = options.stdout ?? (toolId === AUTONOMOUS_IP_LIVENESS_TOOL_ID
    ? `PING ${TARGET} (${TARGET}) 56(84) bytes of data.\n64 bytes from ${TARGET}: icmp_seq=1 ttl=64 time=0.100 ms\n64 bytes from ${TARGET}: icmp_seq=2 ttl=64 time=0.120 ms\n\n--- ${TARGET} ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss, time 1001ms\nrtt min/avg/max/mdev = 0.100/0.110/0.120/0.010 ms\n`
    : `Starting Nmap 7.99\nNmap scan report for ${TARGET}\nHost is up (0.0010s latency).\nPORT    STATE SERVICE VERSION\n22/tcp  open  ssh     OpenSSH 9.2\n80/tcp  open  http    nginx 1.24.0\nNmap done: 1 IP address (1 host up) scanned in 1.00 seconds\n`);
  const stderr = options.stderr ?? "";
  return {
    invocationId: `local_tool_${createHash("sha256").update(action.id).digest("hex").slice(0, 40)}`,
    action,
    toolId,
    startedAt: options.startedAt ?? "2026-07-20T05:59:59.000Z",
    endedAt: options.endedAt ?? NOW.toISOString(),
    wallClockMs: 1_000,
    exitCode: options.exitCode === undefined ? 0 : options.exitCode,
    signal: null,
    termination: options.termination ?? "exited",
    spawnErrorCode: null,
    stdout,
    stderr,
    observedOutputBytes: Buffer.byteLength(stdout) + Buffer.byteLength(stderr),
    retainedOutputBytes: Buffer.byteLength(stdout) + Buffer.byteLength(stderr),
    outputSha256: createHash("sha256").update(stdout).update("\u0000").update(stderr).digest("hex"),
    outputTruncated: options.outputTruncated ?? false,
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
      environmentSha256: "7".repeat(64),
    },
  };
}

function verifier(db: SqliteDatabase): AutonomousIpEvidenceVerifier {
  return new AutonomousIpEvidenceVerifier({
    database: db,
    manifest: manifest(),
    configuration: configuration(),
    now: () => NOW,
  });
}

describe("Autonomous Safe IP Recon", () => {
  test("builds exactly two bounded direct-argv bindings and never a full-range scan", () => {
    const policy = createAutonomousIpSafeReconPlanningPolicy(configuration(), manifest());
    expect(policy.maximumSteps).toBe(2);
    expect(policy.bindings.map(({ actionClassId }) => actionClassId)).toEqual([
      AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
      AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
    ]);
    expect(policy.bindings[1]).toMatchObject({
      executionBinding: "reviewed_local_process",
      toolId: AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
      staticParameters: { workspace: WORKSPACE, ports: "22,80,443" },
    });
    expect(JSON.stringify(policy)).not.toContain("1-65535");
    expect(JSON.stringify(policy)).not.toContain("-p-");
  });

  test("retains successful ping and Nmap output as logs while promoting only parsed facts", () => {
    const db = database();
    const actions = seed(db);
    const authority = verifier(db);
    const ping = authority.processLocalResult(result(actions.liveness));
    const scan = authority.processLocalResult(result(actions.scan));

    expect(ping.executionResult.success).toBe(true);
    expect(ping.evidenceIds).toHaveLength(1);
    expect(scan.executionResult.success).toBe(true);
    expect(scan.evidenceIds).toHaveLength(2);
    expect(db.prepare("SELECT COUNT(*) AS count FROM engagement_log_records WHERE run_id = ?")
      .get(RUN_ID)).toEqual({ count: 2 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM observations WHERE run_id = ?")
      .get(RUN_ID)).toEqual({ count: 2 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?")
      .get(RUN_ID)).toEqual({ count: 3 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM evidence_chain_events")
      .get()).toEqual({ count: 6 });
    const evidence = db.prepare(`
      SELECT evidence_type, extracted_text, provenance_json FROM evidence
      WHERE run_id = ? ORDER BY evidence_type
    `).all(RUN_ID) as Array<{
      evidence_type: string;
      extracted_text: string;
      provenance_json: string;
    }>;
    expect(evidence.map(({ evidence_type }) => evidence_type).sort()).toEqual([
      "asset_discovery_proof",
      "port_service_scan_result",
      "service_version_fingerprint",
    ]);
    expect(evidence.every(({ extracted_text }) => !extracted_text.includes("Starting Nmap"))).toBe(true);
    expect(evidence.every(({ provenance_json }) =>
      provenance_json.includes('"rawOutputPromoted":false')
      && provenance_json.includes('"cveClaimsCreated":false'))).toBe(true);
    expect(db.prepare("SELECT COUNT(*) AS count FROM cve_applicability_records").get())
      .toEqual({ count: 0 });
  });

  test("projects the completed reviewed Nmap observation into an unverified run-scoped topology", () => {
    const db = database();
    const action = seed(db).scan;
    const output = new AutonomousIpVerifiedOutputRecorder(verifier(db), db).record(result(action));

    expect(output.observationIds).toHaveLength(1);
    const nodes = db.prepare(`
      SELECT node_type, verification_state, properties_json
      FROM topology_nodes WHERE run_id = ? ORDER BY node_type, id
    `).all(RUN_ID) as Array<{
      node_type: string;
      verification_state: string;
      properties_json: string;
    }>;
    expect(nodes.map(({ node_type }) => node_type)).toEqual(["asset", "service", "service"]);
    expect(nodes.every(({ verification_state, properties_json }) =>
      verification_state === "unverified"
      && properties_json.includes('"method":"reviewed_local_nmap_observation"')
      && properties_json.includes(`"sourceRef":"${output.observationIds[0]}"`))).toBe(true);
    expect(db.prepare(`
      SELECT COUNT(*) AS count FROM topology_edges te
      JOIN topology_nodes source ON source.id = te.source_node_id
      WHERE source.run_id = ? AND te.edge_type = 'exposes'
        AND te.verification_state = 'unverified'
    `).get(RUN_ID)).toEqual({ count: 2 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM topology_evidence_links").get())
      .toEqual({ count: 0 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM cve_applicability_records").get())
      .toEqual({ count: 0 });
  });

  test("a no-reply ping remains an inconclusive verified fact and does not deny the independent Nmap step", () => {
    const db = database();
    const actions = seed(db);
    const authority = verifier(db);
    const noReply = authority.processLocalResult(result(actions.liveness, {
      exitCode: 1,
      stdout: `PING ${TARGET} (${TARGET}) 56(84) bytes of data.\n\n--- ${TARGET} ping statistics ---\n2 packets transmitted, 0 received, 100% packet loss, time 1001ms\n`,
    }));
    const scan = authority.processLocalResult(result(actions.scan));
    expect(noReply.executionResult.success).toBe(true);
    expect(noReply.executionResult.summary).toContain("does not prove it is offline");
    expect(scan.executionResult.success).toBe(true);
    const normalized = db.prepare(`
      SELECT extracted_text FROM evidence WHERE action_id = ?
    `).get(actions.liveness.id) as { extracted_text: string };
    expect(normalized.extracted_text).toContain('"interpretation":"no_reply_observed_offline_not_established"');
  });

  test("safe-stops unreachable routes with one bounded-retry diagnosis and no evidence", () => {
    const db = database();
    const actions = seed(db);
    const outcome = verifier(db).processLocalResult(result(actions.scan, {
      exitCode: 1,
      stdout: "",
      stderr: "route: Network is unreachable\n",
    }));
    expect(outcome.executionResult).toMatchObject({
      success: false,
      failureCategory: "transient_network",
      failure: { code: "autonomous_ip_target_unreachable" },
    });
    expect(db.prepare("SELECT retryable, state FROM failure_diagnoses WHERE id = ?")
      .get(outcome.diagnosisId!)).toEqual({ retryable: 1, state: "active" });
    expect(db.prepare("SELECT COUNT(*) AS count FROM evidence WHERE action_id = ?")
      .get(actions.scan.id)).toEqual({ count: 0 });
  });

  test("rejects stale output and malformed completed Nmap output without evidence promotion", () => {
    const staleDb = database();
    const staleAction = seed(staleDb).liveness;
    const stale = verifier(staleDb).processLocalResult(result(staleAction, {
      startedAt: "2026-07-20T05:00:00.000Z",
      endedAt: "2026-07-20T05:00:01.000Z",
    }));
    expect(stale.executionResult.failure?.code).toBe("autonomous_ip_result_integrity_invalid");
    expect(stale.evidenceIds).toEqual([]);

    const malformedDb = database();
    const malformedAction = seed(malformedDb).scan;
    const malformed = verifier(malformedDb).processLocalResult(result(malformedAction, {
      stdout: `Nmap scan report for ${TARGET}\nHost is up.\n22/tcp open ssh OpenSSH 9.2\n`,
    }));
    expect(malformed.executionResult.failure?.code)
      .toBe("autonomous_ip_service_scan_output_malformed");
    expect(malformed.evidenceIds).toEqual([]);
  });

  test("rejects scope overlap and persisted port-parameter tampering", () => {
    const scopedDb = database();
    const scopedAction = seed(scopedDb, { prohibitedTarget: true }).scan;
    const scoped = verifier(scopedDb).processLocalResult(result(scopedAction));
    expect(scoped.executionResult).toMatchObject({
      success: false,
      failureCategory: "scope_conflict",
      failure: { code: "autonomous_ip_target_outside_scope" },
    });

    const tamperedDb = database();
    const tamperedAction = seed(tamperedDb, { tamperedPorts: true }).scan;
    const tampered = verifier(tamperedDb).processLocalResult(result(tamperedAction));
    expect(tampered.executionResult).toMatchObject({
      success: false,
      failureCategory: "policy_denied",
      failure: { code: "autonomous_ip_exact_binding_invalid" },
    });
    expect(tamperedDb.prepare("SELECT COUNT(*) AS count FROM evidence").get())
      .toEqual({ count: 0 });
  });

  test("restart replay is idempotent and cannot duplicate logs, observations, evidence, or custody", () => {
    const db = database();
    const action = seed(db).scan;
    const terminal = result(action);
    const first = verifier(db).processLocalResult(terminal);
    const afterRestart = verifier(db).processLocalResult(terminal);
    expect(first.duplicate).toBe(false);
    expect(afterRestart.duplicate).toBe(true);
    expect(afterRestart.evidenceIds).toEqual(first.evidenceIds);
    expect(db.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: 1 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM observations").get())
      .toEqual({ count: 1 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM evidence").get())
      .toEqual({ count: 2 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM evidence_chain_events").get())
      .toEqual({ count: 4 });
  });

  test("coexists with the DNS binding in one deterministic generic planner policy", () => {
    const policy = createAutonomousLocalSafeReconPlanningPolicy(
      dnsConfiguration(),
      configuration(),
      manifest(),
    );
    expect(policy.maximumSteps).toBe(3);
    expect(policy.bindings.map((binding) => binding.actionClassId)).toEqual([
      "dns_domain_certificate_discovery",
      AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
      AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
    ]);
    expect(new Set(policy.bindings.map((binding) =>
      "toolId" in binding ? binding.toolId : binding.toolName))).toEqual(new Set([
      "kali:host-dns-query",
      AUTONOMOUS_IP_LIVENESS_TOOL_ID,
      AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
    ]));
  });
});
