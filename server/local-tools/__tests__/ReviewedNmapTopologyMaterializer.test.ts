import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { ActionRepository } from "../../orchestration";
import { ReconDigitalTwinService } from "../../run-intelligence";
import {
  LocalToolCapabilityManifest,
  OperationalTruthLocalToolOutputRecorder,
  type LocalProcessToolResult,
} from "../index";

const NOW = "2026-07-20T05:00:00.000Z";
const MISSION_ID = "mission-reviewed-nmap-topology";
const TARGET = "192.0.2.44";
const TOOL_ID = "kali:nmap-tcp-connect-service-scan";

function manifest(): LocalToolCapabilityManifest {
  return new LocalToolCapabilityManifest(JSON.parse(readFileSync(
    new URL("../../../deployment/runtime-config/local-tool-capabilities.v1.json", import.meta.url),
    "utf8",
  )));
}

function createDatabase(): SqliteDatabase {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Reviewed Nmap topology', 'Inspect one authorized documentation host',
      'guided', 'active', 'verified', 'operator:test', ?, ?, 'ti_scale')
  `).run(MISSION_ID, NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-reviewed-nmap', ?, ?, 'host', 'allowed', ?, ?)
  `).run(MISSION_ID, TARGET, TARGET, NOW);
  database.prepare(`
    INSERT INTO mission_constraints (
      id, mission_id, constraint_type, value_json, source, created_at
    ) VALUES ('constraint-reviewed-nmap', ?, 'guided_collaboration', ?, 'operator', ?)
  `).run(MISSION_ID, JSON.stringify({
    evidenceExpectations: ["port_service_scan_result", "service_version_fingerprint"],
  }), NOW);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES ('ReconScout', 'reconnaissance', 'ReconScout', 'available', 'test-v1', ?, ?)
  `).run(NOW, NOW);
  return database;
}

function seedRun(database: SqliteDatabase, suffix: string, ports: string) {
  const runId = `run-reviewed-nmap-${suffix}`;
  const planId = `plan-reviewed-nmap-${suffix}`;
  const stepId = `step-reviewed-nmap-${suffix}`;
  const actionId = `action-reviewed-nmap-${suffix}`;
  const invocationId = `tool-reviewed-nmap-${suffix}`;
  const input = {
    schemaVersion: "ti-scale.reviewed-local-tool-action.v1",
    executionBinding: "reviewed_local_process",
    toolId: TOOL_ID,
    parameters: { workspace: "/engagements/reviewed-nmap", target: TARGET, ports },
  } as const;
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, budget_json, budget_usage_json,
      created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'guided', 'running', 0.2, '{}', '{}', ?, ?, 1, 'ti_scale')
  `).run(runId, MISSION_ID, NOW, NOW);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Run one reviewed Nmap scan', ?, 'planner:test', ?, ?)
  `).run(planId, runId, createHash("sha256").update(planId).digest("hex"), NOW, NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      assigned_agent_id, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'reconnaissance', 'Inspect TCP services',
      'Retain attributable service observations', 'running', 'ReconScout', ?, ?)
  `).run(stepId, planId, runId, NOW, NOW);
  database.prepare("UPDATE runs SET current_plan_id = ?, current_step_id = ? WHERE id = ?")
    .run(planId, stepId, runId);
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, action_type, action_class, fingerprint,
      normalized_arguments_json, scoped_target, status, intent_summary,
      started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'port_service_enumeration', ?, ?, ?, 'running',
      'Inspect the exact authorized TCP port set', ?, ?, ?)
  `).run(
    actionId,
    MISSION_ID,
    runId,
    stepId,
    TOOL_ID,
    createHash("sha256").update(actionId).digest("hex"),
    JSON.stringify({
      input,
      orchestration: {
        target: TARGET,
        kind: "tool",
        idempotent: true,
        destructive: false,
        planVersion: 1,
      },
    }),
    TARGET,
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO tool_calls (
      id, action_id, provider, tool_name, normalized_arguments_json,
      status, started_at, created_at
    ) VALUES (?, ?, 'reviewed-local-process', ?, ?, 'running', ?, ?)
  `).run(invocationId, actionId, TOOL_ID, JSON.stringify(input.parameters), NOW, NOW);
  return {
    runId,
    invocationId,
    action: new ActionRepository(database).get(actionId),
  };
}

function result(
  run: ReturnType<typeof seedRun>,
  stdout: string,
): LocalProcessToolResult {
  return {
    invocationId: run.invocationId,
    action: run.action,
    toolId: TOOL_ID,
    startedAt: NOW,
    endedAt: "2026-07-20T05:00:02.000Z",
    wallClockMs: 2_000,
    exitCode: 0,
    signal: null,
    termination: "exited",
    spawnErrorCode: null,
    stdout,
    stderr: "",
    observedOutputBytes: Buffer.byteLength(stdout),
    retainedOutputBytes: Buffer.byteLength(stdout),
    outputSha256: createHash("sha256").update(stdout).digest("hex"),
    outputTruncated: false,
    executable: {
      sourcePath: "/opt/ti-scale-toolchain/nmap-reviewed",
      sourceSha256: "a".repeat(64),
      snapshotSha256: "a".repeat(64),
      sandboxPath: "/run/ti-scale/tool",
    },
    sandbox: {
      executablePath: "/usr/bin/bwrap",
      executableSha256: "b".repeat(64),
      shell: false,
      environmentSha256: "c".repeat(64),
    },
  };
}

function nmapOutput(version: string): string {
  return `Nmap scan report for ${TARGET}
Host is up (0.0010s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     ${version}
8080/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 2.00 seconds
`;
}

describe("reviewed Nmap operational-truth topology materialization", () => {
  test("retains an incomplete scan as an observation without inventing topology", () => {
    const database = createDatabase();
    try {
      const recorder = new OperationalTruthLocalToolOutputRecorder(database, manifest());
      const run = seedRun(database, "partial", "443");
      recorder.record(result(run, `Nmap scan report for ${TARGET}
Host is up (0.0010s latency).
PORT    STATE SERVICE VERSION
443/tcp open  https   nginx 1.24.0
`));
      expect(database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM topology_nodes").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM topology_edges").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
      const observation = database.prepare("SELECT normalized_value_json FROM observations").get() as {
        readonly normalized_value_json: string;
      };
      expect(JSON.parse(observation.normalized_value_json)).toMatchObject({
        result: { scanCompleted: false, openPortCount: 1 },
      });
    } finally {
      database.close();
    }
  });

  test("creates only unverified run-scoped assets, services, and relationships from the parsed observation", () => {
    const database = createDatabase();
    try {
      const recorder = new OperationalTruthLocalToolOutputRecorder(database, manifest());
      const firstRun = seedRun(database, "first", "22,8080");
      const firstResult = result(firstRun, nmapOutput("OpenSSH 9.6p1 Ubuntu"));
      const output = recorder.record(firstResult);
      expect(output.observationIds).toHaveLength(1);
      expect(output.evidenceCandidateIds).toEqual([]);
      expect(output.evidenceIds).toEqual([]);

      const firstGraph = new ReconDigitalTwinService(database).getGraph(MISSION_ID, firstRun.runId);
      expect(firstGraph.nodes).toHaveLength(3);
      expect(firstGraph.edges).toHaveLength(2);
      expect(firstGraph.nodes.every((node) =>
        node.runId === firstRun.runId
        && node.verificationState === "unverified"
        && node.evidence.length === 0
        && node.provenance.observationIds?.[0] === output.observationIds[0]
      )).toBeTrue();
      const asset = firstGraph.nodes.find(({ nodeType }) => nodeType === "asset")!;
      expect(asset.primaryLabel).toBe(TARGET);
      expect(asset.properties).toEqual({
        address: TARGET,
        hostReportedUp: true,
        missionTargetId: "target-reviewed-nmap",
        transportObservation: "tcp_connect_scan",
      });
      expect(asset.properties).not.toHaveProperty("os");
      expect(asset.properties).not.toHaveProperty("kernel");
      expect(asset.properties).not.toHaveProperty("platform");

      const ssh = firstGraph.nodes.find((node) => node.nodeType === "service" && node.properties.port === 22)!;
      expect(ssh.properties).toMatchObject({
        host: TARGET,
        port: 22,
        transport: "tcp",
        service: "ssh",
        version: "OpenSSH 9.6p1 Ubuntu",
        versionDerivation: "nmap_version_light_observation",
      });
      const unknown = firstGraph.nodes.find((node) => node.nodeType === "service" && node.properties.port === 8080)!;
      expect(unknown.properties).toMatchObject({ service: "unknown", port: 8080 });
      expect(unknown.properties).not.toHaveProperty("version");
      expect(firstGraph.edges.every((edge) =>
        edge.sourceNodeId === asset.id
        && edge.edgeType === "exposes"
        && edge.verificationState === "unverified"
        && edge.evidence.length === 0
      )).toBeTrue();

      expect(database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM cve_applicability_records").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM asset_layer_observations").get()).toEqual({ count: 0 });
      const rawLog = database.prepare("SELECT technical_payload_json FROM engagement_log_records").get() as {
        readonly technical_payload_json: string;
      };
      expect(JSON.parse(rawLog.technical_payload_json).stdout).toContain("Nmap scan report");
      const topologyPayloads = database.prepare("SELECT properties_json FROM topology_nodes").all() as Array<{
        readonly properties_json: string;
      }>;
      expect(topologyPayloads.every(({ properties_json }) => !properties_json.includes("Nmap scan report"))).toBeTrue();

      recorder.record(firstResult);
      expect(database.prepare("SELECT COUNT(*) AS count FROM topology_nodes").get()).toEqual({ count: 3 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM topology_edges").get()).toEqual({ count: 2 });

      const secondRun = seedRun(database, "second", "22,8080");
      recorder.record(result(secondRun, nmapOutput("OpenSSH 10.0")));
      const secondGraph = new ReconDigitalTwinService(database).getGraph(MISSION_ID, secondRun.runId);
      expect(secondGraph.nodes).toHaveLength(3);
      expect(secondGraph.edges).toHaveLength(2);
      expect(secondGraph.nodes.every(({ runId }) => runId === secondRun.runId)).toBeTrue();
      expect(secondGraph.nodes.find((node) => node.nodeType === "service" && node.properties.port === 22)?.properties.version)
        .toBe("OpenSSH 10.0");
      expect(firstGraph.nodes.find((node) => node.nodeType === "service" && node.properties.port === 22)?.properties.version)
        .toBe("OpenSSH 9.6p1 Ubuntu");
      expect(secondGraph.nodes.find(({ nodeType }) => nodeType === "asset")?.id).not.toBe(asset.id);
      expect(secondGraph.nodes.find(({ nodeType }) => nodeType === "asset")?.normalizedIdentity)
        .not.toBe(asset.normalizedIdentity);
    } finally {
      database.close();
    }
  });
});
