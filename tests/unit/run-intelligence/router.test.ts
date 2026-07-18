import { once } from "node:events";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { SqliteDatabase } from "../../../server/db";
import { ControlPlaneLeaseService, type ControlPlaneLease } from "../../../server/control-plane";
import {
  createRunIntelligenceRouter,
  type AttackAttempt,
  type AssetOsiStack,
  type ReconDigitalTwin,
  type RunIntelligenceActor,
  type RunIntelligenceAuthorizationRequest,
  type RunMetricsSnapshot,
  type TopologyEdge,
  type TopologyNode,
} from "../../../server/run-intelligence";
import {
  AGENT_ONE_ID,
  createTestDatabase,
  insertEvent,
  insertEvidence,
  MISSION_ID,
  RUN_ID,
} from "./fixtures";

interface RouterHarness {
  readonly database: SqliteDatabase;
  readonly server: Server;
  readonly origin: string;
  readonly state: {
    actor: RunIntelligenceActor | undefined;
    allowed: boolean;
    leaseMode: "valid" | "missing" | "wrong_token" | "wrong_fence" | "heartbeat" | "takeover";
    leaseChecks: number;
    readonly authorizations: RunIntelligenceAuthorizationRequest[];
  };
}

interface HttpResult {
  readonly status: number;
  readonly headers: Headers;
  readonly body: unknown;
}

const openHarnesses: RouterHarness[] = [];
const CONTROL_LEASE_OWNER = "run-intelligence-router-runtime";
const CONTROL_LEASE_TOKEN = "run-intelligence-router-token-000000000";
const TAKEOVER_LEASE_OWNER = "run-intelligence-router-takeover";
const TAKEOVER_LEASE_TOKEN = "run-intelligence-router-takeover-token-0000";

async function createHarness(config: { readonly includeLeaseResolver?: boolean } = {}): Promise<RouterHarness> {
  const database = createTestDatabase();
  const state: RouterHarness["state"] = {
    actor: { id: "operator-router", type: "operator" },
    allowed: true,
    leaseMode: "valid",
    leaseChecks: 0,
    authorizations: [],
  };
  const leases = new ControlPlaneLeaseService(database);
  leases.acquire({
    runId: RUN_ID,
    controlPlane: "ti_scale",
    leaseOwner: CONTROL_LEASE_OWNER,
    leaseToken: CONTROL_LEASE_TOKEN,
    ttlMs: 300_000,
    now: new Date("2026-07-16T12:20:00.000Z"),
  });
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createRunIntelligenceRouter({
    database,
    resolveActor: () => state.actor,
    authorize: (_request, _actor, authorization) => {
      state.authorizations.push(authorization);
      return state.allowed;
    },
    clock: () => new Date("2026-07-16T12:20:00.000Z"),
    ...(config.includeLeaseResolver === false
      ? {}
      : {
          assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
            state.leaseChecks += 1;
            if (state.leaseMode === "missing") return undefined;
            if (state.leaseMode === "heartbeat" && state.leaseChecks === 2) {
              leases.heartbeat({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: CONTROL_LEASE_OWNER,
                leaseToken: CONTROL_LEASE_TOKEN,
                ttlMs: 300_000,
                now: new Date("2026-07-16T12:20:01.000Z"),
              });
              return leases.assertMutationAuthority({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: CONTROL_LEASE_OWNER,
                leaseToken: CONTROL_LEASE_TOKEN,
                now: new Date("2026-07-16T12:20:01.000Z"),
              });
            }
            if (state.leaseMode === "takeover" && state.leaseChecks === 2) {
              leases.release({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: CONTROL_LEASE_OWNER,
                leaseToken: CONTROL_LEASE_TOKEN,
                now: new Date("2026-07-16T12:20:01.000Z"),
              });
              leases.acquire({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: TAKEOVER_LEASE_OWNER,
                leaseToken: TAKEOVER_LEASE_TOKEN,
                ttlMs: 300_000,
                now: new Date("2026-07-16T12:20:02.000Z"),
              });
              return leases.assertMutationAuthority({
                runId,
                controlPlane: "ti_scale",
                leaseOwner: TAKEOVER_LEASE_OWNER,
                leaseToken: TAKEOVER_LEASE_TOKEN,
                now: new Date("2026-07-16T12:20:02.000Z"),
              });
            }
            const proof = leases.assertMutationAuthority({
              runId,
              controlPlane: "ti_scale",
              leaseOwner: CONTROL_LEASE_OWNER,
              leaseToken: state.leaseMode === "wrong_token"
                ? "wrong-run-intelligence-token-000000"
                : CONTROL_LEASE_TOKEN,
              now: new Date("2026-07-16T12:20:00.000Z"),
            });
            return state.leaseMode === "wrong_fence"
              ? { ...proof, version: proof.version + 1 } satisfies ControlPlaneLease
              : proof;
          },
        }),
  }));
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  const harness = { database, server, origin: `http://127.0.0.1:${address.port}`, state };
  openHarnesses.push(harness);
  return harness;
}

async function closeHarness(harness: RouterHarness): Promise<void> {
  const index = openHarnesses.indexOf(harness);
  if (index >= 0) openHarnesses.splice(index, 1);
  if (harness.server.listening) {
    await new Promise<void>((resolve, reject) => {
      harness.server.close((error) => error ? reject(error) : resolve());
    });
  }
  harness.database.close();
}

afterEach(async () => {
  await Promise.all(openHarnesses.splice(0).map(closeHarness));
});

async function request(
  harness: RouterHarness,
  path: string,
  input: { readonly method?: string; readonly idempotencyKey?: string; readonly body?: unknown } = {},
): Promise<HttpResult> {
  const headers = new Headers({ "X-Request-ID": "run-intelligence-router-test" });
  if (input.body !== undefined) headers.set("Content-Type", "application/json");
  if (input.idempotencyKey) headers.set("Idempotency-Key", input.idempotencyKey);
  const response = await fetch(`${harness.origin}${path}`, {
    method: input.method ?? "GET",
    headers,
    ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
  });
  return { status: response.status, headers: response.headers, body: await response.json() as unknown };
}

function errorBody(value: unknown): { readonly error: { readonly code: string; readonly category: string; readonly traceId: string } } {
  return value as { readonly error: { readonly code: string; readonly category: string; readonly traceId: string } };
}

function topologyNodeBody(evidenceId: string, nodeType = "asset", identity = "10.10.10.10") {
  return {
    runId: RUN_ID,
    nodeType,
    primaryLabel: nodeType === "asset" ? "web-01" : "HTTPS",
    normalizedIdentity: identity,
    scopeStatus: "allowed",
    lifecycleState: "observed",
    properties: nodeType === "asset" ? { addresses: ["10.10.10.10"] } : { port: 443, transport: "tcp" },
    provenance: {
      method: "structured_scan_parser",
      sourceRef: `scan:${identity}`,
      sourceAgentId: AGENT_ONE_ID,
    },
    confidence: 0.95,
    verificationState: "verified",
    sensitivity: "internal",
    firstSeenAt: "2026-07-16T12:01:00.000Z",
    lastSeenAt: "2026-07-16T12:02:00.000Z",
    evidence: [{ evidenceId, relationship: "supports" }],
  } as const;
}

function topologyEdgeBody(sourceNodeId: string, targetNodeId: string, evidenceId: string) {
  return {
    sourceNodeId,
    targetNodeId,
    edgeType: "exposes",
    properties: { port: 443 },
    provenance: { method: "service_parser", sourceRef: "scan:https", sourceAgentId: AGENT_ONE_ID },
    confidence: 0.96,
    verificationState: "verified",
    sensitivity: "internal",
    firstSeenAt: "2026-07-16T12:02:00.000Z",
    lastSeenAt: "2026-07-16T12:02:00.000Z",
    evidence: [{ evidenceId, relationship: "supports" }],
  } as const;
}

function osiObservationBody(evidenceId: string) {
  return {
    layer: 7,
    category: "application_product",
    value: "nginx",
    versionValue: "1.24.0",
    derivation: "actively_verified",
    confidence: 0.97,
    evidenceId,
    observedAt: "2026-07-16T12:03:00.000Z",
  } as const;
}

async function createAssetThroughRouter(harness: RouterHarness, evidenceId: string): Promise<TopologyNode> {
  const result = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`, {
    method: "POST",
    idempotencyKey: `node-create-${evidenceId}`,
    body: topologyNodeBody(evidenceId),
  });
  expect(result.status).toBe(201);
  return (result.body as { readonly node: TopologyNode }).node;
}

describe("RunIntelligenceRouter", () => {
  test("lease-fences every topology mutation before replay while imported topology remains readable", async () => {
    const withoutResolver = await createHarness({ includeLeaseResolver: false });
    insertEvidence(withoutResolver.database, { id: "evidence-topology-no-resolver" });
    const absentResolver = await request(
      withoutResolver,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`,
      {
        method: "POST",
        idempotencyKey: "topology-authority-no-resolver",
        body: topologyNodeBody("evidence-topology-no-resolver"),
      },
    );
    expect(absentResolver.status).toBe(409);
    expect(errorBody(absentResolver.body).error.code).toBe("control_plane_lease_missing");
    expect(withoutResolver.database.prepare("SELECT COUNT(*) AS count FROM topology_nodes").get())
      .toEqual({ count: 0 });

    const harness = await createHarness();
    for (const id of [
      "evidence-topology-authority-asset",
      "evidence-topology-authority-service",
      "evidence-topology-authority-node",
      "evidence-topology-authority-edge",
      "evidence-topology-authority-osi",
      "evidence-topology-authority-heartbeat",
    ]) insertEvidence(harness.database, { id });
    const asset = await createAssetThroughRouter(harness, "evidence-topology-authority-asset");
    const serviceResult = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`,
      {
        method: "POST",
        idempotencyKey: "topology-authority-service",
        body: topologyNodeBody(
          "evidence-topology-authority-service",
          "service",
          "10.10.10.10:443/tcp",
        ),
      },
    );
    expect(serviceResult.status).toBe(201);
    const service = (serviceResult.body as { readonly node: TopologyNode }).node;

    harness.state.leaseMode = "missing";
    harness.state.leaseChecks = 0;
    const missingNode = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`,
      {
        method: "POST",
        idempotencyKey: "topology-authority-node-missing",
        body: topologyNodeBody("evidence-topology-authority-node", "asset", "10.10.10.11"),
      },
    );
    expect(missingNode.status).toBe(409);
    expect(errorBody(missingNode.body).error.code).toBe("control_plane_lease_missing");

    harness.state.leaseChecks = 0;
    const missingEdge = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/edges`,
      {
        method: "POST",
        idempotencyKey: "topology-authority-edge-missing",
        body: topologyEdgeBody(asset.id, service.id, "evidence-topology-authority-edge"),
      },
    );
    expect(missingEdge.status).toBe(409);
    expect(errorBody(missingEdge.body).error.code).toBe("control_plane_lease_missing");

    harness.state.leaseChecks = 0;
    const missingOsi = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/assets/${asset.id}/osi`,
      {
        method: "POST",
        idempotencyKey: "topology-authority-osi-missing",
        body: osiObservationBody("evidence-topology-authority-osi"),
      },
    );
    expect(missingOsi.status).toBe(409);
    expect(errorBody(missingOsi.body).error.code).toBe("control_plane_lease_missing");
    expect(harness.database.prepare("SELECT COUNT(*) AS count FROM topology_edges").get())
      .toEqual({ count: 0 });
    expect(harness.database.prepare("SELECT COUNT(*) AS count FROM asset_layer_observations").get())
      .toEqual({ count: 0 });

    harness.state.leaseMode = "heartbeat";
    harness.state.leaseChecks = 0;
    const heartbeatRequest = {
      method: "POST",
      idempotencyKey: "topology-authority-heartbeat",
      body: topologyNodeBody("evidence-topology-authority-heartbeat", "asset", "10.10.10.12"),
    } as const;
    const heartbeat = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`,
      heartbeatRequest,
    );
    expect(heartbeat.status, JSON.stringify(heartbeat.body)).toBe(201);
    expect(heartbeat.headers.get("idempotency-replayed")).toBe("false");

    harness.state.leaseMode = "missing";
    harness.state.leaseChecks = 0;
    const replayWithoutAuthority = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`,
      heartbeatRequest,
    );
    expect(replayWithoutAuthority.status).toBe(409);
    expect(errorBody(replayWithoutAuthority.body).error.code).toBe("control_plane_lease_missing");
    expect(harness.database.prepare("SELECT COUNT(*) AS count FROM topology_nodes").get())
      .toEqual({ count: 3 });

    harness.state.leaseMode = "valid";
    harness.state.leaseChecks = 0;
    harness.database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?").run(MISSION_ID);
    harness.database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?").run(RUN_ID);
    const importedGraph = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology?runId=${RUN_ID}`,
    );
    expect(importedGraph.status).toBe(200);
    expect((importedGraph.body as { readonly digitalTwin: ReconDigitalTwin }).digitalTwin.nodes)
      .toHaveLength(3);
    const importedOsi = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/assets/${asset.id}/osi`,
    );
    expect(importedOsi.status).toBe(200);
    const importedReplay = await request(
      harness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`,
      heartbeatRequest,
    );
    expect(importedReplay.status).toBe(409);
    expect(errorBody(importedReplay.body).error.code).toBe("control_plane_mismatch");

    const takeoverHarness = await createHarness();
    insertEvidence(takeoverHarness.database, { id: "evidence-topology-authority-takeover" });
    takeoverHarness.state.leaseMode = "takeover";
    takeoverHarness.state.leaseChecks = 0;
    const takeover = await request(
      takeoverHarness,
      `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`,
      {
        method: "POST",
        idempotencyKey: "topology-authority-takeover",
        body: topologyNodeBody("evidence-topology-authority-takeover"),
      },
    );
    expect(takeover.status).toBe(409);
    expect(errorBody(takeover.body).error.code).toBe("control_plane_lease_fence_invalid");
    expect(takeoverHarness.database.prepare("SELECT COUNT(*) AS count FROM topology_nodes").get())
      .toEqual({ count: 0 });
  });

  test("keeps deterministic metrics ownership-only while lease-fencing attack-attempt mutations", async () => {
    const harness = await createHarness();

    harness.state.leaseMode = "missing";
    const metrics = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/metrics/recompute`, {
      method: "POST", idempotencyKey: "metrics-ownership-only-0001", body: {},
    });
    expect(metrics.status).toBe(200);

    const attemptBody = {
      targetAssetId: "asset-authority-fixture",
      objective: "Validate the represented service hypothesis",
      techniqueName: "Bounded service validation",
      actionClass: "vulnerability_scanning",
      prerequisites: [],
      normalizedParameters: { target: "fixture.local" },
      assignedAgentId: AGENT_ONE_ID,
    };
    const missing = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`, {
      method: "POST", idempotencyKey: "attempt-authority-missing", body: attemptBody,
    });
    expect(missing.status).toBe(409);
    expect(errorBody(missing.body).error.code).toBe("control_plane_lease_missing");

    harness.state.leaseMode = "wrong_token";
    const wrongToken = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`, {
      method: "POST", idempotencyKey: "attempt-authority-token", body: attemptBody,
    });
    expect(wrongToken.status).toBe(409);
    expect(errorBody(wrongToken.body).error.code).toBe("control_plane_lease_authority_invalid");

    harness.state.leaseMode = "wrong_fence";
    const wrongFence = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`, {
      method: "POST", idempotencyKey: "attempt-authority-fence", body: attemptBody,
    });
    expect(wrongFence.status).toBe(409);
    expect(errorBody(wrongFence.body).error.code).toBe("control_plane_lease_fence_invalid");

    harness.state.leaseMode = "valid";
    harness.database.prepare("UPDATE control_plane_leases SET expires_at = ? WHERE run_id = ?")
      .run("2026-07-16T12:19:59.000Z", RUN_ID);
    const expired = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`, {
      method: "POST", idempotencyKey: "attempt-authority-expired", body: attemptBody,
    });
    expect(expired.status).toBe(409);
    expect(errorBody(expired.body).error.code).toBe("control_plane_lease_expired");

    harness.database.prepare("UPDATE control_plane_leases SET expires_at = ? WHERE run_id = ?")
      .run("2026-07-16T12:25:00.000Z", RUN_ID);
    harness.database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?").run(MISSION_ID);
    harness.database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?").run(RUN_ID);
    const legacyMetrics = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/metrics/recompute`, {
      method: "POST", idempotencyKey: "metrics-legacy-denied-0001", body: {},
    });
    expect(legacyMetrics.status).toBe(409);
    expect(errorBody(legacyMetrics.body).error.code).toBe("control_plane_mismatch");
    harness.database.prepare("UPDATE missions SET control_plane = 'ti_scale' WHERE id = ?").run(MISSION_ID);
    harness.database.prepare("UPDATE runs SET control_plane = 'ti_scale' WHERE id = ?").run(RUN_ID);

    insertEvidence(harness.database, { id: "evidence-authority-asset" });
    const asset = await createAssetThroughRouter(harness, "evidence-authority-asset");
    const valid = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`, {
      method: "POST",
      idempotencyKey: "attempt-authority-valid",
      body: { ...attemptBody, targetAssetId: asset.id },
    });
    expect(valid.status).toBe(201);
    const attempt = (valid.body as { readonly attempt: AttackAttempt }).attempt;

    harness.state.leaseMode = "wrong_token";
    const fencedTransition = await request(
      harness,
      `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts/${attempt.id}/transition`,
      {
        method: "POST",
        idempotencyKey: "attempt-authority-transition-fenced",
        body: { kind: "state", expectedVersion: 1, status: "ready" },
      },
    );
    expect(fencedTransition.status).toBe(409);
    expect(errorBody(fencedTransition.body).error.code).toBe("control_plane_lease_authority_invalid");

    harness.state.leaseMode = "valid";
    const transition = await request(
      harness,
      `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts/${attempt.id}/transition`,
      {
        method: "POST",
        idempotencyKey: "attempt-authority-transition",
        body: { kind: "state", expectedVersion: 1, status: "ready" },
      },
    );
    expect(transition.status).toBe(200);
  });

  test("fails closed for missing identity and denied mission capabilities, and emits canonical errors", async () => {
    const harness = await createHarness();
    harness.state.actor = undefined;
    const unauthenticated = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`);
    expect(unauthenticated.status).toBe(401);
    expect(errorBody(unauthenticated.body).error).toEqual(expect.objectContaining({
      code: "run_intelligence_authentication_required",
      category: "authentication_missing",
      traceId: "run-intelligence-router-test",
    }));
    expect(harness.state.authorizations).toHaveLength(0);

    harness.state.actor = { id: "operator-router", type: "operator" };
    harness.state.allowed = false;
    const denied = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`);
    expect(denied.status).toBe(403);
    expect(errorBody(denied.body).error.code).toBe("run_intelligence_policy_denied");
    expect(harness.state.authorizations.at(-1)).toEqual({
      missionId: MISSION_ID,
      runId: RUN_ID,
      capability: "read_attack_attempts",
      resource: "attack_attempts",
    });

    harness.state.allowed = true;
    const invalidLimit = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/metrics/snapshots?limit=101`);
    expect(invalidLimit.status).toBe(400);
    expect(errorBody(invalidLimit.body).error.code).toBe("invalid_run_intelligence_limit");

    const missingKey = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/metrics/recompute`, {
      method: "POST",
      body: {},
    });
    expect(missingKey.status).toBe(400);
    expect(errorBody(missingKey.body).error.code).toBe("run_intelligence_idempotency_key_required");

    const unknownField = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/metrics/recompute`, {
      method: "POST",
      idempotencyKey: "metrics-unknown-field",
      body: { silentlyIgnored: true },
    });
    expect(unknownField.status).toBe(400);
    expect(errorBody(unknownField.body).error.code).toBe("invalid_run_intelligence_request");
    expect(unknownField.headers.get("cache-control")).toBe("no-store");
  });

  test("recomputes, replays, lists, and reads reproducible metric snapshots with drill-down descriptors", async () => {
    const harness = await createHarness();
    insertEvent(harness.database, 1, "run.started", "2026-07-16T12:00:00.000Z");
    insertEvent(harness.database, 2, "step.completed", "2026-07-16T12:10:00.000Z");

    const first = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/metrics/recompute`, {
      method: "POST",
      idempotencyKey: "metrics-recompute-0001",
      body: {},
    });
    expect(first.status).toBe(200);
    expect(first.headers.get("idempotency-replayed")).toBe("false");
    const snapshot = (first.body as { readonly snapshot: RunMetricsSnapshot }).snapshot;
    expect(snapshot.runId).toBe(RUN_ID);
    expect(snapshot.throughEventSequence).toBe(2);
    expect(snapshot.metrics.length).toBeGreaterThan(40);
    expect(snapshot.metrics.every((metric) => metric.drillDown.length > 0)).toBe(true);
    expect(snapshot.metrics.flatMap((metric) => metric.drillDown).every((reference) => (
      reference.missionId === MISSION_ID
      && reference.runId === RUN_ID
      && reference.filters.some((filter) => filter.field === "run_id" && filter.value === RUN_ID)
    ))).toBe(true);

    const replay = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/metrics/recompute`, {
      method: "POST",
      idempotencyKey: "metrics-recompute-0001",
      body: {},
    });
    expect(replay.status).toBe(200);
    expect(replay.headers.get("idempotency-replayed")).toBe("true");
    expect(replay.body).toEqual(first.body);
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM run_metrics_snapshots").get() as { readonly count: number }).count).toBe(1);

    const list = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/metrics/snapshots`);
    expect(list.status).toBe(200);
    expect((list.body as { readonly latestSnapshotId: string; readonly items: RunMetricsSnapshot[] }).latestSnapshotId).toBe(snapshot.id);
    expect((list.body as { readonly items: RunMetricsSnapshot[] }).items).toHaveLength(1);

    const detail = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/metrics/snapshots/${snapshot.id}`);
    expect(detail.status).toBe(200);
    expect((detail.body as { readonly snapshot: RunMetricsSnapshot }).snapshot.recomputationHash).toBe(snapshot.recomputationHash);
  });

  test("creates and transitions attack attempts idempotently while preserving evidence-gated outcomes", async () => {
    const harness = await createHarness();
    insertEvidence(harness.database, { id: "evidence-asset-router" });
    const asset = await createAssetThroughRouter(harness, "evidence-asset-router");
    const body = {
      targetAssetId: asset.id,
      objective: "Validate the bounded HTTPS hypothesis",
      techniqueName: "Version-aware service validation",
      actionClass: "vulnerability_scanning",
      prerequisites: ["Service fingerprint is attributable"],
      normalizedParameters: { port: 443, target: "10.10.10.10" },
      assignedAgentId: AGENT_ONE_ID,
    };

    const created = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`, {
      method: "POST",
      idempotencyKey: "attempt-create-router-0001",
      body,
    });
    expect(created.status).toBe(201);
    expect(created.headers.get("idempotency-replayed")).toBe("false");
    const attempt = (created.body as { readonly attempt: AttackAttempt }).attempt;
    expect(attempt.status).toBe("planned");
    expect(attempt.missionId).toBe(MISSION_ID);

    const replay = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`, {
      method: "POST",
      idempotencyKey: "attempt-create-router-0001",
      body,
    });
    expect(replay.status).toBe(201);
    expect(replay.headers.get("idempotency-replayed")).toBe("true");
    expect(replay.body).toEqual(created.body);
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM attack_attempts").get() as { readonly count: number }).count).toBe(1);

    const conflictingReplay = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`, {
      method: "POST",
      idempotencyKey: "attempt-create-router-0001",
      body: { ...body, objective: "A materially different objective" },
    });
    expect(conflictingReplay.status).toBe(409);
    expect(errorBody(conflictingReplay.body).error.code).toBe("run_intelligence_idempotency_conflict");

    const ready = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts/${attempt.id}/transition`, {
      method: "POST",
      idempotencyKey: "attempt-ready-router-0001",
      body: { kind: "state", expectedVersion: 1, status: "ready", reason: "Prerequisite is present" },
    });
    expect(ready.status).toBe(200);
    expect((ready.body as { readonly attempt: AttackAttempt }).attempt.status).toBe("ready");

    const running = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts/${attempt.id}/transition`, {
      method: "POST",
      idempotencyKey: "attempt-running-router-0001",
      body: { kind: "state", expectedVersion: 2, status: "running" },
    });
    expect(running.status).toBe(200);
    expect((running.body as { readonly attempt: AttackAttempt }).attempt.version).toBe(3);

    const unsupportedSuccess = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts/${attempt.id}/transition`, {
      method: "POST",
      idempotencyKey: "attempt-outcome-router-0001",
      body: { kind: "outcome", expectedVersion: 3, outcome: "succeeded", outcomeSummary: "Claimed without proof" },
    });
    expect(unsupportedSuccess.status).toBe(409);
    expect(errorBody(unsupportedSuccess.body).error.code).toBe("verified_outcome_evidence_required");

    insertEvidence(harness.database, { id: "evidence-attempt-outcome-router" });
    const succeeded = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts/${attempt.id}/transition`, {
      method: "POST",
      idempotencyKey: "attempt-outcome-router-0002",
      body: {
        kind: "outcome",
        expectedVersion: 3,
        outcome: "succeeded",
        outcomeSummary: "Verified service behavior matched the bounded hypothesis",
        evidence: [{ evidenceId: "evidence-attempt-outcome-router", relationship: "outcome" }],
      },
    });
    expect(succeeded.status).toBe(200);
    expect((succeeded.body as { readonly attempt: AttackAttempt }).attempt).toEqual(expect.objectContaining({
      status: "succeeded",
      version: 4,
    }));

    const list = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts`);
    expect((list.body as { readonly items: AttackAttempt[] }).items).toHaveLength(1);
    const detail = await request(harness, `/api/v2/runs/${RUN_ID}/intelligence/attack-attempts/${attempt.id}`);
    expect((detail.body as { readonly attempt: AttackAttempt }).attempt.evidence[0]?.verificationState).toBe("verified");
  });

  test("creates and reads evidence-backed topology nodes, edges, and complete seven-layer OSI projections", async () => {
    const harness = await createHarness();
    insertEvidence(harness.database, { id: "evidence-topology-asset" });
    insertEvidence(harness.database, { id: "evidence-topology-service" });
    insertEvidence(harness.database, { id: "evidence-topology-edge" });
    insertEvidence(harness.database, { id: "evidence-topology-osi" });

    const assetResult = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`, {
      method: "POST",
      idempotencyKey: "topology-asset-router-0001",
      body: topologyNodeBody("evidence-topology-asset"),
    });
    expect(assetResult.status).toBe(201);
    const asset = (assetResult.body as { readonly node: TopologyNode }).node;
    const assetReplay = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`, {
      method: "POST",
      idempotencyKey: "topology-asset-router-0001",
      body: topologyNodeBody("evidence-topology-asset"),
    });
    expect(assetReplay.headers.get("idempotency-replayed")).toBe("true");
    expect(assetReplay.body).toEqual(assetResult.body);

    const serviceResult = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes`, {
      method: "POST",
      idempotencyKey: "topology-service-router-0001",
      body: topologyNodeBody("evidence-topology-service", "service", "10.10.10.10:443/tcp"),
    });
    const service = (serviceResult.body as { readonly node: TopologyNode }).node;

    const edgeResult = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology/edges`, {
      method: "POST",
      idempotencyKey: "topology-edge-router-0001",
      body: {
        sourceNodeId: asset.id,
        targetNodeId: service.id,
        edgeType: "exposes",
        properties: { port: 443 },
        provenance: { method: "service_parser", sourceRef: "scan:https", sourceAgentId: AGENT_ONE_ID },
        confidence: 0.96,
        verificationState: "verified",
        sensitivity: "internal",
        firstSeenAt: "2026-07-16T12:02:00.000Z",
        lastSeenAt: "2026-07-16T12:02:00.000Z",
        evidence: [{ evidenceId: "evidence-topology-edge", relationship: "supports" }],
      },
    });
    expect(edgeResult.status).toBe(201);
    const edge = (edgeResult.body as { readonly edge: TopologyEdge }).edge;
    expect(edge.edgeType).toBe("exposes");

    const graphResult = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology?runId=${RUN_ID}`);
    const graph = (graphResult.body as { readonly digitalTwin: ReconDigitalTwin }).digitalTwin;
    expect(graph.nodes.map(({ id }) => id)).toEqual(expect.arrayContaining([asset.id, service.id]));
    expect(graph.edges.map(({ id }) => id)).toContain(edge.id);

    const nodeList = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology/nodes?runId=${RUN_ID}`);
    expect((nodeList.body as { readonly items: TopologyNode[] }).items).toHaveLength(2);
    const edgeDetail = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology/edges/${edge.id}`);
    expect((edgeDetail.body as { readonly edge: TopologyEdge }).edge.evidence[0]?.contentHash).toHaveLength(64);

    const osiResult = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology/assets/${asset.id}/osi`, {
      method: "POST",
      idempotencyKey: "topology-osi-router-0001",
      body: {
        layer: 7,
        category: "application_product",
        value: "nginx",
        versionValue: "1.24.0",
        derivation: "actively_verified",
        confidence: 0.97,
        evidenceId: "evidence-topology-osi",
        observedAt: "2026-07-16T12:03:00.000Z",
      },
    });
    expect(osiResult.status).toBe(201);
    const createdStack = (osiResult.body as { readonly stack: AssetOsiStack }).stack;
    expect(createdStack.layers).toHaveLength(7);
    expect(createdStack.layers[0]).toEqual(expect.objectContaining({ layer: 1, state: "not_observed", observations: [] }));
    expect(createdStack.layers[6]).toEqual(expect.objectContaining({ layer: 7, state: "observed" }));
    expect(createdStack.layers[6]?.observations[0]?.versionValue).toBe("1.24.0");

    const osiRead = await request(harness, `/api/v2/missions/${MISSION_ID}/intelligence/topology/assets/${asset.id}/osi`);
    expect((osiRead.body as { readonly stack: AssetOsiStack }).stack).toEqual(createdStack);
    expect(harness.state.authorizations.some(({ capability, resource }) => (
      capability === "manage_topology" && resource === "osi"
    ))).toBe(true);
  });
});
