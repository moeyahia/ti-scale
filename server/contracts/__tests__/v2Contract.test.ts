import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  COMMAND_OS_JOURNEYS,
  COMMAND_OS_RUN_STATES,
  TI_SCALE_DEFERRED_ENDPOINTS,
  TI_SCALE_ENDPOINTS,
  createCommandOsOpenApiDocument,
  operationalEventJsonSchema,
} from "../v2Contract";
import { toOperationalEventEnvelope } from "../../events/EventStreamService";
import type { RunEvent } from "../../events/types";

function routeIds(files: readonly string[]): string[] {
  const identities = new Set<string>();
  const route = /router\.(get|post|put|patch|delete)\(\s*(["'`])([^"'`]+)\2/gu;
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(route)) {
      const method = match[1]!;
      const sourcePath = match[3]!;
      const dynamicPrefix = file.endsWith("OperationalTruthRouter.ts")
        ? "/api/v2/operational-truth"
        : file.endsWith("RunIntelligenceRouter.ts")
          ? "/api/v2"
          : file.endsWith("CveApplicabilityRouter.ts")
            ? "/api/v2"
          : file.endsWith("PageCaptureRouter.ts")
            ? "/api/v2"
          : file.endsWith("ScriptArtifactRouter.ts")
            ? "/api/v2"
          : file.endsWith("PlanChangeRouter.ts")
            ? "/api/v2"
          : null;
      const path = dynamicPrefix && sourcePath.startsWith("${prefix}/")
        ? sourcePath.replace("${prefix}", dynamicPrefix)
        : sourcePath;
      if (!path.startsWith("/api/v2/")) continue;
      if (path === "/api/v2/runs/:runId/${command}") {
        for (const command of ["pause", "resume", "cancel"]) identities.add(`${method}:/api/v2/runs/:runId/${command}`);
      } else {
        identities.add(`${method}:${path}`);
      }
    }
  }
  return [...identities].sort();
}

function mountedImplementationRouteIds(): string[] {
  const serverRoot = resolve(import.meta.dir, "../..");
  return routeIds([
    resolve(serverRoot, "app/CommandOsApplication.ts"),
    resolve(serverRoot, "auth/LocalSessionRouter.ts"),
    resolve(serverRoot, "contracts/ApiContractRouter.ts"),
    resolve(serverRoot, "events/EventStreamRouter.ts"),
    resolve(serverRoot, "guided-commander/GuidedTranscriptReadRouter.ts"),
    resolve(serverRoot, "guided-commander/GuidedMemoryCandidateRouter.ts"),
    resolve(serverRoot, "memory/SecondBrainRouter.ts"),
    resolve(serverRoot, "notifications/NotificationRouter.ts"),
    resolve(serverRoot, "plan-changes/PlanChangeRouter.ts"),
    resolve(serverRoot, "cve-intelligence/CveApplicabilityRouter.ts"),
    resolve(serverRoot, "page-captures/PageCaptureRouter.ts"),
    resolve(serverRoot, "script-artifacts/ScriptArtifactRouter.ts"),
    resolve(serverRoot, "intelligence-v24/OperationalTruthRouter.ts"),
    resolve(serverRoot, "run-intelligence/RunIntelligenceRouter.ts"),
    resolve(serverRoot, "research/ResearchLabRouter.ts"),
    resolve(serverRoot, "routes/MissionRuntimeReadRouter.ts"),
    resolve(serverRoot, "routes/commandOsRoutes.ts"),
    resolve(serverRoot, "routes/operationsRoutes.ts"),
  ]);
}

function deferredImplementationRouteIds(): string[] {
  const serverRoot = resolve(import.meta.dir, "../..");
  const mountedReadProjection = new Set(routeIds([
    resolve(serverRoot, "guided-commander/GuidedTranscriptReadRouter.ts"),
    resolve(serverRoot, "routes/MissionRuntimeReadRouter.ts"),
  ]));
  return routeIds([
    resolve(serverRoot, "guided-commander/GuidedCommanderRouter.ts"),
    resolve(serverRoot, "routes/missionRuntimeV2Routes.ts"),
  ]).filter((identity) => !mountedReadProjection.has(identity));
}

describe("Ti-Scale contract", () => {
  test("publishes exactly the Autonomous and Guided journeys", () => {
    expect(COMMAND_OS_JOURNEYS).toEqual(["autonomous", "guided"]);
    expect(COMMAND_OS_RUN_STATES).toContain("awaiting_contract_confirmation");
    expect(COMMAND_OS_RUN_STATES).toContain("waiting_guided_decision");
    expect(COMMAND_OS_RUN_STATES).not.toContain("waiting_input");
    expect(COMMAND_OS_RUN_STATES).not.toContain("awaiting_plan_approval");
  });

  test("has stable unique operations and idempotency on harmful mutations", () => {
    const identities = TI_SCALE_ENDPOINTS.map((endpoint) => `${endpoint.method}:${endpoint.path}`);
    expect(new Set(identities).size).toBe(identities.length);

    const unsafeWithoutKey = TI_SCALE_ENDPOINTS.filter((endpoint) =>
      endpoint.method !== "get"
      && !endpoint.idempotencyRequired
      && endpoint.path !== "/api/v2/missions/autonomous/preflight"
      && endpoint.path !== "/api/v2/registries/intake/resolve"
      && endpoint.path !== "/api/v2/auth/session"
    );
    expect(unsafeWithoutKey).toEqual([]);
  });

  test("documents every route mounted by the isolated V2 process", () => {
    const catalog = TI_SCALE_ENDPOINTS
      .map((endpoint) => `${endpoint.method}:${endpoint.path}`)
      .sort();
    expect(catalog).toEqual(mountedImplementationRouteIds());
  });

  test("accounts for implemented runtime boundaries that are intentionally not mounted", () => {
    const mounted = new Set(TI_SCALE_ENDPOINTS.map((endpoint) => `${endpoint.method}:${endpoint.path}`));
    const deferred = TI_SCALE_DEFERRED_ENDPOINTS
      .map((endpoint) => `${endpoint.method}:${endpoint.path}`)
      .sort();
    expect(deferred).toEqual(deferredImplementationRouteIds());
    expect(deferred.every((identity) => !mounted.has(identity))).toBe(true);
    expect(TI_SCALE_DEFERRED_ENDPOINTS.every((endpoint) =>
      endpoint.reason.length > 0 && endpoint.requiredAdapters.length > 0
    )).toBe(true);
  });

  test("emits a valid OpenAPI 3.1 document with shared errors", () => {
    const document = createCommandOsOpenApiDocument() as {
      openapi: string;
      info: { title: string };
      servers: readonly { url: string; description: string }[];
      paths: Record<string, Record<string, unknown>>;
      components: { schemas: Record<string, unknown> };
      "x-ti-scale-deferred-operations": readonly { path: string }[];
    };
    expect(document.openapi).toBe("3.1.0");
    expect(document.info.title).toBe("Ti-Scale API");
    expect(document.servers).toEqual([{ url: "/", description: "Authenticated Ti-Scale host" }]);
    expect(document.paths["/api/v2/auth/session"]?.post).toBeDefined();
    expect((document.paths["/api/v2/auth/session"]?.delete as { requestBody?: unknown }).requestBody).toBeUndefined();
    expect(document.paths["/api/v2/missions/{missionId}/runtime"]?.get).toBeDefined();
    expect(document.paths["/api/v2/runs"]?.get).toBeDefined();
    expect(document.paths["/api/v2/runs/{runId}"]?.get).toBeDefined();
    expect(document.paths["/api/v2/runs/{runId}/plans"]?.get).toBeDefined();
    expect(document.paths["/api/v2/decisions"]?.get).toBeDefined();
    expect(document.paths["/api/v2/guided/{missionId}/commander/transcript"]?.get).toBeDefined();
    expect(document.paths["/api/v2/missions/{missionId}/intelligence/cves"]?.get).toBeDefined();
    expect(document.paths["/api/v2/missions/{missionId}/intelligence/cves"]?.post).toBeDefined();
    expect(document.paths["/api/v2/missions/{missionId}/intelligence/page-captures"]?.get).toBeDefined();
    expect(document.paths["/api/v2/missions/{missionId}/intelligence/page-captures"]?.post).toBeDefined();
    expect(document.paths["/api/v2/missions/{missionId}/script-artifacts"]?.get).toBeDefined();
    expect(document.paths["/api/v2/missions/{missionId}/script-artifacts/{scriptArtifactId}/versions"]?.post).toBeDefined();
    const failureResolution = document.paths[
      "/api/v2/operational-truth/missions/{missionId}/runs/{runId}/failure-diagnoses/{diagnosisId}/resolve"
    ]?.post as { requestBody?: { content?: Record<string, { schema?: unknown }> } };
    expect(failureResolution.requestBody?.content?.["application/json"]?.schema).toEqual({
      $ref: "#/components/schemas/FailureDiagnosisResolutionRequest",
    });
    expect(document.components.schemas.FailureDiagnosisResolutionRequest).toEqual({
      type: "object",
      additionalProperties: false,
      required: ["actionKind", "verifiedOutcome", "confirmed"],
      properties: {
        actionKind: {
          type: "string",
          enum: [
            "test_connection", "configure_dependency", "use_compatible_fallback", "retry_bounded",
            "resume_checkpoint", "reassign", "amend_plan", "skip", "start_new_run", "terminate_gracefully",
          ],
        },
        verifiedOutcome: { type: "string", minLength: 16, maxLength: 4_000 },
        confirmed: { type: "boolean", const: true },
      },
    });
    expect(document.paths["/api/v2/guided/{missionId}/commander/explain-more"]).toBeUndefined();
    expect(document.paths["/api/v2/runs/{runId}/cancel"]).toBeUndefined();
    expect(document["x-ti-scale-deferred-operations"]
      .some((endpoint) => endpoint.path === "/api/v2/runs/{runId}/cancel")).toBe(true);
    expect(document.paths["/api/v2/events/stream"]?.get).toBeDefined();
    expect(document.paths["/api/v2/brain/graph"]?.get).toBeDefined();
    expect(document.components.schemas.ErrorEnvelope).toBeDefined();
  });

  test("publishes the exact durable event-stream wire envelope", () => {
    const schema = operationalEventJsonSchema() as {
      required: string[];
      properties: Record<string, { type?: unknown; enum?: readonly string[] }>;
    };
    const durableEvent: RunEvent = {
      id: "evt_contract_1",
      missionId: "mission_contract_1",
      runId: "run_contract_1",
      sequence: 1,
      eventType: "assignment.heartbeat",
      occurredAt: "2026-07-16T00:00:00.000Z",
      actorType: "worker",
      actorId: null,
      summary: "Worker heartbeat retained",
      payload: { progress: true },
      schemaVersion: 1,
      journey: "autonomous",
      traceId: null,
      spanId: null,
      sensitivity: "internal",
      redaction: { paths: [] },
      contextPackId: null,
      createdAt: "2026-07-16T00:00:00.000Z",
    };
    const wireEnvelope = toOperationalEventEnvelope(durableEvent, "restricted");
    for (const field of [
      "id", "sequence", "type", "timestamp", "missionId", "runId", "actor", "summary",
      "payload", "schemaVersion", "journey", "sensitivity", "redaction", "contextPackId",
    ]) {
      expect(schema.required).toContain(field);
    }
    expect(schema.required).not.toContain("eventType");
    expect(schema.required).not.toContain("redacted");
    expect(schema.properties.eventType).toBeUndefined();
    expect(schema.properties.redacted).toBeUndefined();
    expect(schema.properties.schemaVersion?.type).toBe("integer");
    expect(schema.properties.actor).toBeDefined();
    expect(Object.keys(wireEnvelope).sort()).toEqual([...schema.required].sort());
    expect(wireEnvelope.type).toBe(durableEvent.eventType);
    expect(wireEnvelope.timestamp).toBe(durableEvent.occurredAt);
    expect(wireEnvelope.schemaVersion).toBe(1);
    expect(wireEnvelope.actor.type).toBe("worker");
  });
});
