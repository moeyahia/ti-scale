import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  AutonomousActivationReceiptIntegrityError,
  type AutonomousActivationReceipt,
  type AutonomousActivationReceiptRepository,
  type AutonomousActivationReceiptVerifier,
} from "../../autonomous-runtime";
import { RuntimeRepository } from "../../command-runtime";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { createMissionRuntimeReadRouter } from "../MissionRuntimeReadRouter";

const NOW = "2026-07-28T12:00:00.000Z";
const HASH = "a".repeat(64);
const servers: Server[] = [];
const databases: SqliteDatabase[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  for (const database of databases.splice(0)) database.close();
});

function receipt(input: {
  readonly id: string;
  readonly runId: string;
  readonly missionId: string;
  readonly generation: number;
  readonly route: "local_deterministic" | "provider_advisory";
  readonly expiresAt: string;
}): AutonomousActivationReceipt {
  const provider = input.route === "provider_advisory";
  const planning: AutonomousActivationReceipt["planning"] = provider
    ? {
        route: "provider_advisory" as const,
        selection: {
          route: "provider_advisory" as const,
          agentId: "VulnIntel",
          primaryConfigurationId: "configuration-planning",
          fallbackConfigurationId: null,
          enforcementMode: "advisor_only" as const,
          disclosureClass: "sanitized_internal",
          executionAuthority: "none" as const,
        },
        selectionHash: HASH,
        plannerId: "VulnIntel",
        modelAssignmentId: "assignment-planning",
        primaryConfigurationId: "configuration-planning",
        fallbackConfigurationId: null,
        primaryConfigurationHash: HASH,
        fallbackConfigurationHash: null,
      }
    : {
        route: "local_deterministic" as const,
        selection: {
          route: "local_deterministic" as const,
          plannerId: "ti-scale.local-autonomous-contract-planner.v1",
          enforcementMode: "local_policy" as const,
          disclosureClass: "local_only" as const,
          executionAuthority: "none" as const,
        },
        selectionHash: HASH,
        plannerId: "ti-scale.local-autonomous-contract-planner.v1",
        modelAssignmentId: null,
        primaryConfigurationId: null,
        fallbackConfigurationId: null,
        primaryConfigurationHash: null,
        fallbackConfigurationHash: null,
      };
  return {
    id: input.id,
    schemaVersion: "2.4",
    missionId: input.missionId,
    runId: input.runId,
    contractId: `contract-${input.runId}`,
    generation: input.generation,
    contractVersion: 1,
    contractHash: HASH,
    runtimeGenerationHash: HASH,
    modelAssignmentSetHash: HASH,
    evidencePolicyHash: HASH,
    brainContextPackId: `context-${input.runId}`,
    brainContextPackHash: HASH,
    planning,
    selectedActionClassIds: ["port_service_enumeration"],
    selectedActionClassCount: 1,
    activatedActionClassCount: 1,
    routeSetHash: HASH,
    issuedBy: "operator:test",
    issuedAt: NOW,
    expiresAt: input.expiresAt,
    receiptHash: HASH,
    items: [{
      actionClassId: "port_service_enumeration",
      agentId: "ReconScout",
      executionModelAssignmentId: "assignment-execution",
      executionPrimaryConfigurationId: "configuration-execution",
      executionFallbackConfigurationId: null,
      toolId: "nmap-service-scan",
      toolBindingKind: "local",
      mcpServerId: null,
      toolActivationReceiptId: "tool-receipt",
      toolActivationReceiptHash: HASH,
      toolManifestHash: HASH,
      evidenceTypeIds: ["port_service_scan_result"],
      evidenceProducerIds: ["nmap-normalizer"],
      routeExpiresAt: input.expiresAt,
      routeHash: HASH,
      createdAt: NOW,
    }],
    bindings: [{
      id: `binding-${input.id}`,
      receiptId: input.id,
      sequence: 1,
      bindingType: "launch",
      subjectId: input.runId,
      subjectDigest: HASH,
      runtimeGenerationHash: HASH,
      planId: null,
      stepId: null,
      actionId: null,
      contextPackId: `context-${input.runId}`,
      providerTurnId: null,
      previousBindingHash: null,
      boundBy: "operator:test",
      boundAt: NOW,
      bindingHash: HASH,
    }],
  };
}

function seedRun(
  database: SqliteDatabase,
  missionId: string,
  runId: string,
): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      success_criteria_json, memory_policy_json, created_by, created_at,
      updated_at
    ) VALUES (?, ?, 'Assess the authorized local fixture', 'autonomous',
      'active', 'verified', '[]', '{}', 'operator:test', ?, ?)
  `).run(missionId, missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, budget_json,
      budget_usage_json, created_at, updated_at
    ) VALUES (?, ?, 'autonomous', 'planning', 0.1, '{}', '{}', ?, ?)
  `).run(runId, missionId, NOW, NOW);
}

async function application(options: {
  readonly integrityFailureReceiptId?: string;
} = {}) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  seedRun(database, "mission-public", "run-public");
  seedRun(database, "mission-other", "run-other");
  const current = receipt({
    id: "receipt-provider",
    runId: "run-public",
    missionId: "mission-public",
    generation: 2,
    route: "provider_advisory",
    expiresAt: "2026-07-28T14:00:00.000Z",
  });
  const prior = receipt({
    id: "receipt-local-expired",
    runId: "run-public",
    missionId: "mission-public",
    generation: 1,
    route: "local_deterministic",
    expiresAt: "2026-07-28T11:00:00.000Z",
  });
  const other = receipt({
    id: "receipt-other",
    runId: "run-other",
    missionId: "mission-other",
    generation: 1,
    route: "local_deterministic",
    expiresAt: "2026-07-28T14:00:00.000Z",
  });
  const records = new Map([
    [current.id, current],
    [prior.id, prior],
    [other.id, other],
  ]);
  const receiptRepository: Pick<
    AutonomousActivationReceiptRepository,
    "findById" | "findCurrentForRun" | "listForRun"
  > = {
    findById: (id) => records.get(id) ?? null,
    findCurrentForRun: (runId) =>
      runId === "run-public" ? current : runId === "run-other" ? other : null,
    listForRun: (runId, limit = 100) =>
      (runId === "run-public" ? [current, prior] : runId === "run-other" ? [other] : [])
        .slice(0, limit),
  };
  const verifier: Pick<AutonomousActivationReceiptVerifier, "verify"> = {
    verify: (id) => {
      const value = records.get(id);
      if (!value) {
        throw new AutonomousActivationReceiptIntegrityError(
          "activation_receipt_not_found",
          "Activation receipt was not found",
        );
      }
      if (id === options.integrityFailureReceiptId) {
        throw new AutonomousActivationReceiptIntegrityError(
          "activation_receipt_runtime_generation_drift",
          "The current runtime generation no longer matches this proof",
        );
      }
      return { valid: true, receipt: value, verifiedAt: NOW };
    },
  };
  const app = express();
  app.use(express.json());
  app.use(createMissionRuntimeReadRouter({
    repository: new RuntimeRepository(database),
    checkpoints: { latest: () => undefined },
    autonomousActivationReceipts: receiptRepository,
    autonomousActivationReceiptVerifier: verifier,
    clock: () => new Date(NOW),
    resolveActor: () => "operator:test",
    authorizeMission: (_request, _actor, missionId) => missionId === "mission-public",
    authorizeRun: (_request, _actor, scope) => scope.runId === "run-public",
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("Autonomous activation receipt runtime reads", () => {
  test("projects compact current proof, newest-first provider/local history, expiry, and exact detail", async () => {
    const base = await application();
    const run = await (await fetch(`${base}/api/v2/runs/run-public`)).json() as {
      readonly currentAutonomousActivationReceipt: Record<string, unknown>;
    };
    expect(run.currentAutonomousActivationReceipt).toMatchObject({
      id: "receipt-provider",
      generation: 2,
      planningRoute: "provider_advisory",
      activatedActionClassCount: 1,
      selectedActionClassCount: 1,
      integrity: { status: "verified", code: null },
    });

    const history = await (await fetch(
      `${base}/api/v2/runs/run-public/autonomous-activation-receipts?limit=2`,
    )).json() as { readonly items: readonly Record<string, unknown>[] };
    expect(history.items.map(({ id }) => id)).toEqual([
      "receipt-provider",
      "receipt-local-expired",
    ]);
    expect(history.items[1]).toMatchObject({
      planningRoute: "local_deterministic",
      integrity: {
        status: "expired",
        code: "activation_receipt_expired",
      },
    });

    const detailResponse = await fetch(
      `${base}/api/v2/runs/run-public/autonomous-activation-receipts/receipt-provider`,
    );
    expect(detailResponse.status).toBe(200);
    expect(await detailResponse.json()).toMatchObject({
      schemaVersion: "2.4",
      summary: { id: "receipt-provider", planningRoute: "provider_advisory" },
      receipt: {
        id: "receipt-provider",
        runId: "run-public",
        planning: { route: "provider_advisory" },
        items: [{ actionClassId: "port_service_enumeration" }],
        bindings: [{ bindingType: "launch" }],
      },
    });
  });

  test("does not disclose cross-run receipt existence and rejects writes or malformed identifiers", async () => {
    const base = await application();
    const unknown = await fetch(
      `${base}/api/v2/runs/run-public/autonomous-activation-receipts/receipt-unknown`,
    );
    const crossRun = await fetch(
      `${base}/api/v2/runs/run-public/autonomous-activation-receipts/receipt-other`,
    );
    expect(unknown.status).toBe(404);
    expect(crossRun.status).toBe(404);
    expect((await unknown.json() as { error: { code: string } }).error.code)
      .toBe("autonomous_activation_receipt_not_found");
    expect((await crossRun.json() as { error: { code: string } }).error.code)
      .toBe("autonomous_activation_receipt_not_found");

    const write = await fetch(
      `${base}/api/v2/runs/run-public/autonomous-activation-receipts`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
    );
    expect(write.status).toBe(405);
    expect(write.headers.get("allow")).toBe("GET");

    const malformed = await fetch(
      `${base}/api/v2/runs/run-public/autonomous-activation-receipts/%20`,
    );
    expect(malformed.status).toBe(400);
  });

  test("returns runtime-generation drift as an inspectable integrity state", async () => {
    const base = await application({
      integrityFailureReceiptId: "receipt-provider",
    });
    const response = await fetch(`${base}/api/v2/runs/run-public`);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      currentAutonomousActivationReceipt: {
        integrity: {
          status: "integrity_failure",
          code: "activation_receipt_runtime_generation_drift",
          humanMessage: expect.stringContaining("cannot be trusted"),
        },
      },
    });
  });
});
