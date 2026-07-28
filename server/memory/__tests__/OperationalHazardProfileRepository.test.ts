import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository } from "../MemoryRepository";
import {
  OperationalHazardProfileError,
  OperationalHazardProfileRepository,
  type OperationalHazardProfileInput,
} from "../OperationalHazardProfileRepository";
import type { MemoryNodeType } from "../types";

const directories: string[] = [];
const databases: SqliteDatabase[] = [];
const NOW = "2026-07-20T12:00:00.000Z";

function opaqueId(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

const IDS = {
  hazard: opaqueId("hazard-app-exec-hang"),
  procedure: opaqueId("procedure-bounded-expression"),
  procedureVersion: opaqueId("procedure-version-one"),
  product: opaqueId("product-iis"),
  version: opaqueId("version-iis-ten"),
  versionRange: opaqueId("version-runtime-range"),
  framework: opaqueId("runtime-webforms"),
  runtime: opaqueId("runtime-embedded-js"),
  prerequisite: opaqueId("prerequisite-execution-probe"),
  state: opaqueId("state-execution-path-hung"),
  health: opaqueId("health-minimal-execution"),
  recovery: opaqueId("recovery-recycle-execution"),
  alternative: opaqueId("procedure-safer-stage"),
} as const;

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "hazard-profile-test-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const add = (id: string, nodeType: MemoryNodeType, scope: "global" | "engagement" = "global") => memory.createNode({
    id,
    nodeType,
    title: `${nodeType.replaceAll("_", " ")} knowledge`,
    summary: `Generalized evidence-backed ${nodeType.replaceAll("_", " ")} record`,
    scope: scope === "global" ? { kind: "global" } : { kind: "engagement", engagementId: "eng-private" },
    sensitivity: "internal",
    confidence: 0.96,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "operator_statement",
      explanation: "The authorized operator confirmed the generalized pattern",
      sources: [{ sourceType: "private_receipt", sourceId: `receipt-${id}`, acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "operator-test",
  });
  add(IDS.hazard, "operational_hazard");
  add(IDS.procedure, "attack_procedure");
  add(IDS.procedureVersion, "procedure_version");
  add(IDS.product, "technology_product");
  add(IDS.version, "exact_version_fingerprint");
  add(IDS.versionRange, "version_range_fingerprint");
  add(IDS.framework, "framework");
  add(IDS.runtime, "runtime");
  add(IDS.prerequisite, "prerequisite");
  add(IDS.state, "target_state_transition");
  add(IDS.health, "health_check");
  add(IDS.recovery, "recovery_pattern");
  add(IDS.alternative, "attack_procedure");
  // Simulate a quarantined legacy/import row that bypassed the current public
  // repository boundary. The profile repository must still reject it.
  database.prepare(`
    INSERT INTO memory_nodes (
      id, node_type, title, summary, body, scope, engagement_id, mission_id,
      sensitivity, confidence, lifecycle_status, confirmation_state,
      provenance_json, author_type, author_id, version,
      retention_policy_json, expires_at, pinned, created_at, updated_at
    ) VALUES (
      'private-hazard', 'operational_hazard', 'Quarantined private hazard',
      'Private operational row', '', 'engagement', 'eng-private', NULL,
      'private', 0.5, 'candidate', 'pending',
      '{"method":"imported","explanation":"Quarantined","sources":[]}',
      'import', 'legacy-import', 1, '{}', NULL, 0, ?, ?
    )
  `).run(NOW, NOW);
  return {
    database,
    repository: new OperationalHazardProfileRepository(database, { clock: () => new Date(NOW) }),
  };
}

function profile(overrides: Partial<OperationalHazardProfileInput> = {}): OperationalHazardProfileInput {
  return {
    hazardNodeId: IDS.hazard,
    procedureNodeId: IDS.procedure,
    procedureVersionNodeId: IDS.procedureVersion,
    productNodeIds: [IDS.product],
    versionNodeIds: [IDS.version, IDS.versionRange],
    stackNodeIds: [IDS.framework, IDS.runtime],
    prerequisiteNodeIds: [IDS.prerequisite],
    observedStateNodeIds: [IDS.health],
    orderedSteps: [
      "Prove the application execution path responds",
      "Submit one bounded validation stage",
      "Repeat the minimal execution health probe",
      "Checkpoint the observed outcome before continuing",
    ],
    normalizedParameters: {
      automaticRetries: 0,
      maximumStageCount: 1,
      healthProbeRequired: true,
    },
    concurrencyMinimum: 1,
    timingWindowMs: 120_000,
    observedSymptom: "The base page remained reachable while the expression execution path stopped responding",
    affectedComponent: "ASP.NET-hosted embedded JavaScript execution worker",
    stateBefore: "The minimal execution probe returned the expected scalar result",
    stateAfter: "Expression requests timed out and later stages could not be assessed safely",
    stateTransitionNodeId: IDS.state,
    reproducibilityCount: 2,
    attemptCount: 3,
    recoveryPatternNodeId: IDS.recovery,
    recoveryActionSummary: "Recycle the affected execution component and prove the execution health gate before resuming",
    recoveryCost: {
      resetCount: 2,
      operatorReportedResetCountMinimum: 11,
      serviceRecycleCount: 2,
      requiresDisposableTargetReset: true,
    },
    unsafeRetryConditions: [
      "The base page responds but the application execution probe does not",
      "The previous bounded stage has no terminal outcome",
    ],
    safeRetryGate: [
      "A fresh minimal execution probe returns the expected scalar result",
      "The known-bad parameter family is excluded",
      "The automatic retry budget is zero",
    ],
    alternativeSequence: [
      "Restore a clean execution worker",
      "Run one lower-risk diagnostic stage",
      "Re-check application execution health before any next stage",
    ],
    alternativeProcedureNodeId: IDS.alternative,
    applicabilityConstraints: {
      requireExactProcedureVersion: true,
      requireVerifiedVersionRelationship: true,
      requireAllStackNodes: true,
      requireAllPrerequisites: true,
      requireObservedState: true,
    },
    confidence: 0.95,
    observedAt: NOW,
    freshUntil: "2027-01-20T12:00:00.000Z",
    ...overrides,
  };
}

describe("OperationalHazardProfileRepository", () => {
  test("stores a generalized repeated-hang profile without target identity", () => {
    const { repository } = fixture();
    const created = repository.create(profile());

    expect(created).toMatchObject({
      hazardNodeId: IDS.hazard,
      procedureNodeId: IDS.procedure,
      reproducibilityCount: 2,
      attemptCount: 3,
      version: 1,
      recoveryCost: {
        resetCount: 2,
        operatorReportedResetCountMinimum: 11,
        requiresDisposableTargetReset: true,
      },
      safeRetryGate: [
        "A fresh minimal execution probe returns the expected scalar result",
        "The known-bad parameter family is excluded",
        "The automatic retry budget is zero",
      ],
    });
    expect(JSON.stringify(created)).not.toMatch(/(?:\b\d{1,3}\.){3}\d{1,3}|SourceTarget|mission_|target_/u);
  });

  test("uses optimistic concurrency and preserves the profile identity", () => {
    const { repository } = fixture();
    repository.create(profile());
    const updated = repository.update(profile({
      attemptCount: 4,
      reproducibilityCount: 3,
      recoveryCost: { resetCount: 3, operatorReportedResetCountMinimum: 11 },
    }), 1);

    expect(updated.version).toBe(2);
    expect(updated.attemptCount).toBe(4);
    expect(() => repository.update(profile(), 1)).toThrow(OperationalHazardProfileError);
  });

  test("rejects duplicate, private-scope, wrong-type, and address-bearing profiles", () => {
    const { repository } = fixture();
    repository.create(profile());
    expect(() => repository.create(profile())).toThrow(/already exists/u);
    expect(() => repository.create(profile({
      hazardNodeId: "private-hazard",
    }))).toThrow(/reviewed global attack-knowledge/u);
    expect(() => repository.create(profile({
      productNodeIds: [IDS.framework],
    }))).toThrow(/reviewed global attack-knowledge/u);
    expect(() => repository.create(profile({
      observedSymptom: "Requests to 10.20.30.40 stopped responding",
    }))).toThrow(/private operational locators/u);
  });

  test("does not materialize a hazard profile from unreviewed candidate knowledge", () => {
    const { database, repository } = fixture();
    database.prepare(`
      UPDATE memory_nodes
      SET lifecycle_status = 'candidate', confirmation_state = 'pending'
      WHERE id = ?
    `).run(IDS.hazard);
    expect(() => repository.create(profile())).toThrow(/reviewed global attack-knowledge/u);
  });

  test("keeps exact-procedure evidence counts separate from aggregate operator reset cost", () => {
    const { repository } = fixture();
    const created = repository.create(profile({
      reproducibilityCount: 2,
      attemptCount: 2,
      recoveryCost: { operatorReportedResetCountMinimum: 11 },
    }));
    expect(created.reproducibilityCount).toBe(2);
    expect(created.attemptCount).toBe(2);
    expect(created.recoveryCost?.operatorReportedResetCountMinimum).toBe(11);
    expect(() => repository.update(profile({ attemptCount: 1, reproducibilityCount: 2 }), 1)).toThrow(
      /lower than reproducibility/u,
    );
    expect(() => repository.create(profile({
      recoveryCost: { resetCount: 12, operatorReportedResetCountMinimum: 11 },
    }))).toThrow(/aggregate reset minimum cannot be lower/u);
  });

  test("rejects untyped recovery metadata so target labels cannot enter that field", () => {
    const { repository } = fixture();
    expect(() => repository.create(profile({
      recoveryCost: { targetName: "example" } as never,
    }))).toThrow(/unsupported field/u);
  });
});
