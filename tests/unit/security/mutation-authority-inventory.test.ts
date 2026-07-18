import { describe, expect, test } from "bun:test";
import {
  assertMutationAuthorityInventory,
  auditMutationAuthorityInventory,
  mutationAuthorityKey,
  V2_MUTATION_AUTHORITY_INVENTORY,
  type MutationAuthorityRecord,
  type MutationRouteDeclaration,
} from "../../../server/security/MutationAuthorityInventory";
import { discoverV2MutationRoutes } from "../../../scripts/lib/discoverV2MutationRoutes";
import {
  TI_SCALE_DEFERRED_ENDPOINTS,
  TI_SCALE_ENDPOINTS,
} from "../../../server/contracts/v2Contract";

describe("V2 mutation-authority inventory", () => {
  test("classifies every source-declared mutation and every intentional alternative implementation", () => {
    const discovery = discoverV2MutationRoutes();
    expect(discovery.unresolved).toEqual([]);

    const report = auditMutationAuthorityInventory(discovery.routes);
    expect(() => assertMutationAuthorityInventory(report)).not.toThrow();
    expect(report).toMatchObject({
      inventoryCount: 77,
      declarationCount: 89,
      duplicateInventoryKeys: [],
      unclassifiedDeclarations: [],
      staleInventoryRecords: [],
      implementationSourceMismatches: [],
    });
    expect(report.approvedDuplicateDeclarations).toHaveLength(12);
    expect(report.policyScopedGaps).toEqual([]);
    const byKey = new Map(V2_MUTATION_AUTHORITY_INVENTORY.map((record) => [
      mutationAuthorityKey(record),
      record.controlPlaneEnforcement,
    ]));
    expect(byKey.get("POST /api/v2/runs/:runId/intelligence/metrics/recompute")).toBe("ownership_fenced");
    for (const key of [
      "POST /api/v2/runs/:runId/intelligence/attack-attempts",
      "POST /api/v2/runs/:runId/intelligence/attack-attempts/:attemptId/transition",
      "POST /api/v2/runs/:runId/plan-changes",
      "PUT /api/v2/runs/:runId/plan-changes/:requestId",
      "POST /api/v2/runs/:runId/plan-changes/:requestId/apply",
      "POST /api/v2/runs/:runId/plan-changes/:requestId/reject",
      "POST /api/v2/guided/:missionId/commander/explain-more",
      "POST /api/v2/guided/:missionId/commander/show-next-step",
      "POST /api/v2/guided/:missionId/commander/interpret-result",
      "POST /api/v2/guided/:missionId/commander/use-another-approach",
      "POST /api/v2/guided/:missionId/commander/remember",
      "POST /api/v2/guided/:missionId/commander/do-not-remember",
      "POST /api/v2/missions/:missionId/autonomous-branches/preflight",
      "POST /api/v2/missions/:missionId/autonomous-branches",
      "POST /api/v2/missions/bulk/archive",
      "POST /api/v2/operations/runs/:runId/follow-up",
      "POST /api/v2/operational-truth/missions/:missionId/logs",
      "POST /api/v2/operational-truth/missions/:missionId/observations",
      "POST /api/v2/operational-truth/missions/:missionId/evidence-candidates",
      "POST /api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId/promote",
      "POST /api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId/reject",
      "POST /api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId/demote",
      "POST /api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId/verify",
      "POST /api/v2/operational-truth/missions/:missionId/findings/:findingId/verify",
      "POST /api/v2/operational-truth/missions/:missionId/runs/:runId/failure-diagnoses",
      "POST /api/v2/operational-truth/missions/:missionId/runs/:runId/failure-diagnoses/:diagnosisId/resolve",
    ]) expect(byKey.get(key), key).toBe("lease_fenced");
  });

  test("requires complete authority, authentication, request-integrity, and service ownership metadata", () => {
    const keys = new Set<string>();
    for (const record of V2_MUTATION_AUTHORITY_INVENTORY) {
      const key = mutationAuthorityKey(record);
      expect(keys.has(key), key).toBe(false);
      keys.add(key);
      expect(record.path.startsWith("/api/v2/"), key).toBe(true);
      expect(record.path.endsWith("/"), key).toBe(false);
      expect(record.owningService.trim().length, key).toBeGreaterThan(0);
      expect(record.implementationSources.length, key).toBeGreaterThan(0);
      expect(new Set(record.implementationSources).size, key).toBe(record.implementationSources.length);

      if (record.authorityClass === "public_or_health") {
        expect(record.path, key).toBe("/api/v2/auth/session");
        expect(record.controlPlaneEnforcement, key).toBe("not_applicable");
      } else {
        expect(record.authentication, key).toBe("operator_session_or_bearer_required");
        expect(record.csrf, key).toBe("cookie_session_required");
      }
      if (record.authorityClass === "mission_run_control_plane") {
        expect(record.controlPlaneEnforcement, key).not.toBe("not_applicable");
      } else {
        expect(record.controlPlaneEnforcement, key).toBe("not_applicable");
      }
    }
  });

  test("permits non-idempotent declarations only for the bounded read-like and session lifecycle allowlist", () => {
    const exceptions = V2_MUTATION_AUTHORITY_INVENTORY
      .filter((record) => record.idempotency !== "required")
      .map(mutationAuthorityKey)
      .sort();
    expect(exceptions).toEqual([
      "DELETE /api/v2/auth/session",
      "POST /api/v2/auth/session",
      "POST /api/v2/missions/autonomous/preflight",
      "POST /api/v2/registries/intake/resolve",
    ]);
  });

  test("matches the complete live and deferred API mutation contracts", () => {
    const contractMutations = [...TI_SCALE_ENDPOINTS, ...TI_SCALE_DEFERRED_ENDPOINTS]
      .filter((endpoint) => endpoint.method !== "get");
    const contractByKey = new Map(contractMutations.map((endpoint) => [
      `${endpoint.method.toUpperCase()} ${endpoint.path}`,
      endpoint,
    ]));
    const inventoryByKey = new Map(V2_MUTATION_AUTHORITY_INVENTORY.map((record) => [
      mutationAuthorityKey(record),
      record,
    ]));
    expect([...contractByKey.keys()].sort()).toEqual([...inventoryByKey.keys()].sort());
    for (const [key, endpoint] of contractByKey) {
      expect(inventoryByKey.get(key)?.idempotency === "required", key)
        .toBe(endpoint.idempotencyRequired);
    }
  });

  test("fails closed for an unclassified route, stale record, duplicate key, or source mismatch", () => {
    const base = V2_MUTATION_AUTHORITY_INVENTORY[0]!;
    const declaration: MutationRouteDeclaration = {
      method: base.method,
      path: base.path,
      source: base.implementationSources[0]!,
    };
    const mutation: MutationRouteDeclaration = {
      method: "PATCH",
      path: "/api/v2/new-unclassified-mutation",
      source: "server/new/Router.ts",
    };
    const duplicate: MutationAuthorityRecord = { ...base };
    const stale: MutationAuthorityRecord = {
      ...base,
      method: "PATCH",
      path: "/api/v2/stale-inventory-record",
    };
    const report = auditMutationAuthorityInventory(
      [declaration, mutation],
      [base, duplicate, stale],
    );
    expect(report.duplicateInventoryKeys).toEqual([mutationAuthorityKey(base)]);
    expect(report.unclassifiedDeclarations).toEqual([mutationAuthorityKey(mutation)]);
    expect(report.staleInventoryRecords).toEqual([mutationAuthorityKey(stale)]);
    expect(() => assertMutationAuthorityInventory(report)).toThrow("unclassified mutation");

    const mismatched = auditMutationAuthorityInventory(
      [{ ...declaration, source: "server/wrong/Router.ts" }],
      [base],
    );
    expect(mismatched.implementationSourceMismatches).toHaveLength(1);
    expect(() => assertMutationAuthorityInventory(mismatched)).toThrow("implementation mismatch");

    const repeated = auditMutationAuthorityInventory([declaration, declaration], [base]);
    expect(repeated.implementationSourceMismatches).toEqual([
      `${mutationAuthorityKey(base)}: repeated declaration source=[${declaration.source} (2)]`,
    ]);
    expect(() => assertMutationAuthorityInventory(repeated)).toThrow("repeated declaration source");
  });
});
