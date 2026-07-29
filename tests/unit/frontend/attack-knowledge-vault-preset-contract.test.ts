/// <reference lib="dom" />

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  activateAttackKnowledgeVaultPreset,
  amendAttackKnowledgeVaultPreset,
  fetchAttackKnowledgeVaultPreset,
} from "../../../src/data/api/brain";
import { parseAttackKnowledgeVaultPresetPreview } from "../../../src/domain/schemas/brain";

let originalFetch: typeof globalThis.fetch;
let originalDocument: PropertyDescriptor | undefined;
let requests: Array<{ path: string; init?: RequestInit }>;

const preset = {
  id: "ti_scale_attack_knowledge_v1",
  displayName: "Ti-Scale Attack Knowledge Vault",
  vaultPath: "Attack-Knowledge-Vault",
  policyHash: "a".repeat(64),
  activationRequired: true,
  operatorProfileAvailability: {
    requested: false,
    available: false,
    status: "no_eligible_confirmed_profile",
    eligibleNodeCount: 0,
  },
  projection: {
    nodeTypes: ["technology_product", "attack_vector", "attack_procedure", "script_artifact", "failure_mode", "recovery_pattern"],
    scopeKinds: ["global"],
    lifecycleStatuses: ["verified"],
    sensitivities: ["public", "internal", "private"],
    folders: ["20 Technology Products", "41 Attack Vectors", "42 Techniques and Procedures", "45 Scripts and Tools", "51 Operational Hazards", "52 Recovery and Alternatives"],
    policyEligibleNodeCount: 17,
    excludedOperationalNodeCount: 42,
    confirmedKnowledgeIsOptIn: false,
    operatorProfileIncluded: false,
    operatorProfileNodeCount: 0,
  },
  privacyBoundary: {
    excludesNodeTypes: [
      "mission", "run", "plan", "phase", "step", "target", "asset", "entity",
      "decision", "evidence", "finding", "artifact", "report", "source",
    ],
    excludesOperationalLocators: ["IP addresses and CIDRs", "engagement and mission names"],
    restrictedSensitivityWithheld: true,
  },
} as const;

beforeEach(() => {
  originalFetch = globalThis.fetch;
  originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  requests = [];
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { cookie: "ti_scale_csrf=attack-vault-csrf" },
  });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const path = typeof input === "string" ? input : input.toString();
    requests.push({ path, init });
    const payload = path.includes("/amend")
      ? {
          schemaVersion: "2.4",
          connection: {
            id: "vault-attack-knowledge",
            vaultPath: preset.vaultPath,
            displayName: preset.displayName,
            status: "connected",
            syncScope: {
              nodeTypes: preset.projection.nodeTypes,
              scopeKinds: ["global"],
              lifecycleStatuses: ["verified", "confirmed"],
              sensitivities: ["public", "internal", "private"],
            },
            permissionGrantedAt: "2026-07-20T18:00:00.000Z",
            createdAt: "2026-07-20T18:00:00.000Z",
            updatedAt: "2026-07-20T18:05:00.000Z",
          },
          result: {
            previousPolicyHash: "a".repeat(64),
            targetPolicyHash: "b".repeat(64),
            eligibleNodeCountBefore: 17,
            eligibleNodeCountAfter: 23,
            eligibleNodeDelta: 6,
            amendedAt: "2026-07-20T18:05:00.000Z",
            auditRecordId: "audit-vault-amend",
            filesystemHealth: {
              checkedAt: "2026-07-20T18:04:59.000Z",
              checks: { write: true, read: true, rename: true, delete: true },
            },
            connectionIdChanged: false,
            vaultPathChanged: false,
            filesDeleted: 0,
            notesWritten: 0,
          },
          preset: {
            ...preset,
            policyHash: "b".repeat(64),
            alreadyActiveConnectionId: "vault-attack-knowledge",
            activePreset: {
              connectionId: "vault-attack-knowledge",
              updatedAt: "2026-07-20T18:05:00.000Z",
              includeConfirmed: true,
              includeOperatorProfile: false,
              policyHash: "b".repeat(64),
            },
            projection: {
              ...preset.projection,
              lifecycleStatuses: ["verified", "confirmed"],
              policyEligibleNodeCount: 23,
              confirmedKnowledgeIsOptIn: true,
            },
          },
        }
      : path.includes("/activate")
      ? {
          schemaVersion: "2.4",
          connection: {
            id: "vault-attack-knowledge",
            vaultPath: preset.vaultPath,
            displayName: preset.displayName,
            status: "connected",
            syncScope: {
              nodeTypes: preset.projection.nodeTypes,
              scopeKinds: ["global"],
              lifecycleStatuses: ["verified"],
              sensitivities: ["public", "internal", "private"],
            },
            permissionGrantedAt: "2026-07-20T18:00:00.000Z",
            createdAt: "2026-07-20T18:00:00.000Z",
            updatedAt: "2026-07-20T18:00:00.000Z",
          },
        }
      : { schemaVersion: "2.4", enabled: true, preset };
    return new Response(JSON.stringify(payload), {
      status: path.includes("/activate") ? 201 : 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
  else Reflect.deleteProperty(globalThis, "document");
});

describe("Attack Knowledge Vault browser contract", () => {
  test("previews first and sends the exact reviewed activation proof", async () => {
    const preview = await fetchAttackKnowledgeVaultPreset(false, new AbortController().signal);
    expect(preview).toMatchObject({
      enabled: true,
      vaultPath: "Attack-Knowledge-Vault",
      activationRequired: true,
      projection: { scopeKinds: ["global"], lifecycleStatuses: ["verified"] },
      privacyBoundary: { restrictedSensitivityWithheld: true },
    });
    await activateAttackKnowledgeVaultPreset({
      expectedPolicyHash: preview.policyHash,
      includeConfirmed: false,
      permissionGranted: true,
      activationAcknowledged: true,
    });
    expect(requests.map((request) => request.path)).toEqual([
      "/api/v2/brain/vault/attack-knowledge-preset?includeConfirmed=false&includeOperatorProfile=false",
      "/api/v2/brain/vault/attack-knowledge-preset/activate",
    ]);
    expect(JSON.parse(String(requests[1]!.init?.body))).toEqual({
      expectedPolicyHash: "a".repeat(64),
      includeConfirmed: false,
      permissionGranted: true,
      activationAcknowledged: true,
    });
    const headers = new Headers(requests[1]!.init?.headers);
    expect(headers.get("Idempotency-Key")).toBeTruthy();
    expect(headers.get("X-Ti-Scale-CSRF")).toBe("attack-vault-csrf");
  });

  test("sends an optimistic same-connection confirmed-scope amendment receipt", async () => {
    const result = await amendAttackKnowledgeVaultPreset({
      connectionId: "vault-attack-knowledge",
      expectedUpdatedAt: "2026-07-20T18:00:00.000Z",
      expectedCurrentPolicyHash: "a".repeat(64),
      expectedTargetPolicyHash: "b".repeat(64),
      includeConfirmed: true,
      permissionGranted: true,
      amendmentAcknowledged: true,
      reason: "Include reviewed confirmed reusable attack knowledge in this exact Vault",
    });
    expect(result.connection.id).toBe("vault-attack-knowledge");
    expect(result.result).toMatchObject({
      eligibleNodeDelta: 6,
      connectionIdChanged: false,
      vaultPathChanged: false,
      filesDeleted: 0,
      notesWritten: 0,
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]!.path).toBe("/api/v2/brain/vault/attack-knowledge-preset/amend");
    expect(JSON.parse(String(requests[0]!.init?.body))).toMatchObject({
      connectionId: "vault-attack-knowledge",
      expectedCurrentPolicyHash: "a".repeat(64),
      expectedTargetPolicyHash: "b".repeat(64),
      includeConfirmed: true,
      permissionGranted: true,
      amendmentAcknowledged: true,
    });
  });

  test("previews and submits the separately consented Operator Preferences and Profile scope", async () => {
    const profilePreview = parseAttackKnowledgeVaultPresetPreview({
      schemaVersion: "2.4",
      enabled: true,
      preset: {
        ...preset,
        policyHash: "c".repeat(64),
        alreadyActiveConnectionId: "vault-attack-knowledge",
        activePreset: {
          connectionId: "vault-attack-knowledge",
          updatedAt: "2026-07-20T18:05:00.000Z",
          includeConfirmed: true,
          includeOperatorProfile: false,
          policyHash: "b".repeat(64),
        },
        operatorProfileScopeUpgrade: {
          connectionId: "vault-attack-knowledge",
          expectedUpdatedAt: "2026-07-20T18:05:00.000Z",
          currentPolicyHash: "b".repeat(64),
          targetPolicyHash: "c".repeat(64),
          eligibleNodeCountBefore: 23,
          eligibleNodeCountAfter: 26,
          eligibleNodeDelta: 3,
          operatorProfileNodeCount: 3,
        },
        operatorProfileAvailability: {
          requested: true,
          available: true,
          status: "available",
          eligibleNodeCount: 3,
        },
        projection: {
          ...preset.projection,
          nodeTypes: [...preset.projection.nodeTypes, "operator", "preference", "entity"],
          lifecycleStatuses: ["verified", "confirmed"],
          folders: [...preset.projection.folders, "10 Operator"],
          policyEligibleNodeCount: 26,
          confirmedKnowledgeIsOptIn: true,
          operatorProfileIncluded: true,
          operatorProfileNodeCount: 3,
        },
      },
    });
    expect(profilePreview).toMatchObject({
      projection: {
        operatorProfileIncluded: true,
        operatorProfileNodeCount: 3,
        folders: expect.arrayContaining(["10 Operator"]),
      },
      operatorProfileScopeUpgrade: {
        eligibleNodeDelta: 3,
        operatorProfileNodeCount: 3,
      },
    });

    await amendAttackKnowledgeVaultPreset({
      connectionId: "vault-attack-knowledge",
      expectedUpdatedAt: "2026-07-20T18:05:00.000Z",
      expectedCurrentPolicyHash: "b".repeat(64),
      expectedTargetPolicyHash: "c".repeat(64),
      includeConfirmed: true,
      includeOperatorProfile: true,
      permissionGranted: true,
      operatorProfileAcknowledged: true,
      reason: "Include my explicit confirmed Operator Preferences and Profile",
    });
    expect(JSON.parse(String(requests[0]!.init?.body))).toMatchObject({
      includeConfirmed: true,
      includeOperatorProfile: true,
      operatorProfileAcknowledged: true,
    });
  });

  test("rejects Operator Profile projection without confirmed consent or with target data", () => {
    const response = (nodeTypes: readonly string[], lifecycleStatuses: readonly string[]) => ({
      schemaVersion: "2.4",
      enabled: true,
      preset: {
        ...preset,
        projection: {
          ...preset.projection,
          nodeTypes,
          lifecycleStatuses,
          confirmedKnowledgeIsOptIn: lifecycleStatuses.includes("confirmed"),
          operatorProfileIncluded: true,
          operatorProfileNodeCount: 1,
        },
      },
    });
    expect(() => parseAttackKnowledgeVaultPresetPreview(response(
      [...preset.projection.nodeTypes, "operator", "preference", "entity"],
      ["verified"],
    ))).toThrow("Operator Profile Vault projection boundary");
    expect(() => parseAttackKnowledgeVaultPresetPreview(response(
      [...preset.projection.nodeTypes, "operator", "preference", "entity", "target"],
      ["verified", "confirmed"],
    ))).toThrow("operational node types");
  });

  test("keeps an empty Operator Profile request schema-valid and explicitly unavailable", () => {
    const preview = parseAttackKnowledgeVaultPresetPreview({
      schemaVersion: "2.4",
      enabled: true,
      preset: {
        ...preset,
        policyHash: "b".repeat(64),
        activePreset: {
          connectionId: "vault-attack-knowledge",
          updatedAt: "2026-07-20T18:05:00.000Z",
          includeConfirmed: true,
          includeOperatorProfile: false,
          policyHash: "b".repeat(64),
        },
        operatorProfileAvailability: {
          requested: true,
          available: false,
          status: "no_eligible_confirmed_profile",
          eligibleNodeCount: 0,
        },
        projection: {
          ...preset.projection,
          lifecycleStatuses: ["verified", "confirmed"],
          confirmedKnowledgeIsOptIn: true,
          operatorProfileIncluded: false,
          operatorProfileNodeCount: 0,
        },
      },
    });
    expect(preview.operatorProfileAvailability).toEqual({
      requested: true,
      available: false,
      status: "no_eligible_confirmed_profile",
      eligibleNodeCount: 0,
    });
    expect(preview.projection.operatorProfileIncluded).toBe(false);
    expect(preview.projection.nodeTypes).not.toContain("preference");
  });

  test("accepts the original 2.4 projection-only availability shape without broadening its requested policy", () => {
    const { operatorProfileAvailability: _removedAvailability, ...legacyPreset } = preset;
    const attackOnly = parseAttackKnowledgeVaultPresetPreview({
      schemaVersion: "2.4",
      enabled: true,
      preset: legacyPreset,
    });
    expect(attackOnly.operatorProfileAvailability).toEqual({
      requested: false,
      available: false,
      status: "no_eligible_confirmed_profile",
      eligibleNodeCount: 0,
    });

    const requestedProfile = parseAttackKnowledgeVaultPresetPreview({
      schemaVersion: "2.4",
      enabled: true,
      preset: {
        ...legacyPreset,
        policyHash: "c".repeat(64),
        projection: {
          ...legacyPreset.projection,
          nodeTypes: [...legacyPreset.projection.nodeTypes, "operator", "preference", "entity"],
          lifecycleStatuses: ["verified", "confirmed"],
          folders: [...legacyPreset.projection.folders, "10 Operator"],
          policyEligibleNodeCount: 20,
          confirmedKnowledgeIsOptIn: true,
          operatorProfileIncluded: true,
          operatorProfileNodeCount: 3,
        },
      },
    });
    expect(requestedProfile.operatorProfileAvailability).toEqual({
      requested: true,
      available: true,
      status: "available",
      eligibleNodeCount: 3,
    });
  });

  test("rejects a preset response that claims restricted memory is withheld but includes it", () => {
    expect(() => parseAttackKnowledgeVaultPresetPreview({
      schemaVersion: "2.4",
      enabled: true,
      preset: {
        ...preset,
        projection: { ...preset.projection, sensitivities: ["internal", "restricted"] },
      },
    })).toThrow("restricted");
  });

  test("rejects a renamed, re-pathed, stale, or incomplete preset boundary", () => {
    const response = (overrides: Record<string, unknown>) => ({
      schemaVersion: "2.4",
      enabled: true,
      preset: { ...preset, ...overrides },
    });
    expect(() => parseAttackKnowledgeVaultPresetPreview(response({
      displayName: "Broad memory export",
    }))).toThrow("display name");
    expect(() => parseAttackKnowledgeVaultPresetPreview(response({
      vaultPath: "Broad-Memory-Export",
    }))).toThrow("path");
    expect(() => parseAttackKnowledgeVaultPresetPreview(response({
      policyHash: "not-a-policy-hash",
    }))).toThrow("SHA-256");
    expect(() => parseAttackKnowledgeVaultPresetPreview(response({
      privacyBoundary: {
        ...preset.privacyBoundary,
        excludesNodeTypes: ["mission", "run"],
      },
    }))).toThrow("operational node type");
  });

  test("keeps standalone documentation and Vault UI free of external product paths and names", () => {
    const sources = [
      readFileSync(new URL("../../../docs/attack-knowledge-vault.md", import.meta.url), "utf8"),
      readFileSync(new URL("../../../src/features/brain/BrainVaultPage.tsx", import.meta.url), "utf8"),
      readFileSync(new URL("../../../server/vault/AttackKnowledgeVaultPreset.ts", import.meta.url), "utf8"),
    ].join("\n");
    for (const disallowed of [
      "/var/lib/chillspwn",
      "ChillsPwn-Brain",
      "chillspwn-recovery",
    ]) expect(sources.toLocaleLowerCase("en-US")).not.toContain(disallowed.toLocaleLowerCase("en-US"));
  });
});
