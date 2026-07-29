import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../../server/db";
import { ResearchLabRepository } from "../../../server/research";
import {
  parseResearchCampaignMutation,
  parseResearchLab,
  parseResearchPromotionMutation,
} from "../../../src/domain/schemas/research";

describe("Research Lab client boundary", () => {
  test("parses the exact server snapshot and campaign mutation without trusting optional fields", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    try {
      const repository = new ResearchLabRepository(database, undefined, () => new Date("2026-07-16T15:00:00.000Z"));
      const snapshot = parseResearchLab(repository.snapshot());
      expect(snapshot.readiness.status).toBe("blocked");
      expect(snapshot.catalog).toHaveLength(3);
      const created = repository.createCampaign({
        catalogId: "specialist_routing_quality",
        ownerAcknowledged: true,
        actorId: "operator",
        idempotencyKey: "frontend-research-create-1",
      });
      expect(parseResearchCampaignMutation(created).campaign).toMatchObject({
        catalogId: "specialist_routing_quality",
        status: "draft",
        dimensionCount: 3,
      });
    } finally {
      database.close();
    }
  });

  test("rejects any server response that weakens the public-model boundary or skips promotion stages", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    try {
      const snapshot = new ResearchLabRepository(database).snapshot();
      expect(() => parseResearchLab({
        ...snapshot,
        publicLlmBoundary: { ...snapshot.publicLlmBoundary, directToolExecutionAllowed: true },
      })).toThrow("public LLM research boundary is unsafe");
      expect(() => parseResearchLab({
        ...snapshot,
        promotionPath: ["development", "verified"],
      })).toThrow("research promotion path is invalid");
    } finally {
      database.close();
    }
  });

  test("parses only typed human promotion actions and immutable transition bindings", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    try {
      const snapshot = new ResearchLabRepository(database).snapshot();
      const lifecycle = {
        experimentId: "experiment-client-boundary",
        campaignId: "campaign-client-boundary",
        strategyVersionId: "strategy-client-boundary",
        state: "benchmarked",
        stage: "human_review",
        milestones: {
          developmentPassed: true,
          validationPassed: true,
          hiddenHoldoutPassed: true,
          humanReviewApproved: false,
          shadowPassed: false,
          canaryPassed: false,
        },
        version: 6,
        updatedAt: "2026-07-24T12:00:00.000Z",
        latestIntegrityReceiptId: "integrity-client-boundary",
        availableHumanActions: [
          "approve_human_review",
          "reject_human_review",
        ],
        rollbackTargets: [],
        transitions: [
          {
            id: "transition-policy",
            sequence: 1,
            version: 2,
            fromState: "proposed",
            toState: "queued",
            action: "policy_accept",
            actorKind: "local_policy",
            actorId: "local-policy",
            rationale: "The typed strategy patch stays inside the charter.",
            evidenceRefs: ["policy-receipt"],
            hardGateFailures: [],
            exposureReceiptIds: [],
            createdAt: "2026-07-24T08:00:00.000Z",
          },
          {
            id: "transition-start",
            sequence: 2,
            version: 3,
            fromState: "queued",
            toState: "running",
            action: "start_benchmark",
            actorKind: "local_evaluator",
            actorId: "local-evaluator",
            rationale: "The disposable benchmark lab passed readiness.",
            evidenceRefs: ["lab-readiness-receipt"],
            hardGateFailures: [],
            exposureReceiptIds: [],
            createdAt: "2026-07-24T09:00:00.000Z",
          },
          {
            id: "transition-development",
            sequence: 3,
            version: 4,
            fromState: "running",
            toState: "running",
            action: "development_pass",
            actorKind: "local_evaluator",
            actorId: "local-evaluator",
            rationale: "Development scenarios passed the fixed evaluator.",
            evidenceRefs: ["integrity-development"],
            hardGateFailures: [],
            integrityReceiptId: "integrity-development",
            exposureReceiptIds: ["exposure-development"],
            createdAt: "2026-07-24T10:00:00.000Z",
          },
          {
            id: "transition-validation",
            sequence: 4,
            version: 5,
            fromState: "running",
            toState: "benchmarked",
            action: "validation_pass",
            actorKind: "local_evaluator",
            actorId: "local-evaluator",
            rationale: "Validation scenarios passed without regression.",
            evidenceRefs: ["integrity-validation"],
            hardGateFailures: [],
            integrityReceiptId: "integrity-validation",
            exposureReceiptIds: ["exposure-validation"],
            createdAt: "2026-07-24T11:00:00.000Z",
          },
          {
            id: "transition-client-boundary",
            sequence: 5,
            version: 6,
            fromState: "benchmarked",
            toState: "benchmarked",
            action: "hidden_holdout_pass",
            actorKind: "local_evaluator",
            actorId: "local-evaluator",
            rationale: "Hidden holdout passed every hard gate.",
            evidenceRefs: ["integrity-client-boundary"],
            hardGateFailures: [],
            integrityReceiptId: "integrity-client-boundary",
            exposureReceiptIds: ["exposure-client-boundary"],
            createdAt: "2026-07-24T12:00:00.000Z",
          },
        ],
      };
      expect(parseResearchLab({
        ...snapshot,
        promotions: [lifecycle],
      }).promotions[0]).toMatchObject({
        stage: "human_review",
        availableHumanActions: [
          "approve_human_review",
          "reject_human_review",
        ],
      });
      expect(parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle,
      }).lifecycle.version).toBe(6);
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...lifecycle,
          transitions: lifecycle.transitions.map((transition, index) =>
            index === 0
              ? { ...transition, decisionFingerprint: "a".repeat(64) }
              : transition),
        },
      })).toThrow(
        "local promotion transitions cannot carry a human decision fingerprint",
      );
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...lifecycle,
          availableHumanActions: ["auto_deploy_production"],
        },
      })).toThrow("available human promotion action is invalid");
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...lifecycle,
          transitions: lifecycle.transitions.map((transition, index) =>
            index === lifecycle.transitions.length - 1
              ? { ...transition, action: "model_claimed_success" }
              : transition),
        },
      })).toThrow("promotion transition action is invalid");
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...lifecycle,
          transitions: lifecycle.transitions.map((transition, index) =>
            index === lifecycle.transitions.length - 1
              ? { ...transition, hardGateFailures: ["unknown_gate"] }
              : transition),
        },
      })).toThrow("promotion hard-gate failures are invalid");
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...lifecycle,
          transitions: lifecycle.transitions.map((transition, index) =>
            index === 0 ? { ...transition, sequence: 0 } : transition),
        },
      })).toThrow("promotion sequence must be a positive integer");
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...lifecycle,
          milestones: { ...lifecycle.milestones, shadowPassed: true },
        },
      })).toThrow("promotion milestone shadowPassed does not match transition history");
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: { ...lifecycle, stage: "development" },
      })).toThrow("research promotion stage does not match lifecycle state");
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...lifecycle,
          transitions: lifecycle.transitions.map((transition, index) =>
            index === lifecycle.transitions.length - 1
              ? {
                  ...transition,
                  hardGateFailures: ["budget_overrun"],
                }
              : transition),
        },
      })).toThrow(
        "passing promotion transitions cannot contain hard-gate failures",
      );
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...lifecycle,
          transitions: lifecycle.transitions.map((transition, index) =>
            index === lifecycle.transitions.length - 1
              ? {
                  ...transition,
                  integrityReceiptId: undefined,
                }
              : transition),
        },
      })).toThrow(
        "promotion transition is missing its required integrity receipt",
      );

      const shadowPassedLifecycle = {
        ...lifecycle,
        state: "shadow_running",
        stage: "shadow",
        milestones: {
          ...lifecycle.milestones,
          humanReviewApproved: true,
          shadowPassed: true,
        },
        version: 9,
        updatedAt: "2026-07-24T15:00:00.000Z",
        latestIntegrityReceiptId: "integrity-shadow",
        availableHumanActions: ["approve_canary", "reject"],
        transitions: [
          ...lifecycle.transitions,
          {
            id: "transition-human-review",
            sequence: 6,
            version: 7,
            fromState: "benchmarked",
            toState: "shadow_ready",
            action: "approve_human_review",
            actorKind: "human_reviewer",
            actorId: "operator",
            rationale: "The signed holdout is suitable for shadow evaluation.",
            evidenceRefs: ["integrity-client-boundary"],
            hardGateFailures: [],
            integrityReceiptId: "integrity-client-boundary",
            exposureReceiptIds: [],
            createdAt: "2026-07-24T13:00:00.000Z",
          },
          {
            id: "transition-shadow-start",
            sequence: 7,
            version: 8,
            fromState: "shadow_ready",
            toState: "shadow_running",
            action: "start_shadow",
            actorKind: "human_reviewer",
            actorId: "operator",
            rationale: "Start non-influencing shadow evaluation.",
            evidenceRefs: ["integrity-client-boundary"],
            hardGateFailures: [],
            integrityReceiptId: "integrity-client-boundary",
            exposureReceiptIds: [],
            deploymentId: "deployment-shadow",
            createdAt: "2026-07-24T14:00:00.000Z",
          },
          {
            id: "transition-shadow-pass",
            sequence: 8,
            version: 9,
            fromState: "shadow_running",
            toState: "shadow_running",
            action: "shadow_pass",
            actorKind: "local_evaluator",
            actorId: "local-evaluator",
            rationale: "Shadow comparison passed without influencing missions.",
            evidenceRefs: ["integrity-shadow"],
            hardGateFailures: [],
            integrityReceiptId: "integrity-shadow",
            exposureReceiptIds: [],
            createdAt: "2026-07-24T15:00:00.000Z",
          },
        ],
      };
      const fingerprintedShadowLifecycle = {
        ...shadowPassedLifecycle,
        transitions: shadowPassedLifecycle.transitions.map((transition) =>
          transition.action === "approve_human_review"
            ? { ...transition, decisionFingerprint: "d".repeat(64) }
            : transition),
      };
      expect(parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: fingerprintedShadowLifecycle,
      }).lifecycle.transitions.find(
        ({ action }) => action === "approve_human_review",
      )?.decisionFingerprint).toBe("d".repeat(64));
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...shadowPassedLifecycle,
          transitions: shadowPassedLifecycle.transitions.map((transition) =>
            transition.action === "approve_human_review"
              ? { ...transition, decisionFingerprint: "not-a-sha256" }
              : transition),
        },
      })).toThrow("promotion decision fingerprint is invalid");
      expect(parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: shadowPassedLifecycle,
      }).lifecycle.availableHumanActions).toEqual([
        "approve_canary",
        "reject",
      ]);
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...shadowPassedLifecycle,
          availableHumanActions: [
            "approve_canary",
            "reject",
            "rollback",
          ],
        },
      })).toThrow(
        "available human promotion actions do not match lifecycle state",
      );
      expect(() => parseResearchPromotionMutation({
        schemaVersion: "2.4",
        lifecycle: {
          ...shadowPassedLifecycle,
          transitions: shadowPassedLifecycle.transitions.map(
            (transition) =>
              transition.action === "start_shadow"
                ? { ...transition, deploymentId: undefined }
                : transition,
          ),
        },
      })).toThrow(
        "promotion transition is missing its required deployment binding",
      );
    } finally {
      database.close();
    }
  });
});
