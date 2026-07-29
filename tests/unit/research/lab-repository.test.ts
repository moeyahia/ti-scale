import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../../server/db";
import { ResearchLabRepository } from "../../../server/research";

function repository(options: {
  readonly disposableLabReady?: boolean;
  readonly integritySigningKeyReady?: boolean;
  readonly isolatedWorkerReady?: boolean;
} = {}) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  const service = new ResearchLabRepository(
    database,
    () => ({
      disposableLabReady: options.disposableLabReady ?? false,
      integritySigningKeyReady: options.integritySigningKeyReady ?? false,
      isolatedWorkerReady: options.isolatedWorkerReady ?? false,
    }),
    () => new Date("2026-07-16T14:00:00.000Z"),
  );
  return { database, service };
}

describe("ResearchLabRepository", () => {
  test("exposes only the first three bounded strategy campaigns and blocks execution without trusted dependencies", () => {
    const { database, service } = repository({
      disposableLabReady: true,
      integritySigningKeyReady: true,
      isolatedWorkerReady: true,
    });
    try {
      const snapshot = service.snapshot();
      expect(snapshot.catalog.map(({ id }) => id)).toEqual([
        "repeated_no_progress_action_reduction",
        "specialist_routing_quality",
        "memory_retrieval_precision",
      ]);
      expect(snapshot.readiness.status).toBe("blocked");
      expect(snapshot.readiness.checks.filter(({ status }) => status === "fail").map(({ id }) => id)).toEqual([
        "trusted_benchmark_snapshot",
        "approved_research_charter",
      ]);
      expect(snapshot.publicLlmBoundary).toEqual({
        role: "proposal_only",
        rawClientEvidenceAllowed: false,
        directToolExecutionAllowed: false,
        authoritativeScoringAllowed: false,
        automaticPromotionAllowed: false,
      });
      expect(snapshot.promotionPath).toEqual([
        "development", "validation", "hidden_holdout", "human_review", "shadow", "bounded_canary", "verified",
      ]);
      expect(snapshot.experiments).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("requires explicit human ownership before creating a draft campaign", () => {
    const { database, service } = repository();
    try {
      expect(() => service.createCampaign({
        catalogId: "specialist_routing_quality",
        ownerAcknowledged: false,
        actorId: "operator-1",
        idempotencyKey: "research-create-1",
      })).toThrow("Confirm that a human operator owns this campaign");
      expect(database.prepare("SELECT COUNT(*) AS count FROM research_campaigns").get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("creates campaign and dimensions atomically, audits it, and replays one idempotent response", () => {
    const { database, service } = repository();
    try {
      const input = {
        catalogId: "memory_retrieval_precision",
        ownerAcknowledged: true,
        actorId: "operator-1",
        idempotencyKey: "research-create-memory-1",
      } as const;
      const first = service.createCampaign(input);
      const replay = service.createCampaign(input);
      expect(replay).toEqual(first);
      expect(first.campaign).toMatchObject({
        catalogId: "memory_retrieval_precision",
        status: "draft",
        owner: "operator-1",
        dimensionCount: 5,
        experimentCount: 0,
        charterCount: 0,
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM research_campaigns").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM research_dimensions").get()).toEqual({ count: 5 });
      expect(database.prepare("SELECT action FROM audit_records").get()).toEqual({ action: "research_campaign.created" });
      expect(service.snapshot().catalog.find(({ id }) => id === "memory_retrieval_precision")?.existingCampaignIds)
        .toEqual([first.campaign.id]);
      expect(() => service.createCampaign({ ...input, catalogId: "specialist_routing_quality" }))
        .toThrow("already used for a different request");
      expect(() => service.createCampaign({ ...input, idempotencyKey: "research-create-memory-2" }))
        .toThrow("active campaign already exists");
    } finally {
      database.close();
    }
  });

  test("stops a campaign with optimistic concurrency and a content-hashed audit trail", () => {
    const { database, service } = repository();
    try {
      const created = service.createCampaign({
        catalogId: "repeated_no_progress_action_reduction",
        ownerAcknowledged: true,
        actorId: "operator-1",
        idempotencyKey: "research-create-loop-1",
      });
      expect(() => service.stopCampaign({
        campaignId: created.campaign.id,
        expectedUpdatedAt: "2026-07-16T13:59:59.000Z",
        reason: "Campaign configuration changed.",
        actorId: "operator-1",
        idempotencyKey: "research-stop-loop-stale",
      })).toThrow("changed after this view loaded");
      expect(() => service.stopCampaign({
        campaignId: created.campaign.id,
        expectedUpdatedAt: created.campaign.updatedAt,
        reason: "Campaign configuration changed.",
        actorId: "another-operator",
        idempotencyKey: "research-stop-loop-owner",
      })).toThrow("Only the human campaign owner");
      const input = {
        campaignId: created.campaign.id,
        expectedUpdatedAt: created.campaign.updatedAt,
        reason: "Stop before any experiment because the charter is not ready.",
        actorId: "operator-1",
        idempotencyKey: "research-stop-loop-1",
      } as const;
      const stopped = service.stopCampaign(input);
      expect(stopped.campaign.status).toBe("stopped");
      expect(service.stopCampaign(input)).toEqual(stopped);
      const audits = database.prepare("SELECT action, previous_hash, record_hash FROM audit_records ORDER BY rowid").all() as Array<{
        action: string; previous_hash: string | null; record_hash: string;
      }>;
      expect(audits.map(({ action }) => action)).toEqual(["research_campaign.created", "research_campaign.stopped"]);
      expect(audits[1]?.previous_hash).toBe(audits[0]?.record_hash);
      expect(audits[1]?.record_hash.length).toBe(64);
    } finally {
      database.close();
    }
  });
});
