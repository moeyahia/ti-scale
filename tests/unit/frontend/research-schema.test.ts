import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../../server/db";
import { ResearchLabRepository } from "../../../server/research";
import { parseResearchCampaignMutation, parseResearchLab } from "../../../src/domain/schemas/research";

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
});
