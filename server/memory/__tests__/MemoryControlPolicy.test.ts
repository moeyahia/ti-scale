import { afterEach, describe, expect, test } from "bun:test";
import { join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../MemoryRepository";
import {
  getMemoryControlPolicy,
  updateMemoryControlPolicy,
} from "../MemoryControlPolicy";
import { SecondBrainService } from "../SecondBrainService";

const directories: string[] = [];

afterEach(() => directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true })));

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "memory-control-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "memory.sqlite") });
  migrateDatabase(database);
  return { database, brain: new SecondBrainService(new MemoryRepository(database)) };
}

function update(overrides: Record<string, unknown> = {}) {
  return {
    enabled: true,
    personalPreferencePolicy: "candidate_only",
    operationalMemoryEnabled: true,
    engagementIsolation: true,
    defaultRetentionDays: 365,
    autonomousUse: true,
    guidedUse: true,
    obsidianSyncScope: "confirmed_and_verified",
    secretsNeverRetained: true,
    ...overrides,
  };
}

describe("Memory Control Center policy", () => {
  test("persists optimistic versions and a tamper-evident audit without weakening invariants", () => {
    const { database } = setup();
    try {
      expect(getMemoryControlPolicy(database)).toMatchObject({ version: 0, enabled: true, engagementIsolation: true });
      const stored = updateMemoryControlPolicy({
        database,
        expectedVersion: 0,
        actor: "operator-control-test",
        policy: update({ guidedUse: false, defaultRetentionDays: 90 }),
        now: "2026-07-15T12:00:00.000Z",
      });
      expect(stored).toMatchObject({ version: 1, guidedUse: false, defaultRetentionDays: 90 });
      expect(database.prepare("SELECT action, details_json, record_hash FROM audit_records").get()).toMatchObject({
        action: "memory.control.updated",
        record_hash: expect.stringMatching(/^[a-f0-9]{64}$/),
      });
      expect(() => updateMemoryControlPolicy({ database, expectedVersion: 0, actor: "operator", policy: update() }))
        .toThrow(/version does not match/i);
      expect(() => updateMemoryControlPolicy({ database, expectedVersion: 1, actor: "operator", policy: update({ engagementIsolation: false }) }))
        .toThrow(/mandatory safety invariant/i);
      expect(() => updateMemoryControlPolicy({ database, expectedVersion: 1, actor: "operator", policy: update({ secretsNeverRetained: false }) }))
        .toThrow(/mandatory safety invariant/i);
    } finally {
      database.close();
    }
  });

  test("immediately enforces journey use and retention controls", () => {
    const { database, brain } = setup();
    try {
      brain.createOperationalMemory({
        id: "mem-control-technique",
        nodeType: "technique",
        title: "Bounded service discovery",
        summary: "Evidence-backed service discovery technique",
        scope: { kind: "engagement", engagementId: "eng-control" },
        sensitivity: "private",
        confidence: 0.9,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: { method: "evidence", explanation: "Verified in a controlled mission", sources: [{ sourceType: "evidence", sourceId: "evidence-control-1", acquiredAt: "2026-07-15T10:00:00.000Z" }] },
        authorType: "system",
      });
      expect(brain.retrieve("service discovery", {
        engagementId: "eng-control", journey: "guided", maximumSensitivity: "private", contextBudget: 1_000,
      })).toHaveLength(1);

      updateMemoryControlPolicy({
        database,
        expectedVersion: 0,
        actor: "operator",
        policy: update({ guidedUse: false, operationalMemoryEnabled: false, personalPreferencePolicy: "disabled" }),
      });
      expect(brain.retrieve("service discovery", {
        engagementId: "eng-control", journey: "guided", maximumSensitivity: "private", contextBudget: 1_000,
      })).toEqual([]);
      expect(brain.retrieve("service discovery", {
        engagementId: "eng-control", journey: "autonomous", maximumSensitivity: "private", contextBudget: 1_000,
      })).toEqual([]);
      expect(() => brain.proposeMemory({
        nodeType: "preference",
        title: "Use concise explanations",
        summary: "Reviewable operator preference",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.8,
        provenance: { method: "operator_statement", explanation: "Requested by operator", sources: [{ sourceType: "message", sourceId: "message-control-1", acquiredAt: "2026-07-15T10:00:00.000Z" }] },
        proposedBy: "operator",
      })).toThrow(/preference learning is disabled/i);
      expect(() => brain.createOperationalMemory({
        nodeType: "technique",
        title: "Another technique",
        summary: "Should not be retained",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.8,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: { method: "evidence", explanation: "test", sources: [{ sourceType: "evidence", sourceId: "evidence-control-2", acquiredAt: "2026-07-15T10:00:00.000Z" }] },
        authorType: "system",
      })).toThrow(/retention is disabled/i);
    } finally {
      database.close();
    }
  });
});
