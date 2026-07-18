/// <reference lib="dom" />

import { describe, expect, test } from "bun:test";
import type { MemoryControlPolicy } from "../../../src/domain/types/brain";
import { editableMemoryControlPolicy } from "../../../src/features/brain/BrainControlPage";

describe("Brain Control presentation boundary", () => {
  test("projects only editable canonical fields and force-locks both safety invariants", () => {
    const secret = "unit-fixture-secret-that-must-not-project";
    const unsafeRuntimeValue = {
      enabled: true,
      personalPreferencePolicy: "candidate_only",
      operationalMemoryEnabled: true,
      engagementIsolation: false,
      defaultRetentionDays: 365,
      autonomousUse: true,
      guidedUse: true,
      obsidianSyncScope: "confirmed_and_verified",
      secretsNeverRetained: false,
      version: 9,
      updatedBy: "operator-one",
      updatedAt: "2026-07-16T20:00:00.000Z",
      fixtureAuthenticationToken: secret,
    } as unknown as MemoryControlPolicy;

    const editable = editableMemoryControlPolicy(unsafeRuntimeValue);
    expect(editable).toEqual({
      enabled: true,
      personalPreferencePolicy: "candidate_only",
      operationalMemoryEnabled: true,
      engagementIsolation: true,
      defaultRetentionDays: 365,
      autonomousUse: true,
      guidedUse: true,
      obsidianSyncScope: "confirmed_and_verified",
      secretsNeverRetained: true,
    });
    expect(JSON.stringify(editable)).not.toContain(secret);
    expect(editable).not.toHaveProperty("version");
    expect(editable).not.toHaveProperty("updatedBy");
    expect(editable).not.toHaveProperty("updatedAt");
  });
});
