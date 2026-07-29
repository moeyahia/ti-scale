import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  loadProductionPrivateResearchHoldoutConfiguration,
  loadTrustedPrivateResearchHoldoutDescriptor,
  parsePrivateResearchHoldoutDescriptor,
  PrivateResearchHoldoutRegistry,
} from "../../../server/research";

const roots: string[] = [];

function temporaryRoot(): string {
  const root = join(
    tmpdir(),
    `ti-scale-private-holdout-${process.pid}-${crypto.randomUUID()}`,
  );
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  roots.push(root);
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function descriptor(overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "ti-scale.private-research-holdout.v1",
    descriptorVersion: "operator-private-set-1",
    campaigns: [{
      catalogId: "memory_retrieval_precision",
      fixtureKey: "operator-private-fixture-alpha",
      input: {
        schemaVersion: "ti-scale.synthetic-scenario.v1",
        track: "memory_retrieval_precision",
        candidates: [
          {
            memoryId: "private-memory-relevant",
            confidence: 0.94,
            verified: true,
            sameEngagement: true,
          },
          {
            memoryId: "private-memory-decoy",
            confidence: 0.38,
            verified: true,
            sameEngagement: false,
          },
        ],
      },
      groundTruth: {
        relevantMemoryIds: ["private-memory-relevant"],
      },
    }],
    ...overrides,
  };
}

function writeDescriptor(root: string, value: unknown): {
  readonly path: string;
  readonly sha256: string;
} {
  const path = join(root, "private-holdout.json");
  const bytes = `${JSON.stringify(value, null, 2)}\n`;
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
  return {
    path,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

describe("private Research holdout descriptor", () => {
  test("loads a hash-pinned operator file while exposing only commitments", () => {
    const root = temporaryRoot();
    const source = writeDescriptor(root, descriptor());
    const loaded = loadTrustedPrivateResearchHoldoutDescriptor({
      path: source.path,
      trustRoot: root,
      expectedSha256: source.sha256,
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
    });
    const registry = new PrivateResearchHoldoutRegistry(loaded);
    const scenario = registry.scenarioFor({
      catalogId: "memory_retrieval_precision",
      familyId: "family-private-test",
      budgetJson: JSON.stringify({ maxWallClockMs: 30_000 }),
    });
    expect(scenario).toBeDefined();
    expect(scenario?.split).toBe("hidden_holdout");
    expect(Object.values(scenario!.binding).every((value) =>
      /^[a-f0-9]{64}$/u.test(value))).toBe(true);

    const publicProjection = JSON.stringify(scenario);
    expect(publicProjection).not.toContain("operator-private-fixture-alpha");
    expect(publicProjection).not.toContain("private-memory-relevant");
    expect(publicProjection).not.toContain("relevantMemoryIds");

    const fixture = registry.fixtureFor({
      scenarioId: scenario!.id,
      environmentDigest: scenario!.environmentDigest,
    });
    expect(fixture).toBeDefined();
    const localWorkerFixture = fixture!.files["scenario.json"]!;
    expect(localWorkerFixture).toContain("private-memory-relevant");
    expect(localWorkerFixture).not.toContain("operator-private-fixture-alpha");
    expect(localWorkerFixture).not.toContain("groundTruth");
    expect(localWorkerFixture).not.toContain("relevantMemoryIds");
  });

  test("requires a complete production reference and the reviewed source hash", () => {
    const root = temporaryRoot();
    const source = writeDescriptor(root, descriptor());
    expect(loadProductionPrivateResearchHoldoutConfiguration({})).toEqual({
      status: "unconfigured",
      reason:
        "No complete trusted private Research holdout descriptor is configured.",
    });
    expect(() => loadProductionPrivateResearchHoldoutConfiguration({
      TI_SCALE_RESEARCH_HOLDOUT_TRUST_ROOT: root,
      TI_SCALE_RESEARCH_HOLDOUT_DESCRIPTOR_PATH: source.path,
    })).toThrow("incomplete");
    expect(() => loadProductionPrivateResearchHoldoutConfiguration({
      TI_SCALE_RESEARCH_HOLDOUT_TRUST_ROOT: root,
      TI_SCALE_RESEARCH_HOLDOUT_DESCRIPTOR_PATH: source.path,
      TI_SCALE_RESEARCH_HOLDOUT_DESCRIPTOR_SHA256: "0".repeat(64),
    })).toThrow("reviewed SHA-256");
    const configured = loadProductionPrivateResearchHoldoutConfiguration({
      TI_SCALE_RESEARCH_HOLDOUT_TRUST_ROOT: root,
      TI_SCALE_RESEARCH_HOLDOUT_DESCRIPTOR_PATH: source.path,
      TI_SCALE_RESEARCH_HOLDOUT_DESCRIPTOR_SHA256: source.sha256,
    });
    expect(configured.status).toBe("loaded");
  });

  test("rejects target identifiers and secret-bearing content before registry creation", () => {
    const withTarget = descriptor();
    const targetCampaign = structuredClone(
      (withTarget.campaigns as Array<Record<string, unknown>>)[0]!,
    );
    const targetInput = structuredClone(
      targetCampaign.input as Record<string, unknown>,
    );
    const targetCandidates = structuredClone(
      targetInput.candidates as Array<Record<string, unknown>>,
    );
    targetCandidates[0]!.memoryId = "10.129.46.32";
    targetInput.candidates = targetCandidates;
    targetCampaign.input = targetInput;
    expect(() => parsePrivateResearchHoldoutDescriptor({
      ...withTarget,
      campaigns: [targetCampaign],
    })).toThrow("target-free");

    const withSecret = descriptor();
    const secretCampaign = structuredClone(
      (withSecret.campaigns as Array<Record<string, unknown>>)[0]!,
    );
    secretCampaign.fixtureKey = "api_key=operator-private-secret";
    expect(() => parsePrivateResearchHoldoutDescriptor({
      ...withSecret,
      campaigns: [secretCampaign],
    })).toThrow("non-secret");
  });
});
