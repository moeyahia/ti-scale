import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  privateSourceBindingCount,
  privateSourceDestinationHref,
} from "../../../src/features/brain/PrivateSourceCustody";

const inspector = readFileSync(
  new URL("../../../src/features/brain/MemoryNodeInspector.tsx", import.meta.url),
  "utf8",
);
const nodePage = readFileSync(
  new URL("../../../src/features/brain/BrainNodePage.tsx", import.meta.url),
  "utf8",
);
const custody = readFileSync(
  new URL("../../../src/features/brain/PrivateSourceCustody.tsx", import.meta.url),
  "utf8",
);

describe("private historical source-custody presentation", () => {
  test("shares one complete custody renderer between graph and full-record views", () => {
    for (const source of [inspector, nodePage]) {
      expect(source).toContain('from "./PrivateSourceCustody"');
      expect(source).toContain("<PrivateSourceCustody");
    }
    expect(custody).toContain('aria-label="Private source custody"');
    expect(custody).toContain("Source collection");
    expect(custody).toContain("sourceLocator");
    expect(custody).toContain("Import custody record");
    expect(custody).toContain("Custody processing run");
    expect(custody).toContain("Source artifact");
    expect(custody).toContain("Evidence receipt");
    expect(custody).toContain("Private source reference");
    expect(custody).toContain("/missions/");
    expect(custody).toContain("/intelligence/artifacts/");
    expect(custody).toContain("/intelligence/evidence/");
  });

  test("does not label an internal import-custody mission as the originating engagement", () => {
    for (const source of [inspector, nodePage, custody]) {
      expect(source).not.toContain("Originating engagement");
      expect(source).not.toContain("Custody mission");
    }
  });

  test("distinguishes zero reusable edges from multiple exact private origins", () => {
    for (const source of [inspector, nodePage]) {
      expect(source).toContain("privateSourceBindingCount");
      expect(source).toContain("exact private custody binding");
      expect(source).toContain("No reusable graph edges are recorded");
    }
    expect(custody).toContain("exact binding");
    expect(custody).toContain("zero reusable knowledge edges");
    const origins = [
      {
        missionId: "mission-private-one",
        runId: "run-private-one",
        artifactId: "artifact-private-one",
        evidenceId: "evidence-private-one",
        privateSourceReference: "legacy-private-source://one",
      },
      {
        missionId: "mission-private-two",
        runId: "run-private-two",
        evidenceId: "evidence-private-two",
        privateSourceReference: "legacy-private-source://two",
      },
    ];
    expect(privateSourceBindingCount([{
      sourceType: "historical_attack_knowledge_source_candidate",
      sourceId: "candidate:migration",
      acquiredAt: "2026-07-21T00:00:00.000Z",
      origins,
    }])).toBe(2);
    expect(privateSourceDestinationHref(origins[0]!)).toBe("/intelligence/artifacts/artifact-private-one");
    expect(privateSourceDestinationHref(origins[1]!)).toBe("/intelligence/evidence/evidence-private-two");
  });
});
