import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { parseArtifact, parseEvidence, parseFinding } from "../../../src/domain/schemas/operations";
import {
  artifactDeliveryEvidenceLabel,
  artifactDetailHref,
  EvidenceRunExportControl,
  evidenceDetailHref,
  missionDetailHref,
  resolveEvidenceExportBoundary,
  runDetailHref,
  supportsVerifiedArtifactDownload,
} from "../../../src/features/intelligence/IntelligencePage";

const mission = { id: "mission/with space", name: "Authorized fixture" };

describe("canonical Intelligence relationships", () => {
  test("encodes every stable identifier as one internal route segment", () => {
    expect(missionDetailHref(mission.id)).toBe("/missions/mission%2Fwith%20space");
    expect(runDetailHref(mission.id, "run/one")).toBe("/missions/mission%2Fwith%20space/runs/run%2Fone");
    expect(evidenceDetailHref("evidence/one")).toBe("/intelligence/evidence/evidence%2Fone");
    expect(artifactDetailHref("artifact/one")).toBe("/intelligence/artifacts/artifact%2Fone");
  });

  test("parses only explicit verified run and artifact relations", () => {
    const evidence = parseEvidence({
      id: "evidence-one",
      mission,
      runId: "run-one",
      run: { id: "run-one" },
      stepId: null,
      actionId: null,
      source: "fixture",
      acquiredAt: "2026-07-16T00:00:00.000Z",
      target: null,
      evidenceType: "service",
      recordClass: "evidence",
      contentHash: "a".repeat(64),
      provenance: {},
      confidence: 1,
      sensitivity: "internal",
      verificationState: "verified",
      summary: "Attributable observation",
      hasExtractedText: false,
      artifactId: "artifact-one",
      artifact: { id: "artifact-one", artifactType: "scan_archive" },
      createdBy: "operator",
      createdAt: "2026-07-16T00:00:00.000Z",
    });
    expect(evidence.run).toEqual({ id: "run-one" });
    expect(evidence.recordClass).toBe("evidence");
    expect(evidence.artifact).toEqual({ id: "artifact-one", artifactType: "scan_archive" });

    const unresolved = parseEvidence({ ...evidence, run: null, artifact: null });
    expect(unresolved.runId).toBe("run-one");
    expect(unresolved.run).toBeNull();
    expect(unresolved.artifactId).toBe("artifact-one");
    expect(unresolved.artifact).toBeNull();

    const operationalLog = parseEvidence({
      ...evidence,
      id: "legacy-command-output",
      evidenceType: "command_output",
      recordClass: "operational_log",
      verificationState: "unverified",
      summary: "observed output (observe-only)",
    });
    expect(operationalLog.recordClass).toBe("operational_log");
    expect(() => parseEvidence({ ...evidence, recordClass: "raw_output" }))
      .toThrow("evidence.recordClass is invalid");
  });

  test("preserves empty evidence relations on finding and artifact details", () => {
    const finding = parseFinding({
      id: "finding-one",
      mission,
      runId: null,
      run: null,
      title: "Unverified imported conclusion",
      severity: "informational",
      confidence: 0.5,
      affectedScope: "fixture",
      description: "No current evidence relation",
      impact: "No impact asserted",
      reproductionNotes: null,
      remediation: null,
      reviewStatus: "draft",
      operatorOverride: false,
      version: 1,
      evidenceCount: 0,
      verifiedEvidenceCount: 0,
      createdAt: "2026-07-16T00:00:00.000Z",
      updatedAt: "2026-07-16T00:00:00.000Z",
      evidence: [],
    });
    expect(finding.run).toBeNull();
    expect(finding.evidence).toEqual([]);

    const artifact = parseArtifact({
      id: "artifact-one",
      mission,
      runId: null,
      run: null,
      stepId: null,
      actionId: null,
      journey: "guided",
      artifactType: "imported_metadata",
      contentHash: "b".repeat(64),
      byteSize: 1,
      mediaType: "application/json",
      sensitivity: "internal",
      metadata: {},
      storage: { scheme: "artifact-store", available: false },
      evaluation: null,
      contextPackIds: [],
      evidence: [],
      createdAt: "2026-07-16T00:00:00.000Z",
    });
    expect(artifact.run).toBeNull();
    expect(artifact.evidence).toEqual([]);
  });

  test("permits evidence export only for an agreeing repository-verified run projection", () => {
    expect(resolveEvidenceExportBoundary([
      { runId: "run-one", run: { id: "run-one" } },
    ], "run-one", true)).toEqual({ state: "canonical", runId: "run-one" });

    expect(resolveEvidenceExportBoundary([
      { runId: "run-one", run: null },
    ], "run-one", true)).toEqual({ state: "unresolved_relation" });

    expect(resolveEvidenceExportBoundary([
      { runId: "run-one", run: { id: "run-other" } },
    ], "run-one", true)).toEqual({ state: "unresolved_relation" });

    expect(resolveEvidenceExportBoundary([
      { runId: null, run: null },
    ], null, true)).toEqual({ state: "missing_relation" });

    expect(resolveEvidenceExportBoundary([], "syntactically-valid-but-unverified", true))
      .toEqual({ state: "unresolved_relation" });
    expect(resolveEvidenceExportBoundary([], undefined, false)).toEqual({ state: "hidden" });
  });

  test("marks the canonical evidence export as an explicit browser download", () => {
    const markup = renderToStaticMarkup(
      createElement(EvidenceRunExportControl, { boundary: { state: "canonical", runId: "run-one" } }),
    );
    expect(markup).toContain('href="/api/v2/intelligence/evidence/runs/run-one/export"');
    expect(markup).toContain(" download=\"\"");
    expect(markup).toContain("Export evidence metadata");
  });

  test("renders artifact download only for a server-approved, evidence-linked canonical delivery", () => {
    const ready = {
      artifactType: "obsidian_attachment",
      storage: { scheme: "vault-attachment", available: true },
      evidence: [{
        id: "evidence-one",
        summary: "Verified evidence",
        evidenceType: "file_artifact_with_hash",
        verificationState: "verified",
        contentHash: "c".repeat(64),
        acquiredAt: "2026-07-16T00:00:00.000Z",
      }],
      delivery: {
        state: "ready" as const,
        downloadable: true,
        code: "artifact_delivery_ready",
        reason: "Verified",
        remediation: null,
        verifiedEvidenceCount: 1,
      },
    };
    expect(supportsVerifiedArtifactDownload(ready)).toBe(true);
    expect(supportsVerifiedArtifactDownload({ ...ready, evidence: [] })).toBe(false);
    expect(supportsVerifiedArtifactDownload({
      ...ready,
      delivery: { ...ready.delivery, state: "quarantined", downloadable: false },
    })).toBe(false);
    expect(supportsVerifiedArtifactDownload({
      ...ready,
      delivery: undefined,
    })).toBe(false);
    expect(artifactDeliveryEvidenceLabel(0)).toBe("0 visible verified evidence records support this delivery boundary.");
    expect(artifactDeliveryEvidenceLabel(1)).toBe("1 visible verified evidence record supports this delivery boundary.");
    expect(artifactDeliveryEvidenceLabel(2)).toBe("2 visible verified evidence records support this delivery boundary.");
  });
});
