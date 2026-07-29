import { describe, expect, test } from "bun:test";

import {
  EVIDENCE_TYPE_DEFINITIONS,
  canVerifyFinding,
  classifyOperationalInput,
  verifyEvidenceCandidate,
  type EvidenceRecord,
} from "../../../server/domain";

describe("engagement logs are not automatically evidence", () => {
  test("keeps raw command output only in the Engagement Log by default", () => {
    const result = classifyOperationalInput("raw_command_output", {
      parsed: true,
      attributable: true,
      provenanceSourceIds: ["tool-call-1"],
      immutableHash: "sha256:command-output",
      policyAllowsCandidate: true,
    });

    expect(result.stages).toEqual(["engagement_log"]);
    expect(result.stages).not.toContain("evidence_candidate");
    expect(result.stages).not.toContain("verified_evidence");
    expect(result.automaticallyVerified).toBe(false);
  });

  test("normalizes a structured scan into a log, artifact, and observations without evidence promotion", () => {
    const result = classifyOperationalInput("structured_scan_result", {
      parsed: true,
      attributable: true,
      provenanceSourceIds: ["tool-call-2"],
      immutableHash: "sha256:scan",
      policyAllowsCandidate: true,
    });

    expect(result.stages).toEqual(["engagement_log", "artifact", "observation"]);
    expect(result.stages).not.toContain("evidence_candidate");
    expect(result.stages).not.toContain("verified_evidence");
  });

  test("creates a screenshot candidate only after policy, attribution, provenance, and hash gates", () => {
    const incomplete = classifyOperationalInput("screenshot", {
      parsed: true,
      attributable: true,
      provenanceSourceIds: [],
      policyAllowsCandidate: true,
    });
    expect(incomplete.stages).toEqual(["artifact"]);

    const complete = classifyOperationalInput("screenshot", {
      parsed: true,
      attributable: true,
      provenanceSourceIds: ["capture-action-1"],
      immutableHash: "sha256:capture",
      policyAllowsCandidate: true,
    });
    expect(complete.stages).toEqual(["artifact", "evidence_candidate"]);
    expect(complete.stages).not.toContain("verified_evidence");
  });
});

describe("evidence and finding verification gates", () => {
  const pageCaptureDefinition = EVIDENCE_TYPE_DEFINITIONS.find(
    ({ id }) => id === "web_page_capture",
  )!;

  test("rejects a candidate without hash, provenance, target, time, and custody", () => {
    const candidate: EvidenceRecord = {
      id: "evidence-1",
      typeId: "web_page_capture",
      stage: "evidence_candidate",
      provenanceSourceIds: [],
      chainOfCustodyComplete: false,
    };
    const result = verifyEvidenceCandidate(candidate, pageCaptureDefinition, "reviewer-1");

    expect(result.verified).toBe(false);
    expect(result.reasons).toContain("An immutable content hash is required.");
    expect(result.reasons).toContain("At least one provenance source is required.");
    expect(result.reasons).toContain("Acquisition time is required.");
    expect(result.reasons).toContain("A normalized target is required.");
    expect(result.reasons).toContain("Chain of custody is incomplete.");
  });

  test("verifies an attributable candidate but never does so automatically", () => {
    const candidate: EvidenceRecord = {
      id: "evidence-2",
      typeId: "web_page_capture",
      stage: "evidence_candidate",
      immutableHash: "sha256:capture",
      provenanceSourceIds: ["capture-action-1"],
      acquiredAt: "2026-07-16T00:00:00.000Z",
      targetId: "asset-web-1",
      chainOfCustodyComplete: true,
    };
    const result = verifyEvidenceCandidate(candidate, pageCaptureDefinition, "reviewer-1");

    expect(result.verified).toBe(true);
    expect(result.evidence?.stage).toBe("verified_evidence");
    expect(result.evidence?.verificationActorId).toBe("reviewer-1");
  });

  test("prevents finding verification when required verified evidence is absent", () => {
    const rawLog: EvidenceRecord = {
      id: "log-1",
      typeId: "http_exchange",
      stage: "engagement_log",
      immutableHash: "sha256:raw",
      provenanceSourceIds: ["tool-call-1"],
      acquiredAt: "2026-07-16T00:00:00.000Z",
      targetId: "asset-web-1",
      chainOfCustodyComplete: true,
    };
    const absent = canVerifyFinding(
      {
        requiredEvidenceTypeIds: ["http_exchange", "finding_reproduction"],
        requireAtLeastOneVerifiedEvidence: true,
      },
      [rawLog],
    );

    expect(absent.verified).toBe(false);
    expect(absent.missingEvidenceTypeIds).toEqual([
      "http_exchange",
      "finding_reproduction",
    ]);
  });

  test("requires every evidence type in immutable finding policy", () => {
    const httpEvidence: EvidenceRecord = {
      id: "evidence-http",
      typeId: "http_exchange",
      stage: "verified_evidence",
      immutableHash: "sha256:http",
      provenanceSourceIds: ["tool-call-1"],
      acquiredAt: "2026-07-16T00:00:00.000Z",
      targetId: "asset-web-1",
      chainOfCustodyComplete: true,
      verificationActorId: "reviewer-1",
    };
    const partial = canVerifyFinding(
      {
        requiredEvidenceTypeIds: ["http_exchange", "finding_reproduction"],
        requireAtLeastOneVerifiedEvidence: true,
      },
      [httpEvidence],
    );

    expect(partial.verified).toBe(false);
    expect(partial.missingEvidenceTypeIds).toEqual(["finding_reproduction"]);

    const complete = canVerifyFinding(
      {
        requiredEvidenceTypeIds: ["http_exchange"],
        requireAtLeastOneVerifiedEvidence: true,
      },
      [httpEvidence],
    );
    expect(complete.verified).toBe(true);
  });

  test("does not trust a verified stage without an attributable verification actor", () => {
    const unreviewed: EvidenceRecord = {
      id: "evidence-unreviewed",
      typeId: "http_exchange",
      stage: "verified_evidence",
      immutableHash: "sha256:http",
      provenanceSourceIds: ["tool-call-1"],
      acquiredAt: "2026-07-16T00:00:00.000Z",
      targetId: "asset-web-1",
      chainOfCustodyComplete: true,
    };
    const result = canVerifyFinding(
      {
        requiredEvidenceTypeIds: ["http_exchange"],
        requireAtLeastOneVerifiedEvidence: true,
      },
      [unreviewed],
    );
    expect(result.verified).toBe(false);
  });
});
