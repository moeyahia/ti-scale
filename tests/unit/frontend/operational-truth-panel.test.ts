import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { EvidenceCandidateV24, ObservationV24 } from "../../../src/domain/types/operationalTruth";
import {
  additionalCandidateRequirements,
  buildEvidenceVerificationRequest,
  candidateReviewActions,
  deriveCandidateProvenanceSources,
  OPERATIONAL_TRUTH_STAGES,
  OperationalTruthStageTabs,
} from "../../../src/features/intelligence/OperationalTruthPanel";

const NOW = "2026-07-16T10:00:00.000Z";

const candidate: EvidenceCandidateV24 = {
  id: "candidate-one",
  missionId: "mission-one",
  runId: "run-one",
  stepId: "step-one",
  observationId: "observation-one",
  artifactId: "artifact-one",
  evidenceType: "port_service_scan",
  label: "HTTPS service exposure",
  meaning: "The attributable service observation may support the mission inventory.",
  promotionReason: "Retain the parsed result for an explicit independent review.",
  validationRequirements: [
    "immutable_content_hash",
    "attributable_provenance",
    "normalized_target",
    "acquired_time",
    "chain_of_custody",
    "second_source_corroboration",
  ],
  state: "validating",
  sensitivity: "private",
  proposedBy: "ReconScout",
  reviewedBy: "operator-one",
  reviewReason: "The candidate has attributable sources worth validating.",
  createdAt: NOW,
  reviewedAt: NOW,
};

const observation: ObservationV24 = {
  id: "observation-one",
  missionId: "mission-one",
  runId: "run-one",
  stepId: "step-one",
  assetId: "asset-one",
  observationType: "open_port",
  statement: "TCP port 443 appeared open on the authorized fixture.",
  normalizedValue: { port: 443, transport: "tcp" },
  confidence: 0.85,
  verificationState: "corroborated",
  sourceAgentId: "ReconScout",
  sourceTool: "nmap",
  firstSeenAt: NOW,
  lastSeenAt: NOW,
  sensitivity: "private",
  sources: [
    { logRecordId: "log-one", parserId: "nmap-xml", parserVersion: "1.0.0" },
    { logRecordId: "log-two", parserId: "service-probe", parserVersion: "1.0.0" },
  ],
  createdAt: NOW,
};

describe("Operational Truth stage contract", () => {
  test("renders the four ordered, keyboard-focusable truth stages with explicit raw-output semantics", () => {
    expect(OPERATIONAL_TRUTH_STAGES.map((stage) => stage.id)).toEqual([
      "logs", "observations", "candidates", "verified",
    ]);
    expect(OPERATIONAL_TRUTH_STAGES[0]?.explanation).toContain("Raw output is not evidence");

    const markup = renderToStaticMarkup(createElement(OperationalTruthStageTabs, {
      current: "observations",
      onSelect: () => undefined,
    }));
    expect(markup).toContain('role="tablist"');
    expect(markup.match(/role="tab"/g)).toHaveLength(4);
    expect(markup).toContain('aria-selected="true"');
    expect(markup).toContain('tabindex="-1"');
    expect(markup).toContain("Verified evidence");
  });

  test("exposes only server-valid review actions for every candidate state", () => {
    expect(candidateReviewActions("candidate")).toEqual(["promote", "reject"]);
    expect(candidateReviewActions("validating")).toEqual(["verify", "reject"]);
    expect(candidateReviewActions("promoted")).toEqual(["demote"]);
    expect(candidateReviewActions("rejected")).toEqual([]);
    expect(candidateReviewActions("demoted")).toEqual(["promote", "reject"]);
  });
});

describe("Operational Truth verification provenance", () => {
  test("derives the canonical observation, every source log, and artifact without duplicates", () => {
    expect(deriveCandidateProvenanceSources(candidate, observation)).toEqual([
      { kind: "observation", id: "observation-one" },
      { kind: "engagement_log", id: "log-one" },
      { kind: "engagement_log", id: "log-two" },
      { kind: "artifact", id: "artifact-one" },
    ]);
    expect(() => deriveCandidateProvenanceSources(candidate)).toThrow("canonical observation detail is required");
    expect(() => deriveCandidateProvenanceSources(candidate, { ...observation, id: "observation-other" }))
      .toThrow("canonical observation detail is required");
  });

  test("builds a custody-bound request and carries only candidate-specific requirement attestations", () => {
    const sources = deriveCandidateProvenanceSources(candidate, observation);
    expect(additionalCandidateRequirements(candidate)).toEqual(["second_source_corroboration"]);
    expect(buildEvidenceVerificationRequest(candidate, sources, {
      reason: "Two attributable sources were independently checked.",
      source: "nmap XML and bounded service probe",
      target: "asset-one:443/tcp",
      acquiredAt: NOW,
      confidence: 0.9,
      method: "Structured parsing with independent review",
      explanation: "Both canonical logs resolve to the same authorized asset and service.",
      custodyActor: "ReconScout",
      custodyOccurredAt: NOW,
      confirmedIndependentReview: true,
      satisfiedAdditionalRequirements: ["second_source_corroboration"],
    })).toEqual({
      reason: "Two attributable sources were independently checked.",
      source: "nmap XML and bounded service probe",
      target: "asset-one:443/tcp",
      acquiredAt: NOW,
      confidence: 0.9,
      provenance: {
        method: "Structured parsing with independent review",
        explanation: "Both canonical logs resolve to the same authorized asset and service.",
        sources,
      },
      custody: [{
        eventType: "acquired",
        actor: "ReconScout",
        occurredAt: NOW,
        details: { review: "Canonical source and acquisition were explicitly reviewed by a human operator." },
      }],
      satisfiedAdditionalRequirements: ["second_source_corroboration"],
    });
  });

  test("refuses non-validating, unconfirmed, incomplete, or temporally invalid verification", () => {
    const sources = deriveCandidateProvenanceSources(candidate, observation);
    const valid = {
      reason: "Independent source review completed.",
      source: "Structured parser",
      target: "asset-one:443/tcp",
      acquiredAt: NOW,
      confidence: 0.9,
      method: "Independent review",
      explanation: "Canonical sources support the normalized target statement.",
      custodyActor: "ReconScout",
      custodyOccurredAt: NOW,
      confirmedIndependentReview: true,
      satisfiedAdditionalRequirements: ["second_source_corroboration"],
    } as const;
    expect(() => buildEvidenceVerificationRequest({ ...candidate, state: "candidate" }, sources, valid))
      .toThrow("Only a validating candidate");
    expect(() => buildEvidenceVerificationRequest(candidate, sources, { ...valid, confirmedIndependentReview: false }))
      .toThrow("Independent human review");
    expect(() => buildEvidenceVerificationRequest(candidate, sources, { ...valid, satisfiedAdditionalRequirements: [] }))
      .toThrow("remain unsatisfied");
    expect(() => buildEvidenceVerificationRequest(candidate, sources, {
      ...valid,
      custodyOccurredAt: "2026-07-16T09:59:59.000Z",
    })).toThrow("cannot precede acquisition");
  });
});
