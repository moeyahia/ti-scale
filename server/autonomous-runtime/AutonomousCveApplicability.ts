import {
  AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION as REGISTERED_CVE_CRITERION,
  type ActionClassId,
  type EvidenceTypeId,
} from "../domain";
import type {
  AuthoritativeCveCandidate,
  VerifiedServiceProductVersionEvidence,
} from "../cve-intelligence";

export const AUTONOMOUS_CVE_APPLICABILITY_POLICY_SCHEMA_VERSION =
  "ti-scale.autonomous-cve-applicability-policy.v1" as const;
export const AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE =
  "ti-scale:autonomous-cve-applicability" as const;
export const AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS =
  "cve_intelligence_applicability_validation" as const satisfies ActionClassId;
export const AUTONOMOUS_CVE_APPLICABILITY_EVIDENCE_TYPE =
  "cve_applicability" as const satisfies EvidenceTypeId;
export const AUTONOMOUS_CVE_APPLICABILITY_BINDING_ID =
  "binding:autonomous-cve-applicability-v1" as const;
export const AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION =
  REGISTERED_CVE_CRITERION;

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export interface AutonomousCveApplicabilityConfiguration {
  readonly policyId: string;
  readonly bindingId: string;
  readonly agentId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  /** Stable identity of the reviewed local candidate catalogue. */
  readonly catalogId: string;
  /** Immutable snapshot digest. A running mission never follows catalogue drift. */
  readonly catalogSnapshotSha256: string;
  readonly maximumCandidatesPerProduct: number;
  /** At most the highest-ranked persisted candidate is enriched through NVD. */
  readonly nvdEnrichment: "disabled" | "top_candidate";
  readonly successCriterion: string;
}

export interface AuthoritativeCveCatalogQueryReceipt {
  readonly schemaVersion: "ti-scale.authoritative-cve-catalog-query.v1";
  readonly catalogId: string;
  readonly catalogSnapshotSha256: string;
  readonly evidenceId: string;
  readonly candidates: readonly AuthoritativeCveCandidate[];
  readonly queriedAt: string;
  readonly queryReceiptId: string;
  readonly queryReceiptSha256: string;
  readonly targetInteraction: false;
  readonly executionAuthority: "none";
}

export const AUTHORITATIVE_CVE_CATALOG_COMPOSITION_SCHEMA_VERSION =
  "ti-scale.authoritative-cve-catalog-composition.v1" as const;

/**
 * Content-free proof for the exact catalogue object mounted in the runtime.
 * The projection must bind this receipt rather than treating object presence
 * as proof that the configured catalogue was loaded.
 */
export interface AuthoritativeCveCatalogCompositionReceipt {
  readonly schemaVersion:
    typeof AUTHORITATIVE_CVE_CATALOG_COMPOSITION_SCHEMA_VERSION;
  readonly catalogId: string;
  readonly catalogSnapshotSha256: string;
  readonly maximumCandidatesPerProduct: number;
  readonly localReadOnly: true;
  readonly targetInteraction: false;
  readonly executionAuthority: "none";
  readonly receiptSha256: string;
}

/**
 * A reviewed local catalogue is the only candidate-discovery authority. The
 * public NVD binding is exact-CVE detail lookup only and must never receive a
 * product banner, target, URL, keyword search, or provider-authored query.
 */
export interface AuthoritativeCveCandidateCatalogPort {
  inspectComposition(): AuthoritativeCveCatalogCompositionReceipt;
  lookup(
    evidence: VerifiedServiceProductVersionEvidence,
    signal: AbortSignal,
  ): Promise<AuthoritativeCveCatalogQueryReceipt>;
}

function id(value: string, label: string): string {
  if (value !== value.trim() || !PUBLIC_ID.test(value)) {
    throw new TypeError(`${label} must be one stable public identifier`);
  }
  return value;
}

export function validateAutonomousCveApplicabilityConfiguration(
  value: AutonomousCveApplicabilityConfiguration,
): AutonomousCveApplicabilityConfiguration {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Autonomous CVE applicability configuration must be an object");
  }
  const expected = [
    "agentId", "bindingId", "catalogId", "catalogSnapshotSha256",
    "maximumCandidatesPerProduct", "modelConfigurationHash", "modelId",
    "nvdEnrichment", "policyId", "providerId", "successCriterion",
  ].sort();
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError("Autonomous CVE applicability configuration contains unexpected fields");
  }
  if (!SHA256.test(value.modelConfigurationHash)
    || !SHA256.test(value.catalogSnapshotSha256)) {
    throw new TypeError("Autonomous CVE applicability hashes must be SHA-256 digests");
  }
  if (!Number.isSafeInteger(value.maximumCandidatesPerProduct)
    || value.maximumCandidatesPerProduct < 1
    || value.maximumCandidatesPerProduct > 100) {
    throw new RangeError("maximumCandidatesPerProduct must be 1 through 100");
  }
  if (value.nvdEnrichment !== "disabled" && value.nvdEnrichment !== "top_candidate") {
    throw new TypeError("nvdEnrichment must be disabled or top_candidate");
  }
  if (value.successCriterion !== AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION) {
    throw new TypeError("successCriterion must be the canonical CVE applicability criterion");
  }
  return Object.freeze({
    policyId: id(value.policyId, "policyId"),
    bindingId: id(value.bindingId, "bindingId"),
    agentId: id(value.agentId, "agentId"),
    providerId: id(value.providerId, "providerId"),
    modelId: id(value.modelId, "modelId"),
    modelConfigurationHash: value.modelConfigurationHash,
    catalogId: id(value.catalogId, "catalogId"),
    catalogSnapshotSha256: value.catalogSnapshotSha256,
    maximumCandidatesPerProduct: value.maximumCandidatesPerProduct,
    nvdEnrichment: value.nvdEnrichment,
    successCriterion: value.successCriterion,
  });
}
