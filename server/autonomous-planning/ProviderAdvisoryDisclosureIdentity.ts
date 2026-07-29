import { hashCanonical } from "../missions/canonical";

export const PROVIDER_ADVISORY_DISCLOSURE_IDENTITY_SCHEMA_VERSION =
  "ti-scale.provider-advisory-disclosure-identity.v1" as const;

export const PROVIDER_ADVISORY_PLANNING_DISCLOSURE_MODES = [
  "public_only",
  "sanitized_internal",
] as const;

export type ProviderAdvisoryPlanningDisclosureMode =
  (typeof PROVIDER_ADVISORY_PLANNING_DISCLOSURE_MODES)[number];

export interface ProviderAdvisoryDisclosureIdentityInput {
  readonly exposureReceiptId: string;
  readonly planningRequestId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly contextPackId: string;
  readonly providerTurnId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly disclosurePolicyVersion: string;
  readonly planningDisclosureMode: ProviderAdvisoryPlanningDisclosureMode;
  readonly exposedPayloadHash: string;
}

/**
 * Identity hash for the complete local authority tuple. The public-provider
 * payload need not contain this value; the exposure repository, pre-network
 * request auditor and post-response binding reader all recompute it locally.
 */
export function providerAdvisoryDisclosureIdentityHash(
  input: ProviderAdvisoryDisclosureIdentityInput,
): string {
  return hashCanonical({
    schemaVersion: PROVIDER_ADVISORY_DISCLOSURE_IDENTITY_SCHEMA_VERSION,
    ...input,
  });
}

export function isProviderAdvisoryPlanningDisclosureMode(
  value: unknown,
): value is ProviderAdvisoryPlanningDisclosureMode {
  return typeof value === "string"
    && PROVIDER_ADVISORY_PLANNING_DISCLOSURE_MODES.includes(
      value as ProviderAdvisoryPlanningDisclosureMode,
    );
}
