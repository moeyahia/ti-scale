import type { LocalAutonomousPlanningPolicy } from "../autonomous-runtime";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "./TrustedJsonFileLoader";
import {
  parseEngagementWorkspaceMappingsDocument,
  parseLocalAutonomousPlanningPolicy,
  parseRuntimeSourceManifestDocument,
  type EngagementWorkspaceMappingsDocument,
  type RuntimeSourceManifestDocument,
} from "./RuntimeConfigurationDocuments";

const PLANNING_POLICY_MAXIMUM_BYTES = 512 * 1_024;
const RUNTIME_MANIFEST_MAXIMUM_BYTES = 4 * 1_024 * 1_024;
const WORKSPACE_MAPPINGS_MAXIMUM_BYTES = 128 * 1_024;

function bounded(
  reference: TrustedJsonFileReference,
  maximumBytes: number,
): TrustedJsonFileReference {
  if (reference.maximumBytes !== undefined && reference.maximumBytes > maximumBytes) {
    throw new Error(`Trusted configuration maximumBytes exceeds the ${maximumBytes}-byte document boundary`);
  }
  return { ...reference, maximumBytes: reference.maximumBytes ?? maximumBytes };
}

/** Load the exact local deterministic planning policy; this does not mount a planner. */
export function loadTrustedLocalAutonomousPlanningPolicy(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<LocalAutonomousPlanningPolicy> {
  return loadTrustedJson(
    bounded(reference, PLANNING_POLICY_MAXIMUM_BYTES),
    parseLocalAutonomousPlanningPolicy,
  );
}

/** Load and cross-validate runtime capability sources; this performs no readiness attestation. */
export function loadTrustedRuntimeSourceManifests(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<RuntimeSourceManifestDocument> {
  return loadTrustedJson(
    bounded(reference, RUNTIME_MANIFEST_MAXIMUM_BYTES),
    parseRuntimeSourceManifestDocument,
  );
}

/** Load reviewed logical/worker roots; this creates no directory and resolves no engagement. */
export function loadTrustedEngagementWorkspaceMappings(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<EngagementWorkspaceMappingsDocument> {
  return loadTrustedJson(
    bounded(reference, WORKSPACE_MAPPINGS_MAXIMUM_BYTES),
    parseEngagementWorkspaceMappingsDocument,
  );
}
