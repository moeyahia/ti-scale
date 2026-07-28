import type { LoadedTrustedJson, TrustedJsonFileReference } from "./TrustedJsonFileLoader";
import {
  loadTrustedEngagementWorkspaceMappings,
  loadTrustedLocalAutonomousPlanningPolicy,
  loadTrustedRuntimeSourceManifests,
} from "./TrustedRuntimeConfiguration";

export const TRUSTED_RUNTIME_CONFIGURATION_READINESS_SCHEMA_VERSION =
  "ti-scale.trusted-runtime-configuration-readiness.v1" as const;

export type TrustedRuntimeConfigurationReadinessStatus =
  | "unconfigured"
  | "valid"
  | "invalid"
  | "unavailable";

export interface TrustedRuntimeConfigurationReferences {
  readonly planningPolicy?: TrustedJsonFileReference;
  readonly runtimeSourceManifests?: TrustedJsonFileReference;
  readonly workspaceMappings?: TrustedJsonFileReference;
}

export interface TrustedRuntimeConfigurationDocumentReadiness {
  readonly configured: boolean;
  readonly status: TrustedRuntimeConfigurationReadinessStatus;
  readonly reason: string;
  /** Public schema identifier from a successfully validated document. */
  readonly schemaVersion?: string;
  /** Public policy/manifest/mapping version from a successfully validated document. */
  readonly documentVersion?: string;
  /** Exact reviewed byte digest; the document body and path are never projected. */
  readonly sourceSha256?: string;
  /** Canonical parsed-value digest for drift comparison. */
  readonly canonicalSha256?: string;
  readonly byteSize?: number;
}

export interface TrustedRuntimeConfigurationReadiness {
  readonly schemaVersion: typeof TRUSTED_RUNTIME_CONFIGURATION_READINESS_SCHEMA_VERSION;
  readonly status: TrustedRuntimeConfigurationReadinessStatus;
  readonly configured: boolean;
  readonly complete: boolean;
  readonly reason: string;
  readonly checkedAt: string;
  readonly documents: {
    readonly planningPolicy: TrustedRuntimeConfigurationDocumentReadiness;
    readonly runtimeSourceManifests: TrustedRuntimeConfigurationDocumentReadiness;
    readonly workspaceMappings: TrustedRuntimeConfigurationDocumentReadiness;
  };
  /** Configuration integrity is not runtime execution authority. */
  readonly executionAuthorized: false;
  readonly plannerMounted: false;
  readonly providerExecutionMounted: false;
  readonly specialistExecutionMounted: false;
  readonly toolExecutionMounted: false;
}

const UNAVAILABLE_ERROR_CODES = new Set([
  "EACCES",
  "EIO",
  "EMFILE",
  "ENFILE",
  "ENOENT",
  "EPERM",
  "ESTALE",
]);

function errorCode(error: unknown): string | undefined {
  if (error === null || typeof error !== "object" || !("code" in error)) return undefined;
  return typeof error.code === "string" ? error.code : undefined;
}

function unconfigured(): TrustedRuntimeConfigurationDocumentReadiness {
  return Object.freeze({
    configured: false,
    status: "unconfigured",
    reason: "No reviewed reference is configured for this document.",
  });
}

function rejected(error: unknown): TrustedRuntimeConfigurationDocumentReadiness {
  const unavailable = UNAVAILABLE_ERROR_CODES.has(errorCode(error) ?? "");
  return Object.freeze({
    configured: true,
    status: unavailable ? "unavailable" : "invalid",
    reason: unavailable
      ? "The configured reviewed document could not be read. Runtime activation remains unavailable."
      : "The configured reviewed document failed trust, integrity, or schema validation.",
  });
}

function valid<T>(
  loaded: LoadedTrustedJson<T>,
  schemaVersion: string,
  documentVersion: string,
): TrustedRuntimeConfigurationDocumentReadiness {
  return Object.freeze({
    configured: true,
    status: "valid",
    reason: "The reviewed document passed local path, ownership, digest, schema, and semantic validation.",
    schemaVersion,
    documentVersion,
    sourceSha256: loaded.receipt.sourceSha256,
    canonicalSha256: loaded.receipt.canonicalSha256,
    byteSize: loaded.receipt.byteSize,
  });
}

function planningPolicy(
  reference: TrustedJsonFileReference | undefined,
): TrustedRuntimeConfigurationDocumentReadiness {
  if (!reference) return unconfigured();
  try {
    const loaded = loadTrustedLocalAutonomousPlanningPolicy(reference);
    return valid(loaded, loaded.value.schemaVersion, loaded.value.policyId);
  } catch (error) {
    return rejected(error);
  }
}

function runtimeSourceManifests(
  reference: TrustedJsonFileReference | undefined,
): TrustedRuntimeConfigurationDocumentReadiness {
  if (!reference) return unconfigured();
  try {
    const loaded = loadTrustedRuntimeSourceManifests(reference);
    return valid(loaded, loaded.value.schemaVersion, loaded.value.manifestVersion);
  } catch (error) {
    return rejected(error);
  }
}

function workspaceMappings(
  reference: TrustedJsonFileReference | undefined,
): TrustedRuntimeConfigurationDocumentReadiness {
  if (!reference) return unconfigured();
  try {
    const loaded = loadTrustedEngagementWorkspaceMappings(reference);
    return valid(loaded, loaded.value.schemaVersion, loaded.value.mappingVersion);
  } catch (error) {
    return rejected(error);
  }
}

function overallStatus(
  documents: TrustedRuntimeConfigurationReadiness["documents"],
): TrustedRuntimeConfigurationReadinessStatus {
  const values = Object.values(documents);
  if (values.every(({ status }) => status === "unconfigured")) return "unconfigured";
  if (values.some(({ status }) => status === "invalid")) return "invalid";
  if (values.some(({ status }) => status === "unavailable" || status === "unconfigured")) {
    return "unavailable";
  }
  return "valid";
}

function overallReason(status: TrustedRuntimeConfigurationReadinessStatus): string {
  if (status === "unconfigured") {
    return "No trusted runtime configuration documents are configured. Runtime activation remains unavailable.";
  }
  if (status === "invalid") {
    return "At least one configured document failed trust, integrity, or schema validation. Runtime activation remains unavailable.";
  }
  if (status === "unavailable") {
    return "The complete reviewed configuration set is not locally available. Runtime activation remains unavailable.";
  }
  return "All reviewed configuration documents are locally valid. This projection grants no runtime execution authority.";
}

/**
 * Reads explicitly supplied deployment references and projects only
 * secret-free integrity metadata. It does not retain loaded document bodies,
 * construct adapters, mutate readiness, or authorize any execution path.
 */
export function projectTrustedRuntimeConfigurationReadiness(
  references: TrustedRuntimeConfigurationReferences | undefined,
  clock: () => Date = () => new Date(),
): TrustedRuntimeConfigurationReadiness {
  const documents = Object.freeze({
    planningPolicy: planningPolicy(references?.planningPolicy),
    runtimeSourceManifests: runtimeSourceManifests(references?.runtimeSourceManifests),
    workspaceMappings: workspaceMappings(references?.workspaceMappings),
  });
  const status = overallStatus(documents);
  return Object.freeze({
    schemaVersion: TRUSTED_RUNTIME_CONFIGURATION_READINESS_SCHEMA_VERSION,
    status,
    configured: status !== "unconfigured",
    complete: status === "valid",
    reason: overallReason(status),
    checkedAt: clock().toISOString(),
    documents,
    executionAuthorized: false,
    plannerMounted: false,
    providerExecutionMounted: false,
    specialistExecutionMounted: false,
    toolExecutionMounted: false,
  });
}
