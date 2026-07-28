import { hashCanonical } from "../missions/canonical";
import type { StoredModelConfiguration } from "./types";

export const MODEL_CONFIGURATION_BINDING_HASH_SCHEMA_VERSION =
  "ti-scale.model-configuration-binding-hash.v2" as const;

/**
 * Hashes the complete immutable catalog snapshot selected by a model
 * assignment. Provider request hashes remain separate: this digest binds the
 * assignment to the exact configuration ID, provider/model/reasoning tuple,
 * capabilities, policy, readiness snapshot, and stored version.
 */
export function modelConfigurationBindingHash(
  configuration: StoredModelConfiguration,
): string {
  return hashCanonical({
    schemaVersion: MODEL_CONFIGURATION_BINDING_HASH_SCHEMA_VERSION,
    configurationId: configuration.id,
    providerId: configuration.providerId,
    modelId: configuration.modelId,
    displayName: configuration.displayName,
    executionBoundary: configuration.executionBoundary,
    reasoningEffort: configuration.reasoningEffort,
    contextPolicy: configuration.contextPolicy,
    capabilities: configuration.capabilities,
    contextLimit: configuration.contextLimit,
    costClass: configuration.costClass,
    latencyClass: configuration.latencyClass,
    disclosureClass: configuration.disclosureClass,
    enforcementMode: configuration.enforcementMode,
    authState: configuration.authState,
    healthState: configuration.healthState,
    catalogSource: configuration.catalogSource,
    catalogRetrievedAt: configuration.catalogRetrievedAt,
    configurationSource: configuration.configurationSource,
    version: configuration.version,
    createdAt: configuration.createdAt,
    updatedAt: configuration.updatedAt,
  });
}
