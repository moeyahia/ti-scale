export { LegacyMigrationService, restoreMigrationBackup } from "./LegacyMigrationService";
export { LegacyImporter } from "./LegacyImporter";
export { MigrationMetadataRepository } from "./MigrationMetadataRepository";
export { discoverLegacySources } from "./SourceDiscovery";
export {
  canonicalizeLegacySourceRoots,
  discoverLegacyEngagements,
  LEGACY_ENGAGEMENT_FILE_KINDS,
} from "./LegacyEngagementDiscovery";
export { LegacyEngagementImporter, ensureLegacyEngagementSchema } from "./LegacyEngagementImporter";
export { LegacyEngagementBrainProjector } from "./LegacyEngagementBrainProjector";
export { ApprovedLegacyVaultProjectionService } from "./ApprovedLegacyVaultProjectionService";
export type {
  CanonicalLegacyRoots,
  CanonicalLegacyRoot,
  LegacyRootAlias,
  LegacyEngagementDiscovery,
  LegacyEngagementFile,
  LegacyEngagementFileKind,
  LegacyEngagementManifest,
} from "./LegacyEngagementDiscovery";
export type {
  LegacyEngagementBrainProjectionInput,
  LegacyEngagementBrainProjectionResult,
  LegacyEngagementProjectionArtifact,
} from "./LegacyEngagementBrainProjector";
export type {
  ApprovedLegacyVaultProjectionInput,
  ApprovedLegacyVaultProjectionResult,
} from "./ApprovedLegacyVaultProjectionService";
export { redactLegacyText, redactRecursively } from "./SecretSafety";
export type {
  LegacyMigrationOptions,
  LegacyMigrationResult,
  LegacySource,
  LegacySourceType,
  ReconciliationReport,
  SourceInventory,
  SourceMigrationResult,
} from "./types";
