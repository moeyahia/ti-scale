export { LegacyMigrationService } from "./LegacyMigrationService";
export { LegacyImporter } from "./LegacyImporter";
export { MigrationMetadataRepository } from "./MigrationMetadataRepository";
export { discoverLegacySources } from "./SourceDiscovery";
export {
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION,
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
  HISTORICAL_SOURCE_ROOT_MODES,
  loadTrustedHistoricalSourceRootConfiguration,
  parseHistoricalSourceRootConfiguration,
  requiredHistoricalParentRoots,
  resolveRequiredHistoricalSourceRoots,
  type HistoricalSourceRootConfiguration,
  type HistoricalSourceRootDefinition,
  type HistoricalSourceRootMode,
  type ResolvedHistoricalSourceRoots,
} from "./HistoricalSourceRootConfiguration";
export {
  canonicalizeLegacySourceRoots,
  discoverLegacyEngagements,
  LEGACY_ENGAGEMENT_FILE_KINDS,
} from "./LegacyEngagementDiscovery";
export { LegacyEngagementImporter, ensureLegacyEngagementSchema } from "./LegacyEngagementImporter";
export { LegacyEngagementBrainProjector } from "./LegacyEngagementBrainProjector";
export { ApprovedLegacyVaultProjectionService } from "./ApprovedLegacyVaultProjectionService";
export * from "./AttackKnowledgeCompiler";
export * from "./AttackKnowledgePromotionService";
export * from "./AttackKnowledgePromotionRouter";
export * from "./HistoricalHazardEvidenceImportService";
export * from "./HistoricalAttackKnowledgeExtractionService";
export * from "./HistoricalReusableKnowledgeLinkRepairService";
export * from "./HistoricalBundleEdgeBindingReconciliationService";
export * from "./HistoricalAttackKnowledgeBatchPromotionService";
export * from "./HistoricalAttackKnowledgeConfirmationService";
export * from "./HistoricalAttackKnowledgeConfirmationOrchestrator";
export * from "./HistoricalResidualCandidateSuppressionService";
export * from "./GenericHistoricalAttackKnowledgeIngestionService";
export * from "./HistoricalAttackKnowledgeExtractionReconciliationService";
export * from "./CompletedHistoricalExtractionSealService";
export * from "./BoundedHistoricalAttackKnowledgeResumeService";
export * from "./FailedLegacyMigrationReconciliationService";
export * from "./OrphanedHistoricalMigrationLeaseReleaseService";
export * from "./HistoricalSourceDeltaPlanner";
export * from "./HistoricalSourceDeltaExecutionPlan";
export {
  HISTORICAL_SQLITE_SNAPSHOT_DISABLED_ERROR,
  HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION,
  HISTORICAL_SQLITE_SOURCE_ATTESTATION_SCHEMA_VERSION,
  inspectHistoricalSqliteSource,
  type HistoricalSqliteAbsentFileIdentity,
  type HistoricalSqliteFileIdentity,
  type HistoricalSqliteOpenHandleCheck,
  type HistoricalSqliteOpenHandleInspector,
  type HistoricalSqlitePresentFileIdentity,
  type HistoricalSqliteSnapshotOptions,
  type HistoricalSqliteSnapshotReceipt,
  type HistoricalSqliteSnapshotResult,
  type HistoricalSqliteSourceAttestation,
} from "./HistoricalSqliteSnapshotService";
export * from "./HistoricalReportedOutcomeClassificationService";
export * from "./HistoricalExecutableScriptPromotionService";
export * from "./LocalHistoricalExecutableScriptValidator";
export type {
  CanonicalLegacyRoots,
  CanonicalLegacyRoot,
  LegacyRootAlias,
  LegacyEngagementDiscovery,
  LegacyEngagementExclusion,
  LegacyEngagementExclusionCategory,
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
  LegacySourceDiscoveryCoverage,
  LegacySourceType,
  ReconciliationReport,
  SourceInventory,
  SourceMigrationResult,
} from "./types";
