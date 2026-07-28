export {
  ObsidianVaultBridge,
  VaultBulkExportAbortError,
  VaultBulkExportPolicyError,
} from "./ObsidianVaultBridge";
export {
  MAX_PROJECTED_PRIVATE_PROVENANCE_IDS,
  OBSIDIAN_V2_4_VAULT_FOLDERS,
  PRIVATE_PROVENANCE_SCHEMA,
  escapeObsidianSingleLineText,
  normalizeObsidianWikilinkTarget,
  parseObsidianNote,
  projectPrivateProvenanceIds,
  renderObsidianNote,
  vaultRelativePath,
} from "./ObsidianMarkdown";
export { obsidianDeepLink } from "./ObsidianDeepLink";
export { ObsidianVaultWatcher } from "./ObsidianVaultWatcher";
export { VaultRecoveryRepository } from "./VaultRecoveryRepository";
export { VaultRecoveryService } from "./VaultRecoveryService";
export {
  VaultConnectionLifecycleService,
  VaultConnectionAlreadyDisconnectedError,
  VaultConnectionVersionConflictError,
  VaultLastHealthyConnectionError,
  type VaultDisconnectResult,
} from "./VaultConnectionLifecycleService";
export * from "./AttackKnowledgeVaultPreset";
export * from "./AttackKnowledgeVaultPolicyService";
export * from "./OperatorProfileVaultProjection";
export * from "./AttackBrainAtlasMappingRegistry";
export * from "./BrainAtlasProfile";
export * from "./ObsidianPluginManager";
export {
  ConnectedVaultMemoryProjector,
  type ConnectedVaultProjectionReport,
  type ConnectedVaultRevocationReport,
} from "./ConnectedVaultMemoryProjector";
export {
  VaultProjectionReconciliationService,
  type ExecuteVaultProjectionInput,
  type VaultProjectionIssue,
  type VaultProjectionPreview,
  type VaultProjectionReceipt,
  type VaultProjectionReconciliation,
} from "./VaultProjectionReconciliationService";
export {
  VaultPathPolicy,
  VaultRoundTripHealthError,
  safeVaultSegment,
  type VaultRoundTripHealth,
} from "./VaultPathPolicy";
export * from "./types";
