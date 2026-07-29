import type { Migration } from "../types";
import { coreMigration } from "./001_core";
import { memoryLearningMigration } from "./002_memory_learning";
import { searchMigration } from "./003_search";
import { evidenceIntegrityMigration } from "./004_evidence_integrity";
import { attackChainLearningMigration } from "./005_attack_chain_learning";
import { runEvaluationComparisonsMigration } from "./006_run_evaluation_comparisons";
import { auditJourneyMigration } from "./007_audit_journey";
import { followUpContextMigration } from "./008_follow_up_context";
import { guidedDecisionBoundaryMigration } from "./009_guided_decision_boundary";
import { v24OperationalTruthMigration } from "./010_v24_operational_truth";
import { memoryEdgeScopeMigration } from "./011_memory_edge_scope";
import { planningRetryContinuationMigration } from "./012_planning_retry_continuation";
import { importedLegacyControlPlaneMigration } from "./013_imported_legacy_control_plane";
import { providerTurnExactUsageMigration } from "./014_provider_turn_exact_usage";
import { providerRequestAuthorizationMigration } from "./015_provider_request_authorization";
import { planContentFingerprintMigration } from "./016_plan_content_fingerprint";
import { terminalMemoryProjectionContinuationMigration } from "./017_terminal_memory_projection_continuation";
import { attackCentricReusableMemoryMigration } from "./018_attack_centric_reusable_memory";
import { attackAttemptKnowledgeContextMigration } from "./019_attack_attempt_knowledge_context";
import { attackKnowledgeCompilerMigration } from "./020_attack_knowledge_compiler";
import { reusableMemoryEdgePrivacyBoundaryMigration } from "./021_reusable_memory_edge_privacy_boundary";
import { operationalHazardHealthGateMigration } from "./022_operational_hazard_health_gate";
import { attackKnowledgePromotionMigration } from "./023_attack_knowledge_promotion";
import { operationalHazardObservationsMigration } from "./024_operational_hazard_observations";
import { attackKnowledgeEvidenceBindingsMigration } from "./025_attack_knowledge_evidence_bindings";
import { historicalHazardEvidenceStagingMigration } from "./026_historical_hazard_evidence_staging";
import { receiptBackedHazardOccurrenceCountMigration } from "./027_receipt_backed_hazard_occurrence_count";
import { operationalHazardRetryContractMigration } from "./028_operational_hazard_retry_contract";
import { historicalAttackKnowledgeSourceCustodyMigration } from "./029_historical_attack_knowledge_source_custody";
import { historicalAttackKnowledgeBatchPromotionMigration } from "./030_historical_attack_knowledge_batch_promotion";
import { legacyMigrationReconciliationIntegrityMigration } from "./031_legacy_migration_reconciliation_integrity";
import { historicalMigrationSettledSourceBoundaryMigration } from "./032_historical_migration_settled_source_boundary";
import { reusableKnowledgeOutcomesMigration } from "./033_reusable_knowledge_outcomes";
import { privateSourceCustodyAndOperatorGraphMigration } from "./034_private_source_custody_and_operator_graph";
import { canonicalDatabaseLeasesMigration } from "./035_canonical_database_leases";
import { vaultProvenanceSyncInvalidationMigration } from "./036_vault_provenance_sync_invalidation";
import { existingVaultProvenanceReconciliationMigration } from "./037_existing_vault_provenance_reconciliation";
import { startupReadinessAuditClassificationMigration } from "./038_startup_readiness_audit_classification";
import { brainProvenanceSourceLookupMigration } from "./039_brain_provenance_source_lookup";
import { historicalReportedOutcomesMigration } from "./040_historical_reported_outcomes";
import { historicalReportedOutcomeTwoHashCustodyMigration } from "./041_historical_reported_outcome_two_hash_custody";
import { historicalReportedOutcomeProjectionLookupMigration } from "./042_historical_reported_outcome_projection_lookup";
import { autonomousRecoveryMemoryReceiptsMigration } from "./043_autonomous_recovery_memory_receipts";
import { exploitOutcomeObserverSpecsMigration } from "./044_exploit_outcome_observer_specs";
import {
  candidateLinuxPostExploitSessionsMigration,
} from "./045_candidate_linux_post_exploit_sessions";
import {
  candidateLinuxPostExploitIntegrityMigration,
} from "./046_candidate_linux_post_exploit_integrity";
import {
  modelAssignmentPreferencesMigration,
} from "./047_model_assignment_preferences";
import {
  providerTurnAgentBindingMigration,
} from "./048_provider_turn_agent_binding";
import {
  cveApplicabilityReviewLifecycleMigration,
} from "./049_cve_applicability_review_lifecycle";
import {
  researchPromotionLifecycleMigration,
} from "./050_research_promotion_lifecycle";
import {
  planChangeInflightResolutionMigration,
} from "./051_plan_change_inflight_resolution";
import {
  researchExecutionBoundaryMigration,
} from "./052_research_execution_boundary";
import {
  researchPromotionDecisionFingerprintMigration,
} from "./053_research_promotion_decision_fingerprint";
import {
  researchExecutionIntegrityMigration,
} from "./054_research_execution_integrity";
import {
  researchHistoryIntegrityMigration,
} from "./055_research_history_integrity";
import {
  privateResearchHoldoutExecutionMigration,
} from "./056_private_research_holdout_execution";
import {
  modelAssignmentPurposeMigration,
} from "./057_model_assignment_purpose";
import {
  autonomousActivationReceiptsMigration,
} from "./058_autonomous_activation_receipts";
import {
  providerAdvisoryDisclosureModeMigration,
} from "./059_provider_advisory_disclosure_mode";
import {
  autonomousActivationBindingSubjectUniquenessMigration,
} from "./060_autonomous_activation_binding_subject_uniqueness";
import {
  specialistAdvisoryModelPreferencesMigration,
} from "./061_specialist_advisory_model_preferences";
import {
  runScopedCandidateLinuxProcedureActivationsMigration,
} from "./062_run_scoped_candidate_linux_procedure_activations";
import {
  reviewedCandidateLinuxProcedureAdmissionsMigration,
} from "./063_reviewed_candidate_linux_procedure_admissions";

export const DATABASE_MIGRATIONS: readonly Migration[] = Object.freeze([
  coreMigration,
  memoryLearningMigration,
  searchMigration,
  evidenceIntegrityMigration,
  attackChainLearningMigration,
  runEvaluationComparisonsMigration,
  auditJourneyMigration,
  followUpContextMigration,
  guidedDecisionBoundaryMigration,
  v24OperationalTruthMigration,
  memoryEdgeScopeMigration,
  planningRetryContinuationMigration,
  importedLegacyControlPlaneMigration,
  providerTurnExactUsageMigration,
  providerRequestAuthorizationMigration,
  planContentFingerprintMigration,
  terminalMemoryProjectionContinuationMigration,
  attackCentricReusableMemoryMigration,
  attackAttemptKnowledgeContextMigration,
  attackKnowledgeCompilerMigration,
  reusableMemoryEdgePrivacyBoundaryMigration,
  operationalHazardHealthGateMigration,
  attackKnowledgePromotionMigration,
  operationalHazardObservationsMigration,
  attackKnowledgeEvidenceBindingsMigration,
  historicalHazardEvidenceStagingMigration,
  receiptBackedHazardOccurrenceCountMigration,
  operationalHazardRetryContractMigration,
  historicalAttackKnowledgeSourceCustodyMigration,
  historicalAttackKnowledgeBatchPromotionMigration,
  legacyMigrationReconciliationIntegrityMigration,
  historicalMigrationSettledSourceBoundaryMigration,
  reusableKnowledgeOutcomesMigration,
  privateSourceCustodyAndOperatorGraphMigration,
  canonicalDatabaseLeasesMigration,
  vaultProvenanceSyncInvalidationMigration,
  existingVaultProvenanceReconciliationMigration,
  startupReadinessAuditClassificationMigration,
  brainProvenanceSourceLookupMigration,
  historicalReportedOutcomesMigration,
  historicalReportedOutcomeTwoHashCustodyMigration,
  historicalReportedOutcomeProjectionLookupMigration,
  autonomousRecoveryMemoryReceiptsMigration,
  exploitOutcomeObserverSpecsMigration,
  candidateLinuxPostExploitSessionsMigration,
  candidateLinuxPostExploitIntegrityMigration,
  modelAssignmentPreferencesMigration,
  providerTurnAgentBindingMigration,
  cveApplicabilityReviewLifecycleMigration,
  researchPromotionLifecycleMigration,
  planChangeInflightResolutionMigration,
  researchExecutionBoundaryMigration,
  researchPromotionDecisionFingerprintMigration,
  researchExecutionIntegrityMigration,
  researchHistoryIntegrityMigration,
  privateResearchHoldoutExecutionMigration,
  modelAssignmentPurposeMigration,
  autonomousActivationReceiptsMigration,
  providerAdvisoryDisclosureModeMigration,
  autonomousActivationBindingSubjectUniquenessMigration,
  specialistAdvisoryModelPreferencesMigration,
  runScopedCandidateLinuxProcedureActivationsMigration,
  reviewedCandidateLinuxProcedureAdmissionsMigration,
]);
