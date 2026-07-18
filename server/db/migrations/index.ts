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
]);
