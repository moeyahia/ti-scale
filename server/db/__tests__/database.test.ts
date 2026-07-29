import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  assertDatabaseIntegrity,
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  getDatabaseHealth,
  listAppliedMigrations,
  migrateDatabase,
} from "../index";
import * as DatabaseBarrel from "../index";
import {
  backupDatabase,
  createTimestampedBackup,
  DATABASE_BACKUP_DISABLED_ERROR,
} from "../backup";
import { WeakStatementRegistry } from "../connection";
import { MemoryRepository } from "../../memory/index";
import { ControlPlaneLeaseError, RunMutationAuthorityGuard } from "../../control-plane";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-db-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function insertMission(
  database: ReturnType<typeof createDatabaseConnection>,
  id: string,
  journey: "autonomous" | "guided" = "autonomous",
): void {
  const now = new Date().toISOString();
  database
    .prepare(`
      INSERT INTO missions (
        id, name, objective, journey, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .run(id, `Mission ${id}`, "Validate the authorized target", journey, "operator", now, now);
}

describe("Ti-Scale database foundation", () => {
  test("applies ordered migrations once and reports a healthy WAL connection", () => {
    const databasePath = join(temporaryDirectory(), "state", "ti-scale.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      const first = migrateDatabase(database);
      const second = migrateDatabase(database);
      const health = getDatabaseHealth(database);

      expect(first.applied.map((migration) => migration.version)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]);
      expect(second.applied).toEqual([]);
      expect(listAppliedMigrations(database)).toHaveLength(63);
      expect(health.healthy).toBe(true);
      expect(health.journalMode).toBe("wal");
      expect(health.foreignKeys).toBe(true);
      expect(health.busyTimeoutMs).toBe(5_000);
      expect(health.currentMigration).toBe(63);
      expect(existsSync(databasePath)).toBe(true);
      expect(database.prepare(`
        SELECT "unique" AS is_unique
        FROM pragma_index_list('autonomous_activation_bindings')
        WHERE name = 'idx_autonomous_activation_binding_subject'
      `).get()).toEqual({ is_unique: 1 });
      expect(database.prepare(`
        SELECT name
        FROM pragma_index_info('idx_autonomous_activation_binding_subject')
        ORDER BY seqno
      `).all()).toEqual([
        { name: "receipt_id" },
        { name: "binding_type" },
        { name: "subject_id" },
      ]);
      const v24Objects = (database.prepare(`
        SELECT type, name FROM sqlite_master
        WHERE name IN (
          'operational_reset_authorizations',
          'operational_reset_control_receipts',
          'operational_hazard_occurrences',
          'operational_hazard_observation_jobs',
          'operational_reset_authorizations_no_update',
          'operational_reset_authorizations_no_delete',
          'operational_reset_control_receipts_no_update',
          'operational_reset_control_receipts_no_delete',
          'operational_hazard_occurrences_no_update',
          'operational_hazard_occurrences_no_delete',
          'attack_knowledge_bundle_evidence_bindings',
          'attack_knowledge_evidence_bindings_no_update',
          'attack_knowledge_evidence_bindings_no_delete',
          'attack_knowledge_promotion_verification_integrity_insert',
          'operational_hazard_receipt_backed_counts',
          'operational_hazard_profiles_receipt_count_insert',
          'operational_hazard_profiles_receipt_count_update',
          'operational_hazard_occurrence_refresh_profile_count'
        ) ORDER BY type, name
      `).all() as Array<{ type: string; name: string }>).map((item) => item.name);
      expect(v24Objects).toEqual([
        'attack_knowledge_bundle_evidence_bindings',
        'operational_hazard_observation_jobs',
        'operational_hazard_occurrences',
        'operational_reset_authorizations',
        'operational_reset_control_receipts',
        'attack_knowledge_evidence_bindings_no_delete',
        'attack_knowledge_evidence_bindings_no_update',
        'attack_knowledge_promotion_verification_integrity_insert',
        'operational_hazard_occurrence_refresh_profile_count',
        'operational_hazard_occurrences_no_delete',
        'operational_hazard_occurrences_no_update',
        'operational_hazard_profiles_receipt_count_insert',
        'operational_hazard_profiles_receipt_count_update',
        'operational_reset_authorizations_no_delete',
        'operational_reset_authorizations_no_update',
        'operational_reset_control_receipts_no_delete',
        'operational_reset_control_receipts_no_update',
        'operational_hazard_receipt_backed_counts',
      ]);
    } finally {
      database.close();
    }
  });

  test("migrates legacy plan hashes into a non-unique content fingerprint while retaining unique version receipts", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    const now = "2026-07-19T05:00:00.000Z";
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS.slice(0, 15));
      insertMission(database, "mission-plan-fingerprint", "guided");
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-plan-fingerprint', 'mission-plan-fingerprint', 'guided', 'queued', ?, ?)
      `).run(now, now);
      database.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, plan_hash,
          created_by, created_at
        ) VALUES ('plan-fingerprint-v1', 'run-plan-fingerprint', 1,
          'superseded', 'Historical strategy', ?, 'planner:test', ?)
      `).run("a".repeat(64), now);

      expect(migrateDatabase(database)).toMatchObject({
        applied: [
          { version: 16, name: "plan_content_fingerprint" },
          { version: 17, name: "terminal_memory_projection_continuation" },
          { version: 18, name: "attack_centric_reusable_memory" },
          { version: 19, name: "attack_attempt_knowledge_context" },
          { version: 20, name: "attack_knowledge_compiler" },
          { version: 21, name: "reusable_memory_edge_privacy_boundary" },
          { version: 22, name: "operational_hazard_health_gate" },
          { version: 23, name: "attack_knowledge_promotion" },
          { version: 24, name: "operational_hazard_observations" },
          { version: 25, name: "attack_knowledge_evidence_bindings" },
          { version: 26, name: "historical_hazard_evidence_staging" },
          { version: 27, name: "receipt_backed_hazard_occurrence_count" },
          { version: 28, name: "operational_hazard_retry_contract" },
          { version: 29, name: "historical_attack_knowledge_source_custody" },
          { version: 30, name: "historical_attack_knowledge_batch_promotion" },
          { version: 31, name: "legacy_migration_reconciliation_integrity" },
          { version: 32, name: "historical_migration_settled_source_boundary" },
          { version: 33, name: "reusable_knowledge_outcomes" },
          { version: 34, name: "private_source_custody_and_operator_graph" },
          { version: 35, name: "canonical_database_leases" },
          { version: 36, name: "vault_provenance_sync_invalidation" },
          { version: 37, name: "existing_vault_provenance_reconciliation" },
          { version: 38, name: "startup_readiness_audit_classification" },
          { version: 39, name: "brain_provenance_source_lookup" },
          { version: 40, name: "historical_reported_outcomes" },
          { version: 41, name: "historical_reported_outcome_two_hash_custody" },
          { version: 42, name: "historical_reported_outcome_projection_lookup" },
          { version: 43, name: "autonomous_recovery_memory_receipts" },
          { version: 44, name: "exploit_outcome_observer_specs" },
          { version: 45, name: "candidate_linux_post_exploit_sessions" },
          { version: 46, name: "candidate_linux_post_exploit_integrity" },
          { version: 47, name: "model_assignment_preferences" },
          { version: 48, name: "provider_turn_agent_binding" },
          { version: 49, name: "cve_applicability_review_lifecycle" },
          { version: 50, name: "research_promotion_lifecycle" },
          { version: 51, name: "plan_change_inflight_resolution" },
          { version: 52, name: "research_execution_boundary" },
          { version: 53, name: "research_promotion_decision_fingerprint" },
          { version: 54, name: "research_execution_integrity" },
          { version: 55, name: "research_history_integrity" },
          { version: 56, name: "private_research_holdout_execution" },
          { version: 57, name: "model_assignment_purpose" },
          { version: 58, name: "autonomous_activation_receipts" },
          { version: 59, name: "provider_advisory_disclosure_mode" },
          { version: 60, name: "autonomous_activation_binding_subject_uniqueness" },
          { version: 61, name: "specialist_advisory_model_preferences" },
          { version: 62, name: "run_scoped_candidate_linux_procedure_activations" },
          { version: 63, name: "reviewed_candidate_linux_procedure_admissions" },
        ],
        currentVersion: 63,
      });
      expect(database.prepare(`
        SELECT plan_hash, content_hash, content_hash_version
        FROM plans WHERE id = 'plan-fingerprint-v1'
      `).get()).toEqual({
        plan_hash: "a".repeat(64),
        content_hash: "a".repeat(64),
        content_hash_version: 0,
      });
      database.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, plan_hash,
          content_hash, content_hash_version, created_by, created_at
        ) VALUES ('plan-fingerprint-v2', 'run-plan-fingerprint', 2,
          'active', 'Historical strategy', ?, ?, 1, 'operator:test', ?)
      `).run("b".repeat(64), "a".repeat(64), now);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM plans
        WHERE run_id = 'run-plan-fingerprint' AND content_hash = ?
      `).get("a".repeat(64))).toEqual({ count: 2 });
    } finally {
      database.close();
    }
  });

  test("repairs only unambiguously imported ownership and rejects V2 mutation until explicit transfer", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    const importedMissionId = `mission_legacy_${"a".repeat(40)}`;
    const importedRunId = `run_legacy_${"b".repeat(40)}`;
    const engagementMissionId = `mission_engagement_legacy_${"c".repeat(40)}`;
    const engagementRunId = `run_engagement_legacy_${"d".repeat(40)}`;
    const nativeMissionId = "mission-v2-native-control-plane";
    const nativeRunId = "run-v2-native-control-plane";
    const provenanceSpoofMissionId = "mission-operator-owned-legacy-shaped-run";
    const provenanceSpoofRunId = `run_legacy_${"e".repeat(40)}`;
    const now = "2026-07-17T09:00:00.000Z";
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS.slice(0, 12));
      for (const [missionId, createdBy] of [
        [importedMissionId, "import:legacy"],
        [engagementMissionId, "import:legacy-engagement"],
        [nativeMissionId, "operator:local"],
        [provenanceSpoofMissionId, "operator:local"],
      ] as const) {
        insertMission(database, missionId, "guided");
        database.prepare("UPDATE missions SET created_by = ? WHERE id = ?").run(createdBy, missionId);
      }
      const insertRun = database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, lease_owner, lease_acquired_at,
          last_heartbeat_at, lease_expires_at, created_at, updated_at,
          version, control_plane
        ) VALUES (?, ?, 'guided', 'completed', ?, ?, ?, ?, ?, ?, 1, 'ti_scale')
      `);
      insertRun.run(importedRunId, importedMissionId, "worker-imported", now, now, "2026-07-17T10:00:00.000Z", now, now);
      insertRun.run(engagementRunId, engagementMissionId, null, null, null, null, now, now);
      insertRun.run(nativeRunId, nativeMissionId, null, null, null, null, now, now);
      insertRun.run(provenanceSpoofRunId, provenanceSpoofMissionId, null, null, null, null, now, now);
      database.prepare(`
        INSERT INTO control_plane_leases (
          run_id, control_plane, lease_owner, lease_token_hash, acquired_at,
          heartbeat_at, expires_at, released_at, version
        ) VALUES (?, 'ti_scale', 'worker-imported', ?, ?, ?, ?, NULL, 1)
      `).run(importedRunId, "f".repeat(64), now, now, "2026-07-17T10:00:00.000Z");

      expect(migrateDatabase(database)).toMatchObject({
        applied: [
          { version: 13, name: "imported_legacy_control_plane" },
          { version: 14, name: "provider_turn_exact_usage" },
          { version: 15, name: "provider_request_authorization" },
          { version: 16, name: "plan_content_fingerprint" },
          { version: 17, name: "terminal_memory_projection_continuation" },
          { version: 18, name: "attack_centric_reusable_memory" },
          { version: 19, name: "attack_attempt_knowledge_context" },
          { version: 20, name: "attack_knowledge_compiler" },
          { version: 21, name: "reusable_memory_edge_privacy_boundary" },
          { version: 22, name: "operational_hazard_health_gate" },
          { version: 23, name: "attack_knowledge_promotion" },
          { version: 24, name: "operational_hazard_observations" },
          { version: 25, name: "attack_knowledge_evidence_bindings" },
          { version: 26, name: "historical_hazard_evidence_staging" },
          { version: 27, name: "receipt_backed_hazard_occurrence_count" },
          { version: 28, name: "operational_hazard_retry_contract" },
          { version: 29, name: "historical_attack_knowledge_source_custody" },
          { version: 30, name: "historical_attack_knowledge_batch_promotion" },
          { version: 31, name: "legacy_migration_reconciliation_integrity" },
          { version: 32, name: "historical_migration_settled_source_boundary" },
          { version: 33, name: "reusable_knowledge_outcomes" },
          { version: 34, name: "private_source_custody_and_operator_graph" },
          { version: 35, name: "canonical_database_leases" },
          { version: 36, name: "vault_provenance_sync_invalidation" },
          { version: 37, name: "existing_vault_provenance_reconciliation" },
          { version: 38, name: "startup_readiness_audit_classification" },
          { version: 39, name: "brain_provenance_source_lookup" },
          { version: 40, name: "historical_reported_outcomes" },
          { version: 41, name: "historical_reported_outcome_two_hash_custody" },
          { version: 42, name: "historical_reported_outcome_projection_lookup" },
          { version: 43, name: "autonomous_recovery_memory_receipts" },
          { version: 44, name: "exploit_outcome_observer_specs" },
          { version: 45, name: "candidate_linux_post_exploit_sessions" },
          { version: 46, name: "candidate_linux_post_exploit_integrity" },
          { version: 47, name: "model_assignment_preferences" },
          { version: 48, name: "provider_turn_agent_binding" },
          { version: 49, name: "cve_applicability_review_lifecycle" },
          { version: 50, name: "research_promotion_lifecycle" },
          { version: 51, name: "plan_change_inflight_resolution" },
          { version: 52, name: "research_execution_boundary" },
          { version: 53, name: "research_promotion_decision_fingerprint" },
          { version: 54, name: "research_execution_integrity" },
          { version: 55, name: "research_history_integrity" },
          { version: 56, name: "private_research_holdout_execution" },
          { version: 57, name: "model_assignment_purpose" },
          { version: 58, name: "autonomous_activation_receipts" },
          { version: 59, name: "provider_advisory_disclosure_mode" },
          { version: 60, name: "autonomous_activation_binding_subject_uniqueness" },
          { version: 61, name: "specialist_advisory_model_preferences" },
          { version: 62, name: "run_scoped_candidate_linux_procedure_activations" },
          { version: 63, name: "reviewed_candidate_linux_procedure_admissions" },
        ],
        currentVersion: 63,
      });
      expect(database.prepare(`
        SELECT id, control_plane FROM missions ORDER BY id
      `).all()).toEqual([
        { id: engagementMissionId, control_plane: "legacy" },
        { id: importedMissionId, control_plane: "legacy" },
        { id: provenanceSpoofMissionId, control_plane: "ti_scale" },
        { id: nativeMissionId, control_plane: "ti_scale" },
      ].sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
      expect(database.prepare(`
        SELECT id, control_plane, lease_owner, lease_acquired_at,
          last_heartbeat_at, lease_expires_at
        FROM runs ORDER BY id
      `).all()).toEqual([
        { id: engagementRunId, control_plane: "legacy", lease_owner: null, lease_acquired_at: null, last_heartbeat_at: null, lease_expires_at: null },
        { id: importedRunId, control_plane: "legacy", lease_owner: null, lease_acquired_at: null, last_heartbeat_at: null, lease_expires_at: null },
        { id: provenanceSpoofRunId, control_plane: "ti_scale", lease_owner: null, lease_acquired_at: null, last_heartbeat_at: null, lease_expires_at: null },
        { id: nativeRunId, control_plane: "ti_scale", lease_owner: null, lease_acquired_at: null, last_heartbeat_at: null, lease_expires_at: null },
      ].sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
      expect(database.prepare(`
        SELECT control_plane, released_at IS NOT NULL AS released, version
        FROM control_plane_leases WHERE run_id = ?
      `).get(importedRunId)).toEqual({ control_plane: "legacy", released: 1, version: 2 });

      const authority = new RunMutationAuthorityGuard(database);
      try {
        authority.authorize({ runId: importedRunId, actorId: "operator-test", mode: "ownership" });
        throw new Error("Expected imported run ownership to fail closed");
      } catch (error) {
        expect(error).toBeInstanceOf(ControlPlaneLeaseError);
        expect((error as ControlPlaneLeaseError).code).toBe("control_plane_mismatch");
      }
      expect(authority.authorize({
        runId: nativeRunId,
        actorId: "operator-test",
        mode: "ownership",
      }).scope).toEqual({ missionId: nativeMissionId, runId: nativeRunId });

      // Represents the separately authorized transfer transaction. Once the
      // one-time migration is recorded, restarts do not infer or undo it.
      database.prepare("UPDATE missions SET control_plane = 'ti_scale', version = version + 1 WHERE id = ?")
        .run(importedMissionId);
      database.prepare("UPDATE runs SET control_plane = 'ti_scale', version = version + 1 WHERE id = ?")
        .run(importedRunId);
      expect(migrateDatabase(database).applied).toEqual([]);
      expect(authority.authorize({
        runId: importedRunId,
        actorId: "operator-test",
        mode: "ownership",
      }).scope).toEqual({ missionId: importedMissionId, runId: importedRunId });
    } finally {
      database.close();
    }
  });

  test("rehearses the schema-eight bridge, then applies the current additive migrations", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      const schemaSeven = DATABASE_MIGRATIONS.slice(0, 7);
      expect(migrateDatabase(database, schemaSeven).currentVersion).toBe(7);
      insertMission(database, "mission-expand-bridge");

      // The compatibility bridge is additive: legacy notification.read_at
      // remains available to a schema-seven binary while the current app uses
      // actor-scoped receipts and the new runtime-continuation records.
      const schemaEight = DATABASE_MIGRATIONS.slice(0, 8);
      const bridge = migrateDatabase(database, schemaEight);
      expect(bridge.applied.map((migration) => migration.version)).toEqual([8]);
      expect(database.prepare("SELECT name FROM missions WHERE id = ?")
        .get("mission-expand-bridge")).toEqual({ name: "Mission mission-expand-bridge" });
      expect(database.prepare(`
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name = 'run_context_selections'
      `).get()).toEqual({ name: "run_context_selections" });
      expect(database.prepare(`
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name = 'notification_read_receipts'
      `).get()).toEqual({ name: "notification_read_receipts" });

      // Re-starting the bridge/full migration set is idempotent. The retained
      // rollback target must know this exact migration checksum.
      expect(migrateDatabase(database, schemaEight)).toEqual({
        applied: [],
        currentVersion: 8,
      });
      expect(() => migrateDatabase(database, schemaSeven)).toThrow(
        "Database contains unknown migration version 8",
      );
      expect(migrateDatabase(database, DATABASE_MIGRATIONS)).toMatchObject({
        applied: [
          { version: 9, name: "guided_decision_single_pending_boundary" },
          { version: 10, name: "v24_operational_truth" },
          { version: 11, name: "memory_edge_scope_identity" },
          { version: 12, name: "planning_retry_continuation" },
          { version: 13, name: "imported_legacy_control_plane" },
          { version: 14, name: "provider_turn_exact_usage" },
          { version: 15, name: "provider_request_authorization" },
          { version: 16, name: "plan_content_fingerprint" },
          { version: 17, name: "terminal_memory_projection_continuation" },
          { version: 18, name: "attack_centric_reusable_memory" },
          { version: 19, name: "attack_attempt_knowledge_context" },
          { version: 20, name: "attack_knowledge_compiler" },
          { version: 21, name: "reusable_memory_edge_privacy_boundary" },
          { version: 22, name: "operational_hazard_health_gate" },
          { version: 23, name: "attack_knowledge_promotion" },
          { version: 24, name: "operational_hazard_observations" },
          { version: 25, name: "attack_knowledge_evidence_bindings" },
          { version: 26, name: "historical_hazard_evidence_staging" },
          { version: 27, name: "receipt_backed_hazard_occurrence_count" },
          { version: 28, name: "operational_hazard_retry_contract" },
          { version: 29, name: "historical_attack_knowledge_source_custody" },
          { version: 30, name: "historical_attack_knowledge_batch_promotion" },
          { version: 31, name: "legacy_migration_reconciliation_integrity" },
          { version: 32, name: "historical_migration_settled_source_boundary" },
          { version: 33, name: "reusable_knowledge_outcomes" },
          { version: 34, name: "private_source_custody_and_operator_graph" },
          { version: 35, name: "canonical_database_leases" },
          { version: 36, name: "vault_provenance_sync_invalidation" },
          { version: 37, name: "existing_vault_provenance_reconciliation" },
          { version: 38, name: "startup_readiness_audit_classification" },
          { version: 39, name: "brain_provenance_source_lookup" },
          { version: 40, name: "historical_reported_outcomes" },
          { version: 41, name: "historical_reported_outcome_two_hash_custody" },
          { version: 42, name: "historical_reported_outcome_projection_lookup" },
          { version: 43, name: "autonomous_recovery_memory_receipts" },
          { version: 44, name: "exploit_outcome_observer_specs" },
          { version: 45, name: "candidate_linux_post_exploit_sessions" },
          { version: 46, name: "candidate_linux_post_exploit_integrity" },
          { version: 47, name: "model_assignment_preferences" },
          { version: 48, name: "provider_turn_agent_binding" },
          { version: 49, name: "cve_applicability_review_lifecycle" },
          { version: 50, name: "research_promotion_lifecycle" },
          { version: 51, name: "plan_change_inflight_resolution" },
          { version: 52, name: "research_execution_boundary" },
          { version: 53, name: "research_promotion_decision_fingerprint" },
          { version: 54, name: "research_execution_integrity" },
          { version: 55, name: "research_history_integrity" },
          { version: 56, name: "private_research_holdout_execution" },
          { version: 57, name: "model_assignment_purpose" },
          { version: 58, name: "autonomous_activation_receipts" },
          { version: 59, name: "provider_advisory_disclosure_mode" },
          { version: 60, name: "autonomous_activation_binding_subject_uniqueness" },
          { version: 61, name: "specialist_advisory_model_preferences" },
          { version: 62, name: "run_scoped_candidate_linux_procedure_activations" },
          { version: 63, name: "reviewed_candidate_linux_procedure_admissions" },
        ],
        currentVersion: 63,
      });
      expect(getDatabaseHealth(database)).toMatchObject({
        healthy: true,
        currentMigration: 63,
      });
    } finally {
      database.close();
    }
  });

  test("upgrades a persisted pre-v11 memory graph without inventing unrecoverable edge scope IDs", () => {
    const databasePath = join(temporaryDirectory(), "pre-v11", "ti-scale.sqlite");
    const now = "2026-07-15T12:00:00.000Z";
    const provenance = JSON.stringify({
      method: "imported",
      explanation: "Imported from the persisted schema-ten memory graph",
      sources: [{ sourceType: "legacy-v10", sourceId: "memory-edge-scope-regression" }],
    });
    const legacy = createDatabaseConnection({ filename: databasePath });
    try {
      expect(migrateDatabase(legacy, DATABASE_MIGRATIONS.slice(0, 10))).toMatchObject({
        currentVersion: 10,
      });
      expect(listAppliedMigrations(legacy)).toHaveLength(10);
      const preUpgradeColumns = (legacy.pragma("table_info(memory_edges)") as Array<{ name: string }>)
        .map((column) => column.name);
      expect(preUpgradeColumns).not.toContain("engagement_id");
      expect(preUpgradeColumns).not.toContain("mission_id");

      insertMission(legacy, "mission-edge-v11");
      legacy.prepare("UPDATE missions SET engagement_id = ? WHERE id = ?")
        .run("engagement-edge-v11", "mission-edge-v11");
      const insertNode = legacy.prepare(`
        INSERT INTO memory_nodes (
          id, node_type, title, summary, body, scope, engagement_id, mission_id,
          sensitivity, confidence, lifecycle_status, confirmation_state,
          provenance_json, author_type, author_id, version,
          retention_policy_json, expires_at, pinned, created_at, updated_at
        ) VALUES (
          ?, 'asset', ?, 'Persisted schema-ten memory node', '', ?, ?, ?,
          'internal', 0.9, 'confirmed', 'confirmed', ?, 'import',
          'migration-v11-regression', 1, '{}', NULL, 0, ?, ?
        )
      `);
      const nodes = [
        ["node-v11-mission", "Mission-scoped node", "mission", "engagement-edge-v11", "mission-edge-v11"],
        ["node-v11-engagement-a", "Engagement node A", "engagement", "engagement-edge-v11", null],
        ["node-v11-engagement-b", "Engagement node B", "engagement", "engagement-edge-v11", null],
        ["node-v11-global-a", "Global node A", "global", null, null],
        ["node-v11-global-b", "Global node B", "global", null, null],
      ] as const;
      for (const [id, title, scope, engagementId, missionId] of nodes) {
        insertNode.run(id, title, scope, engagementId, missionId, provenance, now, now);
      }

      const insertEdge = legacy.prepare(`
        INSERT INTO memory_edges (
          id, source_node_id, target_node_id, edge_type, title, summary, scope,
          sensitivity, confidence, lifecycle_status, provenance_json,
          explanation, author_type, author_id, version, expires_at,
          created_at, updated_at
        ) VALUES (
          ?, ?, ?, 'supports', ?, 'Persisted schema-ten relationship', ?,
          'internal', 0.9, 'confirmed', ?,
          'The legacy relationship retained only its scope kind', 'import',
          'migration-v11-regression', 1, NULL, ?, ?
        )
      `);
      for (const edge of [
        ["edge-v11-reconstruct-mission", "node-v11-mission", "node-v11-global-a", "Reconstruct mission", "mission"],
        ["edge-v11-reconstruct-engagement", "node-v11-engagement-a", "node-v11-global-a", "Reconstruct engagement", "engagement"],
        ["edge-v11-degrade-engagement", "node-v11-engagement-a", "node-v11-engagement-b", "Degrade to engagement", "mission"],
        ["edge-v11-degrade-global", "node-v11-global-a", "node-v11-global-b", "Degrade to global", "mission"],
      ] as const) {
        insertEdge.run(...edge, provenance, now, now);
      }
    } finally {
      legacy.close();
    }

    const upgraded = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(migrateDatabase(upgraded)).toMatchObject({
        applied: [
          { version: 11, name: "memory_edge_scope_identity" },
          { version: 12, name: "planning_retry_continuation" },
          { version: 13, name: "imported_legacy_control_plane" },
          { version: 14, name: "provider_turn_exact_usage" },
          { version: 15, name: "provider_request_authorization" },
          { version: 16, name: "plan_content_fingerprint" },
          { version: 17, name: "terminal_memory_projection_continuation" },
          { version: 18, name: "attack_centric_reusable_memory" },
          { version: 19, name: "attack_attempt_knowledge_context" },
          { version: 20, name: "attack_knowledge_compiler" },
          { version: 21, name: "reusable_memory_edge_privacy_boundary" },
          { version: 22, name: "operational_hazard_health_gate" },
          { version: 23, name: "attack_knowledge_promotion" },
          { version: 24, name: "operational_hazard_observations" },
          { version: 25, name: "attack_knowledge_evidence_bindings" },
          { version: 26, name: "historical_hazard_evidence_staging" },
          { version: 27, name: "receipt_backed_hazard_occurrence_count" },
          { version: 28, name: "operational_hazard_retry_contract" },
          { version: 29, name: "historical_attack_knowledge_source_custody" },
          { version: 30, name: "historical_attack_knowledge_batch_promotion" },
          { version: 31, name: "legacy_migration_reconciliation_integrity" },
          { version: 32, name: "historical_migration_settled_source_boundary" },
          { version: 33, name: "reusable_knowledge_outcomes" },
          { version: 34, name: "private_source_custody_and_operator_graph" },
          { version: 35, name: "canonical_database_leases" },
          { version: 36, name: "vault_provenance_sync_invalidation" },
          { version: 37, name: "existing_vault_provenance_reconciliation" },
          { version: 38, name: "startup_readiness_audit_classification" },
          { version: 39, name: "brain_provenance_source_lookup" },
          { version: 40, name: "historical_reported_outcomes" },
          { version: 41, name: "historical_reported_outcome_two_hash_custody" },
          { version: 42, name: "historical_reported_outcome_projection_lookup" },
          { version: 43, name: "autonomous_recovery_memory_receipts" },
          { version: 44, name: "exploit_outcome_observer_specs" },
          { version: 45, name: "candidate_linux_post_exploit_sessions" },
          { version: 46, name: "candidate_linux_post_exploit_integrity" },
          { version: 47, name: "model_assignment_preferences" },
          { version: 48, name: "provider_turn_agent_binding" },
          { version: 49, name: "cve_applicability_review_lifecycle" },
          { version: 50, name: "research_promotion_lifecycle" },
          { version: 51, name: "plan_change_inflight_resolution" },
          { version: 52, name: "research_execution_boundary" },
          { version: 53, name: "research_promotion_decision_fingerprint" },
          { version: 54, name: "research_execution_integrity" },
          { version: 55, name: "research_history_integrity" },
          { version: 56, name: "private_research_holdout_execution" },
          { version: 57, name: "model_assignment_purpose" },
          { version: 58, name: "autonomous_activation_receipts" },
          { version: 59, name: "provider_advisory_disclosure_mode" },
          { version: 60, name: "autonomous_activation_binding_subject_uniqueness" },
          { version: 61, name: "specialist_advisory_model_preferences" },
          { version: 62, name: "run_scoped_candidate_linux_procedure_activations" },
          { version: 63, name: "reviewed_candidate_linux_procedure_admissions" },
        ],
        currentVersion: 63,
      });
      expect(upgraded.prepare(`
        SELECT id, scope, engagement_id, mission_id
        FROM memory_edges ORDER BY id
      `).all()).toEqual([
        {
          id: "edge-v11-degrade-engagement",
          scope: "engagement",
          engagement_id: "engagement-edge-v11",
          mission_id: null,
        },
        {
          id: "edge-v11-degrade-global",
          scope: "global",
          engagement_id: null,
          mission_id: null,
        },
        {
          id: "edge-v11-reconstruct-engagement",
          scope: "engagement",
          engagement_id: "engagement-edge-v11",
          mission_id: null,
        },
        {
          id: "edge-v11-reconstruct-mission",
          scope: "mission",
          engagement_id: "engagement-edge-v11",
          mission_id: "mission-edge-v11",
        },
      ]);

      const repository = new MemoryRepository(upgraded, {
        clock: () => new Date("2026-07-16T12:00:00.000Z"),
      });
      expect(repository.listEdges("node-v11-mission").map((edge) => ({
        id: edge.id,
        scope: edge.scope,
      }))).toEqual([{
        id: "edge-v11-reconstruct-mission",
        scope: {
          kind: "mission",
          engagementId: "engagement-edge-v11",
          missionId: "mission-edge-v11",
        },
      }]);
      expect(repository.listEdges("node-v11-engagement-b").map((edge) => ({
        id: edge.id,
        scope: edge.scope,
      }))).toEqual([{
        id: "edge-v11-degrade-engagement",
        scope: { kind: "engagement", engagementId: "engagement-edge-v11" },
      }]);
      expect(repository.listEdges("node-v11-global-b").map((edge) => ({
        id: edge.id,
        scope: edge.scope,
      }))).toEqual([{
        id: "edge-v11-degrade-global",
        scope: { kind: "global" },
      }]);
      expect(getDatabaseHealth(upgraded)).toMatchObject({
        healthy: true,
        currentMigration: 63,
      });
    } finally {
      upgraded.close();
    }
  });

  test("widens the continuation kind boundary without losing a schema-eleven owner fence", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      expect(migrateDatabase(database, DATABASE_MIGRATIONS.slice(0, 11))).toMatchObject({
        currentVersion: 11,
      });
      insertMission(database, "mission-continuation-v12");
      const now = "2026-07-17T08:00:00.000Z";
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, budget_json, budget_usage_json,
          created_at, updated_at, version
        ) VALUES ('run-continuation-v12', 'mission-continuation-v12', 'autonomous',
          'planning', '{}', '{}', ?, ?, 1)
      `).run(now, now);
      database.prepare(`
        INSERT INTO runtime_continuations (
          id, run_id, kind, source_id, payload_json, status, attempt_count,
          available_at, lease_owner, lease_expires_at, last_error,
          created_at, updated_at
        ) VALUES (
          'continuation-v11-owned', 'run-continuation-v12',
          'resume_recovery_pending', 'legacy-source', '{"actionId":"action-v11"}',
          'processing', 2, ?, 'worker-v11:continuation-v11-owned:2', ?,
          'redacted prior failure', ?, ?
        )
      `).run(now, "2026-07-17T08:01:00.000Z", now, now);

      expect(migrateDatabase(database)).toMatchObject({
        applied: [
          { version: 12, name: "planning_retry_continuation" },
          { version: 13, name: "imported_legacy_control_plane" },
          { version: 14, name: "provider_turn_exact_usage" },
          { version: 15, name: "provider_request_authorization" },
          { version: 16, name: "plan_content_fingerprint" },
          { version: 17, name: "terminal_memory_projection_continuation" },
          { version: 18, name: "attack_centric_reusable_memory" },
          { version: 19, name: "attack_attempt_knowledge_context" },
          { version: 20, name: "attack_knowledge_compiler" },
          { version: 21, name: "reusable_memory_edge_privacy_boundary" },
          { version: 22, name: "operational_hazard_health_gate" },
          { version: 23, name: "attack_knowledge_promotion" },
          { version: 24, name: "operational_hazard_observations" },
          { version: 25, name: "attack_knowledge_evidence_bindings" },
          { version: 26, name: "historical_hazard_evidence_staging" },
          { version: 27, name: "receipt_backed_hazard_occurrence_count" },
          { version: 28, name: "operational_hazard_retry_contract" },
          { version: 29, name: "historical_attack_knowledge_source_custody" },
          { version: 30, name: "historical_attack_knowledge_batch_promotion" },
          { version: 31, name: "legacy_migration_reconciliation_integrity" },
          { version: 32, name: "historical_migration_settled_source_boundary" },
          { version: 33, name: "reusable_knowledge_outcomes" },
          { version: 34, name: "private_source_custody_and_operator_graph" },
          { version: 35, name: "canonical_database_leases" },
          { version: 36, name: "vault_provenance_sync_invalidation" },
          { version: 37, name: "existing_vault_provenance_reconciliation" },
          { version: 38, name: "startup_readiness_audit_classification" },
          { version: 39, name: "brain_provenance_source_lookup" },
          { version: 40, name: "historical_reported_outcomes" },
          { version: 41, name: "historical_reported_outcome_two_hash_custody" },
          { version: 42, name: "historical_reported_outcome_projection_lookup" },
          { version: 43, name: "autonomous_recovery_memory_receipts" },
          { version: 44, name: "exploit_outcome_observer_specs" },
          { version: 45, name: "candidate_linux_post_exploit_sessions" },
          { version: 46, name: "candidate_linux_post_exploit_integrity" },
          { version: 47, name: "model_assignment_preferences" },
          { version: 48, name: "provider_turn_agent_binding" },
          { version: 49, name: "cve_applicability_review_lifecycle" },
          { version: 50, name: "research_promotion_lifecycle" },
          { version: 51, name: "plan_change_inflight_resolution" },
          { version: 52, name: "research_execution_boundary" },
          { version: 53, name: "research_promotion_decision_fingerprint" },
          { version: 54, name: "research_execution_integrity" },
          { version: 55, name: "research_history_integrity" },
          { version: 56, name: "private_research_holdout_execution" },
          { version: 57, name: "model_assignment_purpose" },
          { version: 58, name: "autonomous_activation_receipts" },
          { version: 59, name: "provider_advisory_disclosure_mode" },
          { version: 60, name: "autonomous_activation_binding_subject_uniqueness" },
          { version: 61, name: "specialist_advisory_model_preferences" },
          { version: 62, name: "run_scoped_candidate_linux_procedure_activations" },
          { version: 63, name: "reviewed_candidate_linux_procedure_admissions" },
        ],
        currentVersion: 63,
      });
      expect(database.prepare(`
        SELECT kind, source_id, payload_json, status, attempt_count,
          available_at, lease_owner, lease_expires_at, last_error
        FROM runtime_continuations WHERE id = 'continuation-v11-owned'
      `).get()).toEqual({
        kind: "resume_recovery_pending",
        source_id: "legacy-source",
        payload_json: '{"actionId":"action-v11"}',
        status: "processing",
        attempt_count: 2,
        available_at: now,
        lease_owner: "worker-v11:continuation-v11-owned:2",
        lease_expires_at: "2026-07-17T08:01:00.000Z",
        last_error: "redacted prior failure",
      });
      expect(() => database.prepare(`
        INSERT INTO runtime_continuations (
          id, run_id, kind, source_id, payload_json, available_at, created_at, updated_at
        ) VALUES (
          'continuation-planning-v12', 'run-continuation-v12',
          'planning_retry_to_dispatch', 'planning-retry-1',
          '{"failureCategory":"rate_limit","retryCount":"1"}', ?, ?, ?
        )
      `).run(now, now, now)).not.toThrow();
    } finally {
      database.close();
    }
  });

  test("cancels ambiguous legacy Guided decisions fail-closed and enforces one pending decision per run", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS.slice(0, 8));
      insertMission(database, "mission-guided-boundary", "guided");
      const now = "2026-07-15T12:00:00.000Z";
      database.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, version, created_at, updated_at
        ) VALUES (
          'agent-guided-boundary', 'specialist', 'Legacy specialist',
          'busy', 'legacy', ?, ?
        )
      `).run(now, now);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, status_reason, created_at, updated_at
        ) VALUES (
          'run-guided-boundary', 'mission-guided-boundary', 'guided',
          'waiting_guided_decision', 'Legacy ambiguous checkpoint', ?, ?
        )
      `).run(now, now);
      database.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, plan_hash,
          created_by, created_at, activated_at
        ) VALUES (
          'plan-guided-boundary', 'run-guided-boundary', 1, 'active',
          'Legacy plan', ?, 'legacy-runtime', ?, ?
        )
      `).run("a".repeat(64), now, now);
      for (const [stepId, ordinal] of [["step-guided-current", 0], ["step-guided-stale", 1]] as const) {
        database.prepare(`
          INSERT INTO plan_steps (
            id, plan_id, run_id, ordinal, phase, title, objective, status,
            created_at, updated_at
          ) VALUES (?, 'plan-guided-boundary', 'run-guided-boundary', ?,
            'reconnaissance', ?, 'Collect one bounded observation',
            'waiting_guided_decision', ?, ?)
        `).run(stepId, ordinal, stepId, now, now);
        database.prepare(`
          INSERT INTO assignments (
            id, run_id, step_id, agent_id, status, lease_owner,
            lease_acquired_at, last_heartbeat_at, lease_expires_at,
            created_at, updated_at
          ) VALUES (?, 'run-guided-boundary', ?, 'agent-guided-boundary', ?,
            'legacy-worker', ?, ?, ?, ?, ?)
        `).run(
          `assignment-${stepId}`,
          stepId,
          ordinal === 0 ? "active" : "queued",
          now,
          now,
          "2026-07-16T12:00:00.000Z",
          now,
          now,
        );
      }
      database.prepare(`
        UPDATE runs SET current_plan_id = 'plan-guided-boundary',
          current_step_id = 'step-guided-current'
        WHERE id = 'run-guided-boundary'
      `).run();
      const insertDecision = database.prepare(`
        INSERT INTO guided_decisions (
          id, mission_id, run_id, step_id, requested_action_fingerprint,
          requested_parameters_json, rationale, risk_class, reversibility,
          status, expires_at, created_at
        ) VALUES (?, 'mission-guided-boundary', 'run-guided-boundary', ?, ?,
          '{}', 'Legacy exact step', 'low', 'Read only', 'pending', ?, ?)
      `);
      insertDecision.run("decision-guided-current", "step-guided-current", "b".repeat(64), "2026-07-16T12:00:00.000Z", now);
      insertDecision.run("decision-guided-stale", "step-guided-stale", "c".repeat(64), "2026-07-16T12:00:00.000Z", now);

      expect(migrateDatabase(database)).toMatchObject({
        applied: [
          { version: 9, name: "guided_decision_single_pending_boundary" },
          { version: 10, name: "v24_operational_truth" },
          { version: 11, name: "memory_edge_scope_identity" },
          { version: 12, name: "planning_retry_continuation" },
          { version: 13, name: "imported_legacy_control_plane" },
          { version: 14, name: "provider_turn_exact_usage" },
          { version: 15, name: "provider_request_authorization" },
          { version: 16, name: "plan_content_fingerprint" },
          { version: 17, name: "terminal_memory_projection_continuation" },
          { version: 18, name: "attack_centric_reusable_memory" },
          { version: 19, name: "attack_attempt_knowledge_context" },
          { version: 20, name: "attack_knowledge_compiler" },
          { version: 21, name: "reusable_memory_edge_privacy_boundary" },
          { version: 22, name: "operational_hazard_health_gate" },
          { version: 23, name: "attack_knowledge_promotion" },
          { version: 24, name: "operational_hazard_observations" },
          { version: 25, name: "attack_knowledge_evidence_bindings" },
          { version: 26, name: "historical_hazard_evidence_staging" },
          { version: 27, name: "receipt_backed_hazard_occurrence_count" },
          { version: 28, name: "operational_hazard_retry_contract" },
          { version: 29, name: "historical_attack_knowledge_source_custody" },
          { version: 30, name: "historical_attack_knowledge_batch_promotion" },
          { version: 31, name: "legacy_migration_reconciliation_integrity" },
          { version: 32, name: "historical_migration_settled_source_boundary" },
          { version: 33, name: "reusable_knowledge_outcomes" },
          { version: 34, name: "private_source_custody_and_operator_graph" },
          { version: 35, name: "canonical_database_leases" },
          { version: 36, name: "vault_provenance_sync_invalidation" },
          { version: 37, name: "existing_vault_provenance_reconciliation" },
          { version: 38, name: "startup_readiness_audit_classification" },
          { version: 39, name: "brain_provenance_source_lookup" },
          { version: 40, name: "historical_reported_outcomes" },
          { version: 41, name: "historical_reported_outcome_two_hash_custody" },
          { version: 42, name: "historical_reported_outcome_projection_lookup" },
          { version: 43, name: "autonomous_recovery_memory_receipts" },
          { version: 44, name: "exploit_outcome_observer_specs" },
          { version: 45, name: "candidate_linux_post_exploit_sessions" },
          { version: 46, name: "candidate_linux_post_exploit_integrity" },
          { version: 47, name: "model_assignment_preferences" },
          { version: 48, name: "provider_turn_agent_binding" },
          { version: 49, name: "cve_applicability_review_lifecycle" },
          { version: 50, name: "research_promotion_lifecycle" },
          { version: 51, name: "plan_change_inflight_resolution" },
          { version: 52, name: "research_execution_boundary" },
          { version: 53, name: "research_promotion_decision_fingerprint" },
          { version: 54, name: "research_execution_integrity" },
          { version: 55, name: "research_history_integrity" },
          { version: 56, name: "private_research_holdout_execution" },
          { version: 57, name: "model_assignment_purpose" },
          { version: 58, name: "autonomous_activation_receipts" },
          { version: 59, name: "provider_advisory_disclosure_mode" },
          { version: 60, name: "autonomous_activation_binding_subject_uniqueness" },
          { version: 61, name: "specialist_advisory_model_preferences" },
          { version: 62, name: "run_scoped_candidate_linux_procedure_activations" },
          { version: 63, name: "reviewed_candidate_linux_procedure_admissions" },
        ],
        currentVersion: 63,
      });
      expect(database.prepare(`
        SELECT DISTINCT status, decision_actor, decision_reason
        FROM guided_decisions WHERE run_id = 'run-guided-boundary'
      `).all()).toEqual([{
        status: "cancelled",
        decision_actor: "migration:guided-decision-boundary-v9",
        decision_reason: "Cancelled fail-closed because this run had multiple pending Guided decisions",
      }]);
      expect(database.prepare(`
        SELECT status, status_reason, lease_owner, lease_expires_at
        FROM runs WHERE id = 'run-guided-boundary'
      `).get()).toEqual({
        status: "blocked",
        status_reason: "Guided decision authority was ambiguous; legacy pending decisions were cancelled fail-closed",
        lease_owner: null,
        lease_expires_at: null,
      });
      expect(database.prepare(`
        SELECT DISTINCT status FROM plan_steps WHERE run_id = 'run-guided-boundary'
      `).all()).toEqual([{ status: "blocked" }]);
      expect(database.prepare(`
        SELECT DISTINCT status, lease_owner, lease_acquired_at,
          last_heartbeat_at, lease_expires_at
        FROM assignments WHERE run_id = 'run-guided-boundary'
      `).all()).toEqual([{
        status: "blocked",
        lease_owner: null,
        lease_acquired_at: null,
        last_heartbeat_at: null,
        lease_expires_at: null,
      }]);
      expect(database.prepare(`
        SELECT name FROM sqlite_master
        WHERE type = 'index' AND name = 'idx_guided_decisions_one_pending_per_run'
      `).get()).toEqual({ name: "idx_guided_decisions_one_pending_per_run" });

      insertDecision.run("decision-guided-new", "step-guided-current", "d".repeat(64), "2026-07-16T12:00:00.000Z", now);
      expect(() => insertDecision.run(
        "decision-guided-duplicate",
        "step-guided-stale",
        "e".repeat(64),
        "2026-07-16T12:00:00.000Z",
        now,
      )).toThrow("UNIQUE constraint failed");
    } finally {
      database.close();
    }
  });

  test("uses the startup integrity attestation without running quick_check on health reads", () => {
    let quickChecks = 0;
    const database = createDatabaseConnection({
      filename: ":memory:",
      integrityChecker(candidate) {
        quickChecks += 1;
        return { ok: true, messages: ["ok"] };
      },
    });
    try {
      migrateDatabase(database);
      const wrapped = new Proxy(database, {
        get(target, property, receiver) {
          if (property === "pragma") {
            return (source: string, options?: { simple?: boolean }) => {
              if (source === "quick_check") quickChecks += 1;
              return target.pragma(source, options);
            };
          }
          const value = Reflect.get(target, property, receiver);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });

      // A proxy is a distinct connection identity and therefore cannot borrow
      // the canonical connection's attestation.
      expect(getDatabaseHealth(wrapped).healthy).toBe(false);
      expect(getDatabaseHealth(database).healthy).toBe(true);
      expect(getDatabaseHealth(database).healthy).toBe(true);
      expect(quickChecks).toBe(1);
      assertDatabaseIntegrity(database, (candidate) => {
        quickChecks += 1;
        return candidate.pragma("quick_check")
          ? { ok: true, messages: ["ok"] }
          : { ok: false, messages: ["failed"] };
      });
      expect(quickChecks).toBe(2);
    } finally {
      database.close();
    }
  });

  test("does not strongly retain transient Bun prepared statements", () => {
    interface StatementProbe {
      readonly id: string;
    }
    let reachable: StatementProbe | undefined;
    const registry = new WeakStatementRegistry<StatementProbe>(() => ({
      deref: () => reachable,
    }));
    const statement = { id: "statement-probe" };
    reachable = statement;

    registry.track(statement);
    const firstVisit: string[] = [];
    registry.visitLive((candidate) => firstVisit.push(candidate.id));
    expect(firstVisit).toEqual(["statement-probe"]);
    expect(registry.referenceCount).toBe(1);

    // The registry must have no independent path to the statement once its
    // weak reference reports collection. This models the only lifecycle signal
    // the production native WeakRef provides, without asserting GC timing.
    reachable = undefined;
    const afterCollection: string[] = [];
    registry.visitLive((candidate) => afterCollection.push(candidate.id));
    expect(afterCollection).toEqual([]);
    expect(registry.referenceCount).toBe(0);
  });

  test("finalizes live Bun statements before reporting the connection closed", () => {
    if (!("bun" in process.versions)) return;
    const database = createDatabaseConnection({ filename: ":memory:" });
    const statement = database.prepare("SELECT 1 AS value");

    expect(statement.get()).toEqual({ value: 1 });
    expect(database.open).toBe(true);
    database.close();

    expect(database.open).toBe(false);
    expect(() => statement.get()).toThrow("Statement has finalized");
    expect(() => database.close()).not.toThrow();
  });

  test("closes after transient Bun statements are collected but native disposal is pending", () => {
    if (!("bun" in process.versions)) return;
    const database = createDatabaseConnection({ filename: ":memory:" });
    for (let index = 0; index < 5_000; index += 1) {
      database.prepare("SELECT 1 AS value").get();
    }
    Bun.gc(true);

    expect(() => database.close()).not.toThrow();
    expect(database.open).toBe(false);
  });

  test("does not hide an active transaction during Bun connection cleanup", () => {
    if (!("bun" in process.versions)) return;
    const database = createDatabaseConnection({ filename: ":memory:" });
    database.exec("BEGIN IMMEDIATE");

    expect(database.inTransaction).toBe(true);
    expect(() => database.close()).toThrow("while a transaction is active");
    expect(database.open).toBe(true);

    database.exec("ROLLBACK");
    database.close();
    expect(database.open).toBe(false);
  });

  test("creates all canonical runtime, memory, vault, learning, and audit tables", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const rows = database
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .all() as Array<{ name: string }>;
      const names = new Set(rows.map((row) => row.name));
      for (const expected of [
        "missions",
        "runs",
        "plans",
        "plan_steps",
        "actions",
        "guided_decisions",
        "events",
        "event_outbox",
        "evidence",
        "findings",
        "checkpoints",
        "run_evaluations",
        "run_evaluation_comparisons",
        "memory_nodes",
        "memory_edges",
        "memory_sources",
        "memory_versions",
        "memory_candidates",
        "memory_context_packs",
        "memory_context_items",
        "memory_suppressions",
        "preference_profiles",
        "vault_connections",
        "vault_sync_state",
        "vault_conflicts",
        "lessons",
        "lesson_usage",
        "run_context_selections",
        "mission_contract_snapshots",
        "run_branches",
        "runtime_continuations",
        "notification_read_receipts",
        "lesson_attack_chain_details",
        "lesson_attack_chain_items",
        "lesson_attack_chain_sources",
        "control_plane_leases",
        "capability_registry_snapshots",
        "engagement_log_records",
        "observations",
        "observation_log_sources",
        "evidence_candidates",
        "attack_attempts",
        "attack_attempt_evidence",
        "failure_diagnoses",
        "run_metrics_snapshots",
        "topology_nodes",
        "topology_edges",
        "topology_evidence_links",
        "asset_layer_observations",
        "cve_applicability_records",
        "plan_change_requests",
        "plan_step_versions",
        "script_artifacts",
        "page_captures",
        "model_configurations",
        "agent_model_assignments",
        "provider_exposure_receipts",
        "research_campaigns",
        "research_charters",
        "research_dimensions",
        "strategy_versions",
        "strategy_patches",
        "benchmark_families",
        "benchmark_scenarios",
        "benchmark_snapshots",
        "experiments",
        "experiment_runs",
        "experiment_metrics",
        "experiment_events",
        "experiment_failures",
        "near_misses",
        "integrity_receipts",
        "promotion_reviews",
        "strategy_deployments",
        "strategy_rollbacks",
        "research_context_packs",
        "research_context_items",
        "audit_records",
      ]) {
        expect(names.has(expected)).toBe(true);
      }
    } finally {
      database.close();
    }
  });

  test("keeps full Autonomous contract snapshots immutable", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      insertMission(database, "mission-contract-snapshot");
      const now = "2026-07-15T12:00:00.000Z";
      database.prepare(`
        INSERT INTO mission_contracts (
          id, mission_id, version, state, contract_hash,
          authorization_json, action_policy_json, budgets_json,
          safe_stop_json, deliverables_json, memory_scopes_json,
          confirmed_by, confirmed_at, created_at
        ) VALUES (
          'contract-snapshot', 'mission-contract-snapshot', 1, 'confirmed', ?,
          '{}', '{}', '{}', '{}', '[]', '[]', 'operator', ?, ?
        )
      `).run("a".repeat(64), now, now);
      database.prepare(`
        INSERT INTO mission_contract_snapshots (
          contract_id, mission_id, source_contract_id, request_json,
          amendment_reason, created_by, created_at
        ) VALUES (
          'contract-snapshot', 'mission-contract-snapshot', NULL, '{}',
          NULL, 'operator', ?
        )
      `).run(now);

      expect(() => database.prepare(`
        UPDATE mission_contract_snapshots SET request_json = '{"changed":true}'
        WHERE contract_id = 'contract-snapshot'
      `).run()).toThrow("mission contract snapshots are immutable");
      expect(() => database.prepare(`
        DELETE FROM mission_contract_snapshots WHERE contract_id = 'contract-snapshot'
      `).run()).toThrow("mission contract snapshots are immutable");
      expect(database.prepare(`
        SELECT request_json FROM mission_contract_snapshots
        WHERE contract_id = 'contract-snapshot'
      `).get()).toEqual({ request_json: "{}" });
    } finally {
      database.close();
    }
  });

  test("binds a new Autonomous run to its exact contract revision and keeps that binding immutable", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      insertMission(database, "mission-contract-binding");
      const now = "2026-07-15T12:10:00.000Z";
      database.prepare(`
        INSERT INTO mission_contracts (
          id, mission_id, version, state, contract_hash,
          authorization_json, action_policy_json, budgets_json,
          safe_stop_json, deliverables_json, memory_scopes_json,
          confirmed_by, confirmed_at, created_at
        ) VALUES (
          'contract-binding', 'mission-contract-binding', 3, 'confirmed', ?,
          '{}', '{}', '{}', '{}', '[]', '[]', 'operator', ?, ?
        )
      `).run("c".repeat(64), now, now);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, contract_id, created_at, updated_at
        ) VALUES (
          'run-contract-binding', 'mission-contract-binding', 'autonomous',
          'planning', 'contract-binding', ?, ?
        )
      `).run(now, now);

      expect(database.prepare(`
        SELECT contract_id, contract_version_bound, contract_hash_bound
        FROM runs WHERE id = 'run-contract-binding'
      `).get()).toEqual({
        contract_id: "contract-binding",
        contract_version_bound: 3,
        contract_hash_bound: "c".repeat(64),
      });
      expect(() => database.prepare(`
        UPDATE runs SET contract_id = NULL WHERE id = 'run-contract-binding'
      `).run()).toThrow("run contract binding is immutable");
      expect(() => database.prepare(`
        UPDATE runs SET contract_version_bound = 4 WHERE id = 'run-contract-binding'
      `).run()).toThrow("run contract binding is immutable");
      expect(() => database.prepare(`
        UPDATE runs SET contract_hash_bound = ? WHERE id = 'run-contract-binding'
      `).run("d".repeat(64))).toThrow("run contract binding is immutable");

      database.prepare(`
        UPDATE mission_contracts SET version = 4, contract_hash = ?
        WHERE id = 'contract-binding'
      `).run("d".repeat(64));
      expect(database.prepare(`
        SELECT contract_version_bound, contract_hash_bound
        FROM runs WHERE id = 'run-contract-binding'
      `).get()).toEqual({
        contract_version_bound: 3,
        contract_hash_bound: "c".repeat(64),
      });
    } finally {
      database.close();
    }
  });

  test("upgrades a version-five database and marks legacy evaluations as explicitly un-compared", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS.slice(0, 5));
      insertMission(database, "mission-legacy");
      const now = "2026-07-15T12:00:00.000Z";
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, started_at, ended_at, created_at, updated_at
        ) VALUES ('run-legacy', 'mission-legacy', 'autonomous', 'completed', ?, ?, ?, ?)
      `).run(now, now, now, now);
      database.prepare(`
        INSERT INTO run_evaluations (
          id, mission_id, run_id, journey, scores_json, metrics_json,
          retrospective, evidence_coverage, created_by, created_at
        ) VALUES (
          'evaluation-legacy', 'mission-legacy', 'run-legacy', 'autonomous', '{}', '{}',
          'Legacy evaluation', 0, 'evaluator', ?
        )
      `).run(now);

      const result = migrateDatabase(database);
      expect(result.applied.map((migration) => migration.version)).toEqual([6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]);
      expect(database.prepare(`
        SELECT comparison_status, reason, prior_run_id, metrics_json
        FROM run_evaluation_comparisons WHERE evaluation_id = 'evaluation-legacy'
      `).get()).toEqual({
        comparison_status: "insufficient_data",
        reason: "legacy_evaluation_not_compared",
        prior_run_id: null,
        metrics_json: "[]",
      });
    } finally {
      database.close();
    }
  });

  test("backfills audit journeys and rejects missing or mismatched scoped journeys", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS.slice(0, 6));
      insertMission(database, "mission-audit", "guided");
      const now = "2026-07-15T12:30:00.000Z";
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-audit', 'mission-audit', 'guided', 'running', ?, ?)
      `).run(now, now);
      database.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json,
          previous_hash, record_hash, occurred_at
        ) VALUES (
          'audit-legacy', 'mission-audit', 'run-audit', 'operator', 'operator',
          'guided.step_recorded', 'run', 'run-audit', 'Legacy scoped record', '{}',
          NULL, 'legacy-record-hash', ?
        )
      `).run(now);
      database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, artifact_type, storage_uri, content_hash,
          byte_size, sensitivity, metadata_json, created_at
        ) VALUES (
          'artifact-legacy', 'mission-audit', 'run-audit', 'mission_report',
          'artifact://legacy-report', ?, 12, 'private', '{}', ?
        )
      `).run("a".repeat(64), now);
      database.prepare(`
        INSERT INTO checkpoints (
          id, mission_id, run_id, event_sequence, state_json, state_hash, created_at
        ) VALUES (
          'checkpoint-legacy', 'mission-audit', 'run-audit', 0, '{}', ?, ?
        )
      `).run("b".repeat(64), now);

      const result = migrateDatabase(database);
      expect(result.applied.map((migration) => migration.version)).toEqual([7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]);
      expect(database.prepare(
        "SELECT journey, record_hash FROM audit_records WHERE id = 'audit-legacy'",
      ).get()).toEqual({ journey: "guided", record_hash: "legacy-record-hash" });
      expect(database.prepare(
        "SELECT journey FROM artifacts WHERE id = 'artifact-legacy'",
      ).get()).toEqual({ journey: "guided" });
      expect(database.prepare(
        "SELECT journey FROM checkpoints WHERE id = 'checkpoint-legacy'",
      ).get()).toEqual({ journey: "guided" });

      const insert = database.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, journey, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json,
          previous_hash, record_hash, occurred_at
        ) VALUES (?, 'mission-audit', 'run-audit', ?, 'operator', 'operator',
          'guided.step_recorded', 'run', 'run-audit', 'Scoped record', '{}',
          'legacy-record-hash', ?, ?)
      `);
      expect(() => insert.run("audit-missing", null, "missing", now)).toThrow(
        "require a journey",
      );
      expect(() => insert.run("audit-mismatch", "autonomous", "mismatch", now)).toThrow(
        "match",
      );
      insert.run("audit-valid", "guided", "valid", now);
      expect(() => database.prepare(
        "UPDATE audit_records SET journey = 'autonomous' WHERE id = 'audit-valid'",
      ).run()).toThrow("immutable");
      expect(() => database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, artifact_type, storage_uri, content_hash,
          byte_size, sensitivity, metadata_json, created_at
        ) VALUES ('artifact-missing', 'mission-audit', 'run-audit', 'report',
          'artifact://missing', ?, 0, 'private', '{}', ?)
      `).run("c".repeat(64), now)).toThrow("require a journey");
      expect(() => database.prepare(`
        INSERT INTO checkpoints (
          id, mission_id, run_id, event_sequence, state_json, state_hash, created_at
        ) VALUES ('checkpoint-missing', 'mission-audit', 'run-audit', 1, '{}', ?, ?)
      `).run("d".repeat(64), now)).toThrow("require a journey");
    } finally {
      database.close();
    }
  });

  test("enforces journey invariants, JSON validity, and foreign keys", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      insertMission(database, "mission-auto");
      const now = new Date().toISOString();

      expect(() =>
        database
          .prepare(`
            INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `)
          .run(
            "run-waits",
            "mission-auto",
            "autonomous",
            "waiting_guided_decision",
            now,
            now,
          ),
      ).toThrow();
      expect(() =>
        database
          .prepare(`
            INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `)
          .run("run-orphan", "missing", "guided", "queued", now, now),
      ).toThrow();
      expect(() =>
        database
          .prepare("UPDATE missions SET scope_json = ? WHERE id = ?")
          .run("not-json", "mission-auto"),
      ).toThrow();
    } finally {
      database.close();
    }
  });

  test("keeps events, evidence, audit records, and memory versions immutable", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      insertMission(database, "mission-immutable");
      const now = new Date().toISOString();
      database
        .prepare(`
          INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
          VALUES (?, ?, 'autonomous', 'running', ?, ?)
        `)
        .run("run-immutable", "mission-immutable", now, now);
      database
        .prepare(`
          INSERT INTO events (
            id, mission_id, run_id, sequence, event_type, occurred_at, actor_type,
            summary, journey, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          "event-immutable",
          "mission-immutable",
          "run-immutable",
          1,
          "run.started",
          now,
          "system",
          "Run started",
          "autonomous",
          now,
        );
      expect(() =>
        database
          .prepare("UPDATE events SET summary = ? WHERE id = ?")
          .run("Changed", "event-immutable"),
      ).toThrow("append-only");
      expect(() =>
        database.prepare("DELETE FROM events WHERE id = ?").run("event-immutable"),
      ).toThrow("append-only");
    } finally {
      database.close();
    }
  });

  test("indexes canonical text with FTS5", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const now = new Date().toISOString();
      database
        .prepare(`
          INSERT INTO memory_nodes (
            id, node_type, title, summary, body, scope, sensitivity, confidence,
            lifecycle_status, confirmation_state, provenance_json, author_type,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          "memory-search",
          "technique",
          "Service fingerprinting",
          "Correlate banner evidence",
          "Validate versions before selecting a procedure.",
          "global",
          "internal",
          0.9,
          "verified",
          "not_required",
          "{}",
          "agent",
          now,
          now,
        );
      const hit = database
        .prepare(`
          SELECT memory_nodes.id
          FROM memory_nodes_fts
          JOIN memory_nodes ON memory_nodes.rowid = memory_nodes_fts.rowid
          WHERE memory_nodes_fts MATCH ?
        `)
        .get("fingerprint*") as { id: string } | undefined;
      expect(hit?.id).toBe("memory-search");
    } finally {
      database.close();
    }
  });

  test("fails closed before database or backup-path access", async () => {
    const directory = temporaryDirectory();
    const backupRoot = join(directory, "must-not-exist");
    const database = new Proxy({} as ReturnType<typeof createDatabaseConnection>, {
      get() {
        throw new Error("database was accessed");
      },
    });

    await expect(backupDatabase(database, join(backupRoot, "snapshot.sqlite")))
      .rejects.toThrow(DATABASE_BACKUP_DISABLED_ERROR);
    await expect(createTimestampedBackup(database, backupRoot))
      .rejects.toThrow(DATABASE_BACKUP_DISABLED_ERROR);

    expect(existsSync(backupRoot)).toBe(false);
    expect("backupDatabase" in DatabaseBarrel).toBe(false);
    expect("createTimestampedBackup" in DatabaseBarrel).toBe(false);
  });

  test("disables the database driver's direct backup method before destination access", async () => {
    const directory = temporaryDirectory();
    const databasePath = join(directory, "canonical.sqlite");
    const destination = join(directory, "must-not-exist", "snapshot.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      await expect(database.backup(destination))
        .rejects.toThrow(DATABASE_BACKUP_DISABLED_ERROR);
      expect(existsSync(destination)).toBe(false);
      expect(existsSync(join(directory, "must-not-exist"))).toBe(false);
    } finally {
      database.close();
    }
  });
});
