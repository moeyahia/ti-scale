import { isAbsolute } from "node:path";
import {
  CandidateLinuxTransportBindingRegistry,
} from "../server/autonomous-runtime";
import {
  autonomousSuccessCriterionId,
} from "../server/autonomous-runtime/LocalVerifiedEvidenceOutcomeEvaluator";
import {
  loadProductionAutonomousDnsConfiguration,
} from "../server/app/AutonomousDnsProductionConfiguration";
import {
  createDatabaseConnection,
  type SqliteDatabase,
} from "../server/db";
import {
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
} from "../server/domain/autonomous-outcome-registry";
import { digestCanonicalJson } from "../server/mcp";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u;
const REQUIRED_ACTION_CLASSES = Object.freeze([
  "exploit_validation",
  "command_session_execution",
  "data_access_impact_validation",
  "privilege_escalation",
  "cleanup_restoration",
] as const);
const REQUIRED_POST_EXPLOIT_ACTIONS = Object.freeze([
  "autonomous_linux_session_identity_v1",
  "autonomous_linux_user_flag_hash_proof_v1",
  "autonomous_linux_privilege_escalation_v1",
  "autonomous_linux_root_flag_hash_proof_v1",
  "autonomous_linux_session_cleanup_v1",
] as const);

interface RunRow {
  readonly mission_id: string;
  readonly run_id: string;
  readonly plan_id: string;
  readonly contract_id: string;
  readonly contract_hash: string;
  readonly contract_version: number;
  readonly action_policy_json: string;
  readonly success_criteria_json: string;
}

interface SessionRow {
  readonly session_id: string;
  readonly attempt_id: string;
  readonly exploit_evidence_id: string;
  readonly candidate_binding_hash: string;
  readonly exact_target: string;
}

function exactArguments(argv: readonly string[]): Readonly<{
  runId: string;
  databasePath: string;
}> {
  if (argv.length !== 2 || argv[0] !== "--run-id" || !ID.test(argv[1] ?? "")) {
    throw new Error(
      "Usage: bun run scripts/prove-candidate-linux-full-path.ts --run-id <stable-run-id>",
    );
  }
  const databasePath = process.env.TI_SCALE_DATABASE_PATH?.trim()
    ?? "/var/lib/ti-scale/data/ti-scale.sqlite";
  if (!isAbsolute(databasePath)) {
    throw new Error("TI_SCALE_DATABASE_PATH must be absolute");
  }
  return Object.freeze({ runId: argv[1]!, databasePath });
}

function stringArray(value: string, label: string): readonly string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
    throw new Error(`${label} is not a string array`);
  }
  return Object.freeze([...parsed]);
}

function requireRow<T>(row: T | undefined, message: string): T {
  if (!row) throw new Error(message);
  return row;
}

function canonicalRun(database: SqliteDatabase, runId: string): RunRow {
  return requireRow(database.prepare(`
    SELECT mission.id AS mission_id, run.id AS run_id,
      plan.id AS plan_id, contract.id AS contract_id,
      contract.contract_hash, contract.version AS contract_version,
      contract.action_policy_json, mission.success_criteria_json
    FROM runs run
    JOIN missions mission ON mission.id = run.mission_id
      AND mission.journey = 'autonomous'
      AND mission.status = 'completed'
      AND mission.authorization_status = 'verified'
      AND mission.control_plane = 'ti_scale'
    JOIN plans plan ON plan.id = run.current_plan_id
      AND plan.run_id = run.id
      AND plan.status IN ('active', 'completed')
    JOIN mission_contracts contract ON contract.id = run.contract_id
      AND contract.mission_id = mission.id
      AND contract.state = 'confirmed'
      AND contract.version = run.contract_version_bound
      AND contract.contract_hash = run.contract_hash_bound
    WHERE run.id = ?
      AND run.journey = 'autonomous'
      AND run.status = 'completed'
      AND run.control_plane = 'ti_scale'
      AND run.progress = 1
      AND run.ended_at IS NOT NULL
    LIMIT 1
  `).get(runId) as RunRow | undefined,
  "The run is not a completed, current-plan, signed Autonomous Ti-Scale run.");
}

function canonicalSession(database: SqliteDatabase, run: RunRow): SessionRow {
  return requireRow(database.prepare(`
    SELECT session.id AS session_id, attempt.id AS attempt_id,
      proof.id AS exploit_evidence_id, session.candidate_binding_hash,
      session.exact_target
    FROM session_artifacts session
    JOIN candidate_linux_post_exploit_specs spec
      ON spec.id = session.post_exploit_spec_id
      AND spec.status = 'active'
      AND spec.transport_type = 'candidate_runtime_session_v1'
    JOIN attack_attempts attempt
      ON attempt.id = session.origin_attack_attempt_id
      AND attempt.mission_id = session.mission_id
      AND attempt.run_id = session.run_id
      AND attempt.plan_id = session.plan_id
      AND attempt.status = 'succeeded'
      AND attempt.action_class = 'exploit_validation'
    JOIN attack_attempt_evidence link
      ON link.attack_attempt_id = attempt.id
      AND link.evidence_id = session.exploit_outcome_evidence_id
      AND link.relationship = 'outcome'
    JOIN evidence proof ON proof.id = link.evidence_id
      AND proof.verification_state = 'verified'
      AND proof.evidence_type = 'exploit_validation_result'
      AND proof.target = session.exact_target
    JOIN topology_nodes target ON target.id = session.target_node_id
      AND target.scope_status = 'allowed'
      AND target.normalized_identity = session.exact_target
    WHERE session.mission_id = ? AND session.run_id = ?
      AND session.plan_id = ?
      AND session.status = 'closed'
      AND session.access_level = 'root'
      AND session.closed_at IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM session_artifact_leases lease
        WHERE lease.session_artifact_id = session.id
          AND lease.released_at IS NULL
      )
    LIMIT 1
  `).get(run.mission_id, run.run_id, run.plan_id) as SessionRow | undefined,
  "No closed root-level candidate session with a verified succeeded exploit origin exists.");
}

function assertContract(run: RunRow): void {
  const policy = JSON.parse(run.action_policy_json) as {
    readonly allowedActionClasses?: unknown;
  };
  const allowed = Array.isArray(policy.allowedActionClasses)
    ? policy.allowedActionClasses
    : [];
  for (const actionClass of REQUIRED_ACTION_CLASSES) {
    if (!allowed.includes(actionClass)) {
      throw new Error(`Signed contract omitted required action class ${actionClass}`);
    }
  }
  const criteria = stringArray(
    run.success_criteria_json,
    "mission.success_criteria_json",
  );
  for (const criterion of AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA) {
    if (!criteria.includes(criterion)) {
      throw new Error(`Signed mission omitted terminal criterion: ${criterion}`);
    }
  }
}

function assertActionEvidenceAndBrain(
  database: SqliteDatabase,
  run: RunRow,
  session: SessionRow,
): readonly string[] {
  const actionIds: string[] = [];
  for (const actionType of REQUIRED_POST_EXPLOIT_ACTIONS) {
    const row = requireRow(database.prepare(`
      SELECT action.id
      FROM actions action
      JOIN plan_steps step ON step.id = action.step_id
        AND step.plan_id = ?
      WHERE action.mission_id = ? AND action.run_id = ?
        AND action.action_type = ?
        AND action.status = 'succeeded'
        AND action.scoped_target = ?
        AND action.contract_id = ?
        AND json_extract(
          action.normalized_arguments_json,
          '$.sessionArtifactId'
        ) = ?
        AND EXISTS (
          SELECT 1
          FROM memory_context_packs pack
          JOIN memory_context_items item
            ON item.context_pack_id = pack.id AND item.used = 1
          JOIN memory_nodes node ON node.id = item.node_id
            AND node.lifecycle_status IN ('confirmed', 'verified')
            AND node.confirmation_state IN ('not_required', 'confirmed')
            AND (node.expires_at IS NULL OR node.expires_at > action.ended_at)
          JOIN vault_sync_state sync ON sync.node_id = node.id
            AND sync.database_version = node.version
            AND sync.status = 'synced'
          JOIN vault_connections vault ON vault.id = sync.connection_id
            AND vault.status = 'connected'
          WHERE pack.action_id = action.id
            AND pack.mission_id = action.mission_id
            AND pack.run_id = action.run_id
            AND pack.journey = 'autonomous'
            AND EXISTS (
              SELECT 1 FROM audit_records health
              WHERE health.resource_type = 'vault_connection'
                AND health.resource_id = vault.id
                AND health.action = 'vault.health.verified'
            )
            AND NOT EXISTS (
              SELECT 1 FROM vault_conflicts conflict
              WHERE conflict.connection_id = vault.id
                AND conflict.status = 'open'
            )
        )
      LIMIT 1
    `).get(
      run.plan_id,
      run.mission_id,
      run.run_id,
      actionType,
      session.exact_target,
      run.contract_id,
      session.session_id,
    ) as { readonly id: string } | undefined,
    `Action ${actionType} lacks a succeeded current-plan result and active-Vault-backed Context Pack.`);
    actionIds.push(row.id);
  }
  const counts = database.prepare(`
    SELECT
      (
        SELECT COUNT(*) FROM session_identity_observations observation
        JOIN evidence ON evidence.id = observation.evidence_id
          AND evidence.action_id = observation.action_id
          AND evidence.verification_state = 'verified'
        WHERE observation.session_artifact_id = ?
          AND observation.observer_kind = 'user_identity'
          AND observation.uid > 0
      ) AS user_identity_count,
      (
        SELECT COUNT(*) FROM session_identity_observations observation
        JOIN evidence ON evidence.id = observation.evidence_id
          AND evidence.action_id = observation.action_id
          AND evidence.verification_state = 'verified'
        WHERE observation.session_artifact_id = ?
          AND observation.observer_kind = 'root_identity'
          AND observation.principal = 'root'
          AND observation.uid = 0 AND observation.gid = 0
      ) AS root_identity_count,
      (
        SELECT COUNT(*) FROM session_flag_proofs proof
        JOIN evidence ON evidence.id = proof.evidence_id
          AND evidence.action_id = proof.action_id
          AND evidence.verification_state = 'verified'
        WHERE proof.session_artifact_id = ?
          AND proof.proof_kind = 'user_flag'
          AND proof.declared_path GLOB '/home/*/user.txt'
      ) AS user_proof_count,
      (
        SELECT COUNT(*) FROM session_flag_proofs proof
        JOIN evidence ON evidence.id = proof.evidence_id
          AND evidence.action_id = proof.action_id
          AND evidence.verification_state = 'verified'
        WHERE proof.session_artifact_id = ?
          AND proof.proof_kind = 'root_flag'
          AND proof.declared_path = '/root/root.txt'
      ) AS root_proof_count
  `).get(
    session.session_id,
    session.session_id,
    session.session_id,
    session.session_id,
  ) as Record<string, number>;
  if (
    counts.user_identity_count !== 1
    || counts.root_identity_count !== 1
    || counts.user_proof_count !== 1
    || counts.root_proof_count !== 1
  ) {
    throw new Error(
      "The session does not contain exactly one verified user identity, user hash, root identity, and root hash proof.",
    );
  }
  return Object.freeze(actionIds);
}

function assertCriteriaEvidence(
  database: SqliteDatabase,
  run: RunRow,
): readonly string[] {
  return Object.freeze(
    AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA.map((criterion) => {
      const criterionId = autonomousSuccessCriterionId(criterion);
      const row = requireRow(database.prepare(`
        SELECT id FROM evidence
        WHERE mission_id = ? AND run_id = ?
          AND verification_state = 'verified'
          AND json_extract(
            provenance_json,
            '$.successCriterionReference.criterionId'
          ) = ?
        LIMIT 1
      `).get(
        run.mission_id,
        run.run_id,
        criterionId,
      ) as { readonly id: string } | undefined,
      `No verified evidence satisfies terminal criterion ${criterionId}.`);
      return row.id;
    }),
  );
}

const input = exactArguments(process.argv.slice(2));
const database = createDatabaseConnection({
  filename: input.databasePath,
  readonly: true,
  fileMustExist: true,
  verifyIntegrity: true,
});
try {
  const schema = database.prepare(
    "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations",
  ).get() as { readonly version: number };
  if (schema.version < 46) {
    throw new Error(
      "Database schema 46 or later is required for candidate-session integrity.",
    );
  }
  const configuration = loadProductionAutonomousDnsConfiguration();
  if (
    configuration.status !== "loaded"
    || !configuration.candidateLinuxTransportManifest
  ) {
    throw new Error(
      "No complete deployment-pinned candidate Linux transport is configured.",
    );
  }
  const transport = new CandidateLinuxTransportBindingRegistry({
    database,
    loadedManifest: configuration.candidateLinuxTransportManifest,
  });
  const attestation = await transport.attest();
  const run = canonicalRun(database, input.runId);
  assertContract(run);
  const session = canonicalSession(database, run);
  const actionIds = assertActionEvidenceAndBrain(database, run, session);
  const evidenceIds = assertCriteriaEvidence(database, run);
  const receipt = {
    schemaVersion: "ti-scale.candidate-linux-full-path-proof.v1",
    runId: run.run_id,
    missionId: run.mission_id,
    planId: run.plan_id,
    contractId: run.contract_id,
    contractHash: run.contract_hash,
    contractVersion: run.contract_version,
    sessionArtifactId: session.session_id,
    originAttackAttemptId: session.attempt_id,
    exploitEvidenceId: session.exploit_evidence_id,
    candidateBindingHash: session.candidate_binding_hash,
    actionIds,
    terminalCriterionEvidenceIds: evidenceIds,
    brokerAttestationReceiptSha256: attestation.receiptSha256,
    candidateTransportManifestSha256: attestation.manifestSha256,
    databaseSchemaVersion: schema.version,
    readonly: true,
    generatedAt: new Date().toISOString(),
  };
  process.stdout.write(`${JSON.stringify({
    ...receipt,
    receiptSha256: digestCanonicalJson(
      receipt,
      { maxBytes: 256 * 1_024, maxDepth: 32 },
    ).sha256,
  }, null, 2)}\n`);
} finally {
  database.close();
}
