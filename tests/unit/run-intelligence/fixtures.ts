import type { SqliteDatabase } from "../../../server/db";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  migrateDatabase,
} from "../../../server/db";

export const NOW = "2026-07-16T12:00:00.000Z";
export const MISSION_ID = "mission-intelligence";
export const RUN_ID = "run-intelligence";
export const PLAN_ID = "plan-intelligence-v1";
export const STEP_ONE_ID = "step-intelligence-1";
export const STEP_TWO_ID = "step-intelligence-2";
export const AGENT_ONE_ID = "agent-recon";
export const AGENT_TWO_ID = "agent-web";

export function createTestDatabase(): SqliteDatabase {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database, DATABASE_MIGRATIONS);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at
    ) VALUES (?, 'Run intelligence fixture', 'Assess the authorized local fixture',
      'autonomous', 'active', 'verified', 'operator', ?, ?)
  `).run(MISSION_ID, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, retry_count, replan_count,
      started_at, created_at, updated_at
    ) VALUES (?, ?, 'autonomous', 'running', 0.5, 1, 1,
      '2026-07-16T12:00:00.000Z', ?, '2026-07-16T12:10:00.000Z')
  `).run(RUN_ID, MISSION_ID, NOW);
  for (const [id, role, display] of [
    [AGENT_ONE_ID, "reconnaissance", "Recon specialist"],
    [AGENT_TWO_ID, "web", "Web specialist"],
  ] as const) {
    database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, version, created_at, updated_at
      ) VALUES (?, ?, ?, 'available', 'fixture-v1', ?, ?)
    `).run(id, role, display, NOW, NOW);
  }
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Evidence-backed fixture plan', ?, 'planner', ?, ?)
  `).run(PLAN_ID, RUN_ID, "a".repeat(64), NOW, NOW);
  for (const [id, ordinal, status, title] of [
    [STEP_ONE_ID, 0, "completed", "Map approved asset"],
    [STEP_TWO_ID, 1, "failed", "Validate service hypothesis"],
  ] as const) {
    database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, 'reconnaissance', ?, 'Produce attributable intelligence', ?, ?, ?)
    `).run(id, PLAN_ID, RUN_ID, ordinal, title, status, NOW, NOW);
  }
  database.prepare("UPDATE runs SET current_plan_id = ?, current_step_id = ? WHERE id = ?")
    .run(PLAN_ID, STEP_TWO_ID, RUN_ID);
  return database;
}

export function insertEvidence(
  database: SqliteDatabase,
  input: {
    readonly id: string;
    readonly verificationState?: "unverified" | "verified" | "disputed" | "rejected";
    readonly provenance?: Readonly<Record<string, unknown>>;
    readonly missionId?: string;
    readonly runId?: string | null;
    readonly acquiredAt?: string;
    readonly confidence?: number;
  },
): void {
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES (?, ?, ?, ?, 'fixture-parser', ?, 'fixture.local', 'service_fingerprint',
      ?, ?, ?, 'internal', ?, ?, 'fixture-agent', ?)
  `).run(
    input.id,
    input.missionId ?? MISSION_ID,
    input.runId === undefined ? RUN_ID : input.runId,
    input.runId === null ? null : STEP_ONE_ID,
    input.acquiredAt ?? "2026-07-16T12:01:00.000Z",
    input.id.padEnd(64, "0").slice(0, 64),
    JSON.stringify(input.provenance ?? { sourceRecordId: `source-${input.id}`, parser: "fixture-parser-v1" }),
    input.confidence ?? 0.9,
    input.verificationState ?? "verified",
    `Evidence ${input.id}`,
    input.acquiredAt ?? "2026-07-16T12:01:00.000Z",
  );
}

export function insertEvent(
  database: SqliteDatabase,
  sequence: number,
  eventType: string,
  occurredAt: string,
): void {
  database.prepare(`
    INSERT INTO events (
      id, mission_id, run_id, sequence, event_type, occurred_at,
      actor_type, actor_id, summary, payload_json, schema_version,
      journey, sensitivity, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'system', 'fixture-runtime', ?, '{}', 1,
      'autonomous', 'internal', ?)
  `).run(
    `event-intelligence-${sequence}`,
    MISSION_ID,
    RUN_ID,
    sequence,
    eventType,
    occurredAt,
    `Fixture event ${sequence}`,
    occurredAt,
  );
  database.prepare(`
    INSERT INTO run_event_sequences (run_id, last_sequence) VALUES (?, ?)
    ON CONFLICT (run_id) DO UPDATE SET last_sequence = excluded.last_sequence
  `).run(RUN_ID, sequence);
}

export function insertFailedToolCall(
  database: SqliteDatabase,
  attackAttemptId: string,
): { readonly actionId: string; readonly toolCallId: string } {
  const actionId = `action-for-${attackAttemptId}`;
  const toolCallId = `tool-for-${attackAttemptId}`;
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, action_type, action_class,
      fingerprint, normalized_arguments_json, scoped_target, status,
      intent_summary, result_summary, error_category, retry_count,
      started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'tool', 'active_host_discovery', ?, '{}',
      'fixture.local', 'failed', 'Collect one bounded observation',
      'Process returned a deterministic parser error', 'deterministic_tool_error', 2,
      '2026-07-16T12:02:00.000Z', '2026-07-16T12:02:05.000Z', ?, ?)
  `).run(actionId, MISSION_ID, RUN_ID, STEP_TWO_ID, "f".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO tool_calls (
      id, action_id, provider, tool_name, normalized_arguments_json,
      status, error_category, latency_ms, output_summary, started_at,
      ended_at, created_at
    ) VALUES (?, ?, 'local-runtime', 'fixture-tool', '{}', 'failed',
      'deterministic_tool_error', 5000, 'Process failed before producing an observation',
      '2026-07-16T12:02:00.000Z', '2026-07-16T12:02:05.000Z', ?)
  `).run(toolCallId, actionId, NOW);
  database.prepare(`
    INSERT INTO engagement_log_records (
      id, mission_id, run_id, plan_id, step_id, action_id,
      attack_attempt_id, agent_id, tool_call_id, severity, domain,
      record_type, human_summary, technical_payload_json, content_hash,
      sensitivity, occurred_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'error', 'tool', 'process_failure',
      'Tool process failed; attack outcome remains unclassified', '{}', ?,
      'internal', '2026-07-16T12:02:05.000Z', ?)
  `).run(
    `log-for-${attackAttemptId}`,
    MISSION_ID,
    RUN_ID,
    PLAN_ID,
    STEP_TWO_ID,
    actionId,
    attackAttemptId,
    AGENT_ONE_ID,
    toolCallId,
    "b".repeat(64),
    NOW,
  );
  return { actionId, toolCallId };
}
