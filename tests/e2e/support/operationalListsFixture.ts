import { createHash } from "node:crypto";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const BASE_TIME = Date.parse("2099-07-17T18:00:00.000Z");
const AGENT_COUNT = 27;
const TRACE_COUNT = 52;
const REPORT_COUNT = 27;

export interface OperationalListsFixture {
  readonly namespace: string;
  readonly token: string;
  readonly missionId: string;
  readonly runId: string;
  readonly missionTitle: string;
  readonly agentIds: readonly string[];
  readonly agentNames: readonly string[];
  readonly traceIds: readonly string[];
  readonly traceSummaries: readonly string[];
  readonly reportIds: readonly string[];
  readonly reportTypes: readonly string[];
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Operational-list E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function fixtureTime(index: number): string {
  return new Date(BASE_TIME - index * 1_000).toISOString();
}

export function createOperationalListsFixture(instanceId: string): OperationalListsFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const token = `operationallist${digest(namespace).slice(0, 12)}`;
  const missionId = `mission-${token}`;
  const runId = `run-${token}`;
  const missionTitle = `${token} canonical operational records`;
  const agentIds = Array.from({ length: AGENT_COUNT }, (_, index) => `agent-${token}-${String(index).padStart(2, "0")}`);
  const agentNames = Array.from({ length: AGENT_COUNT }, (_, index) => `${token} agent ${String(index).padStart(2, "0")}`);
  const traceIds = Array.from({ length: TRACE_COUNT }, (_, index) => `trace-${token}-${String(index).padStart(2, "0")}`);
  const traceSummaries = Array.from({ length: TRACE_COUNT }, (_, index) => `${token} correlated trace ${String(index).padStart(2, "0")}`);
  const reportIds = Array.from({ length: REPORT_COUNT }, (_, index) => `artifact-${token}-report-${String(index).padStart(2, "0")}`);
  const reportTypes = Array.from({ length: REPORT_COUNT }, (_, index) => `${token}_report_${String(index).padStart(2, "0")}`);
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    inImmediateTransaction(database, () => {
      // A focused retry may intentionally reuse the same run namespace. Reset
      // only this fixture's bounded graph in foreign-key-safe order.
      database.prepare("DELETE FROM artifacts WHERE id LIKE ?").run(`artifact-${token}-%`);
      database.prepare("DELETE FROM events WHERE run_id = ?").run(runId);
      database.prepare("DELETE FROM runs WHERE id = ?").run(runId);
      database.prepare("DELETE FROM missions WHERE id = ?").run(missionId);
      database.prepare("DELETE FROM agents WHERE id LIKE ?").run(`agent-${token}-%`);

      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status, engagement_id,
          scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
          created_by, version, created_at, updated_at
        ) VALUES (?, ?, ?, 'guided', 'active', 'verified', ?, ?, '[]', '{}', '{}',
          'e2e-local-operator', 1, ?, ?)
      `).run(
        missionId,
        missionTitle,
        `${token} isolates real agents, traces, and reports for cursor and detail traversal.`,
        `engagement-${token}`,
        JSON.stringify({ allowedTargets: [`${token}.example.test`] }),
        fixtureTime(TRACE_COUNT + REPORT_COUNT + AGENT_COUNT + 2),
        fixtureTime(0),
      );
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason, next_action_summary,
          budget_json, budget_usage_json, started_at, ended_at, created_at, updated_at, version
        ) VALUES (?, ?, 'guided', 'completed', 1, 'Canonical operational-list fixture completed.',
          'Inspect the attributable fixture records', '{}', '{}', ?, ?, ?, ?, 1)
      `).run(runId, missionId, fixtureTime(TRACE_COUNT + 1), fixtureTime(0), fixtureTime(TRACE_COUNT + 1), fixtureTime(0));
      database.prepare("INSERT INTO run_event_sequences (run_id, last_sequence) VALUES (?, ?)").run(runId, TRACE_COUNT);

      const insertAgent = database.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json, tool_policy_json,
          configuration_json, version, last_heartbeat_at, created_at, updated_at
        ) VALUES (?, 'fixture-specialist', ?, 'available', '{}', '{}', '{}', '2.4', ?, ?, ?)
      `);
      agentIds.forEach((agentId, index) => insertAgent.run(
        agentId,
        agentNames[index],
        fixtureTime(index),
        fixtureTime(AGENT_COUNT + 1),
        fixtureTime(index),
      ));

      const insertEvent = database.prepare(`
        INSERT INTO events (
          id, mission_id, run_id, sequence, event_type, occurred_at, actor_type, actor_id,
          summary, payload_json, schema_version, journey, trace_id, sensitivity,
          redaction_json, created_at
        ) VALUES (?, ?, ?, ?, 'operational_list_fixture_observed', ?, 'system',
          'e2e-fixture', ?, '{}', 1, 'guided', ?, 'internal', '{}', ?)
      `);
      traceIds.forEach((traceId, index) => insertEvent.run(
        `event-${token}-${String(index).padStart(2, "0")}`,
        missionId,
        runId,
        index + 1,
        fixtureTime(index),
        traceSummaries[index],
        traceId,
        fixtureTime(index),
      ));

      const insertReport = database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, artifact_type, storage_uri, content_hash, byte_size,
          media_type, sensitivity, metadata_json, created_at, journey
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'text/markdown', 'internal', ?, ?, 'guided')
      `);
      reportIds.forEach((reportId, index) => insertReport.run(
        reportId,
        missionId,
        runId,
        reportTypes[index],
        `fixture://${reportId}`,
        digest(reportId),
        2_048 + index,
        JSON.stringify({ fixture: token, ordinal: index }),
        fixtureTime(index),
      ));
    });
    return {
      namespace,
      token,
      missionId,
      runId,
      missionTitle,
      agentIds,
      agentNames,
      traceIds,
      traceSummaries,
      reportIds,
      reportTypes,
    };
  } finally {
    database.close();
  }
}
