import { createHash } from "node:crypto";
import { acquireTestRunMutationAuthority } from "../../../server/control-plane/TestRunMutationAuthority";
import { createDatabaseConnection, type SqliteDatabase } from "../../../server/db";
import { EventRepository } from "../../../server/events";
import { FailureDiagnosisService } from "../../../server/intelligence-v24/FailureDiagnosisService";
import { OperationalTruthService } from "../../../server/intelligence-v24/OperationalTruthService";
import { hashCanonical } from "../../../server/missions/canonical";
import { MissionRepository } from "../../../server/missions/MissionRepository";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

export type FailureDiagnosisFixtureState = "empty" | "records" | "resolution";

export interface FailureDiagnosisFixture {
  readonly state: FailureDiagnosisFixtureState;
  readonly missionId: string;
  readonly runId: string;
  readonly target: string;
  readonly timeoutDiagnosisId?: string;
  readonly secondaryDiagnosisId?: string;
  readonly lastSuccessEventId?: string;
  readonly rawErrorLogId?: string;
}

export interface FailureDiagnosisFixtureSnapshot {
  readonly runStatus: string;
  readonly diagnoses: readonly {
    readonly id: string;
    readonly state: string;
    readonly resolvedAt: string | null;
    readonly operatorActions: readonly {
      readonly kind: string;
      readonly label: string;
      readonly consequence: string;
      readonly requiresConfirmation: boolean;
    }[];
  }[];
  readonly audits: readonly {
    readonly id: string;
    readonly action: string;
    readonly actorId: string;
    readonly reason: string;
    readonly details: Readonly<Record<string, unknown>>;
    readonly previousHash: string | null;
    readonly recordHash: string;
  }[];
}

export interface FailureResolutionImmutabilityProof {
  readonly updateRejected: boolean;
  readonly deleteRejected: boolean;
  readonly updateError: string;
  readonly deleteError: string;
  readonly retainedReason: string;
  readonly retainedRecordHash: string;
}

const FIRST_FAILURE_TIME = "2026-07-16T20:00:00.000Z";
const SECOND_FAILURE_TIME = "2026-07-16T20:01:00.000Z";

function database(): SqliteDatabase {
  if (!E2E_DATABASE_PATH) throw new Error("The isolated Playwright database path was not configured");
  return createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Seeds a real V2 mission/run and persists diagnoses through the production
 * service. The browser remains responsible for every HTTP read and mutation.
 */
export function createFailureDiagnosisFixture(
  state: FailureDiagnosisFixtureState,
  instanceId: string,
): FailureDiagnosisFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const digest = createHash("sha256").update(namespace, "utf8").digest("hex").slice(0, 16);
  const target = `https://failure-${digest}.fixture.test`;
  const connection = database();

  try {
    const request = validateMissionCreateRequest({
      journey: "guided",
      launch: true,
      authorizationConfirmed: true,
      title: `Failure diagnosis ${state} browser fixture ${digest}`,
      objective: "Diagnose a bounded provider failure and preserve every prior canonical record in the authorized local fixture.",
      target,
      explanationDepth: "balanced",
      executionPreference: "manual",
      evidenceExpectations: ["Retain the exact failure cause, bounded recovery history, and immutable operator resolution."],
    });
    const created = new MissionRepository(connection).create({
      request,
      requestHash: hashCanonical(request),
      idempotencyKey: `failure-diagnosis-e2e-${namespace}`,
      actorId: "e2e-local-operator",
    });
    const blocked = connection.prepare(`
      UPDATE runs
      SET status = 'blocked', progress = 0.35,
          status_reason = 'The provider exceeded its bounded response deadline; canonical diagnosis is required before recovery.',
          next_action_summary = 'Review the structured diagnosis and choose only a declared recovery route',
          last_heartbeat_at = ?, updated_at = ?, version = version + 1
      WHERE id = ?
    `).run(FIRST_FAILURE_TIME, FIRST_FAILURE_TIME, created.run.id);
    if (blocked.changes !== 1) throw new Error("The failure-diagnosis fixture run was not moved to blocked state");

    if (state === "empty") {
      return { state, missionId: created.mission.id, runId: created.run.id, target };
    }

    let sequence = 0;
    const idFactory = (prefix: string) => `${prefix}_failure_e2e_${namespace}_${++sequence}`;
    const truth = new OperationalTruthService(connection, {
      clock: () => new Date(FIRST_FAILURE_TIME),
      idFactory,
    });
    const lastSuccess = new EventRepository(connection).append({
      runId: created.run.id,
      eventType: "step.completed",
      occurredAt: FIRST_FAILURE_TIME,
      actorType: "agent",
      actorId: "ReconScout",
      summary: "The prior bounded reconnaissance step completed and preserved one attributable observation.",
      payload: { progress: "authorized target identity confirmed" },
      sensitivity: "private",
    });
    const rawError = truth.appendEngagementLog({
      missionId: created.mission.id,
      runId: created.run.id,
      severity: "error",
      domain: "provider",
      recordType: "provider_error",
      humanSummary: "The provider request exceeded the configured deadline after bounded backoff.",
      technicalPayload: { category: "timeout", attempts: 2, target },
      sensitivity: "private",
      occurredAt: FIRST_FAILURE_TIME,
    });
    const timeout = new FailureDiagnosisService(connection, {
      clock: () => new Date(FIRST_FAILURE_TIME),
      idFactory,
    }).create({
      missionId: created.mission.id,
      runId: created.run.id,
      subjectType: "run",
      subjectId: created.run.id,
      humanReason: "The provider exceeded the bounded response deadline twice without returning a usable result.",
      category: "timeout",
      code: "provider_deadline_exceeded",
      originatingComponent: "provider-client",
      lastSuccessEventId: lastSuccess.id,
      failedComponentRef: "provider-route-primary",
      targetSummary: `Authorized local fixture ${target}`,
      policyOrDependency: "Standard mission time and two-attempt retry budget",
      rawErrorLogId: rawError.id,
      retryHistory: [
        { attempt: 1, outcome: "timeout", delayMs: 250 },
        { attempt: 2, outcome: "timeout", delayMs: 500 },
      ],
      progressBeforeFailure: {
        lastCompletedPhase: "reconnaissance",
        uniqueEvidence: 1,
        checkpointPreserved: true,
      },
      preservedReferences: [
        { kind: "event", id: lastSuccess.id, meaning: "Last successful durable transition" },
        { kind: "log", id: rawError.id, meaning: "Redacted provider deadline error" },
      ],
      retryable: true,
      automaticRecovery: [
        { action: "bounded_backoff", outcome: "exhausted", attempts: 2 },
        { action: "checkpoint", outcome: "preserved" },
      ],
      remediation: "Test provider health, then use at most one declared retry after readiness succeeds.",
      operatorActions: [
        {
          kind: "test_connection",
          label: "Test provider connection",
          consequence: "Runs a non-executing readiness probe without resuming the failed action.",
          requiresConfirmation: false,
        },
        {
          kind: "retry_bounded",
          label: "Retry once",
          consequence: "Uses one bounded retry only after the provider readiness probe succeeds.",
          requiresConfirmation: true,
        },
      ],
      objectiveImpact: "The current run cannot advance, but all prior evidence and the durable checkpoint remain preserved.",
      actor: { id: "run-supervisor", type: "system" },
    });

    let secondaryDiagnosisId: string | undefined;
    if (state === "records") {
      const secondary = new FailureDiagnosisService(connection, {
        clock: () => new Date(SECOND_FAILURE_TIME),
        idFactory,
      }).create({
        missionId: created.mission.id,
        runId: created.run.id,
        subjectType: "run",
        subjectId: created.run.id,
        humanReason: "The primary provider remained unavailable after its readiness circuit opened.",
        category: "provider_unavailable",
        code: "primary_provider_circuit_open",
        originatingComponent: "provider-router",
        lastSuccessEventId: lastSuccess.id,
        failedComponentRef: "provider-route-primary",
        targetSummary: `Authorized local fixture ${target}`,
        policyOrDependency: "Provider fallback policy",
        rawErrorLogId: rawError.id,
        retryHistory: [{ attempt: 1, outcome: "circuit_open" }],
        progressBeforeFailure: { checkpointPreserved: true },
        preservedReferences: [
          { kind: "event", id: lastSuccess.id, meaning: "Last successful durable transition" },
          { kind: "log", id: rawError.id, meaning: "Redacted provider availability error" },
        ],
        retryable: true,
        automaticRecovery: [{ action: "circuit_breaker", outcome: "opened" }],
        remediation: "Use a policy-compatible fallback provider or wait for the circuit recovery window.",
        operatorActions: [{
          kind: "use_compatible_fallback",
          label: "Use compatible fallback",
          consequence: "Selects only a configured provider route with equivalent disclosure and enforcement policy.",
          requiresConfirmation: true,
        }],
        objectiveImpact: "The active provider route is unavailable while the preserved run remains stopped.",
        actor: { id: "run-supervisor", type: "system" },
      });
      secondaryDiagnosisId = secondary.id;
    }

    if (state === "resolution") {
      // The release server resolves this fixture through the same fail-closed
      // control-plane guard as production. Seed only the disposable runtime
      // authority that its real mutation needs; the browser never receives a
      // lease token and the first synthetic conflict still reaches no service.
      acquireTestRunMutationAuthority(connection, created.run.id);
    }

    return {
      state,
      missionId: created.mission.id,
      runId: created.run.id,
      target,
      timeoutDiagnosisId: timeout.id,
      ...(secondaryDiagnosisId ? { secondaryDiagnosisId } : {}),
      lastSuccessEventId: lastSuccess.id,
      rawErrorLogId: rawError.id,
    };
  } finally {
    connection.close();
  }
}

export function readFailureDiagnosisFixtureSnapshot(
  fixture: FailureDiagnosisFixture,
): FailureDiagnosisFixtureSnapshot {
  const connection = database();
  try {
    const run = connection.prepare("SELECT status FROM runs WHERE id = ?").get(fixture.runId) as {
      readonly status: string;
    } | undefined;
    if (!run) throw new Error(`Fixture run is missing: ${fixture.runId}`);
    const diagnoses = connection.prepare(`
      SELECT id, state, resolved_at, operator_actions_json
      FROM failure_diagnoses WHERE run_id = ? ORDER BY created_at, id
    `).all(fixture.runId) as Array<{
      readonly id: string;
      readonly state: string;
      readonly resolved_at: string | null;
      readonly operator_actions_json: string;
    }>;
    const audits = connection.prepare(`
      SELECT id, action, actor_id, reason, details_json, previous_hash, record_hash
      FROM audit_records
      WHERE resource_type = 'failure_diagnosis'
        AND resource_id IN (SELECT id FROM failure_diagnoses WHERE run_id = ?)
      ORDER BY rowid
    `).all(fixture.runId) as Array<{
      readonly id: string;
      readonly action: string;
      readonly actor_id: string;
      readonly reason: string;
      readonly details_json: string;
      readonly previous_hash: string | null;
      readonly record_hash: string;
    }>;
    return {
      runStatus: run.status,
      diagnoses: diagnoses.map((diagnosis) => ({
        id: diagnosis.id,
        state: diagnosis.state,
        resolvedAt: diagnosis.resolved_at,
        operatorActions: JSON.parse(diagnosis.operator_actions_json) as FailureDiagnosisFixtureSnapshot["diagnoses"][number]["operatorActions"],
      })),
      audits: audits.map((audit) => ({
        id: audit.id,
        action: audit.action,
        actorId: audit.actor_id,
        reason: audit.reason,
        details: JSON.parse(audit.details_json) as Readonly<Record<string, unknown>>,
        previousHash: audit.previous_hash,
        recordHash: audit.record_hash,
      })),
    };
  } finally {
    connection.close();
  }
}

/** Proves both immutable triggers reject mutation while retaining the exact hash-linked record. */
export function proveFailureResolutionAuditImmutable(
  fixture: FailureDiagnosisFixture,
): FailureResolutionImmutabilityProof {
  if (!fixture.timeoutDiagnosisId) throw new Error("The fixture has no timeout diagnosis");
  const connection = database();
  try {
    const audit = connection.prepare(`
      SELECT id, reason, record_hash FROM audit_records
      WHERE resource_type = 'failure_diagnosis' AND resource_id = ?
        AND action = 'failure_diagnosis.resolved'
    `).get(fixture.timeoutDiagnosisId) as {
      readonly id: string;
      readonly reason: string;
      readonly record_hash: string;
    } | undefined;
    if (!audit) throw new Error("The canonical failure resolution audit record is missing");
    let updateRejected = false;
    let deleteRejected = false;
    let updateError = "";
    let deleteError = "";
    try {
      connection.prepare("UPDATE audit_records SET reason = 'tampered' WHERE id = ?").run(audit.id);
    } catch (error) {
      updateRejected = true;
      updateError = errorMessage(error);
    }
    try {
      connection.prepare("DELETE FROM audit_records WHERE id = ?").run(audit.id);
    } catch (error) {
      deleteRejected = true;
      deleteError = errorMessage(error);
    }
    const retained = connection.prepare("SELECT reason, record_hash FROM audit_records WHERE id = ?").get(audit.id) as {
      readonly reason: string;
      readonly record_hash: string;
    } | undefined;
    if (!retained) throw new Error("The immutable audit record disappeared after a rejected mutation");
    return {
      updateRejected,
      deleteRejected,
      updateError,
      deleteError,
      retainedReason: retained.reason,
      retainedRecordHash: retained.record_hash,
    };
  } finally {
    connection.close();
  }
}
