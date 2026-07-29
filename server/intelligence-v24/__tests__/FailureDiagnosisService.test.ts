import { afterEach, describe, expect, test } from "bun:test";
import type { SqliteDatabase } from "../../db";
import { EventRepository } from "../../events";
import { FailureDiagnosisService } from "../FailureDiagnosisService";
import { OperationalTruthError } from "../errors";
import { OperationalTruthService } from "../OperationalTruthService";
import { deterministicOptions, NOW, testDatabase } from "./fixtures";

const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function fixture() {
  const database = testDatabase();
  databases.push(database);
  const options = deterministicOptions();
  return {
    database,
    failures: new FailureDiagnosisService(database, options),
    truth: new OperationalTruthService(database, options),
  };
}

function event(database: SqliteDatabase, runId = "run-one") {
  return new EventRepository(database).append({
    runId,
    eventType: "step.completed",
    occurredAt: NOW,
    actorType: "agent",
    actorId: "ReconScout",
    summary: "The prior bounded step completed successfully.",
    payload: { progress: "service identified" },
    sensitivity: "private",
  });
}

function errorLog(truth: OperationalTruthService, missionId = "mission-one", runId = "run-one") {
  return truth.appendEngagementLog({
    missionId,
    runId,
    severity: "error",
    domain: "provider",
    recordType: "provider_error",
    humanSummary: "The provider request timed out after the bounded deadline.",
    technicalPayload: { category: "timeout", attempt: 2 },
    sensitivity: "private",
    occurredAt: NOW,
  });
}

describe("structured failure diagnosis persistence", () => {
  test("persists and reads an exact explainable diagnosis with valid recovery actions", () => {
    const { database, failures, truth } = fixture();
    const lastSuccess = event(database);
    const rawError = errorLog(truth);
    const diagnosis = failures.create({
      missionId: "mission-one",
      runId: "run-one",
      subjectType: "run",
      subjectId: "run-one",
      humanReason: "The provider exceeded the bounded response deadline twice without returning a result.",
      category: "timeout",
      code: "provider_deadline_exceeded",
      originatingComponent: "provider-client",
      lastSuccessEventId: lastSuccess.id,
      failedComponentRef: "provider-route-primary",
      targetSummary: "Authorized target lab.internal",
      policyOrDependency: "Standard mission time and retry budget",
      rawErrorLogId: rawError.id,
      retryHistory: [{ attempt: 1, outcome: "timeout" }, { attempt: 2, outcome: "timeout" }],
      progressBeforeFailure: { lastCompletedPhase: "reconnaissance", uniqueEvidence: 1 },
      preservedReferences: [
        { kind: "event", id: lastSuccess.id, meaning: "Last successful durable transition" },
        { kind: "log", id: rawError.id, meaning: "Redacted provider error detail" },
      ],
      retryable: true,
      automaticRecovery: [{ action: "bounded_backoff", outcome: "exhausted" }],
      remediation: "Test provider health, then retry once after the circuit breaker permits it.",
      operatorActions: [
        {
          kind: "test_connection",
          label: "Test provider connection",
          consequence: "Runs a non-executing readiness probe.",
          requiresConfirmation: false,
        },
        {
          kind: "retry_bounded",
          label: "Retry once",
          consequence: "Uses one remaining retry after readiness succeeds.",
          requiresConfirmation: true,
        },
      ],
      objectiveImpact: "The current run cannot advance, but all prior evidence and the checkpoint are preserved.",
      actor: { id: "run-supervisor", type: "system" },
    });

    expect(failures.get(diagnosis.id)).toEqual(diagnosis);
    expect(failures.listForRun("run-one")).toEqual([diagnosis]);
    expect(diagnosis).toMatchObject({
      category: "timeout",
      retryable: true,
      lastSuccessEventId: lastSuccess.id,
      rawErrorLogId: rawError.id,
      state: "active",
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records").get()).toEqual({ count: 1 });
  });

  test("resolution is explicit, audited, and cannot be repeated", () => {
    const { database, failures } = fixture();
    const diagnosis = failures.create({
      missionId: "mission-one",
      runId: "run-one",
      subjectType: "run",
      subjectId: "run-one",
      humanReason: "The required local dependency was unavailable at startup.",
      category: "dependency_missing",
      code: "scanner_binary_missing",
      originatingComponent: "readiness",
      retryable: false,
      remediation: "Install or configure the approved dependency, then start a new run.",
      operatorActions: [{
        kind: "configure_dependency",
        label: "Configure dependency",
        consequence: "Updates future readiness after an explicit local configuration change.",
        requiresConfirmation: true,
      }],
      objectiveImpact: "No assessment action started; the mission remains intact.",
      actor: { id: "readiness-service", type: "system" },
    });
    const resolved = failures.resolve({
      diagnosisId: diagnosis.id,
      actor: { id: "operator-one", type: "operator" },
      actionKind: "configure_dependency",
      verifiedOutcome: "The approved dependency was configured and the readiness probe passed.",
      confirmed: true,
    });
    expect(resolved).toMatchObject({ state: "resolved", resolvedAt: NOW });
    expect(failures.listForRun("run-one")).toEqual([]);
    expect(failures.listForRun("run-one", ["resolved"])).toEqual([resolved]);
    expect(() => failures.resolve({
      diagnosisId: diagnosis.id,
      actor: { id: "operator-one", type: "operator" },
      actionKind: "configure_dependency",
      verifiedOutcome: "Attempt a duplicate resolution after the record was already closed.",
      confirmed: true,
    })).toThrow(OperationalTruthError);
    expect(database.prepare("SELECT action FROM audit_records ORDER BY rowid").all())
      .toEqual([{ action: "failure_diagnosis.created" }, { action: "failure_diagnosis.resolved" }]);
    const audit = database.prepare(`
      SELECT actor_id, reason, details_json FROM audit_records
      WHERE action = 'failure_diagnosis.resolved' AND resource_id = ?
    `).get(diagnosis.id) as { actor_id: string; reason: string; details_json: string };
    expect(audit).toMatchObject({
      actor_id: "operator-one",
      reason: "Declared recovery action: configure_dependency — Configure dependency. Operator-verified outcome: The approved dependency was configured and the readiness probe passed.",
    });
    expect(JSON.parse(audit.details_json)).toEqual({
      actionKind: "configure_dependency",
      actionLabel: "Configure dependency",
      actionRequiresConfirmation: true,
      category: "dependency_missing",
      code: "scanner_binary_missing",
      confirmed: true,
      from: "active",
      to: "resolved",
      verifiedOutcome: "The approved dependency was configured and the readiness probe passed.",
    });
  });

  test("resolves a terminal diagnosis through the same typed declared-action gate", () => {
    const { database, failures } = fixture();
    const diagnosis = failures.create({
      missionId: "mission-one",
      runId: "run-one",
      subjectType: "run",
      subjectId: "run-one",
      humanReason: "The bounded run ended after its required local dependency remained unavailable.",
      category: "dependency_missing",
      code: "terminal_dependency_missing",
      originatingComponent: "readiness",
      retryable: false,
      remediation: "Configure the dependency before starting another run.",
      operatorActions: [{
        kind: "start_new_run",
        label: "Start a new run",
        consequence: "Creates a separate run after readiness is independently verified.",
        requiresConfirmation: true,
      }],
      objectiveImpact: "The ended run remains preserved and no assessment action is resumed in place.",
      terminal: true,
      actor: { id: "run-supervisor", type: "system" },
    });
    expect(diagnosis.state).toBe("terminal");
    const resolved = failures.resolve({
      diagnosisId: diagnosis.id,
      actor: { id: "operator-one", type: "operator" },
      actionKind: "start_new_run",
      verifiedOutcome: "A separate readiness-verified run was created and this terminal record was reconciled.",
      confirmed: true,
    });
    expect(resolved).toMatchObject({ state: "resolved", resolvedAt: NOW });
    const audit = database.prepare(`
      SELECT reason, details_json FROM audit_records
      WHERE action = 'failure_diagnosis.resolved' AND resource_id = ?
    `).get(diagnosis.id) as { reason: string; details_json: string };
    expect(audit.reason).toContain("Declared recovery action: start_new_run — Start a new run.");
    expect(JSON.parse(audit.details_json)).toMatchObject({ from: "terminal", to: "resolved", confirmed: true });
  });

  test("rejects undeclared actions, missing confirmation, and insufficient verified outcomes without partial resolution", () => {
    const { database, failures } = fixture();
    const diagnosis = failures.create({
      missionId: "mission-one",
      runId: "run-one",
      subjectType: "run",
      subjectId: "run-one",
      humanReason: "The provider readiness probe is required before bounded recovery.",
      category: "timeout",
      code: "readiness_probe_required",
      originatingComponent: "provider-client",
      retryable: true,
      remediation: "Run only the declared connection check and record its verified outcome.",
      operatorActions: [{
        kind: "test_connection",
        label: "Test provider connection",
        consequence: "Runs one non-executing readiness probe.",
        requiresConfirmation: false,
      }],
      objectiveImpact: "The stopped run remains at its durable checkpoint.",
      actor: { id: "run-supervisor", type: "system" },
    });
    expect(() => failures.resolve({
      diagnosisId: diagnosis.id,
      actor: { id: "operator-one", type: "operator" },
      actionKind: "retry_bounded",
      verifiedOutcome: "The undeclared retry appeared to produce a result but cannot close this record.",
      confirmed: true,
    })).toThrow("not declared");
    expect(() => failures.resolve({
      diagnosisId: diagnosis.id,
      actor: { id: "operator-one", type: "operator" },
      actionKind: "test_connection",
      verifiedOutcome: "The readiness probe passed and returned an attributable healthy response.",
      confirmed: false,
    })).toThrow("explicit confirmation");
    expect(() => failures.resolve({
      diagnosisId: diagnosis.id,
      actor: { id: "operator-one", type: "operator" },
      actionKind: "test_connection",
      verifiedOutcome: "Probe passed.",
      confirmed: true,
    })).toThrow("at least 16 characters");
    expect(failures.get(diagnosis.id).state).toBe("active");
    expect(database.prepare("SELECT action FROM audit_records ORDER BY rowid").all())
      .toEqual([{ action: "failure_diagnosis.created" }]);
  });

  test("rejects unsafe retryability and cross-engagement error references without partial persistence", () => {
    const { database, failures, truth } = fixture();
    expect(() => failures.create({
      missionId: "mission-one",
      runId: "run-one",
      subjectType: "run",
      subjectId: "run-one",
      humanReason: "Policy denied the requested action.",
      category: "policy_denied",
      code: "action_class_prohibited",
      originatingComponent: "policy-engine",
      retryable: true,
      remediation: "Amend future authorized scope through the explicit contract workflow.",
      operatorActions: [{
        kind: "retry_bounded",
        label: "Retry",
        consequence: "This action must never be offered for a policy denial.",
        requiresConfirmation: true,
      }],
      objectiveImpact: "The prohibited path is unavailable.",
      actor: { id: "policy-engine", type: "system" },
    })).toThrow(OperationalTruthError);

    const foreignLog = errorLog(truth, "mission-two", "run-two");
    expect(() => failures.create({
      missionId: "mission-one",
      runId: "run-one",
      subjectType: "run",
      subjectId: "run-one",
      humanReason: "A local timeout occurred but the supplied raw log is foreign.",
      category: "timeout",
      code: "local_timeout",
      originatingComponent: "worker",
      rawErrorLogId: foreignLog.id,
      retryable: true,
      remediation: "Use a same-run error reference before selecting recovery.",
      operatorActions: [{
        kind: "retry_bounded",
        label: "Retry once",
        consequence: "Consumes one bounded retry.",
        requiresConfirmation: true,
      }],
      objectiveImpact: "The current step is waiting for a valid diagnosis.",
      actor: { id: "run-supervisor", type: "system" },
    })).toThrow(OperationalTruthError);
    expect(database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records").get()).toEqual({ count: 0 });
  });

  test("typed subjects must match their canonical references", () => {
    const { database, failures } = fixture();
    expect(() => failures.create({
      missionId: "mission-one",
      runId: "run-one",
      subjectType: "step",
      subjectId: "run-one",
      humanReason: "The subject deliberately mismatches the canonical step reference.",
      category: "plan_dependency_unresolved",
      code: "dependency_wait",
      originatingComponent: "plan-engine",
      retryable: false,
      remediation: "Select the exact blocked step before persisting a diagnosis.",
      operatorActions: [{
        kind: "amend_plan",
        label: "Amend plan",
        consequence: "Creates a versioned plan change request.",
        requiresConfirmation: true,
      }],
      objectiveImpact: "The plan cannot advance until its dependency is resolved.",
      actor: { id: "run-supervisor", type: "system" },
    })).toThrow(OperationalTruthError);
    expect(database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: 0 });
  });
});
