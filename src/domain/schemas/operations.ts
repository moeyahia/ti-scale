import type {
  ActionRecord, AgentAssignment, AgentCapability, AgentRecord, ArtifactRecord, EvaluationRecord, EventRecord,
  EvaluationBudget, EvaluationBudgetMetric, EvaluationComparison, EvaluationComparisonMetric,
  EvidenceRecord, FindingRecord, FollowUpRunRecord, HealthStatus, LessonRecord, LessonUsageRecord, LogRecord,
  AdministrativeApprovalReviewRecord, DecisionInboxRecord,
  McpRecord, MissionReference, OperationsPage, PolicyRecord, ProviderRecord, RecoveryMutationRecord, RunRecoveryRecord,
  TraceDetailRecord, TraceRecord, TraceSummaryRecord,
  ReportGenerationRecord,
} from "../types/operations";
import { array, boolean, nonEmpty, nullableNumber, nullableString, number, object, schema, string } from "./common";

type Parser<T> = (value: unknown) => T;

function mission(value: unknown, label = "mission"): MissionReference {
  const item = object(value, label);
  return { id: nonEmpty(item.id, `${label}.id`), name: nonEmpty(item.name, `${label}.name`) };
}

function page<T>(payload: unknown, parse: Parser<T>): OperationsPage<T> {
  const root = object(payload, "operations page");
  schema(root);
  return {
    schemaVersion: "2.4",
    items: array(root.items, "operations page items").map(parse),
    nextCursor: nullableString(root.nextCursor, "nextCursor"),
  };
}

function health(value: unknown): HealthStatus {
  const item = object(value, "health");
  return {
    ...(typeof item.id === "string" ? { id: item.id } : {}),
    ...(typeof item.componentType === "string" ? { componentType: item.componentType } : {}),
    ...(typeof item.componentId === "string" ? { componentId: item.componentId } : {}),
    status: nonEmpty(item.status, "health.status"),
    metrics: item.metrics ?? {},
    message: nullableString(item.message, "health.message"),
    capturedAt: nonEmpty(item.capturedAt, "health.capturedAt"),
  };
}

function capability(value: unknown): AgentCapability {
  const item = object(value, "agent capability");
  return { name: nonEmpty(item.name, "capability.name"), source: nonEmpty(item.source, "capability.source"), enabled: boolean(item.enabled, "capability.enabled"), metadata: item.metadata ?? {} };
}

export function parseAgent(value: unknown): AgentRecord {
  const item = object(value, "agent");
  const assignment = object(item.assignmentHealth, "agent.assignmentHealth");
  return {
    id: nonEmpty(item.id, "agent.id"), role: nonEmpty(item.role, "agent.role"), displayName: nonEmpty(item.displayName, "agent.displayName"),
    status: nonEmpty(item.status, "agent.status"), version: string(item.version, "agent.version"),
    lastHeartbeatAt: nullableString(item.lastHeartbeatAt, "agent.lastHeartbeatAt"), updatedAt: nonEmpty(item.updatedAt, "agent.updatedAt"),
    providerPolicy: item.providerPolicy ?? {}, toolPolicy: item.toolPolicy ?? {}, configuration: item.configuration ?? {},
    assignmentHealth: {
      queueDepth: number(assignment.queueDepth, "queueDepth"), active: number(assignment.active, "active"),
      completed: number(assignment.completed, "completed"), failed: number(assignment.failed, "failed"),
      successRate: nullableNumber(assignment.successRate, "successRate"), meanCompletionSeconds: nullableNumber(assignment.meanCompletionSeconds, "meanCompletionSeconds"),
      lastAssignmentAt: nullableString(assignment.lastAssignmentAt, "lastAssignmentAt"),
    },
    health: item.health === null || item.health === undefined ? null : health(item.health),
    ...(Array.isArray(item.capabilities) ? { capabilities: item.capabilities.map(capability) } : {}),
    ...(Array.isArray(item.healthHistory) ? { healthHistory: item.healthHistory.map(health) } : {}),
  };
}

export function parseAgents(payload: unknown): OperationsPage<AgentRecord> { return page(payload, parseAgent); }

function parseAssignment(value: unknown): AgentAssignment {
  const item = object(value, "assignment");
  const missionValue = object(item.mission, "assignment.mission");
  const run = object(item.run, "assignment.run");
  const lease = object(item.lease, "assignment.lease");
  const step = item.step === null ? null : object(item.step, "assignment.step");
  const journey = run.journey === "autonomous" || run.journey === "guided" ? run.journey : (() => { throw new Error("assignment journey is invalid"); })();
  return {
    id: nonEmpty(item.id, "assignment.id"), status: nonEmpty(item.status, "assignment.status"),
    mission: { ...mission(missionValue, "assignment.mission"), engagementId: nullableString(missionValue.engagementId, "engagementId") },
    run: { id: nonEmpty(run.id, "run.id"), status: nonEmpty(run.status, "run.status"), journey, progress: nullableNumber(run.progress, "run.progress") },
    step: step ? { id: nonEmpty(step.id, "step.id"), phase: nonEmpty(step.phase, "step.phase"), title: nonEmpty(step.title, "step.title") } : null,
    lease: { owner: nullableString(lease.owner, "lease.owner"), acquiredAt: nullableString(lease.acquiredAt, "lease.acquiredAt"), lastHeartbeatAt: nullableString(lease.lastHeartbeatAt, "lease.lastHeartbeatAt"), expiresAt: nullableString(lease.expiresAt, "lease.expiresAt"), expired: boolean(lease.expired, "lease.expired") },
    startedAt: nullableString(item.startedAt, "startedAt"), endedAt: nullableString(item.endedAt, "endedAt"), updatedAt: nonEmpty(item.updatedAt, "updatedAt"),
  };
}

export function parseAgentAssignments(payload: unknown): OperationsPage<AgentAssignment> { return page(payload, parseAssignment); }

function safeDecisionDeepLink(value: unknown): string {
  const link = nonEmpty(value, "decision.deepLink");
  if (!link.startsWith("/") || link.startsWith("//") || link.includes("\\")) {
    throw new Error("decision deep link is invalid");
  }
  return link;
}

function parseDecisionInboxRecord(value: unknown): DecisionInboxRecord {
  const item = object(value, "decision inbox record");
  const allowedKinds = new Set(["guided_decision", "autonomous_contract", "autonomous_exception", "administrative_approval"] as const);
  const kind = nonEmpty(item.kind, "decision.kind") as DecisionInboxRecord["kind"];
  if (!allowedKinds.has(kind)) throw new Error("decision inbox kind is invalid");
  const missionValue = item.mission === null ? null : object(item.mission, "decision.mission");
  const missionRecord = missionValue ? {
    ...mission(missionValue, "decision.mission"),
    engagementId: nullableString(missionValue.engagementId, "decision.mission.engagementId"),
  } : null;
  const runValue = item.run === null ? null : object(item.run, "decision.run");
  const journey = runValue?.journey;
  if (runValue && journey !== "autonomous" && journey !== "guided") {
    throw new Error("decision run journey is invalid");
  }
  const runRecord = runValue ? {
    id: nonEmpty(runValue.id, "decision.run.id"),
    status: nonEmpty(runValue.status, "decision.run.status"),
    journey: journey as "autonomous" | "guided",
  } : null;
  const base = {
    id: nonEmpty(item.id, "decision.id"),
    mission: missionRecord,
    run: runRecord,
    status: nonEmpty(item.status, "decision.status"),
    title: nonEmpty(item.title, "decision.title"),
    summary: string(item.summary, "decision.summary"),
    createdAt: nonEmpty(item.createdAt, "decision.createdAt"),
    resolvedAt: nullableString(item.resolvedAt, "decision.resolvedAt"),
    expiresAt: nullableString(item.expiresAt, "decision.expiresAt"),
    deepLink: safeDecisionDeepLink(item.deepLink),
  };
  if (kind === "guided_decision") {
    if (!missionRecord || !runRecord || runRecord.journey !== "guided") throw new Error("Guided decision scope is invalid");
    if (!new Set(["pending", "approved", "manual", "alternative", "rejected", "expired", "cancelled"]).has(base.status)) {
      throw new Error("Guided decision status is invalid");
    }
    const exact = object(item.exactStep, "decision.exactStep");
    return {
      ...base, kind, mission: missionRecord, run: { ...runRecord, journey: "guided" },
      exactStep: {
        stepId: nonEmpty(exact.stepId, "decision.exactStep.stepId"),
        actionFingerprint: nonEmpty(exact.actionFingerprint, "decision.exactStep.actionFingerprint"),
        requestedParameters: exact.requestedParameters ?? {},
        rationale: string(exact.rationale, "decision.exactStep.rationale"),
        riskClass: nonEmpty(exact.riskClass, "decision.exactStep.riskClass"),
        reversibility: string(exact.reversibility, "decision.exactStep.reversibility"),
        decisionActor: nullableString(exact.decisionActor, "decision.exactStep.decisionActor"),
        decisionReason: nullableString(exact.decisionReason, "decision.exactStep.decisionReason"),
      },
    };
  }
  if (kind === "autonomous_contract") {
    if (!missionRecord) throw new Error("Autonomous contract mission is missing");
    const contract = object(item.contract, "decision.contract");
    const state = nonEmpty(contract.state, "decision.contract.state");
    if (!new Set(["draft", "confirmed", "superseded", "revoked"]).has(state)) throw new Error("contract state is invalid");
    const contractVersion = number(contract.version, "decision.contract.version");
    const contractHash = nonEmpty(contract.hash, "decision.contract.hash");
    if (!Number.isSafeInteger(contractVersion) || contractVersion < 1 || contractHash.length < 32) {
      throw new Error("contract identity is invalid");
    }
    return {
      ...base, kind, mission: missionRecord,
      contract: {
        version: contractVersion,
        hash: contractHash,
        state: state as "draft" | "confirmed" | "superseded" | "revoked",
        confirmedBy: nullableString(contract.confirmedBy, "decision.contract.confirmedBy"),
        confirmedAt: nullableString(contract.confirmedAt, "decision.contract.confirmedAt"),
      },
    };
  }
  if (kind === "autonomous_exception") {
    if (!missionRecord || !runRecord || runRecord.journey !== "autonomous") throw new Error("Autonomous exception scope is invalid");
    const exception = object(item.exception, "decision.exception");
    const phase = nonEmpty(exception.phase, "decision.exception.phase");
    if (phase !== "active" && phase !== "post_run") throw new Error("exception phase is invalid");
    const sequence = number(exception.sequence, "decision.exception.sequence");
    if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error("exception sequence is invalid");
    return {
      ...base, kind, mission: missionRecord, run: { ...runRecord, journey: "autonomous" },
      exception: {
        eventType: nonEmpty(exception.eventType, "decision.exception.eventType"),
        sequence,
        phase,
        code: nullableString(exception.code, "decision.exception.code"),
        category: nullableString(exception.category, "decision.exception.category"),
        traceId: nullableString(exception.traceId, "decision.exception.traceId"),
        details: exception.details ?? {},
      },
    };
  }
  const approval = object(item.approval, "decision.approval");
  if (!new Set(["pending", "approved", "rejected", "expired", "cancelled"]).has(base.status)) {
    throw new Error("administrative approval status is invalid");
  }
  return {
    ...base, kind,
    approval: {
      approvalType: nonEmpty(approval.approvalType, "decision.approval.approvalType"),
      requestedBy: nonEmpty(approval.requestedBy, "decision.approval.requestedBy"),
      policyRule: nullableString(approval.policyRule, "decision.approval.policyRule"),
      request: approval.request ?? {},
      decidedBy: nullableString(approval.decidedBy, "decision.approval.decidedBy"),
      reviewAvailable: boolean(approval.reviewAvailable, "decision.approval.reviewAvailable"),
      reviewUnavailableReason: nullableString(approval.reviewUnavailableReason, "decision.approval.reviewUnavailableReason"),
    },
  };
}

export function parseDecisionInboxPage(payload: unknown): OperationsPage<DecisionInboxRecord> {
  return page(payload, parseDecisionInboxRecord);
}

export function parseAdministrativeApprovalReview(payload: unknown): AdministrativeApprovalReviewRecord {
  const root = object(payload, "administrative approval review");
  schema(root);
  const approval = object(root.approval, "administrative approval review.approval");
  const status = nonEmpty(approval.status, "approval.status");
  if (status !== "approved" && status !== "rejected") throw new Error("administrative review status is invalid");
  if (approval.runtimeStateChanged !== false || approval.autonomousActionUnblocked !== false) {
    throw new Error("administrative review must not mutate runtime authority");
  }
  return {
    schemaVersion: "2.4",
    approval: {
      id: nonEmpty(approval.id, "approval.id"),
      missionId: nullableString(approval.missionId, "approval.missionId"),
      runId: nullableString(approval.runId, "approval.runId"),
      approvalType: nonEmpty(approval.approvalType, "approval.approvalType"),
      status,
      decidedBy: nonEmpty(approval.decidedBy, "approval.decidedBy"),
      decidedAt: nonEmpty(approval.decidedAt, "approval.decidedAt"),
      decisionReason: string(approval.decisionReason, "approval.decisionReason"),
      runtimeStateChanged: false,
      autonomousActionUnblocked: false,
    },
  };
}

export function parseRunRecovery(payload: unknown): RunRecoveryRecord {
  const root = object(payload, "run recovery"); schema(root);
  const run = object(root.run, "run recovery.run");
  const journey = run.journey === "autonomous" || run.journey === "guided"
    ? run.journey
    : (() => { throw new Error("recovery journey is invalid"); })();
  const detection = object(root.detection, "run recovery.detection");
  const boundaryValue = root.boundary === null ? null : object(root.boundary, "run recovery.boundary");
  const checkpointValue = root.checkpoint === null ? null : object(root.checkpoint, "run recovery.checkpoint");
  const attempts = object(root.attempts, "run recovery.attempts");
  const proposal = object(root.proposedRecovery, "run recovery.proposedRecovery");
  const impact = object(proposal.impact, "run recovery.proposedRecovery.impact");
  const proposalKinds = new Set(["automatic_recovery", "guided_decision", "operator_resume", "safe_stop", "failed_safely", "none"] as const);
  const proposalKind = nonEmpty(proposal.kind, "proposedRecovery.kind") as RunRecoveryRecord["proposedRecovery"]["kind"];
  if (!proposalKinds.has(proposalKind)) throw new Error("proposed recovery kind is invalid");
  const decisionValue = root.guidedDecision === null ? null : object(root.guidedDecision, "run recovery.guidedDecision");
  const actionKinds = new Set(["resume", "replan", "reassign", "change_provider", "terminate"] as const);
  return {
    schemaVersion: "2.4",
    recoveryRequired: boolean(root.recoveryRequired, "recoveryRequired"),
    run: {
      id: nonEmpty(run.id, "run.id"), missionId: nonEmpty(run.missionId, "run.missionId"),
      missionName: nonEmpty(run.missionName, "run.missionName"), journey,
      status: nonEmpty(run.status, "run.status"), version: number(run.version, "run.version"),
      statusReason: nullableString(run.statusReason, "run.statusReason"),
      currentStepId: nullableString(run.currentStepId, "run.currentStepId"),
      currentOwnerId: nullableString(run.currentOwnerId, "run.currentOwnerId"),
      nextAction: nullableString(run.nextAction, "run.nextAction"),
      leaseExpiresAt: nullableString(run.leaseExpiresAt, "run.leaseExpiresAt"),
    },
    boundary: boundaryValue ? {
      planId: nonEmpty(boundaryValue.planId, "boundary.planId"),
      planVersion: number(boundaryValue.planVersion, "boundary.planVersion"),
      stepId: nonEmpty(boundaryValue.stepId, "boundary.stepId"),
      assignmentId: nonEmpty(boundaryValue.assignmentId, "boundary.assignmentId"),
      agentId: nonEmpty(boundaryValue.agentId, "boundary.agentId"),
      actionKind: nullableString(boundaryValue.actionKind, "boundary.actionKind"),
    } : null,
    reassignmentCandidates: array(root.reassignmentCandidates, "reassignmentCandidates").map((value) => {
      const item = object(value, "reassignment candidate");
      if (item.status !== "available") throw new Error("reassignment candidate status is invalid");
      return {
        agentId: nonEmpty(item.agentId, "candidate.agentId"),
        displayName: nonEmpty(item.displayName, "candidate.displayName"),
        status: "available" as const,
        capabilities: array(item.capabilities, "candidate.capabilities").map((capability) => nonEmpty(capability, "candidate.capability")),
      };
    }),
    providerCandidates: array(root.providerCandidates, "providerCandidates").map((value) => {
      const item = object(value, "provider candidate");
      const status = item.status === "healthy" || item.status === "degraded" || item.status === "unhealthy" ||
        item.status === "unknown" || item.status === "missing"
        ? item.status
        : (() => { throw new Error("provider candidate status is invalid"); })();
      const eligibility = item.eligibility === "compatible" || item.eligibility === "unavailable" ||
        item.eligibility === "stale" || item.eligibility === "budget_incompatible" ||
        item.eligibility === "enforcement_incompatible"
        ? item.eligibility
        : (() => { throw new Error("provider candidate eligibility is invalid"); })();
      const modelId = nullableString(item.modelId, "provider.modelId");
      const modelConfigurationHash = nullableString(item.modelConfigurationHash, "provider.modelConfigurationHash");
      const enabled = boolean(item.enabled, "provider.enabled");
      if (
        (modelId === null) !== (modelConfigurationHash === null) ||
        (modelConfigurationHash !== null && !/^[a-f0-9]{64}$/u.test(modelConfigurationHash)) ||
        enabled !== (eligibility === "compatible") ||
        (enabled && modelId === null)
      ) throw new Error("provider candidate model pin is invalid");
      return {
        providerId: nonEmpty(item.providerId, "provider.providerId"),
        modelId,
        modelConfigurationHash,
        status,
        eligibility,
        enabled,
        reason: nonEmpty(item.reason, "provider.reason"),
        supportsGuided: boolean(item.supportsGuided, "provider.supportsGuided"),
        enforcesAutonomousBoundary: boolean(item.enforcesAutonomousBoundary, "provider.enforcesAutonomousBoundary"),
        reportsExactTokenUsage: boolean(item.reportsExactTokenUsage, "provider.reportsExactTokenUsage"),
        reportsExactCostUsage: boolean(item.reportsExactCostUsage, "provider.reportsExactCostUsage"),
      };
    }),
    detection: {
      summary: string(detection.summary, "detection.summary"),
      category: nullableString(detection.category, "detection.category"),
      evidence: array(detection.evidence, "detection.evidence").map((value) => {
        const item = object(value, "detection evidence"); return {
          id: nonEmpty(item.id, "event.id"), eventType: nonEmpty(item.eventType, "event.eventType"),
          summary: string(item.summary, "event.summary"), occurredAt: nonEmpty(item.occurredAt, "event.occurredAt"),
          sequence: number(item.sequence, "event.sequence"),
        };
      }),
      failedActions: array(detection.failedActions, "detection.failedActions").map((value) => {
        const item = object(value, "failed action"); return {
          id: nonEmpty(item.id, "action.id"), status: nonEmpty(item.status, "action.status"),
          intentSummary: string(item.intentSummary, "action.intentSummary"),
          resultSummary: nullableString(item.resultSummary, "action.resultSummary"),
          errorCategory: nullableString(item.errorCategory, "action.errorCategory"),
          retryCount: number(item.retryCount, "action.retryCount"), endedAt: nullableString(item.endedAt, "action.endedAt"),
        };
      }),
    },
    checkpoint: checkpointValue ? {
      id: nonEmpty(checkpointValue.id, "checkpoint.id"),
      eventSequence: number(checkpointValue.eventSequence, "checkpoint.eventSequence"),
      planVersion: nullableNumber(checkpointValue.planVersion, "checkpoint.planVersion"),
      createdAt: nonEmpty(checkpointValue.createdAt, "checkpoint.createdAt"),
      stateHash: nonEmpty(checkpointValue.stateHash, "checkpoint.stateHash"),
      inFlightClassification: nullableString(checkpointValue.inFlightClassification, "checkpoint.inFlightClassification"),
      completedActionCount: number(checkpointValue.completedActionCount, "checkpoint.completedActionCount"),
      inFlightActions: array(checkpointValue.inFlightActions, "checkpoint.inFlightActions").map((value) => {
        const item = object(value, "in-flight action"); return {
          id: nonEmpty(item.id, "in-flight action.id"), status: nonEmpty(item.status, "in-flight action.status"),
          idempotent: boolean(item.idempotent, "in-flight action.idempotent"),
          destructive: boolean(item.destructive, "in-flight action.destructive"),
        };
      }),
    } : null,
    attempts: {
      retryCount: number(attempts.retryCount, "attempts.retryCount"),
      retryLimit: nullableNumber(attempts.retryLimit, "attempts.retryLimit"),
      retriesRemaining: nullableNumber(attempts.retriesRemaining, "attempts.retriesRemaining"),
      replanCount: number(attempts.replanCount, "attempts.replanCount"),
      replanLimit: nullableNumber(attempts.replanLimit, "attempts.replanLimit"),
      replansRemaining: nullableNumber(attempts.replansRemaining, "attempts.replansRemaining"),
    },
    proposedRecovery: {
      kind: proposalKind, summary: string(proposal.summary, "proposedRecovery.summary"),
      basis: string(proposal.basis, "proposedRecovery.basis"),
      impact: {
        time: string(impact.time, "impact.time"), cost: string(impact.cost, "impact.cost"),
        scope: string(impact.scope, "impact.scope"),
      },
    },
    guidedDecision: decisionValue ? {
      id: nonEmpty(decisionValue.id, "guidedDecision.id"), stepId: nonEmpty(decisionValue.stepId, "guidedDecision.stepId"),
      actionFingerprint: nonEmpty(decisionValue.actionFingerprint, "guidedDecision.actionFingerprint"),
      rationale: string(decisionValue.rationale, "guidedDecision.rationale"),
      riskClass: nonEmpty(decisionValue.riskClass, "guidedDecision.riskClass"),
      expiresAt: nonEmpty(decisionValue.expiresAt, "guidedDecision.expiresAt"),
    } : null,
    failedAttemptMemories: array(root.failedAttemptMemories, "failedAttemptMemories").map((value) => {
      const item = object(value, "failed-attempt memory");
      const kind = item.kind === "memory" || item.kind === "lesson" ? item.kind : (() => { throw new Error("failed-attempt memory kind is invalid"); })();
      return { kind, id: nonEmpty(item.id, "memory.id"), title: string(item.title, "memory.title"),
        status: nonEmpty(item.status, "memory.status"), confidence: nullableNumber(item.confidence, "memory.confidence"),
        failureCategory: nullableString(item.failureCategory, "memory.failureCategory") };
    }),
    actions: array(root.actions, "recovery actions").map((value) => {
      const item = object(value, "recovery action");
      const kind = nonEmpty(item.kind, "recovery action.kind") as RunRecoveryRecord["actions"][number]["kind"];
      if (!actionKinds.has(kind)) throw new Error("recovery action kind is invalid");
      const command = item.command === null || item.command === "resume" || item.command === "replan" ||
        item.command === "reassign" || item.command === "change_provider" || item.command === "cancel"
        ? item.command : (() => { throw new Error("recovery action command is invalid"); })();
      return { kind, label: nonEmpty(item.label, "recovery action.label"),
        available: boolean(item.available, "recovery action.available"), reason: string(item.reason, "recovery action.reason"), command };
    }),
  };
}

export function parseRecoveryMutation(payload: unknown): RecoveryMutationRecord {
  const root = object(payload, "recovery mutation");
  schema(root);
  const mutation = object(root.mutation, "recovery mutation.mutation");
  const kind = nonEmpty(mutation.kind, "mutation.kind");
  if (kind !== "replan" && kind !== "reassign" && kind !== "change_provider") {
    throw new Error("recovery mutation kind is invalid");
  }
  const run = object(root.run, "recovery mutation.run");
  const journey = run.journey === "autonomous" || run.journey === "guided"
    ? run.journey
    : (() => { throw new Error("recovery mutation journey is invalid"); })();
  const providerId = nullableString(mutation.providerId, "mutation.providerId");
  const modelId = nullableString(mutation.modelId, "mutation.modelId");
  const modelConfigurationHash = nullableString(mutation.modelConfigurationHash, "mutation.modelConfigurationHash");
  if (modelConfigurationHash !== null && !/^[a-f0-9]{64}$/u.test(modelConfigurationHash)) {
    throw new Error("mutation.modelConfigurationHash is invalid");
  }
  if (kind === "change_provider" && (!providerId || !modelId || !modelConfigurationHash)) {
    throw new Error("provider recovery mutation model pin is incomplete");
  }
  if (kind !== "change_provider" && (providerId !== null || modelId !== null || modelConfigurationHash !== null)) {
    throw new Error("non-provider recovery mutation contains a provider model pin");
  }
  return {
    schemaVersion: "2.4",
    mutation: {
      kind,
      eventId: nonEmpty(mutation.eventId, "mutation.eventId"),
      checkpointId: nonEmpty(mutation.checkpointId, "mutation.checkpointId"),
      continuationId: nullableString(mutation.continuationId, "mutation.continuationId"),
      agentId: nullableString(mutation.agentId, "mutation.agentId"),
      assignmentId: nullableString(mutation.assignmentId, "mutation.assignmentId"),
      providerId,
      modelId,
      modelConfigurationHash,
      providerRouteVersion: nullableNumber(mutation.providerRouteVersion, "mutation.providerRouteVersion"),
    },
    run: {
      id: nonEmpty(run.id, "run.id"),
      journey,
      status: nonEmpty(run.status, "run.status"),
      version: number(run.version, "run.version"),
      planId: nonEmpty(run.planId, "run.planId"),
      planVersion: number(run.planVersion, "run.planVersion"),
      stepId: nonEmpty(run.stepId, "run.stepId"),
      assignmentId: nonEmpty(run.assignmentId, "run.assignmentId"),
    },
  };
}

export function parseFollowUpRun(payload: unknown): FollowUpRunRecord {
  const root = object(payload, "follow-up run");
  schema(root);
  const run = object(root.run, "follow-up run.run");
  const journey = run.journey === "autonomous" || run.journey === "guided"
    ? run.journey
    : (() => { throw new Error("follow-up run journey is invalid"); })();
  if (run.status !== "planning") throw new Error("follow-up run status is invalid");
  const nextUrl = nonEmpty(root.nextUrl, "follow-up run.nextUrl");
  if (!nextUrl.startsWith("/missions/") || nextUrl.startsWith("//") || nextUrl.includes("\\")) {
    throw new Error("follow-up run next URL is invalid");
  }
  return {
    schemaVersion: "2.4",
    sourceRunId: nonEmpty(root.sourceRunId, "follow-up run.sourceRunId"),
    run: {
      id: nonEmpty(run.id, "follow-up run.id"),
      missionId: nonEmpty(run.missionId, "follow-up run.missionId"),
      missionName: nonEmpty(run.missionName, "follow-up run.missionName"),
      journey,
      status: "planning",
      statusReason: string(run.statusReason, "follow-up run.statusReason"),
      nextAction: string(run.nextAction, "follow-up run.nextAction"),
      createdAt: nonEmpty(run.createdAt, "follow-up run.createdAt"),
    },
    selectedLessons: array(root.selectedLessons, "follow-up run.selectedLessons").map((value, index) => {
      const item = object(value, `follow-up run.selectedLessons[${index}]`);
      if (item.selectionState !== "eligible_for_planning") {
        throw new Error("follow-up lesson selection state is invalid");
      }
      return {
        id: nonEmpty(item.id, "selected lesson.id"),
        nodeId: nonEmpty(item.nodeId, "selected lesson.nodeId"),
        statement: string(item.statement, "selected lesson.statement"),
        selectionState: "eligible_for_planning" as const,
      };
    }),
    nextUrl,
  };
}

export function parseEvidence(value: unknown): EvidenceRecord {
  const item = object(value, "evidence");
  const recordClass = item.recordClass === "evidence" || item.recordClass === "operational_log"
    ? item.recordClass
    : (() => { throw new Error("evidence.recordClass is invalid"); })();
  const run = item.run === undefined || item.run === null ? null : object(item.run, "evidence.run");
  const artifact = item.artifact === undefined || item.artifact === null
    ? null
    : object(item.artifact, "evidence.artifact");
  return {
    id: nonEmpty(item.id, "evidence.id"), mission: mission(item.mission), runId: nullableString(item.runId, "runId"), stepId: nullableString(item.stepId, "stepId"), actionId: nullableString(item.actionId, "actionId"),
    ...(item.run !== undefined ? { run: run ? { id: nonEmpty(run.id, "evidence.run.id") } : null } : {}),
    source: string(item.source, "source"), acquiredAt: nonEmpty(item.acquiredAt, "acquiredAt"), target: nullableString(item.target, "target"), evidenceType: nonEmpty(item.evidenceType, "evidenceType"), recordClass, contentHash: nonEmpty(item.contentHash, "contentHash"),
    provenance: item.provenance ?? {}, confidence: nullableNumber(item.confidence, "confidence"), sensitivity: nonEmpty(item.sensitivity, "sensitivity"), verificationState: nonEmpty(item.verificationState, "verificationState"),
    summary: string(item.summary, "summary"), hasExtractedText: boolean(item.hasExtractedText, "hasExtractedText"), artifactId: nullableString(item.artifactId, "artifactId"), createdBy: nonEmpty(item.createdBy, "createdBy"), createdAt: nonEmpty(item.createdAt, "createdAt"),
    ...(item.artifact !== undefined ? { artifact: artifact ? { id: nonEmpty(artifact.id, "evidence.artifact.id"), artifactType: nonEmpty(artifact.artifactType, "evidence.artifact.artifactType") } : null } : {}),
    ...(Array.isArray(item.chainOfCustody) ? { chainOfCustody: item.chainOfCustody.map((entry) => { const chain = object(entry, "chain event"); return { id: nonEmpty(chain.id, "chain.id"), eventType: nonEmpty(chain.eventType, "chain.eventType"), actor: nonEmpty(chain.actor, "chain.actor"), details: chain.details ?? {}, occurredAt: nonEmpty(chain.occurredAt, "chain.occurredAt") }; }) } : {}),
  };
}
export function parseEvidencePage(payload: unknown): OperationsPage<EvidenceRecord> { return page(payload, parseEvidence); }

export function parseFinding(value: unknown): FindingRecord {
  const item = object(value, "finding");
  const run = item.run === undefined || item.run === null ? null : object(item.run, "finding.run");
  return {
    id: nonEmpty(item.id, "finding.id"), mission: mission(item.mission), runId: nullableString(item.runId, "runId"), title: nonEmpty(item.title, "title"), severity: nonEmpty(item.severity, "severity"),
    ...(item.run !== undefined ? { run: run ? { id: nonEmpty(run.id, "finding.run.id") } : null } : {}),
    confidence: nullableNumber(item.confidence, "confidence"), affectedScope: string(item.affectedScope, "affectedScope"), description: string(item.description, "description"), impact: string(item.impact, "impact"),
    reproductionNotes: nullableString(item.reproductionNotes, "reproductionNotes"), remediation: nullableString(item.remediation, "remediation"), reviewStatus: nonEmpty(item.reviewStatus, "reviewStatus"), operatorOverride: boolean(item.operatorOverride, "operatorOverride"),
    version: number(item.version, "version"), evidenceCount: number(item.evidenceCount, "evidenceCount"), verifiedEvidenceCount: number(item.verifiedEvidenceCount, "verifiedEvidenceCount"), createdAt: nonEmpty(item.createdAt, "createdAt"), updatedAt: nonEmpty(item.updatedAt, "updatedAt"),
    ...(Array.isArray(item.evidence) ? { evidence: item.evidence.map((entry) => { const link = object(entry, "finding evidence"); return { id: nonEmpty(link.id, "evidence.id"), relationship: nonEmpty(link.relationship, "relationship"), summary: string(link.summary, "summary"), evidenceType: nonEmpty(link.evidenceType, "evidenceType"), verificationState: nonEmpty(link.verificationState, "verificationState"), contentHash: nonEmpty(link.contentHash, "contentHash"), addedAt: nonEmpty(link.addedAt, "addedAt") }; }) } : {}),
  };
}
export function parseFindingPage(payload: unknown): OperationsPage<FindingRecord> { return page(payload, parseFinding); }

export function parseArtifact(value: unknown): ArtifactRecord {
  const item = object(value, "artifact"); const storage = object(item.storage, "artifact.storage");
  const run = item.run === undefined || item.run === null ? null : object(item.run, "artifact.run");
  const evaluation = item.evaluation === null ? null : object(item.evaluation, "artifact.evaluation");
  const contextPackIds = array(item.contextPackIds ?? [], "artifact.contextPackIds").map((entry, index) => nonEmpty(entry, `artifact.contextPackIds[${index}]`));
  const journey = item.journey === "autonomous" || item.journey === "guided"
    ? item.journey
    : (() => { throw new Error("artifact journey is invalid"); })();
  const delivery = item.delivery === undefined ? undefined : object(item.delivery, "artifact.delivery");
  const deliveryState = delivery?.state;
  if (delivery && !new Set(["ready", "metadata_only", "reconciliation_required", "quarantined"]).has(deliveryState as string)) {
    throw new Error("artifact delivery state is invalid");
  }
  return {
    id: nonEmpty(item.id, "artifact.id"), mission: mission(item.mission), runId: nullableString(item.runId, "runId"), stepId: nullableString(item.stepId, "stepId"), actionId: nullableString(item.actionId, "actionId"),
    ...(item.run !== undefined ? { run: run ? { id: nonEmpty(run.id, "artifact.run.id") } : null } : {}),
    journey,
    artifactType: nonEmpty(item.artifactType, "artifactType"), contentHash: nonEmpty(item.contentHash, "contentHash"), byteSize: number(item.byteSize, "byteSize"), mediaType: nonEmpty(item.mediaType, "mediaType"), sensitivity: nonEmpty(item.sensitivity, "sensitivity"),
    metadata: item.metadata ?? {}, storage: { scheme: nonEmpty(storage.scheme, "storage.scheme"), available: boolean(storage.available, "storage.available") },
    evaluation: evaluation ? { id: nonEmpty(evaluation.id, "evaluation.id"), evidenceCoverage: nullableNumber(evaluation.evidenceCoverage, "evidenceCoverage") } : null, contextPackIds, createdAt: nonEmpty(item.createdAt, "createdAt"),
    ...(Array.isArray(item.evidence) ? { evidence: item.evidence.map((entry, index) => { const evidence = object(entry, `artifact.evidence[${index}]`); return { id: nonEmpty(evidence.id, "artifact evidence.id"), summary: string(evidence.summary, "artifact evidence.summary"), evidenceType: nonEmpty(evidence.evidenceType, "artifact evidence.evidenceType"), verificationState: nonEmpty(evidence.verificationState, "artifact evidence.verificationState"), contentHash: nonEmpty(evidence.contentHash, "artifact evidence.contentHash"), acquiredAt: nonEmpty(evidence.acquiredAt, "artifact evidence.acquiredAt") }; }) } : {}),
    ...(delivery ? { delivery: {
      state: deliveryState as "ready" | "metadata_only" | "reconciliation_required" | "quarantined",
      downloadable: boolean(delivery.downloadable, "artifact.delivery.downloadable"),
      code: nonEmpty(delivery.code, "artifact.delivery.code"),
      reason: nonEmpty(delivery.reason, "artifact.delivery.reason"),
      remediation: nullableString(delivery.remediation, "artifact.delivery.remediation"),
      verifiedEvidenceCount: number(delivery.verifiedEvidenceCount, "artifact.delivery.verifiedEvidenceCount"),
    } } : {}),
  };
}
export function parseArtifactPage(payload: unknown): OperationsPage<ArtifactRecord> { return page(payload, parseArtifact); }

export function parseReportGeneration(payload: unknown): ReportGenerationRecord {
  const root = object(payload, "report generation");
  schema(root);
  if (root.reportSchemaVersion !== "2.4-report.1") throw new Error("unsupported report schema version");
  if (root.idempotent !== true) throw new Error("report generation is not idempotent");
  return {
    schemaVersion: "2.4",
    reportSchemaVersion: "2.4-report.1",
    missionId: nonEmpty(root.missionId, "report.missionId"),
    runId: nonEmpty(root.runId, "report.runId"),
    reportVersion: number(root.reportVersion, "report.reportVersion"),
    sourceSnapshotHash: nonEmpty(root.sourceSnapshotHash, "report.sourceSnapshotHash"),
    snapshotThrough: nonEmpty(root.snapshotThrough, "report.snapshotThrough"),
    idempotent: true,
    artifacts: array(root.artifacts, "report.artifacts").map((value, index) => {
      const artifact = object(value, `report.artifacts[${index}]`);
      const format = artifact.format === "markdown" || artifact.format === "json"
        ? artifact.format
        : (() => { throw new Error("report artifact format is invalid"); })();
      return {
        id: nonEmpty(artifact.id, "report artifact ID"),
        format,
        mediaType: nonEmpty(artifact.mediaType, "report artifact media type"),
        contentHash: nonEmpty(artifact.contentHash, "report artifact hash"),
        byteSize: number(artifact.byteSize, "report artifact size"),
        downloadUrl: nonEmpty(artifact.downloadUrl, "report artifact download URL"),
      };
    }),
  };
}

export function parseAction(value: unknown): ActionRecord {
  const item = object(value, "action");
  const step = item.step === null ? null : object(item.step, "action.step");
  const correlation = object(item.correlation, "action.correlation");
  const journey = item.journey === "autonomous" || item.journey === "guided"
    ? item.journey
    : (() => { throw new Error("action journey is invalid"); })();
  const statuses = new Set<ActionRecord["status"]>(["queued", "running", "succeeded", "failed", "cancelled", "timed_out", "denied"]);
  const status = nonEmpty(item.status, "action.status") as ActionRecord["status"];
  if (!statuses.has(status)) throw new Error("action status is invalid");
  return {
    id: nonEmpty(item.id, "action.id"), mission: mission(item.mission),
    runId: nonEmpty(item.runId, "action.runId"), journey,
    step: step ? { id: nonEmpty(step.id, "action.step.id"), phase: string(step.phase, "action.step.phase"), title: string(step.title, "action.step.title") } : null,
    agentId: nullableString(item.agentId, "action.agentId"),
    actionType: nonEmpty(item.actionType, "action.actionType"), actionClass: nonEmpty(item.actionClass, "action.actionClass"),
    target: nullableString(item.target, "action.target"), status,
    intentSummary: string(item.intentSummary, "action.intentSummary"), resultSummary: nullableString(item.resultSummary, "action.resultSummary"),
    errorCategory: nullableString(item.errorCategory, "action.errorCategory"), retryCount: number(item.retryCount, "action.retryCount"),
    guidedDecisionId: nullableString(item.guidedDecisionId, "action.guidedDecisionId"), contractId: nullableString(item.contractId, "action.contractId"),
    contextPackId: nullableString(item.contextPackId, "action.contextPackId"),
    correlation: { traceId: nullableString(correlation.traceId, "action.traceId"), spanId: nullableString(correlation.spanId, "action.spanId") },
    startedAt: nullableString(item.startedAt, "action.startedAt"), endedAt: nullableString(item.endedAt, "action.endedAt"),
    createdAt: nonEmpty(item.createdAt, "action.createdAt"), updatedAt: nonEmpty(item.updatedAt, "action.updatedAt"),
  };
}
export function parseActionPage(payload: unknown): OperationsPage<ActionRecord> { return page(payload, parseAction); }

export function parseEventPage(payload: unknown): OperationsPage<EventRecord> {
  return page(payload, (value) => { const item = object(value, "event"); const actor = object(item.actor, "event.actor"); const correlation = object(item.correlation, "event.correlation");
    const journey = item.journey === null ? null : item.journey === "autonomous" || item.journey === "guided" ? item.journey : (() => { throw new Error("event journey is invalid"); })();
    return { id: nonEmpty(item.id, "event.id"), occurredAt: nonEmpty(item.occurredAt, "occurredAt"), eventType: nonEmpty(item.eventType, "eventType"), mission: item.mission === null ? null : mission(item.mission), runId: nullableString(item.runId, "runId"), sequence: nullableNumber(item.sequence, "sequence"), actor: { type: nonEmpty(actor.type, "actor.type"), id: nullableString(actor.id, "actor.id") }, summary: string(item.summary, "summary"), payload: item.payload ?? {}, eventSchemaVersion: number(item.schemaVersion, "event.schemaVersion"), journey, correlation: { traceId: nullableString(correlation.traceId, "traceId"), spanId: nullableString(correlation.spanId, "spanId"), contextPackId: nullableString(correlation.contextPackId, "contextPackId") }, sensitivity: nonEmpty(item.sensitivity, "sensitivity"), redaction: item.redaction ?? {} };
  });
}

export function parseLogPage(payload: unknown): OperationsPage<LogRecord> {
  return page(payload, (value) => { const item = object(value, "log"); const correlation = object(item.correlation, "log.correlation"); return { id: nonEmpty(item.id, "log.id"), occurredAt: nonEmpty(item.occurredAt, "occurredAt"), severity: nonEmpty(item.severity, "severity"), domain: nonEmpty(item.domain, "domain"), message: string(item.message, "message"), attributes: item.attributes ?? {}, mission: item.mission === null ? null : mission(item.mission), runId: nullableString(item.runId, "runId"), stepId: nullableString(item.stepId, "stepId"), actionId: nullableString(item.actionId, "actionId"), correlation: { traceId: nullableString(correlation.traceId, "traceId"), spanId: nullableString(correlation.spanId, "spanId") }, sensitivity: nonEmpty(item.sensitivity, "sensitivity") }; });
}

function parseTraceSummary(value: unknown): TraceSummaryRecord {
  const item = object(value, "trace summary");
  const counts = object(item.counts, "trace summary.counts");
  const status = item.status === "active" || item.status === "completed" || item.status === "failed"
    ? item.status
    : (() => { throw new Error("trace status is invalid"); })();
  const journey = item.journey === null
    ? null
    : item.journey === "autonomous" || item.journey === "guided"
      ? item.journey
      : (() => { throw new Error("trace journey is invalid"); })();
  return {
    id: nonEmpty(item.id, "trace.id"), traceId: nonEmpty(item.traceId, "trace.traceId"), status,
    summary: string(item.summary, "trace.summary"),
    mission: item.mission === null ? null : mission(item.mission, "trace.mission"),
    missionCount: number(item.missionCount, "trace.missionCount"),
    runId: nullableString(item.runId, "trace.runId"), runCount: number(item.runCount, "trace.runCount"),
    journey, startedAt: nonEmpty(item.startedAt, "trace.startedAt"), endedAt: nonEmpty(item.endedAt, "trace.endedAt"),
    durationMs: number(item.durationMs, "trace.durationMs"),
    counts: {
      events: number(counts.events, "trace.counts.events"), logs: number(counts.logs, "trace.counts.logs"),
      actions: number(counts.actions, "trace.counts.actions"), toolCalls: number(counts.toolCalls, "trace.counts.toolCalls"),
      errors: number(counts.errors, "trace.counts.errors"),
    },
  };
}

function parseTraceRecord(value: unknown): TraceRecord {
  const item = object(value, "trace record");
  const correlation = object(item.correlation, "trace record.correlation");
  const kinds = new Set<TraceRecord["kind"]>(["event", "log", "action", "tool_call"]);
  const kind = nonEmpty(item.kind, "trace record.kind") as TraceRecord["kind"];
  if (!kinds.has(kind)) throw new Error("trace record kind is invalid");
  return {
    id: nonEmpty(item.id, "trace record.id"), sourceId: nonEmpty(item.sourceId, "trace record.sourceId"), kind,
    title: string(item.title, "trace record.title"), summary: string(item.summary, "trace record.summary"),
    status: nonEmpty(item.status, "trace record.status"),
    mission: item.mission === null ? null : mission(item.mission, "trace record.mission"),
    runId: nullableString(item.runId, "trace record.runId"), stepId: nullableString(item.stepId, "trace record.stepId"),
    actionId: nullableString(item.actionId, "trace record.actionId"), agentId: nullableString(item.agentId, "trace record.agentId"),
    startedAt: nonEmpty(item.startedAt, "trace record.startedAt"), endedAt: nonEmpty(item.endedAt, "trace record.endedAt"),
    durationMs: number(item.durationMs, "trace record.durationMs"),
    correlation: {
      traceId: nonEmpty(correlation.traceId, "trace record.traceId"),
      spanId: nullableString(correlation.spanId, "trace record.spanId"),
      parentSpanId: nullableString(correlation.parentSpanId, "trace record.parentSpanId"),
    },
    raw: item.raw ?? {},
  };
}

export function parseTracePage(payload: unknown): OperationsPage<TraceSummaryRecord> {
  return page(payload, parseTraceSummary);
}

export function parseTraceDetail(payload: unknown): TraceDetailRecord {
  const root = object(payload, "trace detail");
  schema(root);
  return {
    schemaVersion: "2.4",
    trace: parseTraceSummary(root.trace),
    records: page(root.records, parseTraceRecord),
  };
}

export function parseHealthPage(payload: unknown): OperationsPage<HealthStatus> { return page(payload, health); }

function evaluationComparison(value: unknown): EvaluationComparison {
  const item = object(value, "evaluation comparison");
  const status = item.status === "available" || item.status === "insufficient_data"
    ? item.status
    : (() => { throw new Error("evaluation comparison status is invalid"); })();
  const basis = item.basis === null
    ? null
    : item.basis === "same_mission_and_journey" || item.basis === "same_engagement_and_journey"
      ? item.basis
      : (() => { throw new Error("evaluation comparison basis is invalid"); })();
  const priorValue = item.prior === null ? null : object(item.prior, "evaluation comparison prior");
  const priorStatus = priorValue?.terminalStatus;
  if (priorValue && priorStatus !== "completed" && priorStatus !== "failed" && priorStatus !== "cancelled") {
    throw new Error("evaluation comparison prior terminal status is invalid");
  }
  const metrics = array(item.metrics, "evaluation comparison metrics").map((value, index): EvaluationComparisonMetric => {
    const metric = object(value, `evaluation comparison metrics[${index}]`);
    const unit = metric.unit === "ratio" || metric.unit === "milliseconds" || metric.unit === "count" || metric.unit === "cost"
      ? metric.unit
      : (() => { throw new Error("evaluation comparison metric unit is invalid"); })();
    const favorableDirection = metric.favorableDirection === "higher" || metric.favorableDirection === "lower"
      ? metric.favorableDirection
      : (() => { throw new Error("evaluation comparison metric direction is invalid"); })();
    const movement = metric.movement === "favorable" || metric.movement === "unfavorable" || metric.movement === "unchanged"
      ? metric.movement
      : (() => { throw new Error("evaluation comparison metric movement is invalid"); })();
    return {
      key: nonEmpty(metric.key, "comparison metric key"),
      label: nonEmpty(metric.label, "comparison metric label"),
      unit,
      favorableDirection,
      current: number(metric.current, "comparison metric current"),
      prior: number(metric.prior, "comparison metric prior"),
      delta: number(metric.delta, "comparison metric delta"),
      relativeDelta: nullableNumber(metric.relativeDelta, "comparison metric relativeDelta"),
      movement,
    };
  });
  if (status === "available" && (!basis || !priorValue || metrics.length === 0)) {
    throw new Error("available evaluation comparison is incomplete");
  }
  return {
    status,
    basis,
    reason: nonEmpty(item.reason, "evaluation comparison reason"),
    prior: priorValue ? {
      evaluationId: nonEmpty(priorValue.evaluationId, "prior evaluation ID"),
      runId: nonEmpty(priorValue.runId, "prior run ID"),
      terminalStatus: priorStatus as "completed" | "failed" | "cancelled",
      evaluatedAt: nonEmpty(priorValue.evaluatedAt, "prior evaluatedAt"),
    } : null,
    terminalStatusMatch: item.terminalStatusMatch === null
      ? null
      : boolean(item.terminalStatusMatch, "terminalStatusMatch"),
    metrics,
    summary: string(item.summary, "evaluation comparison summary"),
    createdAt: nonEmpty(item.createdAt, "evaluation comparison createdAt"),
  };
}

function evaluationBudget(value: unknown): EvaluationBudget {
  const item = object(value, "evaluation budget");
  const keys = new Set<EvaluationBudgetMetric["key"]>(["wallClockMs", "providerTokens", "estimatedCost", "toolCalls", "retries", "replans"]);
  const units = new Set<EvaluationBudgetMetric["unit"]>(["milliseconds", "count", "cost"]);
  const limitStatuses = new Set<EvaluationBudgetMetric["limitStatus"]>(["configured", "not_configured"]);
  const usageStatuses = new Set<EvaluationBudgetMetric["usageStatus"]>(["recorded_exact", "recorded_estimate", "unknown"]);
  const statuses = new Set<EvaluationBudgetMetric["status"]>(["within_limit", "limit_reached", "limit_exceeded", "not_configured", "unknown_usage"]);
  const limitSources = new Set<NonNullable<EvaluationBudgetMetric["limitSource"]>>(["terminal_run_budget"]);
  const usageSources = new Set<NonNullable<EvaluationBudgetMetric["usageSource"]>>(["terminal_run", "run_evaluation", "canonical_records"]);
  return {
    metrics: array(item.metrics, "evaluation budget metrics").map((value) => {
      const metric = object(value, "evaluation budget metric");
      const key = nonEmpty(metric.key, "budget metric key") as EvaluationBudgetMetric["key"];
      const unit = nonEmpty(metric.unit, "budget metric unit") as EvaluationBudgetMetric["unit"];
      const limitStatus = nonEmpty(metric.limitStatus, "budget limit status") as EvaluationBudgetMetric["limitStatus"];
      const usageStatus = nonEmpty(metric.usageStatus, "budget usage status") as EvaluationBudgetMetric["usageStatus"];
      const status = nonEmpty(metric.status, "budget status") as EvaluationBudgetMetric["status"];
      const limitSource = nullableString(metric.limitSource, "budget limit source") as EvaluationBudgetMetric["limitSource"];
      const usageSource = nullableString(metric.usageSource, "budget usage source") as EvaluationBudgetMetric["usageSource"];
      if (!keys.has(key) || !units.has(unit) || !limitStatuses.has(limitStatus) || !usageStatuses.has(usageStatus) || !statuses.has(status)) {
        throw new Error("evaluation budget metric is invalid");
      }
      if (limitSource !== null && !limitSources.has(limitSource)) throw new Error("evaluation budget limit source is invalid");
      if (usageSource !== null && !usageSources.has(usageSource)) throw new Error("evaluation budget usage source is invalid");
      return {
        key,
        label: nonEmpty(metric.label, "budget metric label"),
        unit,
        limit: nullableNumber(metric.limit, "budget metric limit"),
        usage: nullableNumber(metric.usage, "budget metric usage"),
        limitStatus,
        usageStatus,
        status,
        limitSource,
        usageSource,
      };
    }),
  };
}

export function parseEvaluationPage(payload: unknown): OperationsPage<EvaluationRecord> {
  return page(payload, (value) => { const item = object(value, "evaluation"); const run = object(item.run, "evaluation.run"); const journey = item.journey === "autonomous" || item.journey === "guided" ? item.journey : (() => { throw new Error("evaluation journey invalid"); })(); return { id: nonEmpty(item.id, "evaluation.id"), mission: mission(item.mission), run: { id: nonEmpty(run.id, "run.id"), status: nonEmpty(run.status, "run.status") }, journey, scores: item.scores ?? {}, metrics: item.metrics ?? {}, retrospective: string(item.retrospective, "retrospective"), evidenceCoverage: nullableNumber(item.evidenceCoverage, "evidenceCoverage"), createdBy: nonEmpty(item.createdBy, "createdBy"), createdAt: nonEmpty(item.createdAt, "createdAt"), budget: evaluationBudget(item.budget), comparison: evaluationComparison(item.comparison) }; });
}

export function parseLesson(value: unknown): LessonRecord {
  const item = object(value, "lesson"); return { id: nonEmpty(item.id, "lesson.id"), statement: string(item.statement, "statement"), lessonType: nonEmpty(item.lessonType, "lessonType"), applicabilityScope: nonEmpty(item.applicabilityScope, "applicabilityScope"), engagementId: nullableString(item.engagementId, "engagementId"), mission: item.mission === null ? null : mission(item.mission), failureCategory: nullableString(item.failureCategory, "failureCategory"), retryConditions: nullableString(item.retryConditions, "retryConditions"), confidence: nullableNumber(item.confidence, "confidence"), expectedBenefit: string(item.expectedBenefit, "expectedBenefit"), risk: string(item.risk, "risk"), status: nonEmpty(item.status, "status"), authoringAgentId: nullableString(item.authoringAgentId, "authoringAgentId"), reviewedBy: nullableString(item.reviewedBy, "reviewedBy"), reviewedAt: nullableString(item.reviewedAt, "reviewedAt"), expiresAt: nullableString(item.expiresAt, "expiresAt"), supersedesLessonId: nullableString(item.supersedesLessonId, "supersedesLessonId"), evidenceCount: number(item.evidenceCount, "evidenceCount"), supportingEvidenceCount: number(item.supportingEvidenceCount, "supportingEvidenceCount"), usageCount: number(item.usageCount, "usageCount"), createdAt: nonEmpty(item.createdAt, "createdAt"), updatedAt: nonEmpty(item.updatedAt, "updatedAt"), ...(Array.isArray(item.evidence) ? { evidence: item.evidence.map((entry) => { const link = object(entry, "lesson evidence"); return { evidenceId: nullableString(link.evidenceId, "evidenceId"), runId: nullableString(link.runId, "runId"), relationship: nonEmpty(link.relationship, "relationship"), rationale: string(link.rationale, "rationale"), evidenceSummary: nullableString(link.evidenceSummary, "evidenceSummary"), createdAt: nonEmpty(link.createdAt, "createdAt") }; }) } : {}) };
}
export function parseLessonPage(payload: unknown): OperationsPage<LessonRecord> { return page(payload, parseLesson); }

export function parseLessonUsagePage(payload: unknown): OperationsPage<LessonUsageRecord> {
  return page(payload, (value) => { const item = object(value, "lesson usage"); const lesson = object(item.lesson, "usage.lesson"); return { id: nonEmpty(item.id, "usage.id"), lesson: { id: nonEmpty(lesson.id, "lesson.id"), statement: string(lesson.statement, "lesson.statement") }, mission: mission(item.mission), runId: nonEmpty(item.runId, "runId"), stepId: nullableString(item.stepId, "stepId"), actionId: nullableString(item.actionId, "actionId"), contextPackId: nullableString(item.contextPackId, "contextPackId"), influenceSummary: string(item.influenceSummary, "influenceSummary"), outcome: nullableString(item.outcome, "outcome"), measuredImpact: item.measuredImpact ?? {}, usedAt: nonEmpty(item.usedAt, "usedAt") }; });
}

export function parseProviderPage(payload: unknown): OperationsPage<ProviderRecord> {
  return page(payload, (value) => { const item = object(value, "provider"); return { id: nonEmpty(item.id, "provider.id"), provider: nonEmpty(item.provider, "provider"), model: nullableString(item.model, "model"), status: nonEmpty(item.status, "status"), turnCount: number(item.turnCount, "turnCount"), completedCount: number(item.completedCount, "completedCount"), failedCount: number(item.failedCount, "failedCount"), meanLatencyMs: nullableNumber(item.meanLatencyMs, "meanLatencyMs"), inputTokens: number(item.inputTokens, "inputTokens"), outputTokens: number(item.outputTokens, "outputTokens"), estimatedCost: nullableNumber(item.estimatedCost, "estimatedCost"), lastTurnAt: nullableString(item.lastTurnAt, "lastTurnAt") }; });
}
export function parseMcpPage(payload: unknown): OperationsPage<McpRecord> {
  return page(payload, (value) => { const item = object(value, "MCP server"); return { id: nonEmpty(item.id, "mcp.id"), name: nonEmpty(item.name, "name"), transport: nonEmpty(item.transport, "transport"), endpointRedacted: nullableString(item.endpointRedacted, "endpointRedacted"), status: nonEmpty(item.status, "status"), capabilities: item.capabilities ?? [], policy: item.policy ?? {}, lastCheckedAt: nullableString(item.lastCheckedAt, "lastCheckedAt"), updatedAt: nonEmpty(item.updatedAt, "updatedAt") }; });
}
export function parsePolicyPage(payload: unknown): OperationsPage<PolicyRecord> {
  return page(payload, (value) => { const item = object(value, "policy"); return { id: nonEmpty(item.id, "policy.id"), sourceType: nonEmpty(item.sourceType, "sourceType"), label: nonEmpty(item.label, "label"), policy: item.policy ?? {}, sensitivity: nonEmpty(item.sensitivity, "sensitivity"), updatedAt: nonEmpty(item.updatedAt, "updatedAt") }; });
}

export function parseFindingReview(payload: unknown): Record<string, unknown> {
  const root = object(payload, "finding review"); schema(root); const finding = object(root.finding, "finding review result");
  nonEmpty(finding.id, "finding.id"); nonEmpty(finding.reviewStatus, "finding.reviewStatus"); number(finding.version, "finding.version"); number(finding.evidenceCount, "finding.evidenceCount");
  return root;
}

export function parseLessonReview(payload: unknown): Record<string, unknown> {
  const root = object(payload, "lesson review"); schema(root); const lesson = object(root.lesson, "lesson review result");
  nonEmpty(lesson.id, "lesson.id"); nonEmpty(lesson.status, "lesson.status"); number(lesson.supportingEvidenceCount, "lesson.supportingEvidenceCount"); nonEmpty(lesson.updatedAt, "lesson.updatedAt");
  return root;
}
