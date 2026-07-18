import { OperationalTruthRepository, type RepositoryOptions } from "./OperationalTruthRepository";
import type { SqliteDatabase } from "../db";
import {
  parseMissionMemoryPolicy,
  retrieveMissionBrainContext,
  type BrainContextService,
} from "../brain-runtime";
import { insufficient, invalid, scopeConflict, stateConflict } from "./errors";
import {
  CORE_EVIDENCE_REQUIREMENTS,
  type AppendEngagementLogInput,
  type CandidateDecisionInput,
  type CreateObservationInput,
  type EngagementLogRecord,
  type EvidenceCandidate,
  type EvidenceCustodyEventInput,
  type EvidenceProvenance,
  type FindingVerificationReadiness,
  type JsonValue,
  type Observation,
  type OperationalActor,
  type ProposeEvidenceCandidateInput,
  type VerifiedEvidence,
  type VerifyEvidenceCandidateInput,
  type VerifyFindingInput,
} from "./types";
import {
  canonicalJson,
  confidence,
  identifier,
  isoTimestamp,
  optionalIdentifier,
  redactedText,
  sanitizedJson,
  sha256,
  sha256Hash,
  text,
  uniqueStrings,
} from "./validation";

const SEVERITIES = new Set(["debug", "info", "notice", "warning", "error", "critical"]);
const SENSITIVITIES = new Set(["public", "internal", "private", "restricted"]);

function actor(input: OperationalActor): OperationalActor {
  return { id: identifier(input.id, "actor.id"), type: input.type };
}

function assertEnum(value: string, allowed: ReadonlySet<string>, label: string): void {
  if (!allowed.has(value)) throw invalid("invalid_enum", `${label} is not supported`);
}

function assertNotFuture(value: string, now: string, label: string): void {
  if (Date.parse(value) > Date.parse(now) + 60_000) {
    throw invalid("future_timestamp", `${label} cannot be in the future`);
  }
}

function optionalScope(input: {
  readonly runId?: string;
  readonly planId?: string;
  readonly stepId?: string;
  readonly actionId?: string;
  readonly attackAttemptId?: string;
  readonly assetId?: string;
  readonly agentId?: string;
  readonly providerTurnId?: string;
  readonly toolCallId?: string;
}): {
  readonly runId?: string;
  readonly planId?: string;
  readonly stepId?: string;
  readonly actionId?: string;
  readonly attackAttemptId?: string;
  readonly assetId?: string;
  readonly agentId?: string;
  readonly providerTurnId?: string;
  readonly toolCallId?: string;
} {
  return {
    ...(optionalIdentifier(input.runId, "runId") ? { runId: optionalIdentifier(input.runId, "runId") } : {}),
    ...(optionalIdentifier(input.planId, "planId") ? { planId: optionalIdentifier(input.planId, "planId") } : {}),
    ...(optionalIdentifier(input.stepId, "stepId") ? { stepId: optionalIdentifier(input.stepId, "stepId") } : {}),
    ...(optionalIdentifier(input.actionId, "actionId") ? { actionId: optionalIdentifier(input.actionId, "actionId") } : {}),
    ...(optionalIdentifier(input.attackAttemptId, "attackAttemptId") ? { attackAttemptId: optionalIdentifier(input.attackAttemptId, "attackAttemptId") } : {}),
    ...(optionalIdentifier(input.assetId, "assetId") ? { assetId: optionalIdentifier(input.assetId, "assetId") } : {}),
    ...(optionalIdentifier(input.agentId, "agentId") ? { agentId: optionalIdentifier(input.agentId, "agentId") } : {}),
    ...(optionalIdentifier(input.providerTurnId, "providerTurnId") ? { providerTurnId: optionalIdentifier(input.providerTurnId, "providerTurnId") } : {}),
    ...(optionalIdentifier(input.toolCallId, "toolCallId") ? { toolCallId: optionalIdentifier(input.toolCallId, "toolCallId") } : {}),
  };
}

/**
 * Transactional log → observation → candidate → verified-evidence boundary.
 * Nothing promotes raw output implicitly; every state change is deliberate,
 * attributable, and audited.
 */
export class OperationalTruthService {
  readonly repository: OperationalTruthRepository;
  readonly #brainContext?: BrainContextService;

  constructor(database: SqliteDatabase, options: RepositoryOptions & {
    readonly brainContext?: BrainContextService;
  } = {}) {
    this.repository = new OperationalTruthRepository(database, options);
    this.#brainContext = options.brainContext;
  }

  appendEngagementLog(input: AppendEngagementLogInput): EngagementLogRecord {
    const missionId = identifier(input.missionId, "missionId");
    assertEnum(input.severity, SEVERITIES, "severity");
    assertEnum(input.sensitivity, SENSITIVITIES, "sensitivity");
    const scope = optionalScope(input);
    const occurredAt = isoTimestamp(input.occurredAt, "occurredAt");
    const createdAt = this.repository.now();
    assertNotFuture(occurredAt, createdAt, "occurredAt");
    const technical = sanitizedJson(input.technicalPayload);
    const humanSummary = redactedText(input.humanSummary, "humanSummary", 4_000);
    const domain = text(input.domain, "domain", 200);
    const recordType = text(input.recordType, "recordType", 200);
    const technicalPayload = technical.redacted
      ? { redacted: true, payload: technical.value } satisfies JsonValue
      : technical.value;
    return this.repository.transaction(() => {
      this.repository.assertCanonicalScope({ missionId, ...scope });
      const id = this.repository.nextId("log");
      const contentHash = sha256(canonicalJson({
        missionId,
        ...scope,
        severity: input.severity,
        domain,
        recordType,
        humanSummary,
        technicalPayload,
        sensitivity: input.sensitivity,
        occurredAt,
      }));
      return this.repository.insertLog({
        id,
        mission_id: missionId,
        run_id: scope.runId ?? null,
        plan_id: scope.planId ?? null,
        step_id: scope.stepId ?? null,
        action_id: scope.actionId ?? null,
        attack_attempt_id: scope.attackAttemptId ?? null,
        asset_id: scope.assetId ?? null,
        agent_id: scope.agentId ?? null,
        provider_turn_id: scope.providerTurnId ?? null,
        tool_call_id: scope.toolCallId ?? null,
        severity: input.severity,
        domain,
        record_type: recordType,
        human_summary: humanSummary,
        technical_payload_json: canonicalJson(technicalPayload),
        content_hash: contentHash,
        sensitivity: input.sensitivity,
        trace_id: optionalIdentifier(input.traceId, "traceId") ?? null,
        span_id: optionalIdentifier(input.spanId, "spanId") ?? null,
        occurred_at: occurredAt,
        created_at: createdAt,
      });
    });
  }

  createObservation(input: CreateObservationInput): Observation {
    const missionId = identifier(input.missionId, "missionId");
    const runId = optionalIdentifier(input.runId, "runId");
    const stepId = optionalIdentifier(input.stepId, "stepId");
    const assetId = optionalIdentifier(input.assetId, "assetId");
    const sourceAgentId = optionalIdentifier(input.sourceAgentId, "sourceAgentId");
    assertEnum(input.sensitivity, SENSITIVITIES, "sensitivity");
    if (input.sources.length === 0 || input.sources.length > 50) {
      throw invalid("observation_sources_required", "An observation requires 1-50 attributable log records");
    }
    const sourceIds = input.sources.map((source) => identifier(source.logRecordId, "logRecordId"));
    if (new Set(sourceIds).size !== sourceIds.length) {
      throw invalid("duplicate_observation_source", "Observation log sources must be unique");
    }
    const firstSeenAt = isoTimestamp(input.firstSeenAt, "firstSeenAt");
    const lastSeenAt = isoTimestamp(input.lastSeenAt, "lastSeenAt");
    const now = this.repository.now();
    if (Date.parse(firstSeenAt) > Date.parse(lastSeenAt)) {
      throw invalid("invalid_observation_window", "firstSeenAt cannot be after lastSeenAt");
    }
    assertNotFuture(lastSeenAt, now, "lastSeenAt");
    const normalized = sanitizedJson(input.normalizedValue).value;
    const sources = input.sources.map((source) => ({
      logRecordId: identifier(source.logRecordId, "logRecordId"),
      parserId: identifier(source.parserId, "parserId"),
      parserVersion: text(source.parserVersion, "parserVersion", 100),
    }));
    return this.repository.transaction(() => {
      this.repository.assertCanonicalScope({ missionId, ...(runId ? { runId } : {}), ...(stepId ? { stepId } : {}), ...(sourceAgentId ? { agentId: sourceAgentId } : {}) });
      for (const source of sources) {
        const log = this.repository.getLog(source.logRecordId);
        if (
          log.missionId !== missionId || log.runId !== runId ||
          (stepId !== undefined && log.stepId !== stepId)
        ) throw scopeConflict("Observation source log does not belong to the exact mission, run, and step");
      }
      const id = this.repository.nextId("obs");
      const observation = this.repository.insertObservation({
        id,
        mission_id: missionId,
        run_id: runId ?? null,
        step_id: stepId ?? null,
        asset_id: assetId ?? null,
        observation_type: text(input.observationType, "observationType", 200),
        statement: text(input.statement, "statement", 4_000),
        normalized_value_json: canonicalJson(normalized),
        confidence: confidence(input.confidence),
        verification_state: input.verificationState ?? "unverified",
        source_agent_id: sourceAgentId ?? null,
        source_tool: input.sourceTool ? text(input.sourceTool, "sourceTool", 200) : null,
        first_seen_at: firstSeenAt,
        last_seen_at: lastSeenAt,
        sensitivity: input.sensitivity,
        created_at: now,
      }, sources);
      this.repository.audit.append({
        missionId,
        ...(runId ? { runId } : {}),
        actor: sourceAgentId ? { id: sourceAgentId, type: "agent" } : { id: "observation-parser", type: "system" },
        action: "observation.created",
        resourceType: "observation",
        resourceId: id,
        reason: "Parsed attributable operational log records into a structured observation.",
        details: { sourceLogIds: sourceIds, verificationState: observation.verificationState },
        occurredAt: now,
      });
      return observation;
    });
  }

  proposeEvidenceCandidate(input: ProposeEvidenceCandidateInput): EvidenceCandidate {
    const missionId = identifier(input.missionId, "missionId");
    const runId = optionalIdentifier(input.runId, "runId");
    const stepId = optionalIdentifier(input.stepId, "stepId");
    const observationId = optionalIdentifier(input.observationId, "observationId");
    const artifactId = optionalIdentifier(input.artifactId, "artifactId");
    if (!observationId && !artifactId) {
      throw invalid("candidate_source_required", "Evidence candidates require an observation or artifact source");
    }
    assertEnum(input.sensitivity, SENSITIVITIES, "sensitivity");
    const requirements = uniqueStrings([
      ...CORE_EVIDENCE_REQUIREMENTS,
      ...(input.additionalValidationRequirements ?? []),
    ], "validationRequirements");
    const now = this.repository.now();
    return this.repository.transaction(() => {
      this.repository.assertCanonicalScope({ missionId, ...(runId ? { runId } : {}), ...(stepId ? { stepId } : {}) });
      if (observationId) {
        const observation = this.repository.getObservation(observationId);
        if (observation.missionId !== missionId || observation.runId !== runId || observation.stepId !== stepId) {
          throw scopeConflict("Observation does not belong to the candidate mission, run, and step");
        }
        if (["rejected", "stale"].includes(observation.verificationState)) {
          throw stateConflict("Rejected or stale observations cannot become evidence candidates");
        }
      }
      if (artifactId) {
        const artifact = this.repository.artifactScope(artifactId);
        if (artifact.mission_id !== missionId || artifact.run_id !== runId || artifact.step_id !== stepId) {
          throw scopeConflict("Artifact does not belong to the candidate mission, run, and step");
        }
      }
      const id = this.repository.nextId("candidate");
      const candidate = this.repository.insertCandidate({
        id,
        mission_id: missionId,
        run_id: runId ?? null,
        step_id: stepId ?? null,
        observation_id: observationId ?? null,
        artifact_id: artifactId ?? null,
        evidence_type: text(input.evidenceType, "evidenceType", 200),
        label: text(input.label, "label", 500),
        meaning: text(input.meaning, "meaning", 4_000),
        promotion_reason: text(input.promotionReason, "promotionReason", 2_000),
        validation_requirements_json: canonicalJson(requirements),
        state: "candidate",
        sensitivity: input.sensitivity,
        proposed_by: identifier(input.proposedBy, "proposedBy"),
        reviewed_by: null,
        review_reason: null,
        promoted_evidence_id: null,
        created_at: now,
        reviewed_at: null,
      });
      this.repository.audit.append({
        missionId,
        ...(runId ? { runId } : {}),
        actor: { id: candidate.proposedBy, type: "agent" },
        action: "evidence_candidate.proposed",
        resourceType: "evidence_candidate",
        resourceId: id,
        reason: candidate.promotionReason,
        details: { observationId: observationId ?? null, artifactId: artifactId ?? null, requirements },
        occurredAt: now,
      });
      return candidate;
    });
  }

  promoteCandidate(input: CandidateDecisionInput): EvidenceCandidate {
    return this.transitionCandidate(input, ["candidate", "demoted"], "validating", "evidence_candidate.promoted_for_validation");
  }

  rejectCandidate(input: CandidateDecisionInput): EvidenceCandidate {
    return this.transitionCandidate(input, ["candidate", "validating", "demoted"], "rejected", "evidence_candidate.rejected");
  }

  demoteCandidate(input: CandidateDecisionInput): EvidenceCandidate {
    const candidateId = identifier(input.candidateId, "candidateId");
    const reviewer = actor(input.actor);
    const reason = text(input.reason, "reason", 2_000);
    const now = this.repository.now();
    return this.repository.transaction(() => {
      const current = this.repository.getCandidate(candidateId);
      if (!current.promotedEvidenceId) throw stateConflict("Candidate has no promoted evidence to demote");
      if (this.repository.verifiedFindingDependents(current.promotedEvidenceId) > 0) {
        throw stateConflict(
          "Evidence supports a verified finding and cannot be silently demoted",
          "Reopen the dependent finding before demoting its evidence.",
        );
      }
      const updated = this.repository.transitionCandidate(candidateId, ["promoted"], "demoted", reviewer.id, reason, now);
      this.repository.appendCustodyEvent({
        id: this.repository.nextId("custody"),
        evidenceId: current.promotedEvidenceId,
        eventType: "demoted",
        actor: reviewer.id,
        details: { reason },
        occurredAt: now,
      });
      this.repository.audit.append({
        missionId: current.missionId,
        ...(current.runId ? { runId: current.runId } : {}),
        actor: reviewer,
        action: "evidence.demoted",
        resourceType: "evidence",
        resourceId: current.promotedEvidenceId,
        reason,
        details: { candidateId },
        occurredAt: now,
      });
      return updated;
    });
  }

  verifyCandidate(input: VerifyEvidenceCandidateInput): VerifiedEvidence {
    const candidateId = identifier(input.candidateId, "candidateId");
    const reviewer = actor(input.actor);
    const reason = text(input.reason, "reason", 2_000);
    const acquiredAt = isoTimestamp(input.acquiredAt, "acquiredAt");
    const now = this.repository.now();
    assertNotFuture(acquiredAt, now, "acquiredAt");
    const provenance = this.validateProvenance(input.provenance);
    const custody = this.validateCustody(input.custody, acquiredAt, now);
    const satisfied = new Set(uniqueStrings(input.satisfiedAdditionalRequirements ?? [], "satisfiedAdditionalRequirements"));
    return this.repository.transaction(() => {
      const candidate = this.repository.getCandidate(candidateId);
      if (candidate.state !== "validating") {
        throw stateConflict("Only a validating evidence candidate can be verified");
      }
      if (candidate.proposedBy === reviewer.id) {
        throw stateConflict("The candidate proposer cannot verify their own evidence", "Use an independent authorized reviewer.");
      }
      const additional = candidate.validationRequirements.filter(
        (requirement) => !(CORE_EVIDENCE_REQUIREMENTS as readonly string[]).includes(requirement),
      );
      const missingRequirements = additional.filter((requirement) => !satisfied.has(requirement));
      if (missingRequirements.length > 0) {
        throw insufficient(
          `Additional validation requirements are unsatisfied: ${missingRequirements.join(", ")}`,
          "Satisfy and explicitly identify every candidate-specific requirement before verification.",
        );
      }
      const requiredProvenance = new Set<string>();
      let contentHash: string;
      let sourceLogIds: readonly string[] = [];
      if (candidate.observationId) {
        const manifest = this.repository.observationManifest(candidate.observationId);
        contentHash = manifest.hash;
        sourceLogIds = manifest.sourceLogIds;
        requiredProvenance.add(`observation:${candidate.observationId}`);
        for (const logId of sourceLogIds) requiredProvenance.add(`engagement_log:${logId}`);
      } else if (candidate.artifactId) {
        const artifact = this.repository.artifactScope(candidate.artifactId);
        contentHash = sha256Hash(artifact.content_hash, "artifact.contentHash");
      } else {
        throw insufficient("Candidate source is no longer available", "Reconcile the candidate source before verification.");
      }
      if (candidate.artifactId) requiredProvenance.add(`artifact:${candidate.artifactId}`);
      const suppliedProvenance = new Set(provenance.sources.map((source) => `${source.kind}:${source.id}`));
      const missingProvenance = [...requiredProvenance].filter((entry) => !suppliedProvenance.has(entry));
      if (missingProvenance.length > 0) {
        throw insufficient(
          `Attributable provenance is incomplete: ${missingProvenance.join(", ")}`,
          "Include every canonical observation, log, and artifact source used by this evidence.",
        );
      }
      if (input.expectedContentHash && sha256Hash(input.expectedContentHash, "expectedContentHash") !== contentHash) {
        throw stateConflict("Expected content hash does not match the canonical candidate source");
      }
      const evidenceId = this.repository.nextId("evidence");
      const persistedProvenance = sanitizedJson({
        method: provenance.method,
        explanation: provenance.explanation,
        sources: provenance.sources,
        candidateId,
        sourceLogIds,
      }).value;
      const events = [
        ...custody.map((event) => ({
          id: this.repository.nextId("custody"),
          eventType: event.eventType,
          actor: event.actor,
          details: event.details,
          occurredAt: event.occurredAt,
        })),
        {
          id: this.repository.nextId("custody"),
          eventType: "verified",
          actor: reviewer.id,
          details: { candidateId, reason, requirements: candidate.validationRequirements },
          occurredAt: now,
        },
      ];
      const evidence = this.repository.insertVerifiedEvidence({
        row: {
          id: evidenceId,
          mission_id: candidate.missionId,
          run_id: candidate.runId ?? null,
          step_id: candidate.stepId ?? null,
          source: text(input.source, "source", 500),
          acquired_at: acquiredAt,
          target: text(input.target, "target", 1_000),
          evidence_type: candidate.evidenceType,
          content_hash: contentHash,
          provenance_json: canonicalJson(persistedProvenance),
          confidence: confidence(input.confidence),
          sensitivity: candidate.sensitivity,
          verification_state: "verified",
          summary: candidate.meaning,
          artifact_id: candidate.artifactId ?? null,
          created_by: reviewer.id,
          created_at: now,
        },
        custody: events,
      });
      this.repository.transitionCandidate(candidateId, ["validating"], "promoted", reviewer.id, reason, now, evidenceId);
      this.repository.audit.append({
        missionId: candidate.missionId,
        ...(candidate.runId ? { runId: candidate.runId } : {}),
        actor: reviewer,
        action: "evidence.verified",
        resourceType: "evidence",
        resourceId: evidenceId,
        reason,
        details: { candidateId, contentHash, custodyEvents: events.length },
        occurredAt: now,
      });
      return evidence;
    });
  }

  linkEvidenceToFinding(input: {
    readonly findingId: string;
    readonly evidenceId: string;
    readonly relationship: "supports" | "contradicts" | "context";
    readonly actor: OperationalActor;
    readonly reason: string;
  }): void {
    const reviewer = actor(input.actor);
    const reason = text(input.reason, "reason", 2_000);
    const findingId = identifier(input.findingId, "findingId");
    const evidenceId = identifier(input.evidenceId, "evidenceId");
    const now = this.repository.now();
    this.repository.transaction(() => {
      this.repository.linkFindingEvidence({ findingId, evidenceId, relationship: input.relationship, addedAt: now });
      const finding = this.repository.findingRow(findingId);
      this.repository.audit.append({
        missionId: finding.mission_id,
        ...(finding.run_id ? { runId: finding.run_id } : {}),
        actor: reviewer,
        action: "finding.evidence_linked",
        resourceType: "finding",
        resourceId: findingId,
        reason,
        details: { evidenceId, relationship: input.relationship },
        occurredAt: now,
      });
    });
  }

  findingVerificationReadiness(findingId: string): FindingVerificationReadiness {
    return this.repository.findingReadiness(identifier(findingId, "findingId"));
  }

  verifyFinding(input: VerifyFindingInput): FindingVerificationReadiness {
    const findingId = identifier(input.findingId, "findingId");
    const reviewer = actor(input.actor);
    const reason = text(input.reason, "reason", 2_000);
    if (!Number.isSafeInteger(input.expectedVersion) || input.expectedVersion < 1) {
      throw invalid("invalid_finding_version", "expectedVersion must be a positive integer");
    }
    const now = this.repository.now();
    if (this.#brainContext) {
      const preflightReadiness = this.repository.findingReadiness(findingId);
      if (!preflightReadiness.sufficient) {
        throw insufficient(
          preflightReadiness.reasons.join(" ") || "Finding evidence is insufficient.",
          "Attach promoted, verified, custody-complete supporting evidence and resolve contradictions.",
        );
      }
      const findingScope = this.repository.findingRow(findingId);
      if (!findingScope.run_id) {
        throw insufficient(
          "Finding validation has no canonical run for scoped Second Brain retrieval.",
          "Link the finding to its originating run before verification.",
        );
      }
      const scope = this.repository.database.prepare(`
        SELECT r.journey, m.memory_policy_json
        FROM runs r JOIN missions m ON m.id = r.mission_id
        WHERE r.id = ? AND r.mission_id = ?
      `).get(findingScope.run_id, findingScope.mission_id) as {
        readonly journey: "autonomous" | "guided";
        readonly memory_policy_json: string;
      } | undefined;
      if (!scope) throw scopeConflict("Finding mission/run scope is unavailable");
      const evidenceSteps = preflightReadiness.supportingEvidenceIds.map((evidenceId) =>
        this.repository.database.prepare("SELECT step_id FROM evidence WHERE id = ?")
          .get(evidenceId) as { readonly step_id: string | null } | undefined);
      if (evidenceSteps.some((row) => !row?.step_id)) {
        throw insufficient(
          "Finding evidence lacks a canonical plan step for scoped Second Brain validation.",
          "Link every supporting evidence item to its originating plan step before verification.",
        );
      }
      const stepIds = [...new Set(evidenceSteps.map((row) => row!.step_id!))];
      for (const stepId of stepIds) {
        const context = retrieveMissionBrainContext({
          brainContext: this.#brainContext,
          hook: "finding_validation",
          journey: scope.journey,
          missionId: findingScope.mission_id,
          runId: findingScope.run_id,
          stepId,
          actorId: reviewer.id,
          actorType: reviewer.type,
          query: "Validate the finding against scoped verified evidence, provenance, comparable findings, and applicable lessons.",
          queryRedacted: "Validate the finding against scoped verified evidence, provenance, comparable findings, and applicable lessons.",
          memoryPolicy: parseMissionMemoryPolicy(scope.memory_policy_json),
        });
        this.#brainContext.recordUnusedContext(
          context,
          "The immutable evidence-readiness policy remained authoritative; retrieved memory did not independently verify, weaken, or alter the finding.",
        );
      }
    }
    return this.repository.transaction(() => {
      const readiness = this.repository.findingReadiness(findingId);
      if (!readiness.sufficient) {
        throw insufficient(
          readiness.reasons.join(" ") || "Finding evidence is insufficient.",
          "Attach promoted, verified, custody-complete supporting evidence and resolve contradictions.",
        );
      }
      const finding = this.repository.markFindingVerified(findingId, input.expectedVersion, now);
      this.repository.audit.append({
        missionId: finding.mission_id,
        ...(finding.run_id ? { runId: finding.run_id } : {}),
        actor: reviewer,
        action: "finding.verified",
        resourceType: "finding",
        resourceId: findingId,
        reason,
        details: { supportingEvidenceIds: readiness.supportingEvidenceIds, version: finding.version },
        occurredAt: now,
      });
      return readiness;
    });
  }

  private transitionCandidate(
    input: CandidateDecisionInput,
    fromStates: readonly EvidenceCandidate["state"][],
    toState: EvidenceCandidate["state"],
    actionName: string,
  ): EvidenceCandidate {
    const candidateId = identifier(input.candidateId, "candidateId");
    const reviewer = actor(input.actor);
    const reason = text(input.reason, "reason", 2_000);
    const now = this.repository.now();
    return this.repository.transaction(() => {
      const current = this.repository.getCandidate(candidateId);
      const updated = this.repository.transitionCandidate(candidateId, fromStates, toState, reviewer.id, reason, now);
      this.repository.audit.append({
        missionId: current.missionId,
        ...(current.runId ? { runId: current.runId } : {}),
        actor: reviewer,
        action: actionName,
        resourceType: "evidence_candidate",
        resourceId: candidateId,
        reason,
        details: { from: current.state, to: toState },
        occurredAt: now,
      });
      return updated;
    });
  }

  private validateProvenance(input: EvidenceProvenance): EvidenceProvenance {
    if (input.sources.length === 0 || input.sources.length > 100) {
      throw invalid("provenance_sources_required", "Evidence provenance requires 1-100 source references");
    }
    const sources = input.sources.map((source) => ({
      kind: source.kind,
      id: identifier(source.id, "provenance.source.id"),
    }));
    if (new Set(sources.map((source) => `${source.kind}:${source.id}`)).size !== sources.length) {
      throw invalid("duplicate_provenance_source", "Evidence provenance sources must be unique");
    }
    return {
      method: text(input.method, "provenance.method", 500),
      explanation: text(input.explanation, "provenance.explanation", 2_000),
      sources,
    };
  }

  private validateCustody(
    input: readonly EvidenceCustodyEventInput[],
    acquiredAt: string,
    now: string,
  ): readonly { eventType: EvidenceCustodyEventInput["eventType"]; actor: string; occurredAt: string; details: JsonValue }[] {
    if (input.length === 0 || input.length > 100) {
      throw invalid("custody_required", "Evidence requires 1-100 chain-of-custody events before verification");
    }
    const events = input.map((event) => {
      const occurredAt = isoTimestamp(event.occurredAt, "custody.occurredAt");
      assertNotFuture(occurredAt, now, "custody.occurredAt");
      if (Date.parse(occurredAt) < Date.parse(acquiredAt)) {
        throw invalid("custody_precedes_acquisition", "Custody events cannot precede evidence acquisition");
      }
      return {
        eventType: event.eventType,
        actor: identifier(event.actor, "custody.actor"),
        occurredAt,
        details: sanitizedJson(event.details ?? {}).value,
      };
    });
    if (!events.some((event) => event.eventType === "acquired")) {
      throw insufficient("Chain of custody lacks an acquisition event", "Record who acquired the evidence and when.");
    }
    return events;
  }
}
