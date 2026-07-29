import { Router, type Request, type Response } from "express";
import {
  ControlPlaneLeaseError,
  RunMutationAuthorityGuard,
  describeRunMutationAuthorityError,
  type AssertRunMutationLease,
} from "../control-plane";
import type { SqliteDatabase } from "../db";
import type { BrainContextService } from "../brain-runtime";
import { RuntimeRepository } from "../command-runtime/RuntimeRepository";
import { CommandRuntimeError } from "../command-runtime/types";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { JsonValue } from "../events";
import { hashCanonical } from "../missions/canonical";
import { LocalGuidedCommander } from "./LocalGuidedCommander";
import { GuidedCommanderRepository, type GuidedScope } from "./GuidedCommanderRepository";
import type { GuidedCommanderReply, GuidedTextResult } from "./types";
import {
  GuidedCommanderError,
  resultRequestIdentity,
  validateContextualActionRequest,
  validateIdempotencyKey,
  validateInterpretResultRequest,
  validatePathId,
  type InterpretResultRequest,
} from "./validation";

const TERMINAL_RUN_STATES = new Set(["completed", "failed", "cancelled"]);

function jsonValue<T>(value: T): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function safeResult(request: InterpretResultRequest): GuidedTextResult {
  return {
    source: request.result.source,
    mediaType: request.result.mediaType,
    ...(request.result.fileName ? { fileName: request.result.fileName } : {}),
    byteSize: request.result.byteSize,
    contentHash: request.result.contentHash,
    redactedText: request.result.redactedText,
    redactionCount: request.result.redactionCount,
  };
}

function deterministicIngestionAttestation(result: GuidedTextResult): {
  readonly body: string;
  readonly summary: string;
  readonly confidence: number;
  readonly observations: readonly string[];
} {
  const lineCount = result.redactedText.length === 0
    ? 0
    : result.redactedText.split(/\r?\n/u).length;
  const nonEmptyLineCount = result.redactedText
    .split(/\r?\n/u)
    .filter((line) => line.trim().length > 0).length;
  const sourceLabel = result.source === "text_upload" ? "text upload" : "pasted text";
  const observations = [
    `Received ${result.byteSize.toLocaleString("en-US")} UTF-8 bytes from ${sourceLabel}.`,
    `The sanitized review copy contains ${lineCount.toLocaleString("en-US")} line${lineCount === 1 ? "" : "s"}, including ${nonEmptyLineCount.toLocaleString("en-US")} non-empty line${nonEmptyLineCount === 1 ? "" : "s"}.`,
    result.redactionCount > 0
      ? `Removed ${result.redactionCount.toLocaleString("en-US")} sensitive-looking segment${result.redactionCount === 1 ? "" : "s"} before retention.`
      : "No configured secret pattern required redaction before retention.",
  ];
  const summary = "Ti-Scale locally retained and indexed the sanitized manual result. Only ingestion metadata was attested; no semantic interpretation or target outcome was verified.";
  return {
    body: [
      "The manual result was retained for your review.",
      ...observations,
      "This deterministic check confirms only bounded ingestion, hashing, and redaction metadata. It does not interpret the text, claim the represented procedure succeeded, identify a vulnerability, verify evidence, or contact the target. This manual-only runtime cannot advance from this result; use a configured semantic interpreter, skip the step, amend the plan, or stop.",
    ].join("\n\n"),
    summary,
    confidence: 1,
    observations,
  };
}

export interface LocalGuidedManualInterpreterOptions {
  readonly database: SqliteDatabase;
  readonly brainContext: BrainContextService;
  readonly clock?: () => Date;
}

/**
 * Provider-free ingestion-attestation boundary for the production manual-only Guided path.
 * It accepts only the already validated/redacted text result, records honest
 * non-use for retrieved Brain context, and never receives a tool, network, or
 * plan-mutation capability.
 */
export class LocalGuidedManualInterpreter {
  readonly repository: GuidedCommanderRepository;
  readonly runtimeRepository: RuntimeRepository;

  constructor(private readonly options: LocalGuidedManualInterpreterOptions) {
    this.repository = new GuidedCommanderRepository(options.database, {
      ...(options.clock ? { clock: options.clock } : {}),
    });
    this.runtimeRepository = new RuntimeRepository(options.database);
  }

  interpret(input: {
    readonly missionId: string;
    readonly request: InterpretResultRequest;
    readonly idempotencyKey: string;
    readonly actorId: string;
    readonly assertMutationAuthority: () => void;
  }): GuidedCommanderReply {
    const idempotencyScope = `local_ingest_result:${input.missionId}`;
    const requestHash = hashCanonical({
      missionId: input.missionId,
      action: "interpret_result",
      mode: "local_deterministic_ingestion_only",
      ...resultRequestIdentity(input.request),
    });
    const replay = this.repository.findIdempotentAuthorized({
      scope: idempotencyScope,
      key: input.idempotencyKey,
      requestHash,
      assertMutationAuthority: input.assertMutationAuthority,
    });
    if (replay !== undefined) return replay as unknown as GuidedCommanderReply;

    return this.repository.commitIdempotent({
      scope: idempotencyScope,
      key: input.idempotencyKey,
      requestHash,
      actorId: input.actorId,
      assertMutationAuthority: input.assertMutationAuthority,
      operation: () => {
        const scope = this.activeScope(input.missionId, input.request);
        const result = safeResult(input.request);
        const context = this.options.brainContext.retrieve({
          hook: "phase_transition",
          journey: "guided",
          availabilityPolicy: "degraded_allowed",
          query: `${scope.mission.objective} ${scope.step.phase} ${scope.step.title} review manual result`,
          queryRedacted: `${scope.step.phase}: ${scope.step.title} — local deterministic manual-result review`,
          actorId: "ti-scale.local-guided-manual-interpreter",
          actorType: "agent",
          missionId: scope.mission.id,
          runId: scope.run.id,
          stepId: scope.step.id,
          allowGlobal: true,
          maximumSensitivity: "private",
          contextBudget: 6_000,
          limit: 8,
        });
        this.options.brainContext.recordUnusedContext(
          context,
          "The local deterministic result review uses only the current represented step and submitted evidence metadata; retained memory did not alter its conclusion.",
        );
        const evidence = this.repository.acquireTextEvidence(
          scope,
          input.actorId,
          result,
          input.assertMutationAuthority,
        );
        const review = deterministicIngestionAttestation(result);
        const exchange = this.repository.insertExchange({
          scope,
          actorId: input.actorId,
          action: "interpret_result",
          operatorBody: input.request.note
            ? `Submitted a bounded text result for local ingestion attestation.\n\nOperator note: ${input.request.note}`
            : "Submitted a bounded text result for local ingestion attestation.",
          operatorStructured: jsonValue({
            kind: "guided_commander_request",
            action: "interpret_result",
            reviewMode: "local_deterministic_ingestion_only",
            stepId: scope.step.id,
            decisionId: scope.step.guidedDecisionId,
            actionFingerprint: scope.step.actionFingerprint,
            evidenceId: evidence.id,
          }),
          assistantBody: review.body,
          assistantStructured: jsonValue({
            kind: "guided_commander_response",
            action: "interpret_result",
            reviewMode: "local_deterministic_ingestion_only",
            stepId: scope.step.id,
            decisionId: scope.step.guidedDecisionId,
            actionFingerprint: scope.step.actionFingerprint,
            summary: review.summary,
            ingestionMetadataConfidence: review.confidence,
            observations: review.observations,
            recommendedNextStep: "Review the retained text. To advance, attach a configured semantic interpreter or choose skip, plan amendment, or stop; ingestion metadata alone cannot complete this step.",
            contextPackId: context.contextPack.id,
            providerExposureReceiptId: null,
            memoryStatus: context.status,
            evidenceId: evidence.id,
            executionPerformed: false,
            planMutated: false,
            targetContacted: false,
            providerContacted: false,
            toolDispatched: false,
            outcomeValidated: false,
            ingestionAttested: true,
            semanticInterpretationPerformed: false,
            evidenceVerified: false,
            nextConsequentialActionRequiresDecision: true,
          }),
          contextPackId: context.contextPack.id,
          evidenceId: evidence.id,
        });
        this.repository.recordTextEvidenceIngestionAttestation({
          scope,
          evidenceId: evidence.id,
          assistantMessageId: exchange.assistantMessage.id,
          contextPackId: context.contextPack.id,
          summary: review.summary,
          confidence: review.confidence,
        });
        return {
          action: "interpret_result",
          ...exchange,
          contextPackId: context.contextPack.id,
          evidenceId: evidence.id,
          actionFingerprint: scope.step.actionFingerprint,
        } satisfies GuidedCommanderReply;
      },
    }).value;
  }

  private activeScope(missionId: string, request: InterpretResultRequest): GuidedScope {
    const scope = this.repository.requireScope(
      missionId,
      request.runId,
      request.stepId,
      request.expectedFingerprint,
    );
    if (TERMINAL_RUN_STATES.has(scope.run.status)) {
      throw new GuidedCommanderError(409, "guided_run_terminal", "Guided run is already terminal", {
        humanMessage: "This run is complete. Start a new run before submitting another result.",
        category: "conflict",
      });
    }
    if (
      scope.run.status !== "waiting_guided_decision" ||
      scope.step.status !== "waiting_guided_decision" ||
      scope.step.guidedDecisionStatus !== "pending"
    ) {
      throw new GuidedCommanderError(409, "guided_manual_review_not_pending", "The exact manual step is not waiting for a result", {
        humanMessage: "This result cannot be attached because the represented manual decision is no longer pending.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and submit output only for its current pending step.",
      });
    }
    const current = this.runtimeRepository.requireCurrentPendingDecision(
      scope.step.guidedDecisionId,
      this.repository.now(),
    );
    if (
      current.id !== scope.step.guidedDecisionId ||
      current.missionId !== scope.mission.id ||
      current.runId !== scope.run.id ||
      current.stepId !== scope.step.id ||
      current.actionFingerprint !== scope.step.actionFingerprint
    ) {
      throw new GuidedCommanderError(409, "guided_manual_review_not_current", "The manual result no longer belongs to the current exact decision", {
        humanMessage: "This result cannot be reviewed because the represented Guided decision changed.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and submit output only for its current exact step.",
      });
    }
    return scope;
  }
}

export interface LocalGuidedManualInterpreterRouterDependencies extends LocalGuidedManualInterpreterOptions {
  readonly resolveActor: (request: Request) => string;
  readonly assertRunMutationLease?: AssertRunMutationLease;
  /** Disable when the model-bound Commander owns explanation mutations. */
  readonly mountGuidanceRoutes?: boolean;
}

function normalizedError(error: unknown): GuidedCommanderError {
  if (error instanceof ControlPlaneLeaseError) {
    const descriptor = describeRunMutationAuthorityError(error);
    return new GuidedCommanderError(descriptor.status, descriptor.code, error.message, {
      humanMessage: error.message,
      category: descriptor.category,
      retryable: descriptor.retryable,
      remediation: descriptor.remediation,
    });
  }
  if (error instanceof CommandRuntimeError) {
    const details = error.options.details;
    return new GuidedCommanderError(error.status, error.code, error.message, {
      ...(error.options.humanMessage ? { humanMessage: error.options.humanMessage } : {}),
      ...(error.options.category ? { category: error.options.category } : {}),
      ...(error.options.remediation ? { remediation: error.options.remediation } : {}),
      ...(error.options.retryable === undefined ? {} : { retryable: error.options.retryable }),
      ...(details && typeof details === "object" && !Array.isArray(details)
        ? { details: details as Readonly<Record<string, unknown>> }
        : {}),
    });
  }
  if (error instanceof GuidedCommanderError) return error;
  if (error instanceof TypeError || error instanceof RangeError) {
    return new GuidedCommanderError(422, "guided_validation_failed", "Guided result validation failed", {
      humanMessage: "The manual result could not be safely validated.",
      category: "invalid_input",
    });
  }
  return new GuidedCommanderError(500, "guided_local_interpreter_failed", "Local Guided result review failed", {
    humanMessage: "Ti-Scale could not retain the manual result for local review.",
    category: "internal",
    remediation: "Use the request ID to inspect the redacted local event before retrying with the same action key.",
  });
}

/** Mount after authentication and bounded JSON parsing middleware. */
export function createLocalGuidedManualInterpreterRouter(
  dependencies: LocalGuidedManualInterpreterRouterDependencies,
): Router {
  const interpreter = new LocalGuidedManualInterpreter(dependencies);
  const commander = new LocalGuidedCommander(dependencies);
  const authority = new RunMutationAuthorityGuard(dependencies.database);
  const router = Router();
  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });
  const localGuidance = (action: "explain_more" | "show_next_step" | "use_another_approach") =>
    async (request: Request, response: Response) => {
      const traceId = attachV2RequestId(request, response);
      try {
        const missionId = validatePathId(request.params.missionId, "missionId");
        const actorId = dependencies.resolveActor(request).trim();
        if (!actorId || actorId.length > 256) {
          throw new GuidedCommanderError(401, "operator_identity_required", "Operator identity is required", {
            humanMessage: "Sign in before requesting Guided guidance.",
            category: "authentication_missing",
          });
        }
        const body = validateContextualActionRequest(request.body);
        const mutation = authority.authorize({
          runId: body.runId,
          actorId,
          mode: "lease",
          ...(dependencies.assertRunMutationLease
            ? { assertLease: dependencies.assertRunMutationLease }
            : {}),
        });
        if (mutation.scope.missionId !== missionId) {
          throw new GuidedCommanderError(404, "guided_scope_not_found", "Guided run does not belong to this mission", {
            humanMessage: "The Guided run is unavailable or does not belong to this mission.",
            category: "not_found",
          });
        }
        const result = commander.respond({
          missionId,
          action,
          request: body,
          idempotencyKey: validateIdempotencyKey(request.get("Idempotency-Key")),
          actorId,
          assertMutationAuthority: mutation.assertCurrent,
        });
        response.json({
          schemaVersion: "2.4",
          result,
          guidance: {
            mode: "local_deterministic",
            providerContacted: false,
            toolDispatched: false,
            targetContacted: false,
            planMutated: false,
            exactDecisionRequired: true,
          },
        });
      } catch (error) {
        const normalized = normalizedError(error);
        sendV2Error(response, traceId, {
          status: normalized.status,
          code: normalized.code,
          message: normalized.message,
          humanMessage: normalized.options.humanMessage ?? normalized.message,
          retryable: normalized.options.retryable ?? false,
          category: normalized.options.category ?? "guided_commander",
          ...(normalized.options.details === undefined ? {} : { details: normalized.options.details }),
          ...(normalized.options.remediation ? { remediation: normalized.options.remediation } : {}),
        });
      }
    };
  if (dependencies.mountGuidanceRoutes !== false) {
    router.post(
      "/api/v2/guided/:missionId/commander/explain-more",
      localGuidance("explain_more"),
    );
    router.post(
      "/api/v2/guided/:missionId/commander/show-next-step",
      localGuidance("show_next_step"),
    );
    router.post(
      "/api/v2/guided/:missionId/commander/use-another-approach",
      localGuidance("use_another_approach"),
    );
  }
  router.get(
    "/api/v2/guided/:missionId/commander/reviewed-observations/:observationId/interpretation",
    (request, response) => {
      const traceId = attachV2RequestId(request, response);
      try {
        const actorId = dependencies.resolveActor(request).trim();
        if (!actorId || actorId.length > 256) {
          throw new GuidedCommanderError(401, "operator_identity_required", "Operator identity is required", {
            humanMessage: "Sign in before reviewing a completed Guided observation.",
            category: "authentication_missing",
          });
        }
        const result = commander.interpretCompletedObservation({
          missionId: validatePathId(request.params.missionId, "missionId"),
          runId: validatePathId(request.query.runId, "runId"),
          observationId: validatePathId(request.params.observationId, "observationId"),
        });
        response.json({
          schemaVersion: "2.4",
          result,
          interpretation: {
            mode: "local_deterministic_canonical_read",
            terminalRunMutated: false,
            rawLogRead: false,
            evidencePromoted: false,
            providerContacted: false,
          },
        });
      } catch (error) {
        const normalized = normalizedError(error);
        sendV2Error(response, traceId, {
          status: normalized.status,
          code: normalized.code,
          message: normalized.message,
          humanMessage: normalized.options.humanMessage ?? normalized.message,
          retryable: normalized.options.retryable ?? false,
          category: normalized.options.category ?? "guided_commander",
          ...(normalized.options.details === undefined ? {} : { details: normalized.options.details }),
          ...(normalized.options.remediation ? { remediation: normalized.options.remediation } : {}),
        });
      }
    },
  );
  router.post("/api/v2/guided/:missionId/commander/interpret-result", async (request, response) => {
    const traceId = attachV2RequestId(request, response);
    try {
      const missionId = validatePathId(request.params.missionId, "missionId");
      const actorId = dependencies.resolveActor(request).trim();
      if (!actorId || actorId.length > 256) {
        throw new GuidedCommanderError(401, "operator_identity_required", "Operator identity is required", {
          humanMessage: "Sign in before submitting a Guided result.",
          category: "authentication_missing",
        });
      }
      const body = validateInterpretResultRequest(request.body);
      const mutation = authority.authorize({
        runId: body.runId,
        actorId,
        mode: "lease",
        ...(dependencies.assertRunMutationLease
          ? { assertLease: dependencies.assertRunMutationLease }
          : {}),
      });
      if (mutation.scope.missionId !== missionId) {
        throw new GuidedCommanderError(404, "guided_scope_not_found", "Guided run does not belong to this mission", {
          humanMessage: "The Guided run is unavailable or does not belong to this mission.",
          category: "not_found",
        });
      }
      const result = interpreter.interpret({
        missionId,
        request: body,
        idempotencyKey: validateIdempotencyKey(request.get("Idempotency-Key")),
        actorId,
        assertMutationAuthority: mutation.assertCurrent,
      });
      response.json({
        schemaVersion: "2.4",
        result,
        ingestion: {
          mode: "local_deterministic_ingestion_only",
          multipartSupported: false,
          acceptedSources: ["paste", "text_upload"],
          rawContentRetained: false,
          providerContacted: false,
          toolDispatched: false,
          targetContacted: false,
        },
      });
    } catch (error) {
      const normalized = normalizedError(error);
      sendV2Error(response, traceId, {
        status: normalized.status,
        code: normalized.code,
        message: normalized.message,
        humanMessage: normalized.options.humanMessage ?? normalized.message,
        retryable: normalized.options.retryable ?? false,
        category: normalized.options.category ?? "guided_commander",
        ...(normalized.options.details === undefined ? {} : { details: normalized.options.details }),
        ...(normalized.options.remediation ? { remediation: normalized.options.remediation } : {}),
      });
    }
  });
  return router;
}
