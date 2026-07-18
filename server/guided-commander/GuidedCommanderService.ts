import type { JsonValue } from "../events";
import {
  BrainContextService,
  type BrainContextResult,
  type BrainProviderContextEnvelope,
} from "../brain-runtime";
import {
  MemoryRepository,
  getMemoryControlPolicy,
  memoryCandidateAllowed,
  SecondBrainService,
  type ContextPack,
  type ContextPackItemDisposition,
  type MemorySensitivity,
  type MemoryScope,
  type RetrievalPolicy,
} from "../memory";
import { hashCanonical } from "../missions/canonical";
import { GuidedCommanderRepository, type GuidedScope } from "./GuidedCommanderRepository";
import type {
  GuidedCommanderAction,
  GuidedCommanderMemoryContext,
  GuidedCommanderOptions,
  GuidedCommanderPort,
  GuidedCommanderPortInput,
  GuidedCommanderReply,
  GuidedMessage,
  GuidedTextResult,
  GuidedTranscriptPage,
  MemoryCandidateReply,
  MemorySuppressionReply,
} from "./types";
import {
  GuidedCommanderError,
  redactSensitiveText,
  resultRequestIdentity,
  validatePortResponse,
  type ContextualActionRequest,
  type DoNotRememberRequest,
  type InterpretResultRequest,
  type RememberRequest,
} from "./validation";

const TERMINAL_RUN_STATES = new Set(["completed", "failed", "cancelled"]);
const MAX_IN_FLIGHT_PROVIDER_MUTATIONS = 256;
const DEFAULT_PROVIDER_MUTATION_LEASE_MS = 120_000;

interface ServiceDependencies {
  readonly repository: GuidedCommanderRepository;
  /** Omitted for the local-only memory-candidate boundary. */
  readonly port?: GuidedCommanderPort;
  readonly secondBrain?: SecondBrainService;
  readonly brainContext?: BrainContextService;
  readonly options?: GuidedCommanderOptions;
}

interface PreparedContext {
  readonly pack: ContextPack;
  readonly nodes: readonly GuidedCommanderMemoryContext[];
  readonly lifecycleResult?: BrainContextResult;
}

interface ProviderMutationFlight {
  readonly requestHash: string;
  readonly promise: Promise<GuidedCommanderReply>;
}

interface ProviderMutationReservation {
  readonly ownerToken: string;
  readonly expiresAt: string;
}

function asJsonValue<T>(value: T): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function contextualIdentity(
  missionId: string,
  action: string,
  request: ContextualActionRequest,
): Readonly<Record<string, unknown>> {
  return {
    missionId,
    action,
    runId: request.runId,
    stepId: request.stepId,
    expectedFingerprint: request.expectedFingerprint,
    note: request.note ?? null,
  };
}

function safeTextResult(result: InterpretResultRequest["result"]): GuidedTextResult {
  return {
    source: result.source,
    mediaType: result.mediaType,
    ...(result.fileName ? { fileName: result.fileName } : {}),
    byteSize: result.byteSize,
    contentHash: result.contentHash,
    redactedText: result.redactedText,
    redactionCount: result.redactionCount,
  };
}

function actionOperatorBody(action: GuidedCommanderAction, note?: string): string {
  const label = action === "explain_more"
    ? "Asked for more explanation of this exact Guided step."
    : action === "show_next_step"
      ? "Asked to review the exact next Guided step."
      : action === "use_another_approach"
        ? "Asked for a different in-scope approach without changing or executing the plan."
        : "Submitted a bounded text result for interpretation.";
  return note ? `${label}\n\nOperator note: ${note}` : label;
}

/**
 * Durable Guided conversational control plane. It explains and interprets but
 * has no executor, tool registry, approval mutation, or plan mutation handle.
 */
export class GuidedCommanderService {
  readonly repository: GuidedCommanderRepository;
  readonly secondBrain: SecondBrainService;
  readonly brainContext: BrainContextService;
  readonly #port?: GuidedCommanderPort;
  readonly #maximumMemorySensitivity: Exclude<MemorySensitivity, "restricted">;
  readonly #memoryContextBudget: number;
  readonly #memoryContextLimit: number;
  readonly #transcriptContextLimit: number;
  readonly #providerMutationLeaseMs: number;
  readonly #providerMutationFlights = new Map<string, ProviderMutationFlight>();

  constructor(dependencies: ServiceDependencies) {
    if (dependencies.port && (
      dependencies.port.kind !== "planning_only" ||
      dependencies.port.supportsToolExecution !== false
    )) {
      throw new TypeError("Guided Commander requires a planning-only provider with tool execution disabled");
    }
    this.repository = dependencies.repository;
    this.#port = dependencies.port;
    this.secondBrain = dependencies.secondBrain ?? new SecondBrainService(
      new MemoryRepository(dependencies.repository.database),
    );
    this.brainContext = dependencies.brainContext ?? new BrainContextService({
      database: dependencies.repository.database,
      secondBrain: this.secondBrain,
    });
    const maximumMemorySensitivity = dependencies.options?.maximumMemorySensitivity ?? "private";
    if (maximumMemorySensitivity === "restricted") {
      throw new RangeError("Guided Commander reusable Brain context cannot include restricted memory");
    }
    this.#maximumMemorySensitivity = maximumMemorySensitivity;
    this.#memoryContextBudget = dependencies.options?.memoryContextBudget ?? 6_000;
    this.#memoryContextLimit = dependencies.options?.memoryContextLimit ?? 8;
    this.#transcriptContextLimit = dependencies.options?.transcriptContextLimit ?? 24;
    this.#providerMutationLeaseMs = dependencies.options?.providerMutationLeaseMs
      ?? DEFAULT_PROVIDER_MUTATION_LEASE_MS;
    for (const [label, value, maximum] of [
      ["memoryContextBudget", this.#memoryContextBudget, 50_000],
      ["memoryContextLimit", this.#memoryContextLimit, 50],
      ["transcriptContextLimit", this.#transcriptContextLimit, 100],
    ] as const) {
      if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
        throw new RangeError(`${label} must be an integer from 1 through ${maximum}`);
      }
    }
    if (
      !Number.isSafeInteger(this.#providerMutationLeaseMs) ||
      this.#providerMutationLeaseMs < 1_000 ||
      this.#providerMutationLeaseMs > 15 * 60_000
    ) {
      throw new RangeError("providerMutationLeaseMs must be an integer from 1,000 through 900,000");
    }
  }

  transcript(input: {
    missionId: string;
    runId: string;
    stepId?: string;
    cursor?: string;
    limit: number;
  }): GuidedTranscriptPage {
    return this.repository.transcript(input);
  }

  async respond(input: {
    missionId: string;
    action: Exclude<GuidedCommanderAction, "interpret_result">;
    request: ContextualActionRequest;
    idempotencyKey: string;
    actorId: string;
    signal: AbortSignal;
    assertMutationAuthority: () => void;
  }): Promise<GuidedCommanderReply> {
    const identity = contextualIdentity(input.missionId, input.action, input.request);
    const requestHash = hashCanonical(identity);
    const idempotencyScope = `${input.action}:${input.missionId}`;
    return this.runProviderMutationSingleFlight({
      idempotencyScope,
      idempotencyKey: input.idempotencyKey,
      requestHash,
      actorId: input.actorId,
      assertMutationAuthority: input.assertMutationAuthority,
      operation: (reservation) => this.providerMutation({
        missionId: input.missionId,
        action: input.action,
        request: input.request,
        requestHash,
        idempotencyKey: input.idempotencyKey,
        actorId: input.actorId,
        signal: input.signal,
        reservation,
        assertMutationAuthority: input.assertMutationAuthority,
      }),
    });
  }

  async interpret(input: {
    missionId: string;
    request: InterpretResultRequest;
    idempotencyKey: string;
    actorId: string;
    signal: AbortSignal;
    assertMutationAuthority: () => void;
  }): Promise<GuidedCommanderReply> {
    const requestHash = hashCanonical({
      missionId: input.missionId,
      action: "interpret_result",
      ...resultRequestIdentity(input.request),
    });
    const idempotencyScope = `interpret_result:${input.missionId}`;
    return this.runProviderMutationSingleFlight({
      idempotencyScope,
      idempotencyKey: input.idempotencyKey,
      requestHash,
      actorId: input.actorId,
      assertMutationAuthority: input.assertMutationAuthority,
      operation: (reservation) => {
        input.assertMutationAuthority();
        const scope = this.requireActiveScope(input.missionId, input.request);
        const result = safeTextResult(input.request.result);
        const evidence = this.repository.acquireTextEvidence(
          scope,
          input.actorId,
          result,
          input.assertMutationAuthority,
        );
        return this.providerMutation({
          missionId: input.missionId,
          action: "interpret_result",
          request: input.request,
          requestHash,
          idempotencyKey: input.idempotencyKey,
          actorId: input.actorId,
          signal: input.signal,
          reservation,
          existingScope: scope,
          result,
          evidenceId: evidence.id,
          assertMutationAuthority: input.assertMutationAuthority,
        });
      },
    });
  }

  remember(input: {
    missionId: string;
    request: RememberRequest;
    idempotencyKey: string;
    actorId: string;
    assertMutationAuthority: () => void;
  }): MemoryCandidateReply {
    const requestHash = hashCanonical({
      missionId: input.missionId,
      action: "remember",
      request: input.request,
    });
    const idempotencyScope = `remember:${input.missionId}`;
    // Durable replay is never an authority receipt.
    const replay = this.repository.findIdempotentAuthorized({
      scope: idempotencyScope,
      key: input.idempotencyKey,
      requestHash,
      assertMutationAuthority: input.assertMutationAuthority,
    });
    if (replay !== undefined) return replay as unknown as MemoryCandidateReply;
    const scope = this.requireActiveScope(input.missionId, input.request);
    const sourceMessage = this.repository.requireMessageForStep(
      input.request.sourceMessageId,
      scope.mission.id,
      scope.run.id,
      scope.step.id,
    );
    const content = input.request.content ?? sourceMessage.body;
    if (redactSensitiveText(content).redactionCount > 0) {
      throw new GuidedCommanderError(422, "sensitive_material_not_retained", "Memory content includes authentication material", {
        humanMessage: "Reusable memory cannot contain credentials or authentication material.",
        category: "policy_denied",
        remediation: "Remove the secret and reference protected evidence by ID.",
      });
    }
    const sourceExcerpt = redactSensitiveText(sourceMessage.body).text.slice(0, 1_000);
    const memoryScope = this.memoryScope(scope, input.request.scope);
    const memoryControl = getMemoryControlPolicy(this.repository.database);
    if (!memoryCandidateAllowed(memoryControl, input.request.nodeType)) {
      throw new GuidedCommanderError(403, "memory_retention_disabled", "This memory category is disabled by operator controls", {
        humanMessage: input.request.nodeType === "preference"
          ? "Personal preference learning is disabled in the Memory Control Center."
          : "Operational memory retention is disabled in the Memory Control Center.",
        category: "policy_denied",
        remediation: "Review the Second Brain memory controls before asking Ti-Scale to retain this item.",
      });
    }
    const value = this.repository.commitIdempotent({
      scope: idempotencyScope,
      key: input.idempotencyKey,
      requestHash,
      actorId: input.actorId,
      assertMutationAuthority: input.assertMutationAuthority,
      operation: () => {
        input.assertMutationAuthority();
        const candidate = this.secondBrain.proposeMemory({
          nodeType: input.request.nodeType,
          title: input.request.title,
          summary: input.request.summary,
          body: content,
          scope: memoryScope,
          sensitivity: input.request.sensitivity,
          confidence: 0.85,
          provenance: {
            method: "operator_statement",
            explanation: "The operator deliberately requested a reviewable memory candidate from a Guided message.",
            sources: [{
              sourceType: "message",
              sourceId: sourceMessage.id,
              acquiredAt: sourceMessage.createdAt,
              sourceHash: hashCanonical(sourceMessage.body),
              excerptRedacted: sourceExcerpt,
            }],
          },
          proposedBy: input.actorId,
        });
        this.repository.appendMemoryEvent({
          scope,
          actorId: input.actorId,
          action: "candidate_created",
          candidateId: candidate.id,
          resourceId: sourceMessage.id,
        });
        this.repository.insertExchange({
          scope,
          actorId: input.actorId,
          action: "remember",
          operatorBody: "Requested a reviewable memory candidate from this Guided step.",
          operatorStructured: {
            kind: "guided_memory_request",
            stepId: scope.step.id,
            actionFingerprint: scope.step.actionFingerprint,
            sourceMessageId: sourceMessage.id,
          },
          assistantBody: "Added a candidate to the Memory Inbox. It is not confirmed memory until reviewed.",
          assistantStructured: {
            kind: "guided_memory_candidate",
            stepId: scope.step.id,
            actionFingerprint: scope.step.actionFingerprint,
            candidateId: candidate.id,
            status: "pending",
          },
        });
        return {
          candidateId: candidate.id,
          status: "pending" as const,
          sourceMessageId: sourceMessage.id,
        };
      },
    });
    return value.value;
  }

  doNotRemember(input: {
    missionId: string;
    request: DoNotRememberRequest;
    idempotencyKey: string;
    actorId: string;
    assertMutationAuthority: () => void;
  }): MemorySuppressionReply {
    const requestHash = hashCanonical({
      missionId: input.missionId,
      action: "do_not_remember",
      request: input.request,
    });
    const idempotencyScope = `do_not_remember:${input.missionId}`;
    // Durable replay is never an authority receipt.
    const replay = this.repository.findIdempotentAuthorized({
      scope: idempotencyScope,
      key: input.idempotencyKey,
      requestHash,
      assertMutationAuthority: input.assertMutationAuthority,
    });
    if (replay !== undefined) return replay as unknown as MemorySuppressionReply;
    const scope = this.requireActiveScope(input.missionId, input.request);
    const candidate = this.repository.candidateScope(input.request.candidateId);
    if (!candidate || !this.candidateIsVisible(scope, candidate)) {
      throw new GuidedCommanderError(404, "memory_candidate_not_found", "Memory candidate was not found in this scope", {
        category: "not_found",
      });
    }
    if (candidate.status !== "pending") {
      throw new GuidedCommanderError(409, "memory_candidate_not_pending", "Only pending memory candidates can be suppressed", {
        category: "conflict",
      });
    }
    const value = this.repository.commitIdempotent({
      scope: idempotencyScope,
      key: input.idempotencyKey,
      requestHash,
      actorId: input.actorId,
      assertMutationAuthority: input.assertMutationAuthority,
      operation: () => {
        input.assertMutationAuthority();
        const suppressionId = this.secondBrain.rejectAndDoNotRelearn(
          input.request.candidateId,
          input.actorId,
          input.request.reason,
        );
        this.repository.appendMemoryEvent({
          scope,
          actorId: input.actorId,
          action: "candidate_suppressed",
          candidateId: input.request.candidateId,
          resourceId: suppressionId,
        });
        this.repository.insertExchange({
          scope,
          actorId: input.actorId,
          action: "do_not_remember",
          operatorBody: "Requested that this memory candidate not be retained or relearned.",
          operatorStructured: {
            kind: "guided_memory_suppression_request",
            stepId: scope.step.id,
            actionFingerprint: scope.step.actionFingerprint,
            candidateId: input.request.candidateId,
          },
          assistantBody: "The candidate was suppressed. Its content will not be used for future retrieval.",
          assistantStructured: {
            kind: "guided_memory_suppression",
            stepId: scope.step.id,
            actionFingerprint: scope.step.actionFingerprint,
            candidateId: input.request.candidateId,
            status: "suppressed",
          },
        });
        return {
          candidateId: input.request.candidateId,
          status: "suppressed" as const,
          suppressionId,
        };
      },
    });
    return value.value;
  }

  private async providerMutation(input: {
    missionId: string;
    action: GuidedCommanderAction;
    request: ContextualActionRequest;
    requestHash: string;
    idempotencyKey: string;
    actorId: string;
    signal: AbortSignal;
    reservation: ProviderMutationReservation;
    existingScope?: GuidedScope;
    result?: GuidedTextResult;
    evidenceId?: string;
    assertMutationAuthority: () => void;
  }): Promise<GuidedCommanderReply> {
    const port = this.#port;
    if (!port) {
      throw new GuidedCommanderError(503, "guided_commander_runtime_unavailable", "Guided Commander mutation runtime is unavailable", {
        humanMessage: "This V2 process has no callable planning-only Guided provider. The represented step remains paused and no Commander result was created.",
        category: "dependency_missing",
        remediation: "Connect a policy-compatible Guided provider and mount its planning-only runtime boundary, then recheck System readiness.",
      });
    }
    const idempotencyScope = `${input.action}:${input.missionId}`;
    input.assertMutationAuthority();
    const scope = input.existingScope ?? this.requireActiveScope(input.missionId, input.request);
    const context = this.prepareMemoryContext(scope, input.action);
    const recentTranscript = this.repository.recentTranscript(
      scope.mission.id,
      scope.run.id,
      this.#transcriptContextLimit,
    );
    const providerModel = port.model?.trim() || "unspecified";
    const turn = this.repository.startProviderTurn(scope, port.providerId, providerModel);
    let response;
    let contextDispositions: readonly ContextPackItemDisposition[];
    let providerBrainContext: BrainProviderContextEnvelope;
    try {
      providerBrainContext = context.lifecycleResult
        ? this.brainContext.prepareProviderContext(context.lifecycleResult, {
            providerTurnId: turn.id,
            providerId: port.providerId,
            modelId: providerModel,
          })
        : this.brainContext.preparePersistedContextPack(context.pack, {
            providerTurnId: turn.id,
            providerId: port.providerId,
            modelId: providerModel,
          });
      const providerInput: GuidedCommanderPortInput = {
        action: input.action,
        mission: scope.mission,
        run: scope.run,
        step: scope.step,
        recentTranscript,
        ...(input.request.note ? { operatorNote: input.request.note } : {}),
        ...(input.result ? { result: input.result } : {}),
        brainContext: providerBrainContext,
        constraints: {
          executeTools: false,
          mutatePlan: false,
          revealPrivateReasoning: false,
          consequentialNextStepRequiresOperatorDecision: true,
        },
      };
      response = validatePortResponse(await port.respond(providerInput, input.signal));
      contextDispositions = this.validateContextUse(context, response.contextUse ?? []);
    } catch (error) {
      const aborted = input.signal.aborted || (error instanceof DOMException && error.name === "AbortError");
      this.repository.finishProviderTurn(
        turn.id,
        aborted ? "cancelled" : "failed",
        turn.startedAt,
        aborted ? "cancelled" : "provider_unavailable",
      );
      if (error instanceof GuidedCommanderError) throw error;
      if (aborted) {
        throw new GuidedCommanderError(503, "guided_commander_cancelled", "Guided Commander request was cancelled", {
          category: "cancelled",
          retryable: true,
        });
      }
      throw new GuidedCommanderError(502, "guided_commander_provider_failed", "Planning-only provider failed", {
        humanMessage: "The explanation provider failed without advancing or executing the mission.",
        category: "provider_unavailable",
        retryable: true,
        remediation: "Retry after the planning provider is healthy.",
      });
    }
    let committed: { value: GuidedCommanderReply; replayed: boolean };
    try {
      committed = this.repository.completeProviderMutationReservation({
        scope: idempotencyScope,
        key: input.idempotencyKey,
        requestHash: input.requestHash,
        ownerToken: input.reservation.ownerToken,
        actorId: input.actorId,
        assertMutationAuthority: input.assertMutationAuthority,
        operation: () => {
          // Context attribution belongs to the durable response, not merely to a
          // provider attempt. The reservation owner is fenced before this
          // callback runs, so a stale worker cannot mark memory as used for a
          // response that it did not commit.
          for (const disposition of contextDispositions) {
            this.secondBrain.recordContextUse(context.pack.id, disposition);
          }
          const exchange = this.repository.insertExchange({
            scope,
            actorId: input.actorId,
            action: input.action,
            operatorBody: actionOperatorBody(input.action, input.request.note),
            operatorStructured: asJsonValue({
              kind: "guided_commander_request",
              action: input.action,
              stepId: scope.step.id,
              decisionId: scope.step.guidedDecisionId,
              actionFingerprint: scope.step.actionFingerprint,
              evidenceId: input.evidenceId ?? null,
            }),
            assistantBody: response.body,
            assistantStructured: asJsonValue({
              kind: "guided_commander_response",
              action: input.action,
              stepId: scope.step.id,
              decisionId: scope.step.guidedDecisionId,
              actionFingerprint: scope.step.actionFingerprint,
              summary: response.summary,
              confidence: response.confidence,
              observations: response.observations ?? [],
              recommendedNextStep: response.recommendedNextStep ?? null,
              contextPackId: context.pack.id,
              providerExposureReceiptId: providerBrainContext.exposureReceiptId ?? null,
              memoryStatus: providerBrainContext.status,
              memoryDegradation: providerBrainContext.degradation ?? null,
              evidenceId: input.evidenceId ?? null,
              executionPerformed: false,
              planMutated: false,
              nextConsequentialActionRequiresDecision: true,
            }),
            contextPackId: context.pack.id,
            providerTurnId: turn.id,
            ...(input.evidenceId ? { evidenceId: input.evidenceId } : {}),
          });
          if (input.evidenceId) {
            this.repository.recordTextEvidenceInterpretation({
              scope,
              evidenceId: input.evidenceId,
              assistantMessageId: exchange.assistantMessage.id,
              contextPackId: context.pack.id,
              summary: response.summary,
              confidence: response.confidence,
            });
          }
          // The winning provider turn and its durable response are one
          // aggregate. A process crash must not leave a committed message with
          // a permanently "started" provider turn.
          this.repository.finishProviderTurn(turn.id, "completed", turn.startedAt);
          return {
            action: input.action,
            ...exchange,
            contextPackId: context.pack.id,
            ...(input.evidenceId ? { evidenceId: input.evidenceId } : {}),
            actionFingerprint: scope.step.actionFingerprint,
          } satisfies GuidedCommanderReply;
        },
      });
    } catch (error) {
      this.repository.finishProviderTurn(turn.id, "failed", turn.startedAt, "persistence_error");
      throw error;
    }
    if (committed.replayed) {
      this.repository.finishProviderTurn(
        turn.id,
        "cancelled",
        turn.startedAt,
        "idempotent_replay",
      );
    }
    return committed.value;
  }

  /**
   * Coalesces concurrent provider-backed mutations before any evidence, Context
   * Pack, provider-turn, or conversation side effect is created. Durable replay
   * remains repository-owned; this bounded in-process layer closes the window
   * before that durable record can exist.
   */
  private runProviderMutationSingleFlight(input: {
    idempotencyScope: string;
    idempotencyKey: string;
    requestHash: string;
    actorId: string;
    assertMutationAuthority: () => void;
    operation: (reservation: ProviderMutationReservation) => Promise<GuidedCommanderReply>;
  }): Promise<GuidedCommanderReply> {
    // Keep direct service consumers fail-closed too: neither replay nor the
    // provider reservation is consulted before the server-held proof passes.
    const replay = this.repository.findIdempotentAuthorized({
      scope: input.idempotencyScope,
      key: input.idempotencyKey,
      requestHash: input.requestHash,
      assertMutationAuthority: input.assertMutationAuthority,
    });
    if (replay !== undefined) {
      return Promise.resolve(replay as unknown as GuidedCommanderReply);
    }

    const flightKey = hashCanonical({
      scope: input.idempotencyScope,
      key: input.idempotencyKey,
    });
    const existing = this.#providerMutationFlights.get(flightKey);
    if (existing) {
      if (existing.requestHash !== input.requestHash) {
        throw new GuidedCommanderError(
          409,
          "idempotency_key_conflict",
          "Idempotency key was reused with another request",
          {
            humanMessage: "This action key already belongs to another Guided command.",
            category: "conflict",
          },
        );
      }
      return existing.promise;
    }

    if (this.#providerMutationFlights.size >= MAX_IN_FLIGHT_PROVIDER_MUTATIONS) {
      throw new GuidedCommanderError(
        503,
        "guided_commander_busy",
        "Guided Commander has reached its bounded concurrent request limit",
        {
          humanMessage: "Guided Commander is handling the maximum number of active requests.",
          category: "provider_unavailable",
          retryable: true,
          remediation: "Retry with the same Idempotency-Key after an active request completes.",
        },
      );
    }

    // Reserve durably before evidence ingestion, Context Pack creation,
    // provider turns, or conversation writes. BEGIN IMMEDIATE + settings.key's
    // primary key makes this fence visible across service processes.
    const reservationResult = this.repository.reserveProviderMutation({
      scope: input.idempotencyScope,
      key: input.idempotencyKey,
      requestHash: input.requestHash,
      actorId: input.actorId,
      leaseMs: this.#providerMutationLeaseMs,
      assertMutationAuthority: input.assertMutationAuthority,
    });
    if (reservationResult.status === "replay") {
      return Promise.resolve(reservationResult.response as unknown as GuidedCommanderReply);
    }
    if (reservationResult.status === "in_progress") {
      const retryAfterMs = Math.max(
        250,
        Math.min(
          this.#providerMutationLeaseMs,
          Date.parse(reservationResult.expiresAt) - Date.parse(this.repository.now()),
        ),
      );
      throw new GuidedCommanderError(
        409,
        "guided_commander_request_in_progress",
        "An identical Guided provider request is already in progress",
        {
          humanMessage: "This Guided request is already being processed by another worker.",
          category: "conflict",
          retryable: true,
          details: { retryAfterMs, expiresAt: reservationResult.expiresAt },
          remediation: "Retry with the same Idempotency-Key after the bounded lease or completion response.",
        },
      );
    }
    const reservation: ProviderMutationReservation = reservationResult;

    // Defer side effects until after the local flight is visible. Renewing the
    // lease prevents a healthy long-running provider turn from being mistaken
    // for a crashed owner; a real crash naturally stops renewal and permits a
    // bounded takeover.
    const promise = Promise.resolve().then(async () => {
      const heartbeat = setInterval(() => {
        try {
          this.repository.renewProviderMutationReservation({
            scope: input.idempotencyScope,
            key: input.idempotencyKey,
            requestHash: input.requestHash,
            ownerToken: reservation.ownerToken,
            leaseMs: this.#providerMutationLeaseMs,
          });
        } catch {
          // Completion remains owner-fenced. A failed heartbeat cannot grant
          // authority and is handled by the atomic completion check.
        }
      }, Math.max(250, Math.floor(this.#providerMutationLeaseMs / 3)));
      heartbeat.unref?.();
      try {
        return await input.operation(reservation);
      } catch (error) {
        this.repository.releaseProviderMutationReservation({
          scope: input.idempotencyScope,
          key: input.idempotencyKey,
          requestHash: input.requestHash,
          ownerToken: reservation.ownerToken,
        });
        throw error;
      } finally {
        clearInterval(heartbeat);
      }
    });
    this.#providerMutationFlights.set(flightKey, {
      requestHash: input.requestHash,
      promise,
    });
    const clear = () => {
      if (this.#providerMutationFlights.get(flightKey)?.promise === promise) {
        this.#providerMutationFlights.delete(flightKey);
      }
    };
    void promise.then(clear, clear);
    return promise;
  }

  private requireActiveScope(missionId: string, request: ContextualActionRequest): GuidedScope {
    const scope = this.repository.requireScope(
      missionId,
      request.runId,
      request.stepId,
      request.expectedFingerprint,
    );
    if (TERMINAL_RUN_STATES.has(scope.run.status)) {
      throw new GuidedCommanderError(409, "guided_run_terminal", "Guided run is already terminal", {
        humanMessage: "This run is complete. Start a new run before requesting another Guided step.",
        category: "conflict",
      });
    }
    return scope;
  }

  private prepareMemoryContext(
    scope: GuidedScope,
    action: GuidedCommanderAction,
  ): PreparedContext {
    const query = [
      scope.mission.objective,
      scope.step.phase,
      scope.step.title,
      scope.step.objective,
      action.replaceAll("_", " "),
    ].join(" ");
    // Result interpretation is the existing, truthful material-result seam:
    // it must refresh phase context before explaining what changed. Ordinary
    // same-step explanation remains a Context Pack retrieval, but is not
    // mislabeled as a phase-transition lifecycle receipt.
    let lifecycleResult: BrainContextResult | undefined;
    const pack = action === "interpret_result"
      ? (lifecycleResult = this.brainContext.retrieve({
          hook: "phase_transition",
          journey: "guided",
          availabilityPolicy: "degraded_allowed",
          query,
          queryRedacted: `${scope.step.phase}: ${scope.step.title} — interpret result`,
          actorId: "guided-commander",
          actorType: "agent",
          missionId: scope.mission.id,
          runId: scope.run.id,
          stepId: scope.step.id,
          allowGlobal: true,
          maximumSensitivity: this.#maximumMemorySensitivity,
          contextBudget: this.#memoryContextBudget,
          limit: this.#memoryContextLimit,
        })).contextPack
      : this.secondBrain.retrieveAndPersistContext({
          query,
          queryRedacted: `${scope.step.phase}: ${scope.step.title} — ${action.replaceAll("_", " ")}`,
          policy: {
            ...(scope.mission.engagementId ? { engagementId: scope.mission.engagementId } : {}),
            missionId: scope.mission.id,
            allowGlobal: true,
            journey: "guided",
            maximumSensitivity: this.#maximumMemorySensitivity,
            allowedStatuses: ["confirmed", "verified"],
            contextBudget: this.#memoryContextBudget,
            limit: this.#memoryContextLimit,
            graphDepth: 1,
          } satisfies RetrievalPolicy,
          purpose: `Guided Commander ${action.replaceAll("_", " ")}`,
          createdBy: "guided-commander",
          missionId: scope.mission.id,
          runId: scope.run.id,
          stepId: scope.step.id,
        });
    const nodes = pack.items.map((item) => {
      const node = this.secondBrain.repository.requireNode(item.nodeId);
      return {
        id: node.id,
        nodeType: node.nodeType,
        title: node.title,
        summary: node.summary,
        body: node.body.slice(0, 4_000),
        scope: node.scope,
        confidence: node.confidence,
        lifecycleStatus: node.lifecycleStatus,
      } satisfies GuidedCommanderMemoryContext;
    });
    return { pack, nodes, ...(lifecycleResult ? { lifecycleResult } : {}) };
  }

  private validateContextUse(
    context: PreparedContext,
    dispositions: readonly {
      nodeId: string;
      used: boolean;
      relevanceReason: string;
      influenceSummary?: string;
      ignoredReason?: string;
    }[],
  ): readonly ContextPackItemDisposition[] {
    const available = new Set(context.nodes.map((node) => node.id));
    const seen = new Set<string>();
    const normalized: ContextPackItemDisposition[] = [];
    for (const disposition of dispositions) {
      if (!available.has(disposition.nodeId) || seen.has(disposition.nodeId)) {
        throw new GuidedCommanderError(502, "invalid_guided_context_use", "Provider context usage is not part of the persisted context pack", {
          category: "provider_unavailable",
          retryable: true,
        });
      }
      if (disposition.used && !disposition.influenceSummary?.trim()) {
        throw new GuidedCommanderError(502, "invalid_guided_context_use", "Used memory requires an influence summary", {
          category: "provider_unavailable",
          retryable: true,
        });
      }
      seen.add(disposition.nodeId);
      normalized.push({
        ...disposition,
        ...(!disposition.used && !disposition.ignoredReason
          ? { ignoredReason: "Retrieved context was not needed for this response" }
          : {}),
      });
    }
    for (const node of context.nodes) {
      if (seen.has(node.id)) continue;
      normalized.push({
        nodeId: node.id,
        used: false,
        relevanceReason: "Retrieved for the current mission and represented step",
        ignoredReason: "The planning-only provider did not use this memory in its response",
      });
    }
    return normalized;
  }

  private memoryScope(scope: GuidedScope, requested: RememberRequest["scope"]): MemoryScope {
    if (requested === "global") return { kind: "global" };
    if (requested === "engagement") {
      if (!scope.mission.engagementId) {
        throw new GuidedCommanderError(409, "engagement_memory_scope_unavailable", "Mission has no engagement scope", {
          category: "scope_conflict",
        });
      }
      return { kind: "engagement", engagementId: scope.mission.engagementId };
    }
    return {
      kind: "mission",
      ...(scope.mission.engagementId ? { engagementId: scope.mission.engagementId } : {}),
      missionId: scope.mission.id,
    };
  }

  private candidateIsVisible(
    scope: GuidedScope,
    candidate: {
      scope: string;
      engagementId: string | null;
      missionId: string | null;
      nodeType: string;
    },
  ): boolean {
    if (candidate.scope === "mission") return candidate.missionId === scope.mission.id;
    if (candidate.scope === "engagement") {
      return Boolean(scope.mission.engagementId) && candidate.engagementId === scope.mission.engagementId;
    }
    return candidate.scope === "global" && candidate.nodeType === "preference";
  }
}
