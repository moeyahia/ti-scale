import type { SqliteDatabase } from "../db";
import {
  ACTION_CLASS_DEFINITIONS,
  EVIDENCE_TYPE_DEFINITIONS,
} from "../domain";
import type { JsonValue } from "../events";
import { hashCanonical } from "../missions/canonical";
import { RuntimeRepository } from "../command-runtime/RuntimeRepository";
import type { BrainContextService } from "../brain-runtime";
import { GuidedCommanderRepository, type GuidedScope } from "./GuidedCommanderRepository";
import type {
  GuidedCommanderAction,
  GuidedCommanderReply,
} from "./types";
import {
  GuidedCommanderError,
  type ContextualActionRequest,
} from "./validation";

const TERMINAL_RUN_STATES = new Set(["completed", "failed", "cancelled"]);
const LOCAL_CONTEXT_ACTIONS = new Set<GuidedCommanderAction>([
  "explain_more",
  "show_next_step",
  "use_another_approach",
]);

function jsonValue<T>(value: T): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function record(value: unknown): Readonly<Record<string, unknown>> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : {};
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function boundedList(values: readonly string[], maximum = 4): string {
  const selected = values.filter(Boolean).slice(0, maximum);
  if (selected.length === 0) return "No additional item is stated.";
  return selected.map((value, index) => `${index + 1}. ${value}`).join("\n");
}

function actionClass(scope: GuidedScope) {
  const id = stringValue(scope.step.representedAction.actionClass);
  return ACTION_CLASS_DEFINITIONS.find((definition) => definition.id === id);
}

function evidenceRequirements(scope: GuidedScope): readonly string[] {
  const definition = actionClass(scope);
  if (!definition) return [];
  return definition.defaultEvidenceTypeIds.flatMap((id) => {
    const evidence = EVIDENCE_TYPE_DEFINITIONS.find((candidate) => candidate.id === id);
    return evidence ? [`${evidence.label}: ${evidence.proves}`] : [];
  });
}

function exactTarget(scope: GuidedScope): string {
  return stringValue(scope.step.representedAction.target)
    ?? "the exact target shown on the decision card";
}

function nextRecommendation(
  action: Exclude<GuidedCommanderAction, "interpret_result">,
  scope: GuidedScope,
): string {
  if (action === "use_another_approach") {
    return "If this represented method is unsuitable, reject this exact step with the reason and request a replacement plan. Ti-Scale has not changed the plan or selected an alternative automatically.";
  }
  return `Review the exact target and parameters on decision ${scope.step.guidedDecisionId}. If they match the authorized scope, deliberately choose the single represented run or manual action; otherwise choose another approach, skip, or stop.`;
}

function localBriefing(
  action: Exclude<GuidedCommanderAction, "interpret_result">,
  scope: GuidedScope,
): {
  readonly body: string;
  readonly summary: string;
  readonly observations: readonly string[];
  readonly recommendedNextStep: string;
} {
  const definition = actionClass(scope);
  const risks = definition?.likelySideEffects.length
    ? definition.likelySideEffects
    : scope.step.riskClass
      ? [`The represented action is classified as ${scope.step.riskClass} risk.`]
      : ["No additional side effect is recorded beyond the exact action card."];
  const evidence = evidenceRequirements(scope);
  const expected = [...scope.step.successCriteria, ...evidence];
  const target = exactTarget(scope);
  const observations = [
    `Current phase: ${scope.step.phase}.`,
    `Exact scope: ${target}.`,
    `Decision state: ${scope.step.guidedDecisionStatus}; no action was executed by this explanation.`,
  ];
  const method = definition
    ? `${definition.plainLanguageDescription} ${definition.technicalDescription}`
    : scope.step.explanation;
  const body = [
    `Phase — ${scope.step.phase}`,
    `Purpose — ${scope.step.objective}`,
    `What the represented step does — ${method}`,
    `Why it is proposed — ${scope.step.rationale}`,
    `Exact scope — ${target}`,
    `Risk and side effects\n${boundedList(risks)}`,
    `How it can be stopped or reversed — ${scope.step.reversibility}`,
    `What a useful result must show\n${boundedList(expected, 8)}`,
    `Control boundary — This explanation does not run a tool, contact the target, change the plan, or approve the step. Only the exact decision card can authorize one represented action.`,
  ].join("\n\n");
  return {
    body,
    summary: `${scope.step.phase}: ${scope.step.title} remains paused at its exact Guided decision.`,
    observations,
    recommendedNextStep: nextRecommendation(action, scope),
  };
}

export interface LocalReviewedToolObservationInterpretation {
  readonly observationId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string;
  readonly actionId: string;
  readonly toolCallId: string;
  readonly actionFingerprint: string;
  readonly observationType: string;
  readonly statement: string;
  readonly normalizedResult: Readonly<Record<string, unknown>>;
  readonly confidence: number;
  readonly verificationState: "unverified" | "corroborated" | "conflicting" | "stale" | "rejected";
  readonly sourceTool: string;
  readonly meaning: string;
  readonly limitation: string;
  readonly recommendedNextStep: string;
  readonly evidencePromoted: false;
  readonly rawLogRead: false;
}

interface ObservationRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string;
  readonly observation_type: string;
  readonly statement: string;
  readonly normalized_value_json: string;
  readonly confidence: number;
  readonly verification_state: LocalReviewedToolObservationInterpretation["verificationState"];
  readonly source_tool: string;
  readonly log_record_id: string;
  readonly action_id: string;
  readonly action_fingerprint: string;
  readonly action_status: string;
  readonly guided_decision_id: string;
  readonly decision_fingerprint: string;
  readonly tool_call_id: string;
  readonly tool_call_status: string;
  readonly parser_id: string;
  readonly parser_version: string;
  readonly run_status: string;
}

function interpretationMeaning(row: ObservationRow, normalized: Readonly<Record<string, unknown>>): string {
  const result = record(normalized.result);
  if (row.observation_type === "tcp_service_scan") {
    const openPorts = Array.isArray(result.openPorts)
      ? result.openPorts.flatMap((entry) => {
          const item = record(entry);
          const port = typeof item.port === "number" ? item.port : null;
          if (port === null) return [];
          const service = stringValue(item.service);
          const version = stringValue(item.version);
          return [`TCP/${port}${service ? ` ${service}` : ""}${version ? ` — ${version}` : ""}`];
        }).slice(0, 100)
      : [];
    return openPorts.length
      ? `The bounded connect scan observed these open services on the exact approved host: ${openPorts.join(", ")}. Product text is an attributable observation, not proof that a CVE applies.`
      : "The bounded connect scan did not observe an open service in its exact requested port set. That says nothing about ports that were not represented by this step.";
  }
  if (row.observation_type === "host_liveness") {
    return result.responded === true
      ? "The exact host answered the bounded reachability check at that time. This confirms a response, not the operating system, service exposure, or vulnerability state."
      : "The exact host did not answer the bounded reachability check. Filtering, routing, and an offline host remain possible; the result does not prove which explanation is correct.";
  }
  if (row.observation_type === "dns_record_query") {
    const count = typeof result.answerCount === "number" ? result.answerCount : null;
    return count === null
      ? "The exact DNS query completed, but the normalized record does not state a trustworthy answer count."
      : `The exact DNS query produced ${count} parsed answer${count === 1 ? "" : "s"} at that time. Resolution can change and does not authorize contact with newly returned addresses outside the signed scope.`;
  }
  if (row.observation_type === "http_metadata_response") {
    const status = typeof result.statusCode === "number" ? result.statusCode : null;
    return status === null
      ? "The bounded HTTP metadata request completed without a retained status line, so reachability remains uncertain."
      : `The exact service returned HTTP ${status} to the bounded metadata request. This confirms that response only; it does not verify page content, authentication behavior, or a finding.`;
  }
  if (row.observation_type === "tcp_connectivity") {
    return result.connectionEstablished === true
      ? "The exact TCP endpoint accepted a connection without an application payload. This confirms transport reachability only."
      : "The exact TCP endpoint did not accept a connection during this check. Refusal, timeout, or routing context must be read from the normalized fields without guessing.";
  }
  return row.statement;
}

/**
 * Provider-independent, explanation-only Guided Commander.
 *
 * The mutation path is restricted to a nonterminal, current, exact pending
 * Guided decision and writes only a conversation exchange plus Context Pack
 * attribution. The completed-observation path is a deterministic canonical
 * read and therefore never mutates a terminal run.
 */
export class LocalGuidedCommander {
  readonly repository: GuidedCommanderRepository;
  readonly runtimeRepository: RuntimeRepository;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    brainContext: BrainContextService;
    clock?: () => Date;
  }>) {
    this.repository = new GuidedCommanderRepository(options.database, {
      ...(options.clock ? { clock: options.clock } : {}),
    });
    this.runtimeRepository = new RuntimeRepository(options.database);
  }

  respond(input: Readonly<{
    missionId: string;
    action: Exclude<GuidedCommanderAction, "interpret_result">;
    request: ContextualActionRequest;
    idempotencyKey: string;
    actorId: string;
    assertMutationAuthority: () => void;
  }>): GuidedCommanderReply {
    if (!LOCAL_CONTEXT_ACTIONS.has(input.action)) {
      throw new GuidedCommanderError(400, "guided_local_action_unsupported", "Local Guided action is unsupported", {
        category: "invalid_input",
      });
    }
    const requestHash = hashCanonical({
      missionId: input.missionId,
      action: input.action,
      mode: "local_deterministic_guidance",
      ...input.request,
    });
    const idempotencyScope = `local_guidance:${input.action}:${input.missionId}`;
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
        const context = this.options.brainContext.retrieve({
          hook: "guided_briefing",
          journey: "guided",
          availabilityPolicy: "degraded_allowed",
          query: `${scope.mission.objective} ${scope.step.phase} ${scope.step.title} ${input.action}`,
          queryRedacted: `${scope.step.phase}: ${scope.step.title} — deterministic Guided briefing`,
          actorId: "ti-scale.local-guided-commander",
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
          "The deterministic local briefing used the canonical mission, plan, decision, action-class, and evidence registries; retained memory did not alter its content or policy.",
        );
        const briefing = localBriefing(input.action, scope);
        const exchange = this.repository.insertExchange({
          scope,
          actorId: input.actorId,
          action: input.action,
          operatorBody: input.request.note
            ? `Requested ${input.action.replaceAll("_", " ")} for the current exact step.\n\nOperator note: ${input.request.note}`
            : `Requested ${input.action.replaceAll("_", " ")} for the current exact step.`,
          operatorStructured: jsonValue({
            kind: "guided_commander_request",
            action: input.action,
            guidanceMode: "local_deterministic",
            stepId: scope.step.id,
            decisionId: scope.step.guidedDecisionId,
            actionFingerprint: scope.step.actionFingerprint,
          }),
          assistantBody: briefing.body,
          assistantStructured: jsonValue({
            kind: "guided_commander_response",
            action: input.action,
            guidanceMode: "local_deterministic",
            stepId: scope.step.id,
            decisionId: scope.step.guidedDecisionId,
            actionFingerprint: scope.step.actionFingerprint,
            summary: briefing.summary,
            confidence: 1,
            observations: briefing.observations,
            recommendedNextStep: briefing.recommendedNextStep,
            contextPackId: context.contextPack.id,
            memoryStatus: context.status,
            providerExposureReceiptId: null,
            providerContacted: false,
            toolDispatched: false,
            targetContacted: false,
            executionPerformed: false,
            planMutated: false,
            evidenceVerified: false,
            nextConsequentialActionRequiresDecision: true,
          }),
          contextPackId: context.contextPack.id,
        });
        return {
          action: input.action,
          ...exchange,
          contextPackId: context.contextPack.id,
          actionFingerprint: scope.step.actionFingerprint,
        } satisfies GuidedCommanderReply;
      },
    }).value;
  }

  interpretCompletedObservation(input: Readonly<{
    missionId: string;
    runId: string;
    observationId: string;
  }>): LocalReviewedToolObservationInterpretation {
    const row = this.options.database.prepare(`
      SELECT o.id, o.mission_id, o.run_id, o.step_id, o.observation_type,
        o.statement, o.normalized_value_json, o.confidence,
        o.verification_state, o.source_tool,
        source.log_record_id, source.parser_id, source.parser_version,
        a.id AS action_id, a.fingerprint AS action_fingerprint,
        a.status AS action_status, a.guided_decision_id,
        gd.requested_action_fingerprint AS decision_fingerprint,
        tc.id AS tool_call_id, tc.status AS tool_call_status,
        r.status AS run_status
      FROM observations o
      JOIN missions m ON m.id = o.mission_id
      JOIN runs r ON r.id = o.run_id AND r.mission_id = m.id
      JOIN plan_steps ps ON ps.id = o.step_id AND ps.run_id = r.id
      JOIN observation_log_sources source ON source.observation_id = o.id
      JOIN engagement_log_records log
        ON log.id = source.log_record_id
        AND log.mission_id = o.mission_id
        AND log.run_id = o.run_id
        AND log.step_id = o.step_id
      JOIN actions a ON a.id = log.action_id AND a.run_id = r.id AND a.step_id = ps.id
      JOIN tool_calls tc ON tc.id = log.tool_call_id AND tc.action_id = a.id
      JOIN guided_decisions gd ON gd.id = a.guided_decision_id
        AND gd.mission_id = m.id AND gd.run_id = r.id AND gd.step_id = ps.id
      WHERE o.id = ? AND o.mission_id = ? AND o.run_id = ?
        AND m.journey = 'guided' AND r.journey = 'guided'
        AND m.control_plane = 'ti_scale' AND r.control_plane = 'ti_scale'
        AND r.status = 'completed'
        AND a.status = 'succeeded' AND tc.status = 'succeeded'
        AND source.parser_id = 'ti-scale.reviewed-local-tool-normalizer'
        AND o.source_tool LIKE 'kali:%'
      ORDER BY source.log_record_id LIMIT 1
    `).get(input.observationId, input.missionId, input.runId) as ObservationRow | undefined;
    if (!row) {
      throw new GuidedCommanderError(404, "guided_reviewed_observation_not_found", "Completed reviewed Guided observation was not found", {
        humanMessage: "No completed, reviewed local-tool observation matches this Guided run.",
        category: "not_found",
      });
    }
    let normalized: Readonly<Record<string, unknown>>;
    try {
      normalized = record(JSON.parse(row.normalized_value_json) as unknown);
    } catch {
      throw new GuidedCommanderError(409, "guided_observation_integrity_failed", "Reviewed observation payload is malformed", {
        humanMessage: "The canonical observation failed its integrity check and was not interpreted.",
        category: "data_integrity",
      });
    }
    const provenance = record(normalized.provenance);
    const exact = normalized.missionId === row.mission_id
      && normalized.runId === row.run_id
      && normalized.stepId === row.step_id
      && normalized.actionId === row.action_id
      && normalized.toolCallId === row.tool_call_id
      && normalized.toolId === row.source_tool
      && provenance.logRecordId === row.log_record_id
      && provenance.actionId === row.action_id
      && provenance.toolCallId === row.tool_call_id
      && row.action_fingerprint === row.decision_fingerprint;
    if (!exact) {
      throw new GuidedCommanderError(409, "guided_observation_binding_changed", "Reviewed observation binding is inconsistent", {
        humanMessage: "The observation no longer matches its exact action, decision, tool call, and log provenance, so it was not interpreted.",
        category: "data_integrity",
      });
    }
    return {
      observationId: row.id,
      missionId: row.mission_id,
      runId: row.run_id,
      stepId: row.step_id,
      actionId: row.action_id,
      toolCallId: row.tool_call_id,
      actionFingerprint: row.action_fingerprint,
      observationType: row.observation_type,
      statement: row.statement,
      normalizedResult: record(normalized.result),
      confidence: row.confidence,
      verificationState: row.verification_state,
      sourceTool: row.source_tool,
      meaning: interpretationMeaning(row, normalized),
      limitation: "This explanation uses only the canonical normalized observation. It did not read raw stdout or stderr, did not promote evidence, and does not verify a finding or CVE.",
      recommendedNextStep: "Review this unverified observation alongside another attributable source before using it to support a finding or a follow-up mission.",
      evidencePromoted: false,
      rawLogRead: false,
    };
  }

  private activeScope(missionId: string, request: ContextualActionRequest): GuidedScope {
    const scope = this.repository.requireScope(
      missionId,
      request.runId,
      request.stepId,
      request.expectedFingerprint,
    );
    if (TERMINAL_RUN_STATES.has(scope.run.status)) {
      throw new GuidedCommanderError(409, "guided_run_terminal", "Guided run is already terminal", {
        humanMessage: "This run is complete. Its reviewed observations are available through the read-only interpretation route.",
        category: "conflict",
      });
    }
    if (
      scope.run.status !== "waiting_guided_decision"
      || scope.step.status !== "waiting_guided_decision"
      || scope.step.guidedDecisionStatus !== "pending"
    ) {
      throw new GuidedCommanderError(409, "guided_action_not_pending", "The exact Guided step is not waiting for a decision", {
        humanMessage: "This explanation is available only for the current exact pending Guided step.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and use its current decision card.",
      });
    }
    const current = this.runtimeRepository.requireCurrentPendingDecision(
      scope.step.guidedDecisionId,
      this.repository.now(),
    );
    if (
      current.id !== scope.step.guidedDecisionId
      || current.missionId !== scope.mission.id
      || current.runId !== scope.run.id
      || current.stepId !== scope.step.id
      || current.actionFingerprint !== scope.step.actionFingerprint
    ) {
      throw new GuidedCommanderError(409, "guided_action_changed", "The represented Guided decision changed", {
        humanMessage: "The exact Guided action changed before the local briefing could be recorded.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and request a briefing for its current exact step.",
      });
    }
    return scope;
  }
}
