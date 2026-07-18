import type {
  GuidedCommanderAction,
  GuidedCommanderMessage,
  GuidedCommanderReply,
  GuidedCommanderReplyEnvelope,
  GuidedCommanderStep,
  GuidedMemoryCandidateResult,
  GuidedMemorySuppressionResult,
  GuidedTranscript,
} from "../types/guidedCommander";
import { array, boolean, nonEmpty, nullableString, number, object, schema, string, stringList } from "./common";

const ACTIONS = new Set<GuidedCommanderAction>([
  "explain_more",
  "show_next_step",
  "interpret_result",
  "use_another_approach",
]);
const ROLES = new Set<GuidedCommanderMessage["role"]>(["operator", "assistant", "system", "tool"]);

function action(value: unknown): GuidedCommanderAction {
  const candidate = nonEmpty(value, "commander action") as GuidedCommanderAction;
  if (!ACTIONS.has(candidate)) throw new Error("commander action is invalid");
  return candidate;
}

function message(value: unknown): GuidedCommanderMessage {
  const item = object(value, "Guided message");
  const role = nonEmpty(item.role, "message.role") as GuidedCommanderMessage["role"];
  if (!ROLES.has(role)) throw new Error("Guided message role is invalid");
  return {
    id: nonEmpty(item.id, "message.id"),
    conversationId: nonEmpty(item.conversationId, "message.conversationId"),
    missionId: nonEmpty(item.missionId, "message.missionId"),
    runId: nonEmpty(item.runId, "message.runId"),
    stepId: nullableString(item.stepId, "message.stepId"),
    role,
    body: string(item.body, "message.body"),
    structuredContent: object(item.structuredContent, "message.structuredContent"),
    contextPackId: nullableString(item.contextPackId, "message.contextPackId"),
    createdAt: nonEmpty(item.createdAt, "message.createdAt"),
  };
}

function step(value: unknown): GuidedCommanderStep {
  const item = object(value, "represented Guided step");
  return {
    id: nonEmpty(item.id, "step.id"),
    planId: nonEmpty(item.planId, "step.planId"),
    planVersion: number(item.planVersion, "step.planVersion"),
    phase: nonEmpty(item.phase, "step.phase"),
    title: nonEmpty(item.title, "step.title"),
    objective: string(item.objective, "step.objective"),
    status: nonEmpty(item.status, "step.status"),
    assignedAgentId: nullableString(item.assignedAgentId, "step.assignedAgentId"),
    riskClass: nullableString(item.riskClass, "step.riskClass"),
    successCriteria: stringList(item.successCriteria, "step.successCriteria"),
    explanation: string(item.explanation, "step.explanation"),
    rationale: string(item.rationale, "step.rationale"),
    reversibility: string(item.reversibility, "step.reversibility"),
    representedAction: object(item.representedAction, "step.representedAction"),
    decisionParameters: item.decisionParameters ?? {},
    actionFingerprint: nonEmpty(item.actionFingerprint, "step.actionFingerprint"),
    guidedDecisionId: nonEmpty(item.guidedDecisionId, "step.guidedDecisionId"),
    guidedDecisionStatus: nonEmpty(item.guidedDecisionStatus, "step.guidedDecisionStatus"),
  };
}

function reply(value: unknown): GuidedCommanderReply {
  const item = object(value, "Guided Commander reply");
  return {
    action: action(item.action),
    operatorMessage: message(item.operatorMessage),
    assistantMessage: message(item.assistantMessage),
    contextPackId: nonEmpty(item.contextPackId, "reply.contextPackId"),
    ...(item.evidenceId === undefined ? {} : { evidenceId: nonEmpty(item.evidenceId, "reply.evidenceId") }),
    actionFingerprint: nonEmpty(item.actionFingerprint, "reply.actionFingerprint"),
  };
}

export function parseGuidedTranscript(payload: unknown): GuidedTranscript {
  const root = object(payload, "Guided transcript");
  schema(root);
  const mission = object(root.mission, "Guided mission");
  const run = object(root.run, "Guided run");
  const observation = root.currentObservation == null
    ? null
    : object(root.currentObservation, "Guided reviewed observation");
  const observationSource = observation?.source;
  if (observation && observationSource !== "paste" && observationSource !== "text_upload") {
    throw new Error("Guided observation source is invalid");
  }
  const verificationState = observation?.verificationState;
  if (
    observation &&
    (typeof verificationState !== "string" ||
      !new Set(["unverified", "verified", "disputed", "rejected"]).has(verificationState))
  ) {
    throw new Error("Guided observation verification state is invalid");
  }
  return {
    schemaVersion: "2.4",
    mission: {
      id: nonEmpty(mission.id, "mission.id"),
      name: nonEmpty(mission.name, "mission.name"),
      objective: string(mission.objective, "mission.objective"),
      engagementId: nullableString(mission.engagementId, "mission.engagementId"),
      authorizationStatus: nonEmpty(mission.authorizationStatus, "mission.authorizationStatus"),
      scope: object(mission.scope, "mission.scope"),
    },
    run: {
      id: nonEmpty(run.id, "run.id"),
      status: nonEmpty(run.status, "run.status"),
      currentStepId: nullableString(run.currentStepId, "run.currentStepId"),
      progress: number(run.progress, "run.progress"),
    },
    currentStep: root.currentStep === null ? null : step(root.currentStep),
    currentObservation: observation ? {
      evidenceId: nonEmpty(observation.evidenceId, "observation.evidenceId"),
      contentHash: nonEmpty(observation.contentHash, "observation.contentHash"),
      source: observationSource as "paste" | "text_upload",
      mediaType: nonEmpty(observation.mediaType, "observation.mediaType"),
      fileName: nullableString(observation.fileName, "observation.fileName"),
      byteSize: number(observation.byteSize, "observation.byteSize"),
      redactionCount: number(observation.redactionCount, "observation.redactionCount"),
      interpretationSummary: nonEmpty(observation.interpretationSummary, "observation.interpretationSummary"),
      verificationState: verificationState as "unverified" | "verified" | "disputed" | "rejected",
      acquiredAt: nonEmpty(observation.acquiredAt, "observation.acquiredAt"),
    } : null,
    items: array(root.items, "transcript.items").map(message),
    nextCursor: nullableString(root.nextCursor, "transcript.nextCursor"),
  };
}

export function parseGuidedCommanderReply(payload: unknown): GuidedCommanderReplyEnvelope {
  const root = object(payload, "Guided Commander response");
  schema(root);
  let ingestion: GuidedCommanderReplyEnvelope["ingestion"];
  if (root.ingestion !== undefined) {
    const item = object(root.ingestion, "Guided ingestion metadata");
    if (boolean(item.multipartSupported, "multipartSupported") !== false) throw new Error("multipart must remain disabled");
    if (boolean(item.rawContentRetained, "rawContentRetained") !== false) throw new Error("raw content retention must remain disabled");
    const acceptedSources = array(item.acceptedSources, "acceptedSources").map((source) => {
      if (source !== "paste" && source !== "text_upload") throw new Error("accepted result source is invalid");
      return source;
    });
    ingestion = { multipartSupported: false, rawContentRetained: false, acceptedSources };
  }
  return {
    schemaVersion: "2.4",
    result: reply(root.result),
    ...(ingestion ? { ingestion } : {}),
  };
}

export function parseGuidedMemoryCandidate(payload: unknown): GuidedMemoryCandidateResult {
  const root = object(payload, "Guided memory candidate response");
  schema(root);
  const result = object(root.result, "Guided memory candidate");
  if (result.status !== "pending") throw new Error("memory candidate must remain pending");
  return {
    schemaVersion: "2.4",
    result: {
      candidateId: nonEmpty(result.candidateId, "candidateId"),
      status: "pending",
      sourceMessageId: nonEmpty(result.sourceMessageId, "sourceMessageId"),
    },
  };
}

export function parseGuidedMemorySuppression(payload: unknown): GuidedMemorySuppressionResult {
  const root = object(payload, "Guided memory suppression response");
  schema(root);
  const result = object(root.result, "Guided memory suppression");
  if (result.status !== "suppressed") throw new Error("memory candidate was not suppressed");
  return {
    schemaVersion: "2.4",
    result: {
      candidateId: nonEmpty(result.candidateId, "candidateId"),
      status: "suppressed",
      suppressionId: nonEmpty(result.suppressionId, "suppressionId"),
    },
  };
}
