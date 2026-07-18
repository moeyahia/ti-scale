import type { JsonValue } from "../events";
import type { MemoryNode, MemorySensitivity } from "../memory";
import type { BrainProviderContextEnvelope } from "../brain-runtime";

export const GUIDED_COMMANDER_ACTIONS = [
  "explain_more",
  "show_next_step",
  "interpret_result",
  "use_another_approach",
] as const;

export type GuidedCommanderAction = (typeof GUIDED_COMMANDER_ACTIONS)[number];

export interface GuidedMissionContext {
  readonly id: string;
  readonly name: string;
  readonly objective: string;
  readonly engagementId: string | null;
  readonly authorizationStatus: string;
  readonly scope: Readonly<Record<string, unknown>>;
}

export interface GuidedRunContext {
  readonly id: string;
  readonly status: string;
  readonly currentStepId: string | null;
  readonly progress: number;
}

export interface GuidedRepresentedStep {
  readonly id: string;
  readonly planId: string;
  readonly planVersion: number;
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly status: string;
  readonly assignedAgentId: string | null;
  readonly riskClass: string | null;
  readonly successCriteria: readonly string[];
  readonly explanation: string;
  readonly rationale: string;
  readonly reversibility: string;
  readonly representedAction: Readonly<Record<string, unknown>>;
  /** Exact canonical parameters owned by the pending Guided decision. */
  readonly decisionParameters: JsonValue;
  readonly actionFingerprint: string;
  readonly guidedDecisionId: string;
  readonly guidedDecisionStatus: string;
}

/**
 * Canonical observation state for the current step. This is projected from
 * evidence and chain-of-custody records, so reload/resume never depends on the
 * chat transcript or client memory.
 */
export interface GuidedReviewedObservation {
  readonly evidenceId: string;
  readonly contentHash: string;
  readonly source: "paste" | "text_upload";
  readonly mediaType: string;
  readonly fileName: string | null;
  readonly byteSize: number;
  readonly redactionCount: number;
  readonly interpretationSummary: string;
  readonly verificationState: "unverified" | "verified" | "disputed" | "rejected";
  readonly acquiredAt: string;
}

export interface GuidedMessage {
  readonly id: string;
  readonly conversationId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string | null;
  readonly role: "operator" | "assistant" | "system" | "tool";
  readonly body: string;
  readonly structuredContent: JsonValue;
  readonly contextPackId: string | null;
  readonly createdAt: string;
}

export interface GuidedTranscriptPage {
  readonly mission: GuidedMissionContext;
  readonly run: GuidedRunContext;
  readonly currentStep: GuidedRepresentedStep | null;
  readonly currentObservation: GuidedReviewedObservation | null;
  readonly items: readonly GuidedMessage[];
  readonly nextCursor: string | null;
}

export interface GuidedCommanderMemoryContext {
  readonly id: string;
  readonly nodeType: MemoryNode["nodeType"];
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly scope: MemoryNode["scope"];
  readonly confidence: number;
  readonly lifecycleStatus: MemoryNode["lifecycleStatus"];
}

/**
 * An inspectable presentation directive derived only from confirmed preference
 * nodes already admitted to the persisted Context Pack. It may influence how
 * an explanation is presented, never authorization or execution policy.
 */
export interface GuidedPresentationPreference {
  readonly nodeId: string;
  readonly directive: string;
  readonly scope: MemoryNode["scope"];
  readonly confidence: number;
}

export interface GuidedTextResult {
  readonly source: "paste" | "text_upload";
  readonly mediaType: "text/plain" | "application/json" | "text/csv" | "application/xml" | "text/xml";
  readonly fileName?: string;
  readonly byteSize: number;
  readonly contentHash: string;
  /** This is redacted before the planning-only port receives it. */
  readonly redactedText: string;
  readonly redactionCount: number;
}

export interface GuidedCommanderPortInput {
  readonly action: GuidedCommanderAction;
  readonly mission: GuidedMissionContext;
  readonly run: GuidedRunContext;
  readonly step: GuidedRepresentedStep;
  readonly recentTranscript: readonly GuidedMessage[];
  readonly operatorNote?: string;
  readonly result?: GuidedTextResult;
  /** Sanitized, disclosure-approved, receipted public-provider context only. */
  readonly brainContext: BrainProviderContextEnvelope;
  readonly constraints: {
    readonly executeTools: false;
    readonly mutatePlan: false;
    readonly revealPrivateReasoning: false;
    readonly consequentialNextStepRequiresOperatorDecision: true;
  };
}

export interface GuidedContextDisposition {
  readonly nodeId: string;
  readonly used: boolean;
  readonly relevanceReason: string;
  readonly influenceSummary?: string;
  readonly ignoredReason?: string;
}

export interface GuidedCommanderPortResponse {
  readonly body: string;
  readonly summary: string;
  readonly confidence: number;
  readonly observations?: readonly string[];
  readonly recommendedNextStep?: string;
  readonly contextUse?: readonly GuidedContextDisposition[];
}

/**
 * Planning/explanation-only provider boundary. Implementations receive no tool
 * registry, command executor, credential material, or plan mutation callback.
 */
export interface GuidedCommanderPort {
  readonly kind: "planning_only";
  readonly supportsToolExecution: false;
  readonly providerId: string;
  readonly model?: string;
  respond(
    input: GuidedCommanderPortInput,
    signal: AbortSignal,
  ): Promise<GuidedCommanderPortResponse>;
}

export interface GuidedCommanderOptions {
  readonly maximumMemorySensitivity?: MemorySensitivity;
  readonly memoryContextBudget?: number;
  readonly memoryContextLimit?: number;
  readonly transcriptContextLimit?: number;
  /** Durable cross-process provider-mutation lease; renewed while work is live. */
  readonly providerMutationLeaseMs?: number;
  readonly clock?: () => Date;
  readonly createId?: (prefix: string) => string;
}

export interface GuidedCommanderReply {
  readonly action: GuidedCommanderAction;
  readonly operatorMessage: GuidedMessage;
  readonly assistantMessage: GuidedMessage;
  readonly contextPackId: string;
  readonly evidenceId?: string;
  readonly actionFingerprint: string;
}

export interface MemoryCandidateReply {
  readonly candidateId: string;
  readonly status: "pending";
  readonly sourceMessageId: string;
}

export interface MemorySuppressionReply {
  readonly candidateId: string;
  readonly status: "suppressed";
  readonly suppressionId: string;
}
