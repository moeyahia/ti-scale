export type GuidedCommanderAction =
  | "explain_more"
  | "show_next_step"
  | "interpret_result"
  | "use_another_approach";

export interface GuidedCommanderMessage {
  readonly id: string;
  readonly conversationId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string | null;
  readonly role: "operator" | "assistant" | "system" | "tool";
  readonly body: string;
  readonly structuredContent: Readonly<Record<string, unknown>>;
  readonly contextPackId: string | null;
  readonly createdAt: string;
}

export interface GuidedCommanderStep {
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
  readonly decisionParameters: unknown;
  readonly actionFingerprint: string;
  readonly guidedDecisionId: string;
  readonly guidedDecisionStatus: string;
}

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

export interface GuidedTranscript {
  readonly schemaVersion: "2.4";
  readonly mission: {
    readonly id: string;
    readonly name: string;
    readonly objective: string;
    readonly engagementId: string | null;
    readonly authorizationStatus: string;
    readonly scope: Readonly<Record<string, unknown>>;
  };
  readonly run: {
    readonly id: string;
    readonly status: string;
    readonly currentStepId: string | null;
    readonly progress: number;
  };
  readonly currentStep: GuidedCommanderStep | null;
  readonly currentObservation: GuidedReviewedObservation | null;
  readonly items: readonly GuidedCommanderMessage[];
  readonly nextCursor: string | null;
}

export interface GuidedCommanderReply {
  readonly action: GuidedCommanderAction;
  readonly operatorMessage: GuidedCommanderMessage;
  readonly assistantMessage: GuidedCommanderMessage;
  readonly contextPackId: string;
  readonly evidenceId?: string;
  readonly actionFingerprint: string;
}

export interface GuidedCommanderReplyEnvelope {
  readonly schemaVersion: "2.4";
  readonly result: GuidedCommanderReply;
  readonly ingestion?: {
    readonly multipartSupported: false;
    readonly acceptedSources: readonly ("paste" | "text_upload")[];
    readonly rawContentRetained: false;
  };
}

export interface GuidedMemoryCandidateResult {
  readonly schemaVersion: "2.4";
  readonly result: {
    readonly candidateId: string;
    readonly status: "pending";
    readonly sourceMessageId: string;
  };
}

export interface GuidedMemorySuppressionResult {
  readonly schemaVersion: "2.4";
  readonly result: {
    readonly candidateId: string;
    readonly status: "suppressed";
    readonly suppressionId: string;
  };
}

export interface GuidedContextualActionInput {
  readonly runId: string;
  readonly stepId: string;
  readonly expectedFingerprint: string;
  readonly note?: string;
}

export interface GuidedTextResultInput extends GuidedContextualActionInput {
  readonly result: {
    readonly source: "paste" | "text_upload";
    readonly mediaType: "text/plain" | "application/json" | "text/csv" | "application/xml" | "text/xml";
    readonly text: string;
    readonly byteSize?: number;
    readonly fileName?: string;
  };
}

export interface GuidedRememberInput extends GuidedContextualActionInput {
  readonly sourceMessageId: string;
  readonly nodeType: "preference" | "procedure" | "tool" | "tactic" | "technique" | "source";
  readonly title: string;
  readonly summary: string;
  readonly content?: string;
  readonly scope: "mission" | "engagement" | "global";
  readonly sensitivity: "internal" | "private" | "restricted";
}

export interface GuidedDoNotRememberInput extends GuidedContextualActionInput {
  readonly candidateId: string;
  readonly reason: string;
}
