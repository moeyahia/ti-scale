import {
  ACTION_CLASS_DEFINITIONS,
  EVIDENCE_TYPE_DEFINITIONS,
} from "../domain";
import type {
  GuidedCommanderPort,
  GuidedCommanderPortInput,
  GuidedCommanderPortResponse,
} from "./types";

const HASH = /^[a-f0-9]{64}$/u;

export interface LocalDeterministicGuidedCommanderPortOptions {
  readonly providerId: string;
  readonly model: string;
  readonly modelConfigurationHash: string;
}

function boundedList(values: readonly string[], maximum = 8): string {
  const selected = values.filter((value) => value.trim()).slice(0, maximum);
  return selected.length === 0
    ? "No additional condition is recorded."
    : selected.map((value, index) => `${index + 1}. ${value}`).join("\n");
}

/**
 * Local, provider-free implementation of the same planning-only port contract
 * used by public models. The selected model assignment is still durable and
 * attributable, but this adapter never opens a socket or dispatches a tool.
 */
export class LocalDeterministicGuidedCommanderPort implements GuidedCommanderPort {
  readonly kind = "planning_only" as const;
  readonly supportsToolExecution = false as const;
  readonly contextBoundary = "trusted_local" as const;
  readonly providerId: string;
  readonly model: string;
  readonly modelConfigurationHash: string;

  constructor(options: LocalDeterministicGuidedCommanderPortOptions) {
    this.providerId = options.providerId.trim();
    this.model = options.model.trim();
    this.modelConfigurationHash = options.modelConfigurationHash.trim();
    if (!this.providerId || !this.model || !HASH.test(this.modelConfigurationHash)) {
      throw new TypeError("A complete local deterministic model binding is required");
    }
  }

  async respond(
    input: GuidedCommanderPortInput,
    signal: AbortSignal,
  ): Promise<GuidedCommanderPortResponse> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const definition = ACTION_CLASS_DEFINITIONS.find(
      ({ id }) => id === input.step.representedAction.actionClass,
    );
    const target = typeof input.step.representedAction.target === "string"
      && input.step.representedAction.target.trim()
      ? input.step.representedAction.target.trim()
      : "the exact target shown on the decision card";
    const evidence = definition?.defaultEvidenceTypeIds.flatMap((id) => {
      const item = EVIDENCE_TYPE_DEFINITIONS.find((candidate) => candidate.id === id);
      return item ? [`${item.label}: ${item.proves}`] : [];
    }) ?? [];
    const risk = definition?.likelySideEffects.length
      ? definition.likelySideEffects
      : [`The represented action is classified as ${input.step.riskClass ?? "unspecified"} risk.`];
    const method = definition
      ? `${definition.plainLanguageDescription} ${definition.technicalDescription}`
      : input.step.explanation;
    const alternative = input.action === "use_another_approach"
      ? "Reject this exact step with a short reason if the represented method is unsuitable. Ti-Scale will then create a separately reviewable plan change; this explanation does not alter the plan."
      : `Review decision ${input.step.guidedDecisionId}. Run only that represented action if its exact target and parameters are correct; otherwise explain more, choose another approach, skip, or stop.`;
    const relevantContext = input.brainContext.items.slice(0, 3);
    const contextSection = relevantContext.length > 0
      ? `Relevant Second Brain context\n${relevantContext
          .map((item) => `- ${item.title}: ${item.summary}`)
          .join("\n")}`
      : "Relevant Second Brain context — no applicable confirmed memory was found.";

    return {
      body: [
        `Phase — ${input.step.phase}`,
        `Purpose — ${input.step.objective}`,
        `What this step does — ${method}`,
        `Why it is proposed — ${input.step.rationale}`,
        `Exact scope — ${target}`,
        `Risk and possible side effects\n${boundedList(risk)}`,
        `How it stops or reverses — ${input.step.reversibility}`,
        `What a useful result must show\n${boundedList([
          ...input.step.successCriteria,
          ...evidence,
        ])}`,
        contextSection,
        "Control boundary — This response explains one represented step. It did not contact the target, run a tool, approve the decision, change the plan, or verify evidence.",
      ].join("\n\n"),
      summary: `${input.step.phase}: ${input.step.title} remains paused at its exact Guided decision.`,
      confidence: 1,
      observations: [
        `Current phase: ${input.step.phase}.`,
        `Exact scope: ${target}.`,
        `Decision state: ${input.step.guidedDecisionStatus}; no action was executed by this explanation.`,
      ],
      recommendedNextStep: alternative,
      contextUse: input.brainContext.items.map((item, index) => index < 3
        ? {
            nodeId: item.nodeId,
            used: true,
            relevanceReason: item.relevanceReason,
            influenceSummary:
              "Included this confirmed memory as visible supporting context for the represented step without allowing it to change scope or policy.",
          }
        : {
            nodeId: item.nodeId,
            used: false,
            relevanceReason: item.relevanceReason,
            ignoredReason:
              "The local explanation used only the three highest-ranked confirmed memories to keep the Context Pack bounded.",
          }),
    };
  }
}

export function createLocalDeterministicGuidedCommanderPort(
  options: LocalDeterministicGuidedCommanderPortOptions,
): LocalDeterministicGuidedCommanderPort {
  return new LocalDeterministicGuidedCommanderPort(options);
}
