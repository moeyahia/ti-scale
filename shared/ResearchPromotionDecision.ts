export interface ResearchPromotionDecisionFingerprintInput {
  readonly expectedVersion: number;
  readonly action: string;
  readonly actorId: string;
  readonly rationale: string;
  readonly evidenceRefs: readonly string[];
  readonly targetStrategyVersionId?: string;
  readonly canaryBounds?: {
    readonly maxMissions: number;
    readonly maxWallClockMs: number;
  };
}

/**
 * Produce the single canonical representation hashed by both the local server
 * and the browser retry boundary. Property order is deliberately stable and
 * nested values are normalized exactly as the server persists them.
 */
export function canonicalResearchPromotionDecision(
  input: ResearchPromotionDecisionFingerprintInput,
): string {
  return JSON.stringify({
    action: input.action,
    actorId: input.actorId.trim(),
    canaryBounds: input.canaryBounds
      ? {
          maxMissions: input.canaryBounds.maxMissions,
          maxWallClockMs: input.canaryBounds.maxWallClockMs,
        }
      : null,
    evidenceRefs: [
      ...new Set(input.evidenceRefs.map((reference) => reference.trim())),
    ],
    expectedVersion: input.expectedVersion,
    rationale: input.rationale.trim(),
    targetStrategyVersionId:
      input.targetStrategyVersionId?.trim() || null,
  });
}
