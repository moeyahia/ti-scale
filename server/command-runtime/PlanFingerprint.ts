import { hashJson } from "../orchestration/serialization";
import type { MissionPlanDraft, PlannedStep } from "./types";

export interface PlanContentDocument {
  readonly strategySummary: string;
  readonly steps: readonly PlannedStep[];
}

export function planContentFingerprint(
  plan: Pick<MissionPlanDraft, "strategySummary" | "steps"> | PlanContentDocument,
): string {
  // Preserve RuntimeRepository's established equivalence contract exactly.
  // A normalization change here would silently alter loop detection for live
  // runs; migrations copy the former plan_hash into this fingerprint column.
  return hashJson({
    strategy: plan.strategySummary,
    steps: plan.steps,
  });
}

/** A unique integrity receipt for one immutable persisted plan version. */
export function planVersionReceiptHash(input: {
  readonly runId: string;
  readonly planId: string;
  readonly version: number;
  readonly contentHash: string;
}): string {
  return hashJson({ schemaVersion: 1, ...input });
}
