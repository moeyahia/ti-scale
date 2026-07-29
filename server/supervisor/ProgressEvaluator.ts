import { createHash } from "node:crypto";
import { stableSerialize } from "./ActionFingerprint";

export type SupervisedStepState = "pending" | "running" | "blocked" | "completed" | "failed" | "skipped";

export interface FindingProgress {
  confidence: number;
  evidenceCount: number;
}

export interface ProgressSnapshot {
  stepStates?: Readonly<Record<string, SupervisedStepState>>;
  evidenceIds?: readonly string[];
  findingProgress?: Readonly<Record<string, FindingProgress>>;
  discoveredEntityIds?: readonly string[];
  resolvedDependencyIds?: readonly string[];
  resolvedDecisionIds?: readonly string[];
  contractMilestoneIds?: readonly string[];
  artifactIds?: readonly string[];
  verifiedWorkerResultIds?: readonly string[];
  uncertainty?: number;
  planVersion?: number;
  strategyFingerprint?: string;
  planChangeReason?: string;
  successCriteria?: Readonly<Record<string, number>>;
}

export const PROGRESS_DIMENSIONS = [
  "step_advanced",
  "evidence_added",
  "finding_strengthened",
  "entity_discovered",
  "dependency_resolved",
  "decision_resolved",
  "contract_milestone",
  "artifact_produced",
  "worker_result_verified",
  "uncertainty_reduced",
  "plan_materially_changed",
  "success_criterion_advanced",
] as const;
export type ProgressDimension = (typeof PROGRESS_DIMENSIONS)[number];

export interface ProgressEvaluation {
  meaningful: boolean;
  dimensions: readonly ProgressDimension[];
  summary: string;
  beforeSignature: string;
  afterSignature: string;
}

function unique(values: readonly string[] | undefined): readonly string[] {
  return [...new Set(values ?? [])].sort();
}

function hasAddition(before: readonly string[] | undefined, after: readonly string[] | undefined): boolean {
  const existing = new Set(before ?? []);
  return (after ?? []).some((value) => !existing.has(value));
}

function progressedStep(before: SupervisedStepState | undefined, after: SupervisedStepState): boolean {
  if (before === after) return false;
  if (after === "completed" || after === "skipped") return true;
  return (before === undefined || before === "pending") && after === "running";
}

export function progressSignature(snapshot: Readonly<ProgressSnapshot>): string {
  const canonical = stableSerialize({
    stepStates: snapshot.stepStates ?? {},
    evidenceIds: unique(snapshot.evidenceIds),
    findingProgress: snapshot.findingProgress ?? {},
    discoveredEntityIds: unique(snapshot.discoveredEntityIds),
    resolvedDependencyIds: unique(snapshot.resolvedDependencyIds),
    resolvedDecisionIds: unique(snapshot.resolvedDecisionIds),
    contractMilestoneIds: unique(snapshot.contractMilestoneIds),
    artifactIds: unique(snapshot.artifactIds),
    verifiedWorkerResultIds: unique(snapshot.verifiedWorkerResultIds),
    uncertainty: snapshot.uncertainty,
    planVersion: snapshot.planVersion,
    strategyFingerprint: snapshot.strategyFingerprint,
    successCriteria: snapshot.successCriteria ?? {},
  });
  return createHash("sha256").update(canonical).digest("hex");
}

export function evaluateProgress(
  before: Readonly<ProgressSnapshot>,
  after: Readonly<ProgressSnapshot>,
): ProgressEvaluation {
  const dimensions: ProgressDimension[] = [];
  if (
    Object.entries(after.stepStates ?? {}).some(([id, state]) =>
      progressedStep(before.stepStates?.[id], state),
    )
  ) dimensions.push("step_advanced");
  if (hasAddition(before.evidenceIds, after.evidenceIds)) dimensions.push("evidence_added");
  if (
    Object.entries(after.findingProgress ?? {}).some(([id, current]) => {
      const prior = before.findingProgress?.[id];
      return !prior || current.confidence > prior.confidence || current.evidenceCount > prior.evidenceCount;
    })
  ) dimensions.push("finding_strengthened");
  if (hasAddition(before.discoveredEntityIds, after.discoveredEntityIds)) dimensions.push("entity_discovered");
  if (hasAddition(before.resolvedDependencyIds, after.resolvedDependencyIds)) dimensions.push("dependency_resolved");
  if (hasAddition(before.resolvedDecisionIds, after.resolvedDecisionIds)) dimensions.push("decision_resolved");
  if (hasAddition(before.contractMilestoneIds, after.contractMilestoneIds)) dimensions.push("contract_milestone");
  if (hasAddition(before.artifactIds, after.artifactIds)) dimensions.push("artifact_produced");
  if (hasAddition(before.verifiedWorkerResultIds, after.verifiedWorkerResultIds)) {
    dimensions.push("worker_result_verified");
  }
  if (
    typeof before.uncertainty === "number" &&
    typeof after.uncertainty === "number" &&
    after.uncertainty < before.uncertainty
  ) dimensions.push("uncertainty_reduced");
  if (
    typeof after.planVersion === "number" &&
    after.planVersion > (before.planVersion ?? -1) &&
    Boolean(after.planChangeReason?.trim()) &&
    Boolean(after.strategyFingerprint) &&
    after.strategyFingerprint !== before.strategyFingerprint
  ) dimensions.push("plan_materially_changed");
  if (
    Object.entries(after.successCriteria ?? {}).some(
      ([id, value]) => Number.isFinite(value) && value > (before.successCriteria?.[id] ?? 0),
    )
  ) dimensions.push("success_criterion_advanced");

  return {
    meaningful: dimensions.length > 0,
    dimensions,
    summary: dimensions.length > 0 ? dimensions.join(", ") : "No meaningful progress detected",
    beforeSignature: progressSignature(before),
    afterSignature: progressSignature(after),
  };
}
