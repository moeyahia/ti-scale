import type {
  ExecutionReadiness,
  GuidedExecutionReadiness,
  RuntimeReadinessSnapshot,
} from "./types/runtimeReadiness";

export type GuidedManualResultHandling =
  | "unavailable"
  | "ingestion_only"
  | "semantic_interpretation";

/**
 * Maps the process attestation to the exact Guided controls the browser may
 * expose. `manual_only` is intentionally useful without implying that a
 * provider or tool executor is attached.
 */
export interface GuidedRuntimeCapabilities {
  readonly mode: GuidedExecutionReadiness;
  readonly manualOnly: boolean;
  readonly decisionMutations: boolean;
  readonly manualResultHandling: GuidedManualResultHandling;
  readonly manualResultReview: boolean;
  readonly manualResultCompletion: boolean;
  /** Locally generated, exact-step explanation with no provider or execution authority. */
  readonly localCommanderGuidance: boolean;
  /** Provider-backed semantic guidance; independent from local deterministic explanations. */
  readonly providerGuidance: boolean;
  readonly memoryCandidateActions: boolean;
  readonly toolDispatch: boolean;
}

export function guidedRuntimeCapabilities(
  readiness: RuntimeReadinessSnapshot | undefined,
): GuidedRuntimeCapabilities {
  const mode = readiness?.execution.guided ?? "unavailable";
  const guidedToolExecution: ExecutionReadiness = readiness?.execution.guidedToolExecution
    ?? "unavailable";
  const boundaryAvailable = mode !== "unavailable";
  const providerAvailable = boundaryAvailable
    && (readiness?.dependencies.providers.guidedCapable ?? 0) > 0;
  const localCommanderGuidance = boundaryAvailable
    && readiness?.execution.localCommanderGuidance === "ready";
  const memoryStoreAvailable = boundaryAvailable
    && readiness?.dependencies.secondBrain.canonicalStoreAvailable === true
    && readiness.dependencies.secondBrain.status !== "unhealthy"
    && readiness.dependencies.secondBrain.status !== "unknown";
  const manualResultHandling: GuidedManualResultHandling = !boundaryAvailable
    ? "unavailable"
    : providerAvailable
      ? "semantic_interpretation"
      : "ingestion_only";
  return {
    mode,
    manualOnly: mode === "manual_only",
    decisionMutations: boundaryAvailable,
    manualResultHandling,
    manualResultReview: boundaryAvailable,
    // A local manual-only process can attest bounded ingestion metadata, but
    // it has no semantic interpreter capable of supporting exact-step
    // completion. Only fully ready Guided runtime paths expose that mutation.
    manualResultCompletion: providerAvailable,
    localCommanderGuidance,
    providerGuidance: providerAvailable,
    // Candidate creation is a local Second Brain mutation. It must not be
    // inferred from provider readiness, but it still fails closed unless the
    // canonical memory store is explicitly attested by this process.
    memoryCandidateActions: memoryStoreAvailable,
    // Exact reviewed local-process dispatch is independently attested. A
    // provider-free Guided runtime can therefore execute the represented
    // local step without pretending a Commander provider exists.
    toolDispatch: mode === "ready" && guidedToolExecution === "ready",
  };
}
