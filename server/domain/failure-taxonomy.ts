export const FAILURE_CATEGORY_IDS = [
  "transient_network",
  "provider_rate_limited",
  "provider_unavailable",
  "provider_refused",
  "mcp_unavailable",
  "timeout",
  "worker_heartbeat_lost",
  "process_crash",
  "target_unreachable",
  "missing_credential",
  "missing_dependency",
  "observe_only_enforcement_mismatch",
  "scope_policy_denial",
  "authorization_denied",
  "guided_decision_missing",
  "tool_deterministic_error",
  "invalid_input",
  "plan_dependency_unresolved",
  "insufficient_evidence",
  "repeated_no_progress_loop",
  "budget_exhausted",
  "restart_recovery_required",
  "migration_data_integrity",
  "operator_rejection",
  "cancelled",
  "unknown",
] as const;

export type FailureCategoryId = (typeof FAILURE_CATEGORY_IDS)[number];
export type RetryPolicyKind = "bounded_transient" | "never_automatic";

export type RecoveryActionId =
  | "test_connection"
  | "configure_dependency"
  | "configure_credential"
  | "use_compatible_fallback"
  | "retry_bounded"
  | "resume_checkpoint"
  | "reassign"
  | "amend_plan"
  | "skip_step"
  | "start_new_run"
  | "terminate_gracefully"
  | "review_scope"
  | "supply_guided_decision"
  | "reconcile_data";

export interface FailureCategoryDefinition {
  readonly id: FailureCategoryId;
  readonly label: string;
  readonly defaultHumanReason: string;
  readonly transient: boolean;
  readonly retryPolicy: RetryPolicyKind;
  readonly recommendedRecoveryActions: readonly RecoveryActionId[];
}

const failure = (
  id: FailureCategoryId,
  label: string,
  defaultHumanReason: string,
  transient: boolean,
  recommendedRecoveryActions: readonly RecoveryActionId[],
): FailureCategoryDefinition => ({
  id,
  label,
  defaultHumanReason,
  transient,
  retryPolicy: transient ? "bounded_transient" : "never_automatic",
  recommendedRecoveryActions,
});

export const FAILURE_CATEGORY_DEFINITIONS: readonly FailureCategoryDefinition[] = [
  failure(
    "transient_network",
    "Transient network failure",
    "A temporary network failure interrupted the action.",
    true,
    ["test_connection", "retry_bounded", "use_compatible_fallback"],
  ),
  failure(
    "provider_rate_limited",
    "Provider rate limited",
    "The provider rejected the call because its current rate limit was reached.",
    true,
    ["retry_bounded", "use_compatible_fallback"],
  ),
  failure(
    "provider_unavailable",
    "Provider unavailable",
    "The configured model provider is temporarily unavailable.",
    true,
    ["test_connection", "retry_bounded", "use_compatible_fallback"],
  ),
  failure(
    "provider_refused",
    "Provider refused the request",
    "The provider refused this request and an identical retry is not justified.",
    false,
    ["use_compatible_fallback", "amend_plan", "terminate_gracefully"],
  ),
  failure(
    "mcp_unavailable",
    "MCP server unavailable",
    "A required MCP server or capability is temporarily unavailable.",
    true,
    ["test_connection", "retry_bounded", "use_compatible_fallback"],
  ),
  failure(
    "timeout",
    "Action timed out",
    "The action exceeded its type-specific deadline without a terminal result.",
    true,
    ["retry_bounded", "resume_checkpoint", "amend_plan"],
  ),
  failure(
    "worker_heartbeat_lost",
    "Worker heartbeat lost",
    "The assigned worker stopped reporting a valid heartbeat.",
    true,
    ["resume_checkpoint", "reassign", "terminate_gracefully"],
  ),
  failure(
    "process_crash",
    "Worker process crashed",
    "The worker process ended before it persisted a terminal action result.",
    true,
    ["resume_checkpoint", "reassign", "terminate_gracefully"],
  ),
  failure(
    "target_unreachable",
    "Target unreachable",
    "The supplied target could not be reached from the current execution context.",
    true,
    ["test_connection", "retry_bounded", "amend_plan"],
  ),
  failure(
    "missing_credential",
    "Credential missing",
    "A required credential is not configured for this exact authorized use.",
    false,
    ["configure_credential", "amend_plan", "terminate_gracefully"],
  ),
  failure(
    "missing_dependency",
    "Dependency missing",
    "A deterministic required dependency is absent or not configured.",
    false,
    ["configure_dependency", "use_compatible_fallback", "amend_plan"],
  ),
  failure(
    "observe_only_enforcement_mismatch",
    "Executor cannot enforce policy",
    "The selected provider path can observe or advise but cannot enforce this action contract.",
    false,
    ["use_compatible_fallback", "reassign", "amend_plan"],
  ),
  failure(
    "scope_policy_denial",
    "Scope or policy denied the action",
    "The action conflicts with normalized mission scope or an action policy.",
    false,
    ["review_scope", "amend_plan", "terminate_gracefully"],
  ),
  failure(
    "authorization_denied",
    "Authorization could not be verified",
    "The runtime could not verify authorization for the represented action.",
    false,
    ["review_scope", "terminate_gracefully"],
  ),
  failure(
    "guided_decision_missing",
    "Guided decision required",
    "The Guided run needs the operator's explicit decision for the represented step.",
    false,
    ["supply_guided_decision", "skip_step", "terminate_gracefully"],
  ),
  failure(
    "tool_deterministic_error",
    "Tool returned a deterministic error",
    "The tool rejected the same normalized input for a deterministic reason.",
    false,
    ["configure_dependency", "amend_plan", "use_compatible_fallback"],
  ),
  failure(
    "invalid_input",
    "Input did not satisfy the tool contract",
    "The normalized input is invalid and must change before another attempt.",
    false,
    ["amend_plan", "skip_step"],
  ),
  failure(
    "plan_dependency_unresolved",
    "Plan dependency unresolved",
    "A required predecessor or prerequisite has not reached the required state.",
    false,
    ["amend_plan", "skip_step", "start_new_run"],
  ),
  failure(
    "insufficient_evidence",
    "Evidence is insufficient",
    "The available observations do not safely support the requested conclusion or next action.",
    false,
    ["amend_plan", "skip_step", "terminate_gracefully"],
  ),
  failure(
    "repeated_no_progress_loop",
    "Repeated action made no progress",
    "The supervisor detected bounded repeated work without a meaningful evidence or state delta.",
    false,
    ["resume_checkpoint", "reassign", "amend_plan", "terminate_gracefully"],
  ),
  failure(
    "budget_exhausted",
    "Mission budget exhausted",
    "The run reached a signed time, cost, token, retry, storage, or concurrency budget.",
    false,
    ["start_new_run", "terminate_gracefully"],
  ),
  failure(
    "restart_recovery_required",
    "Restart recovery required",
    "A recovered in-flight action cannot be safely duplicated without checkpoint review.",
    false,
    ["resume_checkpoint", "start_new_run", "terminate_gracefully"],
  ),
  failure(
    "migration_data_integrity",
    "Migration data integrity failure",
    "Imported or migrated records failed a provenance, relationship, or integrity check.",
    false,
    ["reconcile_data", "terminate_gracefully"],
  ),
  failure(
    "operator_rejection",
    "Operator rejected the Guided action",
    "The operator deliberately rejected this represented Guided action.",
    false,
    ["amend_plan", "skip_step", "terminate_gracefully"],
  ),
  failure(
    "cancelled",
    "Action cancelled",
    "The operator or runtime requested cooperative cancellation.",
    false,
    ["resume_checkpoint", "start_new_run", "terminate_gracefully"],
  ),
  failure(
    "unknown",
    "Unclassified failure",
    "The runtime preserved an error that has not yet been classified.",
    false,
    ["resume_checkpoint", "amend_plan", "terminate_gracefully"],
  ),
] as const;

export interface FailureCodeManifest {
  readonly component: string;
  readonly code: string;
  readonly categoryId: FailureCategoryId;
}

export interface FailureTaxonomy {
  readonly categories: Readonly<Record<FailureCategoryId, FailureCategoryDefinition>>;
  readonly codeMappings: Readonly<Record<string, FailureCategoryId>>;
}

export function buildFailureTaxonomy(
  codeManifests: readonly FailureCodeManifest[] = [],
): FailureTaxonomy {
  const categories = Object.fromEntries(
    FAILURE_CATEGORY_DEFINITIONS.map((definition) => [definition.id, definition]),
  ) as Record<FailureCategoryId, FailureCategoryDefinition>;
  const codeMappings: Record<string, FailureCategoryId> = {};
  for (const mapping of codeManifests) {
    const key = `${mapping.component}:${mapping.code}`;
    if (codeMappings[key] !== undefined) {
      throw new Error(`Duplicate failure-code mapping ${key}.`);
    }
    codeMappings[key] = mapping.categoryId;
  }
  return { categories, codeMappings };
}

export interface FailureDiagnosis {
  readonly id: string;
  readonly categoryId: FailureCategoryId;
  readonly machineCode: string;
  readonly humanReason: string;
  readonly originatingComponent: string;
  readonly failedObjectType: "mission" | "run" | "step" | "assignment" | "action" | "attack_attempt";
  readonly failedObjectId: string;
  readonly lastSuccessfulEventId?: string;
  readonly rawErrorReferenceId?: string;
  readonly retryHistoryActionIds: readonly string[];
  readonly progressBeforeFailure: string;
  readonly preservedEvidenceIds: readonly string[];
  readonly preservedArtifactIds: readonly string[];
  readonly automaticRecoveryAttemptIds: readonly string[];
  readonly retryable: boolean;
  readonly recommendedRecoveryActions: readonly RecoveryActionId[];
  readonly objectiveImpact: string;
}

export interface ClassifyFailureInput {
  readonly id: string;
  readonly component: string;
  readonly code: string;
  readonly humanReason?: string;
  readonly failedObjectType: FailureDiagnosis["failedObjectType"];
  readonly failedObjectId: string;
  readonly lastSuccessfulEventId?: string;
  readonly rawErrorReferenceId?: string;
  readonly retryHistoryActionIds?: readonly string[];
  readonly progressBeforeFailure?: string;
  readonly preservedEvidenceIds?: readonly string[];
  readonly preservedArtifactIds?: readonly string[];
  readonly automaticRecoveryAttemptIds?: readonly string[];
  readonly objectiveImpact?: string;
}

export function classifyFailure(
  taxonomy: FailureTaxonomy,
  input: ClassifyFailureInput,
): FailureDiagnosis {
  const categoryId = taxonomy.codeMappings[`${input.component}:${input.code}`] ?? "unknown";
  const category = taxonomy.categories[categoryId];
  const diagnosis: FailureDiagnosis = {
    id: input.id,
    categoryId,
    machineCode: input.code,
    humanReason: input.humanReason?.trim() || category.defaultHumanReason,
    originatingComponent: input.component,
    failedObjectType: input.failedObjectType,
    failedObjectId: input.failedObjectId,
    retryHistoryActionIds: input.retryHistoryActionIds ?? [],
    progressBeforeFailure: input.progressBeforeFailure ?? "No meaningful progress was recorded.",
    preservedEvidenceIds: input.preservedEvidenceIds ?? [],
    preservedArtifactIds: input.preservedArtifactIds ?? [],
    automaticRecoveryAttemptIds: input.automaticRecoveryAttemptIds ?? [],
    retryable: category.retryPolicy === "bounded_transient",
    recommendedRecoveryActions: category.recommendedRecoveryActions,
    objectiveImpact: input.objectiveImpact ?? "Impact has not yet been evaluated.",
    ...(input.lastSuccessfulEventId === undefined
      ? {}
      : { lastSuccessfulEventId: input.lastSuccessfulEventId }),
    ...(input.rawErrorReferenceId === undefined
      ? {}
      : { rawErrorReferenceId: input.rawErrorReferenceId }),
  };
  return diagnosis;
}

if (FAILURE_CATEGORY_DEFINITIONS.length !== FAILURE_CATEGORY_IDS.length) {
  throw new Error("Every canonical failure category must have exactly one definition.");
}
