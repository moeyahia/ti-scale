export type MutationMethod = "POST" | "PUT" | "PATCH" | "DELETE";

export type MutationAuthorityClass =
  | "mission_run_control_plane"
  | "global_administration"
  | "authenticated_user_owned"
  | "public_or_health";

export type ControlPlaneEnforcement =
  | "lease_fenced"
  | "ownership_fenced"
  | "pre_creation_boundary"
  | "read_only_import_compatible"
  | "fail_closed_when_runtime_unavailable"
  | "policy_scoped_gap"
  | "not_applicable";

export interface MutationAuthorityRecord {
  readonly method: MutationMethod;
  readonly path: string;
  readonly authorityClass: MutationAuthorityClass;
  readonly owningService: string;
  readonly implementationSources: readonly string[];
  /** Process-level auth applies before every protected /api/v2 router. */
  readonly authentication:
    | "operator_session_or_bearer_required"
    | "local_operator_token_exchange"
    | "optional_session_termination";
  /** Bearer requests do not use cookies; cookie-session mutations require the double-submit proof. */
  readonly csrf: "cookie_session_required" | "conditional_when_session_present" | "not_applicable";
  readonly idempotency: "required" | "not_required_read_like" | "not_required_session_lifecycle";
  readonly optimisticConcurrency: "required" | "represented_boundary" | "not_applicable";
  readonly controlPlaneEnforcement: ControlPlaneEnforcement;
  readonly notes?: string;
}

type ProtectedRecord = Omit<
  MutationAuthorityRecord,
  "authentication" | "csrf" | "authorityClass" | "controlPlaneEnforcement"
> & {
  readonly authorityClass?: Exclude<MutationAuthorityClass, "public_or_health">;
  readonly controlPlaneEnforcement?: ControlPlaneEnforcement;
};

const protectedMutation = (record: ProtectedRecord): MutationAuthorityRecord => ({
  authentication: "operator_session_or_bearer_required",
  csrf: "cookie_session_required",
  authorityClass: record.authorityClass ?? "authenticated_user_owned",
  controlPlaneEnforcement: record.controlPlaneEnforcement ?? "not_applicable",
  ...record,
});

const missionMutation = (
  record: Omit<ProtectedRecord, "authorityClass"> & { readonly controlPlaneEnforcement: ControlPlaneEnforcement },
): MutationAuthorityRecord => protectedMutation({
  ...record,
  authorityClass: "mission_run_control_plane",
});

const globalMutation = (
  record: Omit<ProtectedRecord, "authorityClass" | "controlPlaneEnforcement">,
): MutationAuthorityRecord => protectedMutation({
  ...record,
  authorityClass: "global_administration",
  controlPlaneEnforcement: "not_applicable",
});

const source = {
  auth: ["server/auth/LocalSessionRouter.ts"],
  brain: ["server/memory/SecondBrainRouter.ts"],
  commanderProvider: [
    "server/guided-commander/GuidedCommanderRouter.ts",
    "server/routes/UnavailableExecutionRouter.ts",
  ],
  commanderMemory: ["server/guided-commander/GuidedMemoryCandidateRouter.ts"],
  decisionRuntime: [
    "server/routes/missionRuntimeV2Routes.ts",
    "server/routes/UnavailableExecutionRouter.ts",
  ],
  runRuntime: [
    "server/routes/missionRuntimeV2Routes.ts",
    "server/routes/UnavailableExecutionRouter.ts",
  ],
  command: ["server/routes/commandOsRoutes.ts"],
  operationalTruth: ["server/intelligence-v24/OperationalTruthRouter.ts"],
  runIntelligence: ["server/run-intelligence/RunIntelligenceRouter.ts"],
  cve: ["server/cve-intelligence/CveApplicabilityRouter.ts"],
  pageCapture: ["server/page-captures/PageCaptureRouter.ts"],
  script: ["server/script-artifacts/ScriptArtifactRouter.ts"],
  plan: ["server/plan-changes/PlanChangeRouter.ts"],
  operations: ["server/routes/operationsRoutes.ts"],
  notification: ["server/notifications/NotificationRouter.ts"],
  research: ["server/research/ResearchLabRouter.ts"],
} as const;

/**
 * Canonical mutation-authority inventory for every Express POST/PUT/PATCH/DELETE
 * declaration under /api/v2. This is data, not middleware: the static CI guard
 * compares it with source declarations and fails closed on additions, missing
 * classifications, or undeclared alternative implementations.
 */
export const V2_MUTATION_AUTHORITY_INVENTORY = [
  {
    method: "POST", path: "/api/v2/auth/session", authorityClass: "public_or_health",
    owningService: "LocalSessionAuth", implementationSources: source.auth,
    authentication: "local_operator_token_exchange", csrf: "not_applicable",
    idempotency: "not_required_session_lifecycle", optimisticConcurrency: "not_applicable",
    controlPlaneEnforcement: "not_applicable",
    notes: "The route is public only as a credential exchange; it validates the configured local operator token before issuing cookies.",
  },
  {
    method: "DELETE", path: "/api/v2/auth/session", authorityClass: "public_or_health",
    owningService: "LocalSessionAuth", implementationSources: source.auth,
    authentication: "optional_session_termination", csrf: "conditional_when_session_present",
    idempotency: "not_required_session_lifecycle", optimisticConcurrency: "not_applicable",
    controlPlaneEnforcement: "not_applicable",
  },

  protectedMutation({ method: "POST", path: "/api/v2/registries/intake/resolve", owningService: "MissionIntakeService", implementationSources: source.command, idempotency: "not_required_read_like", optimisticConcurrency: "not_applicable" }),
  protectedMutation({ method: "POST", path: "/api/v2/missions/saved-views", owningService: "MissionPortfolioService", implementationSources: source.command, idempotency: "required", optimisticConcurrency: "required" }),
  protectedMutation({ method: "DELETE", path: "/api/v2/missions/saved-views/:viewId", owningService: "MissionPortfolioService", implementationSources: source.command, idempotency: "required", optimisticConcurrency: "required" }),
  protectedMutation({ method: "POST", path: "/api/v2/notifications/:notificationId/read", owningService: "NotificationRepository", implementationSources: source.notification, idempotency: "required", optimisticConcurrency: "not_applicable" }),
  protectedMutation({ method: "POST", path: "/api/v2/notifications/read-all", owningService: "NotificationRepository", implementationSources: source.notification, idempotency: "required", optimisticConcurrency: "not_applicable" }),

  protectedMutation({ method: "PUT", path: "/api/v2/brain/control", owningService: "MemoryControlPolicy", implementationSources: source.brain, idempotency: "required", optimisticConcurrency: "required" }),
  protectedMutation({ method: "POST", path: "/api/v2/brain/candidates/:candidateId/confirm", owningService: "SecondBrainService", implementationSources: source.brain, idempotency: "required", optimisticConcurrency: "not_applicable" }),
  protectedMutation({ method: "POST", path: "/api/v2/brain/candidates/:candidateId/reject", owningService: "SecondBrainService", implementationSources: source.brain, idempotency: "required", optimisticConcurrency: "not_applicable" }),
  ...["correct", "dispute", "pin", "expire", "forget"].map((action): MutationAuthorityRecord => protectedMutation({
    method: "POST", path: `/api/v2/brain/nodes/:nodeId/${action}`,
    owningService: action === "forget" ? "SecondBrainService/ObsidianVaultBridge" : "MemoryRepository",
    implementationSources: source.brain, idempotency: "required", optimisticConcurrency: "required",
  })),
  ...["health-check", "connect", "export", "import", "sync", "portable-export"].map((action): MutationAuthorityRecord => protectedMutation({
    method: "POST", path: `/api/v2/brain/vault/${action}`,
    owningService: "ObsidianVaultBridge", implementationSources: source.brain,
    idempotency: "required", optimisticConcurrency: "represented_boundary",
  })),
  ...["repair", "reindex"].map((action): MutationAuthorityRecord => globalMutation({
    method: "POST", path: `/api/v2/brain/vault/${action}`,
    owningService: "VaultRecoveryService/VaultRecoveryRepository",
    implementationSources: source.brain,
    idempotency: "required",
    optimisticConcurrency: "required",
    notes: "Requires workspace-wide Second Brain authority, an explicit ti_scale control-plane assertion, and the exact current Vault connection version.",
  })),
  protectedMutation({ method: "POST", path: "/api/v2/brain/vault/conflicts/:conflictId/resolve", owningService: "ObsidianVaultBridge", implementationSources: source.brain, idempotency: "required", optimisticConcurrency: "represented_boundary" }),

  globalMutation({ method: "POST", path: "/api/v2/administrative-approvals/:approvalId/review", owningService: "DecisionInboxRepository", implementationSources: source.operations, idempotency: "required", optimisticConcurrency: "represented_boundary" }),
  globalMutation({ method: "POST", path: "/api/v2/intelligence/findings/:findingId/review", owningService: "OperationsReviewRepository", implementationSources: source.operations, idempotency: "required", optimisticConcurrency: "required" }),
  globalMutation({ method: "POST", path: "/api/v2/learning/lessons/:lessonId/review", owningService: "OperationsReviewRepository", implementationSources: source.operations, idempotency: "required", optimisticConcurrency: "required" }),
  globalMutation({ method: "POST", path: "/api/v2/research/campaigns", owningService: "ResearchLabRepository", implementationSources: source.research, idempotency: "required", optimisticConcurrency: "not_applicable" }),
  globalMutation({ method: "POST", path: "/api/v2/research/campaigns/:campaignId/stop", owningService: "ResearchLabRepository", implementationSources: source.research, idempotency: "required", optimisticConcurrency: "required" }),

  missionMutation({ method: "POST", path: "/api/v2/missions", owningService: "MissionService", implementationSources: source.command, idempotency: "required", optimisticConcurrency: "not_applicable", controlPlaneEnforcement: "pre_creation_boundary" }),
  missionMutation({ method: "POST", path: "/api/v2/missions/autonomous/preflight", owningService: "MissionService", implementationSources: source.command, idempotency: "not_required_read_like", optimisticConcurrency: "not_applicable", controlPlaneEnforcement: "pre_creation_boundary" }),
  missionMutation({ method: "POST", path: "/api/v2/missions/:missionId/autonomous-branches/preflight", owningService: "AutonomousBranchService", implementationSources: source.command, idempotency: "required", optimisticConcurrency: "required", controlPlaneEnforcement: "lease_fenced", notes: "The source run is V2-owned and lease-proven before replay; authority, source version, and contract lineage are rechecked inside the atomic draft transaction after readiness." }),
  missionMutation({ method: "POST", path: "/api/v2/missions/:missionId/autonomous-branches", owningService: "AutonomousBranchService", implementationSources: source.command, idempotency: "required", optimisticConcurrency: "required", controlPlaneEnforcement: "lease_fenced", notes: "The source run is V2-owned and lease-proven before replay, then rechecked with source version and contract lineage inside the atomic branch transaction." }),
  missionMutation({ method: "POST", path: "/api/v2/missions/bulk/archive", owningService: "MissionPortfolioService", implementationSources: source.command, idempotency: "required", optimisticConcurrency: "represented_boundary", controlPlaneEnforcement: "lease_fenced", notes: "Every selected mission resolves to an exact latest V2 run; all lease proofs and the complete mission/run set are rechecked atomically before replay or archive." }),
  missionMutation({ method: "POST", path: "/api/v2/missions/bulk/export", owningService: "MissionPortfolioService", implementationSources: source.command, idempotency: "required", optimisticConcurrency: "not_applicable", controlPlaneEnforcement: "read_only_import_compatible", notes: "Read-like metadata export uses POST for an explicit, audited selection and may deliberately include imported read-only missions." }),

  ...["explain-more", "show-next-step", "interpret-result", "use-another-approach"].map((action): MutationAuthorityRecord => missionMutation({
    method: "POST", path: `/api/v2/guided/:missionId/commander/${action}`,
    owningService: "GuidedCommanderService", implementationSources: source.commanderProvider,
    idempotency: "required", optimisticConcurrency: "represented_boundary",
    controlPlaneEnforcement: "lease_fenced",
    notes: "The active provider boundary requires a trusted server-held run lease before replay/reservation and rechecks its proof inside provider-reservation completion; the unavailable preview implementation remains fail-closed.",
  })),
  ...["remember", "do-not-remember"].map((action): MutationAuthorityRecord => missionMutation({
    method: "POST", path: `/api/v2/guided/:missionId/commander/${action}`,
    owningService: "GuidedCommanderService/SecondBrainService",
    implementationSources: source.commanderMemory,
    idempotency: "required", optimisticConcurrency: "represented_boundary",
    controlPlaneEnforcement: "lease_fenced",
    notes: "The local-only boundary enforces exact represented mission/run/step scope, requires current server-held run authority before replay, and rechecks the proof inside its idempotent candidate/suppression transaction.",
  })),
  ...["approve", "reject", "manual-result", "skip", "stop"].map((action): MutationAuthorityRecord => missionMutation({
    method: "POST", path: `/api/v2/guided-decisions/:decisionId/${action}`,
    owningService: "MissionRuntimeEngine", implementationSources: source.decisionRuntime,
    idempotency: "required", optimisticConcurrency: "represented_boundary",
    controlPlaneEnforcement: "lease_fenced",
  })),
  ...["pause", "resume", "cancel"].map((action): MutationAuthorityRecord => missionMutation({
    method: "POST", path: `/api/v2/runs/:runId/${action}`,
    owningService: "MissionRuntimeEngine", implementationSources: source.runRuntime,
    idempotency: "required", optimisticConcurrency: "represented_boundary",
    controlPlaneEnforcement: "lease_fenced",
  })),

  ...["logs", "observations", "evidence-candidates"].map((resource): MutationAuthorityRecord => missionMutation({
    method: "POST", path: `/api/v2/operational-truth/missions/:missionId/${resource}`,
    owningService: "OperationalTruthService", implementationSources: source.operationalTruth,
    idempotency: "required", optimisticConcurrency: "not_applicable",
    controlPlaneEnforcement: "lease_fenced",
    notes: "Operational-truth ingestion requires a canonical V2-owned run and a current trusted runtime lease before replay lookup, then rechecks that authority inside the atomic mutation/receipt transaction. Mission-only imported records remain read-only.",
  })),
  ...["promote", "reject", "demote", "verify"].map((action): MutationAuthorityRecord => missionMutation({
    method: "POST", path: `/api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId/${action}`,
    owningService: "OperationalTruthService", implementationSources: source.operationalTruth,
    idempotency: "required", optimisticConcurrency: "represented_boundary",
    controlPlaneEnforcement: "lease_fenced",
    notes: "Evidence-candidate review resolves the candidate's canonical V2 run, requires current trusted lease authority before replay, and rechecks it inside the atomic mutation/receipt transaction. Imported candidates without a canonical run remain read-only.",
  })),
  missionMutation({ method: "POST", path: "/api/v2/operational-truth/missions/:missionId/findings/:findingId/verify", owningService: "OperationalTruthService", implementationSources: source.operationalTruth, idempotency: "required", optimisticConcurrency: "represented_boundary", controlPlaneEnforcement: "lease_fenced", notes: "Finding verification resolves the finding's canonical V2 run and requires current trusted runtime lease authority before replay and inside the atomic verification/receipt transaction." }),
  missionMutation({ method: "POST", path: "/api/v2/operational-truth/missions/:missionId/runs/:runId/failure-diagnoses", owningService: "FailureDiagnosisService", implementationSources: source.operationalTruth, idempotency: "required", optimisticConcurrency: "not_applicable", controlPlaneEnforcement: "lease_fenced", notes: "Failure diagnosis creation is fenced to the route's canonical V2-owned run before replay and rechecked inside the atomic mutation/receipt transaction." }),
  missionMutation({ method: "POST", path: "/api/v2/operational-truth/missions/:missionId/runs/:runId/failure-diagnoses/:diagnosisId/resolve", owningService: "FailureDiagnosisService", implementationSources: source.operationalTruth, idempotency: "required", optimisticConcurrency: "represented_boundary", controlPlaneEnforcement: "lease_fenced", notes: "Failure diagnosis resolution is fenced to the diagnosis's canonical V2-owned run before replay and rechecked inside the atomic mutation/receipt transaction." }),

  missionMutation({
    method: "POST", path: "/api/v2/missions/:missionId/intelligence/cves",
    owningService: "CveApplicabilityService", implementationSources: source.cve,
    idempotency: "required", optimisticConcurrency: "represented_boundary",
    controlPlaneEnforcement: "lease_fenced",
    notes: "CVE applicability mutation requires an explicit canonical V2 run and current trusted runtime lease before replay, then rechecks the same controller acquisition inside the atomic mutation/receipt transaction. Mission-only and imported legacy CVE intelligence remains read-only.",
  }),
  missionMutation({ method: "POST", path: "/api/v2/missions/:missionId/intelligence/page-captures", owningService: "PageCaptureService", implementationSources: source.pageCapture, idempotency: "required", optimisticConcurrency: "not_applicable", controlPlaneEnforcement: "ownership_fenced" }),
  ...["nodes", "edges"].map((resource): MutationAuthorityRecord => missionMutation({
    method: "POST", path: `/api/v2/missions/:missionId/intelligence/topology/${resource}`,
    owningService: "ReconDigitalTwinService", implementationSources: source.runIntelligence,
    idempotency: "required", optimisticConcurrency: "not_applicable",
    controlPlaneEnforcement: "lease_fenced",
    notes: resource === "nodes"
      ? "Topology node creation requires an explicit canonical V2 run and current trusted runtime lease before replay, then rechecks it inside the atomic mutation/receipt transaction. Mission-only and imported topology remains read-only."
      : "Topology edge creation derives one canonical V2 run from both immutable endpoints, rejects mission-only or cross-run endpoints, requires current trusted runtime lease before replay, and rechecks it inside the atomic mutation/receipt transaction.",
  })),
  missionMutation({
    method: "POST", path: "/api/v2/missions/:missionId/intelligence/topology/assets/:assetNodeId/osi",
    owningService: "ReconDigitalTwinService", implementationSources: source.runIntelligence,
    idempotency: "required", optimisticConcurrency: "not_applicable",
    controlPlaneEnforcement: "lease_fenced",
    notes: "OSI observation creation derives the canonical V2 run from the selected asset, requires current trusted runtime lease before replay, and rechecks it inside the atomic mutation/receipt transaction. Mission-only and imported asset stacks remain read-only.",
  }),
  missionMutation({ method: "POST", path: "/api/v2/missions/:missionId/script-artifacts", owningService: "ScriptArtifactService", implementationSources: source.script, idempotency: "required", optimisticConcurrency: "not_applicable", controlPlaneEnforcement: "ownership_fenced" }),
  missionMutation({ method: "POST", path: "/api/v2/missions/:missionId/script-artifacts/:scriptArtifactId/versions", owningService: "ScriptArtifactService", implementationSources: source.script, idempotency: "required", optimisticConcurrency: "represented_boundary", controlPlaneEnforcement: "ownership_fenced" }),

  missionMutation({
    method: "POST", path: "/api/v2/runs/:runId/intelligence/metrics/recompute",
    owningService: "RunMetricsService", implementationSources: source.runIntelligence,
    idempotency: "required", optimisticConcurrency: "not_applicable",
    controlPlaneEnforcement: "ownership_fenced",
    notes: "Deterministic derived-state recomputation requires V2 mission/run ownership but deliberately does not block behind an execution lease.",
  }),
  missionMutation({ method: "POST", path: "/api/v2/runs/:runId/intelligence/attack-attempts", owningService: "AttackAttemptService", implementationSources: source.runIntelligence, idempotency: "required", optimisticConcurrency: "not_applicable", controlPlaneEnforcement: "lease_fenced" }),
  missionMutation({ method: "POST", path: "/api/v2/runs/:runId/intelligence/attack-attempts/:attemptId/transition", owningService: "AttackAttemptService", implementationSources: source.runIntelligence, idempotency: "required", optimisticConcurrency: "required", controlPlaneEnforcement: "lease_fenced" }),
  missionMutation({ method: "POST", path: "/api/v2/runs/:runId/plan-changes", owningService: "PlanChangeService", implementationSources: source.plan, idempotency: "required", optimisticConcurrency: "represented_boundary", controlPlaneEnforcement: "lease_fenced" }),
  missionMutation({ method: "PUT", path: "/api/v2/runs/:runId/plan-changes/:requestId", owningService: "PlanChangeService", implementationSources: source.plan, idempotency: "required", optimisticConcurrency: "required", controlPlaneEnforcement: "lease_fenced" }),
  missionMutation({ method: "POST", path: "/api/v2/runs/:runId/plan-changes/:requestId/apply", owningService: "PlanChangeService", implementationSources: source.plan, idempotency: "required", optimisticConcurrency: "required", controlPlaneEnforcement: "lease_fenced" }),
  missionMutation({ method: "POST", path: "/api/v2/runs/:runId/plan-changes/:requestId/reject", owningService: "PlanChangeService", implementationSources: source.plan, idempotency: "required", optimisticConcurrency: "required", controlPlaneEnforcement: "lease_fenced" }),

  ...["replan", "reassign", "provider"].map((action): MutationAuthorityRecord => missionMutation({
    method: "POST", path: `/api/v2/operations/runs/:runId/recovery/${action}`,
    owningService: "RecoveryMutationRepository", implementationSources: source.operations,
    idempotency: "required", optimisticConcurrency: "required",
    controlPlaneEnforcement: "ownership_fenced",
    notes: "The repository asserts V2 ownership and exact run/plan/step/checkpoint versions, then uses a durable worker lease; migration to ControlPlaneLeaseService remains tracked.",
  })),
  missionMutation({ method: "POST", path: "/api/v2/operations/runs/:runId/follow-up", owningService: "FollowUpRunRepository", implementationSources: source.operations, idempotency: "required", optimisticConcurrency: "represented_boundary", controlPlaneEnforcement: "lease_fenced", notes: "The terminal source run is V2-owned and lease-proven before repository entry, then rechecked inside the atomic replay/create transaction." }),
] as const satisfies readonly MutationAuthorityRecord[];

export function mutationAuthorityKey(record: Pick<MutationAuthorityRecord, "method" | "path">): string {
  return `${record.method} ${record.path}`;
}

export interface MutationRouteDeclaration {
  readonly method: MutationMethod;
  readonly path: string;
  readonly source: string;
}

export interface MutationAuthorityAuditReport {
  readonly inventoryCount: number;
  readonly declarationCount: number;
  readonly duplicateInventoryKeys: readonly string[];
  readonly unclassifiedDeclarations: readonly string[];
  readonly staleInventoryRecords: readonly string[];
  readonly implementationSourceMismatches: readonly string[];
  readonly approvedDuplicateDeclarations: readonly string[];
  readonly policyScopedGaps: readonly string[];
}

function groupedSources(declarations: readonly MutationRouteDeclaration[]): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();
  for (const declaration of declarations) {
    const key = mutationAuthorityKey(declaration);
    const current = result.get(key) ?? new Set<string>();
    current.add(declaration.source);
    result.set(key, current);
  }
  return result;
}

function repeatedDeclarationSources(
  declarations: readonly MutationRouteDeclaration[],
): Map<string, readonly string[]> {
  const counts = new Map<string, Map<string, number>>();
  for (const declaration of declarations) {
    const key = mutationAuthorityKey(declaration);
    const sources = counts.get(key) ?? new Map<string, number>();
    sources.set(declaration.source, (sources.get(declaration.source) ?? 0) + 1);
    counts.set(key, sources);
  }
  return new Map([...counts].flatMap(([key, sources]) => {
    const repeated = [...sources]
      .filter(([, count]) => count > 1)
      .map(([source, count]) => `${source} (${count})`)
      .sort();
    return repeated.length > 0 ? [[key, repeated] as const] : [];
  }));
}

/** Pure runtime validator used by CI and available to deployment tooling. */
export function auditMutationAuthorityInventory(
  declarations: readonly MutationRouteDeclaration[],
  inventory: readonly MutationAuthorityRecord[] = V2_MUTATION_AUTHORITY_INVENTORY,
): MutationAuthorityAuditReport {
  const inventoryByKey = new Map<string, MutationAuthorityRecord>();
  const duplicateInventoryKeys = new Set<string>();
  for (const record of inventory) {
    const key = mutationAuthorityKey(record);
    if (inventoryByKey.has(key)) duplicateInventoryKeys.add(key);
    else inventoryByKey.set(key, record);
  }
  const declarationsByKey = groupedSources(declarations);
  const repeatedByKey = repeatedDeclarationSources(declarations);
  const unclassifiedDeclarations = [...declarationsByKey.keys()]
    .filter((key) => !inventoryByKey.has(key));
  const staleInventoryRecords = [...inventoryByKey.keys()]
    .filter((key) => !declarationsByKey.has(key));
  const implementationSourceMismatches: string[] = [];
  const approvedDuplicateDeclarations: string[] = [];
  for (const [key, sources] of declarationsByKey) {
    const record = inventoryByKey.get(key);
    if (!record) continue;
    const actual = [...sources].sort();
    const expected = [...new Set(record.implementationSources)].sort();
    const repeated = repeatedByKey.get(key);
    if (repeated) {
      implementationSourceMismatches.push(
        `${key}: repeated declaration source=[${repeated.join(", ")}]`,
      );
    } else if (actual.join("\n") !== expected.join("\n")) {
      implementationSourceMismatches.push(
        `${key}: declared=[${actual.join(", ")}], inventoried=[${expected.join(", ")}]`,
      );
    } else if (actual.length > 1) {
      approvedDuplicateDeclarations.push(`${key}: ${actual.join(", ")}`);
    }
  }
  return {
    inventoryCount: inventory.length,
    declarationCount: declarations.length,
    duplicateInventoryKeys: [...duplicateInventoryKeys].sort(),
    unclassifiedDeclarations: unclassifiedDeclarations.sort(),
    staleInventoryRecords: staleInventoryRecords.sort(),
    implementationSourceMismatches: implementationSourceMismatches.sort(),
    approvedDuplicateDeclarations: approvedDuplicateDeclarations.sort(),
    policyScopedGaps: inventory
      .filter((record) => record.controlPlaneEnforcement === "policy_scoped_gap")
      .map(mutationAuthorityKey)
      .sort(),
  };
}

export function assertMutationAuthorityInventory(report: MutationAuthorityAuditReport): void {
  const failures = [
    ...report.duplicateInventoryKeys.map((item) => `duplicate inventory key: ${item}`),
    ...report.unclassifiedDeclarations.map((item) => `unclassified mutation: ${item}`),
    ...report.staleInventoryRecords.map((item) => `stale inventory record: ${item}`),
    ...report.implementationSourceMismatches.map((item) => `implementation mismatch: ${item}`),
  ];
  if (failures.length > 0) {
    throw new Error(`V2 mutation-authority inventory failed:\n${failures.join("\n")}`);
  }
}
