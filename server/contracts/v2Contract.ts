import { FAILURE_OPERATOR_ACTION_KINDS } from "../intelligence-v24/types";

export const COMMAND_OS_API_VERSION = "2.4" as const;

export const COMMAND_OS_JOURNEYS = ["autonomous", "guided"] as const;

export const COMMAND_OS_RUN_STATES = [
  "queued",
  "planning",
  "awaiting_contract_confirmation",
  "running",
  "waiting_guided_decision",
  "blocked",
  "recovering",
  "completed",
  "failed",
  "cancelled",
] as const;

export type ContractHttpMethod = "get" | "post" | "put" | "delete";

export interface V2EndpointContract {
  readonly method: ContractHttpMethod;
  readonly path: string;
  readonly summary: string;
  readonly idempotencyRequired: boolean;
  readonly requestBodyRequired: boolean;
}

export interface V2DeferredEndpointContract extends V2EndpointContract {
  readonly reason: string;
  readonly requiredAdapters: readonly string[];
}

const read = (path: string, summary: string): V2EndpointContract => ({
  method: "get",
  path,
  summary,
  idempotencyRequired: false,
  requestBodyRequired: false,
});

const write = (
  method: "post" | "put" | "delete",
  path: string,
  summary: string,
  idempotencyRequired = true,
): V2EndpointContract => ({
  method,
  path,
  summary,
  idempotencyRequired,
  requestBodyRequired: method !== "delete",
});

const deferred = (
  endpoint: V2EndpointContract,
  reason: string,
  requiredAdapters: readonly string[],
): V2DeferredEndpointContract => ({ ...endpoint, reason, requiredAdapters });

/**
 * Checked catalog for the public Ti-Scale surface. Internal compatibility
 * routes are intentionally excluded: they are not part of the V2 contract.
 */
export const TI_SCALE_ENDPOINTS: readonly V2EndpointContract[] = [
  write("post", "/api/v2/auth/session", "Exchange the configured local operator token for a signed browser session", false),
  read("/api/v2/auth/session", "Read local browser-session state"),
  write("delete", "/api/v2/auth/session", "Clear the local browser session", false),
  read("/api/v2/openapi.json", "Read the Ti-Scale OpenAPI contract"),
  read("/api/v2/contracts/events", "Read the durable event contract"),
  read("/api/v2/health", "Read constant-time Ti-Scale liveness and the cached startup database attestation"),
  read("/api/v2/system/readiness", "Read the rich nonblocking Ti-Scale dependency and execution readiness projection"),
  read("/api/v2/system/capability-self-tests", "Read authenticated registry-derived dependency self-tests without granting execution"),
  read("/api/v2/overview", "Read the Command Center overview"),
  read("/api/v2/registries/intake", "Read runtime-derived mission intake registries"),
  write("post", "/api/v2/registries/intake/resolve", "Resolve minimal mission intake into a complete reviewable contract", false),
  read("/api/v2/missions", "Search and page through missions"),
  read("/api/v2/missions/saved-views", "Read synchronized operator mission views"),
  write("post", "/api/v2/missions/saved-views", "Save a versioned operator mission view"),
  write("delete", "/api/v2/missions/saved-views/:viewId", "Delete a versioned operator mission view"),
  write("post", "/api/v2/missions/bulk/archive", "Archive an exact bounded selection of terminal missions"),
  write("post", "/api/v2/missions/bulk/export", "Export exact bounded redacted mission metadata"),
  write("post", "/api/v2/missions/autonomous/preflight", "Validate an Autonomous Mission Contract", false),
  write("post", "/api/v2/missions", "Create a durable mission"),
  read("/api/v2/missions/:missionId/runtime", "Read canonical mission runtime state"),
  read("/api/v2/missions/:missionId/autonomous-branches/context", "Read safe Autonomous branch context"),
  write("post", "/api/v2/missions/:missionId/autonomous-branches/preflight", "Preflight an Autonomous branch or contract amendment"),
  write("post", "/api/v2/missions/:missionId/autonomous-branches", "Create a versioned Autonomous branch"),
  read("/api/v2/runs", "Search canonical run projections"),
  read("/api/v2/runs/:runId", "Read canonical run state and checkpoint"),
  read("/api/v2/runs/:runId/model-assignments", "Read the exact provider and model assignments pinned to a run"),
  read("/api/v2/runs/:runId/autonomous-activation-receipts", "Read immutable Autonomous activation receipts for a run"),
  read("/api/v2/runs/:runId/autonomous-activation-receipts/:receiptId", "Read one immutable Autonomous activation receipt"),
  read("/api/v2/runs/:runId/plans", "Read versioned plans for a run"),
  read("/api/v2/runs/:runId/plan-changes", "Read normalized versioned plan-change proposals for a run"),
  write("post", "/api/v2/runs/:runId/plan-changes", "Create and validate one structured plan-change proposal"),
  read("/api/v2/runs/:runId/plan-changes/:requestId", "Read one plan-change proposal, exact diff, and impact analysis"),
  write("put", "/api/v2/runs/:runId/plan-changes/:requestId", "Edit and fully revalidate an unresolved plan-change proposal"),
  write("post", "/api/v2/runs/:runId/plan-changes/:requestId/apply", "Activate one validated pre-execution plan version without executing actions"),
  write("post", "/api/v2/runs/:runId/plan-changes/:requestId/reject", "Reject one unresolved plan-change proposal without changing execution state"),
  read("/api/v2/runs/:runId/plan-changes/:requestId/inflight-resolution", "Read one durable in-flight amendment boundary"),
  write("post", "/api/v2/runs/:runId/plan-changes/:requestId/resolve-inflight", "Fence dispatch and resolve the exact represented in-flight amendment boundary"),
  write("post", "/api/v2/runs/:runId/plan-changes/:requestId/inflight-resolution/finalize", "Reconcile terminal work and prepare one fresh immutable plan-change review"),
  read("/api/v2/decisions", "Search exact Guided decisions"),
  read("/api/v2/guided/:missionId/commander/transcript", "Read a durable Guided Commander transcript"),
  write("post", "/api/v2/guided/:missionId/commander/remember", "Create a reviewable Guided memory candidate"),
  write("post", "/api/v2/guided/:missionId/commander/do-not-remember", "Suppress a Guided memory candidate"),
  read("/api/v2/decision-inbox", "Read Guided decisions, Autonomous exceptions, and administrative approvals"),
  write("post", "/api/v2/administrative-approvals/:approvalId/review", "Review an administrative approval"),
  read("/api/v2/events/stream", "Subscribe to the resumable semantic event stream"),
  read("/api/v2/events/replay", "Replay durable run events after a sequence"),
  read("/api/v2/events/gap", "Repair a detected run event gap"),
  read("/api/v2/notifications", "Page through scope-authorized semantic notifications with actor-scoped read state"),
  read("/api/v2/notifications/unread-count", "Read the actor-scoped unread count inside the current authorization scope"),
  write("post", "/api/v2/notifications/:notificationId/read", "Record one human actor's authorized in-app read receipt"),
  write("post", "/api/v2/notifications/read-all", "Record human actor read receipts for all currently authorized notifications"),
  read("/api/v2/agents", "Search the agent fleet"),
  read("/api/v2/agents/:agentId", "Read an agent profile"),
  read("/api/v2/agents/:agentId/assignments", "Read an agent assignment history"),
  read("/api/v2/provider-connections/openrouter", "Read the secret-free canonical OpenRouter connection and activation state"),
  write("put", "/api/v2/provider-connections/openrouter", "Save one optimistically versioned private OpenRouter connection"),
  write("put", "/api/v2/provider-connections/openrouter/attestation", "Run one bounded OpenRouter provider/model attestation and refresh its catalog projection"),
  read("/api/v2/model-catalog", "Read live-attested selectable provider, model, and reasoning-effort configurations"),
  read("/api/v2/model-configurations", "Read immutable materialized model configurations"),
  read("/api/v2/model-preferences", "Read current scoped model preferences"),
  write("put", "/api/v2/model-preferences/:scopeType/:scopeId", "Append an optimistically versioned scoped model preference"),
  read("/api/v2/model-resolution", "Resolve the effective model configuration for one agent and execution scope"),
  read("/api/v2/intelligence/evidence", "Search immutable evidence metadata"),
  read("/api/v2/intelligence/evidence/:evidenceId", "Read evidence provenance"),
  read("/api/v2/intelligence/evidence/runs/:runId/export", "Export a bounded redacted run evidence bundle"),
  read("/api/v2/intelligence/findings", "Search evidence-linked findings"),
  read("/api/v2/intelligence/findings/:findingId", "Read a finding"),
  write("post", "/api/v2/intelligence/findings/:findingId/review", "Review an evidence-linked finding"),
  read("/api/v2/intelligence/artifacts", "Search artifact metadata"),
  read("/api/v2/intelligence/artifacts/:artifactId", "Read artifact metadata"),
  read("/api/v2/intelligence/artifacts/:artifactId/download", "Download verified content from an approved canonical artifact store"),
  read("/api/v2/learning/evaluations", "Search run evaluations"),
  read("/api/v2/learning/lessons", "Search reusable lessons"),
  read("/api/v2/learning/lessons/:lessonId", "Read lesson provenance and usage"),
  write("post", "/api/v2/learning/lessons/:lessonId/review", "Review a proposed lesson"),
  read("/api/v2/learning/usage", "Read selective lesson usage"),
  read("/api/v2/research", "Read bounded Research Lab campaigns, readiness, integrity, and promotion state"),
  write("post", "/api/v2/research/campaigns", "Create a human-owned bounded draft research campaign"),
  write("post", "/api/v2/research/campaigns/:campaignId/stop", "Stop a bounded research campaign without promoting a candidate"),
  write("post", "/api/v2/research/campaigns/:campaignId/setup", "Approve the exact built-in charter, immutable benchmark snapshot, and queued candidate for one human-owned Research campaign"),
  write("post", "/api/v2/research/experiments/:experimentId/runs", "Queue one receipt-bound synthetic benchmark run in the isolated local Research worker"),
  write("post", "/api/v2/research/experiments/:experimentId/stages/:stage/runs", "Queue the next server-resolved validation or private hidden-holdout stage without accepting a hidden scenario identifier"),
  read("/api/v2/research/experiments/:experimentId/runs/:runId", "Read one durable isolated Research experiment run"),
  write("post", "/api/v2/research/experiments/:experimentId/runs/:runId/cancel", "Cancel one exact bounded Research run and prove isolated-worker cleanup"),
  write("post", "/api/v2/research/experiments/:experimentId/promotion", "Record one human-owned, optimistically versioned Research Lab promotion decision"),
  read("/api/v2/operational-truth/missions/:missionId/logs", "Read scoped engagement log records that are not automatically evidence"),
  write("post", "/api/v2/operational-truth/missions/:missionId/logs", "Append one attributable engagement log record"),
  read("/api/v2/operational-truth/missions/:missionId/logs/:logId", "Read one scoped engagement log record"),
  read("/api/v2/operational-truth/missions/:missionId/observations", "Read parsed attributable observations"),
  write("post", "/api/v2/operational-truth/missions/:missionId/observations", "Create one parsed observation from canonical logs"),
  read("/api/v2/operational-truth/missions/:missionId/observations/:observationId", "Read one parsed observation and its sources"),
  read("/api/v2/operational-truth/missions/:missionId/evidence-candidates", "Read evidence candidates separately from verified evidence"),
  write("post", "/api/v2/operational-truth/missions/:missionId/evidence-candidates", "Propose one reviewable evidence candidate"),
  read("/api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId", "Read one evidence candidate and validation requirements"),
  write("post", "/api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId/promote", "Promote one candidate into provenance validation"),
  write("post", "/api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId/reject", "Reject one evidence candidate with an audited reason"),
  write("post", "/api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId/demote", "Demote one candidate from validation with an audited reason"),
  write("post", "/api/v2/operational-truth/missions/:missionId/evidence-candidates/:candidateId/verify", "Create immutable verified evidence after provenance validation"),
  read("/api/v2/operational-truth/missions/:missionId/verified-evidence", "Read immutable verified evidence records"),
  read("/api/v2/operational-truth/missions/:missionId/verified-evidence/:evidenceId", "Read verified evidence and chain of custody"),
  read("/api/v2/operational-truth/missions/:missionId/findings/:findingId/verification-readiness", "Read evidence-gate readiness for a finding"),
  write("post", "/api/v2/operational-truth/missions/:missionId/findings/:findingId/verify", "Verify a finding only when immutable evidence is sufficient"),
  read("/api/v2/operational-truth/missions/:missionId/runs/:runId/failure-diagnoses", "Read structured failure diagnoses and valid recovery actions"),
  write("post", "/api/v2/operational-truth/missions/:missionId/runs/:runId/failure-diagnoses", "Persist one structured failure diagnosis"),
  read("/api/v2/operational-truth/missions/:missionId/runs/:runId/failure-diagnoses/:diagnosisId", "Read one structured failure diagnosis"),
  write("post", "/api/v2/operational-truth/missions/:missionId/runs/:runId/failure-diagnoses/:diagnosisId/resolve", "Resolve one active or terminal failure diagnosis through a declared action, verified outcome, explicit confirmation, and server-authored audit record"),
  read("/api/v2/runs/:runId/intelligence/metrics/snapshots", "Read reproducible run-metric snapshots with canonical drill-downs"),
  read("/api/v2/runs/:runId/intelligence/metrics/snapshots/:snapshotId", "Read one immutable run-metric snapshot"),
  write("post", "/api/v2/runs/:runId/intelligence/metrics/recompute", "Recompute and persist run metrics from canonical records"),
  read("/api/v2/runs/:runId/intelligence/attack-attempts", "Read intent-level attack attempts separately from tool processes"),
  write("post", "/api/v2/runs/:runId/intelligence/attack-attempts", "Create one scoped intent-level attack attempt"),
  read("/api/v2/runs/:runId/intelligence/attack-attempts/:attemptId", "Read one attack attempt, outcome, and evidence history"),
  write("post", "/api/v2/runs/:runId/intelligence/attack-attempts/:attemptId/transition", "Apply one versioned attack-attempt state or outcome transition"),
  read("/api/v2/missions/:missionId/intelligence/topology", "Read the evidence-backed recon digital twin"),
  read("/api/v2/missions/:missionId/intelligence/topology/nodes", "Read evidence-backed topology nodes"),
  write("post", "/api/v2/missions/:missionId/intelligence/topology/nodes", "Create one evidence-backed topology node"),
  read("/api/v2/missions/:missionId/intelligence/topology/nodes/:nodeId", "Read one topology node and provenance"),
  read("/api/v2/missions/:missionId/intelligence/topology/edges", "Read typed evidence-backed topology relationships"),
  write("post", "/api/v2/missions/:missionId/intelligence/topology/edges", "Create one typed evidence-backed topology relationship"),
  read("/api/v2/missions/:missionId/intelligence/topology/edges/:edgeId", "Read one topology edge and provenance"),
  read("/api/v2/missions/:missionId/intelligence/topology/assets/:assetNodeId/osi", "Read a seven-layer evidence-backed asset stack"),
  write("post", "/api/v2/missions/:missionId/intelligence/topology/assets/:assetNodeId/osi", "Record one attributable OSI or application-stack observation"),
  read("/api/v2/missions/:missionId/intelligence/cves", "Read evidence-gated version-aware CVE applicability records"),
  write("post", "/api/v2/missions/:missionId/intelligence/cves", "Create or optimistically update one evidence-gated CVE applicability record"),
  read("/api/v2/missions/:missionId/intelligence/cves/:recordId", "Read one version-aware CVE applicability record and authoritative provenance"),
  write(
    "post",
    "/api/v2/missions/:missionId/intelligence/cves/:recordId/review",
    "Record one optimistic-concurrency CVE applicability review with immutable audit and run-event evidence",
  ),
  read(
    "/api/v2/missions/:missionId/runs/:runId/steps/:stepId/intelligence/cves/:recordId/nvd-detail",
    "Retrieve one official public NVD record for a reviewed mission CVE without contacting the assessed target or granting execution authority",
  ),
  read("/api/v2/missions/:missionId/intelligence/page-captures", "Read scoped web-page capture metadata and gallery readiness"),
  write("post", "/api/v2/missions/:missionId/intelligence/page-captures", "Record one supplied, attributable web-page capture result without initiating network activity"),
  read("/api/v2/missions/:missionId/intelligence/page-captures/:captureId", "Read one web-page capture, provenance, sensitivity, and canonical artifact links"),
  read("/api/v2/missions/:missionId/script-artifacts", "Read scoped generated-script artifacts and immutable version summaries"),
  write("post", "/api/v2/missions/:missionId/script-artifacts", "Create one documented source artifact without executing it"),
  read("/api/v2/missions/:missionId/script-artifacts/:scriptArtifactId", "Read one documented script artifact, immutable versions, and verified source"),
  write("post", "/api/v2/missions/:missionId/script-artifacts/:scriptArtifactId/versions", "Create one immutable, documented script-source version without executing it"),
  write("post", "/api/v2/missions/:missionId/script-artifacts/:scriptArtifactId/reusable-exploit-procedure", "Onboard one operator-reviewed reusable exploit-validation procedure, typed independent observer, and active-Vault graph without executing it or granting mission authority"),
  read("/api/v2/observability/traces", "Search scoped correlated trace summaries"),
  read("/api/v2/observability/traces/:traceId", "Read a bounded correlated trace waterfall"),
  read("/api/v2/observability/events", "Search semantic operational events"),
  read("/api/v2/observability/logs", "Search redacted structured logs"),
  read("/api/v2/observability/health", "Read canonical component health"),
  read("/api/v2/observability/audit/runs/:runId/export", "Export a bounded redacted run-scoped audit subset"),
  read("/api/v2/operations/runs/:runId/recovery", "Read run recovery intelligence"),
  write("post", "/api/v2/operations/runs/:runId/recovery/replan", "Request one materially different bounded recovery plan"),
  write("post", "/api/v2/operations/runs/:runId/recovery/reassign", "Reassign the exact stopped step to a healthy declared-capable specialist"),
  write("post", "/api/v2/operations/runs/:runId/recovery/provider", "Version an exact live-attested provider/model configuration for the stopped step"),
  read("/api/v2/operations/actions", "Search scoped semantic action activity"),
  write("post", "/api/v2/operations/runs/:runId/follow-up", "Create a versioned follow-up run with selective context"),
  read("/api/v2/reports", "Search report artifacts"),
  write("post", "/api/v2/reports/runs/:runId/generate", "Generate deterministic redacted Markdown and JSON mission reports"),
  read("/api/v2/reports/:artifactId", "Read report metadata"),
  read("/api/v2/reports/:artifactId/download", "Download an integrity-verified generated mission report"),
  read("/api/v2/reports/runs/:runId/export", "Export a bounded terminal-run metadata bundle"),
  read("/api/v2/system/health", "Read paginated system health snapshots"),
  read("/api/v2/system/mcp", "Read MCP connection health"),
  read("/api/v2/system/providers", "Read provider readiness"),
  read("/api/v2/system/policies", "Read active policy posture"),
  read("/api/v2/brain/summary", "Read Second Brain health and growth"),
  read("/api/v2/brain/health", "Read memory database health"),
  read("/api/v2/brain/control", "Read memory consent and retention controls"),
  write("put", "/api/v2/brain/control", "Update memory consent and retention controls"),
  read("/api/v2/brain/nodes", "Search memory nodes"),
  read("/api/v2/brain/nodes/:nodeId", "Read a memory node and provenance"),
  read("/api/v2/brain/nodes/:nodeId/sources", "Page through canonical memory provenance sources"),
  read("/api/v2/brain/nodes/:nodeId/sources/:sourceRecordId/origins", "Page through access-controlled private provenance origins"),
  read("/api/v2/brain/graph", "Read a bounded memory graph neighborhood"),
  read("/api/v2/brain/preferences", "Read the authenticated operator's confirmed preference profile"),
  read("/api/v2/brain/candidates", "Read the memory confirmation inbox"),
  read("/api/v2/brain/attack-knowledge/bundles", "Read generalized attack-knowledge bundles awaiting or retaining operator promotion receipts"),
  read("/api/v2/brain/attack-knowledge/bundles/:fingerprint/evidence", "Read only canonical verified evidence immutably bound to one attack-knowledge bundle"),
  write("post", "/api/v2/brain/attack-knowledge/bundles/:fingerprint/preview", "Preview the exact candidate graph, evidence set, blockers, and review hash without mutation", false),
  write("post", "/api/v2/brain/attack-knowledge/bundles/:fingerprint/promote", "Promote one exact operator-reviewed evidence-backed attack-knowledge graph"),
  write("post", "/api/v2/missions/:missionId/runs/:runId/actions/:actionId/operational-hazard-reset", "Record one completed typed local reset as a provenance-bound operational-hazard occurrence"),
  write("post", "/api/v2/missions/:missionId/runs/:runId/operational-hazards/reset-minimum-observations", "Record an operator-authored aggregate reset lower bound without assigning it to an exact procedure"),
  read("/api/v2/missions/:missionId/runs/:runId/operational-hazards/reset-totals", "Read exact attributable resets separately from the operator-reported aggregate lower bound"),
  read("/api/v2/brain/context-packs", "Search persisted memory influence packs"),
  read("/api/v2/brain/context-packs/:contextPackId", "Read persisted memory influence"),
  write("post", "/api/v2/brain/candidates/:candidateId/confirm", "Confirm a memory candidate"),
  write("post", "/api/v2/brain/candidates/:candidateId/reject", "Reject a memory candidate, optionally adding a privacy-safe suppression against relearning"),
  write("post", "/api/v2/brain/nodes/:nodeId/correct", "Correct and version a memory node"),
  write("post", "/api/v2/brain/nodes/:nodeId/dispute", "Dispute a memory node"),
  write("post", "/api/v2/brain/nodes/:nodeId/pin", "Pin or unpin a memory node"),
  write("post", "/api/v2/brain/nodes/:nodeId/expire", "Set memory expiry"),
  write("post", "/api/v2/brain/nodes/:nodeId/forget", "Forget memory and remove derived retrieval state"),
  read("/api/v2/brain/vault", "Read Obsidian vault connections"),
  read("/api/v2/brain/vault/attack-knowledge-preset", "Preview the exact reusable attack-knowledge Vault policy without creating files or database state"),
  read("/api/v2/brain/vault/brain-atlas", "Read pinned Brain Atlas install, configuration, mapping, and projected-knowledge health without modifying the Vault"),
  write("post", "/api/v2/brain/vault/attack-knowledge-preset/activate", "Activate the exact hash-pinned Attack Knowledge Vault policy after permission, acknowledgement, and filesystem round-trip verification"),
  write("post", "/api/v2/brain/vault/attack-knowledge-preset/amend", "Amend an existing Attack Knowledge Vault to a hash-pinned confirmed or explicit Operator Profile projection after exact operator acknowledgement"),
  write("post", "/api/v2/brain/vault/health-check", "Verify bounded Obsidian vault filesystem round-trip health"),
  write("post", "/api/v2/brain/vault/connect", "Connect an allowed Obsidian vault"),
  write("post", "/api/v2/brain/vault/:connectionId/disconnect", "Disconnect one version-pinned Obsidian projection without deleting or rewriting Vault files"),
  write("post", "/api/v2/brain/vault/export", "Project memory into an Obsidian vault"),
  write("post", "/api/v2/brain/vault/import", "Import reviewable Obsidian notes"),
  write("post", "/api/v2/brain/vault/sync", "Synchronize an Obsidian vault"),
  write("post", "/api/v2/brain/vault/repair", "Repair and reconcile a connected Obsidian vault without overwriting operator edits"),
  write("post", "/api/v2/brain/vault/reindex", "Incrementally refresh canonical search projection from managed Obsidian notes"),
  write("post", "/api/v2/brain/vault/portable-export", "Return the no-backup policy denial for portable Vault archives"),
  read("/api/v2/brain/vault/portable-exports/:connectionId/:archiveName", "Return the no-backup policy denial for retained Vault archives"),
  read("/api/v2/brain/vault/deep-link", "Create a safe Obsidian deep link"),
  read("/api/v2/brain/vault/conflicts", "Read vault sync conflicts"),
  read("/api/v2/brain/vault/conflicts/:conflictId", "Read a vault conflict"),
  write("post", "/api/v2/brain/vault/conflicts/:conflictId/resolve", "Resolve a versioned vault conflict"),
] as const;

/**
 * Implemented, tested service boundaries that are deliberately not mounted by
 * the isolated preview process. Publishing these as live would imply execution
 * capability that does not exist until real provider, MCP, and execution ports
 * are injected. They remain visible for integration planning without becoming
 * fake or accidentally callable API paths.
 */
export const TI_SCALE_DEFERRED_ENDPOINTS: readonly V2DeferredEndpointContract[] = [
  ...[
    ["approve", "Approve one exact represented Guided action"],
    ["reject", "Reject one exact represented Guided action"],
    ["manual-result", "Attach one interpreted manual result to a Guided decision"],
    ["skip", "Skip one exact represented Guided action"],
    ["stop", "Stop a Guided mission at the represented action"],
  ].map(([command, summary]) => deferred(
    write("post", `/api/v2/guided-decisions/:decisionId/${command}`, summary),
    "Guided mutations require a live mission runtime and execution boundary.",
    ["MissionRuntimeEngine", "ResultAwareExecutionPort"],
  )),
  ...["pause", "resume", "cancel"].map((command) => deferred(
    write("post", `/api/v2/runs/:runId/${command}`, `${command[0]!.toUpperCase()}${command.slice(1)} a canonical run`),
    "Run control requires a live mission runtime and cooperative execution adapter.",
    ["MissionRuntimeEngine", "ResultAwareExecutionPort"],
  )),
  deferred(
    write(
      "post",
      "/api/v2/runs/:runId/operational-hazards/retry-authorizations",
      "Authorize one exact health-gated retry for a represented operational hazard",
    ),
    "Hazard retry authorization requires a live mission runtime, a trusted local health evaluator, and current run authority.",
    ["MissionRuntimeEngine", "OperationalHazardHealthGate"],
  ),
  ...[
    ["explain-more", "Explain the represented Guided step in more depth"],
    ["show-next-step", "Recommend one bounded next Guided step"],
    ["use-another-approach", "Propose a materially different Guided approach"],
    ["interpret-result", "Interpret operator-supplied Guided output"],
  ].map(([command, summary]) => deferred(
    write("post", `/api/v2/guided/:missionId/commander/${command}`, summary),
    "Guided Commander is not mounted without a real sanitized provider port.",
    ["GuidedCommanderPort"],
  )),
] as const;

const operationId = (endpoint: V2EndpointContract): string => {
  const resource = endpoint.path
    .replace(/^\/api\/v2\//u, "")
    .replace(/:([A-Za-z0-9_]+)/gu, "by_$1")
    .replace(/[^A-Za-z0-9]+/gu, "_")
    .replace(/^_+|_+$/gu, "");
  return `${endpoint.method}_${resource}`;
};

const tagFor = (path: string): string => path.split("/")[3] || "system";

const openApiPath = (path: string): string => path.replace(/:([A-Za-z0-9_]+)/gu, "{$1}");

const pathParameters = (path: string): readonly Record<string, unknown>[] =>
  [...path.matchAll(/:([A-Za-z0-9_]+)/gu)].map((match) => ({
    name: match[1],
    in: "path",
    required: true,
    schema: { type: "string", minLength: 1, maxLength: 240 },
  }));

export function createCommandOsOpenApiDocument(): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const endpoint of TI_SCALE_ENDPOINTS) {
    const path = openApiPath(endpoint.path);
    const parameters = [...pathParameters(endpoint.path)];
    parameters.push({
      name: "X-Request-ID",
      in: "header",
      required: false,
      description: "Optional caller correlation ID. Invalid values are replaced with a server-generated ID.",
      schema: { type: "string", pattern: "^[A-Za-z0-9._:-]{1,128}$" },
    });
    if (endpoint.idempotencyRequired) {
      parameters.push({
        name: "Idempotency-Key",
        in: "header",
        required: true,
        schema: { type: "string", minLength: 8, maxLength: 200 },
      });
    }
    if (endpoint.method !== "get") {
      parameters.push({
        name: "X-Ti-Scale-CSRF",
        in: "header",
        required: false,
        description: "Required for unsafe browser-session requests; bearer-authenticated requests do not use CSRF proof.",
        schema: { type: "string", minLength: 32, maxLength: 256 },
      });
    }
    const isEventStream = endpoint.path === "/api/v2/events/stream";
    const isArtifactDownload = [
      "/api/v2/intelligence/artifacts/:artifactId/download",
      "/api/v2/reports/:artifactId/download",
    ].includes(endpoint.path);
    const isFailureDiagnosisResolution = endpoint.path === "/api/v2/operational-truth/missions/:missionId/runs/:runId/failure-diagnoses/:diagnosisId/resolve";
    const successStatus = endpoint.method === "post" && [
      "/api/v2/missions",
      "/api/v2/reports/runs/:runId/generate",
    ].includes(endpoint.path)
      ? "201"
      : "200";
    paths[path] ??= {};
    paths[path]![endpoint.method] = {
      operationId: operationId(endpoint),
      summary: endpoint.summary,
      tags: [tagFor(endpoint.path)],
      security: endpoint.path === "/api/v2/auth/session" || [
        "/api/v2/openapi.json",
        "/api/v2/contracts/events",
        "/api/v2/health",
        "/api/v2/system/readiness",
      ].includes(endpoint.path)
        ? []
        : [{ bearerToken: [] }, { localSessionCookie: [] }],
      parameters,
      ...(endpoint.requestBodyRequired ? {
        requestBody: {
          required: true,
          content: { "application/json": { schema: isFailureDiagnosisResolution
            ? { $ref: "#/components/schemas/FailureDiagnosisResolutionRequest" }
            : { type: "object" } } },
        },
      } : {}),
      responses: {
        [successStatus]: isEventStream
          ? {
              description: "Resumable Server-Sent Events stream",
              headers: { "X-Request-ID": { $ref: "#/components/headers/RequestId" } },
              content: { "text/event-stream": { schema: { type: "string" } } },
              "x-event-schema": "#/components/schemas/OperationalEvent",
            }
          : isArtifactDownload
            ? {
                description: "Integrity-verified inert artifact attachment",
                headers: {
                  "X-Request-ID": { $ref: "#/components/headers/RequestId" },
                  "Content-Disposition": { schema: { type: "string" } },
                  "Content-Length": { schema: { type: "integer", minimum: 0 } },
                  "X-Content-Type-Options": { schema: { type: "string", const: "nosniff" } },
                },
                content: {
                  "application/octet-stream": {
                    schema: { type: "string", format: "binary" },
                  },
                },
              }
          : {
              description: "Successful Ti-Scale response",
              headers: { "X-Request-ID": { $ref: "#/components/headers/RequestId" } },
              content: { "application/json": { schema: { type: "object" } } },
            },
        "400": { $ref: "#/components/responses/CommandOsError" },
        "401": { $ref: "#/components/responses/CommandOsError" },
        "403": { $ref: "#/components/responses/CommandOsError" },
        "404": { $ref: "#/components/responses/CommandOsError" },
        "409": { $ref: "#/components/responses/CommandOsError" },
        "413": { $ref: "#/components/responses/CommandOsError" },
        "415": { $ref: "#/components/responses/CommandOsError" },
        "422": { $ref: "#/components/responses/CommandOsError" },
        "500": { $ref: "#/components/responses/CommandOsError" },
        "502": { $ref: "#/components/responses/CommandOsError" },
        "503": { $ref: "#/components/responses/CommandOsError" },
        "504": { $ref: "#/components/responses/CommandOsError" },
      },
      "x-idempotency-required": endpoint.idempotencyRequired,
    };
  }

  return {
    openapi: "3.1.0",
    info: {
      title: "Ti-Scale API",
      version: COMMAND_OS_API_VERSION,
      description: "Canonical mission, runtime, evidence, learning, observability, and user-owned Second Brain contract.",
    },
    servers: [{ url: "/", description: "Authenticated Ti-Scale host" }],
    "x-ti-scale-deferred-operations": TI_SCALE_DEFERRED_ENDPOINTS.map((endpoint) => ({
      method: endpoint.method,
      path: openApiPath(endpoint.path),
      summary: endpoint.summary,
      reason: endpoint.reason,
      requiredAdapters: endpoint.requiredAdapters,
    })),
    paths,
    components: {
      headers: {
        RequestId: {
          description: "Stable correlation ID shared by the response header and any error envelope traceId.",
          schema: { type: "string", pattern: "^[A-Za-z0-9._:-]{1,128}$" },
        },
      },
      securitySchemes: {
        bearerToken: {
          type: "http",
          scheme: "bearer",
          description: "TI_SCALE_OPERATOR_TOKEN supplied as an Authorization bearer token.",
        },
        localSessionCookie: {
          type: "apiKey",
          in: "cookie",
          name: "ti_scale_session",
          description: "Signed HttpOnly local browser session. Unsafe requests additionally require the bound double-submit CSRF token.",
        },
      },
      responses: {
        CommandOsError: {
          description: "Stable Ti-Scale error envelope",
          headers: { "X-Request-ID": { $ref: "#/components/headers/RequestId" } },
          content: {
            "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } },
          },
        },
      },
      schemas: {
        Journey: { type: "string", enum: [...COMMAND_OS_JOURNEYS] },
        RunState: { type: "string", enum: [...COMMAND_OS_RUN_STATES] },
        FailureDiagnosisResolutionRequest: {
          type: "object",
          additionalProperties: false,
          required: ["actionKind", "verifiedOutcome", "confirmed"],
          properties: {
            actionKind: { type: "string", enum: [...FAILURE_OPERATOR_ACTION_KINDS] },
            verifiedOutcome: { type: "string", minLength: 16, maxLength: 4_000 },
            confirmed: { type: "boolean", const: true },
          },
        },
        ErrorResponse: {
          type: "object",
          required: ["error"],
          properties: { error: { $ref: "#/components/schemas/ErrorEnvelope" } },
        },
        ErrorEnvelope: {
          type: "object",
          additionalProperties: false,
          required: ["code", "message", "humanMessage", "retryable", "category", "traceId", "timestamp"],
          properties: {
            code: { type: "string" },
            message: { type: "string" },
            humanMessage: { type: "string" },
            retryable: { type: "boolean" },
            category: { type: "string" },
            details: {},
            traceId: { type: "string" },
            remediation: { type: "string" },
            timestamp: { type: "string", format: "date-time" },
          },
        },
        OperationalEvent: operationalEventJsonSchema(),
      },
    },
  };
}

export function operationalEventJsonSchema(): Record<string, unknown> {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://ti-scale.local/contracts/v2.4/operational-event.schema.json",
    title: "Ti-Scale Operational Event",
    type: "object",
    additionalProperties: false,
    required: [
      "id", "sequence", "type", "timestamp", "missionId", "runId", "journey",
      "summary", "actor", "payload", "schemaVersion", "traceId", "spanId",
      "sensitivity", "redaction", "contextPackId",
    ],
    properties: {
      id: { type: "string", minLength: 1 },
      sequence: { type: "integer", minimum: 1 },
      type: { type: "string", minLength: 1 },
      timestamp: { type: "string", format: "date-time" },
      missionId: { type: "string", minLength: 1 },
      runId: { type: "string", minLength: 1 },
      contextPackId: { type: ["string", "null"] },
      traceId: { type: ["string", "null"] },
      spanId: { type: ["string", "null"] },
      actor: {
        type: "object",
        additionalProperties: false,
        required: ["type", "id"],
        properties: {
          type: { type: "string", enum: ["operator", "agent", "worker", "system", "provider", "tool"] },
          id: { type: ["string", "null"] },
        },
      },
      summary: { type: "string", minLength: 1 },
      payload: {},
      schemaVersion: {
        type: "integer",
        minimum: 1,
        description: "Version of the durable event payload, independent of the HTTP API version.",
      },
      sensitivity: { type: "string", enum: ["public", "internal", "private", "restricted"] },
      redaction: {},
      journey: { type: "string", enum: [...COMMAND_OS_JOURNEYS] },
    },
  };
}

export const COMMAND_OS_EVENT_DELIVERY_CONTRACT = {
  schemaVersion: COMMAND_OS_API_VERSION,
  transport: "server-sent-events",
  contentType: "text/event-stream",
  eventSchema: operationalEventJsonSchema(),
  ordering: "Monotonic sequence per run",
  resume: {
    headers: ["Last-Event-ID"],
    query: ["runId", "afterSequence", "lastEventId"],
    replayEndpoint: "/api/v2/events/replay",
    gapRepairEndpoint: "/api/v2/events/gap",
  },
  delivery: "at-least-once; clients must deduplicate by stable event ID",
  redaction: "Sensitivity is enforced before replay or delivery; payloads carry explicit redaction metadata",
} as const;
