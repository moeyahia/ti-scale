import type {
  AutonomousAgentModelAssignment,
  AutonomousAgentModelAssignmentReceipt,
  AutonomousSpecialistCandidate,
} from "../../domain/types/commandOs";
import type {
  ModelCatalog,
  ModelCatalogItem,
} from "../../domain/types/modelConfiguration";
import { MODEL_CATALOG_SNAPSHOT_MAXIMUM_AGE_MS } from "../../data/api/modelConfiguration";
import { useQuerySnapshotExpired } from "../../data/cache/querySnapshotFreshness";
import { Button, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import {
  assignmentForAgent,
  configurationForId,
  configurationSelectableForAgent,
  configurationsForProvider,
  firstSelectableConfiguration,
  modelControlSegment,
  preferredConfigurationForModel,
  readableModelValue,
  uniqueModelValues,
  upsertAgentModelAssignment,
} from "./missionModelAssignmentState";
import "./mission-agent-model-assignments.css";

type AgentChoice = Pick<AutonomousSpecialistCandidate, "id" | "displayName" | "role">;

interface MissionAgentModelAssignmentsProps {
  readonly idPrefix: string;
  readonly agents: readonly AgentChoice[];
  readonly selectedAgentIds: readonly string[];
  readonly receipts: readonly AutonomousAgentModelAssignmentReceipt[];
  readonly explicitAssignments?: readonly AutonomousAgentModelAssignment[];
  readonly baselineAssignments?: readonly AutonomousAgentModelAssignment[];
  readonly baselineSourceLabel?: string;
  readonly changedSourceLabel?: string;
  readonly catalog?: ModelCatalog;
  readonly catalogUpdatedAt: number | null;
  readonly catalogLoading: boolean;
  readonly catalogError?: Error;
  readonly readinessStale: boolean;
  readonly restoreLabel: string;
  readonly restoreControlId?: string;
  readonly onAssignmentsChange: (
    assignments: readonly AutonomousAgentModelAssignment[] | undefined,
  ) => void;
  readonly onRestore: () => void;
  readonly onRetryCatalog?: () => void;
}

function sameAssignment(
  left: AutonomousAgentModelAssignment | undefined,
  right: AutonomousAgentModelAssignment | undefined,
): boolean {
  return Boolean(
    left
    && right
    && left.agentId === right.agentId
    && left.primaryConfigurationId === right.primaryConfigurationId
    && left.fallbackConfigurationId === right.fallbackConfigurationId,
  );
}

function sameSelectedAssignments(
  selectedAgentIds: readonly string[],
  assignments: readonly AutonomousAgentModelAssignment[] | undefined,
  baselineAssignments: readonly AutonomousAgentModelAssignment[] | undefined,
): boolean {
  if (!assignments || !baselineAssignments) return false;
  return selectedAgentIds.every((agentId) =>
    sameAssignment(
      assignments.find((assignment) => assignment.agentId === agentId),
      baselineAssignments.find((assignment) => assignment.agentId === agentId),
    ))
    && assignments.every((assignment) =>
      !selectedAgentIds.includes(assignment.agentId)
      || baselineAssignments.some((baseline) =>
        sameAssignment(assignment, baseline)))
    && baselineAssignments.every((baseline) =>
      !selectedAgentIds.includes(baseline.agentId)
      || assignments.some((assignment) =>
        sameAssignment(assignment, baseline)));
}

function receiptMatches(
  receipt: AutonomousAgentModelAssignmentReceipt | undefined,
  assignment: AutonomousAgentModelAssignment | undefined,
): boolean {
  return Boolean(
    receipt
    && assignment
    && receipt.primary.configurationId === assignment.primaryConfigurationId
    && (receipt.fallback?.configurationId ?? null) === assignment.fallbackConfigurationId,
  );
}

function sourceLabel(
  assignment: AutonomousAgentModelAssignment | undefined,
  baseline: AutonomousAgentModelAssignment | undefined,
  receipt: AutonomousAgentModelAssignmentReceipt | undefined,
  baselineSourceLabel: string,
  changedSourceLabel: string,
): string {
  if (sameAssignment(assignment, baseline)) return baselineSourceLabel;
  if (!receiptMatches(receipt, assignment)) return changedSourceLabel;
  if (receipt?.source === "recommended") return "Runtime recommendation";
  if (receipt?.source === "inherited") return "Inherited model preference";
  return "Mission operator override";
}

function formatContextLimit(value: number | null | undefined): string {
  if (value === null || value === undefined) return "Not reported";
  return new Intl.NumberFormat(undefined, {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(value);
}

function formatCatalogTime(value: string | null | undefined): string {
  if (!value) return "Not reported";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function modelName(item: ModelCatalogItem): string {
  return item.modelId === item.displayName
    ? item.displayName
    : `${item.displayName} · ${item.modelId}`;
}

function configurationLabel(item: ModelCatalogItem): string {
  return `${item.providerId} · ${item.displayName}${item.reasoningEffort
    ? ` · ${readableModelValue(item.reasoningEffort)} reasoning`
    : " · Provider-default reasoning"}`;
}

function executionBoundaryLabel(
  boundary: ModelCatalogItem["executionBoundary"],
): string {
  return boundary === "local_deterministic_policy"
    ? "Locally enforced deterministic policy"
    : "Provider tool-calling";
}

function autonomousUnavailabilityReason(
  item: ModelCatalogItem,
  agent: AgentChoice,
): string {
  if (
    item.enforcementMode === "observe_only_executor"
    || item.enforcementMode === "advisor_only"
  ) {
    return `${readableModelValue(item.enforcementMode)} cannot satisfy an enforced Autonomous executor assignment.`;
  }
  if (item.unavailableReasons.length > 0) {
    return item.unavailableReasons.join(" ");
  }
  if (!item.compatibleAgentIds.includes(agent.id)) {
    return `This configuration is not declared for ${agent.displayName}.`;
  }
  return "The live catalog marks this exact configuration unavailable.";
}

function AssignmentFacts({
  label,
  item,
}: {
  readonly label: string;
  readonly item: ModelCatalogItem | AutonomousAgentModelAssignmentReceipt["primary"] | undefined;
}) {
  if (!item) {
    return <div className="mission-model-assignment__empty-receipt">
      <strong>{label}</strong>
      <span>No exact configuration has been resolved.</span>
    </div>;
  }
  return <section className="mission-model-assignment__facts" aria-label={`${label} configuration receipt`}>
    <header>
      <div><span>{label}</span><strong>{item.providerId} · {item.displayName}</strong></div>
      <StatusPill status={item.enforcementMode}>{readableModelValue(item.enforcementMode)}</StatusPill>
    </header>
    <dl>
      <div><dt>Configuration</dt><dd className="os-mono">{item.configurationId}</dd></div>
      <div><dt>Exact model</dt><dd>{item.modelId}</dd></div>
      <div><dt>Execution boundary</dt><dd>{executionBoundaryLabel(item.executionBoundary)}</dd></div>
      <div><dt>Reasoning</dt><dd>{item.reasoningEffort ? readableModelValue(item.reasoningEffort) : "Provider default"}</dd></div>
      <div><dt>Authentication</dt><dd>{readableModelValue(item.authState)}</dd></div>
      <div><dt>Provider health</dt><dd>{readableModelValue(item.healthState)}</dd></div>
      <div><dt>Context limit</dt><dd>{formatContextLimit(item.contextLimit)}</dd></div>
      <div><dt>Latency / cost</dt><dd>{readableModelValue(item.latencyClass)} / {readableModelValue(item.costClass)}</dd></div>
      <div><dt>Disclosure</dt><dd>{readableModelValue(item.disclosureClass)}</dd></div>
      <div><dt>Catalog source</dt><dd>{item.catalogSource}</dd></div>
      <div><dt>Catalog observed</dt><dd>{formatCatalogTime(item.catalogRetrievedAt)}</dd></div>
    </dl>
  </section>;
}

function AgentAssignmentEditor({
  idPrefix,
  agent,
  catalog,
  assignment,
  baseline,
  receipt,
  readinessStale,
  baselineSourceLabel,
  changedSourceLabel,
  onChange,
}: {
  readonly idPrefix: string;
  readonly agent: AgentChoice;
  readonly catalog: ModelCatalog;
  readonly assignment?: AutonomousAgentModelAssignment;
  readonly baseline?: AutonomousAgentModelAssignment;
  readonly receipt?: AutonomousAgentModelAssignmentReceipt;
  readonly readinessStale: boolean;
  readonly baselineSourceLabel: string;
  readonly changedSourceLabel: string;
  readonly onChange: (assignment: AutonomousAgentModelAssignment) => void;
}) {
  const items = catalog.items;
  const segment = modelControlSegment(agent.id);
  const primary = configurationForId(items, assignment?.primaryConfigurationId)
    ?? (receiptMatches(receipt, assignment) ? receipt?.primary : undefined);
  const primaryCatalog = configurationForId(items, assignment?.primaryConfigurationId);
  const fallback = configurationForId(items, assignment?.fallbackConfigurationId)
    ?? (receiptMatches(receipt, assignment) ? receipt?.fallback ?? undefined : undefined);
  const fallbackCatalog = configurationForId(items, assignment?.fallbackConfigurationId);
  const primaryProviderId = primary?.providerId ?? "";
  const primaryModelId = primary?.modelId ?? "";
  const fallbackProviderId = fallback?.providerId ?? "";
  const fallbackModelId = fallback?.modelId ?? "";
  const providers = uniqueModelValues(items.map((item) => item.providerId));
  const primaryProviderItems = items.filter((item) => item.providerId === primaryProviderId);
  const primaryModels = uniqueModelValues(primaryProviderItems.map((item) => item.modelId));
  const primaryEfforts = primaryProviderItems.filter((item) => item.modelId === primaryModelId);
  const fallbackProviderItems = items.filter((item) => item.providerId === fallbackProviderId);
  const fallbackModels = uniqueModelValues(fallbackProviderItems.map((item) => item.modelId));
  const fallbackEfforts = fallbackProviderItems.filter((item) =>
    item.modelId === fallbackModelId
    && item.configurationId !== assignment?.primaryConfigurationId);
  const catalogAligned = Boolean(
    assignment
    && primaryCatalog
    && (
      assignment.fallbackConfigurationId === null
      || fallbackCatalog
    ),
  );
  const reviewed = receiptMatches(receipt, assignment)
    && catalogAligned
    && !readinessStale;
  const exactReasons = [
    ...(receiptMatches(receipt, assignment) ? receipt?.reasons ?? [] : []),
    ...(primaryCatalog?.unavailableReasons ?? []),
    ...(fallbackCatalog?.unavailableReasons ?? []),
    ...(!assignment?.primaryConfigurationId
      ? ["No primary model configuration has been selected for this specialist."]
      : !primaryCatalog
        ? ["The selected primary configuration is absent from the current live catalog."]
        : []),
    ...(assignment?.fallbackConfigurationId && !fallbackCatalog
      ? ["The selected fallback configuration is absent from the current live catalog."]
      : []),
    ...(readinessStale
      ? ["The mission changed after the last review. Run readiness again before launch."]
      : []),
  ];
  const readinessStatus = reviewed
    ? receipt?.ready ? "ready" : "blocked"
    : primaryCatalog && configurationSelectableForAgent(primaryCatalog, agent.id)
      ? "pending_review"
      : "unavailable";
  const unavailableCatalogItems = items.filter((item) =>
    !configurationSelectableForAgent(item, agent.id));

  const publish = (
    primaryConfigurationId: string,
    fallbackConfigurationId: string | null,
  ) => onChange({
    agentId: agent.id,
    primaryConfigurationId,
    fallbackConfigurationId,
  });

  const selectPrimaryProvider = (providerId: string) => {
    const next = firstSelectableConfiguration(
      configurationsForProvider(items, agent.id, providerId),
      agent.id,
    );
    if (!next) return;
    publish(
      next.configurationId,
      next.configurationId === assignment?.fallbackConfigurationId
        ? null
        : assignment?.fallbackConfigurationId ?? null,
    );
  };
  const selectPrimaryModel = (modelId: string) => {
    const next = preferredConfigurationForModel(
      primaryProviderItems,
      agent.id,
      modelId,
      primary?.reasoningEffort,
    );
    if (!next) return;
    publish(
      next.configurationId,
      next.configurationId === assignment?.fallbackConfigurationId
        ? null
        : assignment?.fallbackConfigurationId ?? null,
    );
  };
  const selectFallbackProvider = (providerId: string) => {
    if (!providerId) {
      if (assignment?.primaryConfigurationId) publish(assignment.primaryConfigurationId, null);
      return;
    }
    const next = firstSelectableConfiguration(
      configurationsForProvider(items, agent.id, providerId),
      agent.id,
      assignment?.primaryConfigurationId,
    );
    if (next && assignment?.primaryConfigurationId) {
      publish(assignment.primaryConfigurationId, next.configurationId);
    }
  };
  const selectFallbackModel = (modelId: string) => {
    const next = preferredConfigurationForModel(
      fallbackProviderItems,
      agent.id,
      modelId,
      fallback?.reasoningEffort,
      assignment?.primaryConfigurationId,
    );
    if (next && assignment?.primaryConfigurationId) {
      publish(assignment.primaryConfigurationId, next.configurationId);
    }
  };

  return <article className="mission-model-assignment" data-agent-id={agent.id}>
    <header className="mission-model-assignment__heading">
      <div>
        <p className="os-eyebrow">Pinned mission model</p>
        <h4>{agent.displayName}</h4>
        <p>{agent.role}</p>
      </div>
      <div className="mission-model-assignment__state">
        <StatusPill status={readinessStatus}>
          {reviewed ? receipt?.ready ? "Ready" : "Blocked" : "Review required"}
        </StatusPill>
        <span>{sourceLabel(
          assignment,
          baseline,
          receipt,
          baselineSourceLabel,
          changedSourceLabel,
        )}</span>
      </div>
    </header>

    <div className="mission-model-assignment__selectors">
      <label>
        <span>Primary provider</span>
        <TitaniumSelect
          data-control-id={`${idPrefix}-model-provider-${segment}`}
          aria-label={`${agent.displayName} primary provider`}
          value={primaryProviderId}
          onChange={(event) => selectPrimaryProvider(event.target.value)}
        >
          <option value="" disabled>Choose a provider</option>
          {providers.map((providerId) => {
            const available = items.some((item) =>
              item.providerId === providerId
              && configurationSelectableForAgent(item, agent.id));
            return <option key={providerId} value={providerId} disabled={!available}>
              {providerId}{available ? "" : " — unavailable for this specialist"}
            </option>;
          })}
        </TitaniumSelect>
      </label>
      <label>
        <span>Primary model</span>
        <TitaniumSelect
          data-control-id={`${idPrefix}-model-primary-${segment}`}
          aria-label={`${agent.displayName} primary model`}
          value={primaryModelId}
          disabled={!primaryProviderId}
          onChange={(event) => selectPrimaryModel(event.target.value)}
        >
          <option value="" disabled>Choose an exact model</option>
          {primaryModels.map((modelId) => {
            const modelItems = primaryProviderItems.filter((item) => item.modelId === modelId);
            const representative = modelItems[0]!;
            const available = modelItems.some((item) =>
              configurationSelectableForAgent(item, agent.id));
            return <option key={modelId} value={modelId} disabled={!available}>
              {modelName(representative)}{available ? "" : " — unavailable"}
            </option>;
          })}
        </TitaniumSelect>
      </label>
      <label>
        <span>Reasoning effort</span>
        <TitaniumSelect
          data-control-id={`${idPrefix}-model-reasoning-${segment}`}
          aria-label={`${agent.displayName} reasoning effort`}
          value={assignment?.primaryConfigurationId ?? ""}
          disabled={!primaryModelId}
          onChange={(event) => publish(
            event.target.value,
            event.target.value === assignment?.fallbackConfigurationId
              ? null
              : assignment?.fallbackConfigurationId ?? null,
          )}
        >
          <option value="" disabled>Choose reasoning effort</option>
          {primaryEfforts.map((item) => (
            <option
              key={item.configurationId}
              value={item.configurationId}
              disabled={!configurationSelectableForAgent(item, agent.id)}
            >
              {item.reasoningEffort
                ? readableModelValue(item.reasoningEffort)
                : "Provider default"}
              {configurationSelectableForAgent(item, agent.id) ? "" : " — unavailable"}
            </option>
          ))}
        </TitaniumSelect>
      </label>
      <label>
        <span>Fallback provider</span>
        <TitaniumSelect
          data-control-id={`${idPrefix}-model-fallback-provider-${segment}`}
          aria-label={`${agent.displayName} fallback provider`}
          value={fallbackProviderId}
          disabled={!assignment?.primaryConfigurationId}
          onChange={(event) => selectFallbackProvider(event.target.value)}
        >
          <option value="">No automatic fallback</option>
          {providers.map((providerId) => {
            const available = items.some((item) =>
              item.providerId === providerId
              && item.configurationId !== assignment?.primaryConfigurationId
              && configurationSelectableForAgent(item, agent.id));
            return <option key={providerId} value={providerId} disabled={!available}>
              {providerId}{available ? "" : " — unavailable for fallback"}
            </option>;
          })}
        </TitaniumSelect>
      </label>
      <label>
        <span>Fallback model</span>
        <TitaniumSelect
          data-control-id={`${idPrefix}-model-fallback-${segment}`}
          aria-label={`${agent.displayName} fallback model`}
          value={fallbackModelId}
          disabled={!fallbackProviderId}
          onChange={(event) => selectFallbackModel(event.target.value)}
        >
          <option value="" disabled>Choose a fallback model</option>
          {fallbackModels.map((modelId) => {
            const modelItems = fallbackProviderItems.filter((item) =>
              item.modelId === modelId
              && item.configurationId !== assignment?.primaryConfigurationId);
            const representative = modelItems[0];
            if (!representative) return null;
            const available = modelItems.some((item) =>
              configurationSelectableForAgent(item, agent.id));
            const selectedExact = modelItems.find((item) =>
              item.configurationId === assignment?.fallbackConfigurationId);
            return <option
              key={modelId}
              value={modelId}
              disabled={!available}
            >
              {modelName(representative)}
              {selectedExact?.reasoningEffort
                ? ` · ${readableModelValue(selectedExact.reasoningEffort)} reasoning`
                : ""}
              {available ? "" : " — unavailable"}
            </option>;
          })}
        </TitaniumSelect>
      </label>
      <label>
        <span>Fallback reasoning effort</span>
        <TitaniumSelect
          data-control-id={`${idPrefix}-model-fallback-reasoning-${segment}`}
          aria-label={`${agent.displayName} fallback reasoning effort`}
          value={assignment?.fallbackConfigurationId ?? ""}
          disabled={!fallbackModelId}
          onChange={(event) => {
            if (assignment?.primaryConfigurationId) {
              publish(assignment.primaryConfigurationId, event.target.value);
            }
          }}
        >
          <option value="" disabled>Choose fallback reasoning effort</option>
          {fallbackEfforts.map((item) => (
            <option
              key={item.configurationId}
              value={item.configurationId}
              disabled={!configurationSelectableForAgent(item, agent.id)}
            >
              {item.reasoningEffort
                ? readableModelValue(item.reasoningEffort)
                : "Provider default"}
              {configurationSelectableForAgent(item, agent.id) ? "" : " — unavailable"}
            </option>
          ))}
        </TitaniumSelect>
      </label>
    </div>

    <div className="mission-model-assignment__receipts">
      <AssignmentFacts label="Primary" item={primary} />
      <AssignmentFacts label="Fallback" item={fallback} />
    </div>
    {assignment && (!primaryCatalog || (assignment.fallbackConfigurationId && !fallbackCatalog)) && (
      <dl className="mission-model-review__ids mission-model-assignment__drift">
        <div>
          <dt>Preserved primary configuration</dt>
          <dd className="os-mono">{assignment.primaryConfigurationId}</dd>
        </div>
        <div>
          <dt>Preserved fallback configuration</dt>
          <dd className="os-mono">{assignment.fallbackConfigurationId ?? "None"}</dd>
        </div>
      </dl>
    )}
    {exactReasons.length > 0 && <div className="mission-model-assignment__reasons" role={readinessStatus === "blocked" || readinessStatus === "unavailable" ? "alert" : "status"}>
      <strong>{reviewed ? "Readiness explanation" : "Review status"}</strong>
      <ul>{[...new Set(exactReasons)].map((reason) => <li key={reason}>{reason}</li>)}</ul>
    </div>}
    {primaryCatalog && !configurationSelectableForAgent(primaryCatalog, agent.id) && (
      <p className="os-state-remediation">
        {autonomousUnavailabilityReason(primaryCatalog, agent)}
      </p>
    )}
    {unavailableCatalogItems.length > 0 && <section
      className="mission-model-assignment__unavailable"
      aria-label={`${agent.displayName} unavailable model paths`}
      data-control-id={`${idPrefix}-model-unavailable-paths-${segment}`}
    >
      <strong>Unavailable live-catalog paths</strong>
      <ul>{unavailableCatalogItems.map((item) => <li key={item.configurationId}>
        <span>{configurationLabel(item)}</span>
        <small>{autonomousUnavailabilityReason(item, agent)}</small>
      </li>)}</ul>
    </section>}
  </article>;
}

export function MissionAgentModelAssignments({
  idPrefix,
  agents,
  selectedAgentIds,
  receipts,
  explicitAssignments,
  baselineAssignments,
  baselineSourceLabel = "Runtime recommendation",
  changedSourceLabel = "Mission override pending review",
  catalog,
  catalogUpdatedAt,
  catalogLoading,
  catalogError,
  readinessStale,
  restoreLabel,
  restoreControlId,
  onAssignmentsChange,
  onRestore,
  onRetryCatalog,
}: MissionAgentModelAssignmentsProps) {
  const catalogExpired = useQuerySnapshotExpired(
    catalog ? catalogUpdatedAt : null,
    MODEL_CATALOG_SNAPSHOT_MAXIMUM_AGE_MS,
  );
  const catalogFailure = catalogError ?? (catalogExpired
    ? new Error(
        "The cached model catalog exceeded its 15-minute trust window. Refresh the live catalog before selecting or reviewing mission models.",
      )
    : undefined);
  const trustedCatalog = catalogFailure ? undefined : catalog;
  const selected = new Set(selectedAgentIds);
  const selectedAgents = agents.filter((agent) => selected.has(agent.id));
  const alreadyAtBaseline = sameSelectedAssignments(
    selectedAgentIds,
    explicitAssignments,
    baselineAssignments,
  );
  return <section className="mission-model-assignments" aria-label="Mission agent model assignments">
    <header className="mission-model-assignments__header">
      <div>
        <p className="os-eyebrow">Mission-local LLM configuration</p>
        <h3>Pin an exact model for every selected specialist</h3>
        <p>These choices apply only to this mission contract. Workspace and agent defaults are not changed.</p>
      </div>
      <Button
        type="button"
        variant="quiet"
        data-control-id={
          restoreControlId ?? `${idPrefix}-model-restore-recommended`
        }
        disabled={
          explicitAssignments === undefined
          || explicitAssignments.length === 0
          || alreadyAtBaseline
        }
        onClick={onRestore}
      >
        {restoreLabel}
      </Button>
    </header>
    {catalogLoading && <LoadingPanel label="Loading the live provider and model catalog" />}
    {catalogFailure && <ErrorPanel
      title="Mission model catalog is unavailable"
      error={catalogFailure}
      retryControlId={`${idPrefix}-model-catalog-retry`}
      {...(onRetryCatalog ? { onRetry: onRetryCatalog } : {})}
    />}
    {trustedCatalog && trustedCatalog.items.length === 0 && <div className="os-empty">
      <strong>No live model configurations were reported</strong>
      <p>Connect and attest a provider before assigning a specialist model. Ti-Scale will not invent a catalog value.</p>
    </div>}
    {trustedCatalog && selectedAgents.length === 0 && <div className="os-empty">
      <strong>No specialist is selected</strong>
      <p>Select at least one compatible specialist before configuring mission-local models.</p>
    </div>}
    {trustedCatalog && selectedAgents.length > 0 && <div className="mission-model-assignments__list">
      {selectedAgents.map((agent) => {
        const assignment = assignmentForAgent(agent.id, explicitAssignments, receipts);
        const baseline = baselineAssignments?.find((item) => item.agentId === agent.id);
        const receipt = receipts.find((item) => item.agentId === agent.id);
        return <AgentAssignmentEditor
          key={agent.id}
          idPrefix={idPrefix}
          agent={agent}
          catalog={trustedCatalog}
          assignment={assignment}
          baseline={baseline}
          receipt={receipt}
          readinessStale={readinessStale}
          baselineSourceLabel={baselineSourceLabel}
          changedSourceLabel={changedSourceLabel}
          onChange={(next) => onAssignmentsChange(
            upsertAgentModelAssignment(explicitAssignments, next),
          )}
        />;
      })}
    </div>}
    <p className="mission-model-assignments__policy">
      A model path marked observe-only or advisor-only remains inspectable but cannot satisfy an enforced Autonomous executor role. The server decides launch readiness from the exact signed assignments and current catalog receipt.
    </p>
  </section>;
}

export function MissionAgentModelAssignmentReview({
  assignments,
  receipts,
  agents,
  title = "Exact signed specialist models",
}: {
  readonly assignments: readonly AutonomousAgentModelAssignment[];
  readonly receipts: readonly AutonomousAgentModelAssignmentReceipt[];
  readonly agents: readonly AgentChoice[];
  readonly title?: string;
}) {
  return <section className="mission-model-review" aria-label={title}>
    <header>
      <p className="os-eyebrow">Pinned execution receipts</p>
      <h3>{title}</h3>
      <p>Every selected specialist is bound to these exact configuration IDs. Later workspace or provider-default changes cannot silently alter this contract.</p>
    </header>
    {assignments.length === 0 ? <div className="os-validation-summary" role="alert">
      <strong>No signed model assignments were returned</strong>
      <p>Autonomous launch must remain blocked until every selected specialist has one exact primary configuration.</p>
    </div> : <div className="mission-model-review__list">
      {assignments.map((assignment) => {
        const agent = agents.find((candidate) => candidate.id === assignment.agentId);
        const receipt = receipts.find((candidate) =>
          candidate.agentId === assignment.agentId
          && receiptMatches(candidate, assignment));
        return <article key={assignment.agentId} className="mission-model-review__item">
          <div className="mission-model-review__heading">
            <div>
              <h4>{agent?.displayName ?? assignment.agentId}</h4>
              <p>{agent?.role ?? "Selected specialist"}</p>
            </div>
            <StatusPill status={receipt?.ready ? "ready" : "blocked"}>
              {receipt?.ready ? "Ready" : "Not ready"}
            </StatusPill>
          </div>
          <p className="mission-model-review__source">
            {receipt?.source === "recommended"
              ? "Runtime recommendation"
              : receipt?.source === "inherited"
                ? "Inherited preference"
                : receipt?.source === "operator_override"
                  ? "Mission operator override"
                  : "Receipt missing or changed"}
          </p>
          {receipt ? <div className="mission-model-assignment__receipts">
            <AssignmentFacts label="Primary" item={receipt.primary} />
            <AssignmentFacts label="Fallback" item={receipt.fallback ?? undefined} />
          </div> : <dl className="mission-model-review__ids">
            <div><dt>Primary configuration</dt><dd className="os-mono">{assignment.primaryConfigurationId}</dd></div>
            <div><dt>Fallback configuration</dt><dd className="os-mono">{assignment.fallbackConfigurationId ?? "None"}</dd></div>
          </dl>}
          {receipt?.reasons.length ? <div className="mission-model-assignment__reasons" role={receipt.ready ? "status" : "alert"}>
            <strong>Readiness explanation</strong>
            <ul>{receipt.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
          </div> : null}
        </article>;
      })}
    </div>}
  </section>;
}
