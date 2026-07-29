import type {
  AutonomousPlanningSelection,
  AutonomousSpecialistCandidate,
  ReadinessCheck,
} from "../../domain/types/commandOs";
import type {
  ModelCatalog,
  ModelCatalogItem,
} from "../../domain/types/modelConfiguration";
import { MODEL_CATALOG_SNAPSHOT_MAXIMUM_AGE_MS } from "../../data/api/modelConfiguration";
import { useQuerySnapshotExpired } from "../../data/cache/querySnapshotFreshness";
import {
  Button,
  ErrorPanel,
  LoadingPanel,
  StatusPill,
} from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import {
  configurationForId,
  readableModelValue,
  uniqueModelValues,
} from "./missionModelAssignmentState";
import {
  configurationSelectableForPlanning,
  firstPlanningConfiguration,
  planningAgentIds,
  planningSelectionFromConfiguration,
  resolvedPlanningSelection,
  samePlanningSelection,
} from "./autonomousPlanningSelectionState";
import "./mission-agent-model-assignments.css";

type AgentChoice = Pick<
  AutonomousSpecialistCandidate,
  "id" | "displayName" | "role"
>;

interface AutonomousPlanningSelectionEditorProps {
  readonly idPrefix: string;
  readonly selection?: AutonomousPlanningSelection;
  readonly baselineSelection?: AutonomousPlanningSelection;
  readonly agents: readonly AgentChoice[];
  readonly catalog?: ModelCatalog;
  readonly catalogUpdatedAt: number | null;
  readonly catalogLoading: boolean;
  readonly catalogError?: Error;
  readonly readinessCheck?: ReadinessCheck;
  readonly readinessStale: boolean;
  readonly onChange: (selection: AutonomousPlanningSelection) => void;
  readonly onRestore?: () => void;
  readonly onRetryCatalog?: () => void;
}

function itemLabel(item: ModelCatalogItem): string {
  return item.modelId === item.displayName
    ? item.displayName
    : `${item.displayName} · ${item.modelId}`;
}

function planningUnavailableReason(item: ModelCatalogItem, agentId: string): string {
  if (item.enforcementMode !== "advisor_only") {
    return `${readableModelValue(item.enforcementMode)} is not an advisor-only planning path.`;
  }
  if (item.executionBoundary !== "provider_tool_calling") {
    return "This is a local execution path, not a provider-advisory planning route.";
  }
  if (!item.compatibleAgentIds.includes(agentId)) {
    return `This configuration is not declared for planning agent ${agentId}.`;
  }
  if (!item.capabilities.structuredOutput) {
    return "The provider does not attest the structured output required by the local plan compiler.";
  }
  if (item.authState !== "authenticated") {
    return `Provider authentication is ${readableModelValue(item.authState)}.`;
  }
  if (item.healthState !== "healthy") {
    return `Provider health is ${readableModelValue(item.healthState)}.`;
  }
  if (item.disclosureClass !== "public_only" && item.disclosureClass !== "sanitized_internal") {
    return "This configuration has no planning-safe public disclosure classification.";
  }
  return item.unavailableReasons.join(" ")
    || "The live catalog marks this exact planning configuration unavailable.";
}

function PlanningConfigurationFacts({
  label,
  item,
}: {
  readonly label: string;
  readonly item?: ModelCatalogItem;
}) {
  if (!item) return <div className="mission-model-assignment__empty-receipt">
    <strong>{label}</strong>
    <span>No exact configuration is available in the current live catalog.</span>
  </div>;
  return <section
    className="mission-model-assignment__facts"
    aria-label={`${label} planning configuration`}
  >
    <header>
      <div><span>{label}</span><strong>{item.providerId} · {item.displayName}</strong></div>
      <StatusPill status={item.enforcementMode}>Advisor only</StatusPill>
    </header>
    <dl>
      <div><dt>Configuration</dt><dd className="os-mono">{item.configurationId}</dd></div>
      <div><dt>Exact model</dt><dd>{item.modelId}</dd></div>
      <div><dt>Reasoning</dt><dd>{item.reasoningEffort ? readableModelValue(item.reasoningEffort) : "Provider default"}</dd></div>
      <div><dt>Authentication</dt><dd>{readableModelValue(item.authState)}</dd></div>
      <div><dt>Provider health</dt><dd>{readableModelValue(item.healthState)}</dd></div>
      <div><dt>Disclosure</dt><dd>{readableModelValue(item.disclosureClass)}</dd></div>
      <div><dt>Execution authority</dt><dd>None</dd></div>
    </dl>
  </section>;
}

export function AutonomousPlanningSelectionEditor({
  idPrefix,
  selection,
  baselineSelection,
  agents,
  catalog,
  catalogUpdatedAt,
  catalogLoading,
  catalogError,
  readinessCheck,
  readinessStale,
  onChange,
  onRestore,
  onRetryCatalog,
}: AutonomousPlanningSelectionEditorProps) {
  const current = resolvedPlanningSelection(selection);
  const catalogExpired = useQuerySnapshotExpired(
    catalog ? catalogUpdatedAt : null,
    MODEL_CATALOG_SNAPSHOT_MAXIMUM_AGE_MS,
  );
  const catalogFailure = catalogError ?? (catalogExpired
    ? new Error(
        "The cached model catalog exceeded its 15-minute trust window. Refresh it before changing the plan-construction route.",
      )
    : undefined);
  const trustedCatalog = catalogFailure ? undefined : catalog;
  const items = trustedCatalog?.items ?? [];
  const catalogAgentIds = planningAgentIds(items);
  const currentAgentId = current.route === "provider_advisory"
    ? current.agentId
    : catalogAgentIds[0] ?? "";
  const agentChoices = [...new Set([
    ...catalogAgentIds,
    ...(current.route === "provider_advisory" ? [current.agentId] : []),
  ])].map((agentId) => {
    const agent = agents.find(({ id }) => id === agentId);
    return {
      id: agentId,
      displayName: agent?.displayName ?? agentId,
      role: agent?.role ?? "Provider-advisory planning agent",
    };
  });
  const providerSelection = current.route === "provider_advisory"
    ? current
    : undefined;
  const primary = configurationForId(
    items,
    providerSelection?.primaryConfigurationId,
  );
  const fallback = configurationForId(
    items,
    providerSelection?.fallbackConfigurationId,
  );
  const primaryProviderId = primary?.providerId ?? "";
  const primaryModelId = primary?.modelId ?? "";
  const fallbackProviderId = fallback?.providerId ?? "";
  const fallbackModelId = fallback?.modelId ?? "";
  const providers = uniqueModelValues(items.map(({ providerId }) => providerId));
  const primaryProviderItems = items.filter(({ providerId }) =>
    providerId === primaryProviderId);
  const primaryModels = uniqueModelValues(
    primaryProviderItems.map(({ modelId }) => modelId),
  );
  const primaryEfforts = primaryProviderItems.filter(({ modelId }) =>
    modelId === primaryModelId);
  const fallbackProviderItems = items.filter(({ providerId }) =>
    providerId === fallbackProviderId);
  const fallbackModels = uniqueModelValues(
    fallbackProviderItems.map(({ modelId }) => modelId),
  );
  const fallbackEfforts = fallbackProviderItems.filter((item) =>
    item.modelId === fallbackModelId
    && item.configurationId !== providerSelection?.primaryConfigurationId);
  const unavailableItems = items.filter((item) =>
    !configurationSelectableForPlanning(
      item,
      currentAgentId,
      providerSelection?.disclosureClass,
    ));
  const providerRouteAvailable = agentChoices.some(({ id }) =>
    Boolean(firstPlanningConfiguration(items, id)));

  const publishPrimary = (
    agentId: string,
    next: ModelCatalogItem,
    fallbackConfigurationId = providerSelection?.fallbackConfigurationId ?? null,
  ) => {
    const fallbackItem = configurationForId(items, fallbackConfigurationId);
    onChange(planningSelectionFromConfiguration(
      agentId,
      next,
      fallbackItem
        && fallbackItem.configurationId !== next.configurationId
        && configurationSelectableForPlanning(
          fallbackItem,
          agentId,
          next.disclosureClass === "public_only"
            ? "public_only"
            : "sanitized_internal",
        )
        ? fallbackItem.configurationId
        : null,
    ));
  };

  const chooseProviderRoute = () => {
    if (providerSelection) return;
    for (const { id } of agentChoices) {
      const first = firstPlanningConfiguration(items, id);
      if (first) {
        onChange(planningSelectionFromConfiguration(id, first));
        return;
      }
    }
  };
  const chooseAgent = (agentId: string) => {
    const next = firstPlanningConfiguration(items, agentId, {
      providerId: primaryProviderId || undefined,
      modelId: primaryModelId || undefined,
      preferredReasoningEffort: primary?.reasoningEffort,
    }) ?? firstPlanningConfiguration(items, agentId);
    if (next) publishPrimary(agentId, next, null);
  };
  const choosePrimaryProvider = (providerId: string) => {
    const next = firstPlanningConfiguration(items, currentAgentId, {
      providerId,
      preferredReasoningEffort: primary?.reasoningEffort,
    });
    if (next) publishPrimary(currentAgentId, next);
  };
  const choosePrimaryModel = (modelId: string) => {
    const next = firstPlanningConfiguration(items, currentAgentId, {
      providerId: primaryProviderId,
      modelId,
      preferredReasoningEffort: primary?.reasoningEffort,
    });
    if (next) publishPrimary(currentAgentId, next);
  };
  const chooseFallbackProvider = (providerId: string) => {
    if (!providerSelection || !primary) return;
    if (!providerId) {
      onChange({ ...providerSelection, fallbackConfigurationId: null });
      return;
    }
    const next = firstPlanningConfiguration(items, currentAgentId, {
      providerId,
      disclosureClass: providerSelection.disclosureClass,
      excludedConfigurationId: primary.configurationId,
      preferredReasoningEffort: fallback?.reasoningEffort,
    });
    if (next) onChange({
      ...providerSelection,
      fallbackConfigurationId: next.configurationId,
    });
  };
  const chooseFallbackModel = (modelId: string) => {
    if (!providerSelection || !primary) return;
    const next = firstPlanningConfiguration(items, currentAgentId, {
      providerId: fallbackProviderId,
      modelId,
      disclosureClass: providerSelection.disclosureClass,
      excludedConfigurationId: primary.configurationId,
      preferredReasoningEffort: fallback?.reasoningEffort,
    });
    if (next) onChange({
      ...providerSelection,
      fallbackConfigurationId: next.configurationId,
    });
  };

  return <section
    className="mission-model-assignments mission-planning-selection"
    aria-label="Autonomous planning selection"
  >
    <header className="mission-model-assignments__header">
      <div>
        <p className="os-eyebrow">Plan-construction authority</p>
        <h3>Choose how the first plan is constructed</h3>
        <p>The local planner is deterministic and private. A provider may advise the plan only through a sanitized, structured boundary; it receives no tool or execution authority.</p>
      </div>
      {onRestore && baselineSelection && <Button
        type="button"
        variant="quiet"
        data-control-id={`${idPrefix}-planning-restore-signed`}
        disabled={samePlanningSelection(current, baselineSelection)}
        onClick={onRestore}
      >
        Restore signed planning route
      </Button>}
    </header>
    <fieldset className="os-choice-group">
      <legend>Planning route</legend>
      <label className="os-radio-card">
        <input
          type="radio"
          aria-label="Local deterministic planner"
          name={`${idPrefix}-planning-route`}
          data-control-id={`${idPrefix}-planning-route-local`}
          checked={current.route === "local_deterministic"}
          onChange={() => onChange(resolvedPlanningSelection(undefined))}
        />
        <span>
          <strong>Local deterministic planner</strong>
          <small>Build the plan inside Ti-Scale from the signed contract and scope-safe Context Pack. No mission context is sent to a public provider.</small>
        </span>
      </label>
      <label className="os-radio-card">
        <input
          type="radio"
          aria-label="Provider-advisory planner"
          name={`${idPrefix}-planning-route`}
          data-control-id={`${idPrefix}-planning-route-provider`}
          disabled={!trustedCatalog || !providerRouteAvailable}
          checked={current.route === "provider_advisory"}
          onChange={chooseProviderRoute}
        />
        <span>
          <strong>Provider-advisory planner</strong>
          <small>An authenticated advisor-only model proposes structured planning choices. The local runtime validates and compiles them; the model cannot execute tools.</small>
        </span>
      </label>
    </fieldset>
    {catalogLoading && <LoadingPanel label="Loading advisor-only planning models" />}
    {catalogFailure && <ErrorPanel
      title="Planning model catalog is unavailable"
      error={catalogFailure}
      retryControlId={`${idPrefix}-planning-catalog-retry`}
      {...(onRetryCatalog ? { onRetry: onRetryCatalog } : {})}
    />}
    {trustedCatalog && !providerRouteAvailable && <div className="os-empty">
      <strong>No advisor-only planning model is ready</strong>
      <p>The local deterministic planner remains available. Connect an authenticated, healthy provider model that supports structured output and is classified advisor only to enable provider-backed planning.</p>
    </div>}
    {trustedCatalog && providerSelection && <article className="mission-model-assignment">
      <header className="mission-model-assignment__heading">
        <div>
          <p className="os-eyebrow">Pinned planning model</p>
          <h4>{agentChoices.find(({ id }) => id === currentAgentId)?.displayName ?? currentAgentId}</h4>
          <p>Advisor only · no execution authority</p>
        </div>
        <div className="mission-model-assignment__state">
          <StatusPill status={
            readinessStale
              ? "pending_review"
              : readinessCheck?.status === "pass"
                ? "ready"
                : "blocked"
          }>
            {readinessStale
              ? "Review required"
              : readinessCheck?.status === "pass"
                ? "Ready"
                : "Not ready"}
          </StatusPill>
          <span>{readinessCheck?.impact ?? "Run readiness to validate the exact advisor-only route."}</span>
        </div>
      </header>
      <div className="mission-model-assignment__selectors">
        <label>
          <span>Planning agent</span>
          <TitaniumSelect
            data-control-id={`${idPrefix}-planning-agent`}
            aria-label="Autonomous planning agent"
            value={currentAgentId}
            onChange={(event) => chooseAgent(event.target.value)}
          >
            {agentChoices.map((agent) => <option
              key={agent.id}
              value={agent.id}
              disabled={!firstPlanningConfiguration(items, agent.id)}
            >{agent.displayName} · {agent.role}</option>)}
          </TitaniumSelect>
        </label>
        <label>
          <span>Primary provider</span>
          <TitaniumSelect
            data-control-id={`${idPrefix}-planning-primary-provider`}
            aria-label="Autonomous planning primary provider"
            value={primaryProviderId}
            onChange={(event) => choosePrimaryProvider(event.target.value)}
          >
            <option value="" disabled>Choose an advisor-only provider</option>
            {providers.map((providerId) => <option
              key={providerId}
              value={providerId}
              disabled={!firstPlanningConfiguration(items, currentAgentId, {
                providerId,
              })}
            >{providerId}</option>)}
          </TitaniumSelect>
        </label>
        <label>
          <span>Primary model</span>
          <TitaniumSelect
            data-control-id={`${idPrefix}-planning-primary-model`}
            aria-label="Autonomous planning primary model"
            value={primaryModelId}
            disabled={!primaryProviderId}
            onChange={(event) => choosePrimaryModel(event.target.value)}
          >
            <option value="" disabled>Choose an exact planning model</option>
            {primaryModels.map((modelId) => {
              const representative = primaryProviderItems.find((item) =>
                item.modelId === modelId)!;
              return <option
                key={modelId}
                value={modelId}
                disabled={!firstPlanningConfiguration(items, currentAgentId, {
                  providerId: primaryProviderId,
                  modelId,
                })}
              >{itemLabel(representative)}</option>;
            })}
          </TitaniumSelect>
        </label>
        <label>
          <span>Reasoning effort</span>
          <TitaniumSelect
            data-control-id={`${idPrefix}-planning-primary-reasoning`}
            aria-label="Autonomous planning primary reasoning effort"
            value={providerSelection.primaryConfigurationId}
            disabled={!primaryModelId}
            onChange={(event) => {
              const next = configurationForId(items, event.target.value);
              if (next) publishPrimary(currentAgentId, next);
            }}
          >
            <option value="" disabled>Choose reasoning effort</option>
            {primaryEfforts.map((item) => <option
              key={item.configurationId}
              value={item.configurationId}
              disabled={!configurationSelectableForPlanning(item, currentAgentId)}
            >{item.reasoningEffort ? readableModelValue(item.reasoningEffort) : "Provider default"}</option>)}
          </TitaniumSelect>
        </label>
        <label>
          <span>Fallback provider</span>
          <TitaniumSelect
            data-control-id={`${idPrefix}-planning-fallback-provider`}
            aria-label="Autonomous planning fallback provider"
            value={fallbackProviderId}
            disabled={!primary}
            onChange={(event) => chooseFallbackProvider(event.target.value)}
          >
            <option value="">No automatic fallback</option>
            {providers.map((providerId) => <option
              key={providerId}
              value={providerId}
              disabled={!firstPlanningConfiguration(items, currentAgentId, {
                providerId,
                disclosureClass: providerSelection.disclosureClass,
                excludedConfigurationId: primary?.configurationId,
              })}
            >{providerId}</option>)}
          </TitaniumSelect>
        </label>
        <label>
          <span>Fallback model</span>
          <TitaniumSelect
            data-control-id={`${idPrefix}-planning-fallback-model`}
            aria-label="Autonomous planning fallback model"
            value={fallbackModelId}
            disabled={!fallbackProviderId}
            onChange={(event) => chooseFallbackModel(event.target.value)}
          >
            <option value="" disabled>Choose an exact fallback model</option>
            {fallbackModels.map((modelId) => {
              const representative = fallbackProviderItems.find((item) =>
                item.modelId === modelId
                && item.configurationId !== primary?.configurationId);
              if (!representative) return null;
              return <option
                key={modelId}
                value={modelId}
                disabled={!firstPlanningConfiguration(items, currentAgentId, {
                  providerId: fallbackProviderId,
                  modelId,
                  disclosureClass: providerSelection.disclosureClass,
                  excludedConfigurationId: primary?.configurationId,
                })}
              >{itemLabel(representative)}</option>;
            })}
          </TitaniumSelect>
        </label>
        <label>
          <span>Fallback reasoning effort</span>
          <TitaniumSelect
            data-control-id={`${idPrefix}-planning-fallback-reasoning`}
            aria-label="Autonomous planning fallback reasoning effort"
            value={providerSelection.fallbackConfigurationId ?? ""}
            disabled={!fallbackModelId}
            onChange={(event) => onChange({
              ...providerSelection,
              fallbackConfigurationId: event.target.value,
            })}
          >
            <option value="" disabled>Choose fallback reasoning effort</option>
            {fallbackEfforts.map((item) => <option
              key={item.configurationId}
              value={item.configurationId}
              disabled={!configurationSelectableForPlanning(
                item,
                currentAgentId,
                providerSelection.disclosureClass,
              )}
            >{item.reasoningEffort ? readableModelValue(item.reasoningEffort) : "Provider default"}</option>)}
          </TitaniumSelect>
        </label>
      </div>
      <div className="mission-model-assignment__receipts">
        <PlanningConfigurationFacts label="Primary planning model" item={primary} />
        <PlanningConfigurationFacts label="Fallback planning model" item={fallback} />
      </div>
      {(!primary || (
        providerSelection.fallbackConfigurationId !== null && !fallback
      )) && <div className="mission-model-assignment__reasons" role="alert">
        <strong>Catalog drift blocks review</strong>
        <p>The signed planning configuration is absent from the current live catalog. Keep the source selection unchanged for audit, or deliberately choose a current advisor-only route and review a new contract digest.</p>
      </div>}
      {unavailableItems.length > 0 && <section
        className="mission-model-assignment__unavailable"
        aria-label="Unavailable planning model paths"
        data-control-id={`${idPrefix}-planning-unavailable-paths`}
      >
        <strong>Unavailable live-catalog planning paths</strong>
        <ul>{unavailableItems.map((item) => <li key={item.configurationId}>
          <span>{item.providerId} · {itemLabel(item)}</span>
          <small>{planningUnavailableReason(item, currentAgentId)}</small>
        </li>)}</ul>
      </section>}
    </article>}
    <p className="mission-model-assignments__policy">
      Planning authority and execution authority are separate signed fields. An advisor-only planning model can suggest structure, but specialists execute only through their own enforced model assignments and the contract tool boundary.
    </p>
  </section>;
}

export function AutonomousPlanningSelectionReview({
  selection,
  catalog,
  readinessCheck,
}: {
  readonly selection?: AutonomousPlanningSelection;
  readonly catalog?: ModelCatalog;
  readonly readinessCheck?: ReadinessCheck;
}) {
  const current = resolvedPlanningSelection(selection);
  const primary = current.route === "provider_advisory"
    ? configurationForId(catalog?.items ?? [], current.primaryConfigurationId)
    : undefined;
  const fallback = current.route === "provider_advisory"
    ? configurationForId(catalog?.items ?? [], current.fallbackConfigurationId)
    : undefined;
  return <section className="mission-model-review" aria-label="Signed planning route">
    <header>
      <p className="os-eyebrow">Pinned plan construction</p>
      <h3>Signed planning route</h3>
      <p>This choice constructs the plan only. It never grants provider tool access or replaces the exact execution assignments below.</p>
    </header>
    {current.route === "local_deterministic"
      ? <article className="mission-model-review__item">
          <div className="mission-model-review__heading">
            <div><h4>Local deterministic planner</h4><p>No provider disclosure · no execution authority</p></div>
            <StatusPill status={readinessCheck?.status === "fail" ? "blocked" : "ready"} />
          </div>
          <dl className="mission-model-review__ids">
            <div><dt>Planner</dt><dd className="os-mono">{current.plannerId}</dd></div>
            <div><dt>Disclosure</dt><dd>Local only</dd></div>
            <div><dt>Execution authority</dt><dd>None</dd></div>
          </dl>
          {readinessCheck && <p>{readinessCheck.impact}</p>}
        </article>
      : <article className="mission-model-review__item">
          <div className="mission-model-review__heading">
            <div><h4>{current.agentId}</h4><p>Provider advisory · structured planning only</p></div>
            <StatusPill status={readinessCheck?.status === "pass" ? "ready" : "blocked"} />
          </div>
          <dl className="mission-model-review__ids">
            <div><dt>Primary provider / model</dt><dd>{primary ? `${primary.providerId} · ${primary.displayName}` : current.primaryConfigurationId}</dd></div>
            <div><dt>Primary reasoning</dt><dd>{primary?.reasoningEffort ? readableModelValue(primary.reasoningEffort) : "Provider default or catalog unavailable"}</dd></div>
            <div><dt>Fallback provider / model</dt><dd>{current.fallbackConfigurationId === null ? "None" : fallback ? `${fallback.providerId} · ${fallback.displayName}` : current.fallbackConfigurationId}</dd></div>
            <div><dt>Disclosure</dt><dd>{readableModelValue(current.disclosureClass)}</dd></div>
            <div><dt>Enforcement</dt><dd>Advisor only</dd></div>
            <div><dt>Execution authority</dt><dd>None</dd></div>
          </dl>
          {readinessCheck && <p>{readinessCheck.impact}</p>}
        </article>}
  </section>;
}
