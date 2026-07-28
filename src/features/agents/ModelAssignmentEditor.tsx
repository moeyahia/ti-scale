import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  fetchModelCatalog,
  fetchModelConfigurations,
  fetchModelPreferences,
  fetchModelResolution,
  MODEL_CATALOG_SNAPSHOT_MAXIMUM_AGE_MS,
  updateModelPreference,
} from "../../data/api/modelConfiguration";
import { operationsApi } from "../../data/api/operations";
import { useNavigation } from "../../app/router/navigation";
import { useQuery, useQueryCache } from "../../data/cache/QueryProvider";
import { useQuerySnapshotExpired } from "../../data/cache/querySnapshotFreshness";
import { Button, ButtonLink, Card, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import type {
  ModelCatalogItem,
  ModelPreferenceScope,
  ModelResolutionResult,
} from "../../domain/types/modelConfiguration";
import { formatTime, KeyValueGrid } from "../runs/OperationalSurface";
import {
  catalogItemSelectableForAgent,
  configurationReceiptLabel,
  fallbackSelectionIsValid,
  reconcileSavedCatalogReceipt,
} from "./modelAssignmentCatalogRefresh";
import "./model-assignment.css";

type ModelAssignmentScope =
  | {
      readonly type: "global";
      readonly id: "global";
      readonly agentId: null;
      readonly label: "Workspace default";
    }
  | {
      readonly type: "agent";
      readonly id: string;
      readonly agentId: string;
      readonly label: string;
    };

export interface ModelAssignmentEditorProps {
  readonly scope: ModelAssignmentScope;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function readable(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/gu, (character) => character.toUpperCase());
}

function modelOptionLabel(item: ModelCatalogItem): string {
  return `${item.displayName}${item.modelId === item.displayName ? "" : ` · ${item.modelId}`}`;
}

function exactConfigurationLabel(item: ModelCatalogItem): string {
  const effort = item.reasoningEffort ? ` · ${readable(item.reasoningEffort)} reasoning` : "";
  return `${item.providerId} · ${item.displayName}${effort}`;
}

function formatContextLimit(value: number | null): string {
  if (value === null) return "Not reported";
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

function enforcementExplanation(
  mode: ModelCatalogItem["enforcementMode"],
): string {
  if (mode === "enforced_executor") {
    return "The local runtime can enforce scope and tool policy for this model path.";
  }
  if (mode === "observe_only_executor") {
    return "The runtime can observe this model path, but cannot guarantee every action is locally gated.";
  }
  if (mode === "advisor_only") {
    return "This model may plan, explain, or critique, but it cannot execute an Autonomous contract.";
  }
  return "This model path is not currently callable.";
}

function executionBoundaryLabel(
  boundary: ModelCatalogItem["executionBoundary"],
): string {
  return boundary === "local_deterministic_policy"
    ? "Locally enforced deterministic policy"
    : "Provider tool-calling";
}

function selectableForScope(
  item: ModelCatalogItem,
  scope: ModelAssignmentScope,
  workspaceAgentIds: readonly string[],
): boolean {
  return catalogItemSelectableForAgent(
    item,
    scope.agentId,
    workspaceAgentIds,
  );
}

function assignmentReadiness(
  item: ModelCatalogItem | undefined,
  scope: ModelAssignmentScope,
  workspaceAgentIds: readonly string[],
): { readonly label: string; readonly status: string } {
  if (!item) return { label: "Not configured", status: "unconfigured" };
  if (
    !selectableForScope(item, scope, workspaceAgentIds)
    || item.enforcementMode === "unavailable"
  ) {
    return { label: "Unavailable", status: "unavailable" };
  }
  if (item.enforcementMode === "enforced_executor") {
    return { label: "Enforced executor", status: item.enforcementMode };
  }
  if (item.enforcementMode === "observe_only_executor") {
    return { label: "Observe only", status: item.enforcementMode };
  }
  return { label: "Advisor only", status: item.enforcementMode };
}

function firstSelectable(
  items: readonly ModelCatalogItem[],
  scope: ModelAssignmentScope,
  workspaceAgentIds: readonly string[],
): ModelCatalogItem | undefined {
  return items.find((item) =>
    selectableForScope(item, scope, workspaceAgentIds));
}

function findConfiguration(
  items: readonly ModelCatalogItem[],
  id: string,
): ModelCatalogItem | undefined {
  return items.find((item) => item.configurationId === id);
}

function currentSourceDescription(
  scope: ModelAssignmentScope,
  resolution: ModelResolutionResult["resolution"] | undefined,
  hasExactPreference: boolean,
): string {
  if (hasExactPreference) {
    return scope.type === "global"
      ? "Workspace default"
      : `${scope.label} override`;
  }
  if (!resolution) return "No model preference configured";
  return `Inherited from ${readable(resolution.source.scopeType)}`;
}

export function ModelAssignmentEditor({ scope }: ModelAssignmentEditorProps) {
  const location = useNavigation();
  const cache = useQueryCache();
  const catalog = useQuery("model-catalog", fetchModelCatalog, { staleTime: 5_000 });
  const workspaceRoster = useQuery(
    "agents:canonical-product-roster",
    (signal) => operationsApi.agents({ limit: 100 }, signal),
    { staleTime: 5_000 },
  );
  const workspaceAgentIds = useMemo(
    () => (workspaceRoster.data?.items ?? [])
      .filter(({ id }) => id !== "Commander")
      .map(({ id }) => id)
      .sort((left, right) => left.localeCompare(right)),
    [workspaceRoster.data],
  );
  const workspaceRosterBlockingError = scope.type !== "global"
    ? undefined
    : workspaceRoster.error
      ?? (workspaceRoster.data?.nextCursor
        ? new Error(
            "The canonical specialist roster did not fit in one verified page. Ti-Scale cannot prove that a workspace default covers every inheriting specialist.",
          )
        : workspaceRoster.data && workspaceAgentIds.length === 0
          ? new Error(
              "No canonical specialist roster is available. Configure specialists before assigning a workspace default.",
            )
          : undefined);
  const preferenceKey = `model-preference:${scope.type}:${scope.id}:${scope.agentId ?? "all"}`;
  const preferences = useQuery(
    preferenceKey,
    (signal) => fetchModelPreferences({
      scopeType: scope.type,
      scopeId: scope.id,
      agentId: scope.agentId,
    }, signal),
    { staleTime: 5_000 },
  );
  const resolution = useQuery(
    `model-resolution:${scope.agentId ?? "global"}`,
    (signal) => scope.agentId
      ? fetchModelResolution({ agentId: scope.agentId }, signal)
      : Promise.resolve(null),
    { staleTime: 5_000 },
  );
  const catalogExpired = useQuerySnapshotExpired(
    catalog.data ? catalog.updatedAt : null,
    MODEL_CATALOG_SNAPSHOT_MAXIMUM_AGE_MS,
  );
  const catalogBlockingError = catalog.error ?? (catalogExpired
    ? new Error(
        "The cached model catalog exceeded its 15-minute trust window. Refresh the live catalog before saving a model assignment.",
      )
    : undefined);
  const trustedCatalog = catalogBlockingError ? undefined : catalog.data;

  const exactPreference = preferences.data?.items[0];
  const inheritedResolution = resolution.data?.resolution;
  const assignmentSemantics = resolution.data?.assignmentSemantics;
  const savedConfigurationIds = scope.type === "global" && exactPreference
    ? [
        exactPreference.primaryConfigurationId,
        ...(exactPreference.fallbackConfigurationId
          ? [exactPreference.fallbackConfigurationId]
          : []),
      ]
    : [];
  const savedConfigurationsKey = [
    "model-configurations",
    scope.type,
    scope.id,
    ...savedConfigurationIds,
  ].join(":");
  const savedConfigurations = useQuery(
    savedConfigurationsKey,
    (signal) => savedConfigurationIds.length
      ? fetchModelConfigurations(savedConfigurationIds, signal)
      : Promise.resolve({ schemaVersion: "2.4" as const, items: [] }),
    { staleTime: 5_000 },
  );
  const needsSavedConfigurations = savedConfigurationIds.length > 0;
  const items = trustedCatalog?.items ?? [];
  const catalogObservedAt = trustedCatalog?.observedAt ?? null;
  const baselinePrimaryId = exactPreference?.primaryConfigurationId
    ?? inheritedResolution?.primaryConfiguration.id
    ?? "";
  const baselineFallbackId = exactPreference?.fallbackConfigurationId
    ?? inheritedResolution?.fallbackConfiguration?.id
    ?? "";
  const savedPrimaryConfiguration = inheritedResolution?.primaryConfiguration
    ?? savedConfigurations.data?.items.find((item) =>
      item.id === baselinePrimaryId);
  const savedFallbackConfiguration = inheritedResolution?.fallbackConfiguration
    ?? savedConfigurations.data?.items.find((item) =>
      item.id === baselineFallbackId);
  const primaryReceipt = reconcileSavedCatalogReceipt(
    items,
    baselinePrimaryId,
    savedPrimaryConfiguration,
    scope.agentId,
    workspaceAgentIds,
  );
  const fallbackReceipt = reconcileSavedCatalogReceipt(
    items,
    baselineFallbackId,
    savedFallbackConfiguration,
    scope.agentId,
    workspaceAgentIds,
  );
  const currentPrimary = primaryReceipt.item;
  const currentFallback = fallbackReceipt.item;
  const editablePrimaryId = currentPrimary?.configurationId
    ?? baselinePrimaryId;
  const editableFallbackId = currentFallback?.configurationId
    ?? baselineFallbackId;
  const sourceVersion = exactPreference?.version ?? 0;
  const hydrationKey = [
    scope.type,
    scope.id,
    sourceVersion,
    baselinePrimaryId,
    baselineFallbackId,
    editablePrimaryId,
    editableFallbackId,
    catalogObservedAt ?? "no-catalog",
  ].join(":");

  const [hydratedFrom, setHydratedFrom] = useState("");
  const [primaryId, setPrimaryId] = useState("");
  const [fallbackId, setFallbackId] = useState("");
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<Error>();
  const [savedMessage, setSavedMessage] = useState("");

  useEffect(() => {
    if (
      !trustedCatalog
      || !preferences.data
      || (scope.agentId && resolution.isLoading)
      || (needsSavedConfigurations && savedConfigurations.isLoading)
    ) return;
    if (hydratedFrom === hydrationKey) return;
    setPrimaryId(editablePrimaryId);
    setFallbackId(editableFallbackId);
    setReason("");
    setSaveError(undefined);
    setHydratedFrom(hydrationKey);
  }, [
    editableFallbackId,
    editablePrimaryId,
    hydratedFrom,
    hydrationKey,
    preferences.data,
    resolution.isLoading,
    savedConfigurations.isLoading,
    scope.agentId,
    needsSavedConfigurations,
    trustedCatalog,
  ]);

  const selectedPrimary = findConfiguration(items, primaryId);
  const selectedFallback = findConfiguration(items, fallbackId);
  const readiness = assignmentReadiness(
    selectedPrimary,
    scope,
    workspaceAgentIds,
  );
  const providers = useMemo(() => unique(items.map((item) => item.providerId)).sort(), [items]);
  const selectedProvider = selectedPrimary?.providerId ?? "";
  const providerItems = items.filter((item) => item.providerId === selectedProvider);
  const models = unique(providerItems.map((item) => item.modelId));
  const selectedModel = selectedPrimary?.modelId ?? "";
  const effortItems = providerItems.filter((item) => item.modelId === selectedModel);
  const changed = primaryId !== baselinePrimaryId || fallbackId !== baselineFallbackId;
  const catalogRefreshStaged = primaryReceipt.state === "staged"
    || fallbackReceipt.state === "staged";
  const stagedEquivalentStillSelected = hydratedFrom !== hydrationKey || (
    (
      primaryReceipt.state !== "staged"
      || primaryId === primaryReceipt.item?.configurationId
    )
    && (
      fallbackReceipt.state !== "staged"
      || fallbackId === fallbackReceipt.item?.configurationId
    )
  );
  const catalogRefreshUnresolved = primaryReceipt.state === "unresolved"
    || fallbackReceipt.state === "unresolved";
  const canSave = Boolean(
    selectedPrimary
    && selectableForScope(selectedPrimary, scope, workspaceAgentIds)
    && fallbackSelectionIsValid(
      items,
      fallbackId,
      scope.agentId,
      workspaceAgentIds,
    )
    && changed
    && reason.trim().length >= 3
    && fallbackId !== primaryId
    && !catalogBlockingError
    && !saving,
  );
  const loading = catalog.isLoading || preferences.isLoading || Boolean(
    scope.agentId && resolution.isLoading,
  ) || Boolean(
    needsSavedConfigurations && savedConfigurations.isLoading,
  ) || Boolean(
    scope.type === "global" && workspaceRoster.isLoading,
  );

  const editorId = scope.type === "agent"
    ? "agent-model-configuration"
    : "workspace-model-configuration";
  const controlPrefix = scope.type === "agent" ? "agents" : "system";

  useEffect(() => {
    if (
      scope.type !== "agent"
      || location.hash !== `#${editorId}`
      || typeof window === "undefined"
      || loading
    ) return;
    let observer: MutationObserver | undefined;
    const focusEditor = (): boolean => {
      const target = document.getElementById(editorId);
      if (!target || target.closest("[inert], fieldset:disabled")) return false;
      target.scrollIntoView({ behavior: "auto", block: "start" });
      target.focus({ preventScroll: true });
      return document.activeElement === target;
    };
    const frame = window.requestAnimationFrame(() => {
      if (focusEditor()) return;
      const target = document.getElementById(editorId);
      const boundary = target?.closest("[data-ti-boot-boundary]") ?? document.documentElement;
      observer = new MutationObserver(() => {
        if (focusEditor()) observer?.disconnect();
      });
      observer.observe(boundary, {
        attributes: true,
        attributeFilter: ["disabled", "inert"],
        subtree: true,
      });
      if (focusEditor()) observer.disconnect();
    });
    return () => {
      window.cancelAnimationFrame(frame);
      observer?.disconnect();
    };
  }, [editorId, loading, location.hash, location.pathname, scope.id, scope.type]);

  const selectProvider = (providerId: string) => {
    setSavedMessage("");
    setSaveError(undefined);
    const next = firstSelectable(
      items.filter((item) => item.providerId === providerId),
      scope,
      workspaceAgentIds,
    );
    setPrimaryId(next?.configurationId ?? "");
    if (fallbackId === next?.configurationId) setFallbackId("");
  };

  const selectModel = (modelId: string) => {
    setSavedMessage("");
    setSaveError(undefined);
    const candidates = items.filter((item) => (
      item.providerId === selectedProvider && item.modelId === modelId
    ));
    const matchingEffort = candidates.find((item) => (
      selectableForScope(item, scope, workspaceAgentIds)
      && item.reasoningEffort === selectedPrimary?.reasoningEffort
    ));
    const next = matchingEffort
      ?? firstSelectable(candidates, scope, workspaceAgentIds);
    setPrimaryId(next?.configurationId ?? "");
    if (fallbackId === next?.configurationId) setFallbackId("");
  };

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!canSave || !selectedPrimary) return;
    setSaving(true);
    setSaveError(undefined);
    setSavedMessage("");
    try {
      const result = await updateModelPreference(
        scope.type as ModelPreferenceScope,
        scope.id,
        {
          agentId: scope.agentId,
          primaryConfigurationId: selectedPrimary.configurationId,
          fallbackConfigurationId: fallbackId || null,
          expectedVersion: sourceVersion,
          reason: reason.trim(),
        },
      );
      setHydratedFrom("");
      cache.invalidate(preferenceKey);
      if (scope.agentId) cache.invalidate(`model-resolution:${scope.agentId}`);
      else cache.invalidatePrefix("model-resolution:");
      setSavedMessage(
        `Model assignment version ${result.preference.version} saved. New runs will pin this exact configuration.`,
      );
    } catch (error) {
      setSaveError(error instanceof Error
        ? error
        : new Error("The model assignment could not be saved"));
    } finally {
      setSaving(false);
    }
  };

  const loadError = catalogBlockingError
    ?? preferences.error
    ?? resolution.error
    ?? workspaceRosterBlockingError
    ?? (needsSavedConfigurations ? savedConfigurations.error : undefined);

  return (
    <Card
      id={editorId}
      className="model-assignment"
      aria-label={`${scope.label} model configuration`}
      tabIndex={-1}
    >
      <div className="os-card-heading">
        <div>
          <p className="os-eyebrow">LLM assignment</p>
          <h2>{scope.type === "global" ? "Default model configuration" : "Provider and model"}</h2>
          <p>
            {scope.type === "global"
              ? "This is the fail-closed fallback for agents without a more specific assignment."
              : "Choose the exact provider, model, reasoning effort, and fallback used by this specialist for execution assignments."}
          </p>
        </div>
        <StatusPill status={readiness.status}>
          {readiness.label}
        </StatusPill>
      </div>
      <p className="model-assignment__authority-note" role="note">
        Model choice controls reasoning and provider routing. It does not create
        a missing specialist tool binding or grant execution authority.
        Observe-only and advisor-only paths can support guidance, while an
        Autonomous executor still requires a current locally enforced runtime
        binding. Autonomous planning uses a separate route reviewed in each
        mission contract.
      </p>

      {loading && <LoadingPanel label="Loading live model catalog and assignment" />}
      {loadError && (
        <ErrorPanel
          title="Model configuration is unavailable"
          error={loadError}
          retryControlId={`${controlPrefix}-model-load-retry`}
          onRetry={() => {
            catalog.refresh();
            preferences.refresh();
            resolution.refresh();
            if (scope.type === "global") workspaceRoster.refresh();
            if (needsSavedConfigurations) savedConfigurations.refresh();
          }}
        />
      )}

      {trustedCatalog && preferences.data && !loading && !loadError && (
        <>
          <div className="model-assignment__source">
            <span>Resolved source</span>
            <strong>{currentSourceDescription(scope, inheritedResolution, Boolean(exactPreference))}</strong>
            {exactPreference && <small>Preference version {exactPreference.version} · updated {formatTime(exactPreference.updatedAt)}</small>}
            {exactPreference && (
              <small className="model-assignment__saved-reason">
                <strong>Saved rationale:</strong> {exactPreference.resolutionReason}
              </small>
            )}
            {savedPrimaryConfiguration && (
              <small className="model-assignment__configured-receipt">
                <strong>Saved primary receipt:</strong>{" "}
                {configurationReceiptLabel(
                  savedPrimaryConfiguration,
                )}
              </small>
            )}
            {savedFallbackConfiguration && (
              <small className="model-assignment__configured-receipt">
                <strong>Saved fallback receipt:</strong>{" "}
                {configurationReceiptLabel(
                  savedFallbackConfiguration,
                )}
              </small>
            )}
            {!exactPreference && inheritedResolution && (
              <small>
                Preference version {inheritedResolution.source.preferenceVersion} · resolved {formatTime(inheritedResolution.resolvedAt)}
              </small>
            )}
            {!exactPreference && !inheritedResolution && scope.type === "agent" && (
              <small>Set this specialist directly or configure the workspace default below.</small>
            )}
            {!exactPreference && !inheritedResolution && scope.type === "agent" && (
              <ButtonLink
                href="/system/settings"
                variant="quiet"
                data-control-id="agent-model-open-workspace-default"
              >
                Open workspace model settings
              </ButtonLink>
            )}
          </div>

          {catalogRefreshStaged && (
            <p
              className="model-assignment__catalog-refresh"
              data-model-catalog-refresh={stagedEquivalentStillSelected
                ? "staged"
                : "staged-alternative"}
              role="status"
            >
              {stagedEquivalentStillSelected
                ? <>
                    The saved assignment uses an older provider-attestation
                    receipt. Ti-Scale staged the single matching live provider,
                    model, reasoning effort, and execution boundary below.
                    Review it, add a reason, and save to update future runs.
                    Existing run pins stay unchanged.
                  </>
                : <>
                    A matching current receipt exists, but this draft now
                    selects a different route. Saving applies the provider,
                    model, reasoning effort, and fallback currently shown;
                    it does not merely refresh the older receipt. Existing run
                    pins stay unchanged.
                  </>}
            </p>
          )}
          {catalogRefreshUnresolved && (
            <p
              className="os-state-remediation"
              data-model-catalog-refresh="unresolved"
              role="status"
            >
              The saved assignment is not in the current live catalog, and no
              single equivalent route could be proven. Choose a current
              provider, exact model, reasoning effort, and fallback before
              saving. Existing run pins stay unchanged.
            </p>
          )}

          {assignmentSemantics && (
            <section
              className="model-assignment__semantics"
              aria-label={`${scope.label} model assignment semantics`}
            >
              <KeyValueGrid items={[
                { label: "Assignment purpose", value: "Specialist execution" },
                { label: "Preference order", value: "Workspace → agent → mission → run → step" },
                { label: "Saved change applies to", value: "Future model resolutions only" },
                { label: "Active-run assignment", value: "Immutable pinned receipt" },
                { label: "Autonomous planning route", value: "Reviewed in the mission contract" },
              ]} />
              <p className="os-muted">
                Purpose contract: {readable(assignmentSemantics.purpose)}. A
                planning advisor is selected separately and cannot gain
                execution authority from this preference.
              </p>
            </section>
          )}

          {items.length === 0 ? (
            <div className="os-empty">
              <strong>No live model configurations were reported</strong>
              <p>Connect and attest a provider before assigning a model. Ti-Scale will not invent a catalog entry.</p>
            </div>
          ) : (
            <form className="model-assignment__form" onSubmit={save}>
              <div className="model-assignment__selectors">
                <label>
                  <span>Provider</span>
                  <TitaniumSelect
                    data-control-id={`${controlPrefix}-model-provider`}
                    aria-label={`${scope.label} provider`}
                    value={selectedProvider}
                    onChange={(event) => selectProvider(event.target.value)}
                  >
                    <option value="" disabled>Choose an authenticated provider</option>
                    {providers.map((provider) => {
                      const available = items.some((item) => (
                        item.providerId === provider
                        && selectableForScope(item, scope, workspaceAgentIds)
                      ));
                      return <option key={provider} value={provider} disabled={!available}>{provider}{available ? "" : " — unavailable"}</option>;
                    })}
                  </TitaniumSelect>
                </label>

                <label>
                  <span>Primary model</span>
                  <TitaniumSelect
                    data-control-id={`${controlPrefix}-model-primary`}
                    aria-label={`${scope.label} primary model`}
                    value={selectedModel}
                    disabled={!selectedProvider}
                    onChange={(event) => selectModel(event.target.value)}
                  >
                    <option value="" disabled>Choose an exact model</option>
                    {models.map((modelId) => {
                      const modelItems = providerItems.filter((item) => item.modelId === modelId);
                      const representative = modelItems[0]!;
                      const available = modelItems.some((item) =>
                        selectableForScope(item, scope, workspaceAgentIds));
                      return <option key={modelId} value={modelId} disabled={!available}>{modelOptionLabel(representative)}{available ? "" : " — unavailable"}</option>;
                    })}
                  </TitaniumSelect>
                </label>

                <label>
                  <span>Reasoning effort</span>
                  <TitaniumSelect
                    data-control-id={`${controlPrefix}-model-reasoning`}
                    aria-label={`${scope.label} reasoning effort`}
                    value={primaryId}
                    disabled={!selectedModel}
                    onChange={(event) => {
                      setSavedMessage("");
                      setSaveError(undefined);
                      setPrimaryId(event.target.value);
                      if (fallbackId === event.target.value) setFallbackId("");
                    }}
                  >
                    <option value="" disabled>Choose reasoning effort</option>
                    {effortItems.map((item) => (
                      <option
                        key={item.configurationId}
                        value={item.configurationId}
                        disabled={!selectableForScope(
                          item,
                          scope,
                          workspaceAgentIds,
                        )}
                      >
                        {item.reasoningEffort ? readable(item.reasoningEffort) : "Provider default"}
                        {selectableForScope(item, scope, workspaceAgentIds)
                          ? ""
                          : scope.agentId
                            ? " — unavailable for this agent"
                            : " — unavailable"}
                      </option>
                    ))}
                  </TitaniumSelect>
                </label>

                <label>
                  <span>Fallback configuration</span>
                  <TitaniumSelect
                    data-control-id={`${controlPrefix}-model-fallback`}
                    aria-label={`${scope.label} fallback model`}
                    value={fallbackId}
                    onChange={(event) => {
                      setSavedMessage("");
                      setSaveError(undefined);
                      setFallbackId(event.target.value);
                    }}
                  >
                    <option value="">No automatic fallback</option>
                    {items.map((item) => (
                      <option
                        key={item.configurationId}
                        value={item.configurationId}
                        disabled={
                          !selectableForScope(item, scope, workspaceAgentIds)
                          || item.configurationId === primaryId
                        }
                      >
                        {exactConfigurationLabel(item)}
                        {selectableForScope(item, scope, workspaceAgentIds)
                          ? ""
                          : ` — ${item.unavailableReasons.join("; ") || (scope.agentId ? "not declared for this agent" : "unavailable")}`}
                      </option>
                    ))}
                  </TitaniumSelect>
                </label>
              </div>

              {selectedPrimary && (
                <div className="model-assignment__receipt">
                  <div className="os-card-heading">
                    <div><p className="os-eyebrow">Live catalog receipt</p><h3>{selectedPrimary.displayName}</h3></div>
                    <StatusPill status={selectedPrimary.enforcementMode}>
                      {readable(selectedPrimary.enforcementMode)}
                    </StatusPill>
                  </div>
                  <KeyValueGrid items={[
                    { label: "Configuration ID", value: selectedPrimary.configurationId },
                    { label: "Execution boundary", value: executionBoundaryLabel(selectedPrimary.executionBoundary) },
                    { label: "Authentication", value: readable(selectedPrimary.authState) },
                    { label: "Provider health", value: readable(selectedPrimary.healthState) },
                    { label: "Fallback assignment", value: selectedFallback ? exactConfigurationLabel(selectedFallback) : "Not selected" },
                    { label: "Fallback authentication", value: selectedFallback ? readable(selectedFallback.authState) : "Not selected" },
                    { label: "Fallback provider health", value: selectedFallback ? readable(selectedFallback.healthState) : "Not selected" },
                    { label: "Fallback enforcement", value: selectedFallback ? readable(selectedFallback.enforcementMode) : "Not selected" },
                    { label: "Fallback execution boundary", value: selectedFallback ? executionBoundaryLabel(selectedFallback.executionBoundary) : "Not selected" },
                    { label: "Fallback data disclosure", value: selectedFallback ? readable(selectedFallback.disclosureClass) : "Not selected" },
                    { label: "Fallback compatible specialists", value: selectedFallback ? selectedFallback.compatibleAgentIds.join(", ") || "None declared" : "Not selected" },
                    { label: "Context limit", value: formatContextLimit(selectedPrimary.contextLimit) },
                    { label: "Latency / cost", value: `${readable(selectedPrimary.latencyClass)} / ${readable(selectedPrimary.costClass)}` },
                    { label: "Data disclosure", value: readable(selectedPrimary.disclosureClass) },
                    { label: "Tool calling", value: selectedPrimary.capabilities.toolCalling ? "Supported" : "Not reported" },
                    { label: "Structured output", value: selectedPrimary.capabilities.structuredOutput ? "Supported" : "Not reported" },
                    { label: "Compatible specialists", value: selectedPrimary.compatibleAgentIds.join(", ") || "None declared" },
                    { label: "Catalog source", value: selectedPrimary.catalogSource },
                    { label: "Catalog observed", value: formatTime(selectedPrimary.catalogRetrievedAt ?? catalogObservedAt) },
                  ]} />
                  <p className="model-assignment__enforcement-note">
                    <strong>{readable(selectedPrimary.enforcementMode)}.</strong>{" "}
                    {enforcementExplanation(selectedPrimary.enforcementMode)}
                  </p>
                  {!selectableForScope(
                    selectedPrimary,
                    scope,
                    workspaceAgentIds,
                  ) && (
                    <p className="os-state-remediation">
                      {selectedPrimary.unavailableReasons.join(" ")
                        || (scope.agentId && !selectedPrimary.compatibleAgentIds.includes(scope.agentId)
                          ? `This configuration is not declared for ${scope.label}.`
                          : scope.type === "global"
                            ? `This configuration does not cover every canonical specialist. Missing: ${workspaceAgentIds.filter((id) => !selectedPrimary.compatibleAgentIds.includes(id)).join(", ")}.`
                          : "This configuration is not callable in the current runtime.")}
                    </p>
                  )}
                </div>
              )}

              <section className="model-assignment__catalog" aria-label={`${scope.label} live model readiness`}>
                <div>
                  <h3>Live model readiness</h3>
                  <p>Every row comes from the current runtime provider and agent manifests. Disabled paths remain visible so enforcement or connection gaps are explainable.</p>
                </div>
                <div className="os-table-wrap"><table className="os-data-table">
                  <thead><tr><th>Provider and model</th><th>Reasoning</th><th>Execution boundary</th><th>Enforcement</th><th>Availability for this scope</th></tr></thead>
                  <tbody>{items.map((item) => {
                    const available = selectableForScope(
                      item,
                      scope,
                      workspaceAgentIds,
                    );
                    const missingWorkspaceAgents = scope.type === "global"
                      ? workspaceAgentIds.filter((id) =>
                          !item.compatibleAgentIds.includes(id))
                      : [];
                    const incompatible = scope.agentId !== null
                      ? !item.compatibleAgentIds.includes(scope.agentId)
                      : missingWorkspaceAgents.length > 0;
                    return <tr key={item.configurationId}>
                      <th scope="row">{item.providerId} · {item.displayName}<small>{item.modelId}</small></th>
                      <td>{item.reasoningEffort ? readable(item.reasoningEffort) : "Provider default"}</td>
                      <td>{executionBoundaryLabel(item.executionBoundary)}</td>
                      <td><StatusPill status={item.enforcementMode}>{readable(item.enforcementMode)}</StatusPill><small>{enforcementExplanation(item.enforcementMode)}</small></td>
                      <td><StatusPill status={available ? "selectable" : "unavailable"}>{available ? "Selectable" : "Unavailable"}</StatusPill><small>{incompatible
                        ? scope.type === "global"
                          ? `Missing specialist coverage: ${missingWorkspaceAgents.join(", ")}.`
                          : `Not declared for ${scope.label}.`
                        : item.unavailableReasons.join(" ") || `Catalog observed ${formatTime(item.catalogRetrievedAt ?? catalogObservedAt)}.`}</small></td>
                    </tr>;
                  })}</tbody>
                </table></div>
              </section>

              <label className="model-assignment__reason">
                <span>Reason for this assignment</span>
                <textarea
                  data-control-id={`${controlPrefix}-model-reason`}
                  value={reason}
                  onChange={(event) => {
                    setSavedMessage("");
                    setSaveError(undefined);
                    setReason(event.target.value);
                  }}
                  placeholder={scope.type === "global"
                    ? "Why this model is the workspace default"
                    : `Why this model fits ${scope.label}`}
                  disabled={!changed || saving}
                  required
                />
              </label>

              {saveError && (
                <ErrorPanel
                  title="Model assignment was not saved"
                  error={saveError}
                  retryControlId={`${controlPrefix}-model-conflict-retry`}
                  onRetry={() => {
                    preferences.refresh();
                    resolution.refresh();
                  }}
                />
              )}
              {savedMessage && <p className="os-success-note" role="status">{savedMessage}</p>}

              <div className="model-assignment__actions">
                <p>
                  Running missions keep their pinned model receipt. This change applies to future resolutions and cannot silently alter an active run.
                </p>
                <Button
                  type="submit"
                  data-control-id={`${controlPrefix}-model-save`}
                  disabled={!canSave}
                >
                  {saving ? "Saving assignment" : scope.type === "global" ? "Save workspace default" : "Save agent assignment"}
                </Button>
              </div>
            </form>
          )}
        </>
      )}
    </Card>
  );
}

export function GlobalModelAssignmentEditor() {
  return <ModelAssignmentEditor scope={{
    type: "global",
    id: "global",
    agentId: null,
    label: "Workspace default",
  }} />;
}
