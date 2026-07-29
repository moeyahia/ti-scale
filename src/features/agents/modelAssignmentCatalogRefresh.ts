import type {
  ModelCatalogItem,
  ModelConfiguration,
} from "../../domain/types/modelConfiguration";

function normalizedStringList(value: unknown): readonly string[] | null {
  if (
    !Array.isArray(value)
    || !value.every((item): item is string => typeof item === "string")
  ) return null;
  return [...new Set(value)].sort((left, right) => left.localeCompare(right));
}

function sameStringList(
  expected: readonly string[],
  observed: unknown,
): boolean {
  const normalizedObserved = normalizedStringList(observed);
  if (!normalizedObserved) return false;
  const normalizedExpected = [...new Set(expected)]
    .sort((left, right) => left.localeCompare(right));
  return normalizedExpected.length === normalizedObserved.length
    && normalizedExpected.every((item, index) =>
      item === normalizedObserved[index]);
}

function normalizedCoverage(
  value: unknown,
): Readonly<Record<string, readonly string[]>> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const result: Record<string, readonly string[]> = {};
  for (const [agentId, actionClassIds] of Object.entries(value)) {
    const normalized = normalizedStringList(actionClassIds);
    if (!normalized) return null;
    result[agentId] = normalized;
  }
  return result;
}

function sameCoverage(
  expected: Readonly<Record<string, readonly string[]>>,
  observed: unknown,
): boolean {
  const normalizedObserved = normalizedCoverage(observed);
  if (!normalizedObserved) return false;
  const expectedAgentIds = Object.keys(expected).sort();
  const observedAgentIds = Object.keys(normalizedObserved).sort();
  return sameStringList(expectedAgentIds, observedAgentIds)
    && expectedAgentIds.every((agentId) =>
      sameStringList(
        expected[agentId] ?? [],
        normalizedObserved[agentId],
      ));
}

function sameExecutionAuthority(
  catalog: ModelCatalogItem,
  configured: ModelConfiguration,
): boolean {
  const capabilities = configured.capabilities;
  return catalog.providerId === configured.providerId
    && catalog.modelId === configured.modelId
    && catalog.reasoningEffort === configured.reasoningEffort
    && catalog.executionBoundary === configured.executionBoundary
    && catalog.enforcementMode === configured.enforcementMode
    && catalog.disclosureClass === configured.disclosureClass
    && catalog.contextLimit === configured.contextLimit
    && capabilities.toolCalling === catalog.capabilities.toolCalling
    && capabilities.structuredOutput
      === catalog.capabilities.structuredOutput
    && sameStringList(
      catalog.capabilities.compatibleActionClassIds,
      capabilities.compatibleActionClassIds,
    )
    && sameStringList(
      catalog.compatibleAgentIds,
      capabilities.compatibleAgentIds,
    )
    && sameStringList(
      catalog.supportedReasoningEfforts,
      capabilities.supportedReasoningEfforts,
    )
    && sameCoverage(
      catalog.capabilities.localDeterministicActionClassIdsByAgent,
      capabilities.localDeterministicActionClassIdsByAgent,
    );
}

export function catalogItemSelectableForAgent(
  item: ModelCatalogItem,
  agentId: string | null,
  workspaceAgentIds: readonly string[] = [],
): boolean {
  if (!item.selectable) return false;
  if (agentId !== null) return item.compatibleAgentIds.includes(agentId);
  return workspaceAgentIds.length > 0
    && workspaceAgentIds.every((id) => item.compatibleAgentIds.includes(id));
}

export function fallbackSelectionIsValid(
  items: readonly ModelCatalogItem[],
  configurationId: string,
  agentId: string | null,
  workspaceAgentIds: readonly string[] = [],
): boolean {
  if (!configurationId) return true;
  const selected = items.find((item) =>
    item.configurationId === configurationId);
  return Boolean(
    selected && catalogItemSelectableForAgent(
      selected,
      agentId,
      workspaceAgentIds,
    ),
  );
}

/**
 * Resolves a durable assignment receipt into the current live catalog.
 *
 * Configuration IDs intentionally include the provider-attestation timestamp,
 * so a healthy catalog renewal produces a new immutable ID. The editor may
 * stage a refreshed ID only when one selectable current entry is an
 * unambiguous match for the exact provider/model/reasoning tuple and every
 * material execution-authority field. A refreshed attestation timestamp may
 * change the immutable ID; capabilities, enforcement, disclosure, agent
 * compatibility, or context changes may not be silently reconciled.
 */
export function currentCatalogEquivalent(
  items: readonly ModelCatalogItem[],
  configured: ModelConfiguration | null | undefined,
  agentId: string | null,
  workspaceAgentIds: readonly string[] = [],
): ModelCatalogItem | undefined {
  if (!configured) return undefined;
  const exact = items.find((item) => item.configurationId === configured.id);
  if (exact) return exact;
  const candidates = items.filter((item) =>
    sameExecutionAuthority(item, configured)
    && catalogItemSelectableForAgent(item, agentId, workspaceAgentIds));
  return candidates.length === 1 ? candidates[0] : undefined;
}

export type CatalogReceiptRefreshState =
  | "absent"
  | "current"
  | "staged"
  | "unresolved";

export interface CatalogReceiptReconciliation {
  readonly state: CatalogReceiptRefreshState;
  readonly item?: ModelCatalogItem;
}

/**
 * Reconciles the immutable ID and receipt that were actually saved.
 *
 * This deliberately has no editable-selection input: changing a form control
 * cannot manufacture or dismiss catalog-refresh status. Only the saved
 * baseline ID, its immutable receipt, and the current live catalog participate.
 */
export function reconcileSavedCatalogReceipt(
  items: readonly ModelCatalogItem[],
  savedConfigurationId: string,
  savedConfiguration: ModelConfiguration | null | undefined,
  agentId: string | null,
  workspaceAgentIds: readonly string[] = [],
): CatalogReceiptReconciliation {
  if (!savedConfigurationId) return { state: "absent" };
  const exact = items.find((item) =>
    item.configurationId === savedConfigurationId);
  if (exact) return { state: "current", item: exact };
  const receipt = savedConfiguration?.id === savedConfigurationId
    ? savedConfiguration
    : undefined;
  const equivalent = currentCatalogEquivalent(
    items,
    receipt,
    agentId,
    workspaceAgentIds,
  );
  return equivalent
    ? { state: "staged", item: equivalent }
    : { state: "unresolved" };
}

export function configurationReceiptLabel(
  configured: ModelConfiguration,
): string {
  const reasoning = configured.reasoningEffort
    ? ` · ${configured.reasoningEffort.replaceAll("_", " ")} reasoning`
    : " · provider-default reasoning";
  return `${configured.providerId} · ${configured.displayName} (${configured.modelId})${reasoning} · ${configured.id}`;
}
