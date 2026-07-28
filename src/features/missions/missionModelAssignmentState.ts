import type {
  AutonomousAgentModelAssignment,
  AutonomousAgentModelAssignmentReceipt,
} from "../../domain/types/commandOs";
import type { ModelCatalogItem } from "../../domain/types/modelConfiguration";

// Pure mission-local selection helpers; they never write global model preferences.

export function readableModelValue(value: string): string {
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/gu, (character) => character.toLocaleUpperCase("en-US"));
}

export function modelControlSegment(value: string): string {
  return value
    .trim()
    .toLocaleLowerCase("en-US")
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
}

export function exactAssignmentFromReceipt(
  receipt: AutonomousAgentModelAssignmentReceipt,
): AutonomousAgentModelAssignment {
  return {
    agentId: receipt.agentId,
    primaryConfigurationId: receipt.primary.configurationId,
    fallbackConfigurationId: receipt.fallback?.configurationId ?? null,
  };
}

export function assignmentForAgent(
  agentId: string,
  explicitAssignments: readonly AutonomousAgentModelAssignment[] | undefined,
  receipts: readonly AutonomousAgentModelAssignmentReceipt[],
): AutonomousAgentModelAssignment | undefined {
  const explicit = explicitAssignments?.find((assignment) => assignment.agentId === agentId);
  if (explicit) return explicit;
  const receipt = receipts.find((candidate) => candidate.agentId === agentId);
  return receipt ? exactAssignmentFromReceipt(receipt) : undefined;
}

export function upsertAgentModelAssignment(
  current: readonly AutonomousAgentModelAssignment[] | undefined,
  next: AutonomousAgentModelAssignment,
): AutonomousAgentModelAssignment[] {
  return [
    ...(current ?? []).filter((assignment) => assignment.agentId !== next.agentId),
    next,
  ].sort((left, right) => left.agentId.localeCompare(right.agentId));
}

export function filterAgentModelAssignments(
  current: readonly AutonomousAgentModelAssignment[] | undefined,
  selectedAgentIds: readonly string[],
): AutonomousAgentModelAssignment[] | undefined {
  if (current === undefined) return undefined;
  const selected = new Set(selectedAgentIds);
  return current.filter((assignment) => selected.has(assignment.agentId));
}

export function configurationForId(
  catalog: readonly ModelCatalogItem[],
  configurationId: string | null | undefined,
): ModelCatalogItem | undefined {
  if (!configurationId) return undefined;
  return catalog.find((item) => item.configurationId === configurationId);
}

export function configurationSelectableForAgent(
  item: ModelCatalogItem,
  agentId: string,
): boolean {
  return item.selectable
    && item.enforcementMode === "enforced_executor"
    && item.compatibleAgentIds.includes(agentId);
}

export function configurationsForProvider(
  catalog: readonly ModelCatalogItem[],
  agentId: string,
  providerId: string,
): readonly ModelCatalogItem[] {
  return catalog.filter((item) =>
    item.providerId === providerId && item.compatibleAgentIds.includes(agentId));
}

export function firstSelectableConfiguration(
  items: readonly ModelCatalogItem[],
  agentId: string,
  excludedConfigurationId?: string,
): ModelCatalogItem | undefined {
  return items.find((item) =>
    item.configurationId !== excludedConfigurationId
    && configurationSelectableForAgent(item, agentId));
}

export function preferredConfigurationForModel(
  items: readonly ModelCatalogItem[],
  agentId: string,
  modelId: string,
  previousReasoningEffort: string | null | undefined,
  excludedConfigurationId?: string,
): ModelCatalogItem | undefined {
  const candidates = items.filter((item) =>
    item.modelId === modelId
    && item.configurationId !== excludedConfigurationId
    && configurationSelectableForAgent(item, agentId));
  return candidates.find((item) => item.reasoningEffort === previousReasoningEffort)
    ?? candidates.find((item) => item.reasoningEffort === null)
    ?? candidates[0];
}

export function uniqueModelValues(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}
