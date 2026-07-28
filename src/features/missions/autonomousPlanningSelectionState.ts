import {
  AUTONOMOUS_LOCAL_PLANNING_SELECTION,
  type AutonomousPlanningSelection,
} from "../../domain/types/commandOs";
import type { ModelCatalogItem } from "../../domain/types/modelConfiguration";

export function resolvedPlanningSelection(
  selection: AutonomousPlanningSelection | undefined,
): AutonomousPlanningSelection {
  return selection ?? AUTONOMOUS_LOCAL_PLANNING_SELECTION;
}
export function samePlanningSelection(
  left: AutonomousPlanningSelection | undefined,
  right: AutonomousPlanningSelection | undefined,
): boolean {
  const a = resolvedPlanningSelection(left);
  const b = resolvedPlanningSelection(right);
  if (a.route !== b.route) return false;
  if (a.route === "local_deterministic" || b.route === "local_deterministic") {
    return a.route === b.route;
  }
  return a.agentId === b.agentId
    && a.primaryConfigurationId === b.primaryConfigurationId
    && a.fallbackConfigurationId === b.fallbackConfigurationId
    && a.disclosureClass === b.disclosureClass;
}

export function isPlanningDisclosureClass(
  value: string,
): value is "public_only" | "sanitized_internal" {
  return value === "public_only" || value === "sanitized_internal";
}

export function configurationSelectableForPlanning(
  item: ModelCatalogItem,
  agentId: string,
  disclosureClass?: "public_only" | "sanitized_internal",
): boolean {
  return item.selectable
    && item.enforcementMode === "advisor_only"
    && item.executionBoundary === "provider_tool_calling"
    && item.authState === "authenticated"
    && item.healthState === "healthy"
    && item.capabilities.structuredOutput
    && item.compatibleAgentIds.includes(agentId)
    && isPlanningDisclosureClass(item.disclosureClass)
    && (!disclosureClass || item.disclosureClass === disclosureClass);
}

export function planningAgentIds(
  items: readonly ModelCatalogItem[],
): string[] {
  return [...new Set(items.flatMap((item) =>
    item.enforcementMode === "advisor_only"
      && item.executionBoundary === "provider_tool_calling"
      && item.capabilities.structuredOutput
      && isPlanningDisclosureClass(item.disclosureClass)
      ? item.compatibleAgentIds
      : [],
  ))].sort((left, right) => left.localeCompare(right));
}

export function firstPlanningConfiguration(
  items: readonly ModelCatalogItem[],
  agentId: string,
  input: {
    readonly providerId?: string;
    readonly modelId?: string;
    readonly disclosureClass?: "public_only" | "sanitized_internal";
    readonly excludedConfigurationId?: string | null;
    readonly preferredReasoningEffort?: string | null;
  } = {},
): ModelCatalogItem | undefined {
  const candidates = items.filter((item) =>
    item.configurationId !== input.excludedConfigurationId
    && (!input.providerId || item.providerId === input.providerId)
    && (!input.modelId || item.modelId === input.modelId)
    && configurationSelectableForPlanning(
      item,
      agentId,
      input.disclosureClass,
    ));
  return candidates.find((item) =>
    item.reasoningEffort === input.preferredReasoningEffort)
    ?? candidates.find((item) => item.reasoningEffort === null)
    ?? candidates[0];
}

export function planningSelectionFromConfiguration(
  agentId: string,
  primary: ModelCatalogItem,
  fallbackConfigurationId: string | null = null,
): Extract<AutonomousPlanningSelection, { route: "provider_advisory" }> {
  if (!isPlanningDisclosureClass(primary.disclosureClass)) {
    throw new Error(
      "Provider-advisory planning requires a public-only or sanitized-internal disclosure class.",
    );
  }
  return {
    route: "provider_advisory",
    agentId,
    primaryConfigurationId: primary.configurationId,
    fallbackConfigurationId,
    enforcementMode: "advisor_only",
    disclosureClass: primary.disclosureClass,
    executionAuthority: "none",
  };
}
