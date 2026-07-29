import type { AgentRecord } from "../../domain/types/operations";

export interface AgentRuntimeBindingSummary {
  readonly id: string;
  readonly version: string | null;
}

export interface ProductRosterReadinessSummary {
  readonly canonicalRoleCount: number;
  readonly runtimeBoundRoleCount: number;
  readonly runtimeUnboundRoleCount: number;
  readonly executableRuntimeBindingCount: number;
}

function record(value: unknown): Readonly<Record<string, unknown>> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : {};
}

function string(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : null;
}

function versionedBindings(
  value: unknown,
): readonly AgentRuntimeBindingSummary[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    const item = record(entry);
    const id = string(item.id);
    if (!id) return [];
    return [{
      id,
      version: string(item.version),
    }];
  });
}

function uniqueSortedBindings(
  bindings: readonly AgentRuntimeBindingSummary[],
): readonly AgentRuntimeBindingSummary[] {
  return [...new Map(bindings.map((binding) => [binding.id, binding])).values()]
    .sort((left, right) => left.id.localeCompare(right.id));
}

export function runtimeBindingSummaries(
  agent: Pick<AgentRecord, "configuration">,
): readonly AgentRuntimeBindingSummary[] {
  const configuration = record(agent.configuration);
  const hasCanonicalProjection = Object.hasOwn(
    configuration,
    "runtimeBindingAgentIds",
  ) || Object.hasOwn(configuration, "runtimeBindingVersions");

  if (hasCanonicalProjection) {
    const readiness = record(configuration.readiness);
    if (
      readiness.status === "offline"
      || readiness.status === "quarantined"
      || readiness.enabledCapabilityCount === 0
    ) return [];
    const versions = new Map(
      versionedBindings(configuration.runtimeBindingVersions)
        .map((binding) => [binding.id, binding.version]),
    );
    const ids = Array.isArray(configuration.runtimeBindingAgentIds)
      ? configuration.runtimeBindingAgentIds
        .map(string)
        .filter((id): id is string => id !== null)
      : [];
    return uniqueSortedBindings([
      ...ids.map((id) => ({ id, version: versions.get(id) ?? null })),
      ...[...versions].map(([id, version]) => ({ id, version })),
    ]);
  }

  // Compatibility for early preview/import records written before the
  // product-roster projection exposed its canonical ID and version fields.
  return uniqueSortedBindings(versionedBindings(configuration.runtimeBindings));
}

export function productRosterSource(
  agent: Pick<AgentRecord, "configuration" | "version">,
): string {
  const configuration = record(agent.configuration);
  return string(configuration.schemaVersion) ?? agent.version;
}

export function productRosterDescription(
  agent: Pick<AgentRecord, "configuration">,
): string | null {
  return string(record(agent.configuration).description);
}

/**
 * Summarizes the user-facing product roster without turning internal runtime
 * adapters into additional agents. A single reviewed adapter may serve more
 * than one product role, so role coverage and unique adapter count remain
 * separate operator-visible facts.
 */
export function productRosterReadinessSummary(
  agents: readonly Pick<AgentRecord, "configuration">[],
): ProductRosterReadinessSummary {
  const bindingIds = new Set<string>();
  let runtimeBoundRoleCount = 0;
  for (const agent of agents) {
    const bindings = runtimeBindingSummaries(agent);
    if (bindings.length > 0) runtimeBoundRoleCount += 1;
    bindings.forEach(({ id }) => bindingIds.add(id));
  }
  return {
    canonicalRoleCount: agents.length,
    runtimeBoundRoleCount,
    runtimeUnboundRoleCount: agents.length - runtimeBoundRoleCount,
    executableRuntimeBindingCount: bindingIds.size,
  };
}
