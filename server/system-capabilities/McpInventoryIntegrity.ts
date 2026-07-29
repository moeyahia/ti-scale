import type {
  RuntimeMcpServerManifest,
  RuntimeSourceManifests,
} from "../domain";
import type { McpServerProjection } from "../app/RuntimeProjectionService";

const SERVER_ID = /^[A-Za-z0-9._:@-]{1,128}$/u;
const TOOL_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;

function validServerId(serverId: string): boolean {
  return serverId === serverId.trim()
    && SERVER_ID.test(serverId)
    && serverId !== "mcp:";
}

function validOwnedToolId(toolId: string, namespace: string): boolean {
  return toolId === toolId.trim()
    && TOOL_ID.test(toolId)
    && toolId.startsWith(namespace)
    && toolId.length > namespace.length;
}

/**
 * Canonical namespace owned by one MCP server. `public-nvd` and
 * `mcp:public-nvd` deliberately normalize to the same namespace, so they may
 * never coexist as separate owners.
 */
export function mcpToolNamespace(serverId: string): string {
  return `${serverId.startsWith("mcp:") ? serverId : `mcp:${serverId}`}/`;
}

function counts(values: readonly string[]): ReadonlyMap<string, number> {
  const result = new Map<string, number>();
  for (const value of values) result.set(value, (result.get(value) ?? 0) + 1);
  return result;
}

function uniqueExactSet(left: readonly string[], right: readonly string[]): boolean {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  return leftSet.size === left.length
    && rightSet.size === right.length
    && leftSet.size === rightSet.size
    && [...leftSet].every((value) => rightSet.has(value));
}

/**
 * Returns only servers whose manifest inventory is a closed, unique,
 * fully-qualified set exactly equal to the tools assigned to that server.
 * Namespace aliases fail together rather than giving two servers ownership of
 * the same `mcp:<server>/` prefix.
 */
export function exactManifestMcpServerIds(
  manifests: RuntimeSourceManifests,
): ReadonlySet<string> {
  const serverIdCounts = counts(manifests.mcpServers.map(({ id }) => id));
  const namespaceCounts = counts(
    manifests.mcpServers.map(({ id }) => mcpToolNamespace(id)),
  );
  const globalToolIdCounts = counts(manifests.tools.map(({ id }) => id));
  const exact = new Set<string>();

  for (const server of manifests.mcpServers) {
    const namespace = mcpToolNamespace(server.id);
    const declared = [...server.toolIds];
    const assigned = manifests.tools
      .filter(({ mcpServerId }) => mcpServerId === server.id)
      .map(({ id }) => id);
    const qualified = validServerId(server.id)
      && [...declared, ...assigned]
        .every((toolId) => validOwnedToolId(toolId, namespace));
    const globallyUnique = [...declared, ...assigned]
      .every((toolId) => globalToolIdCounts.get(toolId) === 1);

    if (validServerId(server.id)
      && serverIdCounts.get(server.id) === 1
      && namespaceCounts.get(namespace) === 1
      && qualified
      && globallyUnique
      && uniqueExactSet(declared, assigned)) {
      exact.add(server.id);
    }
  }
  return exact;
}

/**
 * Runtime tools/list projections must also own a unique namespace and expose a
 * duplicate-free, fully-qualified inventory. Exact equality with the manifest
 * is checked by the caller because the two registries have different types.
 */
export function exactRuntimeMcpServerIds(
  servers: readonly McpServerProjection[],
): ReadonlySet<string> {
  const serverIdCounts = counts(servers.map(({ id }) => id));
  const namespaceCounts = counts(servers.map(({ id }) => mcpToolNamespace(id)));
  const globalToolIdCounts = counts(servers.flatMap(({ capabilities }) => capabilities));
  const exact = new Set<string>();

  for (const server of servers) {
    const namespace = mcpToolNamespace(server.id);
    if (validServerId(server.id)
      && serverIdCounts.get(server.id) === 1
      && namespaceCounts.get(namespace) === 1
      && new Set(server.capabilities).size === server.capabilities.length
      && server.capabilities.every((toolId) =>
        validOwnedToolId(toolId, namespace) && globalToolIdCounts.get(toolId) === 1)) {
      exact.add(server.id);
    }
  }
  return exact;
}

export function exactManifestAndRuntimeInventory(
  manifest: RuntimeMcpServerManifest,
  projection: McpServerProjection,
  exactManifestServers: ReadonlySet<string>,
  exactRuntimeServers: ReadonlySet<string>,
): boolean {
  return exactManifestServers.has(manifest.id)
    && exactRuntimeServers.has(projection.id)
    && uniqueExactSet(manifest.toolIds, projection.capabilities);
}
