import type {
  RuntimeAgentManifest,
  RuntimeMcpServerManifest,
  RuntimeSourceManifests,
} from "../domain";
import { buildRuntimeCapabilityProjection } from "../domain";
import {
  loadTrustedRuntimeSourceManifests,
  type TrustedJsonFileReference,
  type TrustedLocalFileReceipt,
} from "../trusted-runtime-config";
import type {
  FleetAgentProjection,
  McpServerProjection,
  RuntimeProjectionInput,
} from "./RuntimeProjectionService";

export const RUNTIME_SOURCE_MANIFEST_ENVIRONMENT = Object.freeze({
  path: "TI_SCALE_RUNTIME_SOURCE_MANIFEST_PATH",
  trustRoot: "TI_SCALE_TRUSTED_RUNTIME_CONFIG_ROOT",
  expectedSha256: "TI_SCALE_RUNTIME_SOURCE_MANIFEST_SHA256",
} as const);

const RUNTIME_MANAGED_IDS = Object.freeze({
  providers: new Set(["openrouter"]),
  mcpServers: new Set(["public-nvd"]),
  tools: new Set(["mcp:public-nvd/get_cve_details"]),
  capabilities: new Set(["public-nvd-cve-detail"]),
} as const);

export interface ConfiguredRuntimeManifest {
  readonly status: "loaded";
  readonly manifestVersion: string;
  /**
   * Definitions loaded from one immutable, deployment-pinned document. Live
   * state is withdrawn below until the matching adapter supplies a receipt.
   */
  readonly manifests: RuntimeSourceManifests;
  readonly receipt: TrustedLocalFileReceipt;
}

export interface UnconfiguredRuntimeManifest {
  readonly status: "unconfigured";
  readonly reason: string;
}

export type ProductionRuntimeManifest =
  | ConfiguredRuntimeManifest
  | UnconfiguredRuntimeManifest;

type Environment = Readonly<Record<string, string | undefined>>;

function trimmed(environment: Environment, name: string): string | undefined {
  const value = environment[name]?.trim();
  return value ? value : undefined;
}

function reference(environment: Environment): TrustedJsonFileReference | undefined {
  const path = trimmed(environment, RUNTIME_SOURCE_MANIFEST_ENVIRONMENT.path);
  const trustRoot = trimmed(environment, RUNTIME_SOURCE_MANIFEST_ENVIRONMENT.trustRoot);
  const expectedSha256 = trimmed(
    environment,
    RUNTIME_SOURCE_MANIFEST_ENVIRONMENT.expectedSha256,
  );
  const configured = [path, trustRoot, expectedSha256].filter(Boolean).length;
  if (configured === 0) return undefined;
  if (configured !== 3) {
    const missing = Object.entries(RUNTIME_SOURCE_MANIFEST_ENVIRONMENT)
      .filter(([, name]) => !trimmed(environment, name))
      .map(([, name]) => name)
      .sort();
    throw new Error(
      `Trusted runtime source manifest configuration is incomplete; missing ${missing.join(", ")}`,
    );
  }
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  return {
    path: path!,
    trustRoot: trustRoot!,
    expectedSha256: expectedSha256!,
    // A managed file may be root-owned or owned by the isolated service user.
    // The shared loader still rejects group/world writes, symlinks, unstable
    // identities, executable bits, and every other UID.
    allowedOwnerUids: currentUid === 0 ? [0] : [0, currentUid],
  };
}

function assertRuntimeManagedIdsAreNotShadowed(manifests: RuntimeSourceManifests): void {
  const collisions = [
    ...manifests.providers
      .filter(({ id }) => RUNTIME_MANAGED_IDS.providers.has(id))
      .map(({ id }) => `provider:${id}`),
    ...manifests.mcpServers
      .filter(({ id }) => RUNTIME_MANAGED_IDS.mcpServers.has(id))
      .map(({ id }) => `mcp-server:${id}`),
    ...manifests.tools
      .filter(({ id }) => RUNTIME_MANAGED_IDS.tools.has(id))
      .map(({ id }) => `tool:${id}`),
    ...manifests.capabilities
      .filter(({ id }) => RUNTIME_MANAGED_IDS.capabilities.has(id))
      .map(({ id }) => `capability:${id}`),
  ].sort();
  if (collisions.length > 0) {
    throw new Error(
      `Trusted runtime source manifest shadows live adapter IDs: ${collisions.join(", ")}`,
    );
  }
}

/**
 * Resolves one immutable source manifest at startup. This is deliberately not
 * an auto-discovery path: a file path without its trust root and reviewed byte
 * digest fails startup rather than silently falling back to an empty catalog.
 */
export function loadProductionRuntimeManifest(
  environment: Environment = process.env,
): ProductionRuntimeManifest {
  const configured = reference(environment);
  if (!configured) {
    return Object.freeze({
      status: "unconfigured",
      reason: "No deployment-pinned runtime source manifest is configured.",
    });
  }
  const loaded = loadTrustedRuntimeSourceManifests(configured);
  // Re-run the canonical projection validation at the composition boundary so
  // this module cannot project definitions that drifted from the registries.
  buildRuntimeCapabilityProjection(loaded.value.manifests);
  assertRuntimeManagedIdsAreNotShadowed(loaded.value.manifests);
  return Object.freeze({
    status: "loaded",
    manifestVersion: loaded.value.manifestVersion,
    manifests: loaded.value.manifests,
    receipt: loaded.receipt,
  });
}

function definitionOnlyManifests(source: RuntimeSourceManifests): RuntimeSourceManifests {
  return Object.freeze({
    riskClasses: source.riskClasses,
    evidenceKinds: source.evidenceKinds,
    capabilities: source.capabilities,
    tools: Object.freeze(source.tools.map((tool) => tool.mcpServerId === undefined
      ? tool
      : Object.freeze({
          ...tool,
          available: false,
          dependencies: Object.freeze([
            ...(tool.dependencies ?? []).filter(({ id }) => id !== "live-mcp-attestation"),
            Object.freeze({ id: "live-mcp-attestation", ready: false }),
          ]),
        }))),
    mcpServers: Object.freeze(source.mcpServers.map((server) => Object.freeze({
      ...server,
      status: "unconfigured" as const,
    }))),
    agents: Object.freeze(source.agents.map((agent) => Object.freeze({
      ...agent,
      available: false,
    }))),
    providers: Object.freeze(source.providers.map((provider) => Object.freeze({
      ...provider,
      authenticated: false,
      healthy: false,
    }))),
  });
}

function configuredAgent(
  agent: RuntimeAgentManifest,
  manifests: RuntimeSourceManifests,
  manifestVersion: string,
): FleetAgentProjection {
  const capabilities = new Map(manifests.capabilities.map((item) => [item.id, item]));
  return Object.freeze({
    id: agent.id,
    role: "configured-specialist-definition",
    displayName: agent.label,
    status: "offline" as const,
    providerPolicy: Object.freeze({
      source: "trusted-runtime-source-manifest",
      configuredModelRefs: agent.modelRefs.map(({ providerId, modelId }) =>
        `${providerId}/${modelId}`),
      liveProviderAttestation: false,
    }),
    toolPolicy: Object.freeze({
      configuredToolIds: [...agent.toolIds],
      execution: "unavailable_until_exact_runtime_binding",
      liveToolAttestation: false,
    }),
    configuration: Object.freeze({
      source: "trusted-runtime-source-manifest",
      manifestVersion,
      projectionKind: "definition_only",
      executionMounted: false,
      productRosterBindingEligible: false,
    }),
    version: manifestVersion,
    lastHeartbeatAt: null,
    capabilities: Object.freeze(agent.capabilityIds.map((capabilityId) => {
      const capability = capabilities.get(capabilityId);
      return Object.freeze({
        name: capabilityId,
        source: "trusted-runtime-source-manifest",
        enabled: false,
        metadata: Object.freeze({
          label: capability?.label ?? capabilityId,
          actionClassIds: [...(capability?.actionClassIds ?? [])],
          liveRouteAttestation: false,
        }),
      });
    })),
  });
}

function configuredMcp(
  server: RuntimeMcpServerManifest,
  manifestVersion: string,
): McpServerProjection {
  return Object.freeze({
    id: server.id,
    name: server.label,
    transport: "configured-definition",
    status: "unknown" as const,
    capabilities: [...server.toolIds],
    policy: Object.freeze({
      source: "trusted-runtime-source-manifest",
      manifestVersion,
      configured: true,
      liveAttestation: false,
      executionAuthorization: "none",
    }),
    lastCheckedAt: null,
  });
}

function mergeUnique<T extends { readonly id: string }>(
  kind: string,
  existing: readonly T[],
  additions: readonly T[],
): readonly T[] {
  const ids = new Set(existing.map(({ id }) => id));
  for (const addition of additions) {
    if (ids.has(addition.id)) {
      throw new Error(`Configured runtime ${kind} stable ID collision: ${addition.id}`);
    }
    ids.add(addition.id);
  }
  return Object.freeze([...existing, ...additions]);
}

/**
 * Adds reviewed definitions to the runtime projection without claiming a
 * heartbeat, authenticated provider, live MCP route, specialist executor, or
 * mission authority. Local tool availability is decided later by the exact
 * registry-aligned preflight projection.
 */
export function projectConfiguredRuntimeManifest(
  baseline: RuntimeProjectionInput,
  configured: ProductionRuntimeManifest,
): RuntimeProjectionInput {
  if (configured.status === "unconfigured") return baseline;
  const manifests = definitionOnlyManifests(configured.manifests);
  // Verify that withdrawing live state preserved all registry relationships.
  buildRuntimeCapabilityProjection(manifests);
  return Object.freeze({
    ...baseline,
    agents: mergeUnique(
      "agent",
      baseline.agents,
      manifests.agents.map((agent) =>
        configuredAgent(agent, manifests, configured.manifestVersion)),
    ),
    mcpServers: mergeUnique(
      "MCP server",
      baseline.mcpServers,
      manifests.mcpServers.map((server) => configuredMcp(server, configured.manifestVersion)),
    ),
    capabilityManifests: manifests,
  });
}
