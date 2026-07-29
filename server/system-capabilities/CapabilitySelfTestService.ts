import {
  buildRuntimeCapabilityProjection,
  emptyRuntimeSourceManifests,
  runtimeAdapterAttestationIntegrityValid,
  type RuntimeAdapterAttestation,
  type RuntimeMcpServerManifest,
  type RuntimeProviderManifest,
  type RuntimeSourceManifests,
  type RuntimeToolManifest,
} from "../domain";
import type {
  McpServerProjection,
  RuntimeProjectionInput,
} from "../app/RuntimeProjectionService";
import type { ProviderReadiness } from "../app/RuntimeReadiness";
import type {
  CapabilityLocalHealthReader,
  CapabilityLocalHealthSnapshot,
} from "./CapabilitySelfTestRepository";
import type {
  CapabilityAvailability,
  CapabilityFreshnessState,
  CapabilitySelfTestComponentKind,
  CapabilitySelfTestFreshness,
  CapabilitySelfTestKind,
  CapabilitySelfTestResult,
  CapabilitySelfTestSnapshot,
  CapabilitySelfTestStatus,
} from "./types";
import type { ToolExecutionPreflightResult } from "./ToolExecutionPreflight";
import {
  exactManifestAndRuntimeInventory,
  exactManifestMcpServerIds,
  exactRuntimeMcpServerIds,
} from "./McpInventoryIntegrity";

const PUBLIC_COMPONENT_ID = /^[A-Za-z0-9._:@/-]{1,128}$/u;
const SECRET_SHAPED_ID = /(?:^|[-_.:/])(?:api[-_]?key|authorization|cookie|credential|pass(?:word)?|private[-_]?key|secret|session[-_]?token|token)(?:[-_.:/]|$)|(?:sk|rk|pk)-[A-Za-z0-9_-]{8,}|-----BEGIN/iu;
const DEFAULT_ATTESTATION_MAX_AGE_MS = 5 * 60 * 1_000;
const LOCAL_CHECK_MAX_AGE_MS = 60 * 1_000;

const NO_EXECUTION_AUTHORIZATION = Object.freeze({
  state: "not_granted" as const,
  grantsMissionExecution: false as const,
  explanation: "This read-only self-test reports dependency state only. Mission execution still requires a separately validated contract, policy decision, control-plane lease, and exact runtime authorization.",
});

export interface CapabilitySelfTestServiceOptions {
  readonly repository: CapabilityLocalHealthReader;
  readonly readRuntimeProjection: () => RuntimeProjectionInput;
  /** Cached argument-bounded startup receipts owned by the isolated tool runtime. */
  readonly readToolExecutionPreflight?: (
    toolId: string,
  ) => ToolExecutionPreflightResult | undefined;
  readonly clock?: () => Date;
}

interface ResultInput {
  readonly componentKind: CapabilitySelfTestComponentKind;
  readonly componentId: string;
  readonly componentIndex: number;
  readonly testKind: CapabilitySelfTestKind;
  readonly status: CapabilitySelfTestStatus;
  readonly availability: CapabilityAvailability;
  readonly checkedAt: string;
  readonly freshness: CapabilitySelfTestFreshness;
  readonly explanation: string;
  readonly remediation?: string;
}

function safeComponentId(
  kind: CapabilitySelfTestComponentKind,
  value: string,
  index: number,
): string {
  const normalized = value.trim();
  if (PUBLIC_COMPONENT_ID.test(normalized) && !SECRET_SHAPED_ID.test(normalized)) return normalized;
  return `unreportable-${kind.replaceAll("_", "-")}-${String(index + 1).padStart(2, "0")}`;
}

function componentLabel(kind: CapabilitySelfTestComponentKind, id: string): string {
  const prefix: Readonly<Record<CapabilitySelfTestComponentKind, string>> = {
    registry: "Runtime registry",
    database: "Canonical database",
    event_stream: "Event stream",
    second_brain: "Second Brain",
    obsidian_vault: "Obsidian Vault",
    provider: "Provider",
    mcp_server: "MCP server",
    tool: "Registered tool",
    tool_dependency: "Tool dependency",
  };
  return `${prefix[kind]} · ${id}`;
}

function result(input: ResultInput): CapabilitySelfTestResult {
  const publicId = safeComponentId(input.componentKind, input.componentId, input.componentIndex);
  return {
    id: `self-test:${input.componentKind}:${String(input.componentIndex + 1).padStart(3, "0")}:${publicId}`,
    component: {
      kind: input.componentKind,
      id: publicId,
      label: componentLabel(input.componentKind, publicId),
    },
    testKind: input.testKind,
    status: input.status,
    availability: input.availability,
    checkedAt: input.checkedAt,
    freshness: input.freshness,
    explanation: input.explanation,
    remediation: input.remediation ?? null,
    executionAuthorization: NO_EXECUTION_AUTHORIZATION,
  };
}

function parsedTime(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function freshness(
  now: Date,
  observedAt: string | null | undefined,
  expiresAt: string | null | undefined,
  maximumAgeMs: number | null,
): CapabilitySelfTestFreshness {
  const observed = parsedTime(observedAt);
  const expires = parsedTime(expiresAt);
  let state: CapabilityFreshnessState = "unknown";
  if (observed !== null && observed <= now.getTime() + LOCAL_CHECK_MAX_AGE_MS) {
    const expired = expires !== null && expires <= now.getTime();
    const tooOld = maximumAgeMs !== null && now.getTime() - observed > maximumAgeMs;
    state = expired || tooOld ? "stale" : "fresh";
  }
  return {
    state,
    observedAt: observed === null ? null : new Date(observed).toISOString(),
    expiresAt: expires === null ? null : new Date(expires).toISOString(),
    maximumAgeMs,
  };
}

function currentFreshness(checkedAt: string): CapabilitySelfTestFreshness {
  return {
    state: "fresh",
    observedAt: checkedAt,
    expiresAt: null,
    maximumAgeMs: LOCAL_CHECK_MAX_AGE_MS,
  };
}

function unknownFreshness(): CapabilitySelfTestFreshness {
  return {
    state: "unknown",
    observedAt: null,
    expiresAt: null,
    maximumAgeMs: null,
  };
}

function invalidManifestComponentResult(
  componentKind: "provider" | "mcp_server" | "tool" | "tool_dependency",
  componentId: string,
  componentIndex: number,
  checkedAt: string,
): CapabilitySelfTestResult {
  return result({
    componentKind,
    componentId,
    componentIndex,
    testKind: componentKind === "tool_dependency"
      ? "manifest_dependency"
      : "runtime_attestation",
    status: "fail",
    availability: "unavailable",
    checkedAt,
    freshness: unknownFreshness(),
    explanation: "This component is not trusted because the canonical runtime capability manifest failed structural integrity validation.",
    remediation: "Repair duplicate, unknown, or broken runtime registry records and obtain fresh bounded attestations before using this component.",
  });
}

function structuralManifestValidity(manifests: RuntimeSourceManifests): boolean {
  try {
    buildRuntimeCapabilityProjection(manifests);
    return true;
  } catch {
    return false;
  }
}

function providerResult(
  manifest: RuntimeProviderManifest | undefined,
  runtime: ProviderReadiness | undefined,
  checkedAt: string,
  now: Date,
  index: number,
): CapabilitySelfTestResult {
  const sourceId = manifest?.id ?? runtime?.id ?? `provider-${index + 1}`;
  const sourceFreshness = freshness(
    now,
    runtime?.attestedAt,
    runtime?.expiresAt,
    DEFAULT_ATTESTATION_MAX_AGE_MS,
  );
  const matched = manifest !== undefined && runtime !== undefined;
  const callable = matched
    && manifest.authenticated
    && manifest.healthy
    && runtime.configured !== false
    && runtime.authenticated
    && runtime.callable
    && runtime.health === "healthy";

  if (!matched) {
    return result({
      componentKind: "provider",
      componentId: sourceId,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: "fail",
      availability: "unavailable",
      checkedAt,
      freshness: sourceFreshness,
      explanation: manifest
        ? "The provider exists in the capability manifest, but no matching live readiness route is present."
        : "A live provider readiness route exists without a matching capability manifest, so its catalog and model claims are not trusted.",
      remediation: "Reconcile the provider registry with the live readiness adapter, then obtain a fresh content-free attestation.",
    });
  }
  if (!callable) {
    return result({
      componentKind: "provider",
      componentId: sourceId,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: "fail",
      availability: "unavailable",
      checkedAt,
      freshness: sourceFreshness,
      explanation: "The registered provider is not simultaneously configured, authenticated, healthy, and callable through the local runtime boundary.",
      remediation: "Restore the provider configuration and authentication, then complete a bounded content-free readiness attestation.",
    });
  }
  if (sourceFreshness.state !== "fresh") {
    return result({
      componentKind: "provider",
      componentId: sourceId,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: sourceFreshness.state === "stale" ? "fail" : "degraded",
      availability: sourceFreshness.state === "stale" ? "unavailable" : "degraded",
      checkedAt,
      freshness: sourceFreshness,
      explanation: sourceFreshness.state === "stale"
        ? "The provider's last recorded attestation is stale, so callability is not accepted as current."
        : "The provider reports a callable route, but its attestation freshness cannot be independently established from the registry.",
      remediation: "Refresh the bounded provider attestation and retain its observation and expiry timestamps.",
    });
  }
  return result({
    componentKind: "provider",
    componentId: sourceId,
    componentIndex: index,
    testKind: "runtime_attestation",
    status: "pass",
    availability: "available",
    checkedAt,
    freshness: sourceFreshness,
    explanation: "The registered provider has a matching, fresh, authenticated, callable runtime attestation. Its execution and disclosure modes remain governed separately.",
  });
}

function mcpResult(
  manifest: RuntimeMcpServerManifest | undefined,
  projection: McpServerProjection | undefined,
  runtimeInput: RuntimeProjectionInput,
  checkedAt: string,
  now: Date,
  index: number,
  exactManifestServers: ReadonlySet<string>,
  exactRuntimeServers: ReadonlySet<string>,
): CapabilitySelfTestResult {
  const sourceId = manifest?.id ?? projection?.id ?? `mcp-${index + 1}`;
  const projectionExpiry = typeof projection?.policy.expiresAt === "string"
    ? projection.policy.expiresAt
    : null;
  const sourceFreshness = freshness(
    now,
    projection?.lastCheckedAt,
    projectionExpiry,
    DEFAULT_ATTESTATION_MAX_AGE_MS,
  );
  const globallyEnabled = runtimeInput.readiness.mcp.enabled
    && runtimeInput.readiness.mcp.executionMode === "enabled"
    && runtimeInput.readiness.mcp.startPermitted;
  const boundedMissionReadAdapter = projection?.policy.missionScopedReadAdapter === true
    && projection.policy.readOnly === true
    && projection.policy.targetInteraction === false
    && projection.policy.attested === true
    && projection.policy.executionAuthorization === "none"
    && typeof projection.policy.expiresAt === "string"
    && typeof projection.policy.manifestSha256 === "string"
    && /^[a-f0-9]{64}$/u.test(projection.policy.manifestSha256);
  const matched = manifest !== undefined && projection !== undefined;
  const manifestHealthy = manifest?.status === "healthy";
  const projectionHealthy = projection?.status === "healthy";
  const exactInventory = manifest !== undefined
    && projection !== undefined
    && exactManifestAndRuntimeInventory(
      manifest,
      projection,
      exactManifestServers,
      exactRuntimeServers,
    );

  if (!matched) {
    return result({
      componentKind: "mcp_server",
      componentId: sourceId,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: "fail",
      availability: "unavailable",
      checkedAt,
      freshness: sourceFreshness,
      explanation: manifest
        ? "The MCP server is registered in the capability manifest, but no matching runtime server projection is present."
        : "An MCP runtime projection exists without a matching capability manifest, so its exposed tools are not trusted.",
      remediation: "Reconcile the MCP manifest and runtime server registry, then complete a bounded tools/list attestation.",
    });
  }
  if (!exactInventory) {
    return result({
      componentKind: "mcp_server",
      componentId: sourceId,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: "fail",
      availability: "unavailable",
      checkedAt,
      freshness: sourceFreshness,
      explanation: "The MCP runtime inventory does not exactly account for every fully-qualified tool ID declared by its capability manifest.",
      remediation: "Refresh the bounded tools/list attestation and reconcile exact IDs in the form mcp:<server-id>/<tool-id> before using this route.",
    });
  }
  const executionRuntimeReady = globallyEnabled && runtimeInput.readiness.mcp.runnableServers > 0;
  if ((!executionRuntimeReady && !boundedMissionReadAdapter) || !manifestHealthy || !projectionHealthy) {
    return result({
      componentKind: "mcp_server",
      componentId: sourceId,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: "fail",
      availability: "unavailable",
      checkedAt,
      freshness: sourceFreshness,
      explanation: "The registered MCP server is disabled, unrunnable, or not healthy in both the manifest and runtime projection.",
      remediation: "Restore the declared MCP dependency and bounded tools/list attestation without invoking a target-interactive tool.",
    });
  }
  if (sourceFreshness.state !== "fresh") {
    return result({
      componentKind: "mcp_server",
      componentId: sourceId,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: sourceFreshness.state === "stale" ? "fail" : "degraded",
      availability: sourceFreshness.state === "stale" ? "unavailable" : "degraded",
      checkedAt,
      freshness: sourceFreshness,
      explanation: sourceFreshness.state === "stale"
        ? "The MCP server's last recorded readiness check is stale, so its route remains unavailable."
        : "The MCP server reports healthy, but the registry does not provide a timestamp that proves the attestation is current.",
      remediation: "Refresh the bounded tools/list attestation and retain its observation timestamp.",
    });
  }
  return result({
    componentKind: "mcp_server",
    componentId: sourceId,
    componentIndex: index,
    testKind: "runtime_attestation",
    status: "pass",
    availability: "available",
    checkedAt,
    freshness: sourceFreshness,
    explanation: boundedMissionReadAdapter
      ? "The MCP server has matching healthy registry state, an exact fresh tool inventory, and a mission-scoped read-only adapter. It grants no generic mission execution authority."
      : "The MCP server has matching healthy registry state and an exact fresh bounded tools/list check. No tool was invoked by this self-test.",
  });
}

function mappedModelRouteReady(
  tool: RuntimeToolManifest,
  manifests: RuntimeSourceManifests,
  runtimeInput: RuntimeProjectionInput,
): boolean {
  if (tool.requiresModel === false) return true;
  const callableProviderIds = new Set(runtimeInput.readiness.providers
    .filter((provider) => provider.configured !== false
      && provider.health === "healthy"
      && provider.authenticated
      && provider.callable)
    .map(({ id }) => id));
  const providerById = new Map(manifests.providers.map((provider) => [provider.id, provider]));
  return manifests.agents
    .filter((agent) => agent.available && agent.toolIds.includes(tool.id))
    .some((agent) => agent.modelRefs.some((reference) => {
      const provider = providerById.get(reference.providerId);
      return callableProviderIds.has(reference.providerId)
        && provider?.authenticated === true
        && provider.healthy
        && provider.models.some(({ id }) => id === reference.modelId);
    }));
}

type ToolDependency = NonNullable<RuntimeToolManifest["dependencies"]>[number];

function exactIsoTime(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
    ? parsed
    : null;
}

function runtimeAdapterAttestationValid(
  attestation: RuntimeAdapterAttestation,
  now: Date,
): boolean {
  const observedAt = exactIsoTime(attestation.observedAt);
  const expiresAt = exactIsoTime(attestation.expiresAt);
  return runtimeAdapterAttestationIntegrityValid(attestation)
    && observedAt !== null
    && observedAt <= now.getTime()
    && expiresAt !== null
    && expiresAt > observedAt
    && expiresAt > now.getTime();
}

function localDependencyActivationBound(
  tool: RuntimeToolManifest,
  dependency: ToolDependency,
  preflight: ToolExecutionPreflightResult | undefined,
  now: Date,
): boolean {
  const activation = dependency.attestation;
  if (!dependency.ready || !activation || tool.mcpServerId !== undefined || !preflight) return false;
  const observedAt = exactIsoTime(activation.observedAt);
  const expiresAt = exactIsoTime(activation.expiresAt);
  const preflightCheckedAt = exactIsoTime(preflight.checkedAt);
  const preflightExpiresAt = exactIsoTime(preflight.expiresAt);
  return activation.schemaVersion === "ti-scale.local-tool-activation-receipt.v1"
    && activation.source === "local_guided_tool_activation"
    && /^[a-f0-9]{64}$/u.test(activation.manifestSha256)
    && /^[a-f0-9]{64}$/u.test(activation.toolBindingSha256)
    && /^[a-f0-9]{64}$/u.test(activation.preflightBindingSha256)
    && /^[a-f0-9]{64}$/u.test(activation.executableSha256)
    && preflight.schemaVersion === "ti-scale.tool-execution-preflight.v2"
    && preflight.toolId === tool.id
    && preflight.status === "ready"
    && preflight.code === "ready"
    && preflight.bindingSha256 === activation.preflightBindingSha256
    && preflight.executableIdentity?.sha256 === activation.executableSha256
    && observedAt !== null
    && observedAt <= now.getTime()
    && expiresAt !== null
    && expiresAt > now.getTime()
    && expiresAt > observedAt
    && preflightCheckedAt !== null
    && preflightCheckedAt <= observedAt
    && preflightExpiresAt !== null
    && expiresAt <= preflightExpiresAt;
}

function sameLocalActivation(
  left: NonNullable<ToolDependency["attestation"]>,
  right: NonNullable<ToolDependency["attestation"]>,
): boolean {
  return left.schemaVersion === right.schemaVersion
    && left.source === right.source
    && left.manifestSha256 === right.manifestSha256
    && left.toolBindingSha256 === right.toolBindingSha256
    && left.preflightBindingSha256 === right.preflightBindingSha256
    && left.executableSha256 === right.executableSha256
    && left.observedAt === right.observedAt
    && left.expiresAt === right.expiresAt;
}

function toolResult(
  tool: RuntimeToolManifest,
  manifests: RuntimeSourceManifests,
  runtimeInput: RuntimeProjectionInput,
  mcpAttestations: ReadonlyMap<string, CapabilitySelfTestResult>,
  toolAttestations: ReadonlyMap<string, CapabilitySelfTestResult>,
  preflight: ToolExecutionPreflightResult | undefined,
  checkedAt: string,
  now: Date,
  index: number,
): CapabilitySelfTestResult {
  const dependencies = tool.dependencies ?? [];
  const dependencyBooleansReady = dependencies.every(({ ready }) => ready);
  const constituentToolIds = tool.constituentToolIds ?? [];
  if (constituentToolIds.length > 0) {
    const constituents = constituentToolIds.map((toolId) => manifests.tools.find(({ id }) => id === toolId));
    const attestations = constituentToolIds.map((toolId) => toolAttestations.get(toolId));
    const unavailableConstituentIds = constituentToolIds.filter((_toolId, index) => {
      const constituent = constituents[index];
      const attestation = attestations[index];
      return constituent?.available !== true
        || constituent.locallyPolicyEnforced !== true
        || attestation?.status !== "pass"
        || attestation.availability !== "available"
        || attestation.freshness.state !== "fresh";
    });
    const modelReady = mappedModelRouteReady(tool, manifests, runtimeInput);
    const constituentFreshness = attestations
      .map((attestation) => attestation?.freshness)
      .filter((entry): entry is CapabilitySelfTestFreshness => entry !== undefined);
    const observedTimes = constituentFreshness
      .map(({ observedAt }) => parsedTime(observedAt))
      .filter((value): value is number => value !== null);
    const expiryTimes = constituentFreshness
      .map(({ expiresAt }) => parsedTime(expiresAt))
      .filter((value): value is number => value !== null);
    const aggregateFreshness: CapabilitySelfTestFreshness = {
      state: unavailableConstituentIds.length === 0 ? "fresh" : "unknown",
      observedAt: observedTimes.length === constituentToolIds.length
        ? new Date(Math.max(...observedTimes)).toISOString()
        : null,
      expiresAt: expiryTimes.length === constituentToolIds.length
        ? new Date(Math.min(...expiryTimes)).toISOString()
        : null,
      maximumAgeMs: null,
    };
    const issues: string[] = [];
    if (!tool.available) issues.push("the composite action is not active in the current runtime projection");
    if (!dependencyBooleansReady) issues.push("one or more composite dependencies are unavailable");
    if (unavailableConstituentIds.length > 0) {
      issues.push(`constituent activation is unavailable: ${unavailableConstituentIds.join(", ")}`);
    }
    if (!modelReady) issues.push("no compatible model route is available for this composite action");
    if (issues.length > 0) {
      return result({
        componentKind: "tool",
        componentId: tool.id,
        componentIndex: index,
        testKind: "manifest_dependency",
        status: "fail",
        availability: "unavailable",
        checkedAt,
        freshness: aggregateFreshness,
        explanation: `The registered composite tool cannot run because ${issues.join("; ")}.`,
        remediation: "Restore every named constituent through its exact reviewed target-free activation probe, then refresh the composite runtime projection.",
      });
    }
    if (!tool.locallyPolicyEnforced) {
      return result({
        componentKind: "tool",
        componentId: tool.id,
        componentIndex: index,
        testKind: "manifest_dependency",
        status: "degraded",
        availability: "degraded",
        checkedAt,
        freshness: aggregateFreshness,
        explanation: "Every constituent executable is freshly attested, but the planner-visible composite has no locally enforced policy adapter.",
        remediation: "Bind the composite action to an enforceable local policy adapter before mission use.",
      });
    }
    return result({
      componentKind: "tool",
      componentId: tool.id,
      componentIndex: index,
      testKind: "local_executable_attestation",
      status: "pass",
      availability: "available",
      checkedAt,
      freshness: aggregateFreshness,
      explanation: `The planner-visible composite is backed by ${constituentToolIds.length} exact, fresh, independently attested local executable binding${constituentToolIds.length === 1 ? "" : "s"} and a locally enforced action boundary.`,
    });
  }
  const runtimeAdapter = tool.runtimeAdapterAttestation;
  if (runtimeAdapter) {
    const sourceFreshness = freshness(
      now,
      runtimeAdapter.observedAt,
      runtimeAdapter.expiresAt,
      null,
    );
    const adapterValid = runtimeAdapterAttestationValid(runtimeAdapter, now)
      && runtimeAdapter.toolId === tool.id
      && runtimeAdapter.dependencyId === undefined
      && runtimeAdapter.parentBindingSha256 === undefined
      && tool.executionJourneys !== undefined
      && tool.executionJourneys.length === runtimeAdapter.executionJourneys.length
      && tool.executionJourneys.every(
        (journey, index) => journey === runtimeAdapter.executionJourneys[index],
      );
    const dependencyAttestationsValid = dependencies.every((dependency) => {
      const attestation = dependency.runtimeAdapterAttestation;
      return dependency.ready
        && attestation !== undefined
        && runtimeAdapterAttestationValid(attestation, now)
        && attestation.toolId === tool.id
        && attestation.dependencyId === dependency.id
        && attestation.parentBindingSha256 === runtimeAdapter.bindingSha256
        && attestation.bindingSha256 !== runtimeAdapter.bindingSha256
        && attestation.executionJourneys.length
          === runtimeAdapter.executionJourneys.length
        && attestation.executionJourneys.every(
          (journey, index) => journey === runtimeAdapter.executionJourneys[index],
        )
        && attestation.observedAt === runtimeAdapter.observedAt
        && attestation.expiresAt === runtimeAdapter.expiresAt;
    });
    const modelReady = mappedModelRouteReady(tool, manifests, runtimeInput);
    const issues: string[] = [];
    if (!adapterValid) {
      issues.push("its exact runtime-composition receipt is malformed, future-dated, or expired");
    }
    if (!tool.available) {
      issues.push("the mounted in-process adapter is not currently available");
    }
    if (!dependencyBooleansReady) {
      issues.push("one or more required runtime components report unavailable");
    }
    if (!dependencyAttestationsValid) {
      issues.push("one or more runtime components lack a distinct current binding receipt");
    }
    if (!modelReady) {
      issues.push("no compatible live model route is bound to its specialist");
    }
    if (!tool.locallyPolicyEnforced) {
      issues.push("its local action boundary is not policy-enforced");
    }
    if (issues.length > 0) {
      return result({
        componentKind: "tool",
        componentId: tool.id,
        componentIndex: index,
        testKind: "runtime_attestation",
        status: "fail",
        availability: "unavailable",
        checkedAt,
        freshness: sourceFreshness,
        explanation: `The in-process runtime adapter cannot run because ${issues.join("; ")}.`,
        remediation: "Recompose the exact reviewed adapter objects, configuration, dependencies, and local provider under one fresh expiring runtime receipt.",
      });
    }
    return result({
      componentKind: "tool",
      componentId: tool.id,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: "pass",
      availability: "available",
      checkedAt,
      freshness: sourceFreshness,
      explanation: dependencies.length === 0
        ? "The in-process adapter is bound to the exact reviewed runtime composition by a fresh expiring receipt and an enforced local action boundary."
        : `The in-process adapter and ${dependencies.length} required runtime component${dependencies.length === 1 ? "" : "s"} are bound by distinct fresh receipts under one enforced local action boundary.`,
    });
  }
  const firstLocalActivation = dependencies[0]?.attestation;
  const localDependenciesAttested = tool.mcpServerId !== undefined || (
    dependencies.length > 0
    && firstLocalActivation !== undefined
    && dependencies.every((dependency) => dependency.attestation !== undefined
      && sameLocalActivation(firstLocalActivation, dependency.attestation)
      && localDependencyActivationBound(tool, dependency, preflight, now))
  );
  const dependenciesReady = dependencyBooleansReady && localDependenciesAttested;
  const mcpAttestation = tool.mcpServerId === undefined
    ? undefined
    : mcpAttestations.get(tool.mcpServerId);
  const mcpReady = tool.mcpServerId === undefined
    || mcpAttestation?.availability === "available";
  const modelReady = mappedModelRouteReady(tool, manifests, runtimeInput);

  if (tool.mcpServerId === undefined && !preflight) {
    return result({
      componentKind: "tool",
      componentId: tool.id,
      componentIndex: index,
      testKind: "local_executable_attestation",
      status: "fail",
      availability: "unavailable",
      checkedAt,
      freshness: unknownFreshness(),
      explanation: "The local tool has no current executable-identity and isolated startup receipt, so its manifest claim is not accepted as usable.",
      remediation: "Run the exact reviewed version/help probe through a worker that enforces network isolation, disposable writes, and sealed immutable-snapshot execution, then reconcile the expiring receipt into the runtime manifest.",
    });
  }
  if (tool.mcpServerId === undefined && preflight) {
    const issuedAt = Date.parse(preflight.checkedAt);
    const expiresAt = Date.parse(preflight.expiresAt);
    const preflightFreshness = freshness(
      now,
      preflight.checkedAt,
      preflight.expiresAt,
      null,
    );
    const receiptBoundaryValid = preflight.schemaVersion === "ti-scale.tool-execution-preflight.v2"
      && preflight.toolId === tool.id
      && /^[a-f0-9]{64}$/u.test(preflight.bindingSha256)
      && Number.isFinite(issuedAt)
      && Number.isFinite(expiresAt)
      && expiresAt > issuedAt
      && preflight.probeBoundary.shell === false
      && preflight.probeBoundary.networkIsolationEnforced
      && preflight.probeBoundary.filesystemWriteIsolationEnforced
      && preflight.probeBoundary.immutableSnapshotExecutionEnforced
      && preflight.probeBoundary.targetArgumentsSupplied === false
      && preflight.probeBoundary.providerArgumentsSupplied === false
      && preflight.probeBoundary.mcpArgumentsSupplied === false
      && preflight.executableIdentity !== null
      && /^[a-f0-9]{64}$/u.test(preflight.executableIdentity.sha256);
    if (preflight.status !== "ready" || preflight.code !== "ready" || !receiptBoundaryValid) {
      return result({
        componentKind: "tool",
        componentId: tool.id,
        componentIndex: index,
        testKind: "local_executable_attestation",
        status: "fail",
        availability: "unavailable",
        checkedAt,
        freshness: preflightFreshness,
        explanation: preflight.status === "unavailable"
          ? "The exact local readiness runner reports this binding unavailable. Its raw process output and dependency payload are not exposed by this self-test."
          : "The local tool receipt does not prove its exact tool identity, valid lifetime, all three execution boundaries, and executable identity, so it cannot make the tool available.",
        remediation: "Inspect the redacted canonical readiness receipt, then repeat the exact reviewed probe through a worker that enforces network isolation, disposable writes, and sealed immutable-snapshot execution.",
      });
    }
    if (preflightFreshness.state !== "fresh") {
      return result({
        componentKind: "tool",
        componentId: tool.id,
        componentIndex: index,
        testKind: "local_executable_attestation",
        status: preflightFreshness.state === "stale" ? "fail" : "degraded",
        availability: preflightFreshness.state === "stale" ? "unavailable" : "degraded",
        checkedAt,
        freshness: preflightFreshness,
        explanation: preflightFreshness.state === "stale"
          ? "The exact isolated tool startup receipt has expired, so the binding is no longer accepted as usable."
          : "A tool startup result exists, but its observation time cannot be accepted as current.",
        remediation: "Repeat the exact reviewed version/help check through the isolated tool runtime.",
      });
    }
  }

  if (!tool.available || !dependenciesReady || !mcpReady || !modelReady) {
    const publicToolId = safeComponentId("tool", tool.id, index);
    const missingDependencyIds = dependencies
      .filter(({ ready }) => !ready)
      .map((dependency, dependencyIndex) =>
        safeComponentId("tool_dependency", dependency.id, dependencyIndex));
    const issues: string[] = [];
    const remediations: string[] = [];
    if (!tool.available) {
      if (tool.mcpServerId === undefined) {
        issues.push(`${publicToolId} has no current manifest-bound local activation receipt.`);
        remediations.push("Repeat its reviewed target-free startup probe and reconcile the fresh receipt into the runtime manifest.");
      } else {
        issues.push(`${publicToolId} is absent or unavailable in its current closed MCP inventory.`);
        remediations.push("Repeat the exact MCP tools/list attestation and restore this declared binding only if it is present.");
      }
    }
    if (missingDependencyIds.length > 0) {
      issues.push(
        `${publicToolId} is waiting for ${missingDependencyIds.length === 1 ? "dependency" : "dependencies"}: ${missingDependencyIds.join(", ")}.`,
      );
      remediations.push("Restore only the named dependency and obtain a fresh bounded receipt without contacting a mission target.");
    }
    if (dependencyBooleansReady && !localDependenciesAttested) {
      issues.push(`${publicToolId}'s ready dependency claims do not join to one current exact activation receipt.`);
      remediations.push("Repeat the reviewed local activation wave so every dependency shares the exact manifest, binding, executable, observation, and expiry proof.");
    }
    if (!mcpReady && tool.mcpServerId !== undefined) {
      const publicMcpId = mcpAttestation?.component.id
        ?? safeComponentId("mcp_server", tool.mcpServerId, index);
      issues.push(`${publicToolId} requires MCP server ${publicMcpId}, whose current attestation is unavailable.`);
      remediations.push("Restore that exact server and repeat its bounded tools/list inventory attestation.");
    }
    if (!modelReady) {
      issues.push(`${publicToolId} has no available tool-bound specialist with a live callable mapped model route.`);
      remediations.push("Restore the exact specialist assignment and its configured, authenticated, callable model route.");
    }
    return result({
      componentKind: "tool",
      componentId: tool.id,
      componentIndex: index,
      testKind: "manifest_dependency",
      status: "fail",
      availability: "unavailable",
      checkedAt,
      freshness: unknownFreshness(),
      explanation: `The registered tool cannot run. ${issues.join(" ")}`,
      remediation: [...new Set(remediations)].join(" "),
    });
  }
  if (!tool.locallyPolicyEnforced) {
    return result({
      componentKind: "tool",
      componentId: tool.id,
      componentIndex: index,
      testKind: "manifest_dependency",
      status: "degraded",
      availability: "degraded",
      checkedAt,
      freshness: unknownFreshness(),
      explanation: "The registered tool and declared dependencies are available, but the local runtime does not attest policy enforcement for this binding.",
      remediation: "Bind the tool to an enforceable local policy adapter before considering it for a future mission contract.",
    });
  }
  if (tool.mcpServerId === undefined && preflight?.status === "ready") {
    return result({
      componentKind: "tool",
      componentId: tool.id,
      componentIndex: index,
      testKind: "local_executable_attestation",
      status: "pass",
      availability: "available",
      checkedAt,
      freshness: freshness(now, preflight.checkedAt, preflight.expiresAt, null),
      explanation: "The registered tool has a fresh isolated startup receipt bound to its exact executable identity and a locally enforced dependency chain. Mission execution still requires its exact action boundary.",
    });
  }
  if (tool.mcpServerId !== undefined && mcpAttestation) {
    return result({
      componentKind: "tool",
      componentId: tool.id,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: "pass",
      availability: "available",
      checkedAt,
      freshness: mcpAttestation.freshness,
      explanation: "The exact remote tool is present in its fresh MCP inventory and its declared dependency and local policy boundaries are ready. This does not grant execution outside the represented adapter.",
    });
  }
  return result({
    componentKind: "tool",
    componentId: tool.id,
    componentIndex: index,
    testKind: "manifest_dependency",
    status: "degraded",
    availability: "degraded",
    checkedAt,
    freshness: unknownFreshness(),
    explanation: "The registered tool declares an available, locally enforced dependency chain, but no independent live tool timestamp exists. This self-test did not invoke it.",
    remediation: "Add a content-free, non-target readiness attestation with an expiry before presenting the tool as freshly available.",
  });
}

function toolDependencyResult(
  tool: RuntimeToolManifest,
  dependency: ToolDependency,
  toolAttestation: CapabilitySelfTestResult | undefined,
  preflight: ToolExecutionPreflightResult | undefined,
  checkedAt: string,
  now: Date,
  index: number,
): CapabilitySelfTestResult {
  const sourceFreshness = freshness(
    now,
    dependency.runtimeAdapterAttestation?.observedAt
      ?? dependency.attestation?.observedAt,
    dependency.runtimeAdapterAttestation?.expiresAt
      ?? dependency.attestation?.expiresAt,
    null,
  );
  if (!dependency.ready) {
    return result({
      componentKind: "tool_dependency",
      componentId: `${tool.id}/${dependency.id}`,
      componentIndex: index,
      testKind: "manifest_dependency",
      status: "fail",
      availability: "unavailable",
      checkedAt,
      freshness: sourceFreshness,
      explanation: "The runtime explicitly reports this required tool dependency unavailable.",
      remediation: "Restore the declared dependency without invoking a target-interactive operation.",
    });
  }

  if (tool.mcpServerId !== undefined
    && toolAttestation?.status === "pass"
    && toolAttestation.availability === "available"
    && toolAttestation.freshness.state === "fresh") {
    return result({
      componentKind: "tool_dependency",
      componentId: `${tool.id}/${dependency.id}`,
      componentIndex: index,
      testKind: "manifest_dependency",
      status: "pass",
      availability: "available",
      checkedAt,
      freshness: toolAttestation.freshness,
      explanation: "This dependency is covered by the same fresh exact MCP inventory and mission-scoped policy attestation as its registered tool.",
    });
  }

  const runtimeActivation = dependency.runtimeAdapterAttestation;
  if (runtimeActivation) {
    const parentActivation = tool.runtimeAdapterAttestation;
    const activationBound = parentActivation !== undefined
      && runtimeAdapterAttestationValid(parentActivation, now)
      && runtimeAdapterAttestationValid(runtimeActivation, now)
      && parentActivation.toolId === tool.id
      && parentActivation.dependencyId === undefined
      && runtimeActivation.toolId === tool.id
      && runtimeActivation.dependencyId === dependency.id
      && runtimeActivation.parentBindingSha256 === parentActivation.bindingSha256
      && runtimeActivation.bindingSha256 !== parentActivation.bindingSha256
      && runtimeActivation.observedAt === parentActivation.observedAt
      && runtimeActivation.expiresAt === parentActivation.expiresAt
      && toolAttestation?.status === "pass"
      && toolAttestation.availability === "available"
      && toolAttestation.freshness.state === "fresh";
    if (activationBound && sourceFreshness.state === "fresh") {
      return result({
        componentKind: "tool_dependency",
        componentId: `${tool.id}/${dependency.id}`,
        componentIndex: index,
        testKind: "runtime_attestation",
        status: "pass",
        availability: "available",
        checkedAt,
        freshness: sourceFreshness,
        explanation: "This in-process component has a distinct fresh binding receipt joined to the exact parent runtime adapter.",
      });
    }
    return result({
      componentKind: "tool_dependency",
      componentId: `${tool.id}/${dependency.id}`,
      componentIndex: index,
      testKind: "runtime_attestation",
      status: "fail",
      availability: "unavailable",
      checkedAt,
      freshness: sourceFreshness,
      explanation: "The in-process component receipt is expired, malformed, reused, or no longer joined to the exact parent runtime adapter.",
      remediation: "Recompose the parent adapter and this named component under distinct hashes and one current expiring lifetime.",
    });
  }

  const activation = dependency.attestation;
  if (activation) {
    const activationBound = toolAttestation?.status === "pass"
      && toolAttestation.availability === "available"
      && toolAttestation.freshness.state === "fresh"
      && (tool.constituentToolIds !== undefined
        || localDependencyActivationBound(tool, dependency, preflight, now));
    if (activationBound && sourceFreshness.state === "fresh") {
      return result({
        componentKind: "tool_dependency",
        componentId: `${tool.id}/${dependency.id}`,
        componentIndex: index,
        testKind: "manifest_dependency",
        status: "pass",
        availability: "available",
        checkedAt,
        freshness: sourceFreshness,
        explanation: "This dependency is covered by the same fresh, manifest-bound local activation receipt as the exact executable and enforced tool adapter.",
      });
    }
    return result({
      componentKind: "tool_dependency",
      componentId: `${tool.id}/${dependency.id}`,
      componentIndex: index,
      testKind: "manifest_dependency",
      status: sourceFreshness.state === "stale" ? "fail" : "degraded",
      availability: sourceFreshness.state === "stale" ? "unavailable" : "degraded",
      checkedAt,
      freshness: sourceFreshness,
      explanation: sourceFreshness.state === "stale"
        ? "The dependency activation receipt has expired, so this requirement is no longer accepted as ready."
        : "The dependency claim does not join to the exact fresh executable and local activation receipt.",
      remediation: "Repeat the bounded local activation wave and retain its exact manifest, binding, executable, observation, and expiry proof.",
    });
  }

  return result({
    componentKind: "tool_dependency",
    componentId: `${tool.id}/${dependency.id}`,
    componentIndex: index,
    testKind: "manifest_dependency",
    status: "degraded",
    availability: "degraded",
    checkedAt,
    freshness: unknownFreshness(),
    explanation: "The registry marks this tool dependency ready, but supplies no independent freshness timestamp.",
    remediation: "Retain a bounded dependency observation timestamp and expiry.",
  });
}

function localFailureResults(checkedAt: string, startIndex: number): CapabilitySelfTestResult[] {
  return ([
    ["database", "canonical", "local_integrity"],
    ["event_stream", "multiplexed", "service_state"],
    ["second_brain", "canonical", "canonical_read"],
    ["obsidian_vault", "projection", "vault_round_trip_receipt"],
  ] as const).map(([componentKind, componentId, testKind], offset) => result({
    componentKind,
    componentId,
    componentIndex: startIndex + offset,
    testKind,
    status: "fail",
    availability: "unavailable",
    checkedAt,
    freshness: unknownFreshness(),
    explanation: "The local read-only health reader could not establish this dependency's state safely.",
    remediation: "Inspect the local dependency health path using redacted diagnostics; do not bypass readiness.",
  }));
}

function localResults(
  local: CapabilityLocalHealthSnapshot,
  checkedAt: string,
  startIndex: number,
): CapabilitySelfTestResult[] {
  const databaseReady = local.database.healthy;
  const brainHealth = local.secondBrain.health;
  const vault = local.secondBrain.vaultProjection;
  const vaultReady = vault.status === "healthy";
  // Disconnected rows are retained history, not an active projection. Their
  // presence must not be presented as a degraded configured capability.
  const vaultConfigured = vault.status !== "not_configured";
  return [
    result({
      componentKind: "database",
      componentId: "canonical",
      componentIndex: startIndex,
      testKind: "local_integrity",
      status: databaseReady ? "pass" : "fail",
      availability: databaseReady ? "available" : "unavailable",
      checkedAt,
      freshness: freshness(new Date(checkedAt), local.database.checkedAt, null, LOCAL_CHECK_MAX_AGE_MS),
      explanation: databaseReady
        ? "The canonical database passed its cached integrity and foreign-key checks through the existing health reader."
        : "The canonical database did not pass the required integrity and foreign-key checks.",
      ...(databaseReady ? {} : { remediation: "Repair or restore the canonical database before mission activity; do not ignore integrity failures." }),
    }),
    result({
      componentKind: "event_stream",
      componentId: "multiplexed",
      componentIndex: startIndex + 1,
      testKind: "service_state",
      status: local.eventStream.started ? "pass" : "fail",
      availability: local.eventStream.started ? "available" : "unavailable",
      checkedAt,
      freshness: freshness(new Date(checkedAt), local.checkedAt, null, LOCAL_CHECK_MAX_AGE_MS),
      explanation: local.eventStream.started
        ? "The canonical event-stream service is started; this check did not publish an event or open a subscriber."
        : "The canonical event-stream service is not started.",
      ...(local.eventStream.started ? {} : { remediation: "Start the local durable event-stream service before relying on live operational updates." }),
    }),
    result({
      componentKind: "second_brain",
      componentId: "canonical",
      componentIndex: startIndex + 2,
      testKind: "canonical_read",
      status: brainHealth === "healthy" ? "pass" : brainHealth === "degraded" ? "degraded" : "fail",
      availability: brainHealth === "healthy" ? "available" : brainHealth === "degraded" ? "degraded" : "unavailable",
      checkedAt,
      freshness: freshness(new Date(checkedAt), local.checkedAt, null, LOCAL_CHECK_MAX_AGE_MS),
      explanation: brainHealth === "healthy"
        ? "The canonical Second Brain policy, graph store, and lexical projection are readable through the runtime's existing health path."
        : brainHealth === "degraded"
          ? "The canonical Second Brain is readable, but at least one retrieval projection is degraded."
          : "The canonical Second Brain could not be read safely through its runtime health path.",
      ...(brainHealth === "healthy" ? {} : { remediation: "Restore the canonical Brain policy, schema, and retrieval projection before memory-dependent mission work." }),
    }),
    result({
      componentKind: "obsidian_vault",
      componentId: "projection",
      componentIndex: startIndex + 3,
      testKind: "vault_round_trip_receipt",
      status: vaultReady ? "pass" : vaultConfigured ? "degraded" : "fail",
      availability: vaultReady ? "available" : vaultConfigured ? "degraded" : "unavailable",
      checkedAt,
      freshness: freshness(new Date(checkedAt), local.checkedAt, null, LOCAL_CHECK_MAX_AGE_MS),
      explanation: vaultReady
        ? `${vault.healthVerifiedConnections} configured Vault connection${vault.healthVerifiedConnections === 1 ? " has" : "s have"} a reachable path and persisted round-trip verification receipt.`
        : vaultConfigured
          ? "A Vault connection is configured, but connection, reachability, or persisted round-trip verification is incomplete."
          : "No active Obsidian Vault projection is configured. The canonical Second Brain remains a separate local dependency.",
      ...(vaultReady ? {} : { remediation: "Use the bounded Vault connection workflow and complete its write/read/rename/delete round-trip proof; this self-test remains read-only." }),
    }),
  ];
}

function runtimeOnlyProviders(
  manifests: RuntimeSourceManifests,
  runtime: RuntimeProjectionInput,
): ProviderReadiness[] {
  const manifestIds = new Set(manifests.providers.map(({ id }) => id));
  return runtime.readiness.providers.filter(({ id }) => !manifestIds.has(id));
}

function runtimeOnlyMcpServers(
  manifests: RuntimeSourceManifests,
  runtime: RuntimeProjectionInput,
): McpServerProjection[] {
  const manifestIds = new Set(manifests.mcpServers.map(({ id }) => id));
  return runtime.mcpServers.filter(({ id }) => !manifestIds.has(id));
}

export class CapabilitySelfTestService {
  private readonly options: CapabilitySelfTestServiceOptions;

  constructor(options: CapabilitySelfTestServiceOptions) {
    this.options = options;
  }

  snapshot(): CapabilitySelfTestSnapshot {
    const now = (this.options.clock ?? (() => new Date()))();
    const checkedAt = now.toISOString();
    const results: CapabilitySelfTestResult[] = [];
    let runtimeInput: RuntimeProjectionInput | undefined;
    let runtimeRegistryRead = false;
    try {
      runtimeInput = this.options.readRuntimeProjection();
      runtimeRegistryRead = runtimeInput.capabilityManifests !== undefined;
    } catch {
      runtimeInput = undefined;
    }
    const manifests = runtimeInput?.capabilityManifests ?? emptyRuntimeSourceManifests();
    const manifestValid = runtimeRegistryRead && structuralManifestValidity(manifests);
    const exactManifestMcpServers = manifestValid
      ? exactManifestMcpServerIds(manifests)
      : new Set<string>();
    const exactRuntimeMcpServers = runtimeInput
      ? exactRuntimeMcpServerIds(runtimeInput.mcpServers)
      : new Set<string>();
    results.push(result({
      componentKind: "registry",
      componentId: "runtime-capability-manifest",
      componentIndex: 0,
      testKind: "manifest_integrity",
      status: manifestValid ? "pass" : "fail",
      availability: manifestValid ? "available" : "unavailable",
      checkedAt,
      freshness: runtimeRegistryRead ? currentFreshness(checkedAt) : unknownFreshness(),
      explanation: manifestValid
        ? "The current runtime capability manifests are structurally valid and all catalog and cross-registry references resolve."
        : "The runtime capability manifest is absent or structurally invalid, so no registered capability is promoted by this snapshot.",
      ...(manifestValid ? {} : { remediation: "Restore the canonical runtime manifests and repair duplicate, unknown, or broken references." }),
    }));

    let resultIndex = 1;
    const runtimeProviderById = new Map(runtimeInput?.readiness.providers.map((item) => [item.id, item]) ?? []);
    for (const manifest of manifests.providers) {
      results.push(manifestValid
        ? providerResult(
          manifest,
          runtimeProviderById.get(manifest.id),
          checkedAt,
          now,
          resultIndex++,
        )
        : invalidManifestComponentResult(
          "provider",
          manifest.id,
          resultIndex++,
          checkedAt,
        ));
    }
    if (runtimeInput) {
      for (const runtimeProvider of runtimeOnlyProviders(manifests, runtimeInput)) {
        results.push(providerResult(undefined, runtimeProvider, checkedAt, now, resultIndex++));
      }
    }

    const runtimeMcpById = new Map(runtimeInput?.mcpServers.map((item) => [item.id, item]) ?? []);
    const mcpAttestations = new Map<string, CapabilitySelfTestResult>();
    const toolAttestations = new Map<string, CapabilitySelfTestResult>();
    if (runtimeInput) {
      for (const manifest of manifests.mcpServers) {
        const entry = manifestValid
          ? mcpResult(
            manifest,
            runtimeMcpById.get(manifest.id),
            runtimeInput,
            checkedAt,
            now,
            resultIndex++,
            exactManifestMcpServers,
            exactRuntimeMcpServers,
          )
          : invalidManifestComponentResult(
            "mcp_server",
            manifest.id,
            resultIndex++,
            checkedAt,
          );
        results.push(entry);
        mcpAttestations.set(manifest.id, entry);
      }
      for (const runtimeMcp of runtimeOnlyMcpServers(manifests, runtimeInput)) {
        const entry = mcpResult(
          undefined,
          runtimeMcp,
          runtimeInput,
          checkedAt,
          now,
          resultIndex++,
          exactManifestMcpServers,
          exactRuntimeMcpServers,
        );
        results.push(entry);
        mcpAttestations.set(runtimeMcp.id, entry);
      }
      // Executable tools are attested before planner-visible composites so a
      // composite can only pass by joining the already evaluated exact
      // constituent receipts. Manifest order is not treated as authority.
      const orderedTools = [
        ...manifests.tools.filter(({ constituentToolIds }) => constituentToolIds === undefined),
        ...manifests.tools.filter(({ constituentToolIds }) => constituentToolIds !== undefined),
      ];
      for (const tool of orderedTools) {
        const entry = manifestValid
          ? toolResult(
            tool,
            manifests,
            runtimeInput,
            mcpAttestations,
            toolAttestations,
            tool.constituentToolIds === undefined
              ? this.options.readToolExecutionPreflight?.(tool.id)
              : undefined,
            checkedAt,
            now,
            resultIndex++,
          )
          : invalidManifestComponentResult(
            "tool",
            tool.id,
            resultIndex++,
            checkedAt,
          );
        results.push(entry);
        toolAttestations.set(tool.id, entry);
      }
      let dependencyIndex = 0;
      for (const tool of manifests.tools) {
        for (const dependency of tool.dependencies ?? []) {
          results.push(manifestValid
            ? toolDependencyResult(
              tool,
              dependency,
              toolAttestations.get(tool.id),
              tool.constituentToolIds === undefined
                ? this.options.readToolExecutionPreflight?.(tool.id)
                : undefined,
              checkedAt,
              now,
              dependencyIndex++,
            )
            : invalidManifestComponentResult(
              "tool_dependency",
              `${tool.id}/${dependency.id}`,
              dependencyIndex++,
              checkedAt,
            ));
        }
      }
    }

    try {
      const local = this.options.repository.read();
      results.push(...localResults(local, checkedAt, resultIndex));
    } catch {
      results.push(...localFailureResults(checkedAt, resultIndex));
    }

    const providerCount = manifests.providers.length
      + (runtimeInput ? runtimeOnlyProviders(manifests, runtimeInput).length : 0);
    const mcpCount = manifests.mcpServers.length
      + (runtimeInput ? runtimeOnlyMcpServers(manifests, runtimeInput).length : 0);
    const toolCount = manifests.tools.length;
    const toolDependencyCount = manifests.tools.reduce(
      (total, tool) => total + (tool.dependencies?.length ?? 0),
      0,
    );
    const reported = {
      providers: results.filter(({ component }) => component.kind === "provider").length,
      mcpServers: results.filter(({ component }) => component.kind === "mcp_server").length,
      tools: results.filter(({ component }) => component.kind === "tool").length,
      toolDependencies: results.filter(({ component }) => component.kind === "tool_dependency").length,
    };
    const complete = runtimeRegistryRead
      && manifestValid
      && reported.providers === providerCount
      && reported.mcpServers === mcpCount
      && reported.tools === toolCount
      && reported.toolDependencies === toolDependencyCount;

    return {
      schemaVersion: "2.4",
      checkedAt,
      readOnly: true,
      grantsMissionExecution: false,
      accounting: {
        runtimeRegistryRead,
        manifestValid,
        complete,
        registered: {
          providers: providerCount,
          mcpServers: mcpCount,
          tools: toolCount,
          toolDependencies: toolDependencyCount,
        },
        reported,
      },
      summary: {
        total: results.length,
        pass: results.filter(({ status }) => status === "pass").length,
        degraded: results.filter(({ status }) => status === "degraded").length,
        fail: results.filter(({ status }) => status === "fail").length,
        available: results.filter(({ availability }) => availability === "available").length,
        degradedAvailability: results.filter(({ availability }) => availability === "degraded").length,
        unavailable: results.filter(({ availability }) => availability === "unavailable").length,
        unsupported: results.filter(({ availability }) => availability === "unsupported").length,
      },
      results,
    };
  }
}
