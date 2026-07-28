import {
  buildRuntimeCapabilityProjection,
  type RuntimeSourceManifests,
} from "../domain";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import {
  TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
  ToolBindingRegistry,
  type ToolBindingReadinessReceipt,
  type ToolBindingRegistryDocument,
} from "../system-capabilities";
import { WindowsIdentityToolPack } from "./WindowsIdentityToolPack";
import {
  WINDOWS_IDENTITY_READINESS_SCHEMA_VERSION,
  type WindowsIdentityToolDefinition,
  type WindowsIdentityToolReadinessReceipt,
} from "./types";

export const WINDOWS_IDENTITY_REGISTRY_VERSION =
  "windows-identity-2026.07.20-v1" as const;
const SHA256 = /^[a-f0-9]{64}$/u;

export interface WindowsIdentityAdapterBoundaryReadiness {
  readonly workspaceConfinementReady: boolean;
  readonly credentialIsolationReady: boolean;
  readonly outputBoundReady: boolean;
  readonly cancellationReady: boolean;
}

export interface WindowsIdentityCapabilityRegistryDescriptor {
  readonly registryVersion: typeof WINDOWS_IDENTITY_REGISTRY_VERSION;
  readonly manifestSha256: string;
  readonly toolCount: number;
  readonly sourceOfTruth: "reviewed-windows-identity-tool-pack";
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function validTime(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
    ? parsed
    : null;
}

function mergeUnique<T extends { readonly id: string }>(
  kind: string,
  base: readonly T[],
  additions: readonly T[],
): readonly T[] {
  const seen = new Set(base.map(({ id }) => id));
  for (const { id } of additions) {
    if (seen.has(id)) throw new Error(`Windows identity ${kind} ID collision: ${id}`);
    seen.add(id);
  }
  return Object.freeze([...base, ...additions]);
}

function mergeRiskClasses(
  base: RuntimeSourceManifests["riskClasses"],
  additions: RuntimeSourceManifests["riskClasses"],
): RuntimeSourceManifests["riskClasses"] {
  const merged = new Map(base.map((item) => [item.id, {
    ...item,
    actionClassIds: [...item.actionClassIds],
  }]));
  for (const item of additions) {
    const existing = merged.get(item.id);
    if (existing && existing.label !== item.label) {
      throw new Error(`Windows identity risk class ID collision: ${item.id}`);
    }
    merged.set(item.id, existing
      ? {
          ...existing,
          actionClassIds: [...new Set([
            ...existing.actionClassIds,
            ...item.actionClassIds,
          ])].sort(),
        }
      : { ...item, actionClassIds: [...item.actionClassIds] });
  }
  return deepFreeze([...merged.values()]);
}

export function windowsIdentityReadinessCurrent(
  definition: WindowsIdentityToolDefinition,
  receipt: WindowsIdentityToolReadinessReceipt | undefined,
  now: Date,
): boolean {
  if (!receipt) return false;
  const observedAt = validTime(receipt.observedAt);
  const expiresAt = validTime(receipt.expiresAt);
  return receipt.schemaVersion === WINDOWS_IDENTITY_READINESS_SCHEMA_VERSION
    && receipt.toolId === definition.toolId
    && receipt.executablePath === definition.executable.path
    && receipt.expectedExecutableSha256 === definition.executable.sha256
    && receipt.observedExecutableSha256 === definition.executable.sha256
    && receipt.status === "ready"
    && receipt.code === "ready"
    && receipt.directArgv === true
    && receipt.shell === false
    && receipt.targetContact === false
    && receipt.workspaceConfinementReady
    && receipt.credentialIsolationReady
    && receipt.outputBoundReady
    && receipt.cancellationReady
    && observedAt !== null
    && expiresAt !== null
    && observedAt <= now.getTime()
    && expiresAt > now.getTime()
    && receipt.grantsMissionExecution === false;
}

/**
 * Joins the generic target-free executable receipt to this pack's exact hash
 * and its separately attested execution adapter. Neither input grants mission
 * authority. The active capability projection remains Guided-only; its scope
 * and exact represented decision are rechecked at compile time.
 */
export function windowsIdentityReadinessReceipt(input: Readonly<{
  definition: WindowsIdentityToolDefinition;
  binding: ToolBindingReadinessReceipt;
  adapter: WindowsIdentityAdapterBoundaryReadiness;
}>): WindowsIdentityToolReadinessReceipt {
  const { definition, binding, adapter } = input;
  const observedSha256 = binding.executableIdentity?.sha256 ?? null;
  const identityMatches = observedSha256 === definition.executable.sha256;
  const probeReady = binding.status === "ready"
    && binding.code === "ready"
    && binding.probeBoundary.shell === false
    && binding.probeBoundary.targetArgumentsSupplied === false
    && binding.probeBoundary.providerArgumentsSupplied === false
    && binding.probeBoundary.mcpArgumentsSupplied === false
    && binding.probeBoundary.networkIsolationEnforced === true
    && binding.probeBoundary.filesystemWriteIsolationEnforced === true
    && binding.probeBoundary.immutableSnapshotExecutionEnforced === true;
  const adapterReady = adapter.workspaceConfinementReady
    && adapter.credentialIsolationReady
    && adapter.outputBoundReady
    && adapter.cancellationReady;
  const ready = identityMatches && probeReady && adapterReady;
  const code = ready
    ? "ready" as const
    : !identityMatches && observedSha256 !== null
      ? "windows_identity_tool_identity_changed" as const
      : !adapter.workspaceConfinementReady
        ? "windows_identity_workspace_not_confined" as const
        : !adapterReady
          ? "windows_identity_adapter_not_bounded" as const
          : "windows_identity_tool_unavailable" as const;
  const explanation = ready
    ? `${definition.label} passed its exact executable, isolated target-free probe, and bounded-adapter checks.`
    : code === "windows_identity_tool_identity_changed"
      ? `${definition.label} does not match the reviewed executable SHA-256.`
      : code === "windows_identity_workspace_not_confined"
        ? `${definition.label} has no current proof that tool state is confined to the engagement workspace.`
        : code === "windows_identity_adapter_not_bounded"
          ? `${definition.label} has no complete direct-argv, credential-isolation, output, and cancellation proof.`
          : `${definition.label} did not pass its isolated target-free startup probe: ${binding.explanation}`;
  return deepFreeze({
    schemaVersion: WINDOWS_IDENTITY_READINESS_SCHEMA_VERSION,
    toolId: definition.toolId,
    executablePath: definition.executable.path,
    expectedExecutableSha256: definition.executable.sha256,
    observedExecutableSha256: observedSha256,
    registryBindingSha256: binding.registryBindingSha256,
    preflightBindingSha256: binding.preflightBindingSha256,
    status: ready ? "ready" : "unavailable",
    code,
    directArgv: true,
    shell: false,
    targetContact: false,
    workspaceConfinementReady: adapter.workspaceConfinementReady,
    credentialIsolationReady: adapter.credentialIsolationReady,
    outputBoundReady: adapter.outputBoundReady,
    cancellationReady: adapter.cancellationReady,
    explanation,
    remediation: ready
      ? null
      : code === "windows_identity_tool_identity_changed"
        ? "Review the installed package version and pin its new executable SHA-256 before activation."
        : binding.remediation
          ?? "Restore the missing bounded adapter proof and repeat the target-free readiness wave.",
    observedAt: binding.checkedAt,
    expiresAt: binding.expiresAt,
    grantsMissionExecution: false,
  });
}

export class WindowsIdentityCapabilityRegistry {
  readonly pack = new WindowsIdentityToolPack();
  readonly descriptor: WindowsIdentityCapabilityRegistryDescriptor;

  constructor() {
    this.descriptor = deepFreeze({
      registryVersion: WINDOWS_IDENTITY_REGISTRY_VERSION,
      manifestSha256: digestCanonicalJson({
        schemaVersion: this.pack.schemaVersion,
        definitions: this.pack.definitions,
      }, { maxBytes: 256 * 1_024, maxDepth: 16 }).sha256,
      toolCount: this.pack.definitions.length,
      sourceOfTruth: "reviewed-windows-identity-tool-pack",
    });
  }

  toToolBindingRegistryDocument(): ToolBindingRegistryDocument {
    return deepFreeze({
      schemaVersion: TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
      registryVersion: WINDOWS_IDENTITY_REGISTRY_VERSION,
      bindings: this.pack.definitions.map((definition) => ({
        toolId: definition.toolId,
        executablePath: definition.executable.path,
        probeArguments: definition.probe.arguments as readonly [string],
        expectedExitCodes: definition.probe.expectedExitCodes,
        timeoutMs: definition.probe.timeoutMs,
        maximumOutputBytes: definition.probe.maximumOutputBytes,
        ttlMs: definition.probe.ttlMs,
      })),
    });
  }

  toRuntimeSourceManifests(
    receipts: readonly WindowsIdentityToolReadinessReceipt[] = [],
    now: Date = new Date(),
  ): RuntimeSourceManifests {
    const byTool = new Map(receipts.map((receipt) => [receipt.toolId, receipt]));
    if (byTool.size !== receipts.length) {
      throw new Error("Windows identity readiness contains duplicate tool IDs");
    }
    const capabilities = this.pack.definitions.map((definition) => ({
      id: `capability:${definition.toolId}`,
      label: `${definition.label} capability`,
      actionClassIds: [definition.actionClassId],
      evidenceTypeIds: [definition.evidenceTypeId],
    }));
    const available = new Map(this.pack.definitions.map((definition) => [
      definition.toolId,
      windowsIdentityReadinessCurrent(
        definition,
        byTool.get(definition.toolId),
        now,
      ),
    ]));
    const manifests: RuntimeSourceManifests = deepFreeze({
      riskClasses: [{
        id: "ti-scale:network",
        label: "Authorized network interaction",
        actionClassIds: ["active_directory_identity_operations"],
      }],
      evidenceKinds: [{
        id: "windows-identity:identity-ad-graph",
        label: "Identity and directory observation",
        evidenceTypeIds: ["identity_ad_graph"],
      }],
      capabilities,
      tools: this.pack.definitions.map((definition) => {
        const receipt = byTool.get(definition.toolId);
        const isAvailable = available.get(definition.toolId) === true;
        const observedAt = receipt ? validTime(receipt.observedAt) : null;
        const expiresAt = receipt ? validTime(receipt.expiresAt) : null;
        const receiptBoundToTool = receipt !== undefined
          && receipt.schemaVersion === WINDOWS_IDENTITY_READINESS_SCHEMA_VERSION
          && receipt.toolId === definition.toolId
          && receipt.executablePath === definition.executable.path
          && receipt.expectedExecutableSha256 === definition.executable.sha256
          && receipt.observedExecutableSha256 === definition.executable.sha256
          && SHA256.test(this.descriptor.manifestSha256)
          && SHA256.test(receipt.registryBindingSha256)
          && typeof receipt.preflightBindingSha256 === "string"
          && SHA256.test(receipt.preflightBindingSha256)
          && observedAt !== null
          && expiresAt !== null
          && expiresAt > observedAt;
        const attestation = receiptBoundToTool ? {
          schemaVersion: "ti-scale.local-tool-activation-receipt.v1" as const,
          source: "local_guided_tool_activation" as const,
          manifestSha256: this.descriptor.manifestSha256,
          toolBindingSha256: receipt.registryBindingSha256,
          preflightBindingSha256: receipt.preflightBindingSha256!,
          executableSha256: definition.executable.sha256,
          observedAt: receipt.observedAt,
          expiresAt: receipt.expiresAt,
        } : undefined;
        const dependency = (id: string, ready: boolean) => ({
          id,
          ready,
          ...(attestation ? { attestation } : {}),
        });
        return {
          id: definition.toolId,
          label: definition.label,
          available: isAvailable,
          locallyPolicyEnforced: true,
          requiresModel: false,
          executionJourneys: ["guided"] as const,
          actionClassIds: [definition.actionClassId],
          evidenceTypeIds: [definition.evidenceTypeId],
          riskClassIds: ["ti-scale:network"],
          dependencies: [
            dependency("operator-review", true),
            dependency(
              "executable-integrity",
              receipt?.observedExecutableSha256 === definition.executable.sha256,
            ),
            dependency("isolated-target-free-readiness", receipt?.status === "ready"),
            dependency(
              "direct-argv-adapter",
              receipt?.directArgv === true && receipt?.shell === false,
            ),
            dependency("workspace-confinement", receipt?.workspaceConfinementReady === true),
            dependency("credential-isolation", receipt?.credentialIsolationReady === true),
            dependency("output-bound", receipt?.outputBoundReady === true),
            dependency("cancellation", receipt?.cancellationReady === true),
          ],
        };
      }),
      mcpServers: [],
      agents: [{
        id: "specialist:windows-identity",
        label: "Windows and identity specialist",
        available: [...available.values()].some(Boolean),
        capabilityIds: capabilities.map(({ id }) => id),
        actionClassIds: ["active_directory_identity_operations"],
        toolIds: this.pack.definitions.map(({ toolId }) => toolId),
        modelRefs: [],
      }],
      providers: [],
    });
    buildRuntimeCapabilityProjection(manifests);
    return manifests;
  }

  createToolBindingRegistry(): ToolBindingRegistry {
    const manifests = this.toRuntimeSourceManifests();
    return new ToolBindingRegistry(this.toToolBindingRegistryDocument(), manifests);
  }

  composeRuntimeSourceManifests(
    base: RuntimeSourceManifests,
    receipts: readonly WindowsIdentityToolReadinessReceipt[] = [],
    now: Date = new Date(),
  ): RuntimeSourceManifests {
    buildRuntimeCapabilityProjection(base);
    const identity = this.toRuntimeSourceManifests(receipts, now);
    const composed: RuntimeSourceManifests = deepFreeze({
      riskClasses: mergeRiskClasses(base.riskClasses, identity.riskClasses),
      evidenceKinds: mergeUnique("evidence kind", base.evidenceKinds, identity.evidenceKinds),
      capabilities: mergeUnique("capability", base.capabilities, identity.capabilities),
      tools: mergeUnique("tool", base.tools, identity.tools),
      mcpServers: mergeUnique("MCP server", base.mcpServers, identity.mcpServers),
      agents: mergeUnique("agent", base.agents, identity.agents),
      providers: mergeUnique("provider", base.providers, identity.providers),
    });
    buildRuntimeCapabilityProjection(composed);
    return composed;
  }
}
