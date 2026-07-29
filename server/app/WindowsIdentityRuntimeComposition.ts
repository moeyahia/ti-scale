import type { RuntimeSourceManifests } from "../domain";
import type { ToolBindingReadinessRunner } from "../system-capabilities";
import {
  DirectWindowsIdentityProcessAdapter,
  WindowsIdentityCapabilityRegistry,
  windowsIdentityReadinessReceipt,
  type WindowsIdentityToolReadinessReceipt,
} from "../windows-identity-tools";
import type {
  FleetAgentProjection,
  RuntimeProjectionInput,
} from "./RuntimeProjectionService";

export const WINDOWS_IDENTITY_ACTIVATION_SNAPSHOT_SCHEMA_VERSION =
  "ti-scale.windows-identity-activation-snapshot.v1" as const;

export interface WindowsIdentityActivationSnapshot {
  readonly schemaVersion: typeof WINDOWS_IDENTITY_ACTIVATION_SNAPSHOT_SCHEMA_VERSION;
  readonly status: "ready" | "unavailable";
  readonly checkedAt: string;
  readonly adapterId: string;
  readonly readyToolIds: readonly string[];
  readonly receipts: readonly WindowsIdentityToolReadinessReceipt[];
  readonly reason: string;
}

export interface WindowsIdentityRuntimeProjection {
  readonly capabilityManifests: RuntimeSourceManifests;
  readonly agent: FleetAgentProjection;
  readonly readyToolIds: ReadonlySet<string>;
  readonly readiness: WindowsIdentityActivationSnapshot;
}

export interface WindowsIdentityReadinessDrainResources {
  readonly runner?: Readonly<{ stop(): void | Promise<unknown> }>;
  readonly initialActivation?: Promise<unknown>;
  readonly refreshInFlight?: Promise<unknown>;
  readonly probeEnvironment?: Readonly<{ close(): void }>;
}

/**
 * Drains every consumer before closing the environment-owned immutable
 * snapshot descriptors. The all-settled barrier is deliberate: a rejected
 * activation must not let teardown close an fd under a still-running probe.
 */
export async function drainWindowsIdentityReadinessResources(
  input: WindowsIdentityReadinessDrainResources,
): Promise<void> {
  const settled = await Promise.allSettled([
    ...(input.runner ? [input.runner.stop()] : []),
    ...(input.initialActivation ? [input.initialActivation] : []),
    ...(input.refreshInFlight ? [input.refreshInFlight] : []),
  ]);
  let closeFailure: unknown;
  try {
    input.probeEnvironment?.close();
  } catch (error) {
    closeFailure = error;
  }
  const workFailure = settled.find(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  if (workFailure) throw workFailure.reason;
  if (closeFailure) throw closeFailure;
}

/**
 * Runs the target-free executable wave and joins it to the real bounded
 * process adapter. This never contacts a mission target and no receipt grants
 * mission authority; the active runtime projection remains Guided-only and
 * requires scope plus one exact Guided decision for every dispatch.
 */
export async function activateWindowsIdentityRuntime(input: Readonly<{
  registry: WindowsIdentityCapabilityRegistry;
  runner: ToolBindingReadinessRunner;
  adapter: DirectWindowsIdentityProcessAdapter;
  now?: Date;
  signal?: AbortSignal;
}>): Promise<WindowsIdentityActivationSnapshot> {
  const cancelled = (): boolean => input.signal?.aborted === true;
  const cancelledSnapshot = (): WindowsIdentityActivationSnapshot => Object.freeze({
    schemaVersion: WINDOWS_IDENTITY_ACTIVATION_SNAPSHOT_SCHEMA_VERSION,
    status: "unavailable",
    checkedAt: (input.now ?? new Date()).toISOString(),
    adapterId: input.adapter.adapterId,
    readyToolIds: Object.freeze([]),
    receipts: Object.freeze([]),
    reason: "Windows and identity readiness stopped before another activation stage could begin.",
  });
  if (cancelled()) return cancelledSnapshot();
  const expectedRegistry = input.registry.createToolBindingRegistry().descriptor;
  if (input.runner.registry.descriptor.registrySha256 !== expectedRegistry.registrySha256
    || input.runner.registry.descriptor.runtimeManifestSha256
      !== expectedRegistry.runtimeManifestSha256) {
    throw new Error("Windows identity readiness runner is bound to a different reviewed registry");
  }
  const generic = await input.runner.runAll();
  if (cancelled()) return cancelledSnapshot();
  const genericByTool = new Map(generic.receipts.map((receipt) => [receipt.toolId, receipt]));
  const receipts: WindowsIdentityToolReadinessReceipt[] = [];
  for (const definition of input.registry.pack.definitions) {
    if (cancelled()) return cancelledSnapshot();
    const binding = genericByTool.get(definition.toolId);
    if (!binding) continue;
    const adapter = await input.adapter.boundaryReadiness(definition.toolId, input.signal);
    if (cancelled()) return cancelledSnapshot();
    receipts.push(windowsIdentityReadinessReceipt({ definition, binding, adapter }));
  }
  input.adapter.acceptReadinessReceipts(receipts);
  const readyToolIds = receipts
    .filter(({ status }) => status === "ready")
    .map(({ toolId }) => toolId)
    .sort();
  const now = input.now ?? new Date();
  return Object.freeze({
    schemaVersion: WINDOWS_IDENTITY_ACTIVATION_SNAPSHOT_SCHEMA_VERSION,
    status: readyToolIds.length > 0 ? "ready" : "unavailable",
    checkedAt: now.toISOString(),
    adapterId: input.adapter.adapterId,
    readyToolIds: Object.freeze(readyToolIds),
    receipts: Object.freeze(receipts),
    reason: readyToolIds.length > 0
      ? `${readyToolIds.length} Windows and identity tool binding${readyToolIds.length === 1 ? " is" : "s are"} ready for an exact represented Guided step.`
      : "No Windows or identity tool has a complete executable, sandbox, workspace, credential, output, and cancellation receipt.",
  });
}

export function projectWindowsIdentityRuntime(input: Readonly<{
  baselineManifests: RuntimeSourceManifests;
  registry: WindowsIdentityCapabilityRegistry;
  activation: WindowsIdentityActivationSnapshot;
  now?: Date;
}>): WindowsIdentityRuntimeProjection {
  const now = input.now ?? new Date();
  const capabilityManifests = input.registry.composeRuntimeSourceManifests(
    input.baselineManifests,
    input.activation.receipts,
    now,
  );
  const identityToolIds = new Set<string>(input.registry.pack.definitions.map(({ toolId }) => toolId));
  const readyToolIds = new Set(capabilityManifests.tools
    .filter(({ id, available }) => available && identityToolIds.has(id))
    .map(({ id }) => id));
  const agent: FleetAgentProjection = Object.freeze({
    id: "specialist:windows-identity",
    role: "guided-windows-identity-specialist",
    displayName: "Windows and identity specialist",
    status: readyToolIds.size > 0 ? "available" : "offline",
    providerPolicy: Object.freeze({ providerContact: false, publicProviderExecution: false }),
    toolPolicy: Object.freeze({
      allowedTools: Object.freeze([...readyToolIds].sort()),
      deniedTools: Object.freeze(input.registry.pack.definitions
        .map(({ toolId }) => toolId)
        .filter((toolId) => !readyToolIds.has(toolId))
        .sort()),
      exactGuidedDecisionRequired: true,
    }),
    configuration: Object.freeze({
      schemaVersion: "ti-scale.windows-identity-specialist-runtime.v1",
      executionMode: readyToolIds.size > 0 ? "guided_exact_step" : "unavailable",
      adapterId: input.activation.adapterId,
      directArgv: true,
      shell: false,
      credentialDelivery: "opaque_read_only_private_files",
      evidencePromotion: "explicit_only",
    }),
    version: input.registry.descriptor.registryVersion,
    lastHeartbeatAt: null,
    capabilities: Object.freeze(input.registry.pack.definitions.map((definition) => ({
      name: definition.toolId,
      source: "windows-identity-activation-receipt",
      enabled: readyToolIds.has(definition.toolId),
      metadata: Object.freeze({
        actionClassId: definition.actionClassId,
        evidenceTypeId: definition.evidenceTypeId,
        executionJourneys: Object.freeze(["guided"]),
        targetReadOnly: true,
      }),
    }))),
  });
  return Object.freeze({
    capabilityManifests,
    agent,
    readyToolIds,
    readiness: input.activation,
  });
}

export function applyWindowsIdentityRuntimeProjection(
  baseline: RuntimeProjectionInput,
  identity: WindowsIdentityRuntimeProjection,
): RuntimeProjectionInput {
  if (baseline.agents.some(({ id }) => id === identity.agent.id)) {
    throw new Error(`Windows identity specialist stable ID collision: ${identity.agent.id}`);
  }
  return Object.freeze({
    ...baseline,
    readiness: Object.freeze({
      ...baseline.readiness,
      specialistsConfigured: baseline.readiness.specialistsConfigured
        + (identity.agent.status === "available" ? 1 : 0),
    }),
    agents: Object.freeze([...baseline.agents, identity.agent]),
    capabilityManifests: identity.capabilityManifests,
  });
}
