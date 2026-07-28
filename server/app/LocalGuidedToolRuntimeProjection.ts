import type { RuntimeSourceManifests } from "../domain";
import type {
  LocalToolActivationReceipt,
  LocalToolCapabilityManifest,
} from "../local-tools";
import type {
  FleetAgentProjection,
  RuntimeProjectionInput,
} from "./RuntimeProjectionService";
import type { RuntimeReadinessSnapshot } from "./RuntimeReadiness";

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;

export interface LocalGuidedToolRuntimeProjection {
  readonly capabilityManifests: RuntimeSourceManifests;
  readonly readiness: NonNullable<RuntimeReadinessSnapshot["guidedLocalToolExecution"]>;
  readonly agent: FleetAgentProjection;
  readonly readyToolIds: ReadonlySet<string>;
}

function validDate(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
    ? parsed
    : null;
}

/**
 * Projects only current, manifest-bound activation receipts. This function is
 * synchronous and side-effect free: API and UI reads can never launch a probe
 * or executable. Receipt production remains the activation coordinator's job.
 */
export function projectLocalGuidedToolRuntime(input: Readonly<{
  baselineManifests: RuntimeSourceManifests;
  manifest: LocalToolCapabilityManifest;
  activationReceipts: readonly LocalToolActivationReceipt[];
  adapterId: string | null;
  now?: Date;
}>): LocalGuidedToolRuntimeProjection {
  if (input.adapterId !== null && !PUBLIC_ID.test(input.adapterId)) {
    throw new Error("Local Guided tool adapter ID is invalid");
  }
  const receiptIds = input.activationReceipts.map(({ toolId }) => toolId);
  if (new Set(receiptIds).size !== receiptIds.length) {
    throw new Error("Local Guided tool activation receipts contain duplicate tool IDs");
  }
  const now = input.now ?? new Date();
  const capabilityManifests = input.manifest.composeRuntimeSourceManifests(
    input.baselineManifests,
    input.activationReceipts,
    now,
  );
  const readyTools = capabilityManifests.tools.filter((tool) =>
    input.manifest.resolve(tool.id) !== undefined && tool.available);
  const readyToolIds = new Set(readyTools.map(({ id }) => id));
  const currentReceipts = input.activationReceipts.filter(({ toolId }) => readyToolIds.has(toolId));
  const currentReceiptByToolId = new Map(currentReceipts.map((receipt) => [receipt.toolId, receipt]));
  const observedTimes = currentReceipts
    .map(({ observedAt }) => validDate(observedAt))
    .filter((value): value is number => value !== null);
  const expiryTimes = currentReceipts
    .map(({ expiresAt }) => validDate(expiresAt))
    .filter((value): value is number => value !== null);
  const mounted = input.adapterId !== null;
  const ready = mounted && readyToolIds.size > 0;
  const readiness: LocalGuidedToolRuntimeProjection["readiness"] = Object.freeze({
    status: ready ? "ready" : "unavailable",
    specialistId: input.manifest.specialist.id,
    executionBinding: "reviewed_local_process",
    readyToolIds: Object.freeze([...readyToolIds].sort()),
    exactDecisionRequired: true,
    targetInteraction: "operator_approved_exact_step",
    providerContact: false,
    mcpTransport: false,
    ...(ready && observedTimes.length > 0
      ? { checkedAt: new Date(Math.max(...observedTimes)).toISOString() }
      : {}),
    ...(ready && expiryTimes.length > 0
      ? { expiresAt: new Date(Math.min(...expiryTimes)).toISOString() }
      : {}),
    reason: ready
      ? `${readyToolIds.size} reviewed local tool${readyToolIds.size === 1 ? " is" : "s are"} available for one exact operator-approved Guided step.`
      : mounted
        ? "No reviewed local tool currently has a complete, fresh activation receipt. Guided remains manual-only."
        : "The reviewed local process adapter is not mounted. Guided remains manual-only.",
  });
  const agent: FleetAgentProjection = Object.freeze({
    id: input.manifest.specialist.id,
    role: "guided-local-reconnaissance-specialist",
    displayName: input.manifest.specialist.label,
    status: ready ? "available" : "offline",
    providerPolicy: Object.freeze({
      providerContact: false,
      publicProviderExecution: false,
    }),
    toolPolicy: Object.freeze({
      allowedTools: Object.freeze([...readyToolIds].sort()),
      deniedTools: Object.freeze(input.manifest.list()
        .map(({ toolId }) => toolId)
        .filter((toolId) => !readyToolIds.has(toolId))
        .sort()),
      approvalRequiredTools: Object.freeze([]),
      exactGuidedDecisionRequired: true,
    }),
    configuration: Object.freeze({
      schemaVersion: "ti-scale.guided-local-specialist-runtime.v1",
      executionMode: ready ? "guided_exact_step" : "unavailable",
      adapterId: input.adapterId,
      toolSelection: "exact_persisted_binding_only",
      resultDelivery: "bound_execution_result_sink",
      shellInterpolation: false,
      publicProviderToolExecution: false,
      mcpTransport: false,
    }),
    version: input.manifest.descriptor.manifestVersion,
    lastHeartbeatAt: null,
    capabilities: Object.freeze(input.manifest.list().map((tool) => Object.freeze({
      // The final dispatch boundary joins this canonical capability key to the
      // exact tool ID. Keep descriptive grouping in metadata; never rename the
      // executable authorization key during projection.
      name: tool.toolId,
      source: "live-route-attestation",
      enabled: readyToolIds.has(tool.toolId),
      metadata: Object.freeze({
        toolId: tool.toolId,
        actionClassIds: Object.freeze([...tool.actionClassIds]),
        executionBinding: "reviewed_local_process",
        executionJourneys: Object.freeze(["guided"]),
        validUntil: currentReceiptByToolId.get(tool.toolId)?.expiresAt ?? null,
        exactGuidedDecisionRequired: true,
      }),
    }))),
  });
  return Object.freeze({ capabilityManifests, readiness, agent, readyToolIds });
}

export function applyLocalGuidedToolRuntimeProjection(
  baseline: RuntimeProjectionInput,
  local: LocalGuidedToolRuntimeProjection,
): RuntimeProjectionInput {
  if (baseline.agents.some(({ id }) => id === local.agent.id)) {
    throw new Error(`Local Guided specialist stable ID collision: ${local.agent.id}`);
  }
  return Object.freeze({
    ...baseline,
    readiness: Object.freeze({
      ...baseline.readiness,
      guidedLocalToolExecution: local.readiness,
      specialistsConfigured: baseline.readiness.specialistsConfigured
        + (local.agent.status === "available" ? 1 : 0),
    }),
    agents: Object.freeze([...baseline.agents, local.agent]),
    capabilityManifests: local.capabilityManifests,
  });
}
