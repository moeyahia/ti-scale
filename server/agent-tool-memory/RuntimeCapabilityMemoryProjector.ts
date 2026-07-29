import { createHash } from "node:crypto";
import type { RuntimeSourceManifests, RuntimeToolManifest } from "../domain";
import type { SqliteDatabase } from "../db";
import {
  actionClassIdsForRuntimeManifestAgent,
  productAgentIdForActionClass,
} from "../agents";
import {
  MemoryRepository,
  memoryContentHash,
  type CreateMemoryNodeInput,
  type MemoryNode,
  type MemoryRetentionPolicy,
} from "../memory";
import type { RuntimeProjectionInput } from "../app/RuntimeProjectionService";
import {
  ConnectedVaultMemoryProjector,
  type ConnectedVaultProjectionReport,
} from "../vault/ConnectedVaultMemoryProjector";
import { AGENT_TOOL_MEMORY_SCHEMA_VERSION } from "./types";

export const RUNTIME_CAPABILITY_MEMORY_PROJECTION_SCHEMA_VERSION =
  "ti-scale.runtime-capability-memory-projection.v1" as const;
export const RUNTIME_CAPABILITY_MEMORY_REPORT_SETTING =
  "brain.runtime_capability_memory_projection.latest" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const PROJECTOR_ID = "system:runtime-capability-memory-projector";

type ProjectedKind = "agent" | "tool";

interface RuntimeCapabilityProjectionMetadata {
  readonly schemaVersion: typeof RUNTIME_CAPABILITY_MEMORY_PROJECTION_SCHEMA_VERSION;
  readonly kind: ProjectedKind;
  readonly sourceId: string;
  readonly sourceGenerationHash: string;
  readonly contentHash: string;
  readonly status: "current" | "withdrawn";
}

interface DesiredMemory {
  readonly input: CreateMemoryNodeInput;
  readonly contentHash: string;
}

export interface RuntimeCapabilityMemoryProjectionReport {
  readonly schemaVersion: typeof RUNTIME_CAPABILITY_MEMORY_PROJECTION_SCHEMA_VERSION;
  readonly sourceGenerationHash: string;
  readonly projectedAt: string;
  readonly status: "ready" | "withdrawn";
  readonly eligibleToolIds: readonly string[];
  readonly eligibleAgentIds: readonly string[];
  readonly createdNodeIds: readonly string[];
  readonly updatedNodeIds: readonly string[];
  readonly unchangedNodeIds: readonly string[];
  readonly withdrawnNodeIds: readonly string[];
  readonly withdrawnVaultNodeIds: readonly string[];
  readonly vaultWithdrawalFailures: number;
  readonly currentNodeIds: readonly string[];
  readonly currentContentHashes: Readonly<Record<string, string>>;
  readonly vaultBackedNodeIds: readonly string[];
  readonly vault: ConnectedVaultProjectionReport;
  readonly authority: Readonly<{
    executionGranted: false;
    scopeChanged: false;
    toolChanged: false;
    argumentsChanged: false;
    actionClassChanged: false;
  }>;
}

interface RuntimeCapabilityMemoryProjectorOptions {
  readonly database: SqliteDatabase;
  readonly vaultProjector: ConnectedVaultMemoryProjector;
  readonly clock?: () => Date;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`,
    ).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function validTime(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value
    ? parsed
    : undefined;
}

export function runtimeCapabilityMemoryNodeId(kind: ProjectedKind, sourceId: string): string {
  return `mem_runtime_${kind}_${sha256(sourceId).slice(0, 40)}`;
}

function stableStrings(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values.map(
    (value) => value.trim().toLocaleLowerCase("en-US"),
  ).filter(Boolean))].sort());
}

function capabilityMetadata(node: MemoryNode): RuntimeCapabilityProjectionMetadata | undefined {
  const value = node.retentionPolicy.runtimeCapabilityProjection;
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== RUNTIME_CAPABILITY_MEMORY_PROJECTION_SCHEMA_VERSION
    || (record.kind !== "agent" && record.kind !== "tool")
    || typeof record.sourceId !== "string"
    || typeof record.sourceGenerationHash !== "string"
    || !SHA256.test(record.sourceGenerationHash)
    || typeof record.contentHash !== "string"
    || !SHA256.test(record.contentHash)
    || (record.status !== "current" && record.status !== "withdrawn")
  ) return undefined;
  return record as unknown as RuntimeCapabilityProjectionMetadata;
}

interface CurrentLocalProvider {
  readonly expiresAt: number;
  readonly modelIds: ReadonlySet<string>;
}

function currentLocalProviders(
  input: RuntimeProjectionInput,
  nowMs: number,
): ReadonlyMap<string, CurrentLocalProvider> {
  const providers = new Map<string, CurrentLocalProvider>();
  for (const provider of input.readiness.providers) {
    if (
      provider.executionBoundary !== "local_deterministic_policy"
      || provider.health !== "healthy"
      || provider.authenticated !== true
      || provider.callable !== true
      || provider.enforcesAutonomousBoundary !== true
    ) continue;
    const observedAt = validTime(provider.attestedAt);
    const expiresAt = validTime(provider.expiresAt);
    if (
      observedAt === undefined
      || observedAt > nowMs
      || expiresAt === undefined
      || expiresAt <= nowMs
      || expiresAt <= observedAt
    ) continue;
    const modelIds = new Set(
      [provider.requestedModel, provider.returnedModel]
        .filter((value): value is string => Boolean(value?.trim())),
    );
    if (modelIds.size === 0) continue;
    providers.set(provider.id, { expiresAt, modelIds });
  }
  return providers;
}

function freshDependencyExpiry(tool: RuntimeToolManifest, nowMs: number): number | undefined {
  const dependencies = tool.dependencies ?? [];
  if (dependencies.length === 0) return Number.POSITIVE_INFINITY;
  const expiries: number[] = [];
  for (const dependency of dependencies) {
    const attestation = dependency.attestation;
    const observedAt = validTime(attestation?.observedAt);
    const expiresAt = validTime(attestation?.expiresAt);
    if (
      dependency.ready !== true
      || !attestation
      || observedAt === undefined
      || observedAt > nowMs
      || expiresAt === undefined
      || expiresAt <= nowMs
      || expiresAt <= observedAt
      || !SHA256.test(attestation.manifestSha256)
      || !SHA256.test(attestation.toolBindingSha256)
      || !SHA256.test(attestation.preflightBindingSha256)
      || !SHA256.test(attestation.executableSha256)
    ) return undefined;
    expiries.push(expiresAt);
  }
  return Math.min(...expiries);
}

function currentToolProjection(input: {
  readonly tool: RuntimeToolManifest;
  readonly manifests: RuntimeSourceManifests;
  readonly readyActionClasses: ReadonlySet<string>;
  readonly providerExpiry: number;
  readonly nowMs: number;
}): Readonly<{
  tool: RuntimeToolManifest;
  actionClassIds: readonly string[];
}> | undefined {
  const { tool } = input;
  if (
    tool.available !== true
    || tool.locallyPolicyEnforced !== true
    || tool.requiresModel !== false
    || !tool.executionJourneys?.includes("autonomous")
    || tool.mcpServerId !== undefined
  ) return undefined;
  const actionClassIds = stableStrings(
    tool.actionClassIds.filter((id) => input.readyActionClasses.has(id)),
  );
  if (actionClassIds.length === 0) return undefined;

  const dependencyExpiries: number[] = [];
  const ownExpiry = freshDependencyExpiry(tool, input.nowMs);
  if (ownExpiry === undefined) return undefined;
  if (Number.isFinite(ownExpiry)) dependencyExpiries.push(ownExpiry);
  for (const constituentId of tool.constituentToolIds ?? []) {
    const constituent = input.manifests.tools.find(({ id }) => id === constituentId);
    if (
      !constituent
      || constituent.available !== true
      || constituent.locallyPolicyEnforced !== true
      || constituent.requiresModel !== false
      || constituent.mcpServerId !== undefined
    ) return undefined;
    const expiry = freshDependencyExpiry(constituent, input.nowMs);
    if (expiry === undefined) return undefined;
    if (Number.isFinite(expiry)) dependencyExpiries.push(expiry);
  }
  const expiresAt = Math.min(input.providerExpiry, ...dependencyExpiries);
  if (!Number.isFinite(expiresAt) || expiresAt <= input.nowMs) return undefined;
  return Object.freeze({
    tool,
    actionClassIds,
  });
}

function retainedPolicy(input: {
  readonly kind: ProjectedKind;
  readonly sourceId: string;
  readonly sourceGenerationHash: string;
  readonly contentHash: string;
  readonly actionTypes: readonly string[];
  readonly actionClassIds: readonly string[];
  readonly agentIds?: readonly string[];
}): MemoryRetentionPolicy {
  return Object.freeze({
    journeys: Object.freeze(["autonomous"] as const),
    allowAutonomous: true,
    allowGuided: false,
    runtimeCapabilityProjection: Object.freeze({
      schemaVersion: RUNTIME_CAPABILITY_MEMORY_PROJECTION_SCHEMA_VERSION,
      kind: input.kind,
      sourceId: input.sourceId,
      sourceGenerationHash: input.sourceGenerationHash,
      contentHash: input.contentHash,
      status: "current",
    }),
    agentToolDecision: Object.freeze({
      schemaVersion: AGENT_TOOL_MEMORY_SCHEMA_VERSION,
      match: Object.freeze({
        hooks: Object.freeze([
          input.kind === "agent" ? "assignment_acceptance" : "tool_selection",
        ]),
        ...(input.agentIds ? { agentIds: Object.freeze([...input.agentIds]) } : {}),
        actionTypes: Object.freeze([...input.actionTypes]),
        actionClasses: Object.freeze([...input.actionClassIds]),
      }),
      effect: Object.freeze({
        verdict: "compatible",
        reasonCode: "runtime.current_local_capability",
      }),
    }),
  });
}

function desiredToolNode(input: {
  readonly toolId: string;
  readonly actionClassIds: readonly string[];
  readonly sourceGenerationHash: string;
  readonly acquiredAt: string;
}): DesiredMemory {
  const nodeId = runtimeCapabilityMemoryNodeId("tool", input.toolId);
  const title = `${input.toolId} current local tool compatibility`;
  const summary = "A fresh, locally enforced runtime attestation confirms this exact represented tool and action-class pairing.";
  const body = [
    `Represented action type: ${input.toolId}`,
    `Compatible action classes: ${input.actionClassIds.join(", ")}`,
    "This record does not grant execution, add a target, change arguments, replace a tool, or widen authorization.",
  ].join("\n");
  const contentHash = memoryContentHash({
    nodeType: "tool",
    title,
    summary,
    body,
    scope: { kind: "global" },
  });
  return {
    contentHash,
    input: {
      id: nodeId,
      nodeType: "tool",
      title,
      summary,
      body,
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "not_required",
      provenance: {
        method: "derived",
        explanation: "Derived only from the current locally enforced runtime capability projection.",
        sources: [{
          sourceType: "runtime_capability_projection",
          sourceId: `runtime-tool:${sha256(input.toolId)}`,
          sourceHash: input.sourceGenerationHash,
          acquiredAt: input.acquiredAt,
        }],
      },
      authorType: "system",
      authorId: PROJECTOR_ID,
      retentionPolicy: retainedPolicy({
        kind: "tool",
        sourceId: input.toolId,
        sourceGenerationHash: input.sourceGenerationHash,
        contentHash,
        actionTypes: [input.toolId],
        actionClassIds: input.actionClassIds,
      }),
    },
  };
}

function desiredAgentNode(input: {
  readonly agentId: string;
  readonly actionTypes: readonly string[];
  readonly actionClassIds: readonly string[];
  readonly sourceGenerationHash: string;
  readonly acquiredAt: string;
}): DesiredMemory {
  const nodeId = runtimeCapabilityMemoryNodeId("agent", input.agentId);
  const title = `${input.agentId} current specialist capability dependencies`;
  const summary = "A fresh runtime generation confirms this specialist is compatible with the listed represented local actions.";
  const body = [
    `Represented specialist: ${input.agentId}`,
    `Compatible action types: ${input.actionTypes.join(", ")}`,
    `Compatible action classes: ${input.actionClassIds.join(", ")}`,
    "This record only attests the already represented assignment and cannot assign work or change mission authority.",
  ].join("\n");
  const contentHash = memoryContentHash({
    nodeType: "agent",
    title,
    summary,
    body,
    scope: { kind: "global" },
  });
  return {
    contentHash,
    input: {
      id: nodeId,
      nodeType: "agent",
      title,
      summary,
      body,
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "not_required",
      provenance: {
        method: "derived",
        explanation: "Derived only from the current locally enforced specialist and tool capability projection.",
        sources: [{
          sourceType: "runtime_capability_projection",
          sourceId: `runtime-agent:${sha256(input.agentId)}`,
          sourceHash: input.sourceGenerationHash,
          acquiredAt: input.acquiredAt,
        }],
      },
      authorType: "system",
      authorId: PROJECTOR_ID,
      retentionPolicy: retainedPolicy({
        kind: "agent",
        sourceId: input.agentId,
        sourceGenerationHash: input.sourceGenerationHash,
        contentHash,
        agentIds: [input.agentId],
        actionTypes: input.actionTypes,
        actionClassIds: input.actionClassIds,
      }),
    },
  };
}

function nodeMatchesDesired(node: MemoryNode, desired: DesiredMemory): boolean {
  const expected = desired.input;
  return node.nodeType === expected.nodeType
    && node.title === expected.title
    && node.summary === expected.summary
    && node.body === (expected.body ?? "")
    && canonicalJson(node.scope) === canonicalJson(expected.scope)
    && node.sensitivity === expected.sensitivity
    && node.confidence === expected.confidence
    && node.lifecycleStatus === expected.lifecycleStatus
    && node.confirmationState === expected.confirmationState
    && canonicalJson(node.retentionPolicy) === canonicalJson(expected.retentionPolicy)
    && (node.expiresAt ?? null) === (expected.expiresAt ?? null)
    && node.authorType === expected.authorType
    && node.authorId === expected.authorId
    && capabilityMetadata(node)?.contentHash === desired.contentHash;
}

/**
 * Converts only the current, healthy, locally enforced runtime generation into
 * typed compatibility memory. It cannot create execution authority because
 * its schema contains no target, argument patch, replacement tool, permission,
 * provider call, or action-class mutation.
 */
export class RuntimeCapabilityMemoryProjector {
  readonly #memory: MemoryRepository;
  readonly #clock: () => Date;

  constructor(readonly options: RuntimeCapabilityMemoryProjectorOptions) {
    this.#memory = new MemoryRepository(options.database, { clock: options.clock });
    this.#clock = options.clock ?? (() => new Date());
  }

  project(input: RuntimeProjectionInput): RuntimeCapabilityMemoryProjectionReport {
    const now = this.#clock();
    const projectedAt = now.toISOString();
    const manifests = input.capabilityManifests;
    const runtimeReady = input.readiness.autonomousRuntime?.status === "ready";
    const localProviders = currentLocalProviders(input, now.getTime());
    const providerExpiry = localProviders.size > 0
      ? Math.min(...[...localProviders.values()].map(({ expiresAt }) => expiresAt))
      : undefined;
    const sourceGeneration = {
      readiness: input.readiness.autonomousRuntime ?? null,
      providers: input.readiness.providers
        .filter((provider) => provider.executionBoundary === "local_deterministic_policy")
        .map((provider) => ({
        id: provider.id,
        executionBoundary: provider.executionBoundary ?? null,
        health: provider.health,
        authenticated: provider.authenticated,
        callable: provider.callable,
        enforcesAutonomousBoundary: provider.enforcesAutonomousBoundary,
        requestedModel: provider.requestedModel ?? null,
        returnedModel: provider.returnedModel ?? null,
        modelConfigurationHash: provider.modelConfigurationHash ?? null,
        })).sort((left, right) => left.id.localeCompare(right.id)),
      manifests: manifests ? {
        tools: manifests.tools.map((tool) => ({
          id: tool.id,
          available: tool.available,
          locallyPolicyEnforced: tool.locallyPolicyEnforced,
          requiresModel: tool.requiresModel ?? null,
          executionJourneys: stableStrings(tool.executionJourneys ?? []),
          constituentToolIds: stableStrings(tool.constituentToolIds ?? []),
          actionClassIds: stableStrings(tool.actionClassIds),
          evidenceTypeIds: stableStrings(tool.evidenceTypeIds),
          riskClassIds: stableStrings(tool.riskClassIds),
          mcpServerId: tool.mcpServerId ?? null,
          dependencies: (tool.dependencies ?? []).map((dependency) => ({
            id: dependency.id,
            ready: dependency.ready,
            attestation: dependency.attestation ? {
              schemaVersion: dependency.attestation.schemaVersion,
              source: dependency.attestation.source,
              manifestSha256: dependency.attestation.manifestSha256,
              toolBindingSha256: dependency.attestation.toolBindingSha256,
              preflightBindingSha256: dependency.attestation.preflightBindingSha256,
              executableSha256: dependency.attestation.executableSha256,
            } : null,
          })).sort((left, right) => left.id.localeCompare(right.id)),
        })).sort((left, right) => left.id.localeCompare(right.id)),
        agents: manifests.agents.map((agent) => ({
          id: agent.id,
          available: agent.available,
          capabilityIds: stableStrings(agent.capabilityIds),
          actionClassIds: stableStrings(agent.actionClassIds ?? []),
          toolIds: stableStrings(agent.toolIds),
          modelRefs: [...agent.modelRefs].map((model) => ({
            providerId: model.providerId,
            modelId: model.modelId,
          })).sort((left, right) =>
            left.providerId.localeCompare(right.providerId)
            || left.modelId.localeCompare(right.modelId)),
        })).sort((left, right) => left.id.localeCompare(right.id)),
      } : null,
    };
    const sourceGenerationHash = sha256(canonicalJson(sourceGeneration));
    const desired = new Map<string, DesiredMemory>();
    const eligibleTools = new Map<string, ReturnType<typeof currentToolProjection> & {}>();
    const readyActionClasses = new Set(
      input.readiness.autonomousRuntime?.readyActionClassIds ?? [],
    );

    if (runtimeReady && providerExpiry !== undefined && manifests) {
      for (const tool of manifests.tools) {
        const current = currentToolProjection({
          tool,
          manifests,
          readyActionClasses,
          providerExpiry,
          nowMs: now.getTime(),
        });
        if (!current) continue;
        eligibleTools.set(tool.id, current);
        const node = desiredToolNode({
          toolId: tool.id,
          actionClassIds: current.actionClassIds,
          sourceGenerationHash,
          acquiredAt: projectedAt,
        });
        desired.set(node.input.id!, node);
      }
      const productAgentCompatibility = new Map<string, {
        readonly actionTypes: Set<string>;
        readonly actionClassIds: Set<string>;
      }>();
      for (const agent of manifests.agents) {
        if (!agent.available) continue;
        const locallyBacked = agent.modelRefs.some((reference) =>
          localProviders.get(reference.providerId)?.modelIds.has(reference.modelId));
        if (!locallyBacked) continue;
        const declaredActionClasses = new Set<string>(
          actionClassIdsForRuntimeManifestAgent(agent, manifests),
        );
        for (const toolId of agent.toolIds) {
          const tool = eligibleTools.get(toolId);
          if (!tool) continue;
          for (const actionClassId of tool.actionClassIds) {
            if (!declaredActionClasses.has(actionClassId)) continue;
            const productAgentId = productAgentIdForActionClass(actionClassId);
            if (!productAgentId) continue;
            const aggregate = productAgentCompatibility.get(productAgentId) ?? {
              actionTypes: new Set<string>(),
              actionClassIds: new Set<string>(),
            };
            aggregate.actionTypes.add(toolId);
            aggregate.actionClassIds.add(actionClassId);
            productAgentCompatibility.set(productAgentId, aggregate);
          }
        }
      }
      // Runtime manifests describe replaceable worker/transport adapters.
      // Compatibility memory must follow the stable product specialist that
      // owns each represented action class, because plans and assignments are
      // deliberately persisted under that operator-facing identity.
      for (const [productAgentId, compatibility] of [
        ...productAgentCompatibility.entries(),
      ].sort(([left], [right]) => left.localeCompare(right))) {
        const node = desiredAgentNode({
          agentId: productAgentId,
          actionTypes: stableStrings([...compatibility.actionTypes]),
          actionClassIds: stableStrings([...compatibility.actionClassIds]),
          sourceGenerationHash,
          acquiredAt: projectedAt,
        });
        desired.set(node.input.id!, node);
      }
      // A tool attestation without any currently compatible specialist cannot
      // influence an Autonomous dispatch decision. Withdraw the whole joined
      // capability set rather than publishing an orphan tool rule.
      if (![...desired.values()].some(({ input: node }) => node.nodeType === "agent")) {
        desired.clear();
        eligibleTools.clear();
      }
    }

    const createdNodeIds: string[] = [];
    const updatedNodeIds: string[] = [];
    const unchangedNodeIds: string[] = [];
    const withdrawnNodeIds: string[] = [];
    const ownedRows = this.options.database.prepare(`
      SELECT id FROM memory_nodes
      WHERE lifecycle_status != 'forgotten'
        AND json_extract(
          retention_policy_json,
          '$.runtimeCapabilityProjection.schemaVersion'
        ) = ?
      ORDER BY id
    `).all(RUNTIME_CAPABILITY_MEMORY_PROJECTION_SCHEMA_VERSION) as Array<{ id: string }>;
    const ownedIds = new Set(ownedRows.map(({ id }) => id));

    for (const [nodeId, wanted] of desired) {
      const current = this.#memory.getNode(nodeId, true);
      if (!current) {
        this.#memory.createNode(wanted.input);
        createdNodeIds.push(nodeId);
        continue;
      }
      const metadata = capabilityMetadata(current);
      if (!metadata || metadata.kind !== wanted.input.nodeType || metadata.sourceId
        !== (wanted.input.retentionPolicy?.runtimeCapabilityProjection as { sourceId: string }).sourceId) {
        throw new Error(`Runtime capability memory stable-ID collision: ${nodeId}`);
      }
      if (nodeMatchesDesired(current, wanted)) {
        unchangedNodeIds.push(nodeId);
        continue;
      }
      this.#memory.correctNode(nodeId, {
        title: wanted.input.title,
        summary: wanted.input.summary,
        body: wanted.input.body ?? "",
        scope: wanted.input.scope,
        sensitivity: wanted.input.sensitivity,
        confidence: wanted.input.confidence,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        retentionPolicy: wanted.input.retentionPolicy,
        // Capability availability is revalidated by the lifecycle on every
        // attestation wave. Rotating receipt timestamps must not version or
        // rewrite semantically unchanged Vault notes.
        expiresAt: null,
        pinned: wanted.input.pinned ?? false,
        provenanceExplanation: wanted.input.provenance.explanation,
        authorType: "system",
        authorId: PROJECTOR_ID,
        changeReason: "Refreshed from the current locally enforced capability attestation generation",
      });
      updatedNodeIds.push(nodeId);
    }

    for (const nodeId of [...ownedIds].sort()) {
      if (desired.has(nodeId)) continue;
      const current = this.#memory.requireNode(nodeId);
      const metadata = capabilityMetadata(current);
      if (!metadata) continue;
      const {
        agentToolDecision: _typedDecision,
        runtimeCapabilityProjection: _projection,
        ...retention
      } = current.retentionPolicy;
      if (current.lifecycleStatus === "stale" && !_typedDecision) continue;
      this.#memory.correctNode(nodeId, {
        lifecycleStatus: "stale",
        confirmationState: "not_required",
        retentionPolicy: {
          ...retention,
          allowAutonomous: false,
          runtimeCapabilityProjection: {
            ...metadata,
            sourceGenerationHash,
            status: "withdrawn",
          },
        },
        expiresAt: projectedAt,
        authorType: "system",
        authorId: PROJECTOR_ID,
        changeReason: "Withdrew compatibility memory because its live capability attestation is missing or stale",
      });
      withdrawnNodeIds.push(nodeId);
    }

    const vaultWithdrawal = this.options.vaultProjector.purgeRevoked(
      withdrawnNodeIds,
    );
    const currentNodeIds = [...desired.keys()].sort();
    const eligibleAgentIds = currentNodeIds.flatMap((nodeId) => {
      const metadata = capabilityMetadata(this.#memory.requireNode(nodeId));
      return metadata?.kind === "agent" ? [metadata.sourceId] : [];
    }).sort();
    const vault = this.options.vaultProjector.project(currentNodeIds);
    const vaultBackedNodeIds = currentNodeIds.filter((nodeId) => {
      const row = this.options.database.prepare(`
        SELECT 1 AS present
        FROM vault_sync_state state
        JOIN vault_connections connection ON connection.id = state.connection_id
        WHERE state.node_id = ? AND state.status = 'synced'
          AND connection.status = 'connected'
        LIMIT 1
      `).get(nodeId);
      return Boolean(row);
    });
    const currentContentHashes = Object.fromEntries(
      [...desired.entries()].map(([nodeId, value]) => [nodeId, value.contentHash]),
    );
    const report: RuntimeCapabilityMemoryProjectionReport = {
      schemaVersion: RUNTIME_CAPABILITY_MEMORY_PROJECTION_SCHEMA_VERSION,
      sourceGenerationHash,
      projectedAt,
      status: runtimeReady
        && providerExpiry !== undefined
        && manifests
        && eligibleTools.size > 0
        && eligibleAgentIds.length > 0
        ? "ready"
        : "withdrawn",
      eligibleToolIds: [...eligibleTools.keys()].sort(),
      eligibleAgentIds,
      createdNodeIds: createdNodeIds.sort(),
      updatedNodeIds: updatedNodeIds.sort(),
      unchangedNodeIds: unchangedNodeIds.sort(),
      withdrawnNodeIds: withdrawnNodeIds.sort(),
      withdrawnVaultNodeIds: vaultWithdrawal.removedNodeIds,
      vaultWithdrawalFailures: vaultWithdrawal.failures,
      currentNodeIds,
      currentContentHashes,
      vaultBackedNodeIds: vaultBackedNodeIds.sort(),
      vault,
      authority: {
        executionGranted: false,
        scopeChanged: false,
        toolChanged: false,
        argumentsChanged: false,
        actionClassChanged: false,
      },
    };
    this.options.database.prepare(`
      INSERT INTO settings (
        key, value_json, sensitivity, version, updated_by, updated_at
      ) VALUES (?, ?, 'internal', 1, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        value_json = excluded.value_json,
        version = settings.version + 1,
        updated_by = excluded.updated_by,
        updated_at = excluded.updated_at
    `).run(
      RUNTIME_CAPABILITY_MEMORY_REPORT_SETTING,
      canonicalJson(report),
      PROJECTOR_ID,
      projectedAt,
    );
    return Object.freeze(report);
  }

  latestReport(): RuntimeCapabilityMemoryProjectionReport | undefined {
    const row = this.options.database.prepare(
      "SELECT value_json FROM settings WHERE key = ?",
    ).get(RUNTIME_CAPABILITY_MEMORY_REPORT_SETTING) as { value_json: string } | undefined;
    return row ? JSON.parse(row.value_json) as RuntimeCapabilityMemoryProjectionReport : undefined;
  }
}
