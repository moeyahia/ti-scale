import express from "express";
import { createHash, randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createCommandOsApplication,
  type CommandOsApplication,
} from "../../../server/app/CommandOsApplication";
import { inImmediateTransaction } from "../../../server/db";
import type { RuntimeProjectionInput } from "../../../server/app/RuntimeProjectionService";
import {
  createRuntimeReadinessProviders,
  type RuntimeReadinessSnapshot,
} from "../../../server/app/RuntimeReadiness";
import {
  ControlPlaneLeaseService,
  type AssertRunMutationLease,
} from "../../../server/control-plane";
import { PRODUCT_AGENT_REGISTRY } from "../../../server/agents";
import {
  ACTION_CLASS_IDS,
  createRuntimeAdapterAttestation,
  DELIVERABLE_IDS,
  EVIDENCE_TYPE_IDS,
  type RuntimeSourceManifests,
} from "../../../server/domain";
import { MissionIntakeService } from "../../../server/intake";
import { SEARCHSPLOIT_LOCAL_TOOL_ID } from
  "../../../server/local-exploit-intelligence";
import {
  activeConnectedVaultBackedMemoryNodeIds,
  MemoryRepository,
} from "../../../server/memory";
import { createSecondBrainRouter } from "../../../server/memory/SecondBrainRouter";
import { hashCanonical } from "../../../server/missions/canonical";
import { MissionRepository } from "../../../server/missions/MissionRepository";
import { validateMissionCreateRequest } from "../../../server/missions/validation";
import { createOperationsRouter } from "../../../server/operations";
import { WindowsIdentityToolPack } from "../../../server/windows-identity-tools";
import {
  attackKnowledgeVaultPolicyHash,
  ObsidianVaultBridge,
  VaultPathPolicy,
} from "../../../server/vault";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const RUNTIME_ADAPTER_ID = "e2e-ready-autonomous-runtime-adapter";
const PROVIDER_ID = "e2e-ready-autonomous-provider";
const MODEL_ID = "e2e-ready-autonomous-model";
const ALTERNATE_MODEL_ID = "e2e-ready-autonomous-model-alternate";
const OBSERVE_ONLY_MODEL_ID = "e2e-ready-autonomous-model-observe-only";
const ADVISOR_MODEL_ID = "e2e-ready-autonomous-model-advisor";
const SECONDARY_PROVIDER_ID = "e2e-ready-autonomous-provider-secondary";
const SECONDARY_MODEL_ID = "e2e-ready-autonomous-model-secondary";
const UNAVAILABLE_PROVIDER_ID = "e2e-unavailable-autonomous-provider";
const UNAVAILABLE_MODEL_ID = "e2e-unavailable-autonomous-model";
const TOOL_ID = "e2e-ready-autonomous-tool";
const MCP_ID = "e2e-ready-autonomous-mcp";

export type ReadyAutonomousIntakeBackendProfile =
  | "full"
  | "team_boundary"
  | "guided_windows_identity"
  | "guided_local_exploit_intelligence";

export interface ReadyAutonomousIntakeBackendOptions {
  readonly profile?: ReadyAutonomousIntakeBackendProfile;
}

export interface ReadyAutonomousIntakeBackend {
  readonly baseUrl: string;
  readonly branchFixture: {
    readonly missionId: string;
    readonly runId: string;
    readonly authorization: {
      readonly engagementId: string;
      readonly environmentClassification: "htb";
      readonly allowedTargets: readonly string[];
      readonly prohibitedTargets: readonly string[];
      readonly authorizationConfirmed: true;
      readonly timeWindow: string;
      readonly dataHandling: string;
    };
  };
  readonly productAgents: readonly {
    readonly id: string;
    readonly displayName: string;
    readonly role: string;
  }[];
  readonly memoryNodes: readonly {
    readonly id: string;
    readonly title: string;
  }[];
  stop(): Promise<void>;
}

function memoryNodeId(namespace: string, label: string): string {
  return `mem_${createHash("sha256").update(`${namespace}:${label}`).digest("hex")}`;
}

function supportedActionClassIds(
  profile: ReadyAutonomousIntakeBackendProfile,
): readonly (typeof ACTION_CLASS_IDS)[number][] {
  if (profile === "full") return ACTION_CLASS_IDS;
  const recon = PRODUCT_AGENT_REGISTRY.find(({ id }) => id === "ReconScout");
  if (!recon) throw new Error("Canonical ReconScout product agent is unavailable");
  return Object.freeze(
    [...new Set([
      ...recon.capabilities.flatMap(({ actionClassIds }) => actionClassIds),
      ...(profile === "guided_local_exploit_intelligence"
        ? ["cve_intelligence_applicability_validation" as const]
        : []),
    ])],
  );
}

function manifests(
  observedAt: string,
  profile: ReadyAutonomousIntakeBackendProfile,
): RuntimeSourceManifests {
  const actionClassIds = supportedActionClassIds(profile);
  const deliverableIds = profile === "full" ? DELIVERABLE_IDS : [];
  const readyWindowsIdentityToolIds = new Set([
    "kali:smbclient-share-list",
    "kali:nxc-smb-summary",
    "kali:ldapsearch-root-dse",
  ]);
  const windowsIdentityTools = (
    profile === "guided_windows_identity"
    || profile === "guided_local_exploit_intelligence"
  )
    ? new WindowsIdentityToolPack().definitions.map((definition) => ({
        id: definition.toolId,
        label: definition.label,
        available: readyWindowsIdentityToolIds.has(definition.toolId),
        locallyPolicyEnforced: true,
        requiresModel: false,
        executionJourneys: ["guided"] as const,
        actionClassIds: [definition.actionClassId],
        evidenceTypeIds: [definition.evidenceTypeId],
        deliverableIds: [],
        riskClassIds: ["e2e-ready-autonomous-risk"],
      }))
    : [];
  const localExploitIntelligenceTools =
    profile === "guided_local_exploit_intelligence"
      ? [{
          id: SEARCHSPLOIT_LOCAL_TOOL_ID,
          label: "Search the pinned local ExploitDB catalog",
          available: true,
          locallyPolicyEnforced: true,
          requiresModel: false,
          missionSelectable: true,
          executionJourneys: ["guided"] as const,
          actionClassIds: [
            "cve_intelligence_applicability_validation" as const,
          ],
          evidenceTypeIds: ["cve_applicability" as const],
          deliverableIds: [],
          riskClassIds: ["e2e-ready-autonomous-risk"],
          runtimeAdapterAttestation: createRuntimeAdapterAttestation({
            toolId: SEARCHSPLOIT_LOCAL_TOOL_ID,
            executionJourneys: ["guided"],
            binding: {
              configurationSha256: "1".repeat(64),
              providerReceiptSha256: "2".repeat(64),
              localManifestSha256: "3".repeat(64),
              componentReceiptSha256s: ["4".repeat(64)],
            },
            observedAt,
            expiresAt: new Date(
              Date.parse(observedAt) + (5 * 60_000),
            ).toISOString(),
          }),
          dependencies: [],
        }]
      : [];
  const sourceManifests: RuntimeSourceManifests = {
    riskClasses: [{
      id: "e2e-ready-autonomous-risk",
      label: "Disposable E2E Autonomous boundary",
      actionClassIds,
    }],
    evidenceKinds: [{
      id: "e2e-ready-autonomous-evidence",
      label: "Disposable E2E evidence producer",
      evidenceTypeIds: EVIDENCE_TYPE_IDS,
    }],
    capabilities: [{
      id: "e2e-ready-autonomous-capability",
      label: "Disposable E2E contract capability",
      actionClassIds,
      evidenceTypeIds: EVIDENCE_TYPE_IDS,
      deliverableIds,
    }],
    tools: [{
      id: TOOL_ID,
      label: "Disposable policy-gated E2E tool",
      available: true,
      locallyPolicyEnforced: true,
      requiresModel: true,
      executionJourneys: ["autonomous"],
      actionClassIds,
      evidenceTypeIds: EVIDENCE_TYPE_IDS,
      deliverableIds,
      riskClassIds: ["e2e-ready-autonomous-risk"],
      mcpServerId: MCP_ID,
    }, ...windowsIdentityTools, ...localExploitIntelligenceTools],
    mcpServers: [{
      id: MCP_ID,
      label: "Disposable E2E MCP boundary",
      status: "healthy",
      toolIds: [TOOL_ID],
    }],
    agents: [{
      id: RUNTIME_ADAPTER_ID,
      label: "Isolated full-contract runtime adapter",
      available: true,
      capabilityIds: ["e2e-ready-autonomous-capability"],
      actionClassIds,
      toolIds: [TOOL_ID],
      deliverableIds,
      modelRefs: [
        { providerId: PROVIDER_ID, modelId: MODEL_ID },
        { providerId: PROVIDER_ID, modelId: ALTERNATE_MODEL_ID },
        { providerId: PROVIDER_ID, modelId: OBSERVE_ONLY_MODEL_ID },
        { providerId: PROVIDER_ID, modelId: ADVISOR_MODEL_ID },
        { providerId: SECONDARY_PROVIDER_ID, modelId: SECONDARY_MODEL_ID },
        { providerId: UNAVAILABLE_PROVIDER_ID, modelId: UNAVAILABLE_MODEL_ID },
      ],
    }],
    providers: [{
      id: PROVIDER_ID,
      authenticated: true,
      healthy: true,
      catalogObservedAt: observedAt,
      models: [{
        id: MODEL_ID,
        displayName: "Disposable enforced E2E model",
        toolCalling: true,
        structuredOutput: true,
        enforcement: "enforced_executor",
        compatibleActionClassIds: actionClassIds,
        disclosureClasses: ["public", "internal_sanitized"],
        contextLimit: 128_000,
        reasoningEfforts: ["low", "medium", "high"],
      }, {
        id: ALTERNATE_MODEL_ID,
        displayName: "Disposable enforced E2E alternative",
        toolCalling: true,
        structuredOutput: true,
        enforcement: "enforced_executor",
        compatibleActionClassIds: actionClassIds,
        disclosureClasses: ["public", "internal_sanitized"],
        contextLimit: 196_000,
        reasoningEfforts: ["low", "high"],
      }, {
        id: OBSERVE_ONLY_MODEL_ID,
        displayName: "Disposable observe-only E2E model",
        toolCalling: true,
        structuredOutput: true,
        enforcement: "observe_only_executor",
        compatibleActionClassIds: actionClassIds,
        disclosureClasses: ["public", "internal_sanitized"],
        contextLimit: 64_000,
        reasoningEfforts: ["low"],
      }, {
        id: ADVISOR_MODEL_ID,
        displayName: "Disposable advisor-only E2E planner",
        toolCalling: false,
        structuredOutput: true,
        enforcement: "advisor_only",
        compatibleActionClassIds: actionClassIds,
        disclosureClasses: ["internal_sanitized"],
        contextLimit: 128_000,
        reasoningEfforts: ["low", "high"],
      }],
    }, {
      id: SECONDARY_PROVIDER_ID,
      authenticated: true,
      healthy: true,
      catalogObservedAt: observedAt,
      models: [{
        id: SECONDARY_MODEL_ID,
        displayName: "Disposable secondary enforced E2E model",
        toolCalling: true,
        structuredOutput: true,
        enforcement: "enforced_executor",
        compatibleActionClassIds: actionClassIds,
        disclosureClasses: ["public", "internal_sanitized"],
        contextLimit: 96_000,
        reasoningEfforts: ["medium", "high"],
      }],
    }, {
      id: UNAVAILABLE_PROVIDER_ID,
      authenticated: false,
      healthy: false,
      catalogObservedAt: observedAt,
      models: [{
        id: UNAVAILABLE_MODEL_ID,
        displayName: "Unavailable E2E model",
        toolCalling: true,
        structuredOutput: true,
        enforcement: "enforced_executor",
        compatibleActionClassIds: actionClassIds,
        disclosureClasses: ["public"],
        contextLimit: 32_000,
        reasoningEfforts: ["low"],
      }],
    }],
  };
  return Object.freeze(sourceManifests);
}

function runtimeProjection(
  now: Date,
  profile: ReadyAutonomousIntakeBackendProfile,
): RuntimeProjectionInput {
  const observedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + (10 * 60_000)).toISOString();
  const actionClassIds = supportedActionClassIds(profile);
  const readiness: RuntimeReadinessSnapshot = {
    actionBoundaryActive: true,
    delegationEnforced: true,
    noHandsCommanderEnforced: true,
    directCommanderToolsDenied: true,
    specialistAssignmentRequired: true,
    specialistsConfigured: 1,
    providers: [{
      id: PROVIDER_ID,
      health: "healthy",
      executionBoundary: "public_provider",
      configured: true,
      authenticated: true,
      callable: true,
      attestedAt: observedAt,
      expiresAt,
      circuitState: "closed",
      supportsGuided: true,
      enforcesAutonomousBoundary: true,
      reportsExactTokenUsage: true,
      reportsExactCostUsage: true,
      requestedModel: MODEL_ID,
      returnedModel: MODEL_ID,
      modelConfigurationHash: "a".repeat(64),
      completionProbeReceiptId: `e2e-provider-probe-${normalizeFixtureNamespace(observedAt)}`,
    }, {
      id: SECONDARY_PROVIDER_ID,
      health: "healthy",
      executionBoundary: "public_provider",
      configured: true,
      authenticated: true,
      callable: true,
      attestedAt: observedAt,
      expiresAt,
      circuitState: "closed",
      supportsGuided: true,
      enforcesAutonomousBoundary: true,
      reportsExactTokenUsage: true,
      reportsExactCostUsage: true,
      requestedModel: SECONDARY_MODEL_ID,
      returnedModel: SECONDARY_MODEL_ID,
      modelConfigurationHash: "b".repeat(64),
      completionProbeReceiptId: `e2e-secondary-provider-probe-${normalizeFixtureNamespace(observedAt)}`,
    }],
    mcp: {
      enabled: true,
      executionMode: "enabled",
      startPermitted: true,
      configuredServers: 1,
      runnableServers: 1,
      missingDependencies: 0,
      missingSecrets: 0,
    },
    autonomousRuntime: {
      schemaVersion: "ti-scale.autonomous-runtime-composition.v1",
      status: "ready",
      readyActionClassIds: actionClassIds,
      components: {
        plannerAdapter: true,
        outcomeEvaluator: true,
        resultAwareSpecialistExecution: true,
        enforcingProvider: true,
        durableActionBoundary: true,
        specialistFleet: true,
        mcpExecution: true,
        localProcessExecution: false,
        exactRuntimeManifest: true,
      },
      blockers: [],
    },
    eventStream: "healthy",
    secondBrain: "healthy",
    legacyExecutionEnabled: false,
  };
  const input: RuntimeProjectionInput = {
    readiness,
    agents: [{
      id: RUNTIME_ADAPTER_ID,
      role: "reconnaissance",
      displayName: "Isolated full-contract runtime adapter",
      status: "available",
      providerPolicy: { defaultProvider: PROVIDER_ID },
      toolPolicy: {
        allowedTools: [TOOL_ID],
        deniedTools: [],
        approvalRequiredTools: [],
      },
      configuration: {
        executionMode: "autonomous",
        providerId: PROVIDER_ID,
        modelId: MODEL_ID,
      },
      version: "e2e-ready-v1",
      lastHeartbeatAt: observedAt,
      capabilities: [{
        name: TOOL_ID,
        source: "live-route-attestation",
        enabled: true,
        metadata: {
          attestedAt: observedAt,
          validUntil: expiresAt,
          providerIds: [PROVIDER_ID],
          actionClassIds,
        },
      }],
    }],
    mcpServers: [{
      id: MCP_ID,
      name: "Disposable E2E MCP boundary",
      transport: "isolated-e2e-http",
      endpointRedacted: "disposable local fixture",
      status: "healthy",
      capabilities: [TOOL_ID],
      policy: {
        enabled: true,
        assignedAgents: [RUNTIME_ADAPTER_ID],
        startPermitted: true,
        riskClass: "network",
        executionAuthorization: "signed_autonomous_contract",
      },
      lastCheckedAt: observedAt,
    }],
    capabilityManifests: manifests(observedAt, profile),
  };
  return Object.freeze(input);
}

async function listening(server: Server): Promise<void> {
  if (server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => server.close((error) => {
    if (error) reject(error);
    else resolve();
  }));
}

export async function startReadyAutonomousIntakeBackend(
  instanceId: string,
  options: ReadyAutonomousIntakeBackendOptions = {},
): Promise<ReadyAutonomousIntakeBackend> {
  const namespace = normalizeFixtureNamespace(instanceId);
  const profile = options.profile ?? "full";
  const directory = mkdtempSync(join(tmpdir(), `ti-scale-autonomous-intake-${namespace}-`));
  const projection = runtimeProjection(new Date(), profile);
  const vaultAllowedRoot = join(directory, "vaults");
  const vaultPathPolicy = new VaultPathPolicy(vaultAllowedRoot);
  const actorId = `operator:e2e-autonomous-launch-${namespace}`;
  let assertBranchMutationLease: AssertRunMutationLease = () => undefined;
  let application: CommandOsApplication | undefined;
  let server: Server | undefined;
  try {
    application = createCommandOsApplication({
      databasePath: join(directory, "ti-scale.sqlite"),
      readinessProviders: (_database, readRuntimeProjection) =>
        createRuntimeReadinessProviders(() => readRuntimeProjection().readiness),
      runtimeProjection: () => projection,
      resolveActor: () => actorId,
      assertRunMutationLease: (request) => assertBranchMutationLease(request),
      resolveExistingVaultPath: (vaultPath) => vaultPathPolicy.resolveExistingVault(vaultPath),
      projectionIntervalMs: 300_000,
    });
    // Agent-scoped model preferences have a canonical foreign-key boundary:
    // the live product roster must exist before ModelConfigurationRepository
    // can accept ReconScout as a stable agent ID. Materialize this immutable
    // fixture generation explicitly instead of depending on the later
    // application.start() lifecycle side effect.
    application.synchronizeRuntimeProjection(projection);
    const expectedCompatibleAgentIds = profile === "full"
      ? PRODUCT_AGENT_REGISTRY.map(({ id }) => id)
      : ["ReconScout"];
    const enforcingConfiguration = application.modelConfigurations
      .catalog()
      .items
      .find((item) =>
        item.selectable
        && item.enforcementMode === "enforced_executor"
        && item.reasoningEffort === null
        && expectedCompatibleAgentIds.every((agentId) =>
          item.compatibleAgentIds.includes(agentId)));
    if (!enforcingConfiguration) {
      throw new Error(
        "The isolated runtime manifest did not project one live enforced model configuration across the canonical product roster",
      );
    }
    application.modelConfigurations.putPreference({
      scopeType: profile === "full" ? "global" : "agent",
      scopeId: profile === "full" ? "global" : "ReconScout",
      agentId: profile === "full" ? null : "ReconScout",
      primaryConfigurationId: enforcingConfiguration.configurationId,
      fallbackConfigurationId: null,
      expectedVersion: 0,
      reason: profile === "full"
        ? "Isolated Autonomous intake fixture global model default"
        : "Isolated Autonomous intake fixture ReconScout model assignment",
    }, actorId);
    const branchResolved = new MissionIntakeService({
      readRuntimeManifests: () => projection.capabilityManifests!,
    }).resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [
        { value: "127.0.0.1" },
        { value: "blocked.example.test", excluded: true },
      ],
      environmentClassification: "htb",
      engagementId: `e2e-branch-engagement-${namespace}`,
      templateId: "safe_recon",
      title: `Autonomous branch contract ${namespace}`,
      objective:
        "Validate a versioned successor contract through one real isolated readiness and creation boundary.",
    });
    if (branchResolved.request.journey !== "autonomous") {
      throw new Error("The isolated branch fixture did not resolve an Autonomous request");
    }
    const branchRequest = validateMissionCreateRequest({
      ...branchResolved.request,
      authorization: {
        ...branchResolved.request.authorization,
        timeWindow: "2026-07-26T00:00:00Z/2026-07-27T00:00:00Z",
        dataHandling: "Keep all fixture evidence inside the isolated local test store.",
      },
    });
    if (branchRequest.journey !== "autonomous") {
      throw new Error("The isolated branch fixture request did not remain Autonomous");
    }
    const branchAuthorization = branchRequest.authorization;
    if (
      !branchAuthorization.engagementId
      || branchAuthorization.environmentClassification !== "htb"
      || !branchAuthorization.timeWindow
      || !branchAuthorization.dataHandling
    ) {
      throw new Error(
        "The isolated branch fixture did not retain its complete explicit authorization boundary",
      );
    }
    const branchMission = inImmediateTransaction(application.database, () =>
      new MissionRepository(application!.database).create({
        request: branchRequest,
        requestHash: hashCanonical(branchRequest),
        idempotencyKey: `ready-autonomous-branch-${namespace}`,
        actorId,
      }));
    const leaseOwner = `e2e-autonomous-runtime-${namespace}`;
    const leaseToken = randomUUID();
    const branchLeases = new ControlPlaneLeaseService(application.database);
    branchLeases.acquire({
      runId: branchMission.run.id,
      controlPlane: "ti_scale",
      leaseOwner,
      leaseToken,
      ttlMs: 300_000,
    });
    assertBranchMutationLease = ({ runId, actorId: mutationActorId }) => {
      if (runId !== branchMission.run.id || mutationActorId !== actorId) return undefined;
      return branchLeases.assertMutationAuthority({
        runId,
        controlPlane: "ti_scale",
        leaseOwner,
        leaseToken,
      });
    };
    const completedAt = new Date().toISOString();
    application.database.prepare(`
      UPDATE runs SET status = 'completed', progress = 1,
        status_reason = 'Completed autonomously for isolated successor-contract coverage.',
        next_action_summary = 'Create a separate versioned run when needed.',
        ended_at = ?, updated_at = ?, version = version + 1
      WHERE id = ?
    `).run(completedAt, completedAt, branchMission.run.id);
    application.database.prepare(`
      UPDATE missions SET status = 'completed', updated_at = ? WHERE id = ?
    `).run(completedAt, branchMission.mission.id);
    const branchFixture = {
      missionId: branchMission.mission.id,
      runId: branchMission.run.id,
      authorization: {
        engagementId: branchAuthorization.engagementId,
        environmentClassification: branchAuthorization.environmentClassification,
        allowedTargets: branchAuthorization.allowedTargets,
        prohibitedTargets: branchAuthorization.prohibitedTargets,
        authorizationConfirmed: true,
        timeWindow: branchAuthorization.timeWindow,
        dataHandling: branchAuthorization.dataHandling,
      },
    } as const;
    const memory = new MemoryRepository(application.database);
    const memoryNodes = [
      memory.createNode({
        id: memoryNodeId(namespace, "verified-attack-technique"),
        nodeType: "attack_technique",
        title: `Verified local assessment technique ${namespace}`,
        summary: "A reviewed local-only assessment technique for the disposable Autonomous intake fixture.",
        body: "Use the exact authorized loopback target, retain attributable evidence, and stop at the signed boundary.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.99,
        lifecycleStatus: "verified",
        confirmationState: "confirmed",
        provenance: {
          method: "derived",
          explanation: "Reviewed fixture knowledge created inside the isolated Autonomous intake backend.",
          sources: [{
            sourceType: "review_receipt",
            sourceId: `review-${namespace}`,
            acquiredAt: new Date().toISOString(),
          }],
        },
        authorType: "operator",
        authorId: actorId,
      }),
      memory.createNode({
        id: memoryNodeId(namespace, "confirmed-attack-procedure"),
        nodeType: "attack_procedure",
        title: `Confirmed evidence procedure ${namespace}`,
        summary: "A confirmed evidence-preservation procedure for the disposable Autonomous intake fixture.",
        body: "Record the exact action, result, source, timestamp, and immutable artifact hash before advancing.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.98,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: {
          method: "operator_statement",
          explanation: "Explicitly confirmed inside the isolated Autonomous intake backend.",
          sources: [{
            sourceType: "message",
            sourceId: `confirmation-${namespace}`,
            acquiredAt: new Date().toISOString(),
          }],
        },
        authorType: "operator",
        authorId: actorId,
      }),
    ] as const;
    const vaultBridge = new ObsidianVaultBridge(
      application.database,
      memory,
      vaultPathPolicy,
    );
    application.start();
    const api = express();
    api.use(express.json({ limit: "2mb" }));
    api.use(application.router);
    api.use(createSecondBrainRouter({
      database: application.database,
      resolveActor: () => actorId,
      resolveAccess: () => ({
        maximumSensitivity: "restricted",
        allowGlobal: true,
        allEngagements: true,
      }),
      vaultPathPolicy,
      vaultBridge,
    }));
    api.use(createOperationsRouter({
      database: application.database,
      resolveActor: () => ({ id: actorId, type: "operator" }),
      resolveAccess: () => ({
        maximumSensitivity: "restricted",
        allEngagements: true,
        allowUnscopedSystemData: true,
        allowGlobalKnowledge: true,
      }),
      reportArtifactRoot: join(directory, "reports"),
    }));
    server = createServer(api);
    server.listen(0, "127.0.0.1");
    await listening(server);
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Disposable Autonomous intake backend has no TCP address");
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const activatedResponse = await fetch(
      `${baseUrl}/api/v2/brain/vault/attack-knowledge-preset/activate`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": randomUUID(),
        },
        body: JSON.stringify({
          permissionGranted: true,
          activationAcknowledged: true,
          includeConfirmed: true,
          expectedPolicyHash: attackKnowledgeVaultPolicyHash({ includeConfirmed: true }),
        }),
      },
    );
    if (!activatedResponse.ok) {
      throw new Error(
        `Disposable Attack Knowledge Vault activation failed (${activatedResponse.status}): ${await activatedResponse.text()}`,
      );
    }
    const activated = await activatedResponse.json() as {
      readonly connection: { readonly id: string };
    };
    const exactNodeIds = new Set(memoryNodes.map(({ id }) => id));
    for (const node of memoryNodes) {
      const projected = vaultBridge.exportNode(
        activated.connection.id,
        node.id,
        exactNodeIds,
      );
      if (projected.status !== "synced") {
        throw new Error(`Disposable Attack Knowledge Vault projection was not synchronized: ${node.id}`);
      }
    }
    const usableNodeIds = activeConnectedVaultBackedMemoryNodeIds(
      application.database,
      [...exactNodeIds],
    );
    if (
      usableNodeIds.size !== exactNodeIds.size
      || !application.brainContext.readActiveVaultAvailability([...exactNodeIds]).available
    ) {
      throw new Error(
        "Disposable Attack Knowledge Vault nodes are not current, health-verified, conflict-free, and usable",
      );
    }
    let stopped = false;
    return {
      baseUrl,
      branchFixture,
      productAgents: PRODUCT_AGENT_REGISTRY.map(({ id, displayName, role }) => ({
        id,
        displayName,
        role,
      })),
      memoryNodes: memoryNodes.map(({ id, title }) => ({ id, title })),
      async stop(): Promise<void> {
        if (stopped) return;
        stopped = true;
        await closeServer(server!);
        await application!.stop();
        rmSync(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    if (server) await closeServer(server).catch(() => undefined);
    if (application) await application.stop().catch(() => undefined);
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

if (import.meta.main) {
  const instanceId = process.argv[2]?.trim();
  if (!instanceId) throw new Error("The disposable Autonomous intake backend requires an instance ID");
  const profileArgument = process.argv.find((argument) =>
    argument.startsWith("--profile="));
  const profile = profileArgument?.slice("--profile=".length) ?? "full";
  if (
    profile !== "full"
    && profile !== "team_boundary"
    && profile !== "guided_windows_identity"
    && profile !== "guided_local_exploit_intelligence"
  ) {
    throw new Error(`Unsupported Autonomous intake backend profile: ${profile}`);
  }
  const backend = await startReadyAutonomousIntakeBackend(instanceId, {
    profile,
  });
  process.stdout.write(`TI_SCALE_READY_AUTONOMOUS_BACKEND=${JSON.stringify({
    baseUrl: backend.baseUrl,
    branchFixture: backend.branchFixture,
    productAgents: backend.productAgents,
    memoryNodes: backend.memoryNodes,
  })}\n`);
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    try {
      await backend.stop();
      process.exitCode = 0;
    } catch (error) {
      process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
      process.exitCode = 1;
    }
  };
  process.once("SIGINT", () => { void stop(); });
  process.once("SIGTERM", () => { void stop(); });
}
