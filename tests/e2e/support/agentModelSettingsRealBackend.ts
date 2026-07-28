import express from "express";
import type { AddressInfo } from "node:net";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../../server/db";
import {
  createModelConfigurationRouter,
  ModelConfigurationRepository,
  ModelConfigurationService,
} from "../../../server/model-config";
import { createOperationsRouter } from "../../../server/routes/operationsRoutes";
import {
  RuntimeProjectionService,
  type RuntimeProjectionInput,
} from "../../../server/app/RuntimeProjectionService";
import type { RuntimeSourceManifests } from "../../../server/domain";
import { PRODUCT_AGENT_REGISTRY } from "../../../server/agents";

const OBSERVED_AT = "2099-07-28T12:00:00.000Z";
const INTERNAL_ADAPTER_ID = "runtime:real-backend-recon-adapter";

function manifests(
  observedAt = OBSERVED_AT,
  options: {
    readonly primaryContextLimit?: number;
  } = {},
): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [{
      id: "capability:real-backend-recon",
      label: "Real-backend reconnaissance fixture",
      actionClassIds: ["active_host_discovery"],
    }],
    tools: [{
      id: "tool:real-backend-recon",
      label: "Real-backend authorized discovery",
      available: true,
      locallyPolicyEnforced: true,
      actionClassIds: ["active_host_discovery"],
      evidenceTypeIds: [],
      riskClassIds: [],
    }],
    mcpServers: [],
    providers: [{
      id: "titanium-primary",
      authenticated: true,
      healthy: true,
      catalogObservedAt: observedAt,
      models: [{
        id: "ti-reasoner",
        displayName: "Titanium Reasoner",
        toolCalling: true,
        structuredOutput: true,
        enforcement: "enforced_executor",
        reasoningEfforts: ["medium", "high"],
        compatibleActionClassIds: ["active_host_discovery"],
        disclosureClasses: ["public"],
        contextLimit: options.primaryContextLimit ?? 131_072,
      }],
    }, {
      id: "titanium-fallback",
      authenticated: true,
      healthy: true,
      catalogObservedAt: observedAt,
      models: [{
        id: "ti-fallback",
        displayName: "Titanium Fallback",
        toolCalling: true,
        structuredOutput: true,
        enforcement: "enforced_executor",
        reasoningEfforts: ["medium"],
        compatibleActionClassIds: ["active_host_discovery"],
        disclosureClasses: ["public"],
        contextLimit: 65_536,
      }],
    }],
    agents: [{
      id: INTERNAL_ADAPTER_ID,
      label: "Internal real-backend recon adapter",
      available: true,
      capabilityIds: ["capability:real-backend-recon"],
      toolIds: ["tool:real-backend-recon"],
      modelRefs: [{
        providerId: "titanium-primary",
        modelId: "ti-reasoner",
      }, {
        providerId: "titanium-fallback",
        modelId: "ti-fallback",
      }],
    }, ...PRODUCT_AGENT_REGISTRY.map(({ id }) => ({
      id,
      label: `${id} real-backend model route`,
      available: true,
      capabilityIds: [],
      actionClassIds: [],
      toolIds: [],
      modelRefs: [{
        providerId: "titanium-primary",
        modelId: "ti-reasoner",
      }, {
        providerId: "titanium-fallback",
        modelId: "ti-fallback",
      }],
    }))],
  };
}

function projection(
  capabilityManifests: RuntimeSourceManifests,
): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
      specialistsConfigured: 1,
      providers: [],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      eventStream: "healthy",
      secondBrain: "healthy",
      legacyExecutionEnabled: false,
    },
    capabilityManifests,
    agents: [{
      id: INTERNAL_ADAPTER_ID,
      role: "reviewed-local-process-adapter",
      displayName: "Internal real-backend recon adapter",
      status: "available",
      providerPolicy: {
        source: "real-backend-fixture",
      },
      toolPolicy: {
        allowedTools: ["tool:real-backend-recon"],
        deniedTools: [],
        approvalRequiredTools: [],
      },
      configuration: {
        executionMounted: true,
      },
      version: "real-backend-v1",
      lastHeartbeatAt: OBSERVED_AT,
      capabilities: [{
        name: "capability:real-backend-recon",
        source: "real-backend-fixture",
        enabled: true,
        metadata: {
          actionClassIds: ["active_host_discovery"],
        },
      }],
    }],
    mcpServers: [],
  };
}

export interface AgentModelSettingsRealBackend {
  readonly url: string;
  readonly internalAdapterId: string;
  renewCatalogAttestation(
    observedAt: string,
    options?: {
      readonly primaryContextLimit?: number;
    },
  ): void;
  close(): Promise<void>;
}

/**
 * Starts the actual roster, model-catalog, optimistic preference, and
 * resolution routers over one real SQLite connection. Browser requests may be
 * transport-forwarded here, but no API payload is mocked or synthesized by
 * Playwright.
 */
export async function startAgentModelSettingsRealBackend():
Promise<AgentModelSettingsRealBackend> {
  const database: SqliteDatabase = createDatabaseConnection({
    filename: ":memory:",
  });
  migrateDatabase(database);
  let capabilityManifests = manifests();
  new RuntimeProjectionService({
    database,
    read: () => projection(capabilityManifests),
    clock: () => new Date(OBSERVED_AT),
  }).projectNow();
  const service = new ModelConfigurationService(
    new ModelConfigurationRepository(
      database,
      () => new Date(OBSERVED_AT),
    ),
    {
      readRuntimeManifests: () => capabilityManifests,
      clock: () => new Date(OBSERVED_AT),
    },
  );

  const app = express();
  app.use(express.json({ limit: "64kb" }));
  app.use(createModelConfigurationRouter({
    database,
    readRuntimeManifests: () => capabilityManifests,
    resolveActor: () => "e2e-local-operator",
    service,
    clock: () => new Date(OBSERVED_AT),
  }));
  app.use(createOperationsRouter({
    database,
    resolveActor: () => ({
      id: "e2e-local-operator",
      type: "operator",
    }),
    resolveAccess: () => ({
      maximumSensitivity: "restricted",
      allEngagements: true,
      allowGlobalKnowledge: true,
      allowUnscopedSystemData: false,
    }),
    clock: () => new Date(OBSERVED_AT),
  }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  let closed = false;
  return {
    url: `http://127.0.0.1:${address.port}`,
    internalAdapterId: INTERNAL_ADAPTER_ID,
    renewCatalogAttestation: (observedAt, options) => {
      capabilityManifests = manifests(observedAt, options);
    },
    close: async () => {
      if (closed) return;
      closed = true;
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
      database.close();
    },
  };
}
