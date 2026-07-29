import type { ActionClassId, DeliverableId, RuntimeSourceManifests } from "../domain";
import type { RuntimeAgentManifest } from "../domain";
import type {
  FleetAgentProjection,
  FleetAgentStatus,
} from "../app/RuntimeProjectionService";

export const PRODUCT_AGENT_ROSTER_VERSION =
  "ti-scale.product-agent-roster.v1" as const;

export const COMMANDER_AGENT_ID = "Commander" as const;

export interface ProductAgentCapabilityDefinition {
  readonly id: string;
  readonly label: string;
  readonly actionClassIds: readonly ActionClassId[];
}

export interface ProductAgentDefinition {
  readonly id:
    | "ReconScout"
    | "WebBreaker"
    | "CredSmith"
    | "ADAttackMapper"
    | "CloudSentinel"
    | "ReverseSage"
    | "FuzzSmith"
    | "OSINTSeeker"
    | "SecretHunter"
    | "SessionRunner"
    | "ReportSmith"
    | "VulnIntel";
  readonly displayName: string;
  readonly role: string;
  readonly domains: readonly string[];
  readonly description: string;
  readonly capabilities: readonly ProductAgentCapabilityDefinition[];
  readonly deliverableIds?: readonly DeliverableId[];
}

export type ProductAgentId = ProductAgentDefinition["id"];
export type ProductRosterAgentId =
  | typeof COMMANDER_AGENT_ID
  | ProductAgentId;

export const COMMANDER_AGENT_DEFINITION = Object.freeze({
  id: COMMANDER_AGENT_ID,
  displayName: "Commander",
  role: "Mission planning and orchestration",
  domains: Object.freeze([
    "mission planning",
    "specialist routing",
    "supervision",
    "recovery coordination",
  ]),
  description:
    "Plans and supervises authorized missions, routes work to canonical specialists, and explains progress without directly executing specialist tools.",
  capabilities: Object.freeze([Object.freeze({
    id: "commander.planning-supervision",
    label: "Mission planning and supervision",
    actionClassIds: Object.freeze([]),
  })]),
  executionAuthority: "none",
} as const);

function capability(
  id: string,
  label: string,
  ...actionClassIds: readonly ActionClassId[]
): ProductAgentCapabilityDefinition {
  return Object.freeze({
    id,
    label,
    actionClassIds: Object.freeze([...actionClassIds]),
  });
}

function deliverables(...ids: readonly DeliverableId[]): readonly DeliverableId[] {
  return Object.freeze([...ids]);
}

/**
 * Stable product roles are intentionally independent from worker, provider,
 * and transport identities. Runtime adapters may change without changing the
 * fleet language, deep links, model inheritance keys, or assignment history
 * operators use.
 */
export const PRODUCT_AGENT_REGISTRY: readonly ProductAgentDefinition[] = Object.freeze([
  Object.freeze({
    id: "ReconScout",
    displayName: "ReconScout",
    role: "Reconnaissance and asset intelligence",
    domains: Object.freeze(["network reconnaissance", "DNS", "service discovery", "technology fingerprinting"]),
    description: "Builds an evidence-backed picture of reachable assets, names, ports, services, operating systems, and technology versions.",
    capabilities: Object.freeze([
      capability("recon.asset-discovery", "Authorized host discovery", "active_host_discovery"),
      capability("recon.dns-certificate-mapping", "DNS and certificate mapping", "dns_domain_certificate_discovery"),
      capability("recon.service-enumeration", "Port and service enumeration", "port_service_enumeration"),
      capability("recon.platform-fingerprinting", "Operating-system and technology fingerprinting", "os_technology_fingerprinting"),
    ]),
  }),
  Object.freeze({
    id: "WebBreaker",
    displayName: "WebBreaker",
    role: "Web application assessment",
    domains: Object.freeze(["web applications", "HTTP", "content discovery", "application attack surfaces"]),
    description: "Maps authorized web applications, captures pages, discovers endpoints, and tests application behavior through reviewed web assessment bindings.",
    capabilities: Object.freeze([
      capability("web.surface-mapping", "Web crawling and page capture", "web_crawling_page_capture"),
      capability("web.endpoint-discovery", "Endpoint and content discovery", "web_content_endpoint_discovery_fuzzing"),
    ]),
  }),
  Object.freeze({
    id: "CredSmith",
    displayName: "CredSmith",
    role: "Credential and authentication assessment",
    domains: Object.freeze(["credentials", "passwords", "hashes", "authentication"]),
    description: "Evaluates credential material and authentication controls while retaining exact provenance and account-safety limits.",
    capabilities: Object.freeze([
      capability("credential.audit", "Credential, password, and hash assessment", "credential_password_hash_assessment"),
      capability("authentication.validation", "Authentication testing", "authentication_testing"),
    ]),
  }),
  Object.freeze({
    id: "ADAttackMapper",
    displayName: "ADAttackMapper",
    role: "Active Directory and identity path analysis",
    domains: Object.freeze(["Active Directory", "identity", "trusts", "lateral movement"]),
    description: "Maps identity relationships, trust paths, directory controls, and evidence-backed lateral movement opportunities.",
    capabilities: Object.freeze([
      capability("identity.directory-operations", "Active Directory and identity operations", "active_directory_identity_operations"),
      capability("identity.lateral-paths", "Lateral movement and pivot analysis", "lateral_movement_pivoting"),
    ]),
  }),
  Object.freeze({
    id: "CloudSentinel",
    displayName: "CloudSentinel",
    role: "Cloud, container, and Kubernetes assessment",
    domains: Object.freeze(["cloud", "containers", "Kubernetes", "platform configuration"]),
    description: "Assesses authorized cloud, container, and Kubernetes control planes and records configuration evidence without inventing unavailable coverage.",
    capabilities: Object.freeze([
      capability("cloud.platform-assessment", "Cloud, container, and Kubernetes assessment", "cloud_container_kubernetes_assessment"),
    ]),
  }),
  Object.freeze({
    id: "ReverseSage",
    displayName: "ReverseSage",
    role: "Reverse engineering and binary analysis",
    domains: Object.freeze(["binaries", "reverse engineering", "static analysis", "dynamic analysis"]),
    description: "Explains executable behavior and derives evidence-backed implementation details from authorized binary-analysis work.",
    capabilities: Object.freeze([
      capability("reverse.binary-analysis", "Reverse engineering and binary analysis", "reverse_engineering_binary_analysis"),
    ]),
  }),
  Object.freeze({
    id: "FuzzSmith",
    displayName: "FuzzSmith",
    role: "Fuzzing and crash discovery",
    domains: Object.freeze(["fuzzing", "crash analysis", "input generation", "reproduction"]),
    description: "Runs bounded fuzzing campaigns, classifies crashes, and preserves reproducible inputs and diagnostics.",
    capabilities: Object.freeze([
      capability("fuzz.crash-discovery", "Fuzzing and crash discovery", "fuzzing_crash_discovery"),
    ]),
  }),
  Object.freeze({
    id: "OSINTSeeker",
    displayName: "OSINTSeeker",
    role: "Passive intelligence and OSINT",
    domains: Object.freeze(["OSINT", "public sources", "external footprint", "passive discovery"]),
    description: "Collects relevant public intelligence without directly interacting with the authorized target environment.",
    capabilities: Object.freeze([
      capability("osint.passive-intelligence", "Passive intelligence and OSINT", "passive_intelligence_osint"),
    ]),
  }),
  Object.freeze({
    id: "SecretHunter",
    displayName: "SecretHunter",
    role: "Secrets and source-code analysis",
    domains: Object.freeze(["secrets", "source code", "configuration", "sensitive material"]),
    description: "Finds and validates exposed secrets or sensitive configuration while keeping credential values out of reusable memory and public-provider context.",
    capabilities: Object.freeze([
      capability("secrets.exposure-validation", "Sensitive data access validation", "data_access_impact_validation"),
    ]),
  }),
  Object.freeze({
    id: "SessionRunner",
    displayName: "SessionRunner",
    role: "Controlled exploitation and session execution",
    domains: Object.freeze(["exploit validation", "sessions", "privilege escalation", "persistence", "cleanup"]),
    description: "Executes reviewed attack procedures, manages resulting sessions, validates impact, and performs bounded cleanup through exact runtime bindings.",
    capabilities: Object.freeze([
      capability("session.exploit-validation", "Exploit validation", "exploit_validation"),
      capability("session.command-execution", "Command and session execution", "command_session_execution"),
      capability("session.target-file-write", "Target file write", "target_file_write"),
      capability("session.privilege-escalation", "Privilege escalation", "privilege_escalation"),
      capability("session.persistence", "Persistence", "persistence"),
      capability("session.cleanup", "Cleanup and restoration", "cleanup_restoration"),
      capability("session.service-disruption", "Service disruption", "denial_of_service_disruption"),
      capability("session.destructive-modification", "Destructive modification", "destructive_modification"),
    ]),
  }),
  Object.freeze({
    id: "ReportSmith",
    displayName: "ReportSmith",
    role: "Evidence-backed reporting and memory",
    domains: Object.freeze(["reporting", "artifacts", "evidence synthesis", "Second Brain"]),
    description: "Produces traceable reports and durable knowledge projections from verified mission records and evidence.",
    capabilities: Object.freeze([
      capability("report.canonical-generation", "Local report and artifact generation", "local_report_artifact_generation"),
    ]),
    deliverableIds: deliverables(
      "executive_summary",
      "technical_findings",
      "network_asset_map",
      "osi_application_stack_map",
      "attack_path_visualization",
      "engagement_timeline",
      "evidence_bundle",
      "web_page_screenshot_gallery",
      "cve_applicability_register",
      "scripts_and_documentation",
      "remediation_plan",
      "raw_technical_log_export",
      "obsidian_engagement_pack",
      "machine_readable_export",
      "pdf_html_markdown_report",
    ),
  }),
  Object.freeze({
    id: "VulnIntel",
    displayName: "VulnIntel",
    role: "Vulnerability and CVE intelligence",
    domains: Object.freeze(["vulnerability assessment", "CVE intelligence", "version applicability", "configuration analysis"]),
    description: "Correlates observed products and versions with authoritative vulnerability intelligence and separates confirmed applicability from possible matches.",
    capabilities: Object.freeze([
      capability("vulnerability.configuration-assessment", "Vulnerability and configuration assessment", "vulnerability_configuration_assessment"),
      capability("vulnerability.cve-applicability", "CVE intelligence and applicability validation", "cve_intelligence_applicability_validation"),
    ]),
  }),
]);

/** Action-owning specialist identities. Commander is deliberately excluded. */
export const PRODUCT_AGENT_IDS: ReadonlySet<string> = new Set(
  PRODUCT_AGENT_REGISTRY.map(({ id }) => id),
);

/** User-facing roster and model-configuration identities. */
export const PRODUCT_ROSTER_AGENT_IDS: ReadonlySet<string> = new Set([
  COMMANDER_AGENT_ID,
  ...PRODUCT_AGENT_IDS,
]);

const ACTION_CLASS_OWNER = new Map<ActionClassId, ProductAgentId>(
  PRODUCT_AGENT_REGISTRY.flatMap((agent) =>
    agent.capabilities.flatMap((item) =>
      item.actionClassIds.map((actionClassId) => [actionClassId, agent.id] as const))),
);

export function productAgentIdForActionClass(
  actionClassId: string,
): ProductAgentId | undefined {
  return ACTION_CLASS_OWNER.get(actionClassId as ActionClassId);
}

function orderedProductIds(
  ids: ReadonlySet<ProductRosterAgentId>,
): readonly ProductRosterAgentId[] {
  return [
    COMMANDER_AGENT_ID,
    ...PRODUCT_AGENT_REGISTRY.map(({ id }) => id),
  ]
    .filter((id) => ids.has(id));
}

function productIdsFromRuntimeSignals(input: Readonly<{
  readonly runtimeAgentId: string;
  readonly actionClassIds: readonly string[];
  readonly deliverableIds?: readonly string[];
}>): readonly ProductRosterAgentId[] {
  const ids = new Set<ProductRosterAgentId>();
  if (input.runtimeAgentId === COMMANDER_AGENT_ID) {
    ids.add(COMMANDER_AGENT_ID);
  } else if (PRODUCT_AGENT_IDS.has(input.runtimeAgentId)) {
    ids.add(input.runtimeAgentId as ProductRosterAgentId);
  }
  for (const actionClassId of input.actionClassIds) {
    const owner = ACTION_CLASS_OWNER.get(actionClassId as ActionClassId);
    if (owner) ids.add(owner);
  }
  if ((input.deliverableIds?.length ?? 0) > 0) ids.add("ReportSmith");
  return orderedProductIds(ids);
}

/**
 * Maps an execution-manifest identity to stable product roles. Model catalogs,
 * readiness, and assignment UIs must use this bridge instead of surfacing a
 * worker/transport ID as though it were a product specialist.
 */
export function productAgentIdsForRuntimeManifestAgent(
  agent: RuntimeAgentManifest,
  manifests: Pick<RuntimeSourceManifests, "capabilities" | "tools">,
): readonly ProductRosterAgentId[] {
  const actionClassIds = actionClassIdsForRuntimeManifestAgent(agent, manifests);
  return productIdsFromRuntimeSignals({
    runtimeAgentId: agent.id,
    actionClassIds,
    deliverableIds: agent.deliverableIds,
  });
}

/**
 * Resolve the canonical action classes represented by one runtime adapter.
 * Adapter manifests may omit their optional flattened actionClassIds field;
 * capability and tool declarations remain authoritative inputs to the same
 * product-role bridge used by the fleet projection.
 */
export function actionClassIdsForRuntimeManifestAgent(
  agent: RuntimeAgentManifest,
  manifests: Pick<RuntimeSourceManifests, "capabilities" | "tools">,
): readonly ActionClassId[] {
  const capabilityIds = new Set(agent.capabilityIds);
  const toolIds = new Set(agent.toolIds);
  return [...new Set([
    ...(agent.actionClassIds ?? []),
    ...manifests.capabilities
      .filter(({ id }) => capabilityIds.has(id))
      .flatMap(({ actionClassIds }) => actionClassIds),
    ...manifests.tools
      .filter(({ id }) => toolIds.has(id))
      .flatMap(({ actionClassIds }) => actionClassIds),
  ])].filter((id): id is ActionClassId =>
    ACTION_CLASS_OWNER.has(id as ActionClassId));
}

function record(value: unknown): Readonly<Record<string, unknown>> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : {};
}

function stringArray(value: unknown): readonly string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function exactToolPolicyAllows(
  policy: Readonly<Record<string, unknown>>,
  toolId: string,
): boolean {
  const allowed = new Set(stringArray(policy.allowedTools));
  const denied = new Set(stringArray(policy.deniedTools));
  const approvalRequired = new Set(stringArray(policy.approvalRequiredTools));
  return allowed.has(toolId)
    && !denied.has(toolId)
    && !approvalRequired.has(toolId);
}

function linkedRuntimeActionClasses(
  agent: FleetAgentProjection,
  manifests: RuntimeSourceManifests,
): ReadonlySet<ActionClassId> {
  const manifestAgent = manifests.agents.find(({ id }) => id === agent.id);
  if (!manifestAgent) return new Set();
  const declaredCapabilityIds = new Set(manifestAgent.capabilityIds);
  const declaredToolIds = new Set(manifestAgent.toolIds);
  return new Set(agent.capabilities
    .filter(({ enabled, name }) =>
      enabled && (declaredCapabilityIds.has(name) || declaredToolIds.has(name)))
    .flatMap((capability) => capabilityActionClasses(capability, manifests)));
}

function exactManifestToolCapabilities(
  agent: FleetAgentProjection,
  manifests: RuntimeSourceManifests,
  productAgentId?: ProductAgentId,
): FleetAgentProjection["capabilities"] {
  const manifestAgent = manifests.agents.find(({ id }) => id === agent.id);
  if (!manifestAgent) return Object.freeze([]);
  const linkedActionClasses = linkedRuntimeActionClasses(agent, manifests);
  return Object.freeze(manifestAgent.toolIds.flatMap((toolId) => {
    const tool = manifests.tools.find(({ id }) => id === toolId);
    if (!tool) return [];
    const declaredActionClassIds = tool.actionClassIds
      .filter((actionClassId): actionClassId is ActionClassId => {
        const owner = ACTION_CLASS_OWNER.get(actionClassId as ActionClassId);
        return owner !== undefined
          && (productAgentId === undefined || owner === productAgentId);
      });
    if (declaredActionClassIds.length === 0) return [];
    const actionClassIds = declaredActionClassIds
      .filter((actionClassId) => linkedActionClasses.has(actionClassId));
    const serverReady = !tool.mcpServerId
      || manifests.mcpServers.some((server) =>
        server.id === tool.mcpServerId
        && server.status === "healthy"
        && server.toolIds.includes(tool.id));
    const enabled = actionClassIds.length > 0
      && agent.status !== "offline"
      && agent.status !== "quarantined"
      && manifestAgent.available
      && tool.available
      && tool.locallyPolicyEnforced
      && (tool.dependencies ?? []).every(({ ready }) => ready)
      && serverReady
      && exactToolPolicyAllows(record(agent.toolPolicy), tool.id);
    return [Object.freeze({
      name: tool.id,
      source: "runtime-manifest-tool-binding",
      enabled,
      metadata: Object.freeze({
        toolId: tool.id,
        actionClassIds: Object.freeze([...actionClassIds]),
        declaredActionClassIds: Object.freeze([...declaredActionClassIds]),
        runtimeBindingAgentId: agent.id,
        ...(productAgentId ? { productAgentId } : {}),
        mcpServerId: tool.mcpServerId ?? null,
        locallyPolicyEnforced: tool.locallyPolicyEnforced,
      }),
    })];
  }));
}

function capabilityActionClasses(
  capability: FleetAgentProjection["capabilities"][number],
  manifests: RuntimeSourceManifests | undefined,
): readonly ActionClassId[] {
  const metadata = record(capability.metadata);
  const declared = [
    ...(typeof metadata.actionClassId === "string" ? [metadata.actionClassId] : []),
    ...stringArray(metadata.actionClassIds),
  ];
  const tool = manifests?.tools.find(({ id }) => id === capability.name);
  const manifestCapability = manifests?.capabilities.find(({ id }) => id === capability.name);
  return [...new Set([
    ...declared,
    ...(tool?.actionClassIds ?? []),
    ...(manifestCapability?.actionClassIds ?? []),
  ].filter((item): item is ActionClassId => ACTION_CLASS_OWNER.has(item as ActionClassId)))];
}

function productIdsForBinding(
  agent: FleetAgentProjection,
  manifests: RuntimeSourceManifests | undefined,
): readonly ProductRosterAgentId[] {
  const actionClassIds: ActionClassId[] = [];
  for (const binding of agent.capabilities) {
    for (const actionClassId of capabilityActionClasses(binding, manifests)) {
      actionClassIds.push(actionClassId);
    }
  }
  const manifestAgent = manifests?.agents.find(({ id }) => id === agent.id && agent.status !== "offline");
  return productIdsFromRuntimeSignals({
    runtimeAgentId: agent.id,
    actionClassIds,
    deliverableIds: manifestAgent?.available ? manifestAgent.deliverableIds : [],
  });
}

function isMountedRuntimeBinding(agent: FleetAgentProjection): boolean {
  return !["offline", "quarantined"].includes(agent.status)
    && record(agent.configuration).executionMounted !== false;
}

function maximumHeartbeat(bindings: readonly FleetAgentProjection[]): string | null {
  const valid = bindings
    .map(({ lastHeartbeatAt }) => lastHeartbeatAt)
    .filter((value): value is string => typeof value === "string" && Number.isFinite(Date.parse(value)))
    .sort((left, right) => Date.parse(right) - Date.parse(left));
  return valid[0] ?? null;
}

function fleetStatus(
  bindings: readonly FleetAgentProjection[],
  enabledCapabilityCount: number,
): FleetAgentStatus {
  if (bindings.length === 0 || enabledCapabilityCount === 0) return "offline";
  if (bindings.some(({ status }) => status === "busy")) return "busy";
  if (bindings.some(({ status }) => status === "available")) return "available";
  if (bindings.some(({ status }) => status === "degraded")) return "degraded";
  if (bindings.some(({ status }) => status === "quarantined")) return "quarantined";
  return "offline";
}

function uniqueCapabilities(
  capabilities: readonly FleetAgentProjection["capabilities"][number][],
): FleetAgentProjection["capabilities"] {
  const byKey = new Map<string, FleetAgentProjection["capabilities"][number]>();
  for (const item of capabilities) {
    const key = `${item.source}\u0000${item.name}`;
    const current = byKey.get(key);
    if (!current || (!current.enabled && item.enabled)) byKey.set(key, item);
  }
  return Object.freeze([...byKey.values()].sort((left, right) =>
    left.name.localeCompare(right.name) || left.source.localeCompare(right.source)));
}

/**
 * Produces the stable user-facing fleet plus explicitly hidden adapter rows.
 * A product role becomes available only from an enabled, currently projected
 * binding (or an available manifest-bound report deliverable). Definitions
 * alone never make an unavailable domain look ready.
 */
export function projectProductAgentRoster(input: Readonly<{
  readonly agents: readonly FleetAgentProjection[];
  readonly capabilityManifests?: RuntimeSourceManifests;
  readonly commanderReady?: boolean;
}>): readonly FleetAgentProjection[] {
  const duplicateIds = input.agents
    .map(({ id }) => id)
    .filter((id, index, values) => values.indexOf(id) !== index);
  if (duplicateIds.length > 0) {
    throw new Error(`Duplicate projected agent: ${duplicateIds[0]}`);
  }

  const productIdsByBinding = new Map(
    input.agents.map((agent) => [
      agent.id,
      productIdsForBinding(agent, input.capabilityManifests),
    ] as const),
  );
  const commanderModelBindings = input.capabilityManifests?.agents
    .filter(({ id }) => id === COMMANDER_AGENT_ID)
    .flatMap((agent) => agent.modelRefs.flatMap((reference) => {
      const provider = input.capabilityManifests?.providers.find(
        ({ id }) => id === reference.providerId,
      );
      const model = provider?.models.find(({ id }) => id === reference.modelId);
      return provider?.authenticated === true
        && provider.healthy === true
        && model?.enforcement === "advisor_only"
        && model.structuredOutput === true
        ? [Object.freeze({
            providerId: provider.id,
            modelId: model.id,
            catalogObservedAt: provider.catalogObservedAt,
          })]
        : [];
    })) ?? [];
  const commanderAvailable =
    input.commanderReady === true || commanderModelBindings.length > 0;
  const commander: FleetAgentProjection = Object.freeze({
    id: COMMANDER_AGENT_ID,
    role: COMMANDER_AGENT_DEFINITION.role,
    displayName: COMMANDER_AGENT_DEFINITION.displayName,
    status: commanderAvailable ? "available" : "offline",
    providerPolicy: Object.freeze({
      inheritance: "global_then_agent_then_mission_then_run",
      purpose: "planning",
      executionAuthority: "none",
      modelBindings: Object.freeze(commanderModelBindings),
    }),
    toolPolicy: Object.freeze({
      allowedTools: Object.freeze([]),
      directToolExecution: false,
      specialistDelegationRequired: true,
    }),
    configuration: Object.freeze({
      schemaVersion: PRODUCT_AGENT_ROSTER_VERSION,
      userFacing: true,
      productAgent: true,
      orchestrationAgent: true,
      executionAuthority: "none",
      domains: COMMANDER_AGENT_DEFINITION.domains,
      description: COMMANDER_AGENT_DEFINITION.description,
      capabilityIds: Object.freeze(
        COMMANDER_AGENT_DEFINITION.capabilities.map(({ id }) => id),
      ),
      runtimeBindingAgentIds: Object.freeze([]),
      runtimeBindingVersions: Object.freeze([]),
      readiness: Object.freeze({
        status: commanderAvailable ? "available" : "offline",
        planningModelBindingCount: commanderModelBindings.length,
        localOrchestrationReady: input.commanderReady === true,
      }),
    }),
    version: PRODUCT_AGENT_ROSTER_VERSION,
    lastHeartbeatAt: null,
    capabilities: Object.freeze([
      Object.freeze({
        name: "commander.planning-supervision",
        source: PRODUCT_AGENT_ROSTER_VERSION,
        enabled: commanderAvailable,
        metadata: Object.freeze({
          label: "Mission planning and supervision",
          productAgentId: COMMANDER_AGENT_ID,
          executionAuthority: "none",
          actionClassIds: Object.freeze([]),
        }),
      }),
    ]),
  });
  const productAgents = PRODUCT_AGENT_REGISTRY.map((definition): FleetAgentProjection => {
    const bindings = input.agents.filter((agent) =>
      isMountedRuntimeBinding(agent)
      && productIdsByBinding.get(agent.id)?.includes(definition.id));
    const boundCapabilities = bindings.flatMap((agent) =>
      agent.capabilities.flatMap((binding) => {
        const owned = capabilityActionClasses(binding, input.capabilityManifests)
          .some((actionClassId) => ACTION_CLASS_OWNER.get(actionClassId) === definition.id);
        const exactProductFallback = agent.id === definition.id
          && capabilityActionClasses(binding, input.capabilityManifests).length === 0;
        return owned || exactProductFallback
          ? [Object.freeze({
              ...binding,
              metadata: Object.freeze({
                ...record(binding.metadata),
                runtimeBindingAgentId: agent.id,
                productAgentId: definition.id,
              }),
            })]
          : [];
      }));
    const boundToolCapabilities = input.capabilityManifests
      ? bindings.flatMap((agent) =>
          exactManifestToolCapabilities(
            agent,
            input.capabilityManifests!,
            definition.id,
          ))
      : [];
    const manifestDeliverables = definition.id === "ReportSmith"
      ? bindings.flatMap((agent) => {
          const manifestAgent = input.capabilityManifests?.agents.find(({ id }) => id === agent.id);
          return manifestAgent?.available
            ? (manifestAgent.deliverableIds ?? []).map((deliverableId) => Object.freeze({
                name: `deliverable:${deliverableId}`,
                source: "runtime-manifest-binding",
                enabled: true,
                metadata: Object.freeze({
                  deliverableId,
                  runtimeBindingAgentId: agent.id,
                  productAgentId: definition.id,
                }),
              }))
            : [];
        })
      : [];
    const executableCapabilities = input.capabilityManifests
      ? boundToolCapabilities
      : boundCapabilities;
    const readyActionClasses = new Set(executableCapabilities
      .filter(({ enabled }) => enabled)
      .flatMap((item) => capabilityActionClasses(item, input.capabilityManifests)));
    const semanticCapabilities = definition.capabilities.map((item) => Object.freeze({
      name: item.id,
      source: PRODUCT_AGENT_ROSTER_VERSION,
      enabled: item.actionClassIds.some((actionClassId) => readyActionClasses.has(actionClassId))
        || (definition.id === "ReportSmith" && manifestDeliverables.length > 0),
      metadata: Object.freeze({
        label: item.label,
        actionClassIds: item.actionClassIds,
        productAgentId: definition.id,
      }),
    }));
    const capabilities = uniqueCapabilities([
      ...semanticCapabilities,
      ...boundCapabilities,
      ...boundToolCapabilities,
      ...manifestDeliverables,
    ]);
    const enabledCapabilityCount = executableCapabilities
      .filter(({ enabled }) => enabled).length + manifestDeliverables.length;
    const status = fleetStatus(bindings, enabledCapabilityCount);
    return Object.freeze({
      id: definition.id,
      role: definition.role,
      displayName: definition.displayName,
      status,
      providerPolicy: Object.freeze({
        inheritance: "global_then_agent_then_mission_then_run_then_step",
        runtimeBindings: Object.freeze(bindings.map((agent) => Object.freeze({
          agentId: agent.id,
          policy: agent.providerPolicy,
        }))),
      }),
      toolPolicy: Object.freeze({
        allowedTools: Object.freeze(executableCapabilities
          .filter(({ enabled }) => enabled)
          .map(({ name }) => name)
          .sort()),
        runtimeBindings: Object.freeze(bindings.map((agent) => Object.freeze({
          agentId: agent.id,
          policy: agent.toolPolicy,
        }))),
      }),
      configuration: Object.freeze({
        schemaVersion: PRODUCT_AGENT_ROSTER_VERSION,
        userFacing: true,
        productAgent: true,
        domains: definition.domains,
        description: definition.description,
        capabilityIds: Object.freeze(definition.capabilities.map(({ id }) => id)),
        runtimeBindingAgentIds: Object.freeze(bindings.map(({ id }) => id).sort()),
        runtimeBindingVersions: Object.freeze(bindings.map(({ id, version }) => ({ id, version }))),
        readiness: Object.freeze({
          status,
          boundAdapterCount: bindings.length,
          enabledCapabilityCount,
        }),
      }),
      version: PRODUCT_AGENT_ROSTER_VERSION,
      lastHeartbeatAt: maximumHeartbeat(bindings),
      capabilities,
    });
  });

  const internalAgents = input.agents
    .filter(({ id }) => !PRODUCT_ROSTER_AGENT_IDS.has(id))
    .map((agent): FleetAgentProjection => Object.freeze({
      ...agent,
      capabilities: input.capabilityManifests
        ? uniqueCapabilities([
            ...agent.capabilities,
            ...exactManifestToolCapabilities(agent, input.capabilityManifests),
          ])
        : agent.capabilities,
      configuration: Object.freeze({
        ...agent.configuration,
        userFacing: false,
        productAgent: false,
        internalComponent: true,
        projectedProductAgentIds: Object.freeze([
          ...(productIdsByBinding.get(agent.id) ?? []),
        ]),
      }),
    }));
  return Object.freeze([commander, ...productAgents, ...internalAgents]);
}
