import type {
  LocalToolCapabilityManifestDocument,
  ReviewedLocalToolCapability,
} from "../local-tools";
import {
  LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
  LocalToolCapabilityManifest,
} from "../local-tools";

export const AUTONOMOUS_FULL_TCP_BASELINE_POLICY_SCHEMA_VERSION =
  "ti-scale.autonomous-full-tcp-baseline-policy.v2" as const;
export const AUTONOMOUS_FULL_TCP_BASELINE_BINDING_ID =
  "binding:autonomous-full-tcp-baseline-v1" as const;
export const AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE =
  "ti-scale:autonomous-full-tcp-baseline" as const;
export const AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID =
  "kali:nmap-full-tcp-connect-discovery-v1" as const;
export const AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID =
  "kali:nmap-discovered-tcp-service-version-v1" as const;
export const AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS =
  "port_service_enumeration" as const;
export const AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE =
  "port_service_scan_result" as const;
export const AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE =
  "service_version_fingerprint" as const;

export const AUTONOMOUS_FULL_TCP_NMAP_PATH =
  "/opt/ti-scale-toolchain/nmap/5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f/nmap" as const;
export const AUTONOMOUS_FULL_TCP_NMAP_SHA256 =
  "5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f" as const;

export const AUTONOMOUS_FULL_TCP_PORT_RANGE = "1-65535" as const;
export const AUTONOMOUS_FULL_TCP_DISCOVERY_MAX_RATE = 1_000 as const;
export const AUTONOMOUS_FULL_TCP_SERVICE_MAX_RATE = 250 as const;
export const AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH = 600 as const;
export const AUTONOMOUS_FULL_TCP_MAX_VERSION_BATCHES = 110 as const;
export const AUTONOMOUS_FULL_TCP_MAX_WALL_CLOCK_MS = 30 * 60_000;
export const AUTONOMOUS_FULL_TCP_MAX_TOTAL_OUTPUT_BYTES = 32 * 1024 * 1024;
export const AUTONOMOUS_FULL_TCP_MAX_INVOCATION_OUTPUT_BYTES = 8 * 1024 * 1024;

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const SECRET = /(?:api[-_]?key|authorization|bearer|cookie|credential|password|private[-_]?key|secret|session[-_]?token)/iu;

export interface AutonomousFullTcpBaselineConfiguration {
  readonly policyId: string;
  readonly bindingId: string;
  readonly agentId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly logicalWorkspace: string;
}

export interface AutonomousFullTcpBaselinePolicy {
  readonly schemaVersion: typeof AUTONOMOUS_FULL_TCP_BASELINE_POLICY_SCHEMA_VERSION;
  readonly policyId: string;
  readonly bindingId: string;
  readonly executionBinding: "reviewed_full_tcp_baseline";
  readonly actionType: typeof AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE;
  readonly actionClassId: typeof AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS;
  readonly agentId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly logicalWorkspace: string;
  readonly targetContract: Readonly<{
    readonly exactSingleAuthorizedHost: true;
    readonly cidrAccepted: false;
    readonly rangeAccepted: false;
    readonly targetBatchAccepted: false;
  }>;
  readonly phases: readonly [
    Readonly<{
      readonly ordinal: 0;
      readonly toolId: typeof AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID;
      readonly description: string;
    }>,
    Readonly<{
      readonly ordinal: 1;
      readonly toolId: typeof AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID;
      readonly description: string;
      readonly input: "deterministically_parsed_open_ports_only";
    }>,
  ];
  readonly bounds: Readonly<{
    readonly tcpPortRange: typeof AUTONOMOUS_FULL_TCP_PORT_RANGE;
    readonly discoveryMaxRate: typeof AUTONOMOUS_FULL_TCP_DISCOVERY_MAX_RATE;
    readonly serviceMaxRate: typeof AUTONOMOUS_FULL_TCP_SERVICE_MAX_RATE;
    readonly maximumVersionPortsPerBatch: typeof AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH;
    readonly maximumVersionBatches: typeof AUTONOMOUS_FULL_TCP_MAX_VERSION_BATCHES;
    readonly maximumWallClockMs: typeof AUTONOMOUS_FULL_TCP_MAX_WALL_CLOCK_MS;
    readonly maximumTotalOutputBytes: typeof AUTONOMOUS_FULL_TCP_MAX_TOTAL_OUTPUT_BYTES;
  }>;
  readonly evidence: Readonly<{
    readonly requiredTypeIds: readonly [
      typeof AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
      typeof AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
    ];
    readonly deterministicVerificationRequired: true;
    /** Promotion is permitted only after the general-runtime verifier rechecks canonical authority. */
    readonly autoPromotion: true;
    readonly promotionAuthority: "deterministic_general_recon_verifier_only";
    readonly rawProcessOutputPromoted: false;
  }>;
}

function safeId(value: string, label: string): string {
  if (value !== value.trim() || !PUBLIC_ID.test(value)) {
    throw new TypeError(`${label} must be a stable public ID`);
  }
  return value;
}

function safeWorkspace(value: string): string {
  if (value !== value.trim() || !value.startsWith("/") || value.length > 4_096
    || CONTROL_CHARACTERS.test(value) || SECRET.test(value)) {
    throw new TypeError("logicalWorkspace must be one safe absolute logical path");
  }
  return value;
}

function parameter(
  name: string,
  semantic: "logical_workspace" | "authorized_single_host" | "tcp_port_set",
  minimum: number,
  maximum: number,
) {
  return {
    name,
    type: "string" as const,
    semantic,
    required: true as const,
    minimum,
    maximum,
    allowedValues: [] as const,
  };
}

function commonTool(tool: Readonly<{
  toolId: string;
  label: string;
  routeIntent: "full_tcp_discovery" | "targeted_service_version";
  timeoutMs: number;
  parameters: LocalToolCapabilityManifestDocument["tools"][number]["parameters"];
  argvTemplate: LocalToolCapabilityManifestDocument["tools"][number]["argvTemplate"];
  evidenceTypeIds: LocalToolCapabilityManifestDocument["tools"][number]["evidenceTypeIds"];
}>): LocalToolCapabilityManifestDocument["tools"][number] {
  return {
    toolId: tool.toolId,
    label: tool.label,
    activation: "enabled",
    activationReason: null,
    executable: {
      path: AUTONOMOUS_FULL_TCP_NMAP_PATH,
      expectedSha256: AUTONOMOUS_FULL_TCP_NMAP_SHA256,
      fileCapabilities: "none",
    },
    probe: {
      arguments: ["--version"],
      expectedExitCodes: [0],
      timeoutMs: 3_000,
      maximumOutputBytes: 16 * 1_024,
      ttlMs: 60_000,
    },
    routing: { intent: tool.routeIntent, targetKind: "ip_or_host" },
    execution: {
      transport: "direct_spawn_argv",
      shell: false,
      noNewPrivilegesRequired: true,
      networkPolicy: "authorized_scope_only",
      filesystemWritePolicy: "resolved_workspace_only",
      environmentPolicy: "fixed_minimal",
      logicalWorkspaceParameter: "workspace",
      timeoutMs: tool.timeoutMs,
      maximumOutputBytes: AUTONOMOUS_FULL_TCP_MAX_INVOCATION_OUTPUT_BYTES,
      terminationGraceMs: 2_000,
    },
    parameters: tool.parameters,
    argvTemplate: tool.argvTemplate,
    actionClassIds: [AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS],
    evidenceTypeIds: tool.evidenceTypeIds,
    riskClassIds: ["ti-scale:network"],
  };
}

/**
 * Separate reviewed source manifest. General Safe Recon may compose these
 * phase tools only when both have current operator-reviewed activation
 * receipts and the composite execution adapter is selected; the phase tools
 * never become planner-visible commands merely because this manifest exists.
 */
export function createAutonomousFullTcpBaselineManifest(): LocalToolCapabilityManifest {
  const document: LocalToolCapabilityManifestDocument = {
    schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    manifestVersion: "autonomous-full-tcp-baseline-v2",
    specialist: {
      id: "specialist:autonomous-full-tcp-recon",
      label: "Autonomous full TCP reconnaissance specialist",
    },
    tools: [
      commonTool({
        toolId: AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
        label: "Reviewed full TCP-connect discovery",
        routeIntent: "full_tcp_discovery",
        timeoutMs: 10 * 60_000,
        parameters: [
          parameter("workspace", "logical_workspace", 2, 4_096),
          parameter("target", "authorized_single_host", 1, 253),
        ],
        argvTemplate: [
          { kind: "literal", value: "-n" },
          { kind: "literal", value: "-Pn" },
          { kind: "literal", value: "-sT" },
          { kind: "literal", value: "--open" },
          { kind: "literal", value: "-p" },
          { kind: "literal", value: AUTONOMOUS_FULL_TCP_PORT_RANGE },
          { kind: "literal", value: "--max-retries" },
          { kind: "literal", value: "1" },
          { kind: "literal", value: "--max-rate" },
          { kind: "literal", value: String(AUTONOMOUS_FULL_TCP_DISCOVERY_MAX_RATE) },
          { kind: "literal", value: "--max-parallelism" },
          { kind: "literal", value: "64" },
          { kind: "literal", value: "--host-timeout" },
          { kind: "literal", value: "8m" },
          { kind: "literal", value: "--max-rtt-timeout" },
          { kind: "literal", value: "2s" },
          { kind: "literal", value: "--" },
          { kind: "parameter", value: "target" },
        ],
        evidenceTypeIds: [AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE],
      }),
      commonTool({
        toolId: AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
        label: "Reviewed discovered-port service version scan",
        routeIntent: "targeted_service_version",
        timeoutMs: 5 * 60_000,
        parameters: [
          parameter("workspace", "logical_workspace", 2, 4_096),
          parameter("target", "authorized_single_host", 1, 253),
          parameter("ports", "tcp_port_set", 1, 4_096),
        ],
        argvTemplate: [
          { kind: "literal", value: "-n" },
          { kind: "literal", value: "-Pn" },
          { kind: "literal", value: "-sT" },
          { kind: "literal", value: "--open" },
          { kind: "literal", value: "-p" },
          { kind: "parameter", value: "ports" },
          { kind: "literal", value: "-sV" },
          { kind: "literal", value: "--version-light" },
          { kind: "literal", value: "--max-retries" },
          { kind: "literal", value: "1" },
          { kind: "literal", value: "--max-rate" },
          { kind: "literal", value: String(AUTONOMOUS_FULL_TCP_SERVICE_MAX_RATE) },
          { kind: "literal", value: "--max-parallelism" },
          { kind: "literal", value: "32" },
          { kind: "literal", value: "--host-timeout" },
          { kind: "literal", value: "4m" },
          { kind: "literal", value: "--max-rtt-timeout" },
          { kind: "literal", value: "2s" },
          { kind: "literal", value: "--" },
          { kind: "parameter", value: "target" },
        ],
        evidenceTypeIds: [
          AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
          AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
        ],
      }),
    ],
  };
  return new LocalToolCapabilityManifest(document);
}

function exactToolBoundary(
  tool: ReviewedLocalToolCapability | undefined,
  expected: Readonly<{
    id: string;
    intent: "full_tcp_discovery" | "targeted_service_version";
    parameters: readonly string[];
    bindingSha256: string;
  }>,
): boolean {
  return Boolean(tool
    && tool.toolId === expected.id
    // The binding digest covers the complete reviewed definition: argv,
    // parameters, process/output/time bounds, evidence types, and sandbox
    // requirements. Checking only the executable identity and parameter names
    // would let a re-authored Nmap command masquerade as this baseline.
    && tool.bindingSha256 === expected.bindingSha256
    && tool.activation === "enabled"
    && tool.executable.path === AUTONOMOUS_FULL_TCP_NMAP_PATH
    && tool.executable.expectedSha256 === AUTONOMOUS_FULL_TCP_NMAP_SHA256
    && tool.executable.fileCapabilities === "none"
    && tool.routing.intent === expected.intent
    && tool.routing.targetKind === "ip_or_host"
    && tool.execution.transport === "direct_spawn_argv"
    && tool.execution.shell === false
    && tool.execution.noNewPrivilegesRequired === true
    && tool.execution.networkPolicy === "authorized_scope_only"
    && tool.execution.filesystemWritePolicy === "resolved_workspace_only"
    && tool.parameters.map(({ name }) => name).sort().join("\u0000")
      === [...expected.parameters].sort().join("\u0000"));
}

export function validateAutonomousFullTcpBaselineConfiguration(
  input: AutonomousFullTcpBaselineConfiguration,
  manifest: LocalToolCapabilityManifest,
): AutonomousFullTcpBaselineConfiguration {
  const reviewed = createAutonomousFullTcpBaselineManifest();
  if (!exactToolBoundary(manifest.resolve(AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID), {
    id: AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
    intent: "full_tcp_discovery",
    parameters: ["workspace", "target"],
    bindingSha256: reviewed.resolve(AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID)!.bindingSha256,
  }) || !exactToolBoundary(manifest.resolve(AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID), {
    id: AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
    intent: "targeted_service_version",
    parameters: ["ports", "workspace", "target"],
    bindingSha256: reviewed.resolve(AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID)!.bindingSha256,
  })) {
    throw new Error("The manifest does not expose the exact reviewed full-TCP baseline boundary");
  }
  if (!SHA256.test(input.modelConfigurationHash)) {
    throw new TypeError("modelConfigurationHash must be a lowercase SHA-256");
  }
  if (input.bindingId === "binding-autonomous-ip-services-v1") {
    throw new TypeError("The full-TCP baseline must not reuse the bounded Safe Recon binding ID");
  }
  return Object.freeze({
    policyId: safeId(input.policyId, "policyId"),
    bindingId: safeId(input.bindingId, "bindingId"),
    agentId: safeId(input.agentId, "agentId"),
    providerId: safeId(input.providerId, "providerId"),
    modelId: safeId(input.modelId, "modelId"),
    modelConfigurationHash: input.modelConfigurationHash,
    logicalWorkspace: safeWorkspace(input.logicalWorkspace),
  });
}

export function createAutonomousFullTcpBaselinePolicy(
  input: AutonomousFullTcpBaselineConfiguration,
  manifest: LocalToolCapabilityManifest,
): AutonomousFullTcpBaselinePolicy {
  const configuration = validateAutonomousFullTcpBaselineConfiguration(input, manifest);
  return Object.freeze({
    schemaVersion: AUTONOMOUS_FULL_TCP_BASELINE_POLICY_SCHEMA_VERSION,
    policyId: configuration.policyId,
    bindingId: configuration.bindingId,
    executionBinding: "reviewed_full_tcp_baseline",
    actionType: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    actionClassId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
    agentId: configuration.agentId,
    providerId: configuration.providerId,
    modelId: configuration.modelId,
    modelConfigurationHash: configuration.modelConfigurationHash,
    logicalWorkspace: configuration.logicalWorkspace,
    targetContract: Object.freeze({
      exactSingleAuthorizedHost: true,
      cidrAccepted: false,
      rangeAccepted: false,
      targetBatchAccepted: false,
    }),
    phases: Object.freeze([
      Object.freeze({
        ordinal: 0 as const,
        toolId: AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
        description: "Use ordinary TCP connections to discover listening ports across the complete 1-65535 range on one exact authorized host.",
      }),
      Object.freeze({
        ordinal: 1 as const,
        toolId: AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
        description: "Run light service/version identification only on the numeric open ports parsed from phase one.",
        input: "deterministically_parsed_open_ports_only" as const,
      }),
    ]) as AutonomousFullTcpBaselinePolicy["phases"],
    bounds: Object.freeze({
      tcpPortRange: AUTONOMOUS_FULL_TCP_PORT_RANGE,
      discoveryMaxRate: AUTONOMOUS_FULL_TCP_DISCOVERY_MAX_RATE,
      serviceMaxRate: AUTONOMOUS_FULL_TCP_SERVICE_MAX_RATE,
      maximumVersionPortsPerBatch: AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH,
      maximumVersionBatches: AUTONOMOUS_FULL_TCP_MAX_VERSION_BATCHES,
      maximumWallClockMs: AUTONOMOUS_FULL_TCP_MAX_WALL_CLOCK_MS,
      maximumTotalOutputBytes: AUTONOMOUS_FULL_TCP_MAX_TOTAL_OUTPUT_BYTES,
    }),
    evidence: Object.freeze({
      requiredTypeIds: Object.freeze([
        AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
        AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
      ]) as AutonomousFullTcpBaselinePolicy["evidence"]["requiredTypeIds"],
      deterministicVerificationRequired: true,
      autoPromotion: true,
      promotionAuthority: "deterministic_general_recon_verifier_only" as const,
      rawProcessOutputPromoted: false,
    }),
  });
}
