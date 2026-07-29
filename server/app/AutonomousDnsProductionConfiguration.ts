import {
  loadTrustedCandidateLinuxTransportBindingManifest,
  loadTrustedReviewedRealCandidateLinuxProfile,
  type CandidateLinuxTransportBindingManifest,
  type ReviewedRealCandidateLinuxProfile,
  AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID,
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
} from "../autonomous-runtime";
import { isAbsolute, resolve } from "node:path";
import {
  loadPinnedLocalAuthoritativeCveCandidateCatalog,
  type LoadedPinnedLocalCveCandidateCatalog,
} from "../cve-intelligence";
import {
  hashMcpServerConnectionConfig,
  parseMcpServerConnectionConfig,
  type McpServerConnectionConfig,
} from "../mcp";
import {
  loadTrustedExactTargetSandboxActivationManifest,
  type ExactTargetSandboxActivationManifest,
} from "../exploit-sandbox";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";
import {
  loadTrustedAutonomousDnsRuntimeConfiguration,
  type AutonomousDnsRuntimeConfiguration,
} from "./AutonomousDnsActivationCoordinator";

export const AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT = Object.freeze({
  trustRoot: "TI_SCALE_AUTONOMOUS_DNS_TRUSTED_CONFIG_ROOT",
  runtimeConfigurationPath: "TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_PATH",
  runtimeConfigurationSha256: "TI_SCALE_AUTONOMOUS_DNS_RUNTIME_CONFIG_SHA256",
  mcpConnectionPath: "TI_SCALE_AUTONOMOUS_DNS_MCP_CONFIG_PATH",
  mcpConnectionSha256: "TI_SCALE_AUTONOMOUS_DNS_MCP_CONFIG_SHA256",
  cveCandidateCatalogPath: "TI_SCALE_AUTONOMOUS_CVE_CANDIDATE_CATALOG_PATH",
  cveCandidateCatalogSha256: "TI_SCALE_AUTONOMOUS_CVE_CANDIDATE_CATALOG_SHA256",
  exploitSandboxTrustRoot:
    "TI_SCALE_AUTONOMOUS_EXPLOIT_SANDBOX_TRUST_ROOT",
  exploitSandboxManifestPath:
    "TI_SCALE_AUTONOMOUS_EXPLOIT_SANDBOX_MANIFEST_PATH",
  exploitSandboxManifestSha256:
    "TI_SCALE_AUTONOMOUS_EXPLOIT_SANDBOX_MANIFEST_SHA256",
  candidateLinuxTransportTrustRoot:
    "TI_SCALE_AUTONOMOUS_LINUX_TRANSPORT_TRUST_ROOT",
  candidateLinuxTransportManifestPath:
    "TI_SCALE_AUTONOMOUS_LINUX_TRANSPORT_MANIFEST_PATH",
  candidateLinuxTransportManifestSha256:
    "TI_SCALE_AUTONOMOUS_LINUX_TRANSPORT_MANIFEST_SHA256",
  candidateLinuxProcedureTrustRoot:
    "TI_SCALE_AUTONOMOUS_LINUX_PROCEDURE_TRUST_ROOT",
} as const);

type Environment = Readonly<Record<string, string | undefined>>;

export interface LoadedAutonomousDnsProductionConfiguration {
  readonly status: "loaded";
  readonly runtime: LoadedTrustedJson<AutonomousDnsRuntimeConfiguration>;
  /** Optional advisory inventory. The local process runtime never requires it. */
  readonly mcpConnection?: LoadedTrustedJson<McpServerConnectionConfig>;
  /** Concrete trusted local catalogue required by an enabled CVE phase. */
  readonly cveCandidateCatalog?: LoadedPinnedLocalCveCandidateCatalog;
  /** Root-owned exact-target confinement identities required by exploit validation. */
  readonly exploitSandboxManifest?: LoadedTrustedJson<ExactTargetSandboxActivationManifest>;
  /** Candidate-specific typed session/privilege bindings; never a generic command transport. */
  readonly candidateLinuxTransportManifest?:
    LoadedTrustedJson<CandidateLinuxTransportBindingManifest>;
  /** Reviewed source profile used to derive run-scoped typed candidate specs. */
  readonly candidateLinuxReviewedProfile?:
    LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>;
  /** Owner-controlled executable namespace populated only after plan binding. */
  readonly candidateLinuxProcedureTrustRoot?: string;
}

export interface UnconfiguredAutonomousDnsProductionConfiguration {
  readonly status: "unconfigured";
  readonly reason: string;
}

export type AutonomousDnsProductionConfiguration =
  | LoadedAutonomousDnsProductionConfiguration
  | UnconfiguredAutonomousDnsProductionConfiguration;

function value(environment: Environment, name: string): string | undefined {
  const configured = environment[name]?.trim();
  return configured ? configured : undefined;
}

function references(environment: Environment): Readonly<{
  runtime: TrustedJsonFileReference;
  mcpConnection?: TrustedJsonFileReference;
  cveCandidateCatalog?: TrustedJsonFileReference;
  exploitSandboxManifest?: TrustedJsonFileReference;
  candidateLinuxTransportManifest?: TrustedJsonFileReference;
  candidateLinuxProcedureTrustRoot?: string;
}> | undefined {
  const required = [
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.trustRoot,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationPath,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationSha256,
  ] as const;
  const advisory = [
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.mcpConnectionPath,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.mcpConnectionSha256,
  ] as const;
  const cveCatalog = [
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.cveCandidateCatalogPath,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.cveCandidateCatalogSha256,
  ] as const;
  const exploitSandbox = [
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxTrustRoot,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxManifestPath,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxManifestSha256,
  ] as const;
  const candidateLinuxTransport = [
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.candidateLinuxTransportTrustRoot,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.candidateLinuxTransportManifestPath,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.candidateLinuxTransportManifestSha256,
  ] as const;
  const names = [
    ...required,
    ...advisory,
    ...cveCatalog,
    ...exploitSandbox,
    ...candidateLinuxTransport,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.candidateLinuxProcedureTrustRoot,
  ];
  const configured = names.filter((name) => value(environment, name)).length;
  if (configured === 0) return undefined;
  const missingRequired = required.filter((name) => !value(environment, name));
  const advisoryCount = advisory.filter((name) => value(environment, name)).length;
  const cveCatalogCount = cveCatalog.filter((name) => value(environment, name)).length;
  const exploitSandboxCount = exploitSandbox
    .filter((name) => value(environment, name)).length;
  const candidateLinuxTransportCount = candidateLinuxTransport
    .filter((name) => value(environment, name)).length;
  if (missingRequired.length > 0 || advisoryCount === 1
    || cveCatalogCount === 1
    || (exploitSandboxCount > 0 && exploitSandboxCount < exploitSandbox.length)
    || (candidateLinuxTransportCount > 0
      && candidateLinuxTransportCount < candidateLinuxTransport.length)) {
    const missing = [
      ...missingRequired,
      ...(advisoryCount === 1 ? advisory.filter((name) => !value(environment, name)) : []),
      ...(cveCatalogCount === 1 ? cveCatalog.filter((name) => !value(environment, name)) : []),
      ...(exploitSandboxCount > 0 && exploitSandboxCount < exploitSandbox.length
        ? exploitSandbox.filter((name) => !value(environment, name))
        : []),
      ...(candidateLinuxTransportCount > 0
        && candidateLinuxTransportCount < candidateLinuxTransport.length
        ? candidateLinuxTransport.filter((name) => !value(environment, name))
        : []),
    ].sort();
    throw new Error(
      `Autonomous DNS production configuration is incomplete; missing ${missing.join(", ")}`,
    );
  }
  const trustRoot = value(
    environment,
    AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.trustRoot,
  )!;
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const allowedOwnerUids = currentUid === 0 ? [0] : [0, currentUid];
  const reference = (
    pathName: string,
    shaName: string,
    maximumBytes = 256 * 1_024,
  ): TrustedJsonFileReference => ({
    path: value(environment, pathName)!,
    trustRoot,
    expectedSha256: value(environment, shaName)!,
    allowedOwnerUids,
    maximumBytes,
  });
  return Object.freeze({
    runtime: reference(
      AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationPath,
      AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.runtimeConfigurationSha256,
    ),
    ...(advisoryCount === 2 ? {
      mcpConnection: reference(
        AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.mcpConnectionPath,
        AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.mcpConnectionSha256,
      ),
    } : {}),
    ...(cveCatalogCount === 2 ? {
      cveCandidateCatalog: reference(
        AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.cveCandidateCatalogPath,
        AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.cveCandidateCatalogSha256,
        8 * 1_024 * 1_024,
      ),
    } : {}),
    ...(exploitSandboxCount === exploitSandbox.length ? {
      exploitSandboxManifest: {
        path: value(
          environment,
          AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxManifestPath,
        )!,
        trustRoot: value(
          environment,
          AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxTrustRoot,
        )!,
        expectedSha256: value(
          environment,
          AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.exploitSandboxManifestSha256,
        )!,
        allowedOwnerUids: [0],
        maximumBytes: 32 * 1_024,
      },
    } : {}),
    ...(candidateLinuxTransportCount === candidateLinuxTransport.length ? {
      candidateLinuxTransportManifest: {
        path: value(
          environment,
          AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.candidateLinuxTransportManifestPath,
        )!,
        trustRoot: value(
          environment,
          AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.candidateLinuxTransportTrustRoot,
        )!,
        expectedSha256: value(
          environment,
          AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.candidateLinuxTransportManifestSha256,
        )!,
        allowedOwnerUids: [0],
        maximumBytes: 64 * 1024,
      },
    } : {}),
    ...(value(
      environment,
      AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.candidateLinuxProcedureTrustRoot,
    ) ? {
      candidateLinuxProcedureTrustRoot: resolve(value(
        environment,
        AUTONOMOUS_DNS_PRODUCTION_ENVIRONMENT.candidateLinuxProcedureTrustRoot,
      )!),
    } : {}),
  });
}

function assertExactAdvisoryMcpInventory(
  runtime: AutonomousDnsRuntimeConfiguration,
  connection: McpServerConnectionConfig,
): void {
  const advisory = runtime.mcp;
  const required = connection.toolInventory.requiredTools;
  const tool = required[0];
  if (
    !advisory
    || runtime.localProcess.adapterId !== AUTONOMOUS_DNS_SAFE_RECON_ADAPTER_ID
    || runtime.dns.mcpServerId !== advisory.id
    || connection.enabled !== true
    || connection.id !== advisory.id
    || connection.transport !== advisory.transport
    || connection.expectedServer.name !== advisory.serverName
    || connection.expectedServer.version !== advisory.serverVersion
    || hashMcpServerConnectionConfig(connection) !== advisory.configurationSha256
    || connection.toolInventory.allowAdditionalTools !== false
    || connection.toolInventory.minimumToolCount !== 1
    || required.length !== 1
    || tool?.name !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
    || tool.inputSchemaSha256 !== advisory.toolInputSchemaSha256
    || tool.annotations?.readOnlyHint !== true
    || tool.annotations.destructiveHint !== false
    || tool.annotations.idempotentHint !== true
  ) {
    throw new Error(
      "Autonomous DNS advisory MCP inventory does not match the exact reviewed server, schema, inventory, and read-only annotations",
    );
  }
}

/**
 * Loads the deployment-pinned local runtime document and, when configured,
 * an advisory MCP inventory document that never grants execution. This loader
 * performs no executable probe, network request, MCP initialization,
 * specialist heartbeat, or mission work.
 */
export function loadProductionAutonomousDnsConfiguration(
  environment: Environment = process.env,
): AutonomousDnsProductionConfiguration {
  const configured = references(environment);
  if (!configured) {
    return Object.freeze({
      status: "unconfigured",
      reason: "No complete deployment-pinned Autonomous DNS local runtime configuration is configured.",
    });
  }
  const runtime = loadTrustedAutonomousDnsRuntimeConfiguration(configured.runtime);
  const mcpConnection = configured.mcpConnection
    ? loadTrustedJson(configured.mcpConnection, parseMcpServerConnectionConfig)
    : undefined;
  if (mcpConnection) assertExactAdvisoryMcpInventory(runtime.value, mcpConnection.value);
  if (runtime.value.cveApplicability && !configured.cveCandidateCatalog) {
    throw new Error(
      "Autonomous CVE applicability requires a deployment-pinned local candidate catalogue path and SHA-256",
    );
  }
  if (!runtime.value.cveApplicability && configured.cveCandidateCatalog) {
    throw new Error(
      "A CVE candidate catalogue was configured without an enabled Autonomous CVE applicability phase",
    );
  }
  if (runtime.value.exploitValidation && !configured.exploitSandboxManifest) {
    throw new Error(
      "Autonomous exploit validation requires a root-owned, deployment-pinned exact-target sandbox activation manifest",
    );
  }
  if (!runtime.value.exploitValidation && configured.exploitSandboxManifest) {
    throw new Error(
      "An exact-target sandbox activation manifest was configured without an enabled Autonomous exploit-validation phase",
    );
  }
  if (configured.candidateLinuxTransportManifest
    && !runtime.value.exploitValidation) {
    throw new Error(
      "A candidate Linux transport manifest was configured without an enabled Autonomous exploit-validation phase",
    );
  }
  const cveCandidateCatalog = runtime.value.cveApplicability && configured.cveCandidateCatalog
    ? loadPinnedLocalAuthoritativeCveCandidateCatalog(configured.cveCandidateCatalog, {
        catalogId: runtime.value.cveApplicability.catalogId,
        catalogSnapshotSha256: runtime.value.cveApplicability.catalogSnapshotSha256,
        maximumCandidatesPerProduct:
          runtime.value.cveApplicability.maximumCandidatesPerProduct,
      })
    : undefined;
  const exploitSandboxManifest =
    runtime.value.exploitValidation && configured.exploitSandboxManifest
      ? loadTrustedExactTargetSandboxActivationManifest(
          configured.exploitSandboxManifest,
        )
      : undefined;
  const candidateLinuxTransportManifest =
    runtime.value.exploitValidation && configured.candidateLinuxTransportManifest
      ? loadTrustedCandidateLinuxTransportBindingManifest(
          configured.candidateLinuxTransportManifest,
        )
      : undefined;
  const reviewedBindings = candidateLinuxTransportManifest?.value.bindings
    .filter(({ candidateClass }) =>
      candidateClass === "reviewed_real_candidate_v1") ?? [];
  if (reviewedBindings.length > 1) {
    throw new Error(
      "Autonomous Linux transport may expose only one reviewed real-candidate source profile",
    );
  }
  if (
    reviewedBindings.length === 1
    && !configured.candidateLinuxProcedureTrustRoot
  ) {
    throw new Error(
      "Reviewed real-candidate Linux transport requires a run-scoped procedure trust root",
    );
  }
  if (
    configured.candidateLinuxProcedureTrustRoot
    && (
      !isAbsolute(configured.candidateLinuxProcedureTrustRoot)
      || configured.candidateLinuxProcedureTrustRoot === resolve("/")
    )
  ) {
    throw new Error(
      "Autonomous Linux procedure trust root must be one non-root absolute path",
    );
  }
  const reviewedBinding = reviewedBindings[0];
  const candidateLinuxReviewedProfile = reviewedBinding
    && candidateLinuxTransportManifest
    ? loadTrustedReviewedRealCandidateLinuxProfile({
        path: reviewedBinding.handlerProfilePath,
        trustRoot: candidateLinuxTransportManifest.receipt.trustRoot,
        expectedSha256: reviewedBinding.handlerProfileSha256,
        allowedOwnerUids:
          candidateLinuxTransportManifest.receipt.ownerUid === 0
            ? [0]
            : [0, candidateLinuxTransportManifest.receipt.ownerUid],
        maximumBytes: 64 * 1_024,
      })
    : undefined;
  if (
    reviewedBinding
    && (
      !candidateLinuxReviewedProfile
      || candidateLinuxReviewedProfile.value.bindingId
        !== reviewedBinding.bindingId
      || candidateLinuxReviewedProfile.value.postExploitSpec.id
        !== reviewedBinding.postExploitSpecId
      || candidateLinuxReviewedProfile.value.postExploitSpec.expectedSha256
        !== reviewedBinding.postExploitSpecSha256
    )
  ) {
    throw new Error(
      "Reviewed real-candidate source profile differs from its transport manifest binding",
    );
  }
  return Object.freeze({
    status: "loaded",
    runtime,
    ...(mcpConnection ? { mcpConnection } : {}),
    ...(cveCandidateCatalog ? { cveCandidateCatalog } : {}),
    ...(exploitSandboxManifest ? { exploitSandboxManifest } : {}),
    ...(candidateLinuxTransportManifest
      ? { candidateLinuxTransportManifest }
      : {}),
    ...(candidateLinuxReviewedProfile
      ? { candidateLinuxReviewedProfile }
      : {}),
    ...(configured.candidateLinuxProcedureTrustRoot
      ? {
          candidateLinuxProcedureTrustRoot:
            configured.candidateLinuxProcedureTrustRoot,
        }
      : {}),
  });
}
