import type {
  BubblewrapProbeSandboxDescriptor,
  LocalToolCapabilityManifest,
} from "../local-tools";
import {
  loadTrustedBubblewrapProbeSandboxDescriptor,
  loadTrustedLocalToolCapabilityManifest,
} from "../local-tools";
import type {
  EngagementWorkspaceMappingsDocument,
  TrustedJsonFileReference,
  TrustedLocalFileReceipt,
} from "../trusted-runtime-config";
import { loadTrustedEngagementWorkspaceMappings } from "../trusted-runtime-config";
import { composeReviewedWebAssessmentLocalManifest } from "../web-assessment-tools";

export const LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT = Object.freeze({
  trustRoot: "TI_SCALE_LOCAL_TOOL_TRUSTED_CONFIG_ROOT",
  capabilityManifestPath: "TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_PATH",
  capabilityManifestSha256: "TI_SCALE_LOCAL_TOOL_CAPABILITY_MANIFEST_SHA256",
  probeSandboxPath: "TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_PATH",
  probeSandboxSha256: "TI_SCALE_LOCAL_TOOL_PROBE_SANDBOX_SHA256",
  workspaceMappingsPath: "TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_PATH",
  workspaceMappingsSha256: "TI_SCALE_LOCAL_TOOL_WORKSPACE_MAPPINGS_SHA256",
} as const);
export const REVIEWED_WEB_ASSESSMENT_CONFIGURATION_ENVIRONMENT =
  "TI_SCALE_REVIEWED_WEB_ASSESSMENT_ENABLED" as const;

type Environment = Readonly<Record<string, string | undefined>>;

export interface LoadedLocalGuidedToolConfiguration {
  readonly status: "loaded";
  readonly manifest: LocalToolCapabilityManifest;
  readonly webAssessmentIncluded?: boolean;
  readonly probeSandbox: BubblewrapProbeSandboxDescriptor;
  readonly workspaceMappings: EngagementWorkspaceMappingsDocument;
  readonly receipts: Readonly<{
    capabilityManifest: TrustedLocalFileReceipt;
    probeSandbox: TrustedLocalFileReceipt;
    workspaceMappings: TrustedLocalFileReceipt;
  }>;
}

export interface UnconfiguredLocalGuidedToolConfiguration {
  readonly status: "unconfigured";
  readonly reason: string;
}

export type ProductionLocalGuidedToolConfiguration =
  | LoadedLocalGuidedToolConfiguration
  | UnconfiguredLocalGuidedToolConfiguration;

function trimmed(environment: Environment, name: string): string | undefined {
  const value = environment[name]?.trim();
  return value ? value : undefined;
}

function references(environment: Environment): Readonly<{
  capabilityManifest: TrustedJsonFileReference;
  probeSandbox: TrustedJsonFileReference;
  workspaceMappings: TrustedJsonFileReference;
}> | undefined {
  const names = Object.values(LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT);
  const configured = names.filter((name) => trimmed(environment, name)).length;
  if (configured === 0) return undefined;
  if (configured !== names.length) {
    const missing = names
      .filter((name) => !trimmed(environment, name))
      .sort();
    throw new Error(
      `Reviewed local Guided tool configuration is incomplete; missing ${missing.join(", ")}`,
    );
  }
  const trustRoot = trimmed(
    environment,
    LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.trustRoot,
  )!;
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const allowedOwnerUids = currentUid === 0 ? [0] : [0, currentUid];
  const reference = (pathName: string, shaName: string): TrustedJsonFileReference => ({
    path: trimmed(environment, pathName)!,
    trustRoot,
    expectedSha256: trimmed(environment, shaName)!,
    allowedOwnerUids,
  });
  return Object.freeze({
    capabilityManifest: reference(
      LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestPath,
      LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.capabilityManifestSha256,
    ),
    probeSandbox: reference(
      LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxPath,
      LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.probeSandboxSha256,
    ),
    workspaceMappings: reference(
      LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsPath,
      LOCAL_GUIDED_TOOL_CONFIGURATION_ENVIRONMENT.workspaceMappingsSha256,
    ),
  });
}

/**
 * Loads one complete, immutable local Guided execution configuration. Loading
 * these operator-reviewed documents performs no executable probe, creates no
 * workspace, mounts no adapter, contacts no target, and grants no authority.
 */
export function loadProductionLocalGuidedToolConfiguration(
  environment: Environment = process.env,
): ProductionLocalGuidedToolConfiguration {
  const configured = references(environment);
  if (!configured) {
    return Object.freeze({
      status: "unconfigured",
      reason: "No complete deployment-pinned local Guided tool configuration is configured.",
    });
  }
  const loadedManifest = loadTrustedLocalToolCapabilityManifest(configured.capabilityManifest);
  const webAssessmentValue = environment[REVIEWED_WEB_ASSESSMENT_CONFIGURATION_ENVIRONMENT]?.trim();
  if (webAssessmentValue !== undefined
    && webAssessmentValue !== "true"
    && webAssessmentValue !== "false") {
    throw new Error(`${REVIEWED_WEB_ASSESSMENT_CONFIGURATION_ENVIRONMENT} must be true or false`);
  }
  const webAssessmentIncluded = webAssessmentValue === "true";
  const manifest = webAssessmentIncluded
    ? composeReviewedWebAssessmentLocalManifest(loadedManifest.value)
    : loadedManifest.value;
  const probeSandbox = loadTrustedBubblewrapProbeSandboxDescriptor(configured.probeSandbox);
  const workspaceMappings = loadTrustedEngagementWorkspaceMappings(configured.workspaceMappings);
  return Object.freeze({
    status: "loaded",
    manifest,
    webAssessmentIncluded,
    probeSandbox: probeSandbox.value,
    workspaceMappings: workspaceMappings.value,
    receipts: Object.freeze({
      capabilityManifest: loadedManifest.receipt,
      probeSandbox: probeSandbox.receipt,
      workspaceMappings: workspaceMappings.receipt,
    }),
  });
}
