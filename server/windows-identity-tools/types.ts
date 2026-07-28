import type {
  ActionIntent,
  AutonomousContractBoundary,
  FailureCategory,
  GuidedDecision,
} from "../supervisor";

export const WINDOWS_IDENTITY_TOOL_PACK_SCHEMA_VERSION =
  "ti-scale.windows-identity-tool-pack.v1" as const;
export const WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION =
  "ti-scale.windows-identity-action.v1" as const;
export const WINDOWS_IDENTITY_READINESS_SCHEMA_VERSION =
  "ti-scale.windows-identity-readiness.v1" as const;
export const WINDOWS_IDENTITY_RESULT_SCHEMA_VERSION =
  "ti-scale.windows-identity-result.v1" as const;
export const WINDOWS_IDENTITY_EXECUTION_RECEIPT_SCHEMA_VERSION =
  "ti-scale.windows-identity-execution-receipt.v1" as const;
export const WINDOWS_IDENTITY_NORMALIZATION_SCHEMA_VERSION =
  "ti-scale.windows-identity-normalization.v1" as const;

export const WINDOWS_IDENTITY_TOOL_IDS = [
  "kali:smbclient-share-list",
  "kali:nxc-smb-summary",
  "kali:ldapsearch-root-dse",
  "kali:rpcclient-domain-info",
] as const;

export type WindowsIdentityToolId = (typeof WINDOWS_IDENTITY_TOOL_IDS)[number];

export const WINDOWS_IDENTITY_OPERATIONS = [
  "smb_share_list",
  "smb_identity_summary",
  "ldap_root_dse",
  "rpc_domain_info",
] as const;

export type WindowsIdentityOperation = (typeof WINDOWS_IDENTITY_OPERATIONS)[number];

export type WindowsIdentityAuthenticationMode = "anonymous" | "credential_reference";

export interface WindowsIdentityToolDefinition {
  readonly toolId: WindowsIdentityToolId;
  readonly operation: WindowsIdentityOperation;
  readonly label: string;
  readonly executable: Readonly<{
    path: string;
    sha256: string;
    ownerUid: 0;
    fileCapabilities: "none";
  }>;
  readonly probe: Readonly<{
    arguments: readonly string[];
    expectedExitCodes: readonly number[];
    timeoutMs: number;
    maximumOutputBytes: number;
    ttlMs: number;
    targetContact: false;
  }>;
  readonly actionClassId: "active_directory_identity_operations";
  readonly evidenceTypeId: "identity_ad_graph";
  readonly journeyPolicy: "guided_only";
  readonly authenticationModes: readonly WindowsIdentityAuthenticationMode[];
  readonly execution: Readonly<{
    directArgv: true;
    shell: false;
    readOnlyTargetOperation: true;
    timeoutMs: number;
    maximumOutputBytes: number;
    terminationGraceMs: number;
    maximumConcurrency: 1;
    workspaceWrites: "sandbox_workspace_only";
    credentialDelivery: "opaque_reference_to_private_files";
  }>;
}

export interface WindowsIdentityCredentialReference {
  readonly kind: "systemd_credential_bundle";
  readonly id: string;
}

/**
 * Attests that an execution adapter can resolve one opaque reference into
 * private, read-only files. It deliberately contains no username, password,
 * hash, ticket, certificate, or other reusable authentication material.
 */
export interface WindowsIdentityCredentialBindingReceipt {
  readonly schemaVersion: "ti-scale.windows-identity-credential-binding.v1";
  readonly referenceId: string;
  readonly runId: string;
  readonly actionFingerprint: string;
  readonly availableViews: readonly WindowsIdentityCredentialView[];
  readonly mountedReadOnly: true;
  readonly privateToProcess: true;
  readonly expiresAt: string;
  readonly grantsAuthorization: false;
}

export interface WindowsIdentityActionRequest {
  readonly schemaVersion: typeof WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION;
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string;
  readonly planVersion: number;
  readonly journey: "autonomous" | "guided";
  readonly operation: WindowsIdentityOperation;
  readonly target: string;
  readonly logicalWorkspace: string;
  readonly authenticationMode: WindowsIdentityAuthenticationMode;
  readonly credentialReference: WindowsIdentityCredentialReference | null;
}

export interface WindowsIdentityMissionBoundary {
  readonly authorizationVerified: boolean;
  readonly allowedTargets: readonly string[];
  readonly prohibitedTargets: readonly string[];
  readonly allowedActionClassIds: readonly string[];
  readonly prohibitedActionClassIds: readonly string[];
  readonly guidedDecision: GuidedDecision | null;
  readonly autonomousContract?: AutonomousContractBoundary | null;
}

export interface CompiledWindowsIdentityInvocation {
  readonly schemaVersion: "ti-scale.windows-identity-invocation.v1";
  readonly journey: "autonomous" | "guided";
  readonly toolId: WindowsIdentityToolId;
  readonly operation: WindowsIdentityOperation;
  readonly action: Readonly<ActionIntent>;
  readonly actionFingerprint: string;
  readonly target: string;
  readonly logicalWorkspace: string;
  readonly executablePath: string;
  readonly executableSha256: string;
  readonly arguments: readonly string[];
  readonly environment: Readonly<{
    HOME: "/workspace/.tool-state";
    XDG_CACHE_HOME: "/workspace/.tool-state/cache";
    XDG_CONFIG_HOME: "/workspace/.tool-state/config";
    XDG_DATA_HOME: "/workspace/.tool-state/data";
    LANG: "C.UTF-8";
    LC_ALL: "C.UTF-8";
  }>;
  readonly credentialReference: WindowsIdentityCredentialReference | null;
  readonly credentialBindingReceipt: WindowsIdentityCredentialBindingReceipt | null;
  readonly timeoutMs: number;
  readonly maximumOutputBytes: number;
  readonly terminationGraceMs: number;
  readonly directArgv: true;
  readonly shell: false;
  readonly targetReadOnly: true;
  readonly evidencePromotion: "none";
}

export interface WindowsIdentityToolReadinessReceipt {
  readonly schemaVersion: typeof WINDOWS_IDENTITY_READINESS_SCHEMA_VERSION;
  readonly toolId: WindowsIdentityToolId;
  readonly executablePath: string;
  readonly expectedExecutableSha256: string;
  readonly observedExecutableSha256: string | null;
  readonly registryBindingSha256: string;
  readonly preflightBindingSha256: string | null;
  readonly status: "ready" | "unavailable";
  readonly code: WindowsIdentityFailureCode | "ready";
  readonly directArgv: true;
  readonly shell: false;
  readonly targetContact: false;
  readonly workspaceConfinementReady: boolean;
  readonly credentialIsolationReady: boolean;
  readonly outputBoundReady: boolean;
  readonly cancellationReady: boolean;
  readonly explanation: string;
  readonly remediation: string | null;
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly grantsMissionExecution: false;
}

export interface WindowsIdentityRawResult {
  readonly schemaVersion: typeof WINDOWS_IDENTITY_RESULT_SCHEMA_VERSION;
  readonly toolId: WindowsIdentityToolId;
  readonly actionFingerprint: string;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly observedOutputBytes: number;
  readonly retainedOutputBytes: number;
  readonly outputSha256: string;
  readonly outputTruncated: boolean;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly receipt: WindowsIdentityExecutionReceipt;
}

export interface WindowsIdentityExecutionReceipt {
  readonly schemaVersion: typeof WINDOWS_IDENTITY_EXECUTION_RECEIPT_SCHEMA_VERSION;
  readonly adapterId: string;
  readonly toolId: WindowsIdentityToolId;
  readonly actionFingerprint: string;
  readonly runId: string;
  readonly executableSha256: string;
  readonly sandboxExecutableSha256: string;
  readonly logicalWorkspace: string;
  readonly credentialReferenceId: string | null;
  readonly directArgv: true;
  readonly shell: false;
  readonly targetReadOnly: true;
  readonly workspaceConfined: true;
  readonly credentialsMountedReadOnly: true;
  readonly outputRedacted: true;
  readonly outputSha256: string;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly wallClockMs: number;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
  readonly outputTruncated: boolean;
  readonly grantsAuthorization: false;
}

export type WindowsIdentityObservationType =
  | "smb_share"
  | "smb_host_identity"
  | "ldap_directory_metadata"
  | "rpc_domain_metadata";

export interface WindowsIdentityObservation {
  readonly type: WindowsIdentityObservationType;
  readonly statement: string;
  readonly normalizedValue: Readonly<Record<string, string | number | boolean | null>>;
  readonly confidence: number;
  readonly sourceToolId: WindowsIdentityToolId;
  readonly verified: false;
}

export interface WindowsIdentityNormalizedResult {
  readonly schemaVersion: typeof WINDOWS_IDENTITY_NORMALIZATION_SCHEMA_VERSION;
  readonly stage: "engagement_log_and_observations";
  readonly toolId: WindowsIdentityToolId;
  readonly actionFingerprint: string;
  readonly status: "completed" | "failed" | "cancelled";
  readonly summary: string;
  readonly observations: readonly WindowsIdentityObservation[];
  readonly engagementLog: Readonly<{
    readonly stdout: string;
    readonly stderr: string;
    readonly outputSha256: string;
    readonly outputTruncated: boolean;
  }>;
  readonly evidenceCandidates: readonly [];
  readonly verifiedEvidence: readonly [];
  readonly failure: WindowsIdentityFailureDefinition | null;
}

export type WindowsIdentityCredentialView =
  | "samba_auth_file"
  | "username_file"
  | "password_file"
  | "ldap_bind_identity";

export interface WindowsIdentityCredentialMaterialBinding {
  readonly receipt: WindowsIdentityCredentialBindingReceipt;
  /** Host paths are adapter-private and never included in execution receipts or logs. */
  readonly files: Readonly<Partial<Record<WindowsIdentityCredentialView, string>>>;
}

export interface WindowsIdentityCredentialMaterialResolver {
  /** Target-free proof that the configured private root is currently usable. */
  readiness?(): Promise<boolean>;
  resolve(input: Readonly<{
    reference: WindowsIdentityCredentialReference;
    runId: string;
    actionFingerprint: string;
    requiredViews: readonly WindowsIdentityCredentialView[];
  }>): Promise<WindowsIdentityCredentialMaterialBinding>;
}

export interface WindowsIdentityExecutionAdapter {
  readonly adapterId: string;
  readiness(toolId: WindowsIdentityToolId): WindowsIdentityToolReadinessReceipt | null;
  execute(
    invocation: CompiledWindowsIdentityInvocation,
    signal: AbortSignal,
  ): Promise<WindowsIdentityRawResult>;
  cancelRun(runId: string, reason: string): Promise<void>;
}

export const WINDOWS_IDENTITY_FAILURE_CODES = [
  "windows_identity_request_invalid",
  "windows_identity_target_not_canonical",
  "windows_identity_target_outside_scope",
  "windows_identity_authorization_unverified",
  "windows_identity_action_class_denied",
  "windows_identity_autonomous_not_approved",
  "windows_identity_guided_decision_required",
  "windows_identity_guided_action_changed",
  "windows_identity_credential_reference_invalid",
  "windows_identity_credential_binding_missing",
  "windows_identity_credential_binding_changed",
  "windows_identity_credential_binding_expired",
  "windows_identity_tool_unavailable",
  "windows_identity_tool_identity_changed",
  "windows_identity_workspace_not_confined",
  "windows_identity_adapter_not_bounded",
  "windows_identity_concurrency_exhausted",
  "windows_identity_cancelled",
  "windows_identity_timed_out",
  "windows_identity_output_limit",
  "windows_identity_authentication_rejected",
  "windows_identity_target_unreachable",
  "windows_identity_tool_deterministic_error",
] as const;

export type WindowsIdentityFailureCode = (typeof WINDOWS_IDENTITY_FAILURE_CODES)[number];

export interface WindowsIdentityFailureDefinition {
  readonly code: WindowsIdentityFailureCode;
  readonly category: FailureCategory;
  readonly retryable: boolean;
  readonly humanMessage: string;
}

export class WindowsIdentityBoundaryError extends Error {
  readonly retryable: boolean;

  constructor(
    readonly code: WindowsIdentityFailureCode,
    readonly category: FailureCategory,
    message: string,
    retryable = false,
  ) {
    super(message);
    this.name = "WindowsIdentityBoundaryError";
    this.retryable = retryable;
  }
}
