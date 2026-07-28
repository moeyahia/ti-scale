import type { ActionClassId, EvidenceTypeId, Journey } from "../domain";
import type { ToolBindingReadinessSnapshot } from "../system-capabilities";

export const WEB_ASSESSMENT_TOOL_PACK_SCHEMA_VERSION =
  "ti-scale.web-assessment-tool-pack.v1" as const;
export const WEB_ASSESSMENT_INVOCATION_SCHEMA_VERSION =
  "ti-scale.web-assessment-invocation.v1" as const;
export const WEB_ASSESSMENT_PROBE_RECEIPT_SCHEMA_VERSION =
  "ti-scale.web-assessment-probe-receipt.v1" as const;

export const WEB_ASSESSMENT_TOOL_IDS = [
  "kali:whatweb-bounded-fingerprint",
  "kali:ffuf-bounded-content-discovery",
  "kali:httpx-python-client-held",
  "kali:gobuster-held",
  "kali:nikto-held",
  "kali:nuclei-held",
] as const;

export type WebAssessmentToolId = (typeof WEB_ASSESSMENT_TOOL_IDS)[number];
export type ReviewedWebAssessmentToolId = Extract<
  WebAssessmentToolId,
  "kali:whatweb-bounded-fingerprint" | "kali:ffuf-bounded-content-discovery"
>;

export interface ReviewedFileBinding {
  readonly path: string;
  readonly expectedSha256: string;
  readonly executable: boolean;
}

export interface WebAssessmentToolDefinition {
  readonly toolId: WebAssessmentToolId;
  readonly label: string;
  readonly purpose: string;
  readonly activation: "reviewed_guided" | "held";
  readonly activationReason: string | null;
  readonly defaultPolicyState: "guided_only";
  readonly autonomousExecution: "not_authorized";
  readonly actionClassId: ActionClassId;
  readonly evidenceTypeIds: readonly EvidenceTypeId[];
  readonly executable: ReviewedFileBinding;
  readonly dependencies: readonly ReviewedFileBinding[];
  readonly probe: Readonly<{
    readonly arguments: readonly string[];
    readonly expectedExitCodes: readonly number[];
    readonly timeoutMs: number;
    readonly maximumOutputBytes: number;
    readonly targetContact: false;
  }>;
  readonly execution: Readonly<{
    readonly transport: "bubblewrap_direct_argv";
    readonly shell: false;
    readonly targetBinding: "exact_canonical_mission_url";
    readonly redirectPolicy: "never";
    readonly workspacePolicy: "resolved_workspace_only";
    readonly maximumConcurrentInvocationsPerRun: 1;
    readonly requestConcurrency: number;
    readonly maximumRequests: number;
    readonly maximumRequestRatePerSecond: number;
    readonly timeoutMs: number;
    readonly terminationGraceMs: number;
    readonly maximumOutputBytes: number;
  }>;
}

export interface WebAssessmentDispatchAuthorizationReceipt {
  readonly schemaVersion: "ti-scale.web-assessment-dispatch-authorization.v1";
  readonly invocationId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly actionId: string;
  readonly toolId: ReviewedWebAssessmentToolId;
  readonly representedActionFingerprint: string;
  readonly canonicalTargetUrl: string;
  readonly logicalWorkspace: string;
  readonly authorizationVerified: true;
  readonly exactGuidedDecisionVerified: true;
  readonly actionClassAllowed: true;
  readonly grantsScopeExpansion: false;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface WebAssessmentAdapterReadinessReceipt {
  readonly schemaVersion: "ti-scale.web-assessment-adapter-readiness.v1";
  readonly adapterId: "ti-scale:reviewed-web-assessment-process";
  readonly packSha256: string;
  readonly registrySha256: string;
  readonly runtimeManifestSha256: string;
  readonly readyToolIds: readonly ReviewedWebAssessmentToolId[];
  readonly blockers: readonly Readonly<{
    readonly toolId: WebAssessmentToolId | "sandbox:bubblewrap";
    readonly code: string;
    readonly explanation: string;
    readonly remediation: string;
  }>[];
  readonly boundary: Readonly<{
    readonly directArgv: true;
    readonly shell: false;
    readonly exactTargetBinding: true;
    readonly workspaceConfinement: true;
    readonly immutableExecutableSnapshot: true;
    readonly fixedDictionaryStaging: true;
    readonly boundedOutput: true;
    readonly boundedRuntime: true;
    readonly cooperativeCancellation: true;
    readonly resultNormalization: true;
    readonly targetContactDuringReadiness: false;
  }>;
  readonly observedAt: string;
  readonly expiresAt: string;
  readonly grantsMissionExecution: false;
}

export interface WebAssessmentActivationSnapshot {
  readonly schemaVersion: "ti-scale.web-assessment-activation.v1";
  readonly packSha256: string;
  readonly checkedAt: string;
  readonly status: "ready" | "unavailable";
  readonly readyToolIds: readonly ReviewedWebAssessmentToolId[];
  readonly tools: readonly Readonly<{
    readonly toolId: WebAssessmentToolId;
    readonly state: "ready" | "unavailable" | "held";
    readonly reason: string;
    readonly remediation: string | null;
  }>[];
  readonly toolBindingReadiness: ToolBindingReadinessSnapshot;
  readonly adapterReadiness: WebAssessmentAdapterReadinessReceipt;
  readonly grantsMissionExecution: false;
}

export interface WebAssessmentToolPackDocument {
  readonly schemaVersion: typeof WEB_ASSESSMENT_TOOL_PACK_SCHEMA_VERSION;
  readonly packVersion: string;
  readonly specialist: Readonly<{
    readonly id: "specialist:web-assessment";
    readonly label: "Web assessment specialist";
  }>;
  readonly tools: readonly WebAssessmentToolDefinition[];
}

export interface WebAssessmentActionIdentity {
  readonly missionId: string;
  readonly runId: string;
  readonly actionId: string;
  readonly toolId: ReviewedWebAssessmentToolId;
  readonly canonicalMissionTarget: string;
  readonly requestedUrl: string;
  readonly logicalWorkspace: string;
  readonly profile: "bounded_standard";
}

export interface CompileGuidedWebAssessmentInvocationInput
  extends WebAssessmentActionIdentity {
  readonly invocationId: string;
  readonly journey: Journey;
  readonly authorizationVerified: boolean;
  readonly actionClassAllowed: boolean;
  readonly representedActionFingerprint: string;
  readonly guidedDecisionStatus: "approved" | "pending" | "rejected" | "expired";
}

export interface CompiledWebAssessmentInvocation {
  readonly schemaVersion: typeof WEB_ASSESSMENT_INVOCATION_SCHEMA_VERSION;
  readonly invocationId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly actionId: string;
  readonly toolId: ReviewedWebAssessmentToolId;
  readonly actionClassId: ActionClassId;
  readonly targetUrl: string;
  readonly targetOrigin: string;
  readonly logicalWorkspace: string;
  readonly arguments: readonly string[];
  readonly stagedInput: Readonly<{
    readonly kind: "none" | "fixed_path_dictionary";
    readonly mountPath: string | null;
    readonly lines: readonly string[];
  }>;
  readonly representedActionFingerprint: string;
  readonly shell: false;
  readonly authorizationGrantedByCompiler: false;
  readonly journey: "guided";
  readonly budget: WebAssessmentToolDefinition["execution"];
}

export type WebAssessmentFailureCategory =
  | "policy_denied"
  | "invalid_input"
  | "dependency_missing"
  | "timeout"
  | "operator_rejection"
  | "deterministic_tool_error"
  | "transient_network"
  | "unknown";

export interface WebAssessmentFailureDiagnosis {
  readonly code: string;
  readonly category: WebAssessmentFailureCategory;
  readonly humanReason: string;
  readonly retryable: boolean;
  readonly originatingComponent: "web_assessment_compiler" | "web_assessment_process_runner";
  readonly remediation: string;
}

export interface WebAssessmentEngagementLog {
  readonly stage: "engagement_log";
  readonly toolId: ReviewedWebAssessmentToolId;
  readonly targetUrl: string;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly outputSha256: string;
  readonly outputTruncated: boolean;
}

export interface WebAssessmentObservation {
  readonly stage: "observation";
  readonly observationType: "web_technology_fingerprint" | "web_endpoint_discovery";
  readonly statement: string;
  readonly targetUrl: string;
  readonly confidence: number;
  readonly sourceToolId: ReviewedWebAssessmentToolId;
  readonly normalizedValue: Readonly<Record<string, unknown>>;
  readonly verified: false;
}

export interface WebAssessmentExecutionResult {
  readonly status: "completed" | "failed" | "cancelled";
  readonly invocation: CompiledWebAssessmentInvocation;
  readonly engagementLog: WebAssessmentEngagementLog | null;
  readonly observations: readonly WebAssessmentObservation[];
  /** Web scanner output is never evidence merely because a process printed it. */
  readonly evidenceCandidates: readonly [];
  readonly verifiedEvidence: readonly [];
  readonly diagnosis: WebAssessmentFailureDiagnosis | null;
}

export interface WebAssessmentProcessAdapterOptions {
  readonly sandboxExecutable: Readonly<{
    readonly path: string;
    readonly expectedSha256: string;
  }>;
  readonly now?: () => Date;
}

export interface WebAssessmentProbeReceipt {
  readonly schemaVersion: typeof WEB_ASSESSMENT_PROBE_RECEIPT_SCHEMA_VERSION;
  readonly toolId: WebAssessmentToolId;
  readonly installationReady: boolean;
  readonly probeReady: boolean;
  readonly observedExecutableSha256: string | null;
  readonly expectedExecutableSha256: string;
  readonly targetContact: false;
  readonly observedAt: string;
  readonly failureCode: string | null;
}
