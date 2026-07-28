import { isIP } from "node:net";
import { enforceJourneyActionBoundary, fingerprintAction, type ActionIntent } from "../supervisor";
import { LDAPSEARCH_ROOT_DSE_DEFINITION } from "./definitions/ldap";
import { NXC_SMB_SUMMARY_DEFINITION } from "./definitions/netexec";
import { RPCCLIENT_DOMAIN_INFO_DEFINITION } from "./definitions/rpc";
import { SMBCLIENT_SHARE_LIST_DEFINITION } from "./definitions/samba";
import { windowsIdentityFailure } from "./failureTaxonomy";
import {
  WINDOWS_IDENTITY_TOOL_PACK_SCHEMA_VERSION,
  WindowsIdentityBoundaryError,
  type CompiledWindowsIdentityInvocation,
  type WindowsIdentityActionRequest,
  type WindowsIdentityCredentialBindingReceipt,
  type WindowsIdentityMissionBoundary,
  type WindowsIdentityOperation,
  type WindowsIdentityToolDefinition,
  type WindowsIdentityToolId,
} from "./types";
import { canonicalWindowsIdentityTarget, parseWindowsIdentityActionRequest } from "./validation";

const FIXED_CREDENTIAL_PATHS = Object.freeze({
  sambaAuth: "/run/ti-scale/credential/samba-auth",
  username: "/run/ti-scale/credential/username",
  password: "/run/ti-scale/credential/password",
} as const);

const FIXED_ENVIRONMENT: CompiledWindowsIdentityInvocation["environment"] = Object.freeze({
  HOME: "/workspace/.tool-state",
  XDG_CACHE_HOME: "/workspace/.tool-state/cache",
  XDG_CONFIG_HOME: "/workspace/.tool-state/config",
  XDG_DATA_HOME: "/workspace/.tool-state/data",
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
});

const DEFINITIONS: readonly WindowsIdentityToolDefinition[] = Object.freeze([
  SMBCLIENT_SHARE_LIST_DEFINITION,
  NXC_SMB_SUMMARY_DEFINITION,
  LDAPSEARCH_ROOT_DSE_DEFINITION,
  RPCCLIENT_DOMAIN_INFO_DEFINITION,
]);

const SECRET_VALUE = /(?:\b(?:password|passwd|secret|token|hash|ticket|cookie|private.?key)\s*[:=]|-----BEGIN|\b(?:sk|rk|pk)-[A-Za-z0-9_-]{8,})/iu;

function sameStringArray(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameCredentialReference(
  left: CompiledWindowsIdentityInvocation["credentialReference"],
  right: CompiledWindowsIdentityInvocation["credentialReference"],
): boolean {
  return left === null
    ? right === null
    : right !== null && left.kind === right.kind && left.id === right.id;
}

function exactRecordKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function boundary(code: Parameters<typeof windowsIdentityFailure>[0]): never {
  const failure = windowsIdentityFailure(code);
  throw new WindowsIdentityBoundaryError(
    failure.code,
    failure.category,
    failure.humanMessage,
    failure.retryable,
  );
}

function ldapUri(target: string): string {
  return `ldap://${isIP(target) === 6 ? `[${target}]` : target}:389`;
}

function argv(
  definition: WindowsIdentityToolDefinition,
  request: WindowsIdentityActionRequest,
): readonly string[] {
  const authenticated = request.authenticationMode === "credential_reference";
  switch (definition.operation) {
    case "smb_share_list":
      return Object.freeze([
        "--debuglevel=0",
        "--grepable",
        "--timeout=5",
        "--port=445",
        "--use-kerberos=off",
        "--client-protection=sign",
        "--log-basename=/workspace/.tool-state/samba",
        ...(authenticated
          ? [`--authentication-file=${FIXED_CREDENTIAL_PATHS.sambaAuth}`]
          : ["--no-pass"]),
        `--list=${request.target}`,
      ]);
    case "smb_identity_summary":
      return Object.freeze([
        "smb",
        request.target,
        "--threads", "1",
        "--timeout", "5",
        "--smb-timeout", "5",
        "--dns-timeout", "3",
        "--no-progress",
        "--no-smbv1",
        "--no-admin-check",
        "--shares",
        "--no-write-check",
        "--no-bruteforce",
        "--gfail-limit", "1",
        "--ufail-limit", "1",
        "--fail-limit", "1",
        "-u", FIXED_CREDENTIAL_PATHS.username,
        "-p", FIXED_CREDENTIAL_PATHS.password,
      ]);
    case "ldap_root_dse":
      return Object.freeze([
        "-x",
        "-LLL",
        "-H", ldapUri(request.target),
        "-s", "base",
        "-b", "",
        "-l", "5",
        "-z", "20",
        "(objectClass=*)",
        "defaultNamingContext",
        "rootDomainNamingContext",
        "configurationNamingContext",
        "schemaNamingContext",
        "dnsHostName",
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
      ]);
    case "rpc_domain_info":
      return Object.freeze([
        "--debuglevel=0",
        "--port=445",
        "--use-kerberos=off",
        "--client-protection=sign",
        "--log-basename=/workspace/.tool-state/samba",
        ...(authenticated
          ? [`--authentication-file=${FIXED_CREDENTIAL_PATHS.sambaAuth}`]
          : ["--no-pass"]),
        "--command=querydominfo",
        request.target,
      ]);
  }
}

function requiredViews(operation: WindowsIdentityOperation): readonly string[] {
  return operation === "smb_identity_summary"
    ? ["username_file", "password_file"]
    : ["samba_auth_file"];
}

function credentialReceipt(
  request: WindowsIdentityActionRequest,
  actionFingerprint: string,
  receipt: WindowsIdentityCredentialBindingReceipt | null,
  now: Date,
): WindowsIdentityCredentialBindingReceipt | null {
  if (request.authenticationMode === "anonymous") return null;
  if (!receipt) boundary("windows_identity_credential_binding_missing");
  if (receipt.schemaVersion !== "ti-scale.windows-identity-credential-binding.v1"
    || receipt.referenceId !== request.credentialReference?.id
    || receipt.runId !== request.runId
    || receipt.actionFingerprint !== actionFingerprint
    || receipt.mountedReadOnly !== true
    || receipt.privateToProcess !== true
    || receipt.grantsAuthorization !== false
    || !requiredViews(request.operation).every((view) =>
      (receipt.availableViews as readonly string[]).includes(view))) {
    boundary("windows_identity_credential_binding_changed");
  }
  const expiresAt = Date.parse(receipt.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt <= now.getTime()) {
    boundary("windows_identity_credential_binding_expired");
  }
  return receipt;
}

export class WindowsIdentityToolPack {
  readonly schemaVersion = WINDOWS_IDENTITY_TOOL_PACK_SCHEMA_VERSION;
  readonly definitions = DEFINITIONS;
  private readonly byOperation = new Map(DEFINITIONS.map((item) => [item.operation, item]));
  private readonly byId = new Map(DEFINITIONS.map((item) => [item.toolId, item]));

  resolveOperation(operation: WindowsIdentityOperation): WindowsIdentityToolDefinition | undefined {
    return this.byOperation.get(operation);
  }

  resolveTool(toolId: WindowsIdentityToolId): WindowsIdentityToolDefinition | undefined {
    return this.byId.get(toolId);
  }

  /**
   * Re-derives the complete executable shape from the persisted action. The
   * process adapter calls this immediately before spawn so a deserialized or
   * otherwise modified "compiled" object cannot change its target, argv,
   * credential reference, environment, or execution budgets after the exact
   * Guided decision was checked.
   */
  executionShapeMatches(invocation: CompiledWindowsIdentityInvocation): boolean {
    const definition = this.resolveTool(invocation.toolId);
    if (!definition || definition.operation !== invocation.operation) return false;
    const action = invocation.action;
    if (!exactRecordKeys(action as unknown as Readonly<Record<string, unknown>>, [
      "actionClass",
      "actionType",
      "arguments",
      "missionId",
      "planVersion",
      "runId",
      "stepId",
      "target",
    ]) || !exactRecordKeys(action.arguments, [
      "authenticationMode",
      "credentialReference",
      "executionBinding",
      "logicalWorkspace",
      "operation",
      "schemaVersion",
      "toolId",
    ])) return false;

    let request: WindowsIdentityActionRequest;
    try {
      request = parseWindowsIdentityActionRequest({
        schemaVersion: action.arguments.schemaVersion,
        missionId: action.missionId,
        runId: action.runId,
        stepId: action.stepId,
        planVersion: action.planVersion,
        journey: "guided",
        operation: action.arguments.operation,
        target: action.target,
        logicalWorkspace: action.arguments.logicalWorkspace,
        authenticationMode: action.arguments.authenticationMode,
        credentialReference: action.arguments.credentialReference,
      });
    } catch {
      return false;
    }
    const expectedArguments = argv(definition, request);
    const expectedCredentialReference = request.credentialReference;
    const receipt = invocation.credentialBindingReceipt;
    const environmentMatches = Object.keys(invocation.environment).length === 6
      && Object.entries(FIXED_ENVIRONMENT).every(([key, value]) =>
        invocation.environment[key as keyof typeof FIXED_ENVIRONMENT] === value);
    return action.actionType === definition.toolId
      && action.actionClass === definition.actionClassId
      && invocation.target === request.target
      && invocation.logicalWorkspace === request.logicalWorkspace
      && invocation.actionFingerprint === fingerprintAction(action).hash
      && invocation.executablePath === definition.executable.path
      && invocation.executableSha256 === definition.executable.sha256
      && sameStringArray(invocation.arguments, expectedArguments)
      && environmentMatches
      && sameCredentialReference(invocation.credentialReference, expectedCredentialReference)
      && (expectedCredentialReference === null
        ? receipt === null
        : receipt !== null
          && receipt.referenceId === expectedCredentialReference.id
          && receipt.runId === request.runId
          && receipt.actionFingerprint === invocation.actionFingerprint)
      && invocation.timeoutMs === definition.execution.timeoutMs
      && invocation.maximumOutputBytes === definition.execution.maximumOutputBytes
      && invocation.terminationGraceMs === definition.execution.terminationGraceMs
      && invocation.directArgv === true
      && invocation.shell === false
      && invocation.targetReadOnly === true
      && invocation.evidencePromotion === "none";
  }

  compile(input: Readonly<{
    request: unknown;
    missionBoundary: WindowsIdentityMissionBoundary;
    credentialBindingReceipt: WindowsIdentityCredentialBindingReceipt | null;
    now?: Date;
  }>): CompiledWindowsIdentityInvocation {
    const request = parseWindowsIdentityActionRequest(input.request);
    const definition = this.resolveOperation(request.operation);
    if (!definition) boundary("windows_identity_request_invalid");
    if (request.journey !== "guided" || definition.journeyPolicy !== "guided_only") {
      boundary("windows_identity_autonomous_not_approved");
    }
    if (!definition.authenticationModes.includes(request.authenticationMode)) {
      boundary("windows_identity_credential_reference_invalid");
    }
    if (!input.missionBoundary.authorizationVerified) {
      boundary("windows_identity_authorization_unverified");
    }
    const target = canonicalWindowsIdentityTarget(request.target);
    const allowed = input.missionBoundary.allowedTargets.map(canonicalWindowsIdentityTarget);
    const prohibited = input.missionBoundary.prohibitedTargets.map(canonicalWindowsIdentityTarget);
    if (!allowed.includes(target) || prohibited.includes(target)) {
      boundary("windows_identity_target_outside_scope");
    }
    if (!input.missionBoundary.allowedActionClassIds.includes(definition.actionClassId)
      || input.missionBoundary.prohibitedActionClassIds.includes(definition.actionClassId)) {
      boundary("windows_identity_action_class_denied");
    }
    const action: ActionIntent = Object.freeze({
      missionId: request.missionId,
      runId: request.runId,
      stepId: request.stepId,
      planVersion: request.planVersion,
      actionType: definition.toolId,
      actionClass: definition.actionClassId,
      target,
      arguments: Object.freeze({
        schemaVersion: request.schemaVersion,
        executionBinding: "reviewed_windows_identity_process",
        operation: request.operation,
        toolId: definition.toolId,
        authenticationMode: request.authenticationMode,
        credentialReference: request.credentialReference,
        logicalWorkspace: request.logicalWorkspace,
      }),
    });
    const actionFingerprint = fingerprintAction(action).hash;
    const decision = enforceJourneyActionBoundary({
      journey: "guided",
      action,
      now: (input.now ?? new Date()).toISOString(),
      guidedDecision: input.missionBoundary.guidedDecision ?? undefined,
    });
    if (!decision.allowed) {
      boundary(decision.reason === "guided_action_changed"
        ? "windows_identity_guided_action_changed"
        : "windows_identity_guided_decision_required");
    }
    const binding = credentialReceipt(
      request,
      actionFingerprint,
      input.credentialBindingReceipt,
      input.now ?? new Date(),
    );
    const arguments_ = argv(definition, request);
    if (arguments_.some((value) => SECRET_VALUE.test(value))) {
      boundary("windows_identity_credential_reference_invalid");
    }
    return Object.freeze({
      schemaVersion: "ti-scale.windows-identity-invocation.v1",
      toolId: definition.toolId,
      operation: definition.operation,
      action,
      actionFingerprint,
      target,
      logicalWorkspace: request.logicalWorkspace,
      executablePath: definition.executable.path,
      executableSha256: definition.executable.sha256,
      arguments: arguments_,
      environment: FIXED_ENVIRONMENT,
      credentialReference: request.credentialReference,
      credentialBindingReceipt: binding,
      timeoutMs: definition.execution.timeoutMs,
      maximumOutputBytes: definition.execution.maximumOutputBytes,
      terminationGraceMs: definition.execution.terminationGraceMs,
      directArgv: true,
      shell: false,
      targetReadOnly: true,
      evidencePromotion: "none",
    });
  }
}
