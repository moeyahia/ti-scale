import { createHash } from "node:crypto";
import {
  buildRuntimeCapabilityProjection,
  type RuntimeSourceManifests,
} from "../domain";
import {
  LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
  LocalToolCapabilityManifest,
  type LocalToolCapabilityRecord,
} from "../local-tools";
import {
  TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
  ToolBindingRegistry,
  type ToolBindingReadinessSnapshot,
  type ToolBindingRegistryDocument,
} from "../system-capabilities";
import { REVIEWED_WEB_ASSESSMENT_TOOL_PACK, webAssessmentPackSha256 } from "./WebAssessmentToolPack";
import type {
  ReviewedWebAssessmentToolId,
  WebAssessmentActivationSnapshot,
  WebAssessmentAdapterReadinessReceipt,
  WebAssessmentProbeReceipt,
  WebAssessmentToolDefinition,
  WebAssessmentToolId,
} from "./types";

const SHA256 = /^[a-f0-9]{64}$/u;

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function timestamp(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function reviewedTools(): readonly WebAssessmentToolDefinition[] {
  return REVIEWED_WEB_ASSESSMENT_TOOL_PACK.tools
    .filter(({ activation }) => activation === "reviewed_guided");
}

export function webAssessmentRuntimeSourceManifests(
  readyToolIds: ReadonlySet<string> = new Set(),
): RuntimeSourceManifests {
  const tools = REVIEWED_WEB_ASSESSMENT_TOOL_PACK.tools;
  const manifests: RuntimeSourceManifests = deepFreeze({
    riskClasses: [{
      id: "ti-scale:network",
      label: "Authorized bounded network interaction",
      actionClassIds: [...new Set(tools.map(({ actionClassId }) => actionClassId))],
    }],
    evidenceKinds: [...new Set(tools.flatMap(({ evidenceTypeIds }) => evidenceTypeIds))]
      .map((id) => ({
        id: `web-assessment-evidence:${id}`,
        label: id === "service_version_fingerprint"
          ? "Service and version fingerprint"
          : id === "endpoint_discovery_result"
            ? "Endpoint discovery result"
            : id,
        evidenceTypeIds: [id],
      })),
    capabilities: tools.map((tool) => ({
      id: `capability:${tool.toolId}`,
      label: `${tool.label} capability`,
      actionClassIds: [tool.actionClassId],
      evidenceTypeIds: [...tool.evidenceTypeIds],
    })),
    tools: tools.map((tool) => ({
      id: tool.toolId,
      label: tool.label,
      available: tool.activation === "reviewed_guided" && readyToolIds.has(tool.toolId),
      locallyPolicyEnforced: true,
      requiresModel: false,
      executionJourneys: ["guided"],
      actionClassIds: [tool.actionClassId],
      evidenceTypeIds: [...tool.evidenceTypeIds],
      riskClassIds: ["ti-scale:network"],
      dependencies: [{
        id: tool.activation === "reviewed_guided"
          ? "reviewed-web-assessment-adapter"
          : `held:${tool.toolId}`,
        ready: tool.activation === "reviewed_guided" && readyToolIds.has(tool.toolId),
      }],
    })),
    mcpServers: [],
    agents: [{
      id: REVIEWED_WEB_ASSESSMENT_TOOL_PACK.specialist.id,
      label: REVIEWED_WEB_ASSESSMENT_TOOL_PACK.specialist.label,
      available: reviewedTools().some(({ toolId }) => readyToolIds.has(toolId)),
      capabilityIds: tools.map(({ toolId }) => `capability:${toolId}`),
      actionClassIds: [...new Set(tools.map(({ actionClassId }) => actionClassId))],
      toolIds: tools.map(({ toolId }) => toolId),
      modelRefs: [],
    }],
    providers: [],
  });
  buildRuntimeCapabilityProjection(manifests);
  return manifests;
}

export function webAssessmentToolBindingRegistryDocument(): ToolBindingRegistryDocument {
  return deepFreeze({
    schemaVersion: TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
    registryVersion: REVIEWED_WEB_ASSESSMENT_TOOL_PACK.packVersion,
    bindings: reviewedTools().map((tool) => ({
      toolId: tool.toolId,
      executablePath: tool.executable.path,
      probeArguments: [tool.probe.arguments[0]!] as readonly [string],
      expectedExitCodes: [...tool.probe.expectedExitCodes],
      timeoutMs: tool.probe.timeoutMs,
      maximumOutputBytes: tool.probe.maximumOutputBytes,
      ttlMs: 60_000,
    })),
  });
}

export function createWebAssessmentToolBindingRegistry(): ToolBindingRegistry {
  return new ToolBindingRegistry(
    webAssessmentToolBindingRegistryDocument(),
    webAssessmentRuntimeSourceManifests(),
  );
}

function localWebToolRecords(): readonly LocalToolCapabilityRecord[] {
  const whatweb = REVIEWED_WEB_ASSESSMENT_TOOL_PACK.tools.find(
    ({ toolId }) => toolId === "kali:whatweb-bounded-fingerprint",
  )!;
  const ffuf = REVIEWED_WEB_ASSESSMENT_TOOL_PACK.tools.find(
    ({ toolId }) => toolId === "kali:ffuf-bounded-content-discovery",
  )!;
  const commonExecution = {
    transport: "direct_spawn_argv" as const,
    shell: false as const,
    noNewPrivilegesRequired: true as const,
    networkPolicy: "authorized_scope_only" as const,
    filesystemWritePolicy: "resolved_workspace_only" as const,
    environmentPolicy: "fixed_minimal" as const,
    logicalWorkspaceParameter: "workspace",
  };
  const workspaceParameter = {
    name: "workspace",
    type: "string" as const,
    semantic: "logical_workspace" as const,
    required: true as const,
    minimum: 2,
    maximum: 4_096,
    allowedValues: [],
  };
  const fixedLines = ffuf.toolId === "kali:ffuf-bounded-content-discovery"
    ? [
        "admin", "api", "assets", "docs", "health", "images", "index.html",
        "login", "robots.txt", "static", "status", "swagger", "uploads",
        ".well-known/security.txt",
      ]
    : [];
  const fixedContent = Buffer.from(`${fixedLines.join("\n")}\n`, "utf8");
  return deepFreeze([
    {
      toolId: whatweb.toolId,
      label: whatweb.label,
      activation: "enabled" as const,
      activationReason: null,
      executable: {
        path: whatweb.executable.path,
        expectedSha256: whatweb.executable.expectedSha256,
        fileCapabilities: "none" as const,
      },
      dependencyFiles: whatweb.dependencies.map((dependency) => ({
        path: dependency.path,
        expectedSha256: dependency.expectedSha256,
        executable: dependency.executable,
      })),
      probe: {
        arguments: [whatweb.probe.arguments[0]!] as readonly [string],
        expectedExitCodes: [...whatweb.probe.expectedExitCodes],
        timeoutMs: whatweb.probe.timeoutMs,
        maximumOutputBytes: whatweb.probe.maximumOutputBytes,
        ttlMs: 60_000,
      },
      routing: { intent: "web_fingerprint" as const, targetKind: "url" as const },
      execution: {
        ...commonExecution,
        timeoutMs: whatweb.execution.timeoutMs,
        maximumOutputBytes: whatweb.execution.maximumOutputBytes,
        terminationGraceMs: whatweb.execution.terminationGraceMs,
      },
      parameters: [
        workspaceParameter,
        {
          name: "url", type: "string" as const,
          semantic: "authorized_canonical_http_url" as const,
          required: true as const, minimum: 8, maximum: 2_048, allowedValues: [],
        },
      ],
      argvTemplate: [
        { kind: "literal" as const, value: "--aggression=1" },
        { kind: "literal" as const, value: "--plugins=HTTPServer,Title,X-Powered-By,HTML5" },
        { kind: "literal" as const, value: "--follow-redirect=never" },
        { kind: "literal" as const, value: "--max-redirects=0" },
        { kind: "literal" as const, value: "--max-threads=1" },
        { kind: "literal" as const, value: "--open-timeout=3" },
        { kind: "literal" as const, value: "--read-timeout=5" },
        { kind: "literal" as const, value: "--wait=1" },
        { kind: "literal" as const, value: "--no-cookies" },
        { kind: "literal" as const, value: "--no-errors" },
        { kind: "literal" as const, value: "--color=never" },
        { kind: "literal" as const, value: "--user-agent=Ti-Scale-Reviewed-Web-Assessment/1" },
        { kind: "literal" as const, value: "--" },
        { kind: "parameter" as const, value: "url" },
      ],
      actionClassIds: [whatweb.actionClassId],
      evidenceTypeIds: [...whatweb.evidenceTypeIds],
      riskClassIds: ["ti-scale:network"],
    },
    {
      toolId: ffuf.toolId,
      label: ffuf.label,
      activation: "enabled" as const,
      activationReason: null,
      executable: {
        path: ffuf.executable.path,
        expectedSha256: ffuf.executable.expectedSha256,
        fileCapabilities: "none" as const,
      },
      probe: {
        arguments: [ffuf.probe.arguments[0]!] as readonly [string],
        expectedExitCodes: [...ffuf.probe.expectedExitCodes],
        timeoutMs: ffuf.probe.timeoutMs,
        maximumOutputBytes: ffuf.probe.maximumOutputBytes,
        ttlMs: 60_000,
      },
      routing: { intent: "web_content_discovery" as const, targetKind: "url" as const },
      execution: {
        ...commonExecution,
        timeoutMs: ffuf.execution.timeoutMs,
        maximumOutputBytes: ffuf.execution.maximumOutputBytes,
        terminationGraceMs: ffuf.execution.terminationGraceMs,
      },
      stagedInput: {
        kind: "fixed_lines" as const,
        mountPath: "/run/ti-scale-input/paths.txt",
        lines: fixedLines,
        contentSha256: createHash("sha256").update(fixedContent).digest("hex"),
      },
      parameters: [
        workspaceParameter,
        {
          name: "url", type: "string" as const,
          semantic: "authorized_http_base_url" as const,
          required: true as const, minimum: 8, maximum: 2_048, allowedValues: [],
        },
      ],
      argvTemplate: [
        { kind: "literal" as const, value: "-noninteractive" },
        { kind: "literal" as const, value: "-s" },
        { kind: "literal" as const, value: "-json" },
        { kind: "literal" as const, value: "-u" },
        { kind: "parameter_suffix" as const, value: "url", suffix: "FUZZ" },
        { kind: "literal" as const, value: "-w" },
        { kind: "literal" as const, value: "/run/ti-scale-input/paths.txt" },
        { kind: "literal" as const, value: "-t" },
        { kind: "literal" as const, value: "2" },
        { kind: "literal" as const, value: "-rate" },
        { kind: "literal" as const, value: "10" },
        { kind: "literal" as const, value: "-timeout" },
        { kind: "literal" as const, value: "3" },
        { kind: "literal" as const, value: "-maxtime" },
        { kind: "literal" as const, value: "20" },
        { kind: "literal" as const, value: "-maxtime-job" },
        { kind: "literal" as const, value: "20" },
        { kind: "literal" as const, value: "-mc" },
        { kind: "literal" as const, value: "200-399,401,403,405" },
        { kind: "literal" as const, value: "-H" },
        { kind: "literal" as const, value: "User-Agent: Ti-Scale-Reviewed-Web-Assessment/1" },
        { kind: "literal" as const, value: "-sa" },
      ],
      actionClassIds: [ffuf.actionClassId],
      evidenceTypeIds: [...ffuf.evidenceTypeIds],
      riskClassIds: ["ti-scale:network"],
    },
  ] satisfies readonly LocalToolCapabilityRecord[]);
}

/**
 * Adds the two source-reviewed web bindings to the existing local process
 * manifest. The returned manifest receives a new hash/version and therefore
 * requires a completely fresh activation wave before either tool is visible.
 */
export function composeReviewedWebAssessmentLocalManifest(
  baseline: LocalToolCapabilityManifest,
): LocalToolCapabilityManifest {
  const additions = localWebToolRecords();
  const existing = new Set(baseline.list().map(({ toolId }) => toolId));
  const collision = additions.find(({ toolId }) => existing.has(toolId));
  if (collision) throw new Error(`Local web-assessment tool ID collision: ${collision.toolId}`);
  const tools = baseline.list().map(({ bindingSha256: _bindingSha256, ...tool }) => tool);
  const version = `${baseline.descriptor.manifestVersion}-web-assessment-v1`;
  if (version.length > 80) throw new Error("Composed local web-assessment manifest version exceeds 80 characters");
  return new LocalToolCapabilityManifest({
    schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    manifestVersion: version,
    specialist: baseline.specialist,
    tools: [...tools, ...additions],
  });
}

function bindingReady(
  snapshot: ToolBindingReadinessSnapshot,
  tool: WebAssessmentToolDefinition,
  now: Date,
): boolean {
  const receipt = snapshot.receipts.find(({ toolId }) => toolId === tool.toolId);
  const expiry = receipt ? timestamp(receipt.expiresAt) : null;
  return snapshot.accounting.complete
    && snapshot.accounting.current
    && receipt !== undefined
    && receipt.status === "ready"
    && receipt.code === "ready"
    && receipt.executableIdentity?.sha256 === tool.executable.expectedSha256
    && expiry !== null
    && expiry > now.getTime()
    && receipt.probeBoundary.shell === false
    && receipt.probeBoundary.targetArgumentsSupplied === false
    && receipt.probeBoundary.providerArgumentsSupplied === false
    && receipt.probeBoundary.mcpArgumentsSupplied === false
    && receipt.probeBoundary.networkIsolationEnforced === true
    && receipt.probeBoundary.filesystemWriteIsolationEnforced === true
    && receipt.probeBoundary.immutableSnapshotExecutionEnforced === true
    && receipt.grantsMissionExecution === false;
}

function installationReady(
  receipt: WebAssessmentProbeReceipt | undefined,
  tool: WebAssessmentToolDefinition,
): boolean {
  return receipt !== undefined
    && receipt.toolId === tool.toolId
    && receipt.installationReady
    && receipt.probeReady
    && receipt.targetContact === false
    && receipt.observedExecutableSha256 === tool.executable.expectedSha256
    && receipt.expectedExecutableSha256 === tool.executable.expectedSha256
    && receipt.failureCode === null;
}

function adapterReady(
  receipt: WebAssessmentAdapterReadinessReceipt,
  registry: ToolBindingRegistry,
  now: Date,
): boolean {
  const observed = timestamp(receipt.observedAt);
  const expires = timestamp(receipt.expiresAt);
  const boundary = receipt.boundary;
  return receipt.schemaVersion === "ti-scale.web-assessment-adapter-readiness.v1"
    && receipt.adapterId === "ti-scale:reviewed-web-assessment-process"
    && receipt.packSha256 === webAssessmentPackSha256()
    && receipt.registrySha256 === registry.descriptor.registrySha256
    && receipt.runtimeManifestSha256 === registry.descriptor.runtimeManifestSha256
    && observed !== null
    && observed <= now.getTime()
    && expires !== null
    && expires > now.getTime()
    && expires > observed
    && receipt.grantsMissionExecution === false
    && boundary.directArgv && boundary.shell === false
    && boundary.exactTargetBinding && boundary.workspaceConfinement
    && boundary.immutableExecutableSnapshot && boundary.fixedDictionaryStaging
    && boundary.boundedOutput && boundary.boundedRuntime
    && boundary.cooperativeCancellation && boundary.resultNormalization
    && boundary.targetContactDuringReadiness === false;
}

export function buildWebAssessmentActivationSnapshot(input: Readonly<{
  toolBindingReadiness: ToolBindingReadinessSnapshot;
  installationReceipts: readonly WebAssessmentProbeReceipt[];
  adapterReadiness: WebAssessmentAdapterReadinessReceipt;
  now?: Date;
}>): WebAssessmentActivationSnapshot {
  const now = input.now ?? new Date();
  const registry = createWebAssessmentToolBindingRegistry();
  if (input.toolBindingReadiness.registry.registrySha256 !== registry.descriptor.registrySha256
    || input.toolBindingReadiness.registry.runtimeManifestSha256 !== registry.descriptor.runtimeManifestSha256) {
    throw new Error("Web-assessment readiness snapshot is not bound to the reviewed pack registry");
  }
  const duplicateInstallations = input.installationReceipts.map(({ toolId }) => toolId);
  if (new Set(duplicateInstallations).size !== duplicateInstallations.length) {
    throw new Error("Web-assessment installation receipts contain duplicate tool IDs");
  }
  const installed = new Map(input.installationReceipts.map((receipt) => [receipt.toolId, receipt]));
  const adapterIsReady = adapterReady(input.adapterReadiness, registry, now);
  const readyToolIds = reviewedTools()
    .filter((tool) => adapterIsReady
      && input.adapterReadiness.readyToolIds.includes(tool.toolId as ReviewedWebAssessmentToolId)
      && bindingReady(input.toolBindingReadiness, tool, now)
      && installationReady(installed.get(tool.toolId), tool))
    .map(({ toolId }) => toolId as ReviewedWebAssessmentToolId)
    .sort();
  const readySet = new Set<string>(readyToolIds);
  const tools = REVIEWED_WEB_ASSESSMENT_TOOL_PACK.tools.map((tool) => {
    if (tool.activation === "held") {
      return {
        toolId: tool.toolId,
        state: "held" as const,
        reason: tool.activationReason ?? "This binding is held for a separate review.",
        remediation: tool.activationReason,
      };
    }
    if (readySet.has(tool.toolId)) {
      return {
        toolId: tool.toolId,
        state: "ready" as const,
        reason: "The exact executable, dependency set, isolated startup probe, process adapter, staged input, workspace, output, and cancellation boundaries are current.",
        remediation: null,
      };
    }
    const installation = installed.get(tool.toolId);
    const blocker = input.adapterReadiness.blockers.find(({ toolId }) => toolId === tool.toolId)
      ?? input.adapterReadiness.blockers.find(({ toolId }) => toolId === "sandbox:bubblewrap");
    const reason = !installationReady(installation, tool)
      ? `The reviewed installation check failed: ${installation?.failureCode ?? "no current installation receipt"}.`
      : !bindingReady(input.toolBindingReadiness, tool, now)
        ? "The isolated immutable startup probe is missing, stale, or failed."
        : blocker?.explanation ?? "The bounded web-assessment process adapter is unavailable or stale.";
    return {
      toolId: tool.toolId,
      state: "unavailable" as const,
      reason,
      remediation: blocker?.remediation
        ?? "Repair the exact reviewed dependency and repeat the target-free readiness wave before creating a new Guided decision.",
    };
  });
  return deepFreeze({
    schemaVersion: "ti-scale.web-assessment-activation.v1",
    packSha256: webAssessmentPackSha256(),
    checkedAt: now.toISOString(),
    status: readyToolIds.length > 0 ? "ready" : "unavailable",
    readyToolIds,
    tools,
    toolBindingReadiness: input.toolBindingReadiness,
    adapterReadiness: input.adapterReadiness,
    grantsMissionExecution: false,
  });
}

export function projectReadyWebAssessmentRuntime(
  snapshot: WebAssessmentActivationSnapshot,
): RuntimeSourceManifests {
  if (snapshot.packSha256 !== webAssessmentPackSha256()
    || !SHA256.test(snapshot.packSha256)
    || snapshot.grantsMissionExecution !== false) {
    throw new Error("Web-assessment activation snapshot is not bound to this reviewed pack");
  }
  return webAssessmentRuntimeSourceManifests(new Set(snapshot.readyToolIds));
}

export type { WebAssessmentToolId };
