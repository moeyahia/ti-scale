import { createHash } from "node:crypto";
import { constants as fsConstants, lstatSync, openSync, closeSync, readFileSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import {
  WEB_ASSESSMENT_INVOCATION_SCHEMA_VERSION,
  WEB_ASSESSMENT_PROBE_RECEIPT_SCHEMA_VERSION,
  WEB_ASSESSMENT_TOOL_PACK_SCHEMA_VERSION,
  type CompileGuidedWebAssessmentInvocationInput,
  type CompiledWebAssessmentInvocation,
  type ReviewedFileBinding,
  type WebAssessmentActionIdentity,
  type WebAssessmentProbeReceipt,
  type WebAssessmentToolDefinition,
  type WebAssessmentToolId,
  type WebAssessmentToolPackDocument,
} from "./types";

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const FIXED_ENVIRONMENT = Object.freeze({
  HOME: "/nonexistent",
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
  PATH: "/usr/bin:/bin",
} as const);

const WHATWEB_DEPENDENCIES: readonly ReviewedFileBinding[] = Object.freeze([
  { path: "/usr/bin/env", expectedSha256: "47b5431b62e8104a296c084f93c6ea9581310049b608da88af0144a7ea2e3440", executable: true },
  { path: "/usr/bin/ruby3.3", expectedSha256: "acd9b50b00c1245f91149775213dbcc1f13282de1fe2513f161ee639c1230e9b", executable: true },
  { path: "/usr/lib/ruby/vendor_ruby/whatweb.rb", expectedSha256: "72b1bc913b72966313210ed0d63a322411f488bd9342706e0ba7bbb3c869b035", executable: false },
  { path: "/usr/lib/ruby/vendor_ruby/plugins.rb", expectedSha256: "fa43404ac34f3912dd101ef10ef370fb44cbc9246b227758c94a0f52ac90cbe9", executable: false },
  { path: "/usr/lib/ruby/vendor_ruby/extend-http.rb", expectedSha256: "4517f5d46f069e6704b33f5bb7f0ea47e05e459ff5b9d16c53fce2e30f850385", executable: false },
  { path: "/usr/share/whatweb/plugins/http-server.rb", expectedSha256: "e2b5e5d8137c92fb9c2b23dc6c4cb817503ae42a208f5d1f6454e0d73d06ca87", executable: false },
  { path: "/usr/share/whatweb/plugins/title.rb", expectedSha256: "c343a5e95d0a108ff46abe3ecc8edef4c8dedc5c969cad4a8d2d3def010b3d27", executable: false },
  { path: "/usr/share/whatweb/plugins/x-powered-by-header.rb", expectedSha256: "b32657d8e94a27f711ed436a63e8bf21e219932473f2fc1aed4245082cbe39ed", executable: false },
  { path: "/usr/share/whatweb/plugins/html5.rb", expectedSha256: "894970d93e2701f105fb1a718b85fd1678b2340539d6f5a49198ae79732d7169", executable: false },
]);

const FFUF_PATHS = Object.freeze([
  "admin",
  "api",
  "assets",
  "docs",
  "health",
  "images",
  "index.html",
  "login",
  "robots.txt",
  "static",
  "status",
  "swagger",
  "uploads",
  ".well-known/security.txt",
] as const);

const tool = (definition: WebAssessmentToolDefinition): WebAssessmentToolDefinition =>
  Object.freeze({
    ...definition,
    dependencies: Object.freeze([...definition.dependencies]),
    evidenceTypeIds: Object.freeze([...definition.evidenceTypeIds]),
    executable: Object.freeze({ ...definition.executable }),
    probe: Object.freeze({
      ...definition.probe,
      arguments: Object.freeze([...definition.probe.arguments]),
      expectedExitCodes: Object.freeze([...definition.probe.expectedExitCodes]),
    }),
    execution: Object.freeze({ ...definition.execution }),
  });

const commonExecution = Object.freeze({
  transport: "bubblewrap_direct_argv" as const,
  shell: false as const,
  targetBinding: "exact_canonical_mission_url" as const,
  redirectPolicy: "never" as const,
  workspacePolicy: "resolved_workspace_only" as const,
  maximumConcurrentInvocationsPerRun: 1 as const,
});

export const REVIEWED_WEB_ASSESSMENT_TOOL_PACK: WebAssessmentToolPackDocument = Object.freeze({
  schemaVersion: WEB_ASSESSMENT_TOOL_PACK_SCHEMA_VERSION,
  packVersion: "kali-web-assessment-2026.07.20-v1",
  specialist: Object.freeze({
    id: "specialist:web-assessment",
    label: "Web assessment specialist",
  }),
  tools: Object.freeze([
    tool({
      toolId: "kali:whatweb-bounded-fingerprint",
      label: "Bounded web technology fingerprint",
      purpose: "Identify a small reviewed set of server, title, and HTML signals from one approved URL.",
      activation: "reviewed_guided",
      activationReason: null,
      defaultPolicyState: "guided_only",
      autonomousExecution: "not_authorized",
      actionClassId: "os_technology_fingerprinting",
      evidenceTypeIds: ["service_version_fingerprint"],
      executable: {
        path: "/usr/bin/whatweb",
        expectedSha256: "63f001c7433a1ed4e910bcfdad28969bca0cefb3ec0a48a6b555c67aaf9fb382",
        executable: true,
      },
      dependencies: WHATWEB_DEPENDENCIES,
      probe: {
        arguments: ["--version"], expectedExitCodes: [0], timeoutMs: 3_000,
        maximumOutputBytes: 16_384, targetContact: false,
      },
      execution: {
        ...commonExecution,
        requestConcurrency: 1,
        maximumRequests: 1,
        maximumRequestRatePerSecond: 1,
        timeoutMs: 15_000,
        terminationGraceMs: 1_000,
        maximumOutputBytes: 512 * 1_024,
      },
    }),
    tool({
      toolId: "kali:ffuf-bounded-content-discovery",
      label: "Bounded web content discovery",
      purpose: "Check a fixed, small path dictionary against one approved web origin without following redirects.",
      activation: "reviewed_guided",
      activationReason: null,
      defaultPolicyState: "guided_only",
      autonomousExecution: "not_authorized",
      actionClassId: "web_content_endpoint_discovery_fuzzing",
      evidenceTypeIds: ["endpoint_discovery_result"],
      executable: {
        path: "/usr/bin/ffuf",
        expectedSha256: "4dd9cf7e19abd92440922a28399c948be8d49308f1ca7f1222ef33f2d026313c",
        executable: true,
      },
      dependencies: [],
      probe: {
        arguments: ["-V"], expectedExitCodes: [0], timeoutMs: 3_000,
        maximumOutputBytes: 16_384, targetContact: false,
      },
      execution: {
        ...commonExecution,
        requestConcurrency: 2,
        maximumRequests: FFUF_PATHS.length,
        maximumRequestRatePerSecond: 10,
        timeoutMs: 25_000,
        terminationGraceMs: 1_000,
        maximumOutputBytes: 1024 * 1024,
      },
    }),
    tool({
      toolId: "kali:httpx-python-client-held",
      label: "Installed httpx Python client",
      purpose: "Installed package inventory only; this executable is not ProjectDiscovery httpx.",
      activation: "held",
      activationReason: "The installed /usr/local/bin/httpx is the Python HTTP client CLI and does not expose the reviewed ProjectDiscovery fingerprint schema.",
      defaultPolicyState: "guided_only",
      autonomousExecution: "not_authorized",
      actionClassId: "web_crawling_page_capture",
      evidenceTypeIds: ["http_exchange"],
      executable: { path: "/usr/local/bin/httpx", expectedSha256: "b160eb5461ed2b14461507f8ceabfffeb98067a5ca5373fc2a9af5d26f3b2f76", executable: true },
      dependencies: [],
      probe: { arguments: ["--help"], expectedExitCodes: [0], timeoutMs: 3_000, maximumOutputBytes: 16_384, targetContact: false },
      execution: { ...commonExecution, requestConcurrency: 1, maximumRequests: 1, maximumRequestRatePerSecond: 1, timeoutMs: 10_000, terminationGraceMs: 1_000, maximumOutputBytes: 256 * 1_024 },
    }),
    tool({
      toolId: "kali:gobuster-held",
      label: "Installed Gobuster",
      purpose: "Held as a redundant content-discovery path while FFUF is the reviewed structured-output binding.",
      activation: "held",
      activationReason: "FFUF provides the single reviewed bounded content-discovery route; a second equivalent binding needs independent output and retry semantics before activation.",
      defaultPolicyState: "guided_only",
      autonomousExecution: "not_authorized",
      actionClassId: "web_content_endpoint_discovery_fuzzing",
      evidenceTypeIds: ["endpoint_discovery_result"],
      executable: { path: "/usr/bin/gobuster", expectedSha256: "2be60715f30130842d7a08c41610fbdc2f4c32eab492f27fb9551345a46ea48b", executable: true },
      dependencies: [],
      probe: { arguments: ["version"], expectedExitCodes: [0], timeoutMs: 3_000, maximumOutputBytes: 16_384, targetContact: false },
      execution: { ...commonExecution, requestConcurrency: 2, maximumRequests: FFUF_PATHS.length, maximumRequestRatePerSecond: 10, timeoutMs: 25_000, terminationGraceMs: 1_000, maximumOutputBytes: 1024 * 1024 },
    }),
    tool({
      toolId: "kali:nikto-held",
      label: "Installed Nikto",
      purpose: "Installed package inventory only.",
      activation: "held",
      activationReason: "Nikto's broad plugin and mutation surface does not yet have a pinned read-only plugin allowlist and exact request-count proof.",
      defaultPolicyState: "guided_only",
      autonomousExecution: "not_authorized",
      actionClassId: "vulnerability_configuration_assessment",
      evidenceTypeIds: ["configuration_snapshot"],
      executable: { path: "/usr/bin/nikto", expectedSha256: "e54602d05561c13e36ec7d1072ce8e5d181103bdd40976c1fd2318d990462512", executable: true },
      dependencies: [],
      probe: { arguments: ["-Version"], expectedExitCodes: [0], timeoutMs: 3_000, maximumOutputBytes: 32_768, targetContact: false },
      execution: { ...commonExecution, requestConcurrency: 1, maximumRequests: 1, maximumRequestRatePerSecond: 1, timeoutMs: 30_000, terminationGraceMs: 1_000, maximumOutputBytes: 1024 * 1024 },
    }),
    tool({
      toolId: "kali:nuclei-held",
      label: "Installed Nuclei",
      purpose: "Installed package inventory only.",
      activation: "held",
      activationReason: "The binary is under /root and its template set is mutable and unpinned, so the non-root runtime cannot attest an exact safe scan surface.",
      defaultPolicyState: "guided_only",
      autonomousExecution: "not_authorized",
      actionClassId: "vulnerability_configuration_assessment",
      evidenceTypeIds: ["configuration_snapshot"],
      executable: { path: "/root/go/bin/nuclei", expectedSha256: "fbcda5ecd55fccdd18e804306a3a633758cda2b6f0ac7a169964150de47bcb82", executable: true },
      dependencies: [],
      probe: { arguments: ["-version"], expectedExitCodes: [0], timeoutMs: 3_000, maximumOutputBytes: 32_768, targetContact: false },
      execution: { ...commonExecution, requestConcurrency: 1, maximumRequests: 1, maximumRequestRatePerSecond: 1, timeoutMs: 30_000, terminationGraceMs: 1_000, maximumOutputBytes: 1024 * 1024 },
    }),
  ]),
});

export class WebAssessmentBoundaryError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "WebAssessmentBoundaryError";
  }
}

function safeId(value: string, label: string): string {
  if (!PUBLIC_ID.test(value)) throw new WebAssessmentBoundaryError("identity_invalid", `${label} must be a stable public ID.`);
  return value;
}

function logicalWorkspace(value: string): string {
  if (!isAbsolute(value) || resolve(value) !== value || value === resolve(sep)
    || value.split(sep).includes("..") || CONTROL_CHARACTERS.test(value)) {
    throw new WebAssessmentBoundaryError("workspace_invalid", "The logical workspace must be one normalized, non-root absolute path.");
  }
  return value;
}

export function normalizeCanonicalWebTarget(value: string, requireDirectoryBase = false): string {
  if (typeof value !== "string" || value !== value.trim() || value.length < 8 || value.length > 2_048
    || CONTROL_CHARACTERS.test(value)) {
    throw new WebAssessmentBoundaryError("target_invalid", "The web target must be one normalized HTTP/S URL.");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new WebAssessmentBoundaryError("target_invalid", "The web target is not a valid URL.");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:")
    || parsed.username !== "" || parsed.password !== "" || !parsed.hostname
    || parsed.search !== "" || parsed.hash !== "") {
    throw new WebAssessmentBoundaryError(
      "target_invalid",
      "The web target must use HTTP/S without credentials, query text, or fragments.",
    );
  }
  if (parsed.href !== value) {
    throw new WebAssessmentBoundaryError("target_not_canonical", `Use the canonical URL ${parsed.href}.`);
  }
  if (requireDirectoryBase && !parsed.pathname.endsWith("/")) {
    throw new WebAssessmentBoundaryError("target_base_invalid", "Content discovery requires a canonical URL ending in '/'.");
  }
  return parsed.href;
}

export function webAssessmentActionFingerprint(input: WebAssessmentActionIdentity): string {
  const targetUrl = normalizeCanonicalWebTarget(
    input.requestedUrl,
    input.toolId === "kali:ffuf-bounded-content-discovery",
  );
  if (normalizeCanonicalWebTarget(input.canonicalMissionTarget,
    input.toolId === "kali:ffuf-bounded-content-discovery") !== targetUrl) {
    throw new WebAssessmentBoundaryError("target_scope_mismatch", "The represented web target differs from the canonical mission target.");
  }
  if (input.profile !== "bounded_standard") {
    throw new WebAssessmentBoundaryError("profile_invalid", "Only the bounded standard web-assessment profile is reviewed.");
  }
  return digestCanonicalJson({
    schemaVersion: "ti-scale.web-assessment-action.v1",
    missionId: safeId(input.missionId, "missionId"),
    runId: safeId(input.runId, "runId"),
    actionId: safeId(input.actionId, "actionId"),
    toolId: input.toolId,
    targetUrl,
    logicalWorkspace: logicalWorkspace(input.logicalWorkspace),
    profile: input.profile,
  }, { maxBytes: 16 * 1_024, maxDepth: 8 }).sha256;
}

function resolveReviewedTool(toolId: string): WebAssessmentToolDefinition {
  const toolDefinition = REVIEWED_WEB_ASSESSMENT_TOOL_PACK.tools.find((candidate) => candidate.toolId === toolId);
  if (!toolDefinition || toolDefinition.activation !== "reviewed_guided") {
    throw new WebAssessmentBoundaryError("tool_not_reviewed", "This web-assessment binding is not activated for represented Guided execution.");
  }
  return toolDefinition;
}

export function compileGuidedWebAssessmentInvocation(
  input: CompileGuidedWebAssessmentInvocationInput,
): CompiledWebAssessmentInvocation {
  safeId(input.invocationId, "invocationId");
  if (input.journey !== "guided") {
    throw new WebAssessmentBoundaryError(
      "autonomous_not_authorized",
      "This pack defaults to Guided-only until the Autonomous contract and action-class gate are integrated.",
    );
  }
  if (input.authorizationVerified !== true) {
    throw new WebAssessmentBoundaryError(
      "authorization_unverified",
      "The mission authorization must be verified before a web target can be contacted.",
    );
  }
  if (input.actionClassAllowed !== true) {
    throw new WebAssessmentBoundaryError(
      "action_class_denied",
      "The mission policy does not allow this web-assessment action class.",
    );
  }
  if (input.guidedDecisionStatus !== "approved") {
    throw new WebAssessmentBoundaryError("guided_decision_required", "The exact represented Guided action is not approved.");
  }
  const definition = resolveReviewedTool(input.toolId);
  const fingerprint = webAssessmentActionFingerprint(input);
  if (!SHA256.test(input.representedActionFingerprint)
    || input.representedActionFingerprint !== fingerprint) {
    throw new WebAssessmentBoundaryError("represented_action_changed", "The web action changed after the operator decision.");
  }
  const targetUrl = normalizeCanonicalWebTarget(
    input.requestedUrl,
    input.toolId === "kali:ffuf-bounded-content-discovery",
  );
  const argumentsForTool = input.toolId === "kali:whatweb-bounded-fingerprint"
    ? [
        "--aggression=1",
        "--plugins=HTTPServer,Title,X-Powered-By,HTML5",
        "--follow-redirect=never",
        "--max-redirects=0",
        "--max-threads=1",
        "--open-timeout=3",
        "--read-timeout=5",
        "--wait=1",
        "--no-cookies",
        "--no-errors",
        "--color=never",
        "--user-agent=Ti-Scale-Reviewed-Web-Assessment/1",
        "--",
        targetUrl,
      ]
    : [
        "-noninteractive", "-s", "-json",
        "-u", `${targetUrl}FUZZ`,
        "-w", "/run/ti-scale-input/paths.txt",
        "-t", String(definition.execution.requestConcurrency),
        "-rate", String(definition.execution.maximumRequestRatePerSecond),
        "-timeout", "3",
        "-maxtime", "20",
        "-maxtime-job", "20",
        "-mc", "200-399,401,403,405",
        "-H", "User-Agent: Ti-Scale-Reviewed-Web-Assessment/1",
        "-sa",
      ];
  return Object.freeze({
    schemaVersion: WEB_ASSESSMENT_INVOCATION_SCHEMA_VERSION,
    invocationId: input.invocationId,
    missionId: input.missionId,
    runId: input.runId,
    actionId: input.actionId,
    toolId: input.toolId,
    actionClassId: definition.actionClassId,
    targetUrl,
    targetOrigin: new URL(targetUrl).origin,
    logicalWorkspace: logicalWorkspace(input.logicalWorkspace),
    arguments: Object.freeze(argumentsForTool),
    stagedInput: input.toolId === "kali:ffuf-bounded-content-discovery"
      ? Object.freeze({ kind: "fixed_path_dictionary" as const, mountPath: "/run/ti-scale-input/paths.txt", lines: FFUF_PATHS })
      : Object.freeze({ kind: "none" as const, mountPath: null, lines: Object.freeze([]) }),
    representedActionFingerprint: fingerprint,
    shell: false,
    authorizationGrantedByCompiler: false,
    journey: "guided",
    budget: definition.execution,
  });
}

function inspectBinding(binding: ReviewedFileBinding): { ready: boolean; sha256: string | null; code: string | null } {
  if (!isAbsolute(binding.path) || !SHA256.test(binding.expectedSha256)) return { ready: false, sha256: null, code: "binding_invalid" };
  let descriptor: number | undefined;
  try {
    const before = lstatSync(binding.path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) return { ready: false, sha256: null, code: "not_regular" };
    const mode = Number(before.mode & 0o7777n);
    if (Number(before.uid) !== 0 || (mode & 0o022) !== 0 || (mode & 0o7000) !== 0
      || (binding.executable && (mode & 0o111) === 0)) {
      return { ready: false, sha256: null, code: "unsafe_permissions" };
    }
    descriptor = openSync(binding.path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const bytes = readFileSync(descriptor);
    const digest = createHash("sha256").update(bytes).digest("hex");
    const after = lstatSync(binding.path, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      return { ready: false, sha256: digest, code: "identity_changed" };
    }
    return digest === binding.expectedSha256
      ? { ready: true, sha256: digest, code: null }
      : { ready: false, sha256: digest, code: "hash_drift" };
  } catch {
    return { ready: false, sha256: null, code: "missing" };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function probeWebAssessmentTool(
  toolId: WebAssessmentToolId,
  now = new Date(),
): WebAssessmentProbeReceipt {
  const definition = REVIEWED_WEB_ASSESSMENT_TOOL_PACK.tools.find((candidate) => candidate.toolId === toolId);
  if (!definition) throw new WebAssessmentBoundaryError("tool_unknown", "The web-assessment tool ID is unknown.");
  const executable = inspectBinding(definition.executable);
  const dependenciesReady = definition.dependencies.every((dependency) => inspectBinding(dependency).ready);
  if (!executable.ready || !dependenciesReady) {
    return Object.freeze({
      schemaVersion: WEB_ASSESSMENT_PROBE_RECEIPT_SCHEMA_VERSION,
      toolId,
      installationReady: false,
      probeReady: false,
      observedExecutableSha256: executable.sha256,
      expectedExecutableSha256: definition.executable.expectedSha256,
      targetContact: false,
      observedAt: now.toISOString(),
      failureCode: executable.code ?? "dependency_drift",
    });
  }
  const result = spawnSync(definition.executable.path, [...definition.probe.arguments], {
    shell: false,
    env: { ...FIXED_ENVIRONMENT },
    encoding: "utf8",
    timeout: definition.probe.timeoutMs,
    maxBuffer: definition.probe.maximumOutputBytes,
    input: "",
    windowsHide: true,
  });
  const outputBytes = Buffer.byteLength(result.stdout ?? "") + Buffer.byteLength(result.stderr ?? "");
  const probeReady = !result.error && result.signal === null && result.status !== null
    && definition.probe.expectedExitCodes.includes(result.status)
    && outputBytes <= definition.probe.maximumOutputBytes;
  return Object.freeze({
    schemaVersion: WEB_ASSESSMENT_PROBE_RECEIPT_SCHEMA_VERSION,
    toolId,
    installationReady: true,
    probeReady,
    observedExecutableSha256: executable.sha256,
    expectedExecutableSha256: definition.executable.expectedSha256,
    targetContact: false,
    observedAt: now.toISOString(),
    failureCode: probeReady
      ? null
      : (result.error as NodeJS.ErrnoException | undefined)?.code ?? "probe_failed",
  });
}

export function webAssessmentPackSha256(): string {
  return digestCanonicalJson(REVIEWED_WEB_ASSESSMENT_TOOL_PACK, {
    maxBytes: 512 * 1_024,
    maxDepth: 16,
  }).sha256;
}
