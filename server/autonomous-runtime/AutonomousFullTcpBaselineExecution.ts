import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  realpath,
} from "node:fs/promises";
import {
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import type { DurableAction } from "../orchestration";
import type {
  CompiledLocalToolInvocation,
  LocalProcessAdapterReadinessReceipt,
  LocalProcessToolInvocation,
  LocalProcessToolResult,
  LocalProcessToolResultSink,
  LocalToolCapabilityManifest,
  ReviewedLocalProcessInvocationAdapter,
} from "../local-tools";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import type { EngagementWorkspaceResolver } from "../system-capabilities";
import {
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_BASELINE_POLICY_SCHEMA_VERSION,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_MAX_TOTAL_OUTPUT_BYTES,
  AUTONOMOUS_FULL_TCP_MAX_VERSION_BATCHES,
  AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH,
  AUTONOMOUS_FULL_TCP_MAX_WALL_CLOCK_MS,
  AUTONOMOUS_FULL_TCP_NMAP_PATH,
  AUTONOMOUS_FULL_TCP_NMAP_SHA256,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  createAutonomousFullTcpBaselinePolicy,
  type AutonomousFullTcpBaselineConfiguration,
  type AutonomousFullTcpBaselinePolicy,
} from "./AutonomousFullTcpBaseline";
import { normalizeAutonomousIpHost } from "./AutonomousIpSafeRecon";

export const AUTONOMOUS_FULL_TCP_AUTHORIZATION_SCHEMA_VERSION =
  "ti-scale.autonomous-full-tcp-authorization.v1" as const;
export const AUTONOMOUS_FULL_TCP_BASELINE_RESULT_SCHEMA_VERSION =
  "ti-scale.autonomous-full-tcp-baseline-result.v1" as const;
export const AUTONOMOUS_FULL_TCP_BASELINE_READINESS_SCHEMA_VERSION =
  "ti-scale.autonomous-full-tcp-baseline-readiness.v1" as const;
export const AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION =
  "ti-scale.autonomous-full-tcp-normalizer.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const MAX_STRUCTURED_RESULT_BYTES = 2 * 1024 * 1024;

export interface AutonomousFullTcpAuthorizationReceipt {
  readonly schemaVersion: typeof AUTONOMOUS_FULL_TCP_AUTHORIZATION_SCHEMA_VERSION;
  readonly missionId: string;
  readonly runId: string;
  readonly contractId: string;
  readonly contractHash: string;
  readonly journey: "autonomous";
  readonly controlPlane: "ti_scale";
  readonly authorizationStatus: "verified";
  readonly contractState: "confirmed";
  readonly actionClassId: typeof AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS;
  readonly exactAllowedTargets: readonly [string];
  readonly prohibitedTargets: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly receiptSha256: string;
}

export interface AutonomousFullTcpArtifact {
  readonly kind: "raw_stdout" | "raw_stderr" | "structured_result";
  readonly phase: "discovery" | "service_version" | "result";
  readonly batch: number | null;
  readonly relativePath: string;
  readonly logicalPath: string;
  readonly sha256: string;
  readonly sizeBytes: number;
}

export interface AutonomousFullTcpOpenPort {
  readonly port: number;
  readonly transport: "tcp";
  readonly state: "open";
  readonly service: string | null;
  readonly version: string | null;
}

export interface AutonomousFullTcpNormalizedDiscovery {
  readonly normalizerVersion: typeof AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION;
  readonly target: string;
  readonly scannedPortRange: "1-65535";
  readonly hostReportedUp: true;
  readonly scanCompleted: true;
  readonly openPorts: readonly number[];
}

export interface AutonomousFullTcpNormalizedServiceBatch {
  readonly normalizerVersion: typeof AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION;
  readonly target: string;
  readonly batch: number;
  readonly requestedPorts: readonly number[];
  readonly hostReportedUp: true;
  readonly scanCompleted: true;
  readonly openPorts: readonly AutonomousFullTcpOpenPort[];
}

export interface AutonomousFullTcpBaselineResult {
  readonly schemaVersion: typeof AUTONOMOUS_FULL_TCP_BASELINE_RESULT_SCHEMA_VERSION;
  readonly status: "completed";
  readonly missionId: string;
  readonly runId: string;
  readonly actionId: string;
  readonly actionFingerprint: string;
  readonly contractId: string;
  readonly contractHash: string;
  readonly target: string;
  readonly policyId: string;
  readonly bindingId: string;
  readonly manifestSha256: string;
  readonly executable: Readonly<{
    readonly path: typeof AUTONOMOUS_FULL_TCP_NMAP_PATH;
    readonly sha256: typeof AUTONOMOUS_FULL_TCP_NMAP_SHA256;
    readonly fileCapabilities: "none";
  }>;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly wallClockMs: number;
  readonly discovery: Readonly<{
    readonly invocationId: string;
    readonly argv: readonly string[];
    readonly normalized: AutonomousFullTcpNormalizedDiscovery;
  }>;
  readonly serviceVersionBatches: readonly Readonly<{
    readonly invocationId: string;
    readonly argv: readonly string[];
    readonly normalized: AutonomousFullTcpNormalizedServiceBatch;
  }>[];
  readonly ports: readonly AutonomousFullTcpOpenPort[];
  readonly discoveredOpenPortCount: number;
  readonly versionedOpenPortCount: number;
  readonly portsNoLongerOpenAtVersionScan: readonly number[];
  readonly artifacts: readonly AutonomousFullTcpArtifact[];
  readonly verification: Readonly<{
    readonly state: "verified";
    readonly verifierVersion: typeof AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION;
    readonly exactTargetMatched: true;
    readonly fullRangeDiscoveryCompleted: true;
    readonly discoveredPortCoverageComplete: true;
    readonly processResultsComplete: true;
    readonly outputWithinBound: true;
  }>;
  readonly evidence: Readonly<{
    readonly eligibleForExplicitPromotion: true;
    readonly automaticallyPromoted: false;
    readonly evidenceIds: readonly [];
    readonly explanation: string;
  }>;
  readonly resultSha256: string;
}

export interface AutonomousFullTcpBaselineReadinessReceipt {
  readonly schemaVersion: typeof AUTONOMOUS_FULL_TCP_BASELINE_READINESS_SCHEMA_VERSION;
  readonly status: "ready";
  readonly policySchemaVersion: typeof AUTONOMOUS_FULL_TCP_BASELINE_POLICY_SCHEMA_VERSION;
  readonly manifestSha256: string;
  readonly adapterReceiptSha256: string;
  readonly toolIds: readonly [
    typeof AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
    typeof AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  ];
  readonly boundary: Readonly<{
    readonly directArgv: true;
    readonly shell: false;
    readonly capabilityFreePinnedExecutable: true;
    readonly workspaceConfined: true;
    readonly boundedOutput: true;
    readonly cooperativeCancellation: true;
    readonly processGroupCleanup: true;
    readonly targetContact: false;
  }>;
  readonly observedAt: string;
  readonly expiresAt: string;
}

export interface ReviewedFullTcpBaselineInvocationAdapter
  extends ReviewedLocalProcessInvocationAdapter {
  readinessReceipt(now?: Date, ttlMs?: number): Promise<LocalProcessAdapterReadinessReceipt>;
}

export interface AutonomousFullTcpBaselineExecutionOptions {
  readonly manifest: LocalToolCapabilityManifest;
  readonly configuration: AutonomousFullTcpBaselineConfiguration;
  readonly adapter: ReviewedFullTcpBaselineInvocationAdapter;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly now?: () => Date;
}

export interface AutonomousFullTcpBaselineExecutionInput {
  readonly action: DurableAction;
  readonly authorization: AutonomousFullTcpAuthorizationReceipt;
}

export class AutonomousFullTcpBaselineError extends Error {
  constructor(
    readonly code: string,
    readonly phase: "authorization" | "readiness" | "workspace" | "discovery" | "service_version" | "verification" | "artifact" | "cancellation",
    message: string,
    readonly remediation: string,
    readonly retryable = false,
  ) {
    super(message);
    this.name = "AutonomousFullTcpBaselineError";
  }
}

function validTimestamp(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function inside(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

function boundedText(value: string, maximum: number): string {
  const normalized = value.trim().replace(/\s+/gu, " ");
  return normalized.length <= maximum ? normalized : `${normalized.slice(0, maximum - 1)}…`;
}

function resultOutputSha256(result: Pick<LocalProcessToolResult, "stdout" | "stderr">): string {
  return createHash("sha256")
    .update(result.stdout, "utf8")
    .update("\u0000", "utf8")
    .update(result.stderr, "utf8")
    .digest("hex");
}

function authorizationBody(
  value: Omit<AutonomousFullTcpAuthorizationReceipt, "receiptSha256">,
): Omit<AutonomousFullTcpAuthorizationReceipt, "receiptSha256"> {
  return value;
}

export function createAutonomousFullTcpAuthorizationReceipt(
  input: Omit<AutonomousFullTcpAuthorizationReceipt, "schemaVersion" | "journey" | "controlPlane" | "authorizationStatus" | "contractState" | "actionClassId" | "receiptSha256">,
): AutonomousFullTcpAuthorizationReceipt {
  if (input.exactAllowedTargets.length !== 1) {
    throw new TypeError("Full-TCP authorization requires one exact normalized IP address or hostname");
  }
  const exactTarget = normalizeAutonomousIpHost(input.exactAllowedTargets[0]);
  if (exactTarget !== input.exactAllowedTargets[0]) {
    throw new TypeError("Full-TCP authorization requires one exact normalized IP address or hostname");
  }
  const prohibitedTargets = input.prohibitedTargets.map((value) => normalizeAutonomousIpHost(value));
  if (prohibitedTargets.some((value, index) => value !== input.prohibitedTargets[index])
    || new Set(prohibitedTargets).size !== prohibitedTargets.length) {
    throw new TypeError("Full-TCP prohibited targets must be unique normalized hosts");
  }
  const body = authorizationBody({
    schemaVersion: AUTONOMOUS_FULL_TCP_AUTHORIZATION_SCHEMA_VERSION,
    missionId: input.missionId,
    runId: input.runId,
    contractId: input.contractId,
    contractHash: input.contractHash,
    journey: "autonomous",
    controlPlane: "ti_scale",
    authorizationStatus: "verified",
    contractState: "confirmed",
    actionClassId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
    exactAllowedTargets: Object.freeze([exactTarget]),
    prohibitedTargets: Object.freeze(prohibitedTargets),
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
  });
  return deepFreeze({
    ...body,
    receiptSha256: digestCanonicalJson(body, { maxBytes: 64 * 1_024, maxDepth: 12 }).sha256,
  });
}

function assertAuthorization(
  action: DurableAction,
  receipt: AutonomousFullTcpAuthorizationReceipt,
  now: Date,
): string {
  const { receiptSha256: _receiptSha256, ...body } = receipt;
  const issuedAt = validTimestamp(receipt.issuedAt);
  const expiresAt = validTimestamp(receipt.expiresAt);
  if (receipt.schemaVersion !== AUTONOMOUS_FULL_TCP_AUTHORIZATION_SCHEMA_VERSION
    || digestCanonicalJson(body, { maxBytes: 64 * 1_024, maxDepth: 12 }).sha256 !== receipt.receiptSha256
    || receipt.missionId !== action.missionId
    || receipt.runId !== action.runId
    || receipt.contractId !== action.contractId
    || !SHA256.test(receipt.contractHash)
    || receipt.journey !== "autonomous"
    || receipt.controlPlane !== "ti_scale"
    || receipt.authorizationStatus !== "verified"
    || receipt.contractState !== "confirmed"
    || receipt.actionClassId !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS
    || receipt.exactAllowedTargets.length !== 1
    || issuedAt === null || expiresAt === null
    || issuedAt > now.getTime() || expiresAt <= now.getTime()) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_authorization_invalid",
      "authorization",
      "The full-TCP action is not bound to one fresh, confirmed Autonomous authorization receipt.",
      "Refresh the canonical mission/run/contract authorization receipt; do not bypass it.",
    );
  }
  let target: string;
  try {
    target = normalizeAutonomousIpHost(action.target);
  } catch {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_target_not_single_host",
      "authorization",
      "The full-TCP action target is not one exact IP address or hostname.",
      "Create a separate run for each exact host; CIDRs, ranges, URLs, and batches are not accepted.",
    );
  }
  if (target !== action.target || target !== receipt.exactAllowedTargets[0]
    || receipt.prohibitedTargets.some((value) => {
      try { return normalizeAutonomousIpHost(value) === target; } catch { return false; }
    })
    || action.actionType !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE
    || action.actionClass !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS
    || action.kind !== "tool" || action.status !== "running"
    || action.destructive || !action.idempotent) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_action_boundary_mismatch",
      "authorization",
      "The action, exact target, or contract scope differs from the reviewed full-TCP authorization.",
      "Discard this action and create a new canonical action from the distinct full-TCP baseline policy.",
    );
  }
  return target;
}

function reportTargets(text: string): readonly string[] {
  return [...text.matchAll(/^Nmap scan report for\s+(.+)$/gimu)].flatMap((match) => {
    const value = match[1]?.trim() ?? "";
    const parsed = value.match(/^([^\s()]+)(?:\s+\(([^)]+)\))?$/u);
    return parsed ? [parsed[1], parsed[2]].filter((item): item is string => Boolean(item)) : [];
  });
}

function exactOneTargetCompletion(text: string, target: string): boolean {
  const reports = [...text.matchAll(/^Nmap scan report for\s+(.+)$/gimu)];
  const completions = [...text.matchAll(
    /^Nmap done:\s+1 IP address \(1 host up\) scanned in\s+[\d.]+\s+seconds$/gimu,
  )];
  const hostUpCount = (text.match(/^Host is up(?:\s|\.)/gimu) ?? []).length;
  const attributable = reportTargets(text).some((value) => {
    try { return normalizeAutonomousIpHost(value) === target; } catch { return false; }
  });
  return reports.length === 1 && completions.length === 1 && hostUpCount === 1 && attributable;
}

function processResultComplete(
  result: LocalProcessToolResult,
  toolId: string,
): boolean {
  return result.toolId === toolId
    && result.exitCode === 0
    && result.signal === null
    && result.termination === "exited"
    && result.spawnErrorCode === null
    && !result.outputTruncated
    && result.observedOutputBytes <= result.retainedOutputBytes
    && result.outputSha256 === resultOutputSha256(result)
    && result.executable.sourcePath === AUTONOMOUS_FULL_TCP_NMAP_PATH
    && result.executable.sourceSha256 === AUTONOMOUS_FULL_TCP_NMAP_SHA256
    && result.executable.snapshotSha256 === AUTONOMOUS_FULL_TCP_NMAP_SHA256
    && result.sandbox.shell === false;
}

function parsePortRows(text: string): readonly Readonly<{
  port: number;
  state: string;
  service: string | null;
  version: string | null;
}>[] {
  const rows = text.split(/\r?\n/gu).flatMap((line) => {
    const match = line.trim().match(
      /^(\d{1,5})\/tcp\s+(\S{1,40})(?:\s+(\S{1,120}))?(?:\s+([^\u0000-\u001F\u007F]{1,500}))?$/u,
    );
    if (!match?.[1] || !match[2]) return [];
    const port = Number(match[1]);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) return [];
    return [{
      port,
      state: match[2],
      service: match[3] ? boundedText(match[3], 120) : null,
      version: match[4] ? boundedText(match[4], 500) : null,
    }];
  });
  return rows;
}

export function normalizeAutonomousFullTcpDiscovery(
  target: string,
  result: LocalProcessToolResult,
): AutonomousFullTcpNormalizedDiscovery {
  const expected = normalizeAutonomousIpHost(target);
  const text = `${result.stdout}\n${result.stderr}`.replaceAll("\r\n", "\n");
  const rows = parsePortRows(text);
  const ports = rows.map(({ port }) => port).sort((left, right) => left - right);
  if (!processResultComplete(result, AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID)
    || !exactOneTargetCompletion(text, expected)
    || rows.some(({ state }) => state !== "open")
    || new Set(ports).size !== ports.length) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_discovery_output_unverified",
      "verification",
      "The full-range discovery output was incomplete, ambiguous, truncated, or not attributable to the exact host.",
      "Retain the raw artifact and review the installed Nmap format before creating a new bounded attempt.",
    );
  }
  return deepFreeze({
    normalizerVersion: AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION,
    target: expected,
    scannedPortRange: "1-65535" as const,
    hostReportedUp: true as const,
    scanCompleted: true as const,
    openPorts: ports,
  });
}

export function normalizeAutonomousFullTcpServiceBatch(
  target: string,
  batch: number,
  requestedPorts: readonly number[],
  result: LocalProcessToolResult,
): AutonomousFullTcpNormalizedServiceBatch {
  const expected = normalizeAutonomousIpHost(target);
  const text = `${result.stdout}\n${result.stderr}`.replaceAll("\r\n", "\n");
  const rows = parsePortRows(text);
  const requested = [...requestedPorts].sort((left, right) => left - right);
  const ports = rows.map(({ port }) => port).sort((left, right) => left - right);
  if (!Number.isSafeInteger(batch) || batch < 1
    || requested.length < 1
    || requested.length > AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH
    || new Set(requested).size !== requested.length
    || requested.some((port, index) => !Number.isSafeInteger(port) || port < 1 || port > 65_535
      || (index > 0 && port <= requested[index - 1]!))
    || !processResultComplete(result, AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID)
    || !exactOneTargetCompletion(text, expected)
    || rows.some(({ state, port }) => state !== "open" || !requested.includes(port))
    || new Set(ports).size !== ports.length) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_service_output_unverified",
      "verification",
      "A service/version batch was incomplete, ambiguous, truncated, or reported a port outside the discovered set.",
      "Retain the raw artifact and retry only from a new bounded action after reviewing the conflict.",
    );
  }
  return deepFreeze({
    normalizerVersion: AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION,
    target: expected,
    batch,
    requestedPorts: requested,
    hostReportedUp: true as const,
    scanCompleted: true as const,
    openPorts: rows
      .map(({ port, service, version }) => ({
        port,
        transport: "tcp" as const,
        state: "open" as const,
        service,
        version,
      }))
      .sort((left, right) => left.port - right.port),
  });
}

export function verifyAutonomousFullTcpBaseline(input: Readonly<{
  readonly target: string;
  readonly discovery: AutonomousFullTcpNormalizedDiscovery;
  readonly serviceBatches: readonly AutonomousFullTcpNormalizedServiceBatch[];
  readonly processResults: readonly LocalProcessToolResult[];
}>): AutonomousFullTcpBaselineResult["verification"] {
  const target = normalizeAutonomousIpHost(input.target);
  const discovered = input.discovery.openPorts;
  const requested = input.serviceBatches.flatMap(({ requestedPorts }) => requestedPorts);
  const requiredBatchCount = Math.ceil(discovered.length / AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH);
  const outputBytes = input.processResults.reduce((total, result) => total + result.observedOutputBytes, 0);
  if (input.discovery.target !== target
    || input.discovery.scannedPortRange !== "1-65535"
    || input.serviceBatches.length !== requiredBatchCount
    || input.serviceBatches.length > AUTONOMOUS_FULL_TCP_MAX_VERSION_BATCHES
    || input.serviceBatches.some(({ target: batchTarget }, index) => batchTarget !== target
      || input.serviceBatches[index]?.batch !== index + 1)
    || requested.length !== discovered.length
    || requested.some((port, index) => port !== discovered[index])
    || input.processResults.length !== 1 + input.serviceBatches.length
    || outputBytes > AUTONOMOUS_FULL_TCP_MAX_TOTAL_OUTPUT_BYTES) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_baseline_verification_failed",
      "verification",
      "The two-phase baseline did not cover the exact discovered port set within its reviewed output bound.",
      "Do not promote evidence. Retain the raw artifacts and start a new bounded action after resolving the mismatch.",
    );
  }
  return deepFreeze({
    state: "verified" as const,
    verifierVersion: AUTONOMOUS_FULL_TCP_NORMALIZER_VERSION,
    exactTargetMatched: true as const,
    fullRangeDiscoveryCompleted: true as const,
    discoveredPortCoverageComplete: true as const,
    processResultsComplete: true as const,
    outputWithinBound: true as const,
  });
}

interface PendingResult {
  resolve(result: LocalProcessToolResult): void;
  reject(error: unknown): void;
}

class ProcessResultCollector implements LocalProcessToolResultSink {
  private readonly pending = new Map<string, PendingResult>();

  waitFor(
    invocation: LocalProcessToolInvocation,
    adapter: ReviewedLocalProcessInvocationAdapter,
    signal: AbortSignal,
  ): Promise<LocalProcessToolResult> {
    if (this.pending.has(invocation.invocationId)) {
      throw new Error("Duplicate full-TCP invocation waiter");
    }
    return new Promise<LocalProcessToolResult>((resolveResult, rejectResult) => {
      let settled = false;
      const settle = (callback: () => void) => {
        if (settled) return;
        settled = true;
        this.pending.delete(invocation.invocationId);
        signal.removeEventListener("abort", abort);
        callback();
      };
      const abort = () => {
        void adapter.cancelRun(invocation.action.runId, "Full-TCP baseline cancellation requested")
          .finally(() => settle(() => rejectResult(new DOMException(
            "Full-TCP baseline was cancelled",
            "AbortError",
          ))));
      };
      this.pending.set(invocation.invocationId, {
        resolve: (result) => settle(() => resolveResult(result)),
        reject: (error) => settle(() => rejectResult(error)),
      });
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) {
        abort();
        return;
      }
      void adapter.dispatch(invocation, signal).catch((error) => {
        settle(() => rejectResult(error));
      });
    });
  }

  async acceptLocalProcessToolResult(result: LocalProcessToolResult): Promise<void> {
    const waiter = this.pending.get(result.invocationId);
    if (!waiter) throw new Error("Unexpected full-TCP process result");
    waiter.resolve(result);
  }

  get size(): number {
    return this.pending.size;
  }
}

function invocationId(actionId: string, phase: string): string {
  return `full_tcp_${createHash("sha256").update(`${actionId}\u0000${phase}`, "utf8").digest("hex").slice(0, 40)}`;
}

function compileChecked(
  manifest: LocalToolCapabilityManifest,
  toolId: string,
  parameters: Readonly<Record<string, unknown>>,
): CompiledLocalToolInvocation {
  const compiled = manifest.compileInvocation(toolId, parameters);
  if (compiled.executablePath !== AUTONOMOUS_FULL_TCP_NMAP_PATH
    || compiled.expectedExecutableSha256 !== AUTONOMOUS_FULL_TCP_NMAP_SHA256
    || compiled.shell !== false
    || compiled.authorizationGranted !== false
    || compiled.scopeEnforcementRequired !== true) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_compiler_boundary_invalid",
      "readiness",
      "The compiled Nmap invocation differs from the reviewed capability-free direct-argv boundary.",
      "Restore the reviewed manifest; do not execute this action.",
    );
  }
  return compiled;
}

function splitPorts(ports: readonly number[]): readonly (readonly number[])[] {
  const result: number[][] = [];
  for (let index = 0; index < ports.length; index += AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH) {
    result.push(ports.slice(index, index + AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH));
  }
  if (result.length > AUTONOMOUS_FULL_TCP_MAX_VERSION_BATCHES) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_service_batch_bound_exceeded",
      "service_version",
      "The discovered port set exceeds the reviewed service-version batch bound.",
      "Safe-stop and create a separately reviewed strategy; do not truncate the discovered ports.",
    );
  }
  return result;
}

async function safeDirectory(root: string, name: "scans"): Promise<string> {
  const path = join(root, name);
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  const metadata = await lstat(path);
  const canonical = await realpath(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory() || !inside(root, canonical)) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_artifact_directory_unsafe",
      "artifact",
      "The engagement scans directory is linked, not a directory, or escapes the resolved workspace.",
      "Repair the workspace path before a new action; do not write artifacts elsewhere.",
    );
  }
  return canonical;
}

async function createRunArtifactDirectory(
  root: string,
  action: DurableAction,
  startedAt: Date,
): Promise<string> {
  const scans = await safeDirectory(root, "scans");
  const timestamp = startedAt.toISOString().replace(/[-:]/gu, "").replace(/\.\d{3}Z$/u, "Z");
  const suffix = createHash("sha256").update(action.id, "utf8").digest("hex").slice(0, 10);
  for (let ordinal = 0; ordinal < 100; ordinal += 1) {
    const name = `${timestamp}_full_tcp_baseline_${suffix}${ordinal === 0 ? "" : `_${ordinal}`}`;
    const candidate = join(scans, name);
    try {
      await mkdir(candidate, { mode: 0o700 });
      const canonical = await realpath(candidate);
      if (!inside(root, canonical)) throw new Error("artifact directory escaped workspace");
      return canonical;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }
  throw new AutonomousFullTcpBaselineError(
    "full_tcp_artifact_name_exhausted",
    "artifact",
    "Ti-Scale could not allocate a unique timestamped artifact directory without overwriting data.",
    "Inspect the engagement scans directory and retry with a new action identity.",
  );
}

async function writeArtifact(input: Readonly<{
  root: string;
  directory: string;
  logicalWorkspace: string;
  filename: string;
  content: string;
  kind: AutonomousFullTcpArtifact["kind"];
  phase: AutonomousFullTcpArtifact["phase"];
  batch: number | null;
}>): Promise<AutonomousFullTcpArtifact> {
  if (!/^[A-Za-z0-9._-]{1,160}$/u.test(input.filename)) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_artifact_name_invalid",
      "artifact",
      "A generated artifact filename was outside the fixed safe grammar.",
      "Repair the source-only artifact naming rule before activation.",
    );
  }
  const path = resolve(input.directory, input.filename);
  if (!inside(input.root, path)) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_artifact_path_escape",
      "artifact",
      "A generated artifact path escaped the resolved engagement workspace.",
      "Do not retry until the workspace mapping is repaired.",
    );
  }
  const bytes = Buffer.from(input.content, "utf8");
  const handle = await open(
    path,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const relativePath = relative(input.root, path);
  if (!relativePath || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
    throw new AutonomousFullTcpBaselineError(
      "full_tcp_artifact_relative_path_invalid",
      "artifact",
      "The stored artifact could not be represented inside the logical engagement workspace.",
      "Inspect the workspace mapping before a new action.",
    );
  }
  return deepFreeze({
    kind: input.kind,
    phase: input.phase,
    batch: input.batch,
    relativePath,
    logicalPath: join(input.logicalWorkspace, relativePath),
    sha256: createHash("sha256").update(bytes).digest("hex"),
    sizeBytes: bytes.length,
  });
}

function processInvocation(
  action: DurableAction,
  toolId: string,
  phase: string,
  parameters: Readonly<Record<string, unknown>>,
  resolvedWorkspacePath: string,
): LocalProcessToolInvocation {
  return deepFreeze({
    schemaVersion: "ti-scale.local-process-tool-invocation.v1" as const,
    invocationId: invocationId(action.id, phase),
    action,
    toolId,
    parameters,
    inputSha256: digestCanonicalJson(parameters, { maxBytes: 64 * 1_024, maxDepth: 12 }).sha256,
    resolvedWorkspacePath,
  });
}

export class AutonomousFullTcpBaselineExecution {
  readonly policy: AutonomousFullTcpBaselinePolicy;
  private readonly now: () => Date;
  private readonly collector = new ProcessResultCollector();
  private readonly unbind: () => void;
  private closed = false;

  constructor(private readonly options: AutonomousFullTcpBaselineExecutionOptions) {
    this.policy = createAutonomousFullTcpBaselinePolicy(options.configuration, options.manifest);
    this.now = options.now ?? (() => new Date());
    this.unbind = options.adapter.bindResultSink(this.collector) as () => void;
  }

  async readiness(now = this.now()): Promise<AutonomousFullTcpBaselineReadinessReceipt> {
    if (this.closed) throw new Error("Full-TCP baseline execution is closed");
    const adapter = await this.options.adapter.readinessReceipt(now, 60_000);
    const toolIds = adapter.tools.map(({ toolId }) => toolId).sort();
    const expected = [AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID, AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID].sort();
    const exactToolReceipts = adapter.tools.every((receipt) => {
      const tool = this.options.manifest.resolve(receipt.toolId);
      return Boolean(tool
        && receipt.bindingSha256 === tool.bindingSha256
        && receipt.expectedExecutableSha256 === AUTONOMOUS_FULL_TCP_NMAP_SHA256
        && SHA256.test(receipt.installationReceiptSha256));
    });
    if (adapter.manifestSha256 !== this.options.manifest.descriptor.manifestSha256
      || toolIds.join("\u0000") !== expected.join("\u0000")
      || !exactToolReceipts
      || adapter.boundary.directArgv !== true
      || adapter.boundary.shell !== false
      || adapter.boundary.workspaceResolver !== true
      || adapter.boundary.totalOutputBound !== true
      || adapter.boundary.cooperativeCancellation !== true
      || adapter.boundary.processGroupCleanup !== true
      || adapter.boundary.targetContact !== false) {
      throw new AutonomousFullTcpBaselineError(
        "full_tcp_adapter_readiness_invalid",
        "readiness",
        "The full-TCP process adapter did not attest every reviewed local boundary.",
        "Restore direct-argv, workspace, output, and process-group cancellation readiness before activation.",
      );
    }
    return deepFreeze({
      schemaVersion: AUTONOMOUS_FULL_TCP_BASELINE_READINESS_SCHEMA_VERSION,
      status: "ready" as const,
      policySchemaVersion: AUTONOMOUS_FULL_TCP_BASELINE_POLICY_SCHEMA_VERSION,
      manifestSha256: adapter.manifestSha256,
      adapterReceiptSha256: adapter.receiptSha256,
      toolIds: [AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID, AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID],
      boundary: {
        directArgv: true as const,
        shell: false as const,
        capabilityFreePinnedExecutable: true as const,
        workspaceConfined: true as const,
        boundedOutput: true as const,
        cooperativeCancellation: true as const,
        processGroupCleanup: true as const,
        targetContact: false as const,
      },
      observedAt: adapter.observedAt,
      expiresAt: adapter.expiresAt,
    });
  }

  async execute(
    input: AutonomousFullTcpBaselineExecutionInput,
    signal: AbortSignal,
  ): Promise<AutonomousFullTcpBaselineResult> {
    if (this.closed) throw new Error("Full-TCP baseline execution is closed");
    if (this.collector.size > 0) {
      throw new AutonomousFullTcpBaselineError(
        "full_tcp_execution_busy",
        "readiness",
        "This reviewed composite adapter is already executing a full-TCP action.",
        "Wait for the active action or provision a separately attested adapter instance.",
        true,
      );
    }
    const started = this.now();
    const target = assertAuthorization(input.action, input.authorization, started);
    const workspace = await this.options.workspaceResolver.resolve(this.policy.logicalWorkspace);
    if (workspace.status !== "resolved" || !workspace.resolvedPath) {
      throw new AutonomousFullTcpBaselineError(
        `full_tcp_workspace_${workspace.code}`,
        "workspace",
        workspace.explanation,
        workspace.remediation ?? "Restore the reviewed workspace mapping before retrying.",
      );
    }
    const canonicalWorkspace = await realpath(workspace.resolvedPath);
    if (canonicalWorkspace !== workspace.resolvedPath) {
      throw new AutonomousFullTcpBaselineError(
        "full_tcp_workspace_identity_changed",
        "workspace",
        "The resolved workspace identity changed before execution.",
        "Resolve the workspace again after repairing the path.",
      );
    }
    const artifactDirectory = await createRunArtifactDirectory(canonicalWorkspace, input.action, started);
    const artifacts: AutonomousFullTcpArtifact[] = [];
    const processResults: LocalProcessToolResult[] = [];
    const combined = new AbortController();
    let deadlineExpired = false;
    const forwardAbort = () => combined.abort(signal.reason ?? "Operator cancellation requested");
    signal.addEventListener("abort", forwardAbort, { once: true });
    if (signal.aborted) forwardAbort();
    const timeout = setTimeout(() => {
      deadlineExpired = true;
      combined.abort("Full-TCP baseline wall-clock budget expired");
    }, AUTONOMOUS_FULL_TCP_MAX_WALL_CLOCK_MS);
    timeout.unref?.();

    try {
      const discoveryParameters = deepFreeze({
        workspace: this.policy.logicalWorkspace,
        target,
      });
      const discoveryCompiled = compileChecked(
        this.options.manifest,
        AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
        discoveryParameters,
      );
      const discoveryInvocation = processInvocation(
        input.action,
        AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
        "discovery",
        discoveryParameters,
        canonicalWorkspace,
      );
      const discoveryResult = await this.collector.waitFor(
        discoveryInvocation,
        this.options.adapter,
        combined.signal,
      );
      processResults.push(discoveryResult);
      artifacts.push(await writeArtifact({
        root: canonicalWorkspace,
        directory: artifactDirectory,
        logicalWorkspace: this.policy.logicalWorkspace,
        filename: "discovery.stdout.nmap.txt",
        content: discoveryResult.stdout,
        kind: "raw_stdout",
        phase: "discovery",
        batch: null,
      }), await writeArtifact({
        root: canonicalWorkspace,
        directory: artifactDirectory,
        logicalWorkspace: this.policy.logicalWorkspace,
        filename: "discovery.stderr.log",
        content: discoveryResult.stderr,
        kind: "raw_stderr",
        phase: "discovery",
        batch: null,
      }));
      const discovery = normalizeAutonomousFullTcpDiscovery(target, discoveryResult);
      const serviceBatches: {
        invocationId: string;
        argv: readonly string[];
        normalized: AutonomousFullTcpNormalizedServiceBatch;
      }[] = [];
      const batches = splitPorts(discovery.openPorts);
      for (let index = 0; index < batches.length; index += 1) {
        if (combined.signal.aborted) throw new DOMException("Full-TCP baseline cancelled", "AbortError");
        const batch = batches[index]!;
        const ordinal = index + 1;
        const ports = batch.join(",");
        const parameters = deepFreeze({
          workspace: this.policy.logicalWorkspace,
          target,
          ports,
        });
        const compiled = compileChecked(
          this.options.manifest,
          AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
          parameters,
        );
        const invocation = processInvocation(
          input.action,
          AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
          `service-${ordinal}`,
          parameters,
          canonicalWorkspace,
        );
        const result = await this.collector.waitFor(invocation, this.options.adapter, combined.signal);
        processResults.push(result);
        const filenameOrdinal = String(ordinal).padStart(3, "0");
        artifacts.push(await writeArtifact({
          root: canonicalWorkspace,
          directory: artifactDirectory,
          logicalWorkspace: this.policy.logicalWorkspace,
          filename: `service-${filenameOrdinal}.stdout.nmap.txt`,
          content: result.stdout,
          kind: "raw_stdout",
          phase: "service_version",
          batch: ordinal,
        }), await writeArtifact({
          root: canonicalWorkspace,
          directory: artifactDirectory,
          logicalWorkspace: this.policy.logicalWorkspace,
          filename: `service-${filenameOrdinal}.stderr.log`,
          content: result.stderr,
          kind: "raw_stderr",
          phase: "service_version",
          batch: ordinal,
        }));
        serviceBatches.push({
          invocationId: invocation.invocationId,
          argv: compiled.arguments,
          normalized: normalizeAutonomousFullTcpServiceBatch(target, ordinal, batch, result),
        });
        const totalOutput = processResults.reduce((total, item) => total + item.observedOutputBytes, 0);
        if (totalOutput > AUTONOMOUS_FULL_TCP_MAX_TOTAL_OUTPUT_BYTES) {
          throw new AutonomousFullTcpBaselineError(
            "full_tcp_total_output_bound_exceeded",
            "service_version",
            "The combined full-TCP output exceeded the reviewed 32 MiB bound.",
            "Safe-stop and review the raw artifacts; do not truncate or auto-promote the result.",
          );
        }
      }
      const verification = verifyAutonomousFullTcpBaseline({
        target,
        discovery,
        serviceBatches: serviceBatches.map(({ normalized }) => normalized),
        processResults,
      });
      const portsByNumber = new Map<number, AutonomousFullTcpOpenPort>();
      for (const port of discovery.openPorts) {
        portsByNumber.set(port, {
          port,
          transport: "tcp",
          state: "open",
          service: null,
          version: null,
        });
      }
      for (const service of serviceBatches.flatMap(({ normalized }) => normalized.openPorts)) {
        portsByNumber.set(service.port, service);
      }
      const serviceOpen = new Set(serviceBatches.flatMap(({ normalized }) =>
        normalized.openPorts.map(({ port }) => port)));
      const ended = this.now();
      const unsigned = {
        schemaVersion: AUTONOMOUS_FULL_TCP_BASELINE_RESULT_SCHEMA_VERSION,
        status: "completed" as const,
        missionId: input.action.missionId,
        runId: input.action.runId,
        actionId: input.action.id,
        actionFingerprint: input.action.fingerprint,
        contractId: input.authorization.contractId,
        contractHash: input.authorization.contractHash,
        target,
        policyId: this.policy.policyId,
        bindingId: this.policy.bindingId,
        manifestSha256: this.options.manifest.descriptor.manifestSha256,
        executable: {
          path: AUTONOMOUS_FULL_TCP_NMAP_PATH,
          sha256: AUTONOMOUS_FULL_TCP_NMAP_SHA256,
          fileCapabilities: "none" as const,
        },
        startedAt: started.toISOString(),
        endedAt: ended.toISOString(),
        wallClockMs: Math.max(0, ended.getTime() - started.getTime()),
        discovery: {
          invocationId: discoveryInvocation.invocationId,
          argv: discoveryCompiled.arguments,
          normalized: discovery,
        },
        serviceVersionBatches: serviceBatches,
        ports: [...portsByNumber.values()].sort((left, right) => left.port - right.port),
        discoveredOpenPortCount: discovery.openPorts.length,
        versionedOpenPortCount: serviceOpen.size,
        portsNoLongerOpenAtVersionScan: discovery.openPorts.filter((port) => !serviceOpen.has(port)),
        artifacts: [...artifacts],
        verification,
        evidence: {
          eligibleForExplicitPromotion: true as const,
          automaticallyPromoted: false as const,
          evidenceIds: [] as const,
          explanation: "The raw logs and structured result passed deterministic coverage checks. They remain unpromoted at this boundary until the attested general-runtime verifier rechecks canonical authority, artifact hashes, and criterion binding.",
        },
      };
      const resultSha256 = digestCanonicalJson(unsigned, {
        maxBytes: MAX_STRUCTURED_RESULT_BYTES,
        maxDepth: 24,
      }).sha256;
      const resultArtifact = await writeArtifact({
        root: canonicalWorkspace,
        directory: artifactDirectory,
        logicalWorkspace: this.policy.logicalWorkspace,
        filename: "baseline-result.json",
        content: `${JSON.stringify({ ...unsigned, resultSha256 }, null, 2)}\n`,
        kind: "structured_result",
        phase: "result",
        batch: null,
      });
      return deepFreeze({
        ...unsigned,
        artifacts: [...artifacts, resultArtifact],
        resultSha256,
      });
    } catch (error) {
      if (combined.signal.aborted || error instanceof DOMException && error.name === "AbortError") {
        await this.options.adapter.cancelRun(input.action.runId, deadlineExpired
          ? "Full-TCP baseline wall-clock budget expired"
          : "Full-TCP baseline cancellation requested");
        throw new AutonomousFullTcpBaselineError(
          deadlineExpired ? "full_tcp_wall_clock_budget_exhausted" : "full_tcp_cancelled",
          "cancellation",
          deadlineExpired
            ? "The full-TCP baseline reached its reviewed wall-clock budget and all process groups were stopped."
            : "The full-TCP baseline was cancelled and all process groups were stopped.",
          deadlineExpired
            ? "Review the preserved artifacts and choose a new bounded run or narrower approved strategy."
            : "Start a new action only if the operator still wants this exact baseline.",
        );
      }
      throw error;
    } finally {
      clearTimeout(timeout);
      signal.removeEventListener("abort", forwardAbort);
    }
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    await this.options.adapter.cancelRun(runId, reason);
  }

  close(): void {
    if (this.collector.size > 0) {
      throw new Error("Cannot close full-TCP execution while an invocation is active");
    }
    if (!this.closed) this.unbind();
    this.closed = true;
  }
}
