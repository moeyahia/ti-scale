#!/usr/bin/env bun

import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { resolve } from "node:path";
import {
  AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE,
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
} from "../server/autonomous-runtime/AutonomousDnsSafeRecon";
import {
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
  AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE,
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
  AUTONOMOUS_SAFE_IP_RECON_DEFAULT_PORTS,
} from "../server/autonomous-runtime/AutonomousIpSafeRecon";
import {
  REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID,
  REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION,
} from "../server/local-tools/ReviewedLocalToolObservationNormalizer";
import {
  AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
} from "../server/domain";
import { exactNmapCapabilityAvailable } from "./release/AuthenticatedNmapActivationVerifier";
import { queryActiveV2Work } from "./release/FunctionalReleasePrimitives";

type JsonObject = Record<string, unknown>;

export const FUNCTIONAL_RUNTIME_PROOF_CONFIRMATION =
  "functional-runtime-proof-2026.07.20-v2" as const;
export const FUNCTIONAL_RUNTIME_PROOF_ORIGIN = "http://127.0.0.1:3132" as const;
export const FUNCTIONAL_RUNTIME_PROOF_TOKEN_PATH = "/etc/ti-scale/operator-token" as const;
export const FUNCTIONAL_RUNTIME_PROOF_DATABASE_PATH = "/var/lib/ti-scale/data/ti-scale.sqlite" as const;
const TOKEN_TRUST_ROOT = "/etc/ti-scale";
const MAX_RESPONSE_BYTES = 2 * 1_024 * 1_024;
const REQUEST_TIMEOUT_MS = 10_000;
const DECISION_TIMEOUT_MS = 30_000;
const RUN_TIMEOUT_MS = 180_000;
const BRAIN_PROJECTION_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 250;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;

export const EXPECTED_GUIDED_TOOL_IDS = Object.freeze([
  "kali:curl-http-metadata",
  "kali:ffuf-bounded-content-discovery",
  "kali:host-dns-query",
  "kali:ncat-tcp-connect",
  "kali:nmap-tcp-connect-service-scan",
  "kali:ping-host-liveness",
  "kali:whatweb-bounded-fingerprint",
] as const);

const EXPECTED_DEPENDENCY_SUFFIXES = Object.freeze([
  "operator-activation",
  "executable-integrity",
  "isolated-target-free-readiness",
  "direct-argv-adapter",
  "workspace-confinement",
  "result-sink",
  "cancellation",
] as const);

const EXACT_NMAP_TOOL_ID = "kali:nmap-tcp-connect-service-scan" as const;
const EXACT_GUIDED_TARGET = "127.0.0.1" as const;
const EXACT_GUIDED_PORT = 3_132 as const;
const EXACT_AUTONOMOUS_TARGET = "does-not-exist.invalid" as const;
const EXACT_AUTONOMOUS_IP_TARGET = "127.0.0.1" as const;

export const EXPECTED_AUTONOMOUS_ACTION_CLASS_IDS = Object.freeze([
  AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
] as const);

function object(value: unknown, label: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} was not a JSON object`);
  }
  return value as JsonObject;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} was not an array`);
  return value;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} was missing`);
  return value;
}

function integer(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} was not a non-negative integer`);
  }
  return Number(value);
}

function pick(root: JsonObject, path: readonly string[]): unknown {
  let current: unknown = root;
  for (const segment of path) current = object(current, path.join("."))[segment];
  return current;
}

function safeMessage(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const normalized = value.replace(/[\u0000-\u001f\u007f]/gu, " ").replace(/\s+/gu, " ").trim();
  return normalized ? normalized.slice(0, 500) : fallback;
}

function exactSet(actual: unknown[], expected: readonly string[], label: string): void {
  const values = actual.map((value) => text(value, `${label} entry`));
  if (new Set(values).size !== values.length
    || values.length !== expected.length
    || expected.some((value) => !values.includes(value))) {
    throw new Error(`${label} did not match the exact reviewed inventory`);
  }
}

function failedReadinessSummary(readiness: JsonObject, label: string): string {
  const failed = array(readiness.checks, `${label} checks`)
    .map((value) => object(value, `${label} check`))
    .filter((check) => check.status === "fail")
    .map((check) => {
      const id = safeMessage(check.id, "unknown_check");
      const impact = safeMessage(check.impact, "No impact explanation was returned");
      const remediation = safeMessage(check.remediation, "No remediation was returned");
      return `${id}: ${impact} Remediation: ${remediation}`;
    });
  return failed.length > 0
    ? failed.join(" | ")
    : `status=${safeMessage(readiness.status, "unknown")}`;
}

function exactIsoMilliseconds(value: unknown, label: string): number {
  const timestamp = text(value, label);
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== timestamp) {
    throw new Error(`${label} was not an exact ISO timestamp`);
  }
  return parsed;
}

function canonicalMemoryNodeId(
  prefix: "mem_mission" | "mem_run" | "mem_eval",
  canonicalId: string,
): string {
  const digest = createHash("sha256").update(canonicalId, "utf8").digest("hex");
  return `${prefix}_${digest.slice(0, 32)}`;
}

export function functionalRuntimeProofUsage(): string {
  return `bun run scripts/smoke-functional-runtime.ts --execute --confirm ${FUNCTIONAL_RUNTIME_PROOF_CONFIRMATION}`;
}

export function parseFunctionalRuntimeProofArguments(argv: readonly string[]): void {
  if (argv.length !== 3
    || argv[0] !== "--execute"
    || argv[1] !== "--confirm"
    || argv[2] !== FUNCTIONAL_RUNTIME_PROOF_CONFIRMATION) {
    throw new Error(
      `This proof creates three bounded local missions. Use the exact command: ${functionalRuntimeProofUsage()}`,
    );
  }
}

function validateTokenBuffer(bytes: Buffer): string {
  const bounded = bytes.length > 0 && bytes.at(-1) === 0x0a
    ? bytes.subarray(0, bytes.length - 1)
    : bytes;
  if (bounded.length < 24 || bounded.length > 4_096
    || bounded.includes(0x00) || bounded.includes(0x0a) || bounded.includes(0x0d)) {
    throw new Error("The root operator-token file has an invalid bounded value");
  }
  return bounded.toString("utf8");
}

async function withTrustedOperatorToken<T>(operation: (token: string) => Promise<T>): Promise<T> {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) {
    throw new Error("The production proof must run as root so it can read the private operator-token file");
  }
  const tokenPath = resolve(FUNCTIONAL_RUNTIME_PROOF_TOKEN_PATH);
  const trustRoot = resolve(TOKEN_TRUST_ROOT);
  if (tokenPath !== FUNCTIONAL_RUNTIME_PROOF_TOKEN_PATH
    || trustRoot !== TOKEN_TRUST_ROOT
    || tokenPath !== resolve(trustRoot, "operator-token")) {
    throw new Error("The production proof token path escaped its fixed trust root");
  }
  const root = lstatSync(trustRoot, { bigint: true });
  if (root.isSymbolicLink() || !root.isDirectory() || root.uid !== 0n || (root.mode & 0o022n) !== 0n) {
    throw new Error("The operator-token trust root is not a root-owned, non-writable directory");
  }
  const before = lstatSync(tokenPath, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile() || before.uid !== 0n
    || (before.mode & 0o077n) !== 0n || before.size < 24n || before.size > 4_097n) {
    throw new Error("The operator-token is not a private root-owned regular file");
  }
  const descriptor = openSync(tokenPath, constants.O_RDONLY | NO_FOLLOW);
  let bytes: Buffer | undefined;
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size
      || before.mtimeNs !== opened.mtimeNs || before.ctimeNs !== opened.ctimeNs) {
      throw new Error("The operator-token changed before it was read");
    }
    bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (opened.dev !== after.dev || opened.ino !== after.ino || opened.size !== after.size
      || opened.mtimeNs !== after.mtimeNs || opened.ctimeNs !== after.ctimeNs) {
      throw new Error("The operator-token changed while it was read");
    }
    return await operation(validateTokenBuffer(bytes));
  } finally {
    bytes?.fill(0);
    closeSync(descriptor);
  }
}

async function boundedJson(response: Response, label: string): Promise<JsonObject> {
  const advertised = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(advertised) && advertised > MAX_RESPONSE_BYTES) {
    throw new Error(`${label} exceeded the response-size boundary`);
  }
  if (!response.body) throw new Error(`${label} returned no response body`);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error(`${label} exceeded the response-size boundary`);
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), total);
  try {
    return object(JSON.parse(body.toString("utf8")) as unknown, label);
  } catch (error) {
    if (error instanceof Error && error.message.endsWith("was not a JSON object")) throw error;
    throw new Error(`${label} was not valid JSON`);
  } finally {
    body.fill(0);
  }
}

interface ProofClient {
  readonly request: (
    path: string,
    options?: Readonly<{
      method?: "GET" | "POST";
      body?: JsonObject;
      idempotencyKey?: string;
      expectedStatus?: 200 | 201;
    }>,
  ) => Promise<JsonObject>;
  readonly download: (
    path: string,
  ) => Promise<Readonly<{
    body: Buffer;
    contentType: string;
    contentDisposition: string;
    contentLength: number;
    digest: string;
  }>>;
}

function proofClient(token: string): ProofClient {
  return {
    async request(path, options = {}) {
      if (!path.startsWith("/api/v2/") || path.includes("\\") || path.includes("\u0000")) {
        throw new Error("The proof attempted to leave the fixed V2 API path");
      }
      const response = await fetch(new URL(path, FUNCTIONAL_RUNTIME_PROOF_ORIGIN), {
        method: options.method ?? "GET",
        redirect: "error",
        cache: "no-store",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          ...(options.body ? { "Content-Type": "application/json" } : {}),
          ...(options.idempotencyKey ? { "Idempotency-Key": options.idempotencyKey } : {}),
        },
        ...(options.body ? { body: JSON.stringify(options.body) } : {}),
      });
      const payload = await boundedJson(response, path);
      const expectedStatus = options.expectedStatus ?? 200;
      if (response.status !== expectedStatus) {
        const code = safeMessage(payload.code, "unknown_code");
        const explanation = safeMessage(payload.humanMessage, "No safe explanation was returned");
        throw new Error(`${path} failed (${response.status}, ${code}): ${explanation}`);
      }
      return payload;
    },
    async download(path) {
      if (!/^\/api\/v2\/reports\/[A-Za-z0-9._-]+\/download$/u.test(path)) {
        throw new Error("The proof attempted to download outside the fixed report-artifact route");
      }
      const response = await fetch(new URL(path, FUNCTIONAL_RUNTIME_PROOF_ORIGIN), {
        method: "GET",
        redirect: "error",
        cache: "no-store",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: {
          Accept: "application/json, text/markdown",
          Authorization: `Bearer ${token}`,
        },
      });
      if (response.status !== 200) {
        throw new Error(`${path} failed (${response.status}) without returning an integrity-verified report`);
      }
      const advertised = Number(response.headers.get("content-length") ?? "-1");
      if (!Number.isSafeInteger(advertised) || advertised < 1 || advertised > MAX_RESPONSE_BYTES) {
        throw new Error(`${path} returned an invalid or excessive report length`);
      }
      const bytes = Buffer.from(await response.arrayBuffer());
      if (bytes.length !== advertised) {
        bytes.fill(0);
        throw new Error(`${path} did not match its exact Content-Length`);
      }
      const contentType = response.headers.get("content-type") ?? "";
      const contentDisposition = response.headers.get("content-disposition") ?? "";
      const digest = response.headers.get("digest") ?? "";
      if (!/^attachment; filename="ti-scale-[A-Za-z0-9._-]+"$/u.test(contentDisposition)
        || response.headers.get("x-content-type-options") !== "nosniff"
        || response.headers.get("cross-origin-resource-policy") !== "same-origin"
        || response.headers.get("content-security-policy") !== "sandbox"
        || response.headers.get("cache-control") !== "no-store") {
        bytes.fill(0);
        throw new Error(`${path} did not return the exact inert-download security headers`);
      }
      return { body: bytes, contentType, contentDisposition, contentLength: advertised, digest };
    },
  };
}

function assertFreshCapabilityEntry(
  value: unknown,
  componentKind: "tool" | "tool_dependency",
  componentId: string,
  testKind: "local_executable_attestation" | "manifest_dependency",
  now: number,
): Readonly<{ observedAt: string; expiresAt: string }> {
  const entry = object(value, `${componentId} self-test`);
  const component = object(entry.component, `${componentId} self-test component`);
  const freshness = object(entry.freshness, `${componentId} self-test freshness`);
  const authorization = object(
    entry.executionAuthorization,
    `${componentId} self-test execution authorization`,
  );
  const observedAt = text(freshness.observedAt, `${componentId} observedAt`);
  const expiresAt = text(freshness.expiresAt, `${componentId} expiresAt`);
  const observed = exactIsoMilliseconds(observedAt, `${componentId} observedAt`);
  const expires = exactIsoMilliseconds(expiresAt, `${componentId} expiresAt`);
  if (component.kind !== componentKind || component.id !== componentId
    || entry.testKind !== testKind || entry.status !== "pass" || entry.availability !== "available"
    || freshness.state !== "fresh" || observed > now + 1_000 || expires <= now || expires <= observed
    || authorization.state !== "not_granted" || authorization.grantsMissionExecution !== false) {
    throw new Error(`${componentId} does not have an exact fresh non-authorizing readiness receipt`);
  }
  return { observedAt, expiresAt };
}

export function assertExactRuntimeReadiness(
  readiness: JsonObject,
  capabilitySelfTests: JsonObject,
  now = new Date(),
): Readonly<{ guidedToolIds: readonly string[]; capabilityReceiptExpiresAt: string }> {
  if (readiness.schemaVersion !== "2.4" || readiness.status !== "healthy"
    || pick(readiness, ["database", "healthy"]) !== true
    || pick(readiness, ["eventStream", "status"]) !== "healthy") {
    throw new Error("Ti-Scale database, event stream, and execution readiness are not fully healthy");
  }
  if (pick(readiness, ["execution", "autonomous"]) !== "ready"
    || pick(readiness, ["execution", "guided"]) !== "ready"
    || pick(readiness, ["execution", "guidedToolExecution"]) !== "ready"
    || pick(readiness, ["execution", "localCommanderGuidance"]) !== "ready"
    || pick(readiness, ["execution", "actionBoundaryActive"]) !== true
    || pick(readiness, ["execution", "delegationEnforced"]) !== true
    || pick(readiness, ["execution", "noHandsCommanderEnforced"]) !== true) {
    throw new Error("The Autonomous and Guided execution boundaries are not simultaneously ready");
  }
  const guided = object(
    pick(readiness, ["dependencies", "guidedLocalToolExecution"]),
    "Guided local-tool readiness",
  );
  if (guided.status !== "ready" || guided.executionBinding !== "reviewed_local_process"
    || guided.exactDecisionRequired !== true || guided.providerContact !== false
    || guided.mcpTransport !== false) {
    throw new Error("Guided local execution is not the exact reviewed, decision-gated direct-process route");
  }
  exactSet(array(guided.readyToolIds, "Guided ready tool IDs"), EXPECTED_GUIDED_TOOL_IDS, "Guided ready tool IDs");
  if (exactIsoMilliseconds(guided.expiresAt, "Guided readiness expiry") <= now.getTime()) {
    throw new Error("The Guided local-tool readiness receipt is stale");
  }

  const autonomous = object(
    pick(readiness, ["dependencies", "autonomousRuntime"]),
    "Autonomous runtime readiness",
  );
  const autonomousComponents = object(autonomous.components, "Autonomous runtime components");
  if (autonomous.status !== "ready"
    || autonomousComponents.localProcessExecution !== true
    || autonomousComponents.mcpExecution !== false
    || autonomousComponents.enforcingProvider !== true
    || autonomousComponents.resultAwareSpecialistExecution !== true
    || autonomousComponents.durableActionBoundary !== true
    || autonomousComponents.exactRuntimeManifest !== true) {
    throw new Error("Autonomous is not mounted through the exact local, result-aware, policy-enforced route");
  }
  exactSet(
    array(autonomous.readyActionClassIds, "Autonomous ready action classes"),
    EXPECTED_AUTONOMOUS_ACTION_CLASS_IDS,
    "Autonomous ready action classes",
  );

  if (pick(readiness, ["dependencies", "secondBrain", "status"]) !== "healthy"
    || pick(readiness, ["dependencies", "secondBrain", "canonicalStoreAvailable"]) !== true) {
    throw new Error("The canonical Second Brain is not healthy");
  }

  const accounting = object(capabilitySelfTests.accounting, "Capability self-test accounting");
  if (capabilitySelfTests.schemaVersion !== "2.4" || capabilitySelfTests.readOnly !== true
    || capabilitySelfTests.grantsMissionExecution !== false
    || accounting.runtimeRegistryRead !== true || accounting.manifestValid !== true
    || accounting.complete !== true) {
    throw new Error("Capability self-tests are not a complete read-only registry receipt");
  }
  const results = array(capabilitySelfTests.results, "Capability self-test results");
  let earliestExpiry = Number.POSITIVE_INFINITY;
  for (const toolId of EXPECTED_GUIDED_TOOL_IDS) {
    const toolMatches = results.filter((entry) => {
      const component = object(object(entry, "Capability result").component, "Capability component");
      return component.kind === "tool" && component.id === toolId;
    });
    if (toolMatches.length !== 1) throw new Error(`${toolId} did not have exactly one tool readiness receipt`);
    const tool = assertFreshCapabilityEntry(
      toolMatches[0],
      "tool",
      toolId,
      "local_executable_attestation",
      now.getTime(),
    );
    earliestExpiry = Math.min(earliestExpiry, Date.parse(tool.expiresAt));
    const dependencies = EXPECTED_DEPENDENCY_SUFFIXES.map((suffix) => {
      const dependencyId = `${toolId}/${suffix}`;
      const matches = results.filter((entry) => {
        const component = object(object(entry, "Capability result").component, "Capability component");
        return component.kind === "tool_dependency" && component.id === dependencyId;
      });
      if (matches.length !== 1) {
        throw new Error(`${dependencyId} did not have exactly one dependency readiness receipt`);
      }
      return assertFreshCapabilityEntry(
        matches[0],
        "tool_dependency",
        dependencyId,
        "manifest_dependency",
        now.getTime(),
      );
    });
    const activation = dependencies[0]!;
    if (!dependencies.every((receipt) => receipt.observedAt === activation.observedAt
      && receipt.expiresAt === activation.expiresAt)) {
      throw new Error(`${toolId} dependency receipts were not issued as one exact activation set`);
    }
    earliestExpiry = Math.min(earliestExpiry, Date.parse(activation.expiresAt));
  }
  if (!exactNmapCapabilityAvailable(capabilitySelfTests, now)) {
    throw new Error("The exact reviewed Nmap binding failed its activation-specific readiness proof");
  }
  return {
    guidedToolIds: [...EXPECTED_GUIDED_TOOL_IDS],
    capabilityReceiptExpiresAt: new Date(earliestExpiry).toISOString(),
  };
}

export function assertFunctionalRuntimeLiveness(value: unknown): void {
  const health = object(value, "Ti-Scale liveness response");
  if (health.schemaVersion !== "2.4" || health.status !== "healthy"
    || pick(health, ["database", "healthy"]) !== true
    || pick(health, ["eventStream", "status"]) !== "healthy") {
    throw new Error("Ti-Scale HTTP, database, and event-stream liveness is not fully healthy");
  }
}

interface BrainSnapshot {
  readonly connectionId: string;
  readonly receipt: Readonly<{
    status: "healthy";
    vaultName: string;
    visibleNodes: number;
    confirmed: number;
    verified: number;
    candidateNodes: number;
    stale: number;
    disputed: number;
    edges: number;
    contextPacks: number;
    trackedVaultNotes: number;
    openConflicts: number;
  }>;
}

export function assertConnectedBrain(
  brainHealth: JsonObject,
  summary: JsonObject,
  vault: JsonObject,
): BrainSnapshot {
  if (brainHealth.schemaVersion !== "2.4" || brainHealth.status !== "healthy"
    || pick(brainHealth, ["database", "status"]) !== "healthy"
    || pick(brainHealth, ["search", "status"]) !== "healthy"
    || Number(pick(brainHealth, ["vault", "connected"])) < 1) {
    throw new Error("The authenticated Second Brain and Vault health proof is not healthy");
  }
  const counts = object(summary.counts, "Second Brain counts");
  const confirmed = integer(counts.confirmed, "confirmed Brain nodes");
  const verified = integer(counts.verified, "verified Brain nodes");
  const candidateNodes = integer(counts.candidateNodes, "candidate Brain nodes");
  const stale = integer(counts.stale, "stale Brain nodes");
  const disputed = integer(counts.disputed, "disputed Brain nodes");
  const edges = integer(counts.edges, "Brain edges");
  const contextPacks = integer(counts.contextPacks, "Brain Context Packs");
  const connections = array(vault.connections, "Vault connections")
    .map((value) => object(value, "Vault connection"));
  const matching = connections.filter((connection) => connection.displayName === "Ti-Scale-Brain");
  if (matching.length !== 1) throw new Error("Exactly one Ti-Scale-Brain connection was not found");
  const connection = matching[0]!;
  const checks = object(connection.healthChecks, "Ti-Scale-Brain round-trip health checks");
  if (connection.status !== "connected" || connection.pathAvailable !== true
    || checks.write !== true || checks.read !== true || checks.rename !== true || checks.delete !== true) {
    throw new Error("Ti-Scale-Brain is not connected, reachable, and round-trip verified");
  }
  const connectionId = text(connection.id, "Ti-Scale-Brain connection ID");
  const openConflicts = array(vault.conflicts, "Vault conflicts")
    .map((value) => object(value, "Vault conflict"))
    .filter((conflict) => conflict.connectionId === connectionId && conflict.status === "open").length;
  if (openConflicts !== 0) throw new Error("Ti-Scale-Brain has an unresolved synchronization conflict");
  const trackedVaultNotes = integer(connection.trackedNoteCount ?? 0, "tracked Vault notes");
  const visibleNodes = confirmed + verified + candidateNodes + stale + disputed;
  if (visibleNodes < 1 || edges < 1 || contextPacks < 1 || trackedVaultNotes < 1) {
    throw new Error("The connected Brain does not yet contain a usable graph, Context Pack, and Vault projection");
  }
  return {
    connectionId,
    receipt: {
      status: "healthy",
      vaultName: "Ti-Scale-Brain",
      visibleNodes,
      confirmed,
      verified,
      candidateNodes,
      stale,
      disputed,
      edges,
      contextPacks,
      trackedVaultNotes,
      openConflicts,
    },
  };
}

async function sleep(milliseconds: number): Promise<void> {
  await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function waitForGlobalV2Quiescence(): Promise<Readonly<{ activeRuns: 0; activeLeases: 0 }>> {
  const deadline = Date.now() + BRAIN_PROJECTION_TIMEOUT_MS;
  do {
    const active = queryActiveV2Work(FUNCTIONAL_RUNTIME_PROOF_DATABASE_PATH);
    if (active.activeRuns.length === 0 && active.activeLeases.length === 0) {
      return { activeRuns: 0, activeLeases: 0 };
    }
    if (Date.now() >= deadline) break;
    await sleep(500);
  } while (Date.now() < deadline);
  throw new Error("Ti-Scale retained an active V2 run or control-plane lease after the proof missions terminated");
}

async function waitForTerminalRun(
  client: ProofClient,
  runId: string,
  journey: "autonomous" | "guided",
): Promise<JsonObject> {
  const deadline = Date.now() + RUN_TIMEOUT_MS;
  do {
    const response = await client.request(`/api/v2/runs/${encodeURIComponent(runId)}`);
    const run = object(response.run, `${journey} run`);
    const status = String(run.status ?? "");
    if (journey === "autonomous" && status === "waiting_guided_decision") {
      throw new Error("The Autonomous proof violated its no-routine-intervention invariant");
    }
    if (["blocked", "failed", "cancelled"].includes(status)) {
      throw new Error(
        `${journey} proof ended ${status}: ${safeMessage(run.statusReason, "No safe reason was returned")}`,
      );
    }
    if (status === "completed") return run;
    if (Date.now() >= deadline) break;
    await sleep(POLL_INTERVAL_MS);
  } while (Date.now() < deadline);
  throw new Error(`${journey} proof did not reach a terminal state within ${RUN_TIMEOUT_MS} ms`);
}

async function exactRunCollections(client: ProofClient, missionId: string, runId: string) {
  const encodedMission = encodeURIComponent(missionId);
  const encodedRun = encodeURIComponent(runId);
  const [actions, logs, observations, candidates, verifiedEvidence, evidence, evaluations, events] = await Promise.all([
    client.request(`/api/v2/operations/actions?runId=${encodedRun}&limit=20`),
    client.request(`/api/v2/operational-truth/missions/${encodedMission}/logs?runId=${encodedRun}&limit=20`),
    client.request(`/api/v2/operational-truth/missions/${encodedMission}/observations?runId=${encodedRun}&limit=20`),
    client.request(`/api/v2/operational-truth/missions/${encodedMission}/evidence-candidates?runId=${encodedRun}&limit=20`),
    client.request(`/api/v2/operational-truth/missions/${encodedMission}/verified-evidence?runId=${encodedRun}&limit=20`),
    client.request(`/api/v2/intelligence/evidence?missionId=${encodedMission}&runId=${encodedRun}&limit=20`),
    client.request(`/api/v2/learning/evaluations?runId=${encodedRun}&limit=20`),
    client.request(`/api/v2/observability/events?runId=${encodedRun}&limit=100`),
  ]);
  return {
    actions: array(actions.items, "run actions").map((value) => object(value, "run action")),
    logs: array(logs.items, "Engagement Logs").map((value) => object(value, "Engagement Log")),
    observations: array(observations.items, "observations").map((value) => object(value, "observation")),
    candidates: array(candidates.items, "evidence candidates").map((value) => object(value, "evidence candidate")),
    verifiedEvidence: array(verifiedEvidence.items, "verified evidence").map((value) => object(value, "verified evidence")),
    evidence: array(evidence.items, "Evidence Vault records").map((value) => object(value, "Evidence Vault record")),
    evaluations: array(evaluations.items, "run evaluations").map((value) => object(value, "run evaluation")),
    events: array(events.items, "run events").map((value) => object(value, "run event")),
  };
}

async function assertTerminalRunBoundary(
  client: ProofClient,
  runId: string,
  terminal: JsonObject,
  actions: readonly JsonObject[],
): Promise<Readonly<{
  currentStepCleared: true;
  currentOwnerCleared: true;
  runLeaseCleared: true;
  pendingDecisions: 0;
  nonterminalActions: 0;
}>> {
  if (terminal.currentStepId !== null || terminal.currentOwnerId !== null
    || terminal.leaseExpiresAt !== null || typeof terminal.endedAt !== "string") {
    throw new Error("A terminal proof run retained an active step, owner, lease, or missing end time");
  }
  const nonterminalActions = actions.filter((action) =>
    action.status === "queued" || action.status === "running");
  if (nonterminalActions.length !== 0) {
    throw new Error("A terminal proof run retained queued or running action work");
  }
  const decisions = await client.request(
    `/api/v2/decisions?status=pending&runId=${encodeURIComponent(runId)}`,
  );
  if (array(decisions.items, "pending decisions after terminal run").length !== 0) {
    throw new Error("A terminal proof run retained a pending operator decision");
  }
  return {
    currentStepCleared: true,
    currentOwnerCleared: true,
    runLeaseCleared: true,
    pendingDecisions: 0,
    nonterminalActions: 0,
  };
}

interface GeneratedReportArtifact {
  readonly id: string;
  readonly format: "markdown" | "json";
  readonly mediaType: string;
  readonly contentHash: string;
  readonly byteSize: number;
  readonly downloadUrl: string;
}

function generatedReportArtifact(value: unknown): GeneratedReportArtifact {
  const artifact = object(value, "generated canonical report artifact");
  const format = text(artifact.format, "canonical report format");
  if (format !== "markdown" && format !== "json") {
    throw new Error("Canonical report returned an unsupported artifact format");
  }
  const contentHash = text(artifact.contentHash, "canonical report SHA-256");
  if (!/^[a-f0-9]{64}$/u.test(contentHash)) {
    throw new Error("Canonical report returned an invalid SHA-256");
  }
  return {
    id: text(artifact.id, "canonical report artifact ID"),
    format,
    mediaType: text(artifact.mediaType, "canonical report media type"),
    contentHash,
    byteSize: integer(artifact.byteSize, "canonical report byte size"),
    downloadUrl: text(artifact.downloadUrl, "canonical report download URL"),
  };
}

export function assertCanonicalAutonomousIpReport(
  report: JsonObject,
  missionId: string,
  runId: string,
  expectedEvidenceTypes: readonly string[],
  expectedTopologyNodes: number,
  expectedTopologyEdges: number,
): Readonly<{ verifiedEvidence: number; topologyNodes: number; topologyEdges: number }> {
  const mission = object(report.mission, "canonical report mission");
  const run = object(report.run, "canonical report run");
  const logs = object(report.engagementLogs, "canonical report Engagement Logs");
  const observations = object(report.observations, "canonical report observations");
  const evidence = object(report.verifiedEvidence, "canonical report verified evidence");
  const findings = object(report.findings, "canonical report findings");
  const topology = object(report.topology, "canonical report topology");
  const contexts = object(report.contextPacks, "canonical report Context Packs");
  const evidenceRecords = array(evidence.records, "canonical report evidence records")
    .map((value) => object(value, "canonical report evidence record"));
  const topologyNodes = array(topology.nodes, "canonical report topology nodes")
    .map((value) => object(value, "canonical report topology node"));
  const topologyEdges = array(topology.edges, "canonical report topology edges")
    .map((value) => object(value, "canonical report topology edge"));
  if (report.schemaVersion !== "2.4-report.1" || mission.id !== missionId || run.id !== runId
    || run.journey !== "autonomous" || run.status !== "completed"
    || logs.classification !== "technical_record_not_evidence" || logs.rawPayloadsOmitted !== true
    || observations.classification !== "parsed_statement_not_automatically_verified"
    || observations.rawValuesOmitted !== true
    || evidence.classification !== "canonical_verified_evidence_only"
    || evidence.extractedTextOmitted !== true || evidence.provenancePayloadOmitted !== true
    || findings.unverifiedClaimsNotAsserted !== true
    || array(findings.verified, "canonical report verified findings").length !== 0
    || array(findings.reviewRequired, "canonical report review-required findings").length !== 0
    || topology.propertiesOmitted !== true
    || topologyNodes.length !== expectedTopologyNodes || topologyEdges.length !== expectedTopologyEdges
    || topologyNodes.some((node) => node.verificationState !== "unverified")
    || topologyEdges.some((edge) => edge.verificationState !== "unverified")
    || contexts.memoryContentOmitted !== true
    || array(contexts.records, "canonical report Context Packs").length < 1
    || object(report.privacy, "canonical report privacy").redacted !== true) {
    throw new Error("Canonical Autonomous IP report taxonomy, scope, or privacy contract drifted");
  }
  exactSet(
    evidenceRecords.map((record) => record.evidenceType),
    expectedEvidenceTypes,
    "canonical report verified evidence types",
  );
  return {
    verifiedEvidence: evidenceRecords.length,
    topologyNodes: topologyNodes.length,
    topologyEdges: topologyEdges.length,
  };
}

async function canonicalReportProof(
  client: ProofClient,
  nonce: string,
  missionId: string,
  runId: string,
  expectedEvidenceTypes: readonly string[],
  expectedTopologyNodes: number,
  expectedTopologyEdges: number,
) {
  const generated = await client.request(
    `/api/v2/reports/runs/${encodeURIComponent(runId)}/generate`,
    {
      method: "POST",
      expectedStatus: 201,
      idempotencyKey: `functional-generate-report-${nonce}-${runId}`,
      body: { reportVersion: 1 },
    },
  );
  if (generated.schemaVersion !== "2.4" || generated.reportSchemaVersion !== "2.4-report.1"
    || generated.missionId !== missionId || generated.runId !== runId
    || generated.reportVersion !== 1 || generated.idempotent !== true) {
    throw new Error("Canonical report generation receipt drifted from the exact completed run");
  }
  const artifacts = array(generated.artifacts, "generated canonical report artifacts")
    .map(generatedReportArtifact);
  if (artifacts.length !== 2) throw new Error("Canonical report did not produce exactly Markdown and JSON");
  exactSet(artifacts.map((artifact) => artifact.format), ["markdown", "json"], "canonical report formats");

  let jsonReceipt: Readonly<{ verifiedEvidence: number; topologyNodes: number; topologyEdges: number }> | undefined;
  for (const artifact of artifacts) {
    const downloaded = await client.download(artifact.downloadUrl);
    try {
      const actualHash = createHash("sha256").update(downloaded.body).digest("hex");
      const expectedDigest = `sha-256=${Buffer.from(artifact.contentHash, "hex").toString("base64")}`;
      const expectedContentType = artifact.format === "json"
        ? "application/json; charset=utf-8"
        : "text/markdown; charset=utf-8";
      if (actualHash !== artifact.contentHash || downloaded.digest !== expectedDigest
        || downloaded.contentLength !== artifact.byteSize || downloaded.contentType !== expectedContentType
        || artifact.mediaType !== expectedContentType) {
        throw new Error(`Downloaded ${artifact.format} report failed its hash, size, media, or Digest receipt`);
      }
      const rendered = downloaded.body.toString("utf8");
      if (rendered.includes("Nmap scan report for") || rendered.includes("packets transmitted")
        || /(?:password|token|secret|cookie|private[_ -]?key)\s*[:=]\s*[^\s,;}]+/iu.test(rendered)) {
        throw new Error(`Downloaded ${artifact.format} report exposed raw process output or credential-like content`);
      }
      if (artifact.format === "json") {
        jsonReceipt = assertCanonicalAutonomousIpReport(
          object(JSON.parse(rendered) as unknown, "downloaded canonical JSON report"),
          missionId,
          runId,
          expectedEvidenceTypes,
          expectedTopologyNodes,
          expectedTopologyEdges,
        );
      } else if (!rendered.includes("Engagement Log (not evidence)")
        || !rendered.includes("Observations (not automatically verified)")
        || !rendered.includes("Verified Evidence")
        || !rendered.includes("Review required (not asserted as fact)")) {
        throw new Error("Downloaded Markdown report did not explain the operational-truth taxonomy");
      }
    } finally {
      downloaded.body.fill(0);
    }
  }
  if (!jsonReceipt) throw new Error("Canonical JSON report was not downloaded and verified");
  return {
    reportVersion: 1,
    artifacts: 2,
    formats: ["markdown", "json"],
    downloadsIntegrityVerified: 2,
    inertDownloadHeadersVerified: 2,
    ...jsonReceipt,
  } as const;
}

async function assertBrainRunAnchors(
  client: ProofClient,
  missionId: string,
  runId: string,
  evaluationId: string,
  connectionId: string,
): Promise<Readonly<{ contextPacks: number; graphNodes: 3; vaultProjectedNodes: 3 }>> {
  const encodedMission = encodeURIComponent(missionId);
  const missionNodeId = canonicalMemoryNodeId("mem_mission", missionId);
  const runNodeId = canonicalMemoryNodeId("mem_run", runId);
  const evaluationNodeId = canonicalMemoryNodeId("mem_eval", evaluationId);
  const deadline = Date.now() + BRAIN_PROJECTION_TIMEOUT_MS;
  do {
    const [contexts, graph, vault] = await Promise.all([
      client.request(`/api/v2/brain/context-packs?missionId=${encodedMission}`),
      client.request(`/api/v2/brain/graph?view=mission&missionId=${encodedMission}&limit=50`),
      client.request("/api/v2/brain/vault"),
    ]);
    const contextPacks = array(contexts.items, "mission Context Packs")
      .map((value) => object(value, "mission Context Pack"))
      .filter((context) => context.runId === runId);
    const nodes = array(graph.nodes, "mission graph nodes")
      .map((value) => object(value, "mission graph node"));
    const edges = array(graph.edges, "mission graph edges")
      .map((value) => object(value, "mission graph edge"));
    const graphReady = nodes.some((node) => node.id === missionNodeId && node.nodeType === "mission")
      && nodes.some((node) => node.id === runNodeId && node.nodeType === "run")
      && nodes.some((node) => node.id === evaluationNodeId && node.nodeType === "evaluation")
      && edges.some((edge) => edge.sourceNodeId === runNodeId
        && edge.targetNodeId === missionNodeId && edge.edgeType === "belongs_to")
      && edges.some((edge) => edge.sourceNodeId === evaluationNodeId
        && edge.targetNodeId === runNodeId && edge.edgeType === "derived_from");
    const projected = new Set(array(vault.syncStates, "Vault synchronization states")
      .map((value) => object(value, "Vault synchronization state"))
      .filter((state) => state.connectionId === connectionId && state.status === "synced")
      .map((state) => state.nodeId)
      .filter((nodeId): nodeId is string => typeof nodeId === "string"));
    const vaultReady = projected.has(missionNodeId)
      && projected.has(runNodeId)
      && projected.has(evaluationNodeId);
    if (contextPacks.length > 0 && graphReady && vaultReady) {
      return { contextPacks: contextPacks.length, graphNodes: 3, vaultProjectedNodes: 3 };
    }
    if (Date.now() >= deadline) break;
    await sleep(500);
  } while (Date.now() < deadline);
  throw new Error(
    `The completed mission/run/evaluation did not reach its durable Brain graph and Ti-Scale-Brain projection within ${BRAIN_PROJECTION_TIMEOUT_MS} ms`,
  );
}

async function autonomousProof(client: ProofClient, nonce: string, connectionId: string) {
  const resolved = await client.request("/api/v2/registries/intake/resolve", {
    method: "POST",
    idempotencyKey: `functional-resolve-autonomous-${nonce}`,
    body: {
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: EXACT_AUTONOMOUS_TARGET, type: "domain" }],
      templateId: "safe_recon",
      actionPolicyOverrides: {
        [AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS]: "pre_authorized",
        [AUTONOMOUS_IP_LIVENESS_ACTION_CLASS]: "prohibited",
        [AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS]: "prohibited",
      },
    },
  });
  const request = object(resolved.request, "resolved Autonomous mission request");
  const contract = object(request.contract, "resolved Autonomous contract");
  exactSet(
    array(contract.allowedActionClasses, "Autonomous allowed action classes"),
    [AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS],
    "Autonomous allowed action classes",
  );
  if (!array(contract.evidenceRequirements, "Autonomous evidence requirements")
    .includes(AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE)) {
    throw new Error("The resolved Autonomous contract did not require exact DNS evidence");
  }
  const preflight = await client.request("/api/v2/missions/autonomous/preflight", {
    method: "POST",
    idempotencyKey: `functional-preflight-autonomous-${nonce}`,
    body: request,
  });
  const preflightReadiness = object(preflight.readiness, "Autonomous preflight readiness");
  if (preflightReadiness.status !== "ready"
    || array(preflightReadiness.checks, "Autonomous preflight checks")
      .some((value) => object(value, "Autonomous preflight check").status === "fail")) {
    throw new Error(
      `The Autonomous contract did not pass every preflight readiness check: ${failedReadinessSummary(preflightReadiness, "Autonomous preflight")}`,
    );
  }
  const contractReview = object(preflight.contract, "Autonomous contract review");
  text(contractReview.hash, "Autonomous contract hash");
  const created = await client.request("/api/v2/missions", {
    method: "POST",
    expectedStatus: 201,
    idempotencyKey: `functional-create-autonomous-${nonce}`,
    body: { ...request, contractReview },
  });
  const missionId = text(object(created.mission, "created Autonomous mission").id, "Autonomous mission ID");
  const runId = text(object(created.run, "created Autonomous run").id, "Autonomous run ID");
  const terminal = await waitForTerminalRun(client, runId, "autonomous");
  const records = await exactRunCollections(client, missionId, runId);
  const terminalBoundary = await assertTerminalRunBoundary(client, runId, terminal, records.actions);
  if (records.actions.length !== 1) throw new Error("Autonomous did not create exactly one canonical action");
  const action = records.actions[0]!;
  if (action.status !== "succeeded" || action.actionType !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID
    || action.actionClass !== AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS || action.target !== EXACT_AUTONOMOUS_TARGET) {
    throw new Error("Autonomous did not execute the one exact reviewed DNS action inside its contract");
  }
  if (records.logs.length !== 1 || records.logs[0]!.domain !== "autonomous_dns_safe_recon"
    || records.logs[0]!.recordType !== "bounded_dns_process_output") {
    throw new Error("Autonomous did not retain exactly one bounded DNS Engagement Log record");
  }
  if (records.observations.length !== 1
    || records.observations[0]!.observationType !== "dns_record_query"
    || records.observations[0]!.verificationState !== "corroborated"
    || records.observations[0]!.sourceTool !== AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID) {
    throw new Error("Autonomous did not retain exactly one corroborated DNS observation");
  }
  if (records.candidates.length !== 0 || records.verifiedEvidence.length !== 1
    || records.evidence.length !== 1
    || records.verifiedEvidence[0]!.evidenceType !== AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE
    || records.verifiedEvidence[0]!.verificationState !== "verified"
    || records.evidence[0]!.recordClass !== "evidence") {
    throw new Error("Autonomous operational truth did not preserve one verified DNS evidence item without a candidate detour");
  }
  if (records.evaluations.length !== 1 || records.evaluations[0]!.journey !== "autonomous") {
    throw new Error("Autonomous completion did not create exactly one journey-aware evaluation");
  }
  if (records.events.some((event) => String(event.eventType ?? "").startsWith("guided.")
    || JSON.stringify(event).includes("waiting_guided_decision"))) {
    throw new Error("Autonomous emitted a Guided decision or waiting state");
  }
  const brain = await assertBrainRunAnchors(
    client,
    missionId,
    runId,
    text(records.evaluations[0]!.id, "Autonomous evaluation ID"),
    connectionId,
  );
  return {
    missionId,
    runId,
    status: terminal.status,
    target: EXACT_AUTONOMOUS_TARGET,
    actionClass: AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
    toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    actions: 1,
    engagementLogs: 1,
    observations: 1,
    evidenceCandidates: 0,
    verifiedEvidence: 1,
    evaluations: 1,
    guidedWaitEvents: 0,
    terminalBoundary,
    brain,
  } as const;
}

async function autonomousIpProof(client: ProofClient, nonce: string, connectionId: string) {
  const resolved = await client.request("/api/v2/registries/intake/resolve", {
    method: "POST",
    idempotencyKey: `functional-resolve-autonomous-ip-${nonce}`,
    body: {
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: EXACT_AUTONOMOUS_IP_TARGET, type: "host" }],
      templateId: "safe_recon",
      actionPolicyOverrides: {
        [AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS]: "prohibited",
        [AUTONOMOUS_IP_LIVENESS_ACTION_CLASS]: "pre_authorized",
        [AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS]: "pre_authorized",
      },
    },
  });
  const request = object(resolved.request, "resolved Autonomous IP mission request");
  const contract = object(request.contract, "resolved Autonomous IP contract");
  exactSet(
    array(contract.allowedActionClasses, "Autonomous IP allowed action classes"),
    [AUTONOMOUS_IP_LIVENESS_ACTION_CLASS, AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS],
    "Autonomous IP allowed action classes",
  );
  exactSet(
    array(contract.evidenceRequirements, "Autonomous IP evidence requirements"),
    [
      AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE,
      AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE,
      AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE,
    ],
    "Autonomous IP evidence requirements",
  );
  exactSet(
    array(request.successCriteria, "Autonomous IP success criteria"),
    [AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION, AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION],
    "Autonomous IP success criteria",
  );

  const preflight = await client.request("/api/v2/missions/autonomous/preflight", {
    method: "POST",
    idempotencyKey: `functional-preflight-autonomous-ip-${nonce}`,
    body: request,
  });
  const preflightReadiness = object(preflight.readiness, "Autonomous IP preflight readiness");
  if (preflightReadiness.status !== "ready"
    || array(preflightReadiness.checks, "Autonomous IP preflight checks")
      .some((value) => object(value, "Autonomous IP preflight check").status === "fail")) {
    throw new Error(
      `The bounded Autonomous IP contract did not pass every preflight readiness check: ${failedReadinessSummary(preflightReadiness, "Autonomous IP preflight")}`,
    );
  }
  const contractReview = object(preflight.contract, "Autonomous IP contract review");
  text(contractReview.hash, "Autonomous IP contract hash");
  const created = await client.request("/api/v2/missions", {
    method: "POST",
    expectedStatus: 201,
    idempotencyKey: `functional-create-autonomous-ip-${nonce}`,
    body: { ...request, contractReview },
  });
  const missionId = text(object(created.mission, "created Autonomous IP mission").id, "Autonomous IP mission ID");
  const runId = text(object(created.run, "created Autonomous IP run").id, "Autonomous IP run ID");
  const terminal = await waitForTerminalRun(client, runId, "autonomous");
  const records = await exactRunCollections(client, missionId, runId);
  const terminalBoundary = await assertTerminalRunBoundary(client, runId, terminal, records.actions);

  if (records.actions.length !== 2) {
    throw new Error("Autonomous IP did not create exactly the reviewed ping and Nmap actions");
  }
  const actionsByType = new Map(records.actions.map((action) => [action.actionType, action]));
  const expectedActions = [
    [AUTONOMOUS_IP_LIVENESS_TOOL_ID, AUTONOMOUS_IP_LIVENESS_ACTION_CLASS],
    [AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID, AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS],
  ] as const;
  for (const [toolId, actionClass] of expectedActions) {
    const action = actionsByType.get(toolId);
    if (!action || action.status !== "succeeded" || action.actionClass !== actionClass
      || action.target !== EXACT_AUTONOMOUS_IP_TARGET || action.guidedDecisionId !== null
      || typeof action.contractId !== "string") {
      throw new Error(`Autonomous IP did not execute the exact reviewed ${toolId} action inside its signed contract`);
    }
  }
  if (records.logs.length !== 2 || records.logs.some((log) =>
    log.domain !== "autonomous_ip_safe_recon" || log.recordType !== "bounded_ip_process_output")) {
    throw new Error("Autonomous IP did not retain exactly two bounded IP Engagement Log records");
  }
  if (records.observations.length !== 2) {
    throw new Error("Autonomous IP did not retain exactly two parsed observations");
  }
  const observationsByTool = new Map(records.observations.map((observation) => [
    observation.sourceTool,
    observation,
  ]));
  const liveness = observationsByTool.get(AUTONOMOUS_IP_LIVENESS_TOOL_ID);
  const scan = observationsByTool.get(AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID);
  if (!liveness || liveness.observationType !== "host_liveness"
    || liveness.verificationState !== "corroborated"
    || !scan || scan.observationType !== "tcp_service_scan"
    || scan.verificationState !== "corroborated") {
    throw new Error("Autonomous IP observation types, attribution, or verification semantics drifted");
  }
  for (const observation of [liveness, scan]) {
    const sources = array(observation.sources, "Autonomous IP observation sources")
      .map((value) => object(value, "Autonomous IP observation source"));
    const normalized = object(observation.normalizedValue, "Autonomous IP normalized observation");
    if (sources.length !== 1
      || sources[0]!.parserId !== "ti-scale.autonomous-ip-deterministic-parser"
      || sources[0]!.parserVersion !== "1.0.0"
      || normalized.rawOutputPromoted !== false || normalized.cveClaimsCreated !== false
      || normalized.missionId !== missionId || normalized.runId !== runId
      || normalized.target !== EXACT_AUTONOMOUS_IP_TARGET) {
      throw new Error("Autonomous IP parser provenance or no-overclaim receipt drifted");
    }
  }
  const scanResult = object(
    object(scan.normalizedValue, "Autonomous IP scan observation").result,
    "Autonomous IP scan result",
  );
  exactSet(
    array(scanResult.requestedPorts, "Autonomous IP requested ports").map(String),
    AUTONOMOUS_SAFE_IP_RECON_DEFAULT_PORTS.map(String),
    "Autonomous IP requested ports",
  );
  if (scanResult.host !== EXACT_AUTONOMOUS_IP_TARGET || scanResult.scanCompleted !== true
    || scanResult.hostReportedUp !== true) {
    throw new Error("Autonomous IP Nmap result was not a complete attributable scan of loopback");
  }
  const openPorts = array(scanResult.openPorts, "Autonomous IP open ports")
    .map((value) => object(value, "Autonomous IP open port"));
  if (openPorts.some((port) => !AUTONOMOUS_SAFE_IP_RECON_DEFAULT_PORTS.includes(Number(port.port) as never)
    || port.transport !== "tcp" || port.state !== "open")) {
    throw new Error("Autonomous IP reported a service outside the exact reviewed TCP port set");
  }

  const expectedEvidenceTypes = [
    AUTONOMOUS_IP_LIVENESS_EVIDENCE_TYPE,
    AUTONOMOUS_IP_SERVICE_SCAN_EVIDENCE_TYPE,
    ...(openPorts.length > 0 ? [AUTONOMOUS_IP_VERSION_EVIDENCE_TYPE] : []),
  ];
  if (records.candidates.length !== 0 || records.verifiedEvidence.length !== expectedEvidenceTypes.length
    || records.evidence.length !== expectedEvidenceTypes.length) {
    throw new Error("Autonomous IP evidence counts did not match only the parsed attributable facts");
  }
  exactSet(
    records.verifiedEvidence.map((evidence) => evidence.evidenceType),
    expectedEvidenceTypes,
    "Autonomous IP verified evidence types",
  );
  exactSet(
    records.evidence.map((evidence) => evidence.evidenceType),
    expectedEvidenceTypes,
    "Autonomous IP Evidence Vault types",
  );
  for (const evidence of records.evidence) {
    const provenance = object(evidence.provenance, "Autonomous IP evidence provenance");
    if (evidence.recordClass !== "evidence" || evidence.verificationState !== "verified"
      || provenance.method !== "deterministic_reviewed_ip_result_validation"
      || provenance.rawOutputPromoted !== false || provenance.cveClaimsCreated !== false
      || JSON.stringify(evidence.summary).includes("Nmap scan report for")
      || JSON.stringify(evidence.summary).includes("packets transmitted")) {
      throw new Error("Autonomous IP evidence overclaimed or embedded raw process output");
    }
  }

  const encodedMission = encodeURIComponent(missionId);
  const encodedRun = encodeURIComponent(runId);
  const [topologyResponse, findingsResponse, cvesResponse] = await Promise.all([
    client.request(`/api/v2/missions/${encodedMission}/intelligence/topology?runId=${encodedRun}`),
    client.request(`/api/v2/intelligence/findings?missionId=${encodedMission}&runId=${encodedRun}&limit=20`),
    client.request(`/api/v2/missions/${encodedMission}/intelligence/cves?runId=${encodedRun}`),
  ]);
  const topology = object(topologyResponse.digitalTwin, "Autonomous IP Recon Digital Twin");
  const topologyNodes = array(topology.nodes, "Autonomous IP topology nodes")
    .map((value) => object(value, "Autonomous IP topology node"));
  const topologyEdges = array(topology.edges, "Autonomous IP topology edges")
    .map((value) => object(value, "Autonomous IP topology edge"));
  const assets = topologyNodes.filter((node) => node.nodeType === "asset");
  const services = topologyNodes.filter((node) => node.nodeType === "service");
  if (topology.missionId !== missionId || topology.runId !== runId || assets.length !== 1
    || assets[0]!.primaryLabel !== EXACT_AUTONOMOUS_IP_TARGET
    || services.length !== openPorts.length || topologyNodes.length !== 1 + services.length
    || topologyEdges.length !== services.length) {
    throw new Error("Autonomous IP Recon Digital Twin did not match the parsed loopback scan");
  }
  for (const subject of [...topologyNodes, ...topologyEdges]) {
    const provenance = object(subject.provenance, "Autonomous IP topology provenance");
    if (subject.verificationState !== "unverified"
      || array(subject.evidence, "Autonomous IP topology evidence links").length !== 0
      || provenance.method !== "reviewed_local_nmap_observation"
      || provenance.sourceRef !== scan.id
      || provenance.sourceTool !== AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID) {
      throw new Error("Autonomous IP topology was not an unverified observation-backed projection");
    }
  }
  if (topologyEdges.some((edge) => edge.edgeType !== "exposes")
    || array(findingsResponse.items, "Autonomous IP findings").length !== 0
    || array(cvesResponse.items, "Autonomous IP CVE applicability records").length !== 0) {
    throw new Error("Autonomous IP fabricated a finding, CVE claim, or non-observed topology relationship");
  }

  if (records.evaluations.length !== 1 || records.evaluations[0]!.journey !== "autonomous") {
    throw new Error("Autonomous IP completion did not create exactly one journey-aware evaluation");
  }
  const evaluationMetrics = object(records.evaluations[0]!.metrics, "Autonomous IP evaluation metrics");
  if (evaluationMetrics.providerTurnCount !== 0 || evaluationMetrics.guidedDecisionCount !== 0
    || evaluationMetrics.autonomousUserWaitCount !== 0) {
    throw new Error("Autonomous IP contacted a provider or entered an operator-decision path");
  }
  if (records.events.some((event) => /^(?:guided|mcp|provider)\./u.test(String(event.eventType ?? ""))
    || JSON.stringify(event).includes("waiting_guided_decision"))) {
    throw new Error("Autonomous IP emitted a Guided wait, MCP, or provider-turn event");
  }
  const brain = await assertBrainRunAnchors(
    client,
    missionId,
    runId,
    text(records.evaluations[0]!.id, "Autonomous IP evaluation ID"),
    connectionId,
  );
  const report = await canonicalReportProof(
    client,
    nonce,
    missionId,
    runId,
    expectedEvidenceTypes,
    topologyNodes.length,
    topologyEdges.length,
  );
  return {
    missionId,
    runId,
    status: terminal.status,
    target: EXACT_AUTONOMOUS_IP_TARGET,
    actionClasses: [AUTONOMOUS_IP_LIVENESS_ACTION_CLASS, AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS],
    toolIds: [AUTONOMOUS_IP_LIVENESS_TOOL_ID, AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID],
    reviewedPorts: [...AUTONOMOUS_SAFE_IP_RECON_DEFAULT_PORTS],
    actions: 2,
    engagementLogs: 2,
    observations: 2,
    evidenceCandidates: 0,
    verifiedEvidence: expectedEvidenceTypes.length,
    openServices: services.length,
    topologyNodes: topologyNodes.length,
    topologyEdges: topologyEdges.length,
    findings: 0,
    cveClaims: 0,
    providerTurns: 0,
    guidedWaitEvents: 0,
    terminalBoundary,
    brain,
    report,
  } as const;
}

async function guidedNmapProof(client: ProofClient, nonce: string, connectionId: string) {
  const created = await client.request("/api/v2/missions", {
    method: "POST",
    expectedStatus: 201,
    idempotencyKey: `functional-create-guided-nmap-${nonce}`,
    body: {
      journey: "guided",
      launch: true,
      authorizationConfirmed: true,
      title: `Reviewed loopback Nmap proof ${nonce}`,
      objective: "Inspect only the Ti-Scale loopback service on TCP 3132 and retain its bounded result as an Engagement Log and observation.",
      target: EXACT_GUIDED_TARGET,
      explanationDepth: "balanced",
      executionPreference: "single_step_agent",
      evidenceExpectations: [],
      guidedReconnaissance: {
        mode: "tcp_service_scan",
        portSelection: { source: "custom", ports: [EXACT_GUIDED_PORT] },
      },
    },
  });
  const missionId = text(object(created.mission, "created Guided mission").id, "Guided mission ID");
  const runId = text(object(created.run, "created Guided run").id, "Guided run ID");
  const deadline = Date.now() + DECISION_TIMEOUT_MS;
  let decision: JsonObject | undefined;
  do {
    const runResponse = await client.request(`/api/v2/runs/${encodeURIComponent(runId)}`);
    const run = object(runResponse.run, "Guided run before decision");
    const status = String(run.status ?? "");
    if (["blocked", "failed", "cancelled", "completed"].includes(status)) {
      throw new Error(`Guided ended ${status} before presenting the exact Nmap decision`);
    }
    const decisions = await client.request(`/api/v2/decisions?status=pending&runId=${encodeURIComponent(runId)}`);
    const items = array(decisions.items, "pending Guided decisions");
    if (items.length > 1) throw new Error("Guided presented more than one pending decision");
    if (items[0]) {
      decision = object(items[0], "pending Guided decision");
      break;
    }
    if (Date.now() >= deadline) break;
    await sleep(POLL_INTERVAL_MS);
  } while (Date.now() < deadline);
  if (!decision) throw new Error(`Guided did not present its decision within ${DECISION_TIMEOUT_MS} ms`);
  const requested = object(decision.requestedParameters, "Guided requested parameters");
  const argumentsEnvelope = object(requested.arguments, "Guided requested argument envelope");
  const parameters = object(argumentsEnvelope.parameters, "Guided requested tool parameters");
  if (requested.kind !== "tool" || requested.actionType !== EXACT_NMAP_TOOL_ID
    || requested.target !== EXACT_GUIDED_TARGET
    || argumentsEnvelope.executionBinding !== "reviewed_local_process"
    || argumentsEnvelope.toolId !== EXACT_NMAP_TOOL_ID
    || parameters.target !== EXACT_GUIDED_TARGET
    || parameters.ports !== String(EXACT_GUIDED_PORT)) {
    throw new Error("Guided did not represent the exact reviewed Nmap action and normalized loopback parameters");
  }
  const decisionId = text(decision.id, "Guided decision ID");
  const stepId = text(decision.stepId, "Guided step ID");
  const actionFingerprint = text(decision.actionFingerprint, "Guided action fingerprint");
  const guidanceResponse = await client.request(
    `/api/v2/guided/${encodeURIComponent(missionId)}/commander/show-next-step`,
    {
      method: "POST",
      idempotencyKey: `functional-guided-local-commander-${nonce}`,
      body: {
        runId,
        stepId,
        expectedFingerprint: actionFingerprint,
      },
    },
  );
  const guidance = object(guidanceResponse.guidance, "local Guided Commander receipt");
  if (guidance.mode !== "local_deterministic"
    || guidance.providerContacted !== false
    || guidance.toolDispatched !== false
    || guidance.targetContacted !== false
    || guidance.planMutated !== false
    || guidance.exactDecisionRequired !== true) {
    throw new Error("Local Guided Commander guidance crossed its provider, tool, target, plan, or decision boundary");
  }
  const guidanceResult = object(guidanceResponse.result, "local Guided Commander result");
  const guidanceMessage = object(guidanceResult.assistantMessage, "local Guided Commander message");
  const guidanceContent = object(guidanceMessage.structuredContent, "local Guided Commander structured content");
  const guidanceContextPackId = text(guidanceResult.contextPackId, "local Guided Commander Context Pack ID");
  if (!text(guidanceMessage.body, "local Guided Commander body")
    .includes("Only the exact decision card can authorize one represented action")
    || guidanceContent.guidanceMode !== "local_deterministic"
    || guidanceContent.providerContacted !== false
    || guidanceContent.toolDispatched !== false
    || guidanceContent.targetContacted !== false
    || guidanceContent.planMutated !== false
    || guidanceContent.nextConsequentialActionRequiresDecision !== true) {
    throw new Error("Local Guided Commander did not preserve the exact-step explanation boundary");
  }
  const [transcript, pendingAfterGuidance, actionsBeforeDecision] = await Promise.all([
    client.request(
      `/api/v2/guided/${encodeURIComponent(missionId)}/commander/transcript?runId=${encodeURIComponent(runId)}&stepId=${encodeURIComponent(stepId)}`,
    ),
    client.request(`/api/v2/decisions?status=pending&runId=${encodeURIComponent(runId)}`),
    client.request(`/api/v2/operations/actions?runId=${encodeURIComponent(runId)}&limit=20`),
  ]);
  const transcriptMessages = array(transcript.items, "local Guided Commander transcript")
    .map((value) => object(value, "local Guided Commander transcript message"));
  const contextAttributedMessages = transcriptMessages
    .filter((message) => message.contextPackId === guidanceContextPackId);
  const pendingItems = array(pendingAfterGuidance.items, "pending decisions after local guidance")
    .map((value) => object(value, "pending decision after local guidance"));
  if (contextAttributedMessages.length !== 1
    || contextAttributedMessages[0]!.role !== "assistant"
    || transcriptMessages.some((message) => message.role === "operator"
      && message.contextPackId === guidanceContextPackId)
    || pendingItems.length !== 1
    || pendingItems[0]!.id !== decisionId
    || pendingItems[0]!.actionFingerprint !== actionFingerprint
    || array(actionsBeforeDecision.items, "actions before exact Guided decision").length !== 0) {
    throw new Error("Local Guided guidance did not remain durable, decision-pending, and zero-execution");
  }
  await client.request(`/api/v2/guided-decisions/${encodeURIComponent(decisionId)}/approve`, {
    method: "POST",
    idempotencyKey: `functional-approve-guided-nmap-${nonce}`,
    body: {
      expectedFingerprint: actionFingerprint,
      expectedParameters: requested,
      reason: "Approve only the represented Nmap TCP connect and service-version check on 127.0.0.1 port 3132.",
    },
  });
  const terminal = await waitForTerminalRun(client, runId, "guided");
  const records = await exactRunCollections(client, missionId, runId);
  const terminalBoundary = await assertTerminalRunBoundary(client, runId, terminal, records.actions);
  if (records.actions.length !== 1) throw new Error("Guided did not create exactly one canonical action");
  const action = records.actions[0]!;
  if (action.status !== "succeeded" || action.actionType !== EXACT_NMAP_TOOL_ID
    || action.target !== EXACT_GUIDED_TARGET || action.guidedDecisionId !== decisionId) {
    throw new Error("Guided did not execute only the exact approved Nmap action");
  }
  if (records.logs.length !== 1 || records.logs[0]!.domain !== "local_tool_execution"
    || records.logs[0]!.recordType !== "bounded_process_output") {
    throw new Error("Guided Nmap did not retain exactly one bounded Engagement Log record");
  }
  if (records.observations.length !== 1) throw new Error("Guided Nmap did not retain exactly one observation");
  const observation = records.observations[0]!;
  const sources = array(observation.sources, "Guided Nmap observation sources")
    .map((value) => object(value, "Guided Nmap observation source"));
  if (observation.observationType !== "tcp_service_scan" || observation.verificationState !== "unverified"
    || observation.sourceTool !== EXACT_NMAP_TOOL_ID || sources.length !== 1
    || sources[0]!.parserId !== REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID
    || sources[0]!.parserVersion !== REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION) {
    throw new Error("Guided Nmap observation semantics or parser provenance drifted");
  }
  if (records.candidates.length !== 0 || records.verifiedEvidence.length !== 0 || records.evidence.length !== 0) {
    throw new Error("Guided Nmap incorrectly promoted raw operational output into evidence");
  }
  if (records.evaluations.length !== 1 || records.evaluations[0]!.journey !== "guided") {
    throw new Error("Guided completion did not create exactly one journey-aware evaluation");
  }
  const brain = await assertBrainRunAnchors(
    client,
    missionId,
    runId,
    text(records.evaluations[0]!.id, "Guided evaluation ID"),
    connectionId,
  );
  return {
    missionId,
    runId,
    decisionId,
    status: terminal.status,
    target: `${EXACT_GUIDED_TARGET}:${EXACT_GUIDED_PORT}`,
    toolId: EXACT_NMAP_TOOL_ID,
    parser: `${REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID}@${REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION}`,
    localCommanderGuidance: {
      mode: "local_deterministic",
      contextPackId: guidanceContextPackId,
      providerContacted: false,
      toolDispatched: false,
      targetContacted: false,
      planMutated: false,
      exactDecisionRemainedPending: true,
    },
    actions: 1,
    engagementLogs: 1,
    observations: 1,
    evidenceCandidates: 0,
    verifiedEvidence: 0,
    evaluations: 1,
    terminalBoundary,
    brain,
  } as const;
}

export async function runFunctionalRuntimeProof(token: string): Promise<JsonObject> {
  const client = proofClient(token);
  const now = new Date();
  const [liveness, readiness, capabilitySelfTests, brainHealth, brainSummary, vault] = await Promise.all([
    client.request("/api/v2/health"),
    client.request("/api/v2/system/readiness"),
    client.request("/api/v2/system/capability-self-tests"),
    client.request("/api/v2/brain/health"),
    client.request("/api/v2/brain/summary"),
    client.request("/api/v2/brain/vault"),
  ]);
  assertFunctionalRuntimeLiveness(liveness);
  const runtime = assertExactRuntimeReadiness(readiness, capabilitySelfTests, now);
  const brain = assertConnectedBrain(brainHealth, brainSummary, vault);
  const nonce = randomUUID();
  const autonomous = await autonomousProof(client, nonce, brain.connectionId);
  const autonomousIp = await autonomousIpProof(client, nonce, brain.connectionId);
  const guided = await guidedNmapProof(client, nonce, brain.connectionId);
  const quiescence = await waitForGlobalV2Quiescence();
  return {
    schemaVersion: "ti-scale.functional-runtime-proof.v2",
    status: "passed",
    origin: FUNCTIONAL_RUNTIME_PROOF_ORIGIN,
    checkedAt: new Date().toISOString(),
    readiness: {
      status: "healthy",
      guidedToolCount: runtime.guidedToolIds.length,
      guidedToolIds: runtime.guidedToolIds,
      autonomousActionClassCount: EXPECTED_AUTONOMOUS_ACTION_CLASS_IDS.length,
      autonomousActionClassIds: EXPECTED_AUTONOMOUS_ACTION_CLASS_IDS,
      capabilityReceiptExpiresAt: runtime.capabilityReceiptExpiresAt,
    },
    autonomous,
    autonomousIp,
    guided,
    quiescence,
    secondBrain: brain.receipt,
    secretHandling: {
      tokenSource: "private_root_file",
      tokenPersistedByProof: false,
      tokenIncludedInReceipt: false,
    },
  };
}

async function main(): Promise<void> {
  parseFunctionalRuntimeProofArguments(process.argv.slice(2));
  const receipt = await withTrustedOperatorToken(runFunctionalRuntimeProof);
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `Functional runtime proof failed: ${safeMessage(error instanceof Error ? error.message : undefined, "unknown error")}\n`,
    );
    process.exitCode = 1;
  });
}
