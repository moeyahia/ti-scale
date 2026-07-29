#!/usr/bin/env bun

import { randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { resolve } from "node:path";
import { createDatabaseConnection, type SqliteDatabase } from "../server/db";
import {
  REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID,
  REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION,
} from "../server/local-tools";

type JsonObject = Record<string, unknown>;

export const REVIEWED_WEB_LIVE_PROOF_CONFIRMATION =
  "reviewed-web-live-proof-2026.07.20-v1" as const;
export const REVIEWED_WEB_LIVE_PROOF_ORIGIN = "http://127.0.0.1:3132" as const;
export const REVIEWED_WEB_LIVE_PROOF_TOKEN_PATH = "/etc/ti-scale/operator-token" as const;
export const REVIEWED_WEB_LIVE_PROOF_DATABASE_PATH = "/var/lib/ti-scale/data/ti-scale.sqlite" as const;

export const REVIEWED_WEB_TOOL_IDS = Object.freeze([
  "kali:whatweb-bounded-fingerprint",
  "kali:ffuf-bounded-content-discovery",
] as const);

export const REVIEWED_FFUF_PATHS = Object.freeze([
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

const TOKEN_TRUST_ROOT = "/etc/ti-scale";
const MAX_RESPONSE_BYTES = 2 * 1_024 * 1_024;
const REQUEST_TIMEOUT_MS = 15_000;
const DECISION_TIMEOUT_MS = 45_000;
const RUN_TIMEOUT_MS = 120_000;
const CANCELLATION_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 100;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const TERMINAL_RUN_STATUSES = new Set(["completed", "failed", "cancelled"]);

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

function safeMessage(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const normalized = value.replace(/[\u0000-\u001f\u007f]/gu, " ").replace(/\s+/gu, " ").trim();
  return normalized ? normalized.slice(0, 500) : fallback;
}

function timestamp(value: unknown, label: string): number {
  const normalized = text(value, label);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed)) throw new Error(`${label} was not a timestamp`);
  return parsed;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

export function reviewedWebLiveProofUsage(): string {
  return `bun run scripts/smoke-reviewed-web-assessment.ts --execute --confirm ${REVIEWED_WEB_LIVE_PROOF_CONFIRMATION}`;
}

export function parseReviewedWebLiveProofArguments(argv: readonly string[]): void {
  if (argv.length !== 3
    || argv[0] !== "--execute"
    || argv[1] !== "--confirm"
    || argv[2] !== REVIEWED_WEB_LIVE_PROOF_CONFIRMATION) {
    throw new Error(
      `This proof creates, executes, and terminally cancels disposable loopback missions while retaining their canonical audit history. Use the exact command: ${reviewedWebLiveProofUsage()}`,
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
  const tokenPath = resolve(REVIEWED_WEB_LIVE_PROOF_TOKEN_PATH);
  const trustRoot = resolve(TOKEN_TRUST_ROOT);
  if (tokenPath !== REVIEWED_WEB_LIVE_PROOF_TOKEN_PATH
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
  const bytes = Buffer.from(await response.arrayBuffer());
  try {
    if (bytes.byteLength > MAX_RESPONSE_BYTES) throw new Error(`${label} exceeded the response-size boundary`);
    return object(JSON.parse(bytes.toString("utf8")) as unknown, label);
  } catch (error) {
    if (error instanceof Error && (error.message.endsWith("was not a JSON object")
      || error.message.endsWith("exceeded the response-size boundary"))) throw error;
    throw new Error(`${label} was not valid JSON`);
  } finally {
    bytes.fill(0);
  }
}

export interface ReviewedWebProofClient {
  readonly request: (
    path: string,
    options?: Readonly<{
      method?: "GET" | "POST";
      body?: JsonObject;
      idempotencyKey?: string;
      expectedStatus?: 200 | 201;
    }>,
  ) => Promise<JsonObject>;
}

function proofClient(token: string): ReviewedWebProofClient {
  return {
    async request(path, options = {}) {
      if (!path.startsWith("/api/v2/") || path.includes("\\") || path.includes("\u0000")) {
        throw new Error("The proof attempted to leave the fixed V2 API path");
      }
      const response = await fetch(new URL(path, REVIEWED_WEB_LIVE_PROOF_ORIGIN), {
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
        throw new Error(
          `${path} failed (${response.status}, ${safeMessage(payload.code, "unknown_code")}): ${safeMessage(payload.humanMessage, "No safe explanation was returned")}`,
        );
      }
      return payload;
    },
  };
}

export interface ReviewedWebReadinessReceipt {
  readonly checkedAt: string;
  readonly expiresAt: string;
  readonly readyToolIds: readonly string[];
  readonly selfTestIds: readonly string[];
  readonly intakeActionClassIds: readonly string[];
}

export function assertReviewedWebReadiness(
  readinessValue: unknown,
  selfTestsValue: unknown,
  intakeValue: unknown,
  now = new Date(),
): ReviewedWebReadinessReceipt {
  const readiness = object(readinessValue, "readiness response");
  const dependencies = object(readiness.dependencies, "readiness dependencies");
  const local = object(dependencies.guidedLocalToolExecution, "Guided local-tool readiness");
  const readyToolIds = array(local.readyToolIds, "ready local tool IDs")
    .map((value) => text(value, "ready local tool ID"));
  if (readiness.status !== "healthy"
    || local.status !== "ready"
    || local.executionBinding !== "reviewed_local_process"
    || local.exactDecisionRequired !== true
    || local.targetInteraction !== "operator_approved_exact_step"
    || local.providerContact !== false
    || local.mcpTransport !== false
    || REVIEWED_WEB_TOOL_IDS.some((toolId) => !readyToolIds.includes(toolId))) {
    throw new Error("The reviewed WhatWeb/FFUF pack is not live behind the exact Guided local-process boundary");
  }
  const checkedAt = text(local.checkedAt, "Guided local-tool checked time");
  const expiresAt = text(local.expiresAt, "Guided local-tool expiry");
  if (timestamp(expiresAt, "Guided local-tool expiry") <= now.getTime()) {
    throw new Error("The reviewed WhatWeb/FFUF activation receipt is expired");
  }

  const selfTests = object(selfTestsValue, "capability self-tests response");
  const results = array(selfTests.results, "capability self-test results")
    .map((value) => object(value, "capability self-test result"));
  const requiredSelfTestIds: string[] = [];
  const dependencySuffixes = [
    "operator-activation",
    "executable-integrity",
    "isolated-target-free-readiness",
    "direct-argv-adapter",
    "workspace-confinement",
    "result-sink",
    "cancellation",
  ];
  for (const toolId of REVIEWED_WEB_TOOL_IDS) {
    const expectedComponentIds = [toolId, ...dependencySuffixes.map((suffix) => `${toolId}/${suffix}`)];
    for (const componentId of expectedComponentIds) {
      const match = results.find((result) => {
        const component = object(result.component, "capability self-test component");
        return component.id === componentId;
      });
      if (!match || match.status !== "pass" || match.availability !== "available") {
        throw new Error(`Reviewed web capability self-test did not pass: ${componentId}`);
      }
      const executionAuthorization = object(match.executionAuthorization, "self-test execution authorization");
      if (executionAuthorization.grantsMissionExecution !== false) {
        throw new Error(`Read-only self-test unexpectedly granted mission execution: ${componentId}`);
      }
      const freshness = object(match.freshness, "self-test freshness");
      if (freshness.state !== "fresh"
        || timestamp(freshness.expiresAt, "self-test expiry") <= now.getTime()) {
        throw new Error(`Reviewed web capability self-test is stale: ${componentId}`);
      }
      requiredSelfTestIds.push(text(match.id, "self-test ID"));
    }
  }

  const intake = object(intakeValue, "intake registry response");
  const actionClasses = object(intake.actionClasses, "intake action classes");
  const classes = object(actionClasses.classes, "intake action-class records");
  const expectedClasses = [
    ["os_technology_fingerprinting", REVIEWED_WEB_TOOL_IDS[0]],
    ["web_content_endpoint_discovery_fuzzing", REVIEWED_WEB_TOOL_IDS[1]],
  ] as const;
  for (const [actionClassId, toolId] of expectedClasses) {
    const actionClass = object(classes[actionClassId], `intake action class ${actionClassId}`);
    const capability = object(actionClass.capability, `intake capability ${actionClassId}`);
    const availableToolIds = array(capability.availableToolIds, `available tools for ${actionClassId}`);
    if (capability.availability !== "supported" || !availableToolIds.includes(toolId)) {
      throw new Error(`Intake registry does not advertise live Guided tool ${toolId}`);
    }
  }
  return {
    checkedAt,
    expiresAt,
    readyToolIds: REVIEWED_WEB_TOOL_IDS,
    selfTestIds: requiredSelfTestIds,
    intakeActionClassIds: expectedClasses.map(([id]) => id),
  };
}

export function assertReviewedWebLiveness(value: unknown): void {
  const health = object(value, "Ti-Scale liveness response");
  const database = object(health.database, "Ti-Scale liveness database");
  const eventStream = object(health.eventStream, "Ti-Scale liveness event stream");
  if (health.schemaVersion !== "2.4" || health.status !== "healthy"
    || database.healthy !== true || eventStream.status !== "healthy") {
    throw new Error("Ti-Scale HTTP, database, and event-stream liveness is not fully healthy");
  }
}

interface FixtureRequest {
  readonly method: string;
  readonly path: string;
  readonly userAgent: string;
  readonly observedAt: string;
}

interface LoopbackFixture {
  readonly server: Server;
  readonly origin: string;
  readonly secretSentinel: string;
  readonly requests: FixtureRequest[];
  readonly close: () => Promise<void>;
}

function requestPath(request: IncomingMessage): string {
  try {
    return new URL(request.url ?? "/", "http://127.0.0.1").pathname;
  } catch {
    return "/invalid";
  }
}

function sendFixtureResponse(response: ServerResponse, status: number, secretSentinel: string): void {
  const body = "<!doctype html><html><head><title>Ti-Scale loopback fixture</title></head><body><main>Reviewed web-tool smoke fixture</main></body></html>";
  response.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Server": "TiScaleLoopbackFixture/1",
    "X-Powered-By": `api_key=${secretSentinel};FixtureCore`,
    "Cache-Control": "no-store",
    "Connection": "close",
  });
  response.end(body);
}

async function startLoopbackFixture(): Promise<LoopbackFixture> {
  const secretSentinel = `web-smoke-${randomUUID()}`;
  const requests: FixtureRequest[] = [];
  const sockets = new Set<Socket>();
  const heldResponses = new Set<ServerResponse>();
  const server = createServer((request, response) => {
    const path = requestPath(request);
    requests.push({
      method: request.method ?? "UNKNOWN",
      path,
      userAgent: typeof request.headers["user-agent"] === "string" ? request.headers["user-agent"] : "",
      observedAt: new Date().toISOString(),
    });
    if (path === "/slow/") {
      heldResponses.add(response);
      response.once("close", () => heldResponses.delete(response));
      return;
    }
    sendFixtureResponse(response, path === "/" || path === "/health" ? 200 : path === "/admin" ? 403 : 404, secretSentinel);
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", rejectListen);
      resolveListen();
    });
  });
  const address = server.address() as AddressInfo;
  let closed = false;
  return {
    server,
    origin: `http://127.0.0.1:${address.port}`,
    secretSentinel,
    requests,
    async close() {
      if (closed) return;
      closed = true;
      for (const response of heldResponses) response.destroy();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    },
  };
}

interface CreatedMission {
  readonly missionId: string;
  readonly runId: string;
}

async function createGuidedMission(
  client: ReviewedWebProofClient,
  target: string,
  nonce: string,
  suffix: string,
): Promise<CreatedMission> {
  const created = await client.request("/api/v2/missions", {
    method: "POST",
    expectedStatus: 201,
    idempotencyKey: `reviewed-web-create-${suffix}-${nonce}`,
    body: {
      journey: "guided",
      launch: true,
      authorizationConfirmed: true,
      title: `Disposable reviewed web proof ${suffix} ${nonce}`,
      objective: "Inspect only the disposable loopback web fixture with the reviewed bounded fingerprint and fixed-path discovery tools, retain operational truth, and create no evidence automatically.",
      target,
      explanationDepth: "balanced",
      executionPreference: "single_step_agent",
      evidenceExpectations: [],
    },
  });
  return {
    missionId: text(object(created.mission, "created Guided mission").id, "Guided mission ID"),
    runId: text(object(created.run, "created Guided run").id, "Guided run ID"),
  };
}

export interface ExactWebDecisionReceipt {
  readonly decisionId: string;
  readonly stepId: string;
  readonly fingerprint: string;
  readonly requestedParameters: JsonObject;
}

export function assertExactWebDecision(
  decisionValue: unknown,
  toolId: typeof REVIEWED_WEB_TOOL_IDS[number],
  targetUrl: string,
): ExactWebDecisionReceipt {
  const decision = object(decisionValue, "pending Guided decision");
  const requested = object(decision.requestedParameters, "Guided requested parameters");
  const argumentsEnvelope = object(requested.arguments, "Guided requested argument envelope");
  const parameters = object(argumentsEnvelope.parameters, "Guided requested tool parameters");
  if (decision.status !== "pending"
    || requested.kind !== "tool"
    || requested.actionType !== toolId
    || requested.target !== targetUrl
    || argumentsEnvelope.executionBinding !== "reviewed_local_process"
    || argumentsEnvelope.toolId !== toolId
    || parameters.url !== targetUrl
    || typeof parameters.workspace !== "string"
    || !parameters.workspace.startsWith("/")) {
    throw new Error(`Guided decision did not preserve the exact reviewed ${toolId} action and canonical URL`);
  }
  return {
    decisionId: text(decision.id, "Guided decision ID"),
    stepId: text(decision.stepId, "Guided step ID"),
    fingerprint: text(decision.actionFingerprint, "Guided action fingerprint"),
    requestedParameters: requested,
  };
}

async function waitForDecision(
  client: ReviewedWebProofClient,
  runId: string,
  toolId: typeof REVIEWED_WEB_TOOL_IDS[number],
  targetUrl: string,
): Promise<ExactWebDecisionReceipt> {
  const deadline = Date.now() + DECISION_TIMEOUT_MS;
  do {
    const runResponse = await client.request(`/api/v2/runs/${encodeURIComponent(runId)}`);
    const run = object(runResponse.run, "Guided run while awaiting decision");
    const status = String(run.status ?? "");
    if (TERMINAL_RUN_STATUSES.has(status) || status === "blocked") {
      throw new Error(`Guided run ended ${status} before presenting ${toolId}: ${safeMessage(run.statusReason, "No reason returned")}`);
    }
    const decisions = await client.request(`/api/v2/decisions?status=pending&runId=${encodeURIComponent(runId)}`);
    const items = array(decisions.items, "pending Guided decisions");
    if (items.length > 1) throw new Error("Guided presented more than one pending exact-step decision");
    if (items[0]) return assertExactWebDecision(items[0], toolId, targetUrl);
    await sleep(POLL_INTERVAL_MS);
  } while (Date.now() < deadline);
  throw new Error(`Guided did not present ${toolId} within ${DECISION_TIMEOUT_MS} ms`);
}

async function approveDecision(
  client: ReviewedWebProofClient,
  decision: ExactWebDecisionReceipt,
  nonce: string,
  suffix: string,
): Promise<void> {
  await client.request(`/api/v2/guided-decisions/${encodeURIComponent(decision.decisionId)}/approve`, {
    method: "POST",
    idempotencyKey: `reviewed-web-approve-${suffix}-${nonce}`,
    body: {
      expectedFingerprint: decision.fingerprint,
      expectedParameters: decision.requestedParameters,
      reason: "Approve only this represented disposable loopback action with its exact canonical URL and normalized parameters.",
    },
  });
}

async function runProjection(client: ReviewedWebProofClient, runId: string): Promise<JsonObject> {
  return object(
    (await client.request(`/api/v2/runs/${encodeURIComponent(runId)}`)).run,
    "run projection",
  );
}

async function waitForRunStatus(
  client: ReviewedWebProofClient,
  runId: string,
  expected: "completed" | "cancelled",
  timeoutMs = RUN_TIMEOUT_MS,
): Promise<JsonObject> {
  const deadline = Date.now() + timeoutMs;
  do {
    const run = await runProjection(client, runId);
    const status = String(run.status ?? "");
    if (status === expected) return run;
    if (TERMINAL_RUN_STATUSES.has(status) || status === "blocked") {
      throw new Error(`Guided run ended ${status}, expected ${expected}: ${safeMessage(run.statusReason, "No reason returned")}`);
    }
    await sleep(POLL_INTERVAL_MS);
  } while (Date.now() < deadline);
  throw new Error(`Guided run did not reach ${expected} within ${timeoutMs} ms`);
}

async function runCollections(client: ReviewedWebProofClient, missionId: string, runId: string) {
  const mission = encodeURIComponent(missionId);
  const run = encodeURIComponent(runId);
  const [actions, logs, observations, candidates, verifiedEvidence, evidence, findings, events] = await Promise.all([
    client.request(`/api/v2/operations/actions?runId=${run}&limit=20`),
    client.request(`/api/v2/operational-truth/missions/${mission}/logs?runId=${run}&limit=20`),
    client.request(`/api/v2/operational-truth/missions/${mission}/observations?runId=${run}&limit=20`),
    client.request(`/api/v2/operational-truth/missions/${mission}/evidence-candidates?runId=${run}&limit=20`),
    client.request(`/api/v2/operational-truth/missions/${mission}/verified-evidence?runId=${run}&limit=20`),
    client.request(`/api/v2/intelligence/evidence?missionId=${mission}&runId=${run}&limit=20`),
    client.request(`/api/v2/intelligence/findings?missionId=${mission}&runId=${run}&limit=20`),
    client.request(`/api/v2/observability/events?runId=${run}&limit=100`),
  ]);
  return {
    actions: array(actions.items, "run actions").map((value) => object(value, "run action")),
    logs: array(logs.items, "Engagement Logs").map((value) => object(value, "Engagement Log")),
    observations: array(observations.items, "observations").map((value) => object(value, "observation")),
    candidates: array(candidates.items, "evidence candidates").map((value) => object(value, "evidence candidate")),
    verifiedEvidence: array(verifiedEvidence.items, "verified evidence").map((value) => object(value, "verified evidence")),
    evidence: array(evidence.items, "Evidence Vault records").map((value) => object(value, "Evidence Vault record")),
    findings: array(findings.items, "findings").map((value) => object(value, "finding")),
    events: array(events.items, "run events").map((value) => object(value, "run event")),
  };
}

function assertTerminalProjection(run: JsonObject, expectedStatus: "completed" | "cancelled"): void {
  if (run.status !== expectedStatus
    || run.currentStepId !== null
    || run.currentOwnerId !== null
    || run.leaseExpiresAt !== null
    || typeof run.endedAt !== "string") {
    throw new Error(`Terminal ${expectedStatus} run retained an active step, owner, lease, or missing end time`);
  }
}

interface DatabaseRunReceipt {
  readonly toolCalls: readonly JsonObject[];
  readonly assignments: readonly JsonObject[];
  readonly providerTurns: number;
  readonly mcpToolCalls: number;
  readonly activeActions: number;
  readonly activeToolCalls: number;
  readonly activeAssignments: number;
  readonly activeLeases: number;
  readonly secretAbsent: true;
}

function count(database: SqliteDatabase, sql: string, runId: string): number {
  return Number((database.prepare(sql).get(runId) as { count: number }).count);
}

function databaseRunReceipt(runId: string, secretSentinel?: string): DatabaseRunReceipt {
  const database = createDatabaseConnection({
    filename: REVIEWED_WEB_LIVE_PROOF_DATABASE_PATH,
    readonly: true,
    fileMustExist: true,
  });
  try {
    const toolCalls = database.prepare(`
      SELECT tc.id, tc.provider, tc.tool_name AS toolName, tc.mcp_server_id AS mcpServerId,
        tc.status, tc.error_category AS errorCategory, tc.output_summary AS outputSummary,
        tc.redacted_payload_json AS redactedPayloadJson, tc.started_at AS startedAt, tc.ended_at AS endedAt
      FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
      WHERE a.run_id = ? ORDER BY tc.created_at, tc.id
    `).all(runId) as JsonObject[];
    const assignments = database.prepare(`
      SELECT id, status, lease_owner AS leaseOwner, lease_expires_at AS leaseExpiresAt,
        started_at AS startedAt, ended_at AS endedAt
      FROM assignments WHERE run_id = ? ORDER BY created_at, id
    `).all(runId) as JsonObject[];
    const providerTurns = count(database, "SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?", runId);
    const mcpToolCalls = count(database, `
      SELECT COUNT(*) AS count FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
      WHERE a.run_id = ? AND tc.mcp_server_id IS NOT NULL
    `, runId);
    const activeActions = count(database, "SELECT COUNT(*) AS count FROM actions WHERE run_id = ? AND status IN ('queued', 'running')", runId);
    const activeToolCalls = count(database, `
      SELECT COUNT(*) AS count FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
      WHERE a.run_id = ? AND tc.status IN ('queued', 'running')
    `, runId);
    const activeAssignments = count(database, "SELECT COUNT(*) AS count FROM assignments WHERE run_id = ? AND status IN ('queued', 'active', 'blocked')", runId);
    const activeLeases = count(database, `
      SELECT COUNT(*) AS count FROM control_plane_leases
      WHERE run_id = ? AND released_at IS NULL AND datetime(expires_at) > datetime('now')
    `, runId);
    if (secretSentinel) {
      const surfaces = {
        actions: database.prepare(`
          SELECT normalized_arguments_json, intent_summary, result_summary
          FROM actions WHERE run_id = ?
        `).all(runId),
        toolCalls,
        logs: database.prepare(`
          SELECT human_summary, technical_payload_json FROM engagement_log_records WHERE run_id = ?
        `).all(runId),
        observations: database.prepare(`
          SELECT statement, normalized_value_json FROM observations WHERE run_id = ?
        `).all(runId),
        events: database.prepare("SELECT summary, payload_json FROM events WHERE run_id = ?").all(runId),
        evidence: database.prepare(`
          SELECT source, target, evidence_type, provenance_json, summary, extracted_text
          FROM evidence WHERE run_id = ?
        `).all(runId),
        candidates: database.prepare(`
          SELECT evidence_type, label, meaning, promotion_reason, validation_requirements_json
          FROM evidence_candidates WHERE run_id = ?
        `).all(runId),
      };
      if (JSON.stringify(surfaces).includes(secretSentinel)) {
        throw new Error("The synthetic loopback secret leaked into canonical mission records");
      }
    }
    return {
      toolCalls,
      assignments,
      providerTurns,
      mcpToolCalls,
      activeActions,
      activeToolCalls,
      activeAssignments,
      activeLeases,
      secretAbsent: true,
    };
  } finally {
    database.close();
  }
}

function assertNoPendingDecisions(
  client: ReviewedWebProofClient,
  runId: string,
): Promise<void> {
  return client.request(`/api/v2/decisions?status=pending&runId=${encodeURIComponent(runId)}`)
    .then((response) => {
      if (array(response.items, "pending terminal decisions").length !== 0) {
        throw new Error("Terminal proof run retained a pending Guided decision");
      }
    });
}

function assertSuccessfulRecords(
  records: Awaited<ReturnType<typeof runCollections>>,
  decisions: readonly ExactWebDecisionReceipt[],
  target: string,
  secretSentinel: string,
): void {
  if (records.actions.length !== 2 || records.logs.length !== 2 || records.observations.length !== 2) {
    throw new Error("Reviewed web run did not persist exactly two actions, two Engagement Logs, and two observations");
  }
  for (const [index, toolId] of REVIEWED_WEB_TOOL_IDS.entries()) {
    const action = records.actions.find((candidate) => candidate.actionType === toolId);
    if (!action || action.status !== "succeeded" || action.target !== target
      || action.guidedDecisionId !== decisions[index]?.decisionId) {
      throw new Error(`Canonical action did not match the exact approved ${toolId} decision`);
    }
  }
  const expectedObservations = new Map<string, string>([
    [REVIEWED_WEB_TOOL_IDS[0], "web_technology_fingerprint"],
    [REVIEWED_WEB_TOOL_IDS[1], "web_endpoint_discovery"],
  ]);
  for (const observation of records.observations) {
    const sourceTool = text(observation.sourceTool, "observation source tool");
    const sources = array(observation.sources, "observation sources")
      .map((value) => object(value, "observation source"));
    if (observation.observationType !== expectedObservations.get(sourceTool)
      || observation.verificationState !== "unverified"
      || sources.length !== 1
      || sources[0]?.parserId !== REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID
      || sources[0]?.parserVersion !== REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION) {
      throw new Error(`Observation provenance drifted for ${sourceTool}`);
    }
  }
  for (const log of records.logs) {
    if (log.domain !== "local_tool_execution" || log.recordType !== "bounded_process_output") {
      throw new Error("Reviewed web output was not retained as a bounded Engagement Log");
    }
  }
  if (records.candidates.length !== 0 || records.verifiedEvidence.length !== 0
    || records.evidence.length !== 0 || records.findings.length !== 0) {
    throw new Error("Reviewed web output was incorrectly promoted into evidence or a finding");
  }
  const serialized = JSON.stringify(records);
  if (serialized.includes(secretSentinel)) {
    throw new Error("The synthetic loopback secret leaked through authenticated canonical APIs");
  }
  if (!serialized.includes("[REDACTED]")) {
    throw new Error("The proof fixture's synthetic secret did not produce an inspectable redaction marker");
  }
}

function assertFixtureRequests(fixture: LoopbackFixture): Readonly<{
  rootRequests: 1;
  ffufRequests: 14;
  unexpectedRequests: 0;
}>
{
  const reviewed = fixture.requests.filter(({ userAgent }) =>
    userAgent === "Ti-Scale-Reviewed-Web-Assessment/1");
  const paths = reviewed.map(({ path }) => path);
  if (paths.filter((path) => path === "/").length !== 1) {
    throw new Error("WhatWeb did not make exactly one request to the exact approved root URL");
  }
  for (const path of REVIEWED_FFUF_PATHS) {
    if (paths.filter((candidate) => candidate === `/${path}`).length !== 1) {
      throw new Error(`FFUF did not make exactly one bounded request for /${path}`);
    }
  }
  const allowed = new Set(["/", ...REVIEWED_FFUF_PATHS.map((path) => `/${path}`)]);
  const unexpected = reviewed.filter(({ path, method }) => !allowed.has(path) || method !== "GET");
  if (reviewed.length !== 15 || unexpected.length !== 0) {
    throw new Error("Reviewed web tools contacted an unexpected path, method, or request count");
  }
  return { rootRequests: 1, ffufRequests: 14, unexpectedRequests: 0 };
}

async function waitForRunningAction(
  client: ReviewedWebProofClient,
  runId: string,
  toolId: string,
): Promise<void> {
  const deadline = Date.now() + CANCELLATION_TIMEOUT_MS;
  do {
    const response = await client.request(`/api/v2/operations/actions?runId=${encodeURIComponent(runId)}&limit=20`);
    const actions = array(response.items, "cancellation actions").map((value) => object(value, "cancellation action"));
    if (actions.some((action) => action.actionType === toolId && action.status === "running")) return;
    const run = await runProjection(client, runId);
    if (TERMINAL_RUN_STATUSES.has(String(run.status)) || run.status === "blocked") {
      throw new Error(`Cancellation proof run reached ${String(run.status)} before its action was observed running`);
    }
    await sleep(25);
  } while (Date.now() < deadline);
  throw new Error("Cancellation proof never exposed its approved action as running");
}

async function cancelRun(
  client: ReviewedWebProofClient,
  runId: string,
  nonce: string,
  reason: string,
): Promise<JsonObject> {
  const response = await client.request(`/api/v2/runs/${encodeURIComponent(runId)}/cancel`, {
    method: "POST",
    idempotencyKey: `reviewed-web-cancel-${nonce}-${runId}`,
    body: { reason },
  });
  return object(response.run, "cancelled run response");
}

async function bestEffortCleanup(
  client: ReviewedWebProofClient,
  missions: readonly CreatedMission[],
  nonce: string,
): Promise<void> {
  for (const mission of missions) {
    try {
      const run = await runProjection(client, mission.runId);
      if (!TERMINAL_RUN_STATUSES.has(String(run.status))) {
        await cancelRun(client, mission.runId, `${nonce}-cleanup`, "Dispose of an interrupted loopback production smoke mission.");
        await waitForRunStatus(client, mission.runId, "cancelled", CANCELLATION_TIMEOUT_MS);
      }
    } catch {
      // The caller retains the primary failure. The final archive attempt still
      // reports any remaining cleanup defect when there was no primary error.
    }
  }
}

export async function runReviewedWebLiveProof(token: string): Promise<JsonObject> {
  const client = proofClient(token);
  const nonce = randomUUID();
  const missions: CreatedMission[] = [];
  const fixture = await startLoopbackFixture();
  let completedNormally = false;
  try {
    const [liveness, readinessHealth, selfTests, intake] = await Promise.all([
      client.request("/api/v2/health"),
      client.request("/api/v2/system/readiness"),
      client.request("/api/v2/system/capability-self-tests"),
      client.request("/api/v2/registries/intake"),
    ]);
    assertReviewedWebLiveness(liveness);
    const readiness = assertReviewedWebReadiness(readinessHealth, selfTests, intake);

    const target = `${fixture.origin}/`;
    const successMission = await createGuidedMission(client, target, nonce, "success");
    missions.push(successMission);
    const firstDecision = await waitForDecision(client, successMission.runId, REVIEWED_WEB_TOOL_IDS[0], target);
    const beforeFirst = await client.request(`/api/v2/operations/actions?runId=${encodeURIComponent(successMission.runId)}&limit=20`);
    if (array(beforeFirst.items, "actions before WhatWeb decision").length !== 0) {
      throw new Error("Guided dispatched WhatWeb before the exact operator decision");
    }
    await approveDecision(client, firstDecision, nonce, "whatweb");

    const secondDecision = await waitForDecision(client, successMission.runId, REVIEWED_WEB_TOOL_IDS[1], target);
    const between = await client.request(`/api/v2/operations/actions?runId=${encodeURIComponent(successMission.runId)}&limit=20`);
    const betweenActions = array(between.items, "actions before FFUF decision")
      .map((value) => object(value, "action before FFUF decision"));
    if (betweenActions.length !== 1
      || betweenActions[0]?.actionType !== REVIEWED_WEB_TOOL_IDS[0]
      || betweenActions[0]?.status !== "succeeded") {
      throw new Error("FFUF was not held behind its own decision after the completed WhatWeb action");
    }
    await approveDecision(client, secondDecision, nonce, "ffuf");
    const completed = await waitForRunStatus(client, successMission.runId, "completed");
    assertTerminalProjection(completed, "completed");
    await assertNoPendingDecisions(client, successMission.runId);
    const successRecords = await runCollections(client, successMission.missionId, successMission.runId);
    assertSuccessfulRecords(successRecords, [firstDecision, secondDecision], target, fixture.secretSentinel);
    const successDatabase = databaseRunReceipt(successMission.runId, fixture.secretSentinel);
    if (successDatabase.toolCalls.length !== 2
      || successDatabase.toolCalls.some((call) => call.provider !== "reviewed-local-process"
        || call.status !== "succeeded" || call.mcpServerId !== null || typeof call.endedAt !== "string")
      || successDatabase.providerTurns !== 0
      || successDatabase.mcpToolCalls !== 0
      || successDatabase.activeActions !== 0
      || successDatabase.activeToolCalls !== 0
      || successDatabase.activeAssignments !== 0
      || successDatabase.activeLeases !== 0) {
      throw new Error("Successful reviewed web run did not reach exact direct-process terminal quiescence");
    }
    const fixtureRequests = assertFixtureRequests(fixture);

    const cancellationTarget = `${fixture.origin}/slow/`;
    const cancellationMission = await createGuidedMission(client, cancellationTarget, nonce, "cancellation");
    missions.push(cancellationMission);
    const cancellationDecision = await waitForDecision(
      client,
      cancellationMission.runId,
      REVIEWED_WEB_TOOL_IDS[0],
      cancellationTarget,
    );
    await approveDecision(client, cancellationDecision, nonce, "cancel-whatweb");
    await waitForRunningAction(client, cancellationMission.runId, REVIEWED_WEB_TOOL_IDS[0]);
    const cancelledFromApi = await cancelRun(
      client,
      cancellationMission.runId,
      nonce,
      "Verify cooperative child-process cancellation against the disposable slow loopback response.",
    );
    if (cancelledFromApi.status !== "cancelled") {
      throw new Error("Run cancellation did not return a cancelled canonical projection");
    }
    const cancelled = await waitForRunStatus(client, cancellationMission.runId, "cancelled", CANCELLATION_TIMEOUT_MS);
    assertTerminalProjection(cancelled, "cancelled");
    await assertNoPendingDecisions(client, cancellationMission.runId);
    const cancellationRecords = await runCollections(
      client,
      cancellationMission.missionId,
      cancellationMission.runId,
    );
    if (cancellationRecords.actions.some((action) => action.status === "queued" || action.status === "running")
      || cancellationRecords.candidates.length !== 0
      || cancellationRecords.verifiedEvidence.length !== 0
      || cancellationRecords.evidence.length !== 0
      || cancellationRecords.findings.length !== 0) {
      throw new Error("Cancelled reviewed web run retained work or promoted evidence");
    }
    const cancellationDatabase = databaseRunReceipt(cancellationMission.runId);
    if (cancellationDatabase.toolCalls.length !== 1
      || cancellationDatabase.toolCalls[0]?.status !== "cancelled"
      || typeof cancellationDatabase.toolCalls[0]?.endedAt !== "string"
      || cancellationDatabase.activeActions !== 0
      || cancellationDatabase.activeToolCalls !== 0
      || cancellationDatabase.activeAssignments !== 0
      || cancellationDatabase.activeLeases !== 0) {
      throw new Error("Cancelled reviewed web action did not release its tool call, assignment, or lease");
    }
    if (fixture.requests.filter(({ path }) => path === "/slow/").length !== 1) {
      throw new Error("Cancellation fixture did not observe exactly one in-flight target request");
    }

    completedNormally = true;
    return {
      schemaVersion: "ti-scale.reviewed-web-live-proof.v1",
      status: "passed",
      checkedAt: new Date().toISOString(),
      target: "ephemeral 127.0.0.1 HTTP fixture",
      readiness,
      successfulRun: {
        missionId: successMission.missionId,
        runId: successMission.runId,
        status: "completed",
        decisions: [
          { decisionId: firstDecision.decisionId, toolId: REVIEWED_WEB_TOOL_IDS[0] },
          { decisionId: secondDecision.decisionId, toolId: REVIEWED_WEB_TOOL_IDS[1] },
        ],
        actions: successRecords.actions.length,
        toolCalls: successDatabase.toolCalls.length,
        engagementLogs: successRecords.logs.length,
        observations: successRecords.observations.length,
        evidenceCandidates: successRecords.candidates.length,
        verifiedEvidence: successRecords.verifiedEvidence.length,
        evidenceVaultRecords: successRecords.evidence.length,
        findings: successRecords.findings.length,
        providerTurns: successDatabase.providerTurns,
        mcpToolCalls: successDatabase.mcpToolCalls,
        fixtureRequests,
        redaction: { syntheticSecretAbsent: true, markerObserved: true },
        quiescence: {
          activeActions: successDatabase.activeActions,
          activeToolCalls: successDatabase.activeToolCalls,
          activeAssignments: successDatabase.activeAssignments,
          activeLeases: successDatabase.activeLeases,
          pendingDecisions: 0,
        },
      },
      cancellationRun: {
        missionId: cancellationMission.missionId,
        runId: cancellationMission.runId,
        status: "cancelled",
        decisionId: cancellationDecision.decisionId,
        toolId: REVIEWED_WEB_TOOL_IDS[0],
        toolCalls: cancellationDatabase.toolCalls.length,
        evidenceCandidates: cancellationRecords.candidates.length,
        verifiedEvidence: cancellationRecords.verifiedEvidence.length,
        evidenceVaultRecords: cancellationRecords.evidence.length,
        findings: cancellationRecords.findings.length,
        quiescence: {
          activeActions: cancellationDatabase.activeActions,
          activeToolCalls: cancellationDatabase.activeToolCalls,
          activeAssignments: cancellationDatabase.activeAssignments,
          activeLeases: cancellationDatabase.activeLeases,
          pendingDecisions: 0,
        },
      },
      cleanup: {
        fixtureClosed: true,
        terminalDisposableMissions: missions.length,
        activeRuns: 0,
        activeActions: 0,
        activeToolCalls: 0,
        activeAssignments: 0,
        activeLeases: 0,
        retainedCanonicalAuditHistory: true,
      },
    };
  } finally {
    if (!completedNormally) await bestEffortCleanup(client, missions, nonce);
    await fixture.close();
  }
}

async function main(): Promise<void> {
  try {
    parseReviewedWebLiveProofArguments(process.argv.slice(2));
    const receipt = await withTrustedOperatorToken(runReviewedWebLiveProof);
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Reviewed web live proof failed"}\n`);
    process.exitCode = 1;
  }
}

if (import.meta.main) await main();
