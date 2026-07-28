#!/usr/bin/env bun

import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import {
  createDatabaseConnection,
  type SqliteDatabase,
} from "../server/db";
import {
  ACTION_CLASS_IDS,
  AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION,
  AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
  AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
  AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_SUCCESS_CRITERION,
  AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
  type ActionClassId,
} from "../server/domain";
import {
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE,
  AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
  AUTONOMOUS_WHATWEB_ACTION_CLASS,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
} from "../server/autonomous-runtime";
import {
  DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST,
  startDisposableAutonomousAssessmentTarget,
  type DisposableAutonomousAssessmentTarget,
} from "../server/autonomous-runtime/testing/DisposableAutonomousAssessmentTarget";

type JsonObject = Record<string, unknown>;

export const AUTONOMOUS_ASSESSMENT_PROOF_ORIGIN = "http://127.0.0.1:3132" as const;
export const AUTONOMOUS_ASSESSMENT_PROOF_TARGET =
  DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST;
export const AUTONOMOUS_ASSESSMENT_PROOF_TARGET_ID =
  `target_${createHash("sha256")
    .update(`host\0${AUTONOMOUS_ASSESSMENT_PROOF_TARGET}`)
    .digest("hex")
    .slice(0, 16)}` as const;
export const AUTONOMOUS_ASSESSMENT_PROOF_TOKEN_PATH = "/etc/ti-scale/operator-token" as const;
export const AUTONOMOUS_ASSESSMENT_PROOF_DATABASE_PATH =
  "/var/lib/ti-scale/data/ti-scale.sqlite" as const;
export const AUTONOMOUS_ASSESSMENT_PROOF_CONFIRMATION =
  "run-reviewed-autonomous-assessment-on-loopback-3132" as const;

const TOKEN_TRUST_ROOT = "/etc/ti-scale";
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const MAXIMUM_RESPONSE_BYTES = 8 * 1_024 * 1_024;
const REQUEST_TIMEOUT_MS = 20_000;
const RUN_TIMEOUT_MS = 15 * 60_000;
const TERMINAL_CLOSEOUT_TIMEOUT_MS = 2 * 60_000;
const POLL_INTERVAL_MS = 500;
const AUTONOMOUS_TERMINAL_REPORT_ARTIFACT_TYPES = Object.freeze([
  "mission_report_json",
  "mission_report_markdown",
] as const);

export const AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS = Object.freeze([
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  AUTONOMOUS_HTTP_METADATA_ACTION_CLASS,
  AUTONOMOUS_WHATWEB_ACTION_CLASS,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_CLASS,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_CLASS,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_CLASS,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
] as const);

/**
 * This proof deliberately evaluates assessment outcomes only. Exploit
 * validation is an authorized optional evidence-driven branch, but a missing
 * candidate neither claims nor satisfies exploit, session, user, root, or
 * cleanup success.
 */
export const AUTONOMOUS_ASSESSMENT_SUCCESS_CRITERIA = Object.freeze([
  AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
  AUTONOMOUS_HTTP_METADATA_SUCCESS_CRITERION,
  AUTONOMOUS_WEB_FINGERPRINT_SUCCESS_CRITERION,
  AUTONOMOUS_ENDPOINT_DISCOVERY_SUCCESS_CRITERION,
  AUTONOMOUS_CVE_APPLICABILITY_SUCCESS_CRITERION,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_SUCCESS_CRITERION,
] as const);

/**
 * The first seven actions are the deterministic evidence-gathering baseline.
 * The eighth is represented only when current verified version/CVE evidence
 * matches one exact active-Vault procedure with an independently attested
 * target-outcome observer. The Full-TCP composite invokes two separately
 * attested phase tools, so the two truthful outcomes contain either eight
 * reviewed physical bindings (deferred validation) or nine (one validation).
 */
export const AUTONOMOUS_ASSESSMENT_ACTION_TYPES = Object.freeze([
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_HTTP_METADATA_ACTION_TYPE,
  AUTONOMOUS_WHATWEB_FINGERPRINT_ACTION_TYPE,
  AUTONOMOUS_ENDPOINT_DISCOVERY_ACTION_TYPE,
  AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE,
  AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
] as const);

export const AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS = Object.freeze([
  "intake",
  "planning",
  "assignment_acceptance",
  "tool_selection",
  "phase_transition",
  "finding_validation",
  "evaluation",
  "lesson_proposal",
  "reporting",
  "closeout",
] as const);

const AUTONOMOUS_ASSESSMENT_BASE_ACTION_COUNT = 7;
const AUTONOMOUS_ASSESSMENT_BASE_EXECUTION_BINDING_COUNT = 8;

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

function json(value: string, label: string): JsonObject {
  try {
    return object(JSON.parse(value) as unknown, label);
  } catch (error) {
    if (error instanceof Error && error.message.endsWith("was not a JSON object")) throw error;
    throw new Error(`${label} was not valid JSON`);
  }
}

function exactSet(actual: readonly unknown[], expected: readonly string[], label: string): void {
  const normalized = actual.map((value) => text(value, `${label} entry`));
  if (
    normalized.length !== expected.length
    || new Set(normalized).size !== normalized.length
    || expected.some((value) => !normalized.includes(value))
  ) throw new Error(`${label} did not match the exact reviewed set`);
}

function safeMessage(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const normalized = value.replace(/[\u0000-\u001f\u007f]/gu, " ").replace(/\s+/gu, " ").trim();
  return normalized ? normalized.slice(0, 700) : fallback;
}

export function formatAutonomousAssessmentProofApiError(
  path: string,
  status: number,
  payload: JsonObject,
): string {
  const nested = payload.error && typeof payload.error === "object" && !Array.isArray(payload.error)
    ? payload.error as JsonObject
    : undefined;
  const code = safeMessage(nested?.code ?? payload.code, "unknown_code");
  const explanation = safeMessage(
    nested?.humanMessage
      ?? nested?.message
      ?? payload.humanMessage
      ?? payload.message,
    "No explanation was returned",
  );
  const remediation = safeMessage(
    nested?.remediation ?? payload.remediation,
    "",
  );
  const traceId = safeMessage(nested?.traceId ?? payload.traceId, "");
  return [
    `${path} failed (${status}, ${code}): ${explanation}`,
    ...(remediation ? [`Remediation: ${remediation}`] : []),
    ...(traceId ? [`Trace: ${traceId}`] : []),
  ].join(" ");
}

export function autonomousAssessmentProofUsage(): string {
  return [
    "bun run smoke:autonomous-assessment-live",
    "--execute",
    "--confirm",
    AUTONOMOUS_ASSESSMENT_PROOF_CONFIRMATION,
  ].join(" ");
}

export function parseAutonomousAssessmentProofArguments(argv: readonly string[]): void {
  if (
    argv.length !== 3
    || argv[0] !== "--execute"
    || argv[1] !== "--confirm"
    || argv[2] !== AUTONOMOUS_ASSESSMENT_PROOF_CONFIRMATION
  ) {
    throw new Error(
      `This proof creates one authorized loopback Autonomous mission. Use the exact command: ${autonomousAssessmentProofUsage()}`,
    );
  }
}

function validateTokenBuffer(bytes: Buffer): string {
  const bounded = bytes.length > 0 && bytes.at(-1) === 0x0a
    ? bytes.subarray(0, bytes.length - 1)
    : bytes;
  if (
    bounded.length < 24
    || bounded.length > 4_096
    || bounded.includes(0x00)
    || bounded.includes(0x0a)
    || bounded.includes(0x0d)
  ) throw new Error("The root operator-token file has an invalid bounded value");
  return bounded.toString("utf8");
}

async function withTrustedOperatorToken<T>(operation: (token: string) => Promise<T>): Promise<T> {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) {
    throw new Error("The production proof must run as root to read the private operator-token file");
  }
  const tokenPath = resolve(AUTONOMOUS_ASSESSMENT_PROOF_TOKEN_PATH);
  const trustRoot = resolve(TOKEN_TRUST_ROOT);
  if (
    tokenPath !== AUTONOMOUS_ASSESSMENT_PROOF_TOKEN_PATH
    || tokenPath !== resolve(trustRoot, "operator-token")
  ) throw new Error("The operator-token path escaped its fixed trust root");
  const root = lstatSync(trustRoot, { bigint: true });
  if (root.isSymbolicLink() || !root.isDirectory() || root.uid !== 0n || (root.mode & 0o022n) !== 0n) {
    throw new Error("The operator-token trust root is not root-owned and non-writable");
  }
  const before = lstatSync(tokenPath, { bigint: true });
  if (
    before.isSymbolicLink()
    || !before.isFile()
    || before.uid !== 0n
    || (before.mode & 0o077n) !== 0n
    || before.size < 24n
    || before.size > 4_097n
  ) throw new Error("The operator-token is not a private root-owned regular file");
  const descriptor = openSync(tokenPath, constants.O_RDONLY | NO_FOLLOW);
  let bytes: Buffer | undefined;
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (
      before.dev !== opened.dev
      || before.ino !== opened.ino
      || before.size !== opened.size
      || before.mtimeNs !== opened.mtimeNs
      || before.ctimeNs !== opened.ctimeNs
    ) throw new Error("The operator-token changed before it was read");
    bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (
      opened.dev !== after.dev
      || opened.ino !== after.ino
      || opened.size !== after.size
      || opened.mtimeNs !== after.mtimeNs
      || opened.ctimeNs !== after.ctimeNs
    ) throw new Error("The operator-token changed while it was read");
    return await operation(validateTokenBuffer(bytes));
  } finally {
    bytes?.fill(0);
    closeSync(descriptor);
  }
}

async function boundedJson(response: Response, label: string): Promise<JsonObject> {
  const advertised = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(advertised) && advertised > MAXIMUM_RESPONSE_BYTES) {
    throw new Error(`${label} exceeded the response-size boundary`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  try {
    if (bytes.length > MAXIMUM_RESPONSE_BYTES) {
      throw new Error(`${label} exceeded the response-size boundary`);
    }
    return object(JSON.parse(bytes.toString("utf8")) as unknown, label);
  } catch (error) {
    if (error instanceof Error && (
      error.message.endsWith("was not a JSON object")
      || error.message.endsWith("exceeded the response-size boundary")
    )) throw error;
    throw new Error(`${label} was not valid JSON`);
  } finally {
    bytes.fill(0);
  }
}

interface ProofClient {
  readonly request: (
    path: string,
    options?: Readonly<{
      method?: "GET" | "POST";
      body?: JsonObject;
      idempotencyKey?: string;
      expectedStatus?: number;
      timeoutMs?: number;
    }>,
  ) => Promise<JsonObject>;
}

function proofClient(token: string): ProofClient {
  return {
    async request(path, options = {}) {
      if (!path.startsWith("/api/v2/") || path.includes("\\") || path.includes("\u0000")) {
        throw new Error("The proof attempted to leave the fixed V2 API path");
      }
      const response = await fetch(new URL(path, AUTONOMOUS_ASSESSMENT_PROOF_ORIGIN), {
        method: options.method ?? "GET",
        redirect: "error",
        cache: "no-store",
        signal: AbortSignal.timeout(options.timeoutMs ?? REQUEST_TIMEOUT_MS),
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
        throw new Error(formatAutonomousAssessmentProofApiError(path, response.status, payload));
      }
      return payload;
    },
  };
}

export interface AutonomousAssessmentReadinessReceipt {
  readonly actionClassIds: readonly string[];
  readonly activeVaultConnectionId: string;
  readonly activeVaultName: "Ti-Scale Attack Knowledge Vault";
  readonly baselinePlannerActionCount: 7;
  readonly maximumPlannerActionCount: 8;
  readonly baselineReviewedExecutionBindingCount: 8;
  readonly maximumReviewedExecutionBindingCount: 9;
}

export function assertAutonomousAssessmentReadiness(
  readinessValue: unknown,
  vaultValue: unknown,
): AutonomousAssessmentReadinessReceipt {
  const readiness = object(readinessValue, "runtime readiness");
  const database = object(readiness.database, "runtime readiness database");
  const stream = object(readiness.eventStream, "runtime readiness event stream");
  const execution = object(readiness.execution, "runtime readiness execution");
  const dependencies = object(readiness.dependencies, "runtime readiness dependencies");
  const runtime = object(dependencies.autonomousRuntime, "Autonomous runtime readiness");
  const components = object(runtime.components, "Autonomous runtime components");
  const secondBrain = object(
    dependencies.secondBrain,
    "Second Brain runtime readiness",
  );
  const vaultProjection = object(
    secondBrain.vaultProjection,
    "Second Brain Vault projection readiness",
  );
  const readyActionClassIds = array(
    runtime.readyActionClassIds,
    "Autonomous ready action classes",
  ).map((value) => text(value, "Autonomous ready action class"));
  if (
    readiness.schemaVersion !== "2.4"
    || readiness.status !== "healthy"
    || database.healthy !== true
    || stream.status !== "healthy"
    || execution.autonomous !== "ready"
    || execution.actionBoundaryActive !== true
    || execution.delegationEnforced !== true
    || execution.noHandsCommanderEnforced !== true
    || runtime.status !== "ready"
    || components.localProcessExecution !== true
    || components.mcpExecution !== false
    || components.enforcingProvider !== true
    || components.resultAwareSpecialistExecution !== true
    || components.durableActionBoundary !== true
    || components.exactRuntimeManifest !== true
    || secondBrain.status !== "healthy"
    || secondBrain.canonicalStoreAvailable !== true
    || secondBrain.lexicalIndexAvailable !== true
    || secondBrain.lexicalIndexSynchronized !== true
    || vaultProjection.status !== "healthy"
    || integer(
      vaultProjection.connectedConnections,
      "Second Brain connected Vault connections",
    ) < 1
    || integer(
      vaultProjection.healthVerifiedConnections,
      "Second Brain verified Vault connections",
    ) < 1
    || AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS.some((id) => !readyActionClassIds.includes(id))
  ) throw new Error("The complete reviewed local Autonomous assessment path is not ready");

  const vault = object(vaultValue, "Vault snapshot");
  const connections = array(vault.connections, "Vault connections")
    .map((value) => object(value, "Vault connection"));
  const matches = connections.filter((connection) =>
    connection.displayName === "Ti-Scale Attack Knowledge Vault"
    && connection.vaultPath === "Attack-Knowledge-Vault");
  if (matches.length !== 1) {
    throw new Error("Exactly one Attack Knowledge Vault connection was not found");
  }
  const active = matches[0]!;
  const checks = object(active.healthChecks, "Attack Knowledge Vault health checks");
  if (
    active.status !== "connected"
    || active.pathAvailable === false
    || checks.read !== true
    || checks.write !== true
    || checks.rename !== true
    || checks.delete !== true
    || integer(active.trackedNoteCount ?? 0, "Attack Knowledge Vault tracked notes") < 1
  ) throw new Error("The Attack Knowledge Vault is not connected and round-trip healthy");
  return {
    actionClassIds: [...AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS],
    activeVaultConnectionId: text(active.id, "Attack Knowledge Vault connection ID"),
    activeVaultName: "Ti-Scale Attack Knowledge Vault",
    baselinePlannerActionCount: 7,
    maximumPlannerActionCount: 8,
    baselineReviewedExecutionBindingCount: 8,
    maximumReviewedExecutionBindingCount: 9,
  };
}

interface AuditAction {
  readonly id: string;
  readonly step_id: string;
  readonly assignment_id: string | null;
  readonly parent_action_id: string | null;
  readonly action_type: string;
  readonly action_class: string;
  readonly fingerprint: string;
  readonly status: string;
  readonly result_summary: string | null;
  readonly error_category: string | null;
  readonly retry_count: number;
  readonly scoped_target: string | null;
  readonly normalized_arguments_json: string;
  readonly guided_decision_id: string | null;
  readonly plan_version: number;
  readonly ordinal: number;
  readonly step_status: string;
}

interface AuditFailureDiagnosis {
  readonly id: string;
  readonly action_id: string | null;
  readonly category: string;
  readonly code: string;
  readonly retryable: number;
  readonly state: string;
  readonly resolved_at: string | null;
  readonly automatic_recovery: JsonObject;
}

interface AuditContext {
  readonly id: string;
  readonly hook: string;
  readonly action_id: string | null;
  readonly used_count: number;
}

interface AuditAgentToolDecision {
  readonly hook: string;
  readonly decision: string;
  readonly context_pack_id: string;
  readonly applied_node_ids: readonly string[];
  readonly representation_unchanged: boolean;
  readonly scope_expanded: boolean;
  readonly tool_changed: boolean;
  readonly action_class_changed: boolean;
  readonly arguments_changed: boolean;
  readonly provider_exposure_created: boolean;
}

interface AuditCandidate {
  readonly state: string;
  readonly promoted_evidence_id: string | null;
  readonly observation_verification_state: string | null;
}

interface AuditEvidence {
  readonly evidence_type: string;
  readonly verification_state: string;
  readonly summary: string;
  readonly extracted_text: string | null;
  readonly provenance: JsonObject;
}

interface AuditCve {
  readonly cve_id: string;
  readonly applicability: string;
  readonly confidence: number;
}

interface AuditUsedMemoryNode {
  readonly context_pack_id: string;
  readonly hook: string;
  readonly node_id: string;
  readonly lifecycle_status: string;
  readonly confirmation_state: string;
  readonly active_vault_sync_status: string | null;
}

interface AuditAttackAttempt {
  readonly id: string;
  readonly status: string;
  readonly action_class: string;
  readonly action_type: string | null;
  readonly scoped_target: string | null;
  readonly outcome_summary: string | null;
  readonly started_at: string | null;
  readonly ended_at: string | null;
  readonly outcome_evidence_count: number;
  readonly outcome_evidence_id: string | null;
  readonly outcome_verification_state: string | null;
  readonly outcome_source: string | null;
  readonly outcome_provenance: JsonObject | null;
}

export interface AutonomousAssessmentAuditSnapshot {
  readonly runStatus: string;
  readonly runJourney: string;
  readonly runRetryCount: number;
  readonly runBudgetUsage: JsonObject;
  readonly contractActionPolicy: JsonObject;
  readonly actions: readonly AuditAction[];
  readonly toolCalls: readonly {
    readonly action_id: string;
    readonly provider: string;
    readonly tool_name: string;
    readonly mcp_server_id: string | null;
    readonly status: string;
    readonly error_category: string | null;
    readonly normalized_arguments_json: string;
  }[];
  readonly failureDiagnoses: readonly AuditFailureDiagnosis[];
  readonly providerTurnCount: number;
  readonly guidedDecisionCount: number;
  readonly approvalCount: number;
  readonly events: readonly { readonly event_type: string; readonly payload_json: string }[];
  readonly plans: readonly {
    readonly version: number;
    readonly strategy_summary: string;
    readonly rationale_summary: string | null;
  }[];
  readonly contexts: readonly AuditContext[];
  readonly usedMemoryNodes: readonly AuditUsedMemoryNode[];
  readonly agentToolDecisions: readonly AuditAgentToolDecision[];
  readonly activeVaultSyncedNodeIds: readonly string[];
  readonly candidates: readonly AuditCandidate[];
  readonly evidence: readonly AuditEvidence[];
  readonly rawVulnerabilityLogs: readonly { readonly technical_payload_json: string }[];
  readonly findings: readonly { readonly review_status: string }[];
  readonly cves: readonly AuditCve[];
  readonly attackAttempts: readonly AuditAttackAttempt[];
  readonly evaluations: readonly { readonly journey: string; readonly metrics: JsonObject }[];
  readonly reportArtifacts: readonly {
    readonly artifact_type: string;
    readonly content_hash: string;
    readonly storage_uri: string;
  }[];
  readonly missionMemoryPolicy: JsonObject;
}

function readonlyDatabase(): SqliteDatabase {
  return createDatabaseConnection({
    filename: AUTONOMOUS_ASSESSMENT_PROOF_DATABASE_PATH,
    readonly: true,
    fileMustExist: true,
    busyTimeoutMs: 10_000,
    verifyIntegrity: false,
  });
}

export function readAutonomousAssessmentAuditSnapshot(
  runId: string,
  missionId: string,
  activeVaultConnectionId: string,
  databaseOverride?: SqliteDatabase,
): AutonomousAssessmentAuditSnapshot {
  const database = databaseOverride ?? readonlyDatabase();
  try {
    const actions = database.prepare(`
      SELECT a.id, a.step_id, a.assignment_id, a.parent_action_id,
        a.action_type, a.action_class, a.fingerprint, a.status, a.result_summary,
        a.error_category, a.retry_count, a.scoped_target,
        a.normalized_arguments_json,
        a.guided_decision_id, p.version AS plan_version, ps.ordinal,
        ps.status AS step_status
      FROM actions a
      JOIN plan_steps ps ON ps.id = a.step_id
      JOIN plans p ON p.id = ps.plan_id
      WHERE a.run_id = ? ORDER BY p.version, ps.ordinal, a.created_at, a.id
    `).all(runId) as AuditAction[];
    const toolCalls = database.prepare(`
      SELECT tc.action_id, tc.provider, tc.tool_name, tc.mcp_server_id,
        tc.status, tc.error_category, tc.normalized_arguments_json
      FROM tool_calls tc JOIN actions a ON a.id = tc.action_id
      WHERE a.run_id = ? ORDER BY a.created_at, tc.created_at, tc.id
    `).all(runId) as AutonomousAssessmentAuditSnapshot["toolCalls"];
    const failureDiagnoses = database.prepare(`
      SELECT id, action_id, category, code, retryable, state, resolved_at,
        automatic_recovery_json
      FROM failure_diagnoses
      WHERE run_id = ? AND subject_type = 'action'
      ORDER BY created_at, id
    `).all(runId).map((row) => {
      const typed = row as Omit<AuditFailureDiagnosis, "automatic_recovery"> & {
        readonly automatic_recovery_json: string;
      };
      return {
        id: typed.id,
        action_id: typed.action_id,
        category: typed.category,
        code: typed.code,
        retryable: Number(typed.retryable),
        state: typed.state,
        resolved_at: typed.resolved_at,
        automatic_recovery: json(
          typed.automatic_recovery_json,
          "failure diagnosis automatic recovery",
        ),
      };
    });
    const count = (sql: string): number =>
      (database.prepare(sql).get(runId) as { readonly count: number }).count;
    const events = database.prepare(`
      SELECT event_type, payload_json FROM events WHERE run_id = ? ORDER BY sequence
    `).all(runId) as AutonomousAssessmentAuditSnapshot["events"];
    const plans = database.prepare(`
      SELECT version, strategy_summary, rationale_summary
      FROM plans WHERE run_id = ? ORDER BY version, id
    `).all(runId) as AutonomousAssessmentAuditSnapshot["plans"];
    const contexts = database.prepare(`
      SELECT pack.id,
        COALESCE(json_extract(audit.details_json, '$.hook'), '') AS hook,
        pack.action_id,
        SUM(CASE WHEN item.used = 1 THEN 1 ELSE 0 END) AS used_count
      FROM memory_context_packs pack
      JOIN audit_records audit
        ON audit.resource_id = pack.id
        AND audit.action = 'brain.context_hook.invoked'
        AND audit.mission_id = pack.mission_id
        AND (
          audit.run_id = pack.run_id
          OR (audit.run_id IS NULL AND pack.run_id IS NULL)
        )
      LEFT JOIN memory_context_items item ON item.context_pack_id = pack.id
      WHERE pack.mission_id = ?
        AND (
          pack.run_id = ?
          OR (
            pack.run_id IS NULL
            AND json_extract(audit.details_json, '$.hook') = 'intake'
          )
        )
        AND pack.release_data_class = 'canonical'
      GROUP BY pack.id, audit.id
      ORDER BY pack.created_at, pack.id
    `).all(missionId, runId).map((row) => ({
      ...(row as Omit<AuditContext, "used_count">),
      used_count: Number((row as { used_count: number | bigint | null }).used_count ?? 0),
    }));
    const usedMemoryNodes = database.prepare(`
      WITH eligible_packs AS (
        SELECT pack.id,
          COALESCE(json_extract(audit.details_json, '$.hook'), '') AS hook
        FROM memory_context_packs pack
        JOIN audit_records audit
          ON audit.resource_id = pack.id
          AND audit.action = 'brain.context_hook.invoked'
          AND audit.mission_id = pack.mission_id
          AND (
            audit.run_id = pack.run_id
            OR (audit.run_id IS NULL AND pack.run_id IS NULL)
          )
        WHERE pack.mission_id = ?
          AND (
            pack.run_id = ?
            OR (
              pack.run_id IS NULL
              AND json_extract(audit.details_json, '$.hook') = 'intake'
            )
          )
          AND pack.release_data_class = 'canonical'
      )
      SELECT eligible.id AS context_pack_id, eligible.hook, node.id AS node_id,
        node.lifecycle_status, node.confirmation_state,
        (
          SELECT state.status
          FROM vault_sync_state state
          WHERE state.connection_id = ? AND state.node_id = node.id
          ORDER BY CASE state.status WHEN 'synced' THEN 0 ELSE 1 END,
            state.last_synced_at DESC, state.id
          LIMIT 1
        ) AS active_vault_sync_status
      FROM eligible_packs eligible
      JOIN memory_context_items item
        ON item.context_pack_id = eligible.id AND item.used = 1
      JOIN memory_nodes node ON node.id = item.node_id
      ORDER BY eligible.id, item.rank, node.id
    `).all(
      missionId,
      runId,
      activeVaultConnectionId,
    ) as AuditUsedMemoryNode[];
    const agentToolDecisions = database.prepare(`
      SELECT
        json_extract(details_json, '$.hook') AS hook,
        json_extract(details_json, '$.decision') AS decision,
        json_extract(details_json, '$.contextPackId') AS context_pack_id,
        details_json
      FROM audit_records
      WHERE run_id = ? AND action = 'brain.agent_tool_memory.decision'
      ORDER BY occurred_at, id
    `).all(runId).map((row) => {
      const typed = row as {
        hook: string;
        decision: string;
        context_pack_id: string;
        details_json: string;
      };
      const details = json(typed.details_json, "agent/tool memory decision");
      return {
        hook: typed.hook,
        decision: typed.decision,
        context_pack_id: typed.context_pack_id,
        applied_node_ids: array(details.appliedNodeIds, "applied memory node IDs")
          .map((value) => text(value, "applied memory node ID")),
        representation_unchanged: details.representationUnchanged === true,
        scope_expanded: details.scopeExpanded === true,
        tool_changed: details.toolChanged === true,
        action_class_changed: details.actionClassChanged === true,
        arguments_changed: details.argumentsChanged === true,
        provider_exposure_created: details.providerExposureCreated === true,
      } satisfies AuditAgentToolDecision;
    });
    const activeVaultSyncedNodeIds = (database.prepare(`
      SELECT DISTINCT state.node_id
      FROM vault_sync_state state JOIN vault_connections connection
        ON connection.id = state.connection_id
      WHERE connection.id = ? AND connection.status = 'connected'
        AND state.status = 'synced' AND state.node_id IS NOT NULL
      ORDER BY state.node_id
    `).all(activeVaultConnectionId) as Array<{ readonly node_id: string }>)
      .map(({ node_id }) => node_id);
    const candidates = database.prepare(`
      SELECT candidate.state, candidate.promoted_evidence_id,
        observation.verification_state AS observation_verification_state
      FROM evidence_candidates candidate
      LEFT JOIN observations observation ON observation.id = candidate.observation_id
      WHERE candidate.run_id = ? ORDER BY candidate.created_at, candidate.id
    `).all(runId) as AuditCandidate[];
    const evidence = database.prepare(`
      SELECT evidence_type, verification_state, summary, extracted_text, provenance_json
      FROM evidence WHERE run_id = ? ORDER BY acquired_at, id
    `).all(runId).map((row) => {
      const typed = row as {
        evidence_type: string;
        verification_state: string;
        summary: string;
        extracted_text: string | null;
        provenance_json: string;
      };
      return {
        evidence_type: typed.evidence_type,
        verification_state: typed.verification_state,
        summary: typed.summary,
        extracted_text: typed.extracted_text,
        provenance: json(typed.provenance_json, "evidence provenance"),
      };
    });
    const rawVulnerabilityLogs = database.prepare(`
      SELECT technical_payload_json FROM engagement_log_records
      WHERE run_id = ? AND domain = 'autonomous_vulnerability_assessment_raw'
      ORDER BY occurred_at, id
    `).all(runId) as AutonomousAssessmentAuditSnapshot["rawVulnerabilityLogs"];
    const findings = database.prepare(`
      SELECT review_status FROM findings WHERE run_id = ? ORDER BY created_at, id
    `).all(runId) as AutonomousAssessmentAuditSnapshot["findings"];
    const cves = database.prepare(`
      SELECT cve_id, applicability, confidence
      FROM cve_applicability_records WHERE run_id = ? ORDER BY cve_id, id
    `).all(runId) as AuditCve[];
    const attackAttempts = database.prepare(`
      SELECT attempt.id, attempt.status, attempt.action_class,
        binding.action_type, binding.scoped_target, attempt.outcome_summary,
        attempt.started_at, attempt.ended_at,
        (
          SELECT COUNT(*)
          FROM attack_attempt_evidence linked
          WHERE linked.attack_attempt_id = attempt.id
            AND linked.relationship = 'outcome'
        ) AS outcome_evidence_count,
        (
          SELECT linked.evidence_id
          FROM attack_attempt_evidence linked
          WHERE linked.attack_attempt_id = attempt.id
            AND linked.relationship = 'outcome'
          ORDER BY linked.created_at, linked.evidence_id
          LIMIT 1
        ) AS outcome_evidence_id,
        (
          SELECT evidence.verification_state
          FROM attack_attempt_evidence linked
          JOIN evidence ON evidence.id = linked.evidence_id
          WHERE linked.attack_attempt_id = attempt.id
            AND linked.relationship = 'outcome'
          ORDER BY linked.created_at, linked.evidence_id
          LIMIT 1
        ) AS outcome_verification_state,
        (
          SELECT evidence.source
          FROM attack_attempt_evidence linked
          JOIN evidence ON evidence.id = linked.evidence_id
          WHERE linked.attack_attempt_id = attempt.id
            AND linked.relationship = 'outcome'
          ORDER BY linked.created_at, linked.evidence_id
          LIMIT 1
        ) AS outcome_source,
        (
          SELECT evidence.provenance_json
          FROM attack_attempt_evidence linked
          JOIN evidence ON evidence.id = linked.evidence_id
          WHERE linked.attack_attempt_id = attempt.id
            AND linked.relationship = 'outcome'
          ORDER BY linked.created_at, linked.evidence_id
          LIMIT 1
        ) AS outcome_provenance_json
      FROM attack_attempts attempt
      LEFT JOIN attack_attempt_action_bindings binding
        ON binding.attack_attempt_id = attempt.id
      WHERE attempt.run_id = ?
      ORDER BY attempt.created_at, attempt.id
    `).all(runId).map((row) => {
      const typed = row as Omit<AuditAttackAttempt, "outcome_provenance">
        & { readonly outcome_provenance_json: string | null };
      return {
        ...typed,
        outcome_evidence_count: Number(typed.outcome_evidence_count),
        outcome_provenance: typed.outcome_provenance_json
          ? json(typed.outcome_provenance_json, "attack-attempt outcome provenance")
          : null,
      };
    });
    const evaluations = database.prepare(`
      SELECT journey, metrics_json FROM run_evaluations WHERE run_id = ?
    `).all(runId).map((row) => {
      const typed = row as { journey: string; metrics_json: string };
      return { journey: typed.journey, metrics: json(typed.metrics_json, "evaluation metrics") };
    });
    const reportArtifacts = database.prepare(`
      SELECT artifact_type, content_hash, storage_uri FROM artifacts
      WHERE run_id = ? AND artifact_type LIKE 'mission_report_%'
      ORDER BY artifact_type, id
    `).all(runId) as AutonomousAssessmentAuditSnapshot["reportArtifacts"];
    const mission = database.prepare(`
      SELECT mission.journey, mission.memory_policy_json, run.status AS run_status,
        run.journey AS run_journey, run.retry_count,
        run.budget_usage_json, contract.action_policy_json
      FROM missions mission
      JOIN runs run ON run.id = ? AND run.mission_id = mission.id
      JOIN mission_contracts contract
        ON contract.id = run.contract_id AND contract.mission_id = mission.id
      WHERE mission.id = ?
    `).get(runId, missionId) as {
      readonly journey: string;
      readonly memory_policy_json: string;
      readonly run_status: string;
      readonly run_journey: string;
      readonly retry_count: number;
      readonly budget_usage_json: string;
      readonly action_policy_json: string;
    } | undefined;
    if (mission?.journey !== "autonomous") {
      throw new Error("The proof mission is not canonically Autonomous");
    }
    return {
      runStatus: mission.run_status,
      runJourney: mission.run_journey,
      runRetryCount: Number(mission.retry_count),
      runBudgetUsage: json(mission.budget_usage_json, "Autonomous run budget usage"),
      contractActionPolicy: json(
        mission.action_policy_json,
        "Autonomous contract action policy",
      ),
      actions,
      toolCalls,
      failureDiagnoses,
      providerTurnCount: count("SELECT COUNT(*) AS count FROM provider_turns WHERE run_id = ?"),
      guidedDecisionCount: count("SELECT COUNT(*) AS count FROM guided_decisions WHERE run_id = ?"),
      approvalCount: count("SELECT COUNT(*) AS count FROM approvals WHERE run_id = ?"),
      events,
      plans,
      contexts,
      usedMemoryNodes,
      agentToolDecisions,
      activeVaultSyncedNodeIds,
      candidates,
      evidence,
      rawVulnerabilityLogs,
      findings,
      cves,
      attackAttempts,
      evaluations,
      reportArtifacts,
      missionMemoryPolicy: json(
        mission.memory_policy_json,
        "Autonomous mission memory policy",
      ),
    };
  } finally {
    if (!databaseOverride) database.close();
  }
}

export interface AutonomousAssessmentAuditReceipt {
  readonly logicalActions: 7 | 8;
  readonly durableActionAttempts: 8 | 9;
  readonly reviewedExecutionBindings: 8 | 9;
  readonly reviewedExecutionAttempts: 9 | 10;
  readonly recoveredFailures: 1;
  readonly retrySuccessors: 1;
  readonly exploitValidationOutcome:
    | "deferred_no_confirmed_current_evidence"
    | "independently_verified";
  readonly attackAttempts: 0 | 1;
  readonly providerTurns: 0;
  readonly mcpToolCalls: 0;
  readonly guidedDecisions: 0;
  readonly approvals: 0;
  readonly contextHooks: readonly string[];
  readonly assignmentMemoryReceipts: 8 | 9;
  readonly toolMemoryReceipts: 8 | 9;
  readonly vaultBackedMemoryNodesUsed: number;
  readonly evidenceCandidates: number;
  readonly verifiedFindings: 0;
  readonly cveRecords: number;
  readonly reportArtifacts: number;
  readonly intakePresentationPreferences: 3;
  readonly reportPresentationPreferences: 2;
  readonly targetConfinement: "127.0.0.2_only";
}

const CONFINED_TARGET_FIELD_NAMES = new Set([
  "target",
  "parenttarget",
  "exacttarget",
  "scopedtarget",
  "host",
  "hostname",
  "origin",
  "url",
  "baseurl",
]);

function normalizedFieldName(value: string): string {
  return value.toLocaleLowerCase("en-US").replace(/[^a-z0-9]/gu, "");
}

function targetHost(value: string): string | undefined {
  if (/^https?:\/\//iu.test(value)) {
    try {
      return new URL(value).hostname;
    } catch {
      throw new Error("A target-bearing Autonomous argument was not a valid URL");
    }
  }
  return value;
}

function assertConfinedArguments(value: unknown, path: readonly string[]): number {
  if (typeof value === "string") {
    if (
      /(?:^|[^0-9])127\.0\.0\.1(?:[^0-9]|$)/u.test(value)
      || /(?:^|[^a-z0-9])localhost(?:[^a-z0-9]|$)/iu.test(value)
      || value.includes("::1")
    ) {
      throw new Error(
        `Autonomous proof arguments could address the legacy loopback host at ${path.join(".")}`,
      );
    }
    const field = path.at(-1);
    if (field && CONFINED_TARGET_FIELD_NAMES.has(normalizedFieldName(field))) {
      if (targetHost(value) !== AUTONOMOUS_ASSESSMENT_PROOF_TARGET) {
        throw new Error(
          `Autonomous proof target argument escaped ${AUTONOMOUS_ASSESSMENT_PROOF_TARGET}`,
        );
      }
      return 1;
    }
    return 0;
  }
  if (Array.isArray(value)) {
    return value.reduce(
      (count, item, index) => count + assertConfinedArguments(item, [...path, String(index)]),
      0,
    );
  }
  if (!value || typeof value !== "object") return 0;
  return Object.entries(value as JsonObject).reduce(
    (count, [key, item]) => count + assertConfinedArguments(item, [...path, key]),
    0,
  );
}

export function assertAutonomousAssessmentTargetConfinement(
  snapshot: Pick<AutonomousAssessmentAuditSnapshot, "actions" | "toolCalls">,
): void {
  if (snapshot.actions.length < 1 || snapshot.toolCalls.length < 1) {
    throw new Error("Autonomous proof target confinement has no durable execution records");
  }
  for (const [index, action] of snapshot.actions.entries()) {
    if (action.scoped_target !== AUTONOMOUS_ASSESSMENT_PROOF_TARGET) {
      throw new Error(`Autonomous action ${index + 1} escaped the disposable target`);
    }
    const argumentsValue = json(
      action.normalized_arguments_json,
      `Autonomous action ${index + 1} arguments`,
    );
    if (assertConfinedArguments(argumentsValue, ["action", String(index), "arguments"]) < 1) {
      throw new Error(`Autonomous action ${index + 1} has no exact target binding`);
    }
  }
  for (const [index, call] of snapshot.toolCalls.entries()) {
    const argumentsValue = json(
      call.normalized_arguments_json,
      `Autonomous tool call ${index + 1} arguments`,
    );
    if (assertConfinedArguments(argumentsValue, ["toolCall", String(index), "arguments"]) < 1) {
      throw new Error(`Autonomous tool call ${index + 1} has no exact target binding`);
    }
  }
}

export function assertAutonomousAssessmentAudit(
  snapshot: AutonomousAssessmentAuditSnapshot,
): AutonomousAssessmentAuditReceipt {
  assertAutonomousAssessmentTargetConfinement(snapshot);
  exactSet(
    array(
      snapshot.contractActionPolicy.allowedActionClasses,
      "persisted allowed action classes",
    ),
    AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS,
    "persisted allowed action classes",
  );
  const prohibitedActionClasses = array(
    snapshot.contractActionPolicy.prohibitedActionClasses,
    "persisted prohibited action classes",
  ).map((value) => text(value, "persisted prohibited action class"));
  const logicalActionGroups: AuditAction[][] = [];
  const actionGroupByStep = new Map<string, AuditAction[]>();
  for (const action of snapshot.actions) {
    const key = `${action.plan_version}\u0000${action.step_id}`;
    let group = actionGroupByStep.get(key);
    if (!group) {
      group = [];
      actionGroupByStep.set(key, group);
      logicalActionGroups.push(group);
    }
    group.push(action);
  }
  if (
    snapshot.runStatus !== "completed"
    || snapshot.runJourney !== "autonomous"
    || prohibitedActionClasses.includes(AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS)
    || logicalActionGroups.length < AUTONOMOUS_ASSESSMENT_BASE_ACTION_COUNT
    || logicalActionGroups.length > AUTONOMOUS_ASSESSMENT_ACTION_TYPES.length
    || snapshot.actions.length !== logicalActionGroups.length + 1
  ) {
    throw new Error(
      "The terminal run was not a completed Autonomous Assessment contract",
    );
  }
  const retryGroups = logicalActionGroups.filter((group) => group.length > 1);
  if (
    retryGroups.length !== 1
    || retryGroups[0]!.length !== 2
    || logicalActionGroups.some((group) => group.length < 1 || group.length > 2)
  ) {
    throw new Error("The Autonomous assessment did not contain exactly one bounded retry lineage");
  }
  let failedPredecessor: AuditAction | undefined;
  let retrySuccessor: AuditAction | undefined;
  logicalActionGroups.forEach((group, index) => {
    const expectedType = AUTONOMOUS_ASSESSMENT_ACTION_TYPES[index]!;
    const expectedClass = AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS[index]!;
    for (const action of group) {
      if (
        action.plan_version
          !== (index < AUTONOMOUS_ASSESSMENT_BASE_ACTION_COUNT ? 1 : 2)
        || action.ordinal
          !== (index < AUTONOMOUS_ASSESSMENT_BASE_ACTION_COUNT ? index : 0)
        || action.action_type !== expectedType
        || action.action_class !== expectedClass
        || action.step_status !== "completed"
        || action.scoped_target !== AUTONOMOUS_ASSESSMENT_PROOF_TARGET
        || action.guided_decision_id !== null
      ) throw new Error(`Autonomous logical action ${index + 1} drifted from its reviewed binding`);
    }
    if (group.length === 1) {
      const action = group[0]!;
      if (
        action.status !== "succeeded"
        || action.parent_action_id !== null
        || action.error_category !== null
      ) throw new Error(`Autonomous logical action ${index + 1} did not complete in one clean attempt`);
      return;
    }
    if (
      index !== 2
      || expectedType !== AUTONOMOUS_HTTP_METADATA_ACTION_TYPE
      || expectedClass !== AUTONOMOUS_HTTP_METADATA_ACTION_CLASS
    ) {
      throw new Error("The bounded proof retry did not remain confined to HTTP metadata");
    }
    const [predecessor, successor] = group;
    if (
      !predecessor
      || !successor
      || !["failed", "timed_out"].includes(predecessor.status)
      || predecessor.parent_action_id !== null
      || !["transient_network", "timeout"].includes(predecessor.error_category ?? "")
      || successor.status !== "succeeded"
      || successor.parent_action_id !== predecessor.id
      || successor.error_category !== null
      || successor.assignment_id !== predecessor.assignment_id
      || successor.fingerprint !== predecessor.fingerprint
      || successor.normalized_arguments_json !== predecessor.normalized_arguments_json
    ) {
      throw new Error("The HTTP metadata recovery attempts do not form one exact failed-parent/succeeded-child lineage");
    }
    failedPredecessor = predecessor;
    retrySuccessor = successor;
  });
  if (!failedPredecessor || !retrySuccessor) {
    throw new Error("The bounded recovery lineage is missing");
  }
  const toolCallsByAction = new Map<string, typeof snapshot.toolCalls[number]>();
  for (const call of snapshot.toolCalls) {
    if (toolCallsByAction.has(call.action_id)) {
      throw new Error("A durable action has more than one composite tool-call receipt");
    }
    toolCallsByAction.set(call.action_id, call);
  }
  if (
    snapshot.providerTurnCount !== 0
    || snapshot.guidedDecisionCount !== 0
    || snapshot.approvalCount !== 0
    || snapshot.toolCalls.length !== snapshot.actions.length
    || snapshot.toolCalls.some((call) =>
      call.mcp_server_id !== null
      || !["succeeded", "failed", "timed_out"].includes(call.status)
      || ![
        "reviewed-local-process",
        "reviewed-local-intelligence",
        "exact-target-sandbox",
      ].includes(call.provider))
    || snapshot.events.some((event) =>
      /^(?:guided|mcp|provider)\./u.test(event.event_type)
      || event.payload_json.includes("waiting_guided_decision"))
  ) throw new Error("The Autonomous assessment crossed a Guided, provider, MCP, or approval boundary");
  snapshot.actions.forEach((action, index) => {
    const call = toolCallsByAction.get(action.id);
    const expectedProvider = action.action_type === AUTONOMOUS_CVE_APPLICABILITY_ACTION_TYPE
      ? "reviewed-local-intelligence"
      : action.action_type === AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE
        ? "exact-target-sandbox"
        : "reviewed-local-process";
    const expectedStatus = action.status === "timed_out" ? "timed_out" : action.status;
    if (
      !call
      || call.tool_name !== action.action_type
      || call.provider !== expectedProvider
      || call.status !== expectedStatus
      || call.error_category !== action.error_category
    ) {
      throw new Error(`Reviewed execution receipt ${index + 1} drifted from its exact tool binding`);
    }
  });
  const diagnosis = snapshot.failureDiagnoses.length === 1
    ? snapshot.failureDiagnoses[0]
    : undefined;
  if (
    !diagnosis
    || diagnosis.action_id !== failedPredecessor.id
    || diagnosis.category !== "target_unreachable"
    || diagnosis.code !== "autonomous_http_metadata_transient_network"
    || diagnosis.retryable !== 1
    || diagnosis.automatic_recovery.directive !== "retry"
    || diagnosis.automatic_recovery.retryPersisted !== true
  ) {
    throw new Error("The recovered HTTP failure has no exact retryable structured diagnosis");
  }
  const retryEvents = snapshot.events.filter(({ event_type, payload_json }) => {
    if (event_type !== "action.completed") return false;
    const payload = json(payload_json, "action completion event");
    return payload.directive === "retry";
  });
  const recoveryTransitions = snapshot.events.filter(({ event_type, payload_json }) => {
    if (event_type !== "run.state_changed") return false;
    return json(payload_json, "run recovery transition").to === "recovering";
  });
  if (retryEvents.length !== 1 || recoveryTransitions.length !== 1) {
    throw new Error("The failed action did not persist exactly one retry directive and recovering transition");
  }
  const retryPayload = json(retryEvents[0]!.payload_json, "bounded retry event");
  if (
    retryPayload.actionId !== failedPredecessor.id
    || retryPayload.retryAssignmentId !== failedPredecessor.assignment_id
  ) {
    throw new Error("The bounded retry event is not linked to its exact failed action and assignment");
  }

  const fullTcpEvidence = snapshot.evidence.filter(({ evidence_type, provenance }) =>
    provenance.compositeToolId === AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE
    && (
      evidence_type === AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE
      || evidence_type === AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE
    ));
  if (
    fullTcpEvidence.length !== 2
    || !fullTcpEvidence.some(({ evidence_type }) =>
      evidence_type === AUTONOMOUS_FULL_TCP_SCAN_EVIDENCE_TYPE)
    || !fullTcpEvidence.some(({ evidence_type }) =>
      evidence_type === AUTONOMOUS_FULL_TCP_VERSION_EVIDENCE_TYPE)
    || fullTcpEvidence.some((item) =>
      item.verification_state !== "verified"
      || item.provenance.compositeToolId !== AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE
      || item.provenance.rawProcessOutputPromoted !== false
      || JSON.stringify(item.provenance.phaseToolIds) !== JSON.stringify([
        AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
        AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
      ]))
  ) throw new Error("The Full-TCP composite did not prove both reviewed physical phase bindings");

  const hookCounts = new Map<string, number>();
  for (const context of snapshot.contexts) {
    hookCounts.set(context.hook, (hookCounts.get(context.hook) ?? 0) + 1);
  }
  const hooks = new Set(hookCounts.keys());
  for (const required of AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS) {
    if (!hooks.has(required)) throw new Error(`Required Brain lifecycle Context Pack is missing: ${required}`);
  }
  for (const exactOnce of [
    "intake",
    "planning",
    "evaluation",
    "lesson_proposal",
    "closeout",
  ]) {
    if (hookCounts.get(exactOnce) !== 1) {
      throw new Error(`Brain lifecycle hook did not occur exactly once: ${exactOnce}`);
    }
  }
  if ((hookCounts.get("phase_transition") ?? 0) !== snapshot.actions.length) {
    throw new Error("Every completed action did not refresh phase-transition Brain context");
  }
  if ((hookCounts.get("finding_validation") ?? 0) < 1) {
    throw new Error("The concrete run did not consult Brain context for finding validation");
  }
  const failureContexts = snapshot.contexts.filter(({ hook }) => hook === "failure");
  if (
    failureContexts.length !== 1
    || failureContexts[0]!.action_id !== failedPredecessor.id
  ) {
    throw new Error("The bounded recovery did not consult exactly one failure Context Pack");
  }
  const decisionsFor = (hook: "assignment_acceptance" | "tool_selection") =>
    snapshot.agentToolDecisions.filter((decision) => decision.hook === hook);
  const assignments = decisionsFor("assignment_acceptance");
  const tools = decisionsFor("tool_selection");
  if (
    assignments.length !== snapshot.actions.length
    || tools.length !== snapshot.actions.length
    || hookCounts.get("assignment_acceptance") !== snapshot.actions.length
    || (hookCounts.get("tool_selection") ?? 0) < snapshot.actions.length
  ) {
    throw new Error("Every represented action did not consult agent and tool memory exactly once");
  }
  const synced = new Set(snapshot.activeVaultSyncedNodeIds);
  if (snapshot.usedMemoryNodes.length < 1 || snapshot.usedMemoryNodes.some((node) =>
    !["confirmed", "verified"].includes(node.lifecycle_status)
    || (
      node.lifecycle_status === "confirmed"
      && node.confirmation_state !== "confirmed"
    )
    || (
      node.lifecycle_status === "verified"
      && !["confirmed", "not_required"].includes(node.confirmation_state)
    )
    || node.active_vault_sync_status !== "synced"
    || !synced.has(node.node_id)
  )) {
    throw new Error(
      "Every memory item actually used by the run was not confirmed or verified and synchronized to the active connected Vault",
    );
  }
  const usedNodeIds = new Set(snapshot.usedMemoryNodes.map(({ node_id }) => node_id));
  for (const decision of [...assignments, ...tools]) {
    if (
      decision.decision !== "attest_compatible"
      || decision.applied_node_ids.length < 1
      || !decision.representation_unchanged
      || decision.scope_expanded
      || decision.tool_changed
      || decision.action_class_changed
      || decision.arguments_changed
      || decision.provider_exposure_created
      || decision.applied_node_ids.some((nodeId) =>
        !synced.has(nodeId) || !usedNodeIds.has(nodeId))
    ) throw new Error("Agent/tool memory was not an unchanged active-Vault-backed compatibility attestation");
    const pack = snapshot.contexts.find(({ id }) => id === decision.context_pack_id);
    if (!pack || pack.used_count < 1) {
      throw new Error("An active Vault-backed memory decision was not marked used in its Context Pack");
    }
  }

  const intakeContext = object(
    snapshot.missionMemoryPolicy.intakeContext,
    "Autonomous intake Context Pack binding",
  );
  const intakeDefaults = object(
    intakeContext.safeOptionalDefaults,
    "Autonomous intake preference defaults",
  );
  if (
    intakeContext.memoryInfluencedDefaults !== true
    || intakeDefaults.autonomyPresentation !== "high_autonomy"
    || intakeDefaults.explanationTemplate !== "technical_readable"
    || intakeDefaults.reportTemplate !== "evidence_first"
    || intakeDefaults.safetyBoundary !== "presentation_only_contract_unchanged"
  ) {
    throw new Error(
      "The Autonomous intake did not apply the exact confirmed presentation-only preference set",
    );
  }

  const reportingEvents = snapshot.events
    .filter(({ event_type }) => event_type === "brain.terminal_report_preferences_resolved");
  if (reportingEvents.length !== 1) {
    throw new Error("The terminal report did not persist exactly one Brain preference decision");
  }
  const reportingPayload = json(
    reportingEvents[0]!.payload_json,
    "terminal report preference decision",
  );
  const reportingPresentation = object(
    reportingPayload.presentation,
    "terminal report preference presentation",
  );
  const reportingNodeIds = array(
    reportingPresentation.appliedPreferenceNodeIds,
    "terminal report preference node IDs",
  ).map((value) => text(value, "terminal report preference node ID"));
  exactSet(
    array(
      reportingPresentation.appliedPreferenceKeys,
      "terminal report preference keys",
    ),
    [
      "communication.technical_readability",
      "communication.evidence_first",
    ],
    "terminal report preference keys",
  );
  const reportingContextPackId = text(
    reportingPayload.contextPackId,
    "terminal report preference Context Pack ID",
  );
  const reportingContext = snapshot.contexts.find(({ id }) => id === reportingContextPackId);
  if (
    reportingPresentation.narrativeStyle !== "technical_readable"
    || reportingPresentation.evidencePresentation !== "evidence_first"
    || reportingNodeIds.length !== 2
    || reportingNodeIds.some((nodeId) => !synced.has(nodeId))
    || !reportingContext
    || reportingContext.hook !== "reporting"
    || reportingContext.used_count < 2
    || reportingPayload.safetyBoundary
      !== "presentation_only_no_evidence_finding_scope_policy_or_deliverable_change"
  ) {
    throw new Error(
      "The terminal report did not use two active-Vault-backed confirmed preferences within its presentation-only boundary",
    );
  }

  if (snapshot.rawVulnerabilityLogs.length < 1) {
    const vulnerabilityAction = snapshot.actions.find(({ action_type }) =>
      action_type === AUTONOMOUS_VULNERABILITY_ASSESSMENT_ACTION_TYPE);
    if (vulnerabilityAction?.result_summary?.includes("not applicable")) {
      throw new Error(
        "The disposable target was not recognized as an HTTP origin, so the bounded Nuclei execution never ran",
      );
    }
    throw new Error("The bounded Nuclei execution did not retain its raw technical log separately");
  }
  if (snapshot.candidates.length < 1 || snapshot.candidates.some((candidate) =>
    candidate.state !== "candidate"
    || candidate.promoted_evidence_id !== null
    || candidate.observation_verification_state !== "unverified")) {
    throw new Error("Nuclei signals were not retained exclusively as unverified evidence candidates");
  }
  if (snapshot.findings.length !== 0) {
    throw new Error("The bounded assessment automatically created a finding from scanner signals");
  }
  const vulnerabilityExecution = snapshot.evidence.filter((item) =>
    item.evidence_type === "configuration_snapshot");
  if (
    vulnerabilityExecution.length !== 1
    || vulnerabilityExecution[0]!.verification_state !== "verified"
    || vulnerabilityExecution[0]!.provenance.rawProcessOutputPromoted !== false
    || vulnerabilityExecution[0]!.provenance.findingsCreated !== false
    || !vulnerabilityExecution[0]!.summary.includes("matches remain unverified")
  ) throw new Error("The vulnerability execution receipt overclaimed raw scanner output");
  if (snapshot.evidence.some((item) =>
    item.summary.includes("Nmap scan report for")
    || item.summary.includes("packets transmitted")
    || item.extracted_text?.includes("Authorization: Bearer"))) {
    throw new Error("Raw process or credential-like output leaked into canonical evidence");
  }

  const cveExecutionEvidence = snapshot.evidence.filter((item) =>
    item.evidence_type === "cve_applicability");
  if (
    cveExecutionEvidence.length !== 1
    || cveExecutionEvidence.some((item) =>
      item.verification_state !== "verified"
      || item.provenance.bannerOnlyConfirmationPermitted !== false
      || item.provenance.rawOutputPromoted !== false
      || item.provenance.targetInteraction !== false
      || !Array.isArray(item.provenance.sourceEvidenceIds)
      || item.provenance.sourceEvidenceIds.length < 1)
  ) {
    throw new Error("CVE applicability did not preserve its no-banner-confirmation rule");
  }

  if (snapshot.evaluations.length !== 1 || snapshot.evaluations[0]!.journey !== "autonomous") {
    throw new Error("The completed run did not produce exactly one Autonomous evaluation");
  }
  const metrics = snapshot.evaluations[0]!.metrics;
  if (
    metrics.providerTurnCount !== 0
    || metrics.guidedDecisionCount !== 0
    || metrics.autonomousUserWaitCount !== 0
    || metrics.retryCount !== 1
    || metrics.recoveryCount !== 1
    || metrics.recoverySuccessRate !== 1
    || metrics.failedActions !== 1
    || metrics.actionCount !== snapshot.actions.length
    || metrics.succeededActions !== logicalActionGroups.length
    || snapshot.runRetryCount !== 1
    || snapshot.runBudgetUsage.retries !== 1
  ) {
    throw new Error(
      "The Autonomous evaluation did not report exactly one successful bounded recovery without provider or operator-decision dependence",
    );
  }
  if (
    snapshot.reportArtifacts.length !== 2
    || snapshot.reportArtifacts.some(({ artifact_type, content_hash, storage_uri }) => {
      const format = artifact_type === "mission_report_json"
        ? "json"
        : artifact_type === "mission_report_markdown"
          ? "markdown"
          : "";
      return !format
        || !/^[a-f0-9]{64}$/u.test(content_hash)
        || storage_uri !== `ti-scale-report://sha256/${content_hash}/${format}`;
    })
  ) throw new Error("The completed run did not produce two integrity-hashed report artifacts");
  exactSet(
    snapshot.reportArtifacts.map(({ artifact_type }) => artifact_type),
    AUTONOMOUS_TERMINAL_REPORT_ARTIFACT_TYPES,
    "terminal report artifact types",
  );

  const exploitActionPresent = logicalActionGroups.length
    === AUTONOMOUS_ASSESSMENT_ACTION_TYPES.length;
  const exploitExpansionEvents = snapshot.events.filter(({ event_type }) =>
    event_type === "plan.evidence_driven_expansion_applied");
  let exploitValidationOutcome:
    AutonomousAssessmentAuditReceipt["exploitValidationOutcome"];
  if (exploitActionPresent) {
    const attempt = snapshot.attackAttempts[0];
    const provenance = attempt?.outcome_provenance;
    const expansionPayload = exploitExpansionEvents.length === 1
      ? json(
          exploitExpansionEvents[0]!.payload_json,
          "evidence-driven exploit expansion event",
        )
      : undefined;
    if (
      snapshot.attackAttempts.length !== 1
      || !attempt
      || attempt.status !== "succeeded"
      || attempt.action_class !== AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS
      || attempt.action_type !== AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE
      || attempt.scoped_target !== AUTONOMOUS_ASSESSMENT_PROOF_TARGET
      || !attempt.started_at
      || !attempt.ended_at
      || attempt.outcome_evidence_count !== 1
      || !attempt.outcome_evidence_id
      || attempt.outcome_verification_state !== "verified"
      || attempt.outcome_source !== "local:independent-http-outcome-observer"
      || !provenance
      || provenance.attackAttemptId !== attempt.id
      || provenance.exactTarget !== AUTONOMOUS_ASSESSMENT_PROOF_TARGET
      || provenance.independentVerifier !== 1
      || provenance.rawOutputPromoted !== 0
      || provenance.matched !== true
      || !expansionPayload
      || expansionPayload.attackAttemptId !== attempt.id
      || expansionPayload.contractAmended !== false
      || expansionPayload.memoryPolicyAmended !== false
      || hookCounts.get("attack_attempt") !== 1
      || !snapshot.cves.some(({ applicability, confidence }) =>
        applicability === "confirmed" && confidence >= 0.8)
    ) {
      throw new Error(
        "The evidence-matched exploit branch was not exactly one independently verified attempt",
      );
    }
    exploitValidationOutcome = "independently_verified";
  } else {
    const deferredPlan = snapshot.plans.length === 1
      ? snapshot.plans[0]
      : undefined;
    if (
      snapshot.attackAttempts.length !== 0
      || exploitExpansionEvents.length !== 0
      || hookCounts.has("attack_attempt")
      || snapshot.cves.some(({ applicability }) => applicability === "confirmed")
      || snapshot.evidence.some(({ evidence_type }) =>
        evidence_type === "exploit_validation_result")
      || !deferredPlan
      || !deferredPlan.strategy_summary.includes(
        "Exploit validation remains deferred until its exact candidate gate is ready.",
      )
      || !deferredPlan.rationale_summary?.includes("Exploit validation is deferred")
    ) {
      throw new Error(
        "Exploit validation was neither independently verified nor explicitly deferred by current evidence",
      );
    }
    exploitValidationOutcome = "deferred_no_confirmed_current_evidence";
  }

  const logicalActions = logicalActionGroups.length as 7 | 8;
  const durableActionAttempts = snapshot.actions.length as 8 | 9;
  const reviewedExecutionBindings = (
    AUTONOMOUS_ASSESSMENT_BASE_EXECUTION_BINDING_COUNT
    + (exploitActionPresent ? 1 : 0)
  ) as 8 | 9;
  const reviewedExecutionAttempts = (
    reviewedExecutionBindings + 1
  ) as 9 | 10;
  return {
    logicalActions,
    durableActionAttempts,
    reviewedExecutionBindings,
    reviewedExecutionAttempts,
    recoveredFailures: 1,
    retrySuccessors: 1,
    exploitValidationOutcome,
    attackAttempts: snapshot.attackAttempts.length as 0 | 1,
    providerTurns: 0,
    mcpToolCalls: 0,
    guidedDecisions: 0,
    approvals: 0,
    contextHooks: [...AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS],
    assignmentMemoryReceipts: assignments.length as 8 | 9,
    toolMemoryReceipts: tools.length as 8 | 9,
    vaultBackedMemoryNodesUsed: usedNodeIds.size,
    evidenceCandidates: snapshot.candidates.length,
    verifiedFindings: 0,
    cveRecords: snapshot.cves.length,
    reportArtifacts: snapshot.reportArtifacts.length,
    intakePresentationPreferences: 3,
    reportPresentationPreferences: 2,
    targetConfinement: "127.0.0.2_only",
  };
}

function actionPolicyOverrides(): Readonly<Record<ActionClassId, "pre_authorized" | "prohibited">> {
  const allowed = new Set<string>(AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS);
  return Object.freeze(Object.fromEntries(
    ACTION_CLASS_IDS.map((id) => [id, allowed.has(id) ? "pre_authorized" : "prohibited"]),
  ) as Record<ActionClassId, "pre_authorized" | "prohibited">);
}

async function waitForCompletedRun(client: ProofClient, runId: string): Promise<JsonObject> {
  const deadline = Date.now() + RUN_TIMEOUT_MS;
  do {
    const response = await client.request(`/api/v2/runs/${encodeURIComponent(runId)}`);
    const run = object(response.run, "Autonomous assessment run");
    const status = String(run.status ?? "");
    if (status === "waiting_guided_decision") {
      throw new Error("The Autonomous assessment entered a Guided waiting state");
    }
    if (["blocked", "failed", "cancelled"].includes(status)) {
      throw new Error(
        `The Autonomous assessment ended ${status}: ${safeMessage(run.statusReason, "No reason was returned")}`,
      );
    }
    if (status === "completed") return run;
    if (Date.now() >= deadline) break;
    await Bun.sleep(POLL_INTERVAL_MS);
  } while (Date.now() < deadline);
  throw new Error(`The Autonomous assessment did not complete within ${RUN_TIMEOUT_MS} ms`);
}

export function autonomousAssessmentTerminalCloseoutPending(
  snapshot: AutonomousAssessmentAuditSnapshot,
): readonly string[] {
  const pending: string[] = [];
  if (snapshot.evaluations.length < 1) pending.push("terminal evaluation");
  const hooks = new Set(snapshot.contexts.map(({ hook }) => hook));
  for (const hook of AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS) {
    if (!hooks.has(hook)) pending.push(`${hook} Context Pack`);
  }
  if (snapshot.usedMemoryNodes.some((node) =>
    !["confirmed", "verified"].includes(node.lifecycle_status)
    || (
      node.lifecycle_status === "confirmed"
      && node.confirmation_state !== "confirmed"
    )
    || (
      node.lifecycle_status === "verified"
      && !["confirmed", "not_required"].includes(node.confirmation_state)
    )
    || node.active_vault_sync_status !== "synced")) {
    pending.push("active Vault synchronization for every used memory item");
  }
  if (!snapshot.events.some(({ event_type }) =>
    event_type === "brain.terminal_report_preferences_resolved")) {
    pending.push("terminal report preference event");
  }
  for (const artifactType of AUTONOMOUS_TERMINAL_REPORT_ARTIFACT_TYPES) {
    const artifact = snapshot.reportArtifacts.find((item) =>
      item.artifact_type === artifactType);
    if (!artifact) {
      pending.push(`${artifactType} artifact`);
      continue;
    }
    const format = artifactType === "mission_report_json" ? "json" : "markdown";
    if (
      !/^[a-f0-9]{64}$/u.test(artifact.content_hash)
      || artifact.storage_uri
        !== `ti-scale-report://sha256/${artifact.content_hash}/${format}`
    ) {
      throw new Error(
        `The auto-generated ${artifactType} artifact failed its immutable content-addressed binding`,
      );
    }
  }
  return pending;
}

interface TerminalCloseoutWaitOptions {
  readonly timeoutMs?: number;
  readonly pollIntervalMs?: number;
  readonly now?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly readSnapshot?: (
    runId: string,
    missionId: string,
    activeVaultConnectionId: string,
  ) => AutonomousAssessmentAuditSnapshot;
}

export async function waitForAutonomousAssessmentTerminalCloseout(
  runId: string,
  missionId: string,
  activeVaultConnectionId: string,
  options: TerminalCloseoutWaitOptions = {},
): Promise<AutonomousAssessmentAuditSnapshot> {
  const timeoutMs = options.timeoutMs ?? TERMINAL_CLOSEOUT_TIMEOUT_MS;
  const pollIntervalMs = options.pollIntervalMs ?? POLL_INTERVAL_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0) {
    throw new TypeError("Terminal closeout timeout must be a non-negative integer");
  }
  if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 0) {
    throw new TypeError("Terminal closeout poll interval must be a non-negative integer");
  }
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? (async (milliseconds: number) => {
    await Bun.sleep(milliseconds);
  });
  const readSnapshot = options.readSnapshot ?? readAutonomousAssessmentAuditSnapshot;
  const deadline = now() + timeoutMs;
  let lastPending: readonly string[] = [];
  do {
    const snapshot = readSnapshot(runId, missionId, activeVaultConnectionId);
    lastPending = autonomousAssessmentTerminalCloseoutPending(snapshot);
    if (lastPending.length === 0) return snapshot;
    if (now() >= deadline) break;
    await sleep(pollIntervalMs);
  } while (now() <= deadline);
  throw new Error(
    `The completed Autonomous run did not finish durable terminal closeout within ${timeoutMs} ms; still waiting for: ${lastPending.join(", ")}`,
  );
}

export async function runAutonomousAssessmentLiveProof(
  token: string,
  fixture: DisposableAutonomousAssessmentTarget,
): Promise<JsonObject> {
  if (
    fixture.host !== AUTONOMOUS_ASSESSMENT_PROOF_TARGET
    || fixture.port < 1
    || fixture.port > 65_535
    || fixture.origin !== `http://${AUTONOMOUS_ASSESSMENT_PROOF_TARGET}:${fixture.port}`
  ) throw new Error("The disposable Autonomous assessment target is not exactly confined");
  const client = proofClient(token);
  const [health, readiness, vault] = await Promise.all([
    client.request("/api/v2/health"),
    client.request("/api/v2/system/readiness"),
    client.request("/api/v2/brain/vault"),
  ]);
  if (
    health.schemaVersion !== "2.4"
    || health.status !== "healthy"
    || object(health.database, "health database").healthy !== true
    || object(health.eventStream, "health event stream").status !== "healthy"
  ) throw new Error("Ti-Scale HTTP, database, and event-stream health is not ready");
  const ready = assertAutonomousAssessmentReadiness(readiness, vault);
  const nonce = randomUUID();
  const resolved = await client.request("/api/v2/registries/intake/resolve", {
    method: "POST",
    idempotencyKey: `autonomous-assessment-resolve-${nonce}`,
    body: {
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: AUTONOMOUS_ASSESSMENT_PROOF_TARGET, type: "host" }],
      templateId: "custom",
      objective:
        "Assess the exact authorized disposable web target, establish its current service and application exposure, evaluate applicable vulnerabilities, and report only evidence-backed assessment outcomes.",
      successCriteria: [...AUTONOMOUS_ASSESSMENT_SUCCESS_CRITERIA],
      environmentClassification: "local_disposable_lab",
      destructivePolicy: "bounded_lab_only",
      boundedDestructiveTargetIds: [AUTONOMOUS_ASSESSMENT_PROOF_TARGET_ID],
      actionPolicyOverrides: actionPolicyOverrides(),
    },
  });
  const request = object(resolved.request, "resolved mission request");
  const contract = object(request.contract, "resolved Autonomous contract");
  if (contract.outcomeProfile !== "assessment") {
    throw new Error(
      "The assessment proof was incorrectly classified as a Complete Autonomous Engagement",
    );
  }
  exactSet(
    array(request.successCriteria, "resolved assessment success criteria"),
    AUTONOMOUS_ASSESSMENT_SUCCESS_CRITERIA,
    "resolved assessment success criteria",
  );
  exactSet(
    array(contract.allowedActionClasses, "resolved allowed action classes"),
    AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS,
    "resolved allowed action classes",
  );
  if (!array(contract.allowedActionClasses, "resolved allowed action classes")
    .includes(AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS)) {
    throw new Error("The Autonomous Assessment contract did not authorize its optional strict validation class");
  }
  const preflight = await client.request("/api/v2/missions/autonomous/preflight", {
    method: "POST",
    idempotencyKey: `autonomous-assessment-preflight-${nonce}`,
    body: request,
  });
  const preflightReadiness = object(preflight.readiness, "Autonomous preflight readiness");
  const preflightOutcome = object(preflight.outcome, "Autonomous preflight outcome");
  if (preflightOutcome.id !== "assessment") {
    throw new Error(
      "The server changed the reviewed Autonomous Assessment completion promise",
    );
  }
  const failedChecks = array(preflightReadiness.checks, "Autonomous preflight checks")
    .map((value) => object(value, "Autonomous preflight check"))
    .filter((check) => check.status === "fail");
  if (preflightReadiness.status !== "ready" || failedChecks.length > 0) {
    throw new Error(
      `Autonomous preflight was not ready: ${failedChecks.map((check) =>
        `${safeMessage(check.id, "unknown")}: ${safeMessage(check.impact, "no impact")}`).join(" | ")}`,
    );
  }
  const contractReview = object(preflight.contract, "Autonomous preflight contract");
  text(contractReview.hash, "Autonomous contract hash");
  const created = await client.request("/api/v2/missions", {
    method: "POST",
    expectedStatus: 201,
    idempotencyKey: `autonomous-assessment-create-${nonce}`,
    body: { ...request, contractReview },
  });
  const missionId = text(object(created.mission, "created mission").id, "mission ID");
  const runId = text(object(created.run, "created run").id, "run ID");
  const terminal = await waitForCompletedRun(client, runId);
  const terminalSnapshot = await waitForAutonomousAssessmentTerminalCloseout(
    runId,
    missionId,
    ready.activeVaultConnectionId,
  );
  const audit = assertAutonomousAssessmentAudit(terminalSnapshot);
  const fixtureRequests = fixture.requests();
  const failureReceipt = fixture.failureReceipt();
  if (fixtureRequests.length < 1) {
    throw new Error("The Autonomous assessment did not contact its disposable target");
  }
  if (
    failureReceipt.enabled !== true
    || failureReceipt.injectedFailureCount !== 1
    || failureReceipt.recoveredCurlHeadCount < 1
  ) {
    throw new Error(
      "The disposable target did not prove exactly one injected HTTP transport failure followed by a recovered retry",
    );
  }
  return {
    schemaVersion: "ti-scale.autonomous-assessment-live-proof.v4",
    status: "passed",
    origin: AUTONOMOUS_ASSESSMENT_PROOF_ORIGIN,
    target: AUTONOMOUS_ASSESSMENT_PROOF_TARGET,
    disposableTarget: {
      host: fixture.host,
      port: fixture.port,
      origin: fixture.origin,
      observedRequestCount: fixtureRequests.length,
      failureReceipt,
      redirectsEnabled: false,
      legacy3131ContactPermitted: false,
    },
    checkedAt: new Date().toISOString(),
    missionId,
    runId,
    terminalStatus: terminal.status,
    readiness: ready,
    audit,
    contract: {
      journey: "autonomous",
      actionClassIds: [...AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS],
      exploitValidationAuthorized: true,
      exploitValidationOutcome: audit.exploitValidationOutcome,
    },
    secondBrain: {
      vaultConnectionId: ready.activeVaultConnectionId,
      vaultName: ready.activeVaultName,
      requiredHooks: [...AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS],
      activeVaultBackedMemoryUsed: true,
    },
    secretHandling: {
      tokenSource: "private_root_file",
      tokenPersistedByProof: false,
      tokenIncludedInReceipt: false,
    },
  };
}

export async function withDisposableAutonomousAssessmentTarget<T>(
  operation: (fixture: DisposableAutonomousAssessmentTarget) => Promise<T>,
  start: () => Promise<DisposableAutonomousAssessmentTarget> =
    () => startDisposableAutonomousAssessmentTarget({
      recoverableHttpMetadataFailureOnce: true,
    }),
): Promise<T> {
  const fixture = await start();
  try {
    return await operation(fixture);
  } finally {
    await fixture.close();
  }
}

async function main(): Promise<void> {
  parseAutonomousAssessmentProofArguments(process.argv.slice(2));
  const receipt = await withDisposableAutonomousAssessmentTarget((fixture) =>
    withTrustedOperatorToken((token) =>
      runAutonomousAssessmentLiveProof(token, fixture)),
  );
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `Autonomous assessment live proof failed: ${safeMessage(error instanceof Error ? error.message : undefined, "unknown error")}\n`,
    );
    process.exitCode = 1;
  });
}
