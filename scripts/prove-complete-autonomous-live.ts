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
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS,
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
  AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  type ActionClassId,
} from "../server/domain";
import {
  autonomousSuccessCriterionId,
} from "../server/autonomous-runtime/LocalVerifiedEvidenceOutcomeEvaluator";
import { digestCanonicalJson } from "../server/mcp";
import {
  AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS,
  AUTONOMOUS_ASSESSMENT_ACTION_TYPES,
  AUTONOMOUS_ASSESSMENT_PROOF_DATABASE_PATH,
  AUTONOMOUS_ASSESSMENT_PROOF_ORIGIN,
  AUTONOMOUS_ASSESSMENT_PROOF_TOKEN_PATH,
  AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS,
  AUTONOMOUS_ASSESSMENT_SUCCESS_CRITERIA,
  formatAutonomousAssessmentProofApiError,
  readAutonomousAssessmentAuditSnapshot,
  type AutonomousAssessmentAuditSnapshot,
} from "./prove-autonomous-assessment-live";
import {
  DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
  DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER,
  DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
  DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
  DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
  DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
  DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
  DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
  startDisposableCompleteAutonomousTarget,
  isDisposableCompleteAutonomousImpactPath,
  type DisposableCompleteAutonomousTarget,
  type DisposableCompleteAutonomousTrace,
} from "../server/autonomous-runtime/testing/DisposableCompleteAutonomousTarget";

type JsonObject = Record<string, unknown>;

export const COMPLETE_AUTONOMOUS_LIVE_PROOF_CONFIRMATION =
  "run-one-complete-autonomous-disposable-loopback-on-3132" as const;
export const COMPLETE_AUTONOMOUS_LIVE_PROOF_SCHEMA_VERSION =
  "ti-scale.complete-autonomous-live-proof.v1" as const;
export const COMPLETE_AUTONOMOUS_CANDIDATE_TRANSPORT_UNAVAILABLE =
  "complete_autonomous_candidate_transport_unavailable" as const;
export const COMPLETE_AUTONOMOUS_TARGET_ID =
  `target_${createHash("sha256")
    .update(`host\0${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}`)
    .digest("hex")
    .slice(0, 16)}` as const;

const TOKEN_TRUST_ROOT = "/etc/ti-scale";
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const MAXIMUM_RESPONSE_BYTES = 8 * 1_024 * 1_024;
const REQUEST_TIMEOUT_MS = 20_000;
const RUN_TIMEOUT_MS = 20 * 60_000;
const TERMINAL_CLOSEOUT_TIMEOUT_MS = 2 * 60_000;
const POLL_INTERVAL_MS = 500;
const MINIMUM_CANDIDATE_SESSION_SCHEMA_VERSION = 46;
const SHA256 = /^[a-f0-9]{64}$/u;

export const COMPLETE_AUTONOMOUS_POST_EXPLOIT_ACTION_TYPES = Object.freeze([
  "autonomous_linux_session_identity_v1",
  "autonomous_linux_user_flag_hash_proof_v1",
  "autonomous_linux_privilege_escalation_v1",
  "autonomous_linux_root_flag_hash_proof_v1",
  "autonomous_linux_session_cleanup_v1",
] as const);

export const COMPLETE_AUTONOMOUS_ACTION_TYPES = Object.freeze([
  ...AUTONOMOUS_ASSESSMENT_ACTION_TYPES,
  ...COMPLETE_AUTONOMOUS_POST_EXPLOIT_ACTION_TYPES,
] as const);

export const COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS = Object.freeze([
  ...AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS,
  ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS.filter(
    (actionClassId) =>
      !AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS.includes(
        actionClassId as
          (typeof AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS)[number],
      ),
  ),
] as const satisfies readonly ActionClassId[]);

export const COMPLETE_AUTONOMOUS_SUCCESS_CRITERIA = Object.freeze([
  ...AUTONOMOUS_ASSESSMENT_SUCCESS_CRITERIA,
  ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
] as const);

export const COMPLETE_AUTONOMOUS_REQUIRED_CONTEXT_HOOKS = Object.freeze([
  ...AUTONOMOUS_ASSESSMENT_REQUIRED_CONTEXT_HOOKS,
  "attack_attempt",
] as const);

const REQUIRED_ACTION_CLASS_BY_TYPE = Object.freeze(
  new Map<string, ActionClassId>([
    ...AUTONOMOUS_ASSESSMENT_ACTION_TYPES.map((actionType, index) => [
      actionType,
      AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS[index]!,
    ] as const),
    ["autonomous_linux_session_identity_v1", "command_session_execution"],
    [
      "autonomous_linux_user_flag_hash_proof_v1",
      "data_access_impact_validation",
    ],
    [
      "autonomous_linux_privilege_escalation_v1",
      "privilege_escalation",
    ],
    [
      "autonomous_linux_root_flag_hash_proof_v1",
      "data_access_impact_validation",
    ],
    [
      "autonomous_linux_session_cleanup_v1",
      "cleanup_restoration",
    ],
  ]),
);

function plain(value: unknown, label: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} was not a JSON object`);
  }
  return value as JsonObject;
}

function list(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} was not an array`);
  return value;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${label} was missing`);
  }
  return value;
}

function integer(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} was not a non-negative integer`);
  }
  return Number(value);
}

function parseJson(value: string, label: string): JsonObject {
  try {
    return plain(JSON.parse(value) as unknown, label);
  } catch (error) {
    if (
      error instanceof Error
      && error.message.endsWith("was not a JSON object")
    ) {
      throw error;
    }
    throw new Error(`${label} was not valid JSON`);
  }
}

function safeMessage(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const normalized = value
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  return normalized ? normalized.slice(0, 700) : fallback;
}

function exactSet(
  actual: readonly unknown[],
  expected: readonly string[],
  label: string,
): void {
  const normalized = actual.map((value) => text(value, `${label} entry`));
  if (
    normalized.length !== expected.length
    || new Set(normalized).size !== normalized.length
    || expected.some((value) => !normalized.includes(value))
  ) {
    throw new Error(`${label} did not match the exact reviewed set`);
  }
}

export class CompleteAutonomousLivePrerequisiteError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly remediation: string,
  ) {
    super(message);
    this.name = "CompleteAutonomousLivePrerequisiteError";
  }
}

export function completeAutonomousLiveProofUsage(): string {
  return [
    "bun run scripts/prove-complete-autonomous-live.ts",
    "--execute",
    "--confirm",
    COMPLETE_AUTONOMOUS_LIVE_PROOF_CONFIRMATION,
  ].join(" ");
}

export function parseCompleteAutonomousLiveProofArguments(
  argv: readonly string[],
): void {
  if (
    argv.length !== 3
    || argv[0] !== "--execute"
    || argv[1] !== "--confirm"
    || argv[2] !== COMPLETE_AUTONOMOUS_LIVE_PROOF_CONFIRMATION
  ) {
    throw new Error(
      "This proof creates exactly one authorized disposable-loopback "
      + `Complete Autonomous mission. Use: ${completeAutonomousLiveProofUsage()}`,
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
  ) {
    throw new Error("The root operator-token file has an invalid bounded value");
  }
  return bounded.toString("utf8");
}

async function withTrustedOperatorToken<T>(
  operation: (token: string) => Promise<T>,
): Promise<T> {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) {
    throw new Error(
      "The production proof must run as root to read the private operator token",
    );
  }
  const tokenPath = resolve(AUTONOMOUS_ASSESSMENT_PROOF_TOKEN_PATH);
  const trustRoot = resolve(TOKEN_TRUST_ROOT);
  if (
    tokenPath !== AUTONOMOUS_ASSESSMENT_PROOF_TOKEN_PATH
    || tokenPath !== resolve(trustRoot, "operator-token")
  ) {
    throw new Error("The operator-token path escaped its fixed trust root");
  }
  const root = lstatSync(trustRoot, { bigint: true });
  if (
    root.isSymbolicLink()
    || !root.isDirectory()
    || root.uid !== 0n
    || (root.mode & 0o022n) !== 0n
  ) {
    throw new Error(
      "The operator-token trust root is not root-owned and non-writable",
    );
  }
  const before = lstatSync(tokenPath, { bigint: true });
  if (
    before.isSymbolicLink()
    || !before.isFile()
    || before.uid !== 0n
    || (before.mode & 0o077n) !== 0n
    || before.size < 24n
    || before.size > 4_097n
  ) {
    throw new Error(
      "The operator-token is not a private root-owned regular file",
    );
  }
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
    ) {
      throw new Error("The operator-token changed before it was read");
    }
    bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (
      opened.dev !== after.dev
      || opened.ino !== after.ino
      || opened.size !== after.size
      || opened.mtimeNs !== after.mtimeNs
      || opened.ctimeNs !== after.ctimeNs
    ) {
      throw new Error("The operator-token changed while it was read");
    }
    return await operation(validateTokenBuffer(bytes));
  } finally {
    bytes?.fill(0);
    closeSync(descriptor);
  }
}

async function boundedJson(
  response: Response,
  label: string,
): Promise<JsonObject> {
  const advertised = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(advertised) && advertised > MAXIMUM_RESPONSE_BYTES) {
    throw new Error(`${label} exceeded the response-size boundary`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  try {
    if (bytes.length > MAXIMUM_RESPONSE_BYTES) {
      throw new Error(`${label} exceeded the response-size boundary`);
    }
    return plain(JSON.parse(bytes.toString("utf8")) as unknown, label);
  } catch (error) {
    if (
      error instanceof Error
      && (
        error.message.endsWith("was not a JSON object")
        || error.message.endsWith("exceeded the response-size boundary")
      )
    ) {
      throw error;
    }
    throw new Error(`${label} was not valid JSON`);
  } finally {
    bytes.fill(0);
  }
}

export interface CompleteAutonomousProofClient {
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

export function createCompleteAutonomousProofClient(
  token: string,
): CompleteAutonomousProofClient {
  if (!token) throw new Error("The operator token is missing");
  const request: CompleteAutonomousProofClient["request"] =
    async (path, options = {}) => {
      if (
        !path.startsWith("/api/v2/")
        || path.includes("\\")
        || path.includes("\u0000")
      ) {
        throw new Error("The proof attempted to leave the fixed V2 API path");
      }
      const response = await fetch(
        new URL(path, AUTONOMOUS_ASSESSMENT_PROOF_ORIGIN),
        {
          method: options.method ?? "GET",
          redirect: "error",
          cache: "no-store",
          signal: AbortSignal.timeout(
            options.timeoutMs ?? REQUEST_TIMEOUT_MS,
          ),
          headers: {
            Accept: "application/json",
            Authorization: `Bearer ${token}`,
            ...(options.body
              ? { "Content-Type": "application/json" }
              : {}),
            ...(options.idempotencyKey
              ? { "Idempotency-Key": options.idempotencyKey }
              : {}),
          },
          ...(options.body ? { body: JSON.stringify(options.body) } : {}),
        },
      );
      const payload = await boundedJson(response, path);
      const expectedStatus = options.expectedStatus ?? 200;
      if (response.status !== expectedStatus) {
        throw new Error(
          formatAutonomousAssessmentProofApiError(
            path,
            response.status,
            payload,
          ),
        );
      }
      return payload;
    };
  return Object.freeze({ request });
}

export interface CompleteAutonomousPrerequisiteReceipt {
  readonly schemaVersion:
    "ti-scale.complete-autonomous-live-prerequisites.v1";
  readonly databaseSchemaVersion: number;
  readonly readyActionClassIds: readonly string[];
  readonly candidateActionClassIds: readonly string[];
  readonly activeVaultConnectionId: string;
  readonly activeVaultName: "Ti-Scale Attack Knowledge Vault";
  readonly fixtureOnly: true;
  readonly realTargetSupportClaimed: false;
}

export function assertCompleteAutonomousLivePrerequisites(input: Readonly<{
  health: unknown;
  readiness: unknown;
  vault: unknown;
  databaseSchemaVersion: number;
}>): CompleteAutonomousPrerequisiteReceipt {
  const health = plain(input.health, "health");
  const healthDatabase = plain(health.database, "health database");
  const healthStream = plain(health.eventStream, "health event stream");
  if (
    health.schemaVersion !== "2.4"
    || health.status !== "healthy"
    || healthDatabase.healthy !== true
    || healthStream.status !== "healthy"
  ) {
    throw new CompleteAutonomousLivePrerequisiteError(
      "complete_autonomous_control_plane_unhealthy",
      "Ti-Scale 3132 is not healthy enough to launch a proof mission.",
      "Restore the Ti-Scale HTTP, database, and event-stream health checks.",
    );
  }
  if (
    !Number.isSafeInteger(input.databaseSchemaVersion)
    || input.databaseSchemaVersion
      < MINIMUM_CANDIDATE_SESSION_SCHEMA_VERSION
  ) {
    throw new CompleteAutonomousLivePrerequisiteError(
      "complete_autonomous_candidate_schema_unavailable",
      "The live database does not contain the immutable candidate-session "
      + `schema (requires ${MINIMUM_CANDIDATE_SESSION_SCHEMA_VERSION} or later).`,
      "Apply the forward-only Ti-Scale migrations before enabling the "
      + "candidate transport; do not fabricate candidate rows.",
    );
  }

  const readiness = plain(input.readiness, "runtime readiness");
  const execution = plain(
    readiness.execution,
    "runtime readiness execution",
  );
  const dependencies = plain(
    readiness.dependencies,
    "runtime readiness dependencies",
  );
  const runtime = plain(
    dependencies.autonomousRuntime,
    "Autonomous runtime readiness",
  );
  const components = plain(
    runtime.components,
    "Autonomous runtime components",
  );
  const readyActionClassIds = list(
    runtime.readyActionClassIds,
    "Autonomous ready action classes",
  ).map((value) => text(value, "Autonomous ready action class"));
  if (
    readiness.status !== "healthy"
    || execution.autonomous !== "ready"
    || execution.actionBoundaryActive !== true
    || execution.delegationEnforced !== true
    || execution.noHandsCommanderEnforced !== true
    || runtime.status !== "ready"
    || components.localProcessExecution !== true
    || components.enforcingProvider !== true
    || components.resultAwareSpecialistExecution !== true
    || components.durableActionBoundary !== true
    || components.exactRuntimeManifest !== true
  ) {
    throw new CompleteAutonomousLivePrerequisiteError(
      "complete_autonomous_runtime_unavailable",
      "The live Autonomous runtime is not enforcing its reviewed execution boundary.",
      "Restore the exact planner, specialist, provider, execution, and "
      + "result-aware runtime composition before launching.",
    );
  }
  const missingCandidateClasses =
    AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS.filter(
      (actionClassId) => !readyActionClassIds.includes(actionClassId),
    );
  if (missingCandidateClasses.length > 0) {
    throw new CompleteAutonomousLivePrerequisiteError(
      COMPLETE_AUTONOMOUS_CANDIDATE_TRANSPORT_UNAVAILABLE,
      "The running Ti-Scale process has no complete candidate Linux "
      + `transport for: ${missingCandidateClasses.join(", ")}.`,
      "Mount and attest the reviewed candidate transport/profile in the "
      + "3132 runtime, then verify the five typed post-exploit bindings are "
      + "present before retrying. This proof will not claim an isolated "
      + "harness or fixture as production runtime support.",
    );
  }
  const missingAssessmentClasses =
    AUTONOMOUS_ASSESSMENT_ACTION_CLASS_IDS.filter(
      (actionClassId) => !readyActionClassIds.includes(actionClassId),
    );
  if (missingAssessmentClasses.length > 0) {
    throw new CompleteAutonomousLivePrerequisiteError(
      "complete_autonomous_recon_or_exploit_runtime_unavailable",
      "The running Ti-Scale process is missing reviewed intake/recon/exploit "
      + `bindings for: ${missingAssessmentClasses.join(", ")}.`,
      "Restore the exact live assessment and exploit-validation activation "
      + "receipts before retrying.",
    );
  }

  const vault = plain(input.vault, "Vault snapshot");
  const connections = list(vault.connections, "Vault connections")
    .map((value) => plain(value, "Vault connection"));
  const matches = connections.filter((connection) =>
    connection.displayName === "Ti-Scale Attack Knowledge Vault"
    && connection.vaultPath === "Attack-Knowledge-Vault");
  if (matches.length !== 1) {
    throw new CompleteAutonomousLivePrerequisiteError(
      "complete_autonomous_vault_unavailable",
      "Exactly one connected Attack Knowledge Vault was not found.",
      "Connect and health-verify the canonical Attack-Knowledge-Vault.",
    );
  }
  const active = matches[0]!;
  const checks = plain(
    active.healthChecks,
    "Attack Knowledge Vault health checks",
  );
  if (
    vault.enabled !== true
    || active.status !== "connected"
    || active.pathAvailable !== true
    || checks.read !== true
    || checks.write !== true
    || checks.rename !== true
    || checks.delete !== true
    || integer(
      active.trackedNoteCount ?? 0,
      "Attack Knowledge Vault tracked notes",
    ) < 1
  ) {
    throw new CompleteAutonomousLivePrerequisiteError(
      "complete_autonomous_vault_unavailable",
      "The canonical Attack Knowledge Vault is not connected and round-trip healthy.",
      "Restore read/write/rename/delete health and synchronize at least one "
      + "canonical note before retrying.",
    );
  }
  return Object.freeze({
    schemaVersion: "ti-scale.complete-autonomous-live-prerequisites.v1",
    databaseSchemaVersion: input.databaseSchemaVersion,
    readyActionClassIds: Object.freeze([...readyActionClassIds]),
    candidateActionClassIds: Object.freeze([
      ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS,
    ]),
    activeVaultConnectionId: text(
      active.id,
      "Attack Knowledge Vault connection ID",
    ),
    activeVaultName: "Ti-Scale Attack Knowledge Vault",
    fixtureOnly: true,
    realTargetSupportClaimed: false,
  });
}

function actionPolicyOverrides():
Readonly<Record<ActionClassId, "pre_authorized" | "prohibited">> {
  const allowed = new Set<string>(COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS);
  return Object.freeze(Object.fromEntries(
    ACTION_CLASS_IDS.map((id) => [
      id,
      allowed.has(id) ? "pre_authorized" : "prohibited",
    ]),
  ) as Record<ActionClassId, "pre_authorized" | "prohibited">);
}

export function buildCompleteAutonomousResolveInput(): JsonObject {
  return {
    journey: "autonomous",
    authorizationAcknowledged: true,
    targets: [{
      value: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
      type: "host",
    }],
    templateId: "htb_web_full_path",
    objective:
      "Map the exact authorized disposable loopback host, fingerprint its "
      + "reachable web stack, assess evidence-backed weaknesses, run at most "
      + "one approved evidence-matched validation, establish the typed "
      + "candidate session, prove user and root access using hash-only "
      + "receipts without flag content, close the session, evaluate the run, "
      + "write reusable target-independent knowledge, and generate reports.",
    successCriteria: [...COMPLETE_AUTONOMOUS_SUCCESS_CRITERIA],
    environmentClassification: "local_disposable_lab",
    destructivePolicy: "bounded_lab_only",
    boundedDestructiveTargetIds: [COMPLETE_AUTONOMOUS_TARGET_ID],
    actionPolicyOverrides: actionPolicyOverrides(),
  };
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

function liveDatabaseSchemaVersion(): number {
  const database = readonlyDatabase();
  try {
    return Number((database.prepare(`
      SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations
    `).get() as { readonly version: number }).version);
  } finally {
    database.close();
  }
}

export async function inspectCompleteAutonomousLiveEnvironment(
  client: CompleteAutonomousProofClient,
  databaseSchemaVersion = liveDatabaseSchemaVersion(),
): Promise<CompleteAutonomousPrerequisiteReceipt> {
  const [health, readiness, vault] = await Promise.all([
    client.request("/api/v2/health"),
    client.request("/api/v2/system/readiness"),
    client.request("/api/v2/brain/vault"),
  ]);
  return assertCompleteAutonomousLivePrerequisites({
    health,
    readiness,
    vault,
    databaseSchemaVersion,
  });
}

interface CanonicalCompleteRun {
  readonly mission_id: string;
  readonly run_id: string;
  readonly plan_id: string;
  readonly contract_id: string;
  readonly contract_hash: string;
  readonly contract_version: number;
  readonly action_policy_json: string;
  readonly deliverables_json: string;
  readonly success_criteria_json: string;
  readonly scope_json: string;
}

interface CanonicalCompleteSession {
  readonly session_id: string;
  readonly attempt_id: string;
  readonly exploit_evidence_id: string;
  readonly candidate_binding_hash: string;
  readonly exact_target: string;
  readonly transport_type: string;
  readonly post_exploit_spec_id: string;
  readonly script_artifact_id: string;
  readonly expected_principal: string;
  readonly expected_uid: number;
  readonly declared_user_flag_path: string;
  readonly declared_root_flag_path: string;
}

export interface CompleteAutonomousDurableProofReceipt {
  readonly actionTypes: readonly string[];
  readonly logicalSucceededActions: 13;
  readonly durableActionAttempts: number;
  readonly independentlyVerifiedExploitAttempts: 1;
  readonly sessionArtifactId: string;
  readonly candidateTransportType: "candidate_runtime_session_v1";
  readonly userPrincipal: string;
  readonly userUid: number;
  readonly userFlagProofSha256: string;
  readonly rootPrincipal: "root";
  readonly rootUid: 0;
  readonly rootGid: 0;
  readonly rootFlagProofSha256: string;
  readonly cleanupVerified: true;
  readonly terminalCriterionEvidenceIds: readonly string[];
  readonly evaluationId: string;
  readonly reportArtifactIds: readonly string[];
  readonly contextHooks: readonly string[];
  readonly contextPackCount: number;
  readonly vaultBackedMemoryNodeIds: readonly string[];
  readonly activeVaultConnectionId: string;
}

function requiredRow<T>(value: T | undefined, message: string): T {
  if (!value) throw new Error(message);
  return value;
}

function stringArray(value: string, label: string): readonly string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
    throw new Error(`${label} was not a string array`);
  }
  return Object.freeze([...parsed]);
}

function canonicalCompleteRun(
  database: SqliteDatabase,
  runId: string,
  missionId: string,
): CanonicalCompleteRun {
  const run = database.prepare(`
    SELECT mission.id AS mission_id, run.id AS run_id,
      plan.id AS plan_id, contract.id AS contract_id,
      contract.contract_hash, contract.version AS contract_version,
      contract.action_policy_json, contract.deliverables_json,
      mission.success_criteria_json, mission.scope_json
    FROM runs run
    JOIN missions mission ON mission.id = run.mission_id
      AND mission.journey = 'autonomous'
      AND mission.status = 'completed'
      AND mission.authorization_status = 'verified'
      AND mission.control_plane = 'ti_scale'
    JOIN plans plan ON plan.id = run.current_plan_id
      AND plan.run_id = run.id
      AND plan.status IN ('active', 'completed')
    JOIN mission_contracts contract ON contract.id = run.contract_id
      AND contract.mission_id = mission.id
      AND contract.state = 'confirmed'
      AND contract.version = run.contract_version_bound
      AND contract.contract_hash = run.contract_hash_bound
    WHERE run.id = ? AND mission.id = ?
      AND run.journey = 'autonomous'
      AND run.status = 'completed'
      AND run.control_plane = 'ti_scale'
      AND run.progress = 1
      AND run.ended_at IS NOT NULL
    LIMIT 1
  `).get(runId, missionId) as CanonicalCompleteRun | undefined;
  return requiredRow(
    run,
    "The result is not one completed current-plan signed Autonomous run.",
  );
}

function assertCompleteContract(run: CanonicalCompleteRun): void {
  const policy = parseJson(
    run.action_policy_json,
    "persisted Complete Autonomous action policy",
  );
  exactSet(
    list(policy.allowedActionClasses, "persisted allowed action classes"),
    COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS,
    "persisted allowed action classes",
  );
  const prohibited = list(
    policy.prohibitedActionClasses,
    "persisted prohibited action classes",
  ).map((value) => text(value, "persisted prohibited action class"));
  if (
    COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS.some((actionClassId) =>
      prohibited.includes(actionClassId))
  ) {
    throw new Error(
      "The Complete Autonomous contract prohibits one of its required classes",
    );
  }
  exactSet(
    stringArray(
      run.success_criteria_json,
      "persisted success criteria",
    ),
    COMPLETE_AUTONOMOUS_SUCCESS_CRITERIA,
    "persisted success criteria",
  );
  exactSet(
    stringArray(run.deliverables_json, "persisted deliverables"),
    AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
    "persisted terminal deliverables",
  );
  const scope = parseJson(run.scope_json, "persisted mission scope");
  exactSet(
    list(scope.allowedTargets, "persisted allowed targets"),
    [DISPOSABLE_COMPLETE_AUTONOMOUS_HOST],
    "persisted allowed targets",
  );
  if (
    scope.environmentClassification !== "local_disposable_lab"
    || list(scope.prohibitedTargets, "persisted prohibited targets").length
      !== 0
  ) {
    throw new Error(
      "The Complete Autonomous mission is not one exact disposable local lab",
    );
  }
}

export function assertCompleteAutonomousActionAudit(
  snapshot: AutonomousAssessmentAuditSnapshot,
): Readonly<{
  logicalSucceededActions: 13;
  durableActionAttempts: number;
}> {
  const expectedTypes = [...COMPLETE_AUTONOMOUS_ACTION_TYPES];
  if (
    snapshot.runStatus !== "completed"
    || snapshot.runJourney !== "autonomous"
  ) {
    throw new Error("The durable run is not completed Autonomous work");
  }
  if (snapshot.actions.length < expectedTypes.length) {
    throw new Error(
      "The durable run has fewer action attempts than the complete route",
    );
  }
  const expectedTypeSet = new Set<string>(expectedTypes);
  for (const [index, action] of snapshot.actions.entries()) {
    const expectedClass = REQUIRED_ACTION_CLASS_BY_TYPE.get(action.action_type);
    if (
      !expectedTypeSet.has(action.action_type)
      || !expectedClass
      || action.action_class !== expectedClass
      || action.scoped_target !== DISPOSABLE_COMPLETE_AUTONOMOUS_HOST
      || action.guided_decision_id !== null
      || !["succeeded", "failed", "timed_out"].includes(action.status)
    ) {
      throw new Error(
        `Durable Complete Autonomous action attempt ${index + 1} drifted `
        + "from its exact target, type, class, or no-hands boundary",
      );
    }
  }
  const succeeded = snapshot.actions.filter(({ status }) =>
    status === "succeeded");
  if (succeeded.length !== expectedTypes.length) {
    throw new Error(
      "The run did not contain exactly one succeeded action for every "
      + "Complete Autonomous phase",
    );
  }
  const succeededTypes = succeeded.map(({ action_type }) => action_type);
  if (
    succeededTypes.some((actionType, index) =>
      actionType !== expectedTypes[index])
  ) {
    throw new Error(
      "The succeeded actions did not preserve the reviewed "
      + "recon→exploit→user→root→cleanup order",
    );
  }
  for (const actionType of expectedTypes) {
    if (
      succeeded.filter((action) => action.action_type === actionType).length
        !== 1
    ) {
      throw new Error(
        `The complete route did not succeed exactly once: ${actionType}`,
      );
    }
  }

  const callsByAction = new Map<
    string,
    AutonomousAssessmentAuditSnapshot["toolCalls"][number]
  >();
  for (const call of snapshot.toolCalls) {
    if (callsByAction.has(call.action_id)) {
      throw new Error("One durable action has multiple physical tool receipts");
    }
    callsByAction.set(call.action_id, call);
  }
  if (
    snapshot.toolCalls.length !== snapshot.actions.length
    || snapshot.providerTurnCount !== 0
    || snapshot.guidedDecisionCount !== 0
    || snapshot.approvalCount !== 0
    || snapshot.toolCalls.some(({ mcp_server_id }) => mcp_server_id !== null)
  ) {
    throw new Error(
      "The complete route crossed a provider, MCP, Guided, or approval boundary",
    );
  }
  for (const [index, action] of snapshot.actions.entries()) {
    const call = callsByAction.get(action.id);
    const expectedProvider =
      COMPLETE_AUTONOMOUS_POST_EXPLOIT_ACTION_TYPES.includes(
        action.action_type as
          (typeof COMPLETE_AUTONOMOUS_POST_EXPLOIT_ACTION_TYPES)[number],
      )
        ? "candidate-linux-session"
        : action.action_class === "exploit_validation"
          ? "exact-target-sandbox"
          : action.action_class ===
              "cve_intelligence_applicability_validation"
            ? "reviewed-local-intelligence"
            : "reviewed-local-process";
    const expectedStatus = action.status === "timed_out"
      ? "timed_out"
      : action.status;
    if (
      !call
      || call.tool_name !== action.action_type
      || call.provider !== expectedProvider
      || call.status !== expectedStatus
      || call.error_category !== action.error_category
    ) {
      throw new Error(
        `Physical execution receipt ${index + 1} did not match its action`,
      );
    }
  }
  return Object.freeze({
    logicalSucceededActions: 13,
    durableActionAttempts: snapshot.actions.length,
  });
}

function canonicalCompleteSession(
  database: SqliteDatabase,
  run: CanonicalCompleteRun,
): CanonicalCompleteSession {
  const row = database.prepare(`
    SELECT session.id AS session_id, attempt.id AS attempt_id,
      proof.id AS exploit_evidence_id, session.candidate_binding_hash,
      session.exact_target, spec.transport_type,
      spec.id AS post_exploit_spec_id, spec.script_artifact_id,
      spec.expected_principal, spec.expected_uid,
      spec.declared_user_flag_path, spec.declared_root_flag_path
    FROM session_artifacts session
    JOIN candidate_linux_post_exploit_specs spec
      ON spec.id = session.post_exploit_spec_id
      AND spec.status = 'active'
      AND spec.transport_type = 'candidate_runtime_session_v1'
    JOIN attack_attempts attempt
      ON attempt.id = session.origin_attack_attempt_id
      AND attempt.mission_id = session.mission_id
      AND attempt.run_id = session.run_id
      AND attempt.plan_id = session.plan_id
      AND attempt.status = 'succeeded'
      AND attempt.action_class = 'exploit_validation'
    JOIN attack_attempt_evidence link
      ON link.attack_attempt_id = attempt.id
      AND link.evidence_id = session.exploit_outcome_evidence_id
      AND link.relationship = 'outcome'
    JOIN evidence proof ON proof.id = link.evidence_id
      AND proof.verification_state = 'verified'
      AND proof.evidence_type = 'exploit_validation_result'
      AND proof.target = session.exact_target
    JOIN topology_nodes target ON target.id = session.target_node_id
      AND target.scope_status = 'allowed'
      AND target.normalized_identity = session.exact_target
    WHERE session.mission_id = ? AND session.run_id = ?
      AND session.plan_id = ?
      AND session.exact_target = ?
      AND session.status = 'closed'
      AND session.access_level = 'root'
      AND session.closed_at IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM session_artifact_leases lease
        WHERE lease.session_artifact_id = session.id
          AND lease.released_at IS NULL
      )
  `).all(
    run.mission_id,
    run.run_id,
    run.plan_id,
    DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
  ) as CanonicalCompleteSession[];
  if (row.length !== 1) {
    throw new Error(
      "Exactly one closed root-level candidate-runtime session with a "
      + "verified exploit origin was not found",
    );
  }
  return row[0]!;
}

function assertPostExploitActionsAndVault(
  database: SqliteDatabase,
  run: CanonicalCompleteRun,
  session: CanonicalCompleteSession,
  activeVaultConnectionId: string,
): readonly string[] {
  const actionIds: string[] = [];
  for (const actionType of COMPLETE_AUTONOMOUS_POST_EXPLOIT_ACTION_TYPES) {
    const rows = database.prepare(`
      SELECT action.id
      FROM actions action
      JOIN plan_steps step ON step.id = action.step_id
        AND step.plan_id = ?
      WHERE action.mission_id = ? AND action.run_id = ?
        AND action.action_type = ?
        AND action.status = 'succeeded'
        AND action.scoped_target = ?
        AND action.contract_id = ?
        AND json_extract(
          action.normalized_arguments_json,
          '$.sessionArtifactId'
        ) = ?
        AND EXISTS (
          SELECT 1
          FROM memory_context_packs pack
          JOIN memory_context_items item
            ON item.context_pack_id = pack.id AND item.used = 1
          JOIN memory_nodes node ON node.id = item.node_id
            AND node.lifecycle_status IN ('confirmed', 'verified')
            AND node.confirmation_state IN ('not_required', 'confirmed')
            AND (node.expires_at IS NULL OR node.expires_at > action.ended_at)
          JOIN vault_sync_state sync ON sync.node_id = node.id
            AND sync.connection_id = ?
            AND sync.database_version = node.version
            AND sync.status = 'synced'
            AND sync.vault_content_hash = sync.database_content_hash
          JOIN vault_connections vault ON vault.id = sync.connection_id
            AND vault.status = 'connected'
          WHERE pack.action_id = action.id
            AND pack.mission_id = action.mission_id
            AND pack.run_id = action.run_id
            AND pack.journey = 'autonomous'
            AND pack.release_data_class = 'canonical'
            AND EXISTS (
              SELECT 1 FROM audit_records health
              WHERE health.resource_type = 'vault_connection'
                AND health.resource_id = vault.id
                AND health.action = 'vault.health.verified'
            )
            AND NOT EXISTS (
              SELECT 1 FROM vault_conflicts conflict
              WHERE conflict.connection_id = vault.id
                AND conflict.status = 'open'
            )
        )
    `).all(
      run.plan_id,
      run.mission_id,
      run.run_id,
      actionType,
      DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
      run.contract_id,
      session.session_id,
      activeVaultConnectionId,
    ) as Array<{ readonly id: string }>;
    if (rows.length !== 1) {
      throw new Error(
        `${actionType} lacks one succeeded current-plan action with an `
        + "active-Vault-backed Context Pack",
      );
    }
    actionIds.push(rows[0]!.id);
  }
  return Object.freeze(actionIds);
}

function assertSessionProofs(
  database: SqliteDatabase,
  session: CanonicalCompleteSession,
): Readonly<{
  userPrincipal: string;
  userUid: number;
  userFlagProofSha256: string;
  rootFlagProofSha256: string;
}> {
  const identities = database.prepare(`
    SELECT observation.observer_kind, observation.principal,
      observation.uid, observation.gid, observation.groups_json,
      evidence.verification_state, evidence.action_id
    FROM session_identity_observations observation
    JOIN evidence ON evidence.id = observation.evidence_id
      AND evidence.action_id = observation.action_id
      AND evidence.verification_state = 'verified'
    WHERE observation.session_artifact_id = ?
    ORDER BY observation.observer_kind
  `).all(session.session_id) as Array<{
    readonly observer_kind: string;
    readonly principal: string;
    readonly uid: number;
    readonly gid: number;
    readonly groups_json: string;
    readonly verification_state: string;
    readonly action_id: string;
  }>;
  const user = identities.filter(({ observer_kind }) =>
    observer_kind === "user_identity");
  const root = identities.filter(({ observer_kind }) =>
    observer_kind === "root_identity");
  if (
    user.length !== 1
    || root.length !== 1
    || user[0]!.principal !== session.expected_principal
    || user[0]!.uid !== session.expected_uid
    || user[0]!.uid < 1
    || user[0]!.gid < 1
    || root[0]!.principal !== "root"
    || root[0]!.uid !== 0
    || root[0]!.gid !== 0
  ) {
    throw new Error(
      "The candidate session does not contain exactly one verified "
      + "non-root identity and one verified root UID/GID identity",
    );
  }
  for (const identity of identities) {
    const groups = JSON.parse(identity.groups_json) as unknown;
    if (
      !Array.isArray(groups)
      || groups.length < 1
      || groups.some((group) => typeof group !== "string")
    ) {
      throw new Error("A typed session identity has invalid groups");
    }
  }

  const proofs = database.prepare(`
    SELECT proof.proof_kind, proof.declared_path, proof.content_sha256,
      proof.byte_size, evidence.verification_state, evidence.action_id,
      evidence.extracted_text
    FROM session_flag_proofs proof
    JOIN evidence ON evidence.id = proof.evidence_id
      AND evidence.action_id = proof.action_id
      AND evidence.verification_state = 'verified'
    WHERE proof.session_artifact_id = ?
    ORDER BY proof.proof_kind
  `).all(session.session_id) as Array<{
    readonly proof_kind: string;
    readonly declared_path: string;
    readonly content_sha256: string;
    readonly byte_size: number;
    readonly verification_state: string;
    readonly action_id: string;
    readonly extracted_text: string | null;
  }>;
  const userProof = proofs.filter(({ proof_kind }) =>
    proof_kind === "user_flag");
  const rootProof = proofs.filter(({ proof_kind }) =>
    proof_kind === "root_flag");
  if (
    userProof.length !== 1
    || rootProof.length !== 1
    || userProof[0]!.declared_path !== session.declared_user_flag_path
    || rootProof[0]!.declared_path !== session.declared_root_flag_path
    || userProof[0]!.declared_path
      !== `/home/${session.expected_principal}/user.txt`
    || rootProof[0]!.declared_path !== "/root/root.txt"
    || !SHA256.test(userProof[0]!.content_sha256)
    || !SHA256.test(rootProof[0]!.content_sha256)
    || userProof[0]!.byte_size < 1
    || userProof[0]!.byte_size > 4_096
    || rootProof[0]!.byte_size < 1
    || rootProof[0]!.byte_size > 4_096
  ) {
    throw new Error(
      "The candidate session does not contain exactly one bounded hash-only "
      + "user proof and one bounded hash-only root proof",
    );
  }
  if (
    proofs.some(({ extracted_text, content_sha256 }) =>
      extracted_text !== null
      && extracted_text.trim() !== ""
      && !extracted_text.includes(content_sha256))
  ) {
    throw new Error(
      "A flag proof retained extracted content instead of a hash-only receipt",
    );
  }
  return Object.freeze({
    userPrincipal: user[0]!.principal,
    userUid: user[0]!.uid,
    userFlagProofSha256: userProof[0]!.content_sha256,
    rootFlagProofSha256: rootProof[0]!.content_sha256,
  });
}

function assertExploitLineage(
  database: SqliteDatabase,
  run: CanonicalCompleteRun,
  session: CanonicalCompleteSession,
  snapshot: AutonomousAssessmentAuditSnapshot,
): void {
  const attempt = snapshot.attackAttempts[0];
  const provenance = attempt?.outcome_provenance;
  const independentVerifier = provenance?.independentVerifier;
  const rawOutputPromoted = provenance?.rawOutputPromoted;
  if (
    snapshot.attackAttempts.length !== 1
    || !attempt
    || attempt.id !== session.attempt_id
    || attempt.status !== "succeeded"
    || attempt.action_class !== "exploit_validation"
    || attempt.action_type !== "ti-scale:autonomous-exploit-validation"
    || attempt.scoped_target !== DISPOSABLE_COMPLETE_AUTONOMOUS_HOST
    || !attempt.started_at
    || !attempt.ended_at
    || attempt.outcome_evidence_count !== 1
    || attempt.outcome_evidence_id !== session.exploit_evidence_id
    || attempt.outcome_verification_state !== "verified"
    || attempt.outcome_source
      !== "local:independent-http-outcome-observer"
    || !provenance
    || provenance.attackAttemptId !== attempt.id
    || provenance.exactTarget !== DISPOSABLE_COMPLETE_AUTONOMOUS_HOST
    || ![true, 1].includes(independentVerifier as true | 1)
    || ![false, 0].includes(rawOutputPromoted as false | 0)
    || provenance.matched !== true
  ) {
    throw new Error(
      "The exploit branch is not exactly one independently observed, "
      + "custody-verified attempt on the disposable target",
    );
  }

  const cve = database.prepare(`
    SELECT cve.id, cve.cve_id, cve.component, cve.detected_version,
      cve.applicability, cve.confidence, cve.source_links_json,
      version.id AS version_evidence_id,
      version.content_hash AS version_evidence_hash,
      version.verification_state AS version_verification_state,
      version.target AS version_target
    FROM cve_applicability_records cve
    JOIN evidence version ON version.id = cve.version_evidence_id
      AND version.mission_id = cve.mission_id
      AND version.run_id = cve.run_id
      AND version.evidence_type = 'service_version_fingerprint'
      AND version.verification_state = 'verified'
      AND version.target = ?
    WHERE cve.mission_id = ? AND cve.run_id = ?
      AND cve.cve_id = ?
      AND cve.component = ?
      AND cve.detected_version = ?
      AND cve.applicability = 'confirmed'
      AND cve.confidence >= 0.8
  `).all(
    DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
    run.mission_id,
    run.run_id,
    DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
    DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
    DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
  ) as Array<{
    readonly id: string;
    readonly cve_id: string;
    readonly component: string;
    readonly detected_version: string;
    readonly applicability: string;
    readonly confidence: number;
    readonly source_links_json: string;
    readonly version_evidence_id: string;
    readonly version_evidence_hash: string;
    readonly version_verification_state: string;
    readonly version_target: string;
  }>;
  if (cve.length !== 1 || !SHA256.test(cve[0]!.version_evidence_hash)) {
    throw new Error(
      "The exploit attempt has no exact current-run verified "
      + `${DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT} `
      + `${DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION}/`
      + `${DISPOSABLE_COMPLETE_AUTONOMOUS_CVE} evidence match`,
    );
  }
  const sources = JSON.parse(cve[0]!.source_links_json) as unknown;
  if (
    !Array.isArray(sources)
    || !sources.some((source) =>
      source
      && typeof source === "object"
      && !Array.isArray(source)
      && ["nvd", "cve_org", "mitre", "cisa"].includes(
        String((source as Record<string, unknown>).kind ?? "")
          .toLocaleLowerCase("en-US"),
      ))
  ) {
    throw new Error(
      "The confirmed CVE record has no authoritative source provenance",
    );
  }

  const expansionEvents = snapshot.events.filter(({ event_type }) =>
    event_type === "plan.evidence_driven_expansion_applied");
  if (expansionEvents.length !== 1) {
    throw new Error(
      "The current evidence did not produce exactly one durable plan expansion",
    );
  }
  const expansion = parseJson(
    expansionEvents[0]!.payload_json,
    "evidence-driven plan expansion",
  );
  if (
    expansion.attackAttemptId !== attempt.id
    || expansion.contractAmended !== false
    || expansion.memoryPolicyAmended !== false
  ) {
    throw new Error(
      "The exploit expansion changed authority or lost its attempt lineage",
    );
  }
}

function terminalCriterionEvidenceIds(
  database: SqliteDatabase,
  run: CanonicalCompleteRun,
): readonly string[] {
  return Object.freeze(
    AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA.map(
      (criterion) => {
        const criterionId = autonomousSuccessCriterionId(criterion);
        const rows = database.prepare(`
          SELECT id FROM evidence
          WHERE mission_id = ? AND run_id = ?
            AND verification_state = 'verified'
            AND json_extract(
              provenance_json,
              '$.successCriterionReference.criterionId'
            ) = ?
          ORDER BY acquired_at, id
        `).all(
          run.mission_id,
          run.run_id,
          criterionId,
        ) as Array<{ readonly id: string }>;
        if (rows.length !== 1) {
          throw new Error(
            `Terminal criterion ${criterionId} does not have exactly one `
            + "verified evidence record",
          );
        }
        return rows[0]!.id;
      },
    ),
  );
}

function assertEvaluationAndReports(
  database: SqliteDatabase,
  run: CanonicalCompleteRun,
): Readonly<{
  evaluationId: string;
  reportArtifactIds: readonly string[];
}> {
  const evaluations = database.prepare(`
    SELECT id, journey, evidence_coverage, metrics_json
    FROM run_evaluations
    WHERE mission_id = ? AND run_id = ?
  `).all(run.mission_id, run.run_id) as Array<{
    readonly id: string;
    readonly journey: string;
    readonly evidence_coverage: number;
    readonly metrics_json: string;
  }>;
  if (
    evaluations.length !== 1
    || evaluations[0]!.journey !== "autonomous"
    || evaluations[0]!.evidence_coverage <= 0
  ) {
    throw new Error(
      "The complete run did not produce exactly one evidence-covered "
      + "Autonomous evaluation",
    );
  }
  const metrics = parseJson(
    evaluations[0]!.metrics_json,
    "Complete Autonomous evaluation metrics",
  );
  if (
    Number(metrics.guidedDecisionCount ?? 0) !== 0
    || Number(metrics.autonomousUserWaitCount ?? 0) !== 0
  ) {
    throw new Error(
      "The Complete Autonomous evaluation reports Guided or operator-wait dependence",
    );
  }

  const reports = database.prepare(`
    SELECT id, artifact_type, content_hash, storage_uri, byte_size, journey
    FROM artifacts
    WHERE mission_id = ? AND run_id = ?
      AND artifact_type IN (
        'mission_report_json',
        'mission_report_markdown'
      )
    ORDER BY artifact_type, id
  `).all(run.mission_id, run.run_id) as Array<{
    readonly id: string;
    readonly artifact_type: string;
    readonly content_hash: string;
    readonly storage_uri: string;
    readonly byte_size: number;
    readonly journey: string;
  }>;
  if (
    reports.length !== 2
    || reports.some((report) => {
      const format = report.artifact_type === "mission_report_json"
        ? "json"
        : report.artifact_type === "mission_report_markdown"
          ? "markdown"
          : "";
      return !format
        || report.journey !== "autonomous"
        || report.byte_size < 1
        || !SHA256.test(report.content_hash)
        || report.storage_uri
          !== `ti-scale-report://sha256/${report.content_hash}/${format}`;
    })
  ) {
    throw new Error(
      "The complete run did not produce both immutable content-addressed reports",
    );
  }
  exactSet(
    reports.map(({ artifact_type }) => artifact_type),
    ["mission_report_json", "mission_report_markdown"],
    "terminal report artifact types",
  );
  return Object.freeze({
    evaluationId: evaluations[0]!.id,
    reportArtifactIds: Object.freeze(reports.map(({ id }) => id)),
  });
}

function assertContextPacksAndVault(
  database: SqliteDatabase,
  run: CanonicalCompleteRun,
  snapshot: AutonomousAssessmentAuditSnapshot,
  activeVaultConnectionId: string,
): Readonly<{
  contextPackCount: number;
  vaultBackedMemoryNodeIds: readonly string[];
}> {
  const hooks = new Set(snapshot.contexts.map(({ hook }) => hook));
  for (const hook of COMPLETE_AUTONOMOUS_REQUIRED_CONTEXT_HOOKS) {
    if (!hooks.has(hook)) {
      throw new Error(`Required Brain Context Pack hook is missing: ${hook}`);
    }
  }
  if (
    snapshot.contexts.length < COMPLETE_AUTONOMOUS_REQUIRED_CONTEXT_HOOKS.length
  ) {
    throw new Error("The complete run has too few canonical Context Packs");
  }
  const assignments = snapshot.agentToolDecisions.filter(({ hook }) =>
    hook === "assignment_acceptance");
  const tools = snapshot.agentToolDecisions.filter(({ hook }) =>
    hook === "tool_selection");
  if (
    assignments.length !== snapshot.actions.length
    || tools.length !== snapshot.actions.length
  ) {
    throw new Error(
      "Every represented action did not consult both assignment and tool Context Packs",
    );
  }

  const syncedNodeIds = new Set(snapshot.activeVaultSyncedNodeIds);
  const usedNodeIds = new Set(
    snapshot.usedMemoryNodes.map(({ node_id }) => node_id),
  );
  if (
    usedNodeIds.size < 1
    || snapshot.usedMemoryNodes.some((node) =>
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
      || !syncedNodeIds.has(node.node_id))
  ) {
    throw new Error(
      "A used Context Pack item is not confirmed/verified and synchronized "
      + "to the active connected Vault",
    );
  }
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
        !usedNodeIds.has(nodeId) || !syncedNodeIds.has(nodeId))
    ) {
      throw new Error(
        "Brain memory changed execution authority or lacks active-Vault custody",
      );
    }
  }

  const vault = database.prepare(`
    SELECT connection.id
    FROM vault_connections connection
    WHERE connection.id = ?
      AND connection.display_name = 'Ti-Scale Attack Knowledge Vault'
      AND connection.vault_path = 'Attack-Knowledge-Vault'
      AND connection.status = 'connected'
      AND EXISTS (
        SELECT 1 FROM audit_records health
        WHERE health.resource_type = 'vault_connection'
          AND health.resource_id = connection.id
          AND health.action = 'vault.health.verified'
      )
      AND NOT EXISTS (
        SELECT 1 FROM vault_conflicts conflict
        WHERE conflict.connection_id = connection.id
          AND conflict.status = 'open'
      )
  `).all(activeVaultConnectionId) as Array<{ readonly id: string }>;
  if (vault.length !== 1) {
    throw new Error(
      "The proof Context Packs are not backed by the one connected, "
      + "health-verified Attack Knowledge Vault",
    );
  }
  const exactSynced = database.prepare(`
    SELECT DISTINCT state.node_id
    FROM vault_sync_state state
    JOIN memory_nodes node ON node.id = state.node_id
      AND node.version = state.database_version
    WHERE state.connection_id = ?
      AND state.status = 'synced'
      AND state.vault_content_hash IS NOT NULL
      AND state.vault_content_hash = state.database_content_hash
      AND state.node_id IN (
        SELECT item.node_id
        FROM memory_context_items item
        JOIN memory_context_packs pack ON pack.id = item.context_pack_id
        WHERE pack.mission_id = ?
          AND (
            pack.run_id = ?
            OR (pack.run_id IS NULL AND pack.journey = 'autonomous')
          )
          AND item.used = 1
      )
    ORDER BY state.node_id
  `).all(
    activeVaultConnectionId,
    run.mission_id,
    run.run_id,
  ) as Array<{ readonly node_id: string }>;
  if (
    exactSynced.length !== usedNodeIds.size
    || exactSynced.some(({ node_id }) => !usedNodeIds.has(node_id))
  ) {
    throw new Error(
      "The connected Vault does not contain an exact synchronized projection "
      + "of every memory node used by the proof Context Packs",
    );
  }
  return Object.freeze({
    contextPackCount: snapshot.contexts.length,
    vaultBackedMemoryNodeIds: Object.freeze(
      exactSynced.map(({ node_id }) => node_id),
    ),
  });
}

function assertNoSecretOrFlagContent(database: SqliteDatabase, runId: string): void {
  const violations = database.prepare(`
    SELECT id
    FROM evidence
    WHERE run_id = ?
      AND (
        extracted_text LIKE '%Authorization: Bearer%'
        OR extracted_text LIKE '%BEGIN %PRIVATE KEY%'
        OR (
          evidence_type = 'privilege_access_proof'
          AND extracted_text IS NOT NULL
          AND length(trim(extracted_text)) > 0
          AND extracted_text NOT GLOB '*[a-f0-9][a-f0-9][a-f0-9][a-f0-9]*'
        )
      )
    LIMIT 1
  `).all(runId) as Array<{ readonly id: string }>;
  if (violations.length > 0) {
    throw new Error(
      "Canonical evidence retained credential-like or non-hash flag content",
    );
  }
}

export function assertCompleteAutonomousDurableProof(
  database: SqliteDatabase,
  runId: string,
  missionId: string,
  activeVaultConnectionId: string,
): CompleteAutonomousDurableProofReceipt {
  const run = canonicalCompleteRun(database, runId, missionId);
  assertCompleteContract(run);
  const snapshot = readAutonomousAssessmentAuditSnapshot(
    runId,
    missionId,
    activeVaultConnectionId,
    database,
  );
  const actionAudit = assertCompleteAutonomousActionAudit(snapshot);
  const session = canonicalCompleteSession(database, run);
  assertExploitLineage(database, run, session, snapshot);
  assertPostExploitActionsAndVault(
    database,
    run,
    session,
    activeVaultConnectionId,
  );
  const sessionProofs = assertSessionProofs(database, session);
  const criterionEvidenceIds = terminalCriterionEvidenceIds(database, run);
  const terminal = assertEvaluationAndReports(database, run);
  const context = assertContextPacksAndVault(
    database,
    run,
    snapshot,
    activeVaultConnectionId,
  );
  assertNoSecretOrFlagContent(database, runId);
  return Object.freeze({
    actionTypes: Object.freeze([...COMPLETE_AUTONOMOUS_ACTION_TYPES]),
    logicalSucceededActions: actionAudit.logicalSucceededActions,
    durableActionAttempts: actionAudit.durableActionAttempts,
    independentlyVerifiedExploitAttempts: 1,
    sessionArtifactId: session.session_id,
    candidateTransportType: "candidate_runtime_session_v1",
    userPrincipal: sessionProofs.userPrincipal,
    userUid: sessionProofs.userUid,
    userFlagProofSha256: sessionProofs.userFlagProofSha256,
    rootPrincipal: "root",
    rootUid: 0,
    rootGid: 0,
    rootFlagProofSha256: sessionProofs.rootFlagProofSha256,
    cleanupVerified: true,
    terminalCriterionEvidenceIds: criterionEvidenceIds,
    evaluationId: terminal.evaluationId,
    reportArtifactIds: terminal.reportArtifactIds,
    contextHooks: Object.freeze([
      ...COMPLETE_AUTONOMOUS_REQUIRED_CONTEXT_HOOKS,
    ]),
    contextPackCount: context.contextPackCount,
    vaultBackedMemoryNodeIds: context.vaultBackedMemoryNodeIds,
    activeVaultConnectionId,
  });
}

export interface DisposableCompleteTargetTraceReceipt {
  readonly observedRequestCount: number;
  readonly reconRequestCount: number;
  readonly exploitTriggerRequestCount: 1;
  readonly exploitMarkerRequestCount: number;
  readonly typedSessionRequestCount: number;
  readonly openSessionCount: 0;
  readonly impactMarker: typeof DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER;
}

export function assertDisposableCompleteTargetTrace(
  target: DisposableCompleteAutonomousTarget,
): DisposableCompleteTargetTraceReceipt {
  if (
    target.host !== DISPOSABLE_COMPLETE_AUTONOMOUS_HOST
    || target.port !== DISPOSABLE_COMPLETE_AUTONOMOUS_PORT
    || target.origin
      !== `http://${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}:`
        + `${DISPOSABLE_COMPLETE_AUTONOMOUS_PORT}`
    || target.fixtureOnly !== true
    || target.disposableSimulationOnly !== true
    || target.realTargetSupport !== false
    || target.arbitraryExternalTargetSupport !== false
    || target.hostFileReads !== false
    || target.commandExecution !== false
  ) {
    throw new Error(
      "The target is not the exact truthfully labelled disposable fixture",
    );
  }
  const traces = target.traces();
  const recon = traces.filter(({ phase, result }) =>
    phase === "recon" && result === "recon_response");
  const trigger = traces.filter(({
    phase,
    path,
    fixtureMarker,
    result,
  }) =>
    phase === "exploit_validation"
    && isDisposableCompleteAutonomousImpactPath(path)
    && fixtureMarker === DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER
    && result === "fixed_impact_triggered");
  const exploit = traces.filter(({
    phase,
    path,
    actionId,
    fixtureMarker,
    result,
  }) =>
    phase === "exploit_validation"
    && isDisposableCompleteAutonomousImpactPath(path)
    && actionId === null
    && fixtureMarker === null
    && result === "fixed_impact_disclosed");
  const session = traces.filter(({ phase }) => phase === "session");
  if (
    traces.length < 1
    || recon.length < 1
    || trigger.length !== 1
    || exploit.length !== 1
    || trigger[0]!.sequence >= exploit[0]!.sequence
  ) {
    throw new Error(
      "The disposable target did not prove real recon, exactly one reviewed "
      + "fixture trigger, and one later independent fixed-marker observation",
    );
  }
  if (
    traces.some(({ path }) =>
      path.includes("3131")
      || path.includes("localhost")
      || path.includes("127.0.0.1"))
  ) {
    throw new Error("A disposable target trace referenced the excluded 3131 host");
  }
  if (target.openSessionCount() !== 0) {
    throw new Error(
      "The disposable target retained an open typed fixture session after cleanup",
    );
  }
  return Object.freeze({
    observedRequestCount: traces.length,
    reconRequestCount: recon.length,
    exploitTriggerRequestCount: 1,
    exploitMarkerRequestCount: 1,
    typedSessionRequestCount: session.length,
    openSessionCount: 0,
    impactMarker: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
  });
}

async function waitForCompletedRun(
  client: CompleteAutonomousProofClient,
  runId: string,
): Promise<JsonObject> {
  const deadline = Date.now() + RUN_TIMEOUT_MS;
  do {
    const response = await client.request(
      `/api/v2/runs/${encodeURIComponent(runId)}`,
    );
    const run = plain(response.run, "Complete Autonomous run");
    const status = String(run.status ?? "");
    if (status === "waiting_guided_decision") {
      throw new Error(
        "The Complete Autonomous run entered a Guided waiting state",
      );
    }
    if (["blocked", "failed", "cancelled"].includes(status)) {
      throw new Error(
        `The Complete Autonomous run ended ${status}: `
        + safeMessage(run.statusReason, "No reason was returned"),
      );
    }
    if (status === "completed") return run;
    if (Date.now() >= deadline) break;
    await Bun.sleep(POLL_INTERVAL_MS);
  } while (Date.now() < deadline);
  throw new Error(
    `The Complete Autonomous run did not finish within ${RUN_TIMEOUT_MS} ms`,
  );
}

interface CompleteCloseoutWaitOptions {
  readonly timeoutMs?: number;
  readonly pollIntervalMs?: number;
  readonly now?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
  readonly verify?: () => CompleteAutonomousDurableProofReceipt;
}

export async function waitForCompleteAutonomousDurableCloseout(
  runId: string,
  missionId: string,
  activeVaultConnectionId: string,
  options: CompleteCloseoutWaitOptions = {},
): Promise<CompleteAutonomousDurableProofReceipt> {
  const timeoutMs = options.timeoutMs ?? TERMINAL_CLOSEOUT_TIMEOUT_MS;
  const pollIntervalMs = options.pollIntervalMs ?? POLL_INTERVAL_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0) {
    throw new TypeError(
      "Complete Autonomous closeout timeout must be a non-negative integer",
    );
  }
  if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 0) {
    throw new TypeError(
      "Complete Autonomous closeout poll interval must be a non-negative integer",
    );
  }
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? (async (milliseconds: number) => {
    await Bun.sleep(milliseconds);
  });
  const database = options.verify ? undefined : readonlyDatabase();
  const verify = options.verify ?? (() =>
    assertCompleteAutonomousDurableProof(
      database!,
      runId,
      missionId,
      activeVaultConnectionId,
    ));
  const deadline = now() + timeoutMs;
  let latest = "durable closeout has not been evaluated";
  try {
    do {
      try {
        return verify();
      } catch (error) {
        latest = safeMessage(
          error instanceof Error ? error.message : undefined,
          "unknown durable closeout condition",
        );
      }
      if (now() >= deadline) break;
      await sleep(pollIntervalMs);
    } while (now() <= deadline);
  } finally {
    database?.close();
  }
  throw new Error(
    "The completed run did not finish durable Complete Autonomous closeout "
    + `within ${timeoutMs} ms; latest check: ${latest}`,
  );
}

function assertApiProjection(
  evidenceValue: unknown,
  reportsValue: unknown,
  contextsValue: unknown,
  vaultValue: unknown,
  durable: CompleteAutonomousDurableProofReceipt,
): Readonly<{
  evidenceCount: number;
  reportCount: number;
  contextPackCount: number;
}> {
  const evidence = list(
    plain(evidenceValue, "evidence API projection").items,
    "evidence API items",
  ).map((item) => plain(item, "evidence API item"));
  const evidenceIds = new Set(
    evidence.map((item) => text(item.id, "evidence API item ID")),
  );
  if (
    durable.terminalCriterionEvidenceIds.some((id) => !evidenceIds.has(id))
  ) {
    throw new Error(
      "The evidence API does not expose every terminal criterion proof",
    );
  }

  const reports = list(
    plain(reportsValue, "reports API projection").items,
    "reports API items",
  ).map((item) => plain(item, "reports API item"));
  const reportIds = new Set(
    reports.map((item) => text(item.id, "report API item ID")),
  );
  if (durable.reportArtifactIds.some((id) => !reportIds.has(id))) {
    throw new Error("The Reports API does not expose both durable reports");
  }

  const contexts = list(
    plain(contextsValue, "Context Pack API projection").items,
    "Context Pack API items",
  ).map((item) => plain(item, "Context Pack API item"));
  if (
    contexts.length < durable.contextPackCount
    || !contexts.some((item) =>
      String(item.purpose ?? "").toLocaleLowerCase("en-US")
        .includes("plan"))
    || !contexts.some((item) =>
      String(item.purpose ?? "").toLocaleLowerCase("en-US")
        .includes("report"))
  ) {
    throw new Error(
      "The Brain API does not expose the durable planning/reporting Context Packs",
    );
  }

  const vault = plain(vaultValue, "Vault API projection");
  const connections = list(vault.connections, "Vault API connections")
    .map((item) => plain(item, "Vault API connection"));
  const active = connections.filter((connection) =>
    connection.id === durable.activeVaultConnectionId
    && connection.displayName === "Ti-Scale Attack Knowledge Vault"
    && connection.vaultPath === "Attack-Knowledge-Vault"
    && connection.status === "connected");
  const syncStates = list(vault.syncStates, "Vault API sync states")
    .map((item) => plain(item, "Vault API sync state"));
  if (
    vault.enabled !== true
    || active.length !== 1
    || !syncStates.some((state) =>
      state.connectionId === durable.activeVaultConnectionId
      && state.status === "synced")
  ) {
    throw new Error(
      "The Vault API does not expose the connected synchronized "
      + "Attack Knowledge Vault used by the run",
    );
  }
  return Object.freeze({
    evidenceCount: evidence.length,
    reportCount: reports.length,
    contextPackCount: contexts.length,
  });
}

export async function runCompleteAutonomousLiveProof(
  token: string,
  target: DisposableCompleteAutonomousTarget,
  prerequisite?: CompleteAutonomousPrerequisiteReceipt,
  client = createCompleteAutonomousProofClient(token),
): Promise<JsonObject> {
  const ready = prerequisite
    ?? await inspectCompleteAutonomousLiveEnvironment(client);
  if (
    target.host !== DISPOSABLE_COMPLETE_AUTONOMOUS_HOST
    || target.port !== DISPOSABLE_COMPLETE_AUTONOMOUS_PORT
  ) {
    throw new Error(
      "The live proof accepts only the exact fixed disposable-loopback target",
    );
  }

  const nonce = randomUUID();
  const resolved = await client.request(
    "/api/v2/registries/intake/resolve",
    {
      method: "POST",
      idempotencyKey: `complete-autonomous-resolve-${nonce}`,
      body: buildCompleteAutonomousResolveInput(),
    },
  );
  const request = plain(
    resolved.request,
    "resolved Complete Autonomous request",
  );
  const contract = plain(
    request.contract,
    "resolved Complete Autonomous contract",
  );
  if (contract.outcomeProfile !== "complete_engagement") {
    throw new Error(
      "The full-path request was not classified as a Complete Autonomous Engagement",
    );
  }
  exactSet(
    list(contract.deliverables, "resolved terminal deliverables"),
    AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
    "resolved terminal deliverables",
  );
  exactSet(
    list(request.successCriteria, "resolved success criteria"),
    COMPLETE_AUTONOMOUS_SUCCESS_CRITERIA,
    "resolved success criteria",
  );
  exactSet(
    list(contract.allowedActionClasses, "resolved allowed action classes"),
    COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS,
    "resolved allowed action classes",
  );

  const preflight = await client.request(
    "/api/v2/missions/autonomous/preflight",
    {
      method: "POST",
      idempotencyKey: `complete-autonomous-preflight-${nonce}`,
      body: request,
    },
  );
  const preflightReadiness = plain(
    preflight.readiness,
    "Complete Autonomous preflight readiness",
  );
  const preflightOutcome = plain(
    preflight.outcome,
    "Complete Autonomous preflight outcome",
  );
  const failedChecks = list(
    preflightReadiness.checks,
    "Complete Autonomous preflight checks",
  ).map((value) => plain(value, "Complete Autonomous preflight check"))
    .filter((check) => check.status === "fail");
  if (
    preflightOutcome.id !== "complete_engagement"
    || preflightReadiness.status !== "ready"
    || failedChecks.length > 0
  ) {
    throw new CompleteAutonomousLivePrerequisiteError(
      "complete_autonomous_preflight_unavailable",
      "The running API rejected the complete exploit→session→user→root→"
      + `cleanup promise: ${failedChecks.map((check) =>
        `${safeMessage(check.id, "unknown")}: `
        + safeMessage(check.impact, "no impact")).join(" | ")}`,
      "Repair the exact failed live preflight bindings. Do not narrow the "
      + "mission to assessment-only or report a partial run as complete.",
    );
  }
  const contractReview = plain(
    preflight.contract,
    "Complete Autonomous preflight contract",
  );
  text(contractReview.hash, "Complete Autonomous contract hash");

  // This is the only mission-creation request in the proof.
  const created = await client.request("/api/v2/missions", {
    method: "POST",
    expectedStatus: 201,
    idempotencyKey: `complete-autonomous-create-${nonce}`,
    body: { ...request, contractReview },
  });
  const missionId = text(
    plain(created.mission, "created mission").id,
    "created mission ID",
  );
  const runId = text(
    plain(created.run, "created run").id,
    "created run ID",
  );
  const terminal = await waitForCompletedRun(client, runId);
  const durable = await waitForCompleteAutonomousDurableCloseout(
    runId,
    missionId,
    ready.activeVaultConnectionId,
  );
  const trace = assertDisposableCompleteTargetTrace(target);

  const queryMission = encodeURIComponent(missionId);
  const queryRun = encodeURIComponent(runId);
  const [evidence, reports, contexts, vault] = await Promise.all([
    client.request(
      `/api/v2/intelligence/evidence?missionId=${queryMission}`
      + `&runId=${queryRun}&limit=100`,
    ),
    client.request(`/api/v2/reports?missionId=${queryMission}&limit=100`),
    client.request(
      `/api/v2/brain/context-packs?missionId=${queryMission}&limit=200`,
    ),
    client.request("/api/v2/brain/vault"),
  ]);
  const apiProjection = assertApiProjection(
    evidence,
    reports,
    contexts,
    vault,
    durable,
  );

  const receipt = {
    schemaVersion: COMPLETE_AUTONOMOUS_LIVE_PROOF_SCHEMA_VERSION,
    status: "passed",
    checkedAt: new Date().toISOString(),
    origin: AUTONOMOUS_ASSESSMENT_PROOF_ORIGIN,
    missionId,
    runId,
    terminalStatus: terminal.status,
    oneMissionCreated: true,
    target: {
      schemaVersion: target.schemaVersion,
      host: target.host,
      port: target.port,
      origin: target.origin,
      fixtureOnly: true,
      disposableSimulationOnly: true,
      realTargetSupport: false,
      arbitraryExternalTargetSupport: false,
      exploitFixture: {
        product: DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
        version: DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
        cveId: DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
        impactPath: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
        fixedReadOnlyMarker: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
      },
      trace,
      legacy3131ContactPermitted: false,
    },
    prerequisite: ready,
    contract: {
      journey: "autonomous",
      outcomeProfile: "complete_engagement",
      actionClassIds: [...COMPLETE_AUTONOMOUS_ACTION_CLASS_IDS],
      successCriteria: [...COMPLETE_AUTONOMOUS_SUCCESS_CRITERIA],
    },
    durable,
    apiProjection,
    brainAndVault: {
      contextPacksVerified: true,
      activeVaultConnectionId: ready.activeVaultConnectionId,
      activeVaultName: ready.activeVaultName,
      everyUsedMemoryNodeSynchronized: true,
    },
    secretHandling: {
      tokenSource: "private_root_file",
      tokenPersistedByProof: false,
      tokenIncludedInReceipt: false,
      flagContentRetained: false,
      hashOnlyObjectiveProofs: true,
    },
    claims: {
      productionApiAndRuntimeExercised: true,
      isolatedHarnessAcceptedAsProductionProof: false,
      arbitraryExternalTargetSupport: false,
      disposableLoopbackFixtureOnly: true,
    },
  };
  return Object.freeze({
    ...receipt,
    receiptSha256: digestCanonicalJson(
      receipt,
      { maxBytes: 512 * 1_024, maxDepth: 40 },
    ).sha256,
  });
}

export async function withDisposableCompleteAutonomousTarget<T>(
  operation: (target: DisposableCompleteAutonomousTarget) => Promise<T>,
  start: () => Promise<DisposableCompleteAutonomousTarget> =
    () => startDisposableCompleteAutonomousTarget(),
): Promise<T> {
  const target = await start();
  try {
    return await operation(target);
  } finally {
    await target.close();
  }
}

async function main(): Promise<void> {
  parseCompleteAutonomousLiveProofArguments(process.argv.slice(2));
  const receipt = await withTrustedOperatorToken(async (token) => {
    const client = createCompleteAutonomousProofClient(token);
    // Fail before binding the fixture or creating a mission when the running
    // process does not expose the complete candidate transport.
    const prerequisite =
      await inspectCompleteAutonomousLiveEnvironment(client);
    return withDisposableCompleteAutonomousTarget((target) =>
      runCompleteAutonomousLiveProof(
        token,
        target,
        prerequisite,
        client,
      ));
  });
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    if (error instanceof CompleteAutonomousLivePrerequisiteError) {
      process.stderr.write(
        "Complete Autonomous live proof prerequisite failed "
        + `[${error.code}]: ${safeMessage(error.message, "unknown error")} `
        + `Remediation: ${safeMessage(error.remediation, "none returned")}\n`,
      );
    } else {
      process.stderr.write(
        "Complete Autonomous live proof failed: "
        + `${safeMessage(
          error instanceof Error ? error.message : undefined,
          "unknown error",
        )}\n`,
      );
    }
    process.exitCode = 1;
  });
}
